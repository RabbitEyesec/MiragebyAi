"""JetStream client: stream provisioning, at-least-once publish with
Nats-Msg-Id dedup, and a dead-letter-aware durable consumer (spec §6.3,
Appendix D, Step 1b).

This is the ONE place the five-failed-deliveries dead-letter rule is
implemented — every consumer in every service (mirage-worker,
mirage-sandbox-gateway, mirage-agent-ingestion, ...) is built on
`DeadLetterAwareConsumer` so the behaviour (backoff, *.failed publication,
alert callback) is identical everywhere rather than reimplemented per service.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import nats
from nats.aio.client import Client as NATSClient
from nats.aio.msg import Msg
from nats.js import JetStreamContext
from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy, RetentionPolicy, StreamConfig
from nats.js.errors import NotFoundError

from mirage_common.subjects import (
    MAX_DELIVER_ATTEMPTS,
    REDELIVERY_BACKOFF_SECONDS,
    STREAM_DEFINITIONS,
    failed_subject_for,
)

logger = logging.getLogger("mirage.nats")


async def connect(servers: str | list[str], **kwargs) -> tuple[NATSClient, JetStreamContext]:
    nc = await nats.connect(servers=servers, **kwargs)
    js = nc.jetstream()
    return nc, js


async def ensure_streams(js: JetStreamContext, *, replicas_override: int | None = None) -> list[str]:
    """Idempotently create or update all six Mirage streams. Returns stream names touched."""
    touched: list[str] = []
    for definition in STREAM_DEFINITIONS.values():
        config = StreamConfig(
            name=definition.name,
            subjects=definition.subjects,
            retention=RetentionPolicy.LIMITS,
            # nats-py's StreamConfig.max_age / duplicate_window are SECONDS
            # (confirmed empirically against a real server: writing 86400
            # round-trips as 86400.0, not nanoseconds) despite the wire
            # protocol using nanoseconds — the client converts internally.
            max_age=float(definition.max_age_seconds),
            max_bytes=definition.max_bytes,
            num_replicas=replicas_override or definition.num_replicas,
            duplicate_window=float(definition.duplicate_window_seconds),
            description=definition.description,
        )
        try:
            await js.stream_info(definition.name)
            await js.update_stream(config=config)
        except NotFoundError:
            await js.add_stream(config=config)
        touched.append(definition.name)
    return touched


async def publish_event(js: JetStreamContext, subject: str, event: dict, *, event_id: str) -> bool:
    """Publish an event with event_id as Nats-Msg-Id (dedup key).

    Returns True if this was a new message, False if JetStream recognized it
    as a duplicate within the dedup window (§6.3 — at-least-once delivery,
    once-effective business effect).
    """
    ack = await js.publish(
        subject,
        json.dumps(event, separators=(",", ":")).encode("utf-8"),
        headers={"Nats-Msg-Id": event_id},
    )
    return not ack.duplicate


@dataclass
class DeadLetterInfo:
    original_event_id: str | None
    consumer_name: str
    error_type: str
    error_message: str
    attempt_count: int
    first_failure_at: str
    last_failure_at: str
    original_subject: str


AlertCallback = Callable[[DeadLetterInfo], None]


def _default_alert(info: DeadLetterInfo) -> None:
    logger.critical(
        "mirage.nats.dead_letter",
        extra={
            "consumer_name": info.consumer_name,
            "original_subject": info.original_subject,
            "original_event_id": info.original_event_id,
            "attempt_count": info.attempt_count,
            "error_type": info.error_type,
        },
    )


@dataclass
class DeadLetterAwareConsumer:
    """A durable, explicit-ack JetStream pull consumer with exponential-backoff
    retry and a five-failed-deliveries dead-letter rule.

    Usage:
        consumer = DeadLetterAwareConsumer(js, stream="MIRAGE_HEALTH",
                                            durable_name="worker-health",
                                            filter_subject="agent.heartbeat")
        await consumer.bind()
        await consumer.run_once(handler)   # or loop run_once() in a task
    """

    js: JetStreamContext
    stream: str
    durable_name: str
    filter_subject: str
    max_deliver: int = MAX_DELIVER_ATTEMPTS
    backoff_seconds: list[float] = field(default_factory=lambda: list(REDELIVERY_BACKOFF_SECONDS))
    on_dead_letter: AlertCallback = field(default=_default_alert)

    _sub: JetStreamContext.PullSubscription | None = field(default=None, init=False, repr=False)
    _first_failure_seen: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    async def bind(self) -> None:
        config = ConsumerConfig(
            durable_name=self.durable_name,
            filter_subject=self.filter_subject,
            ack_policy=AckPolicy.EXPLICIT,
            max_deliver=self.max_deliver,
            deliver_policy=DeliverPolicy.ALL,
        )
        try:
            await self.js.consumer_info(self.stream, self.durable_name)
        except NotFoundError:
            await self.js.add_consumer(self.stream, config=config)
        self._sub = await self.js.pull_subscribe_bind(self.durable_name, stream=self.stream)

    async def fetch(self, batch: int = 1, timeout: float = 5.0) -> list[Msg]:
        assert self._sub is not None, "call bind() first"
        try:
            return await self._sub.fetch(batch, timeout=timeout)
        except TimeoutError:
            return []

    async def process(self, msg: Msg, handler: Callable[[Msg], Awaitable[None]]) -> str:
        """Process one message with the dead-letter rule applied.

        Returns "processed", "retried", or "dead_lettered".
        """
        num_delivered = msg.metadata.num_delivered
        event_id = msg.headers.get("Nats-Msg-Id") if msg.headers else None
        now = datetime.now(UTC).isoformat()
        if event_id and event_id not in self._first_failure_seen:
            self._first_failure_seen[event_id] = now

        try:
            await handler(msg)
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any handler failure enters retry/DLQ
            if num_delivered >= self.max_deliver:
                await self._dead_letter(msg, exc, num_delivered, event_id, now)
                await msg.ack()
                return "dead_lettered"
            delay_index = min(num_delivered - 1, len(self.backoff_seconds) - 1)
            await msg.nak(delay=self.backoff_seconds[delay_index])
            return "retried"
        else:
            await msg.ack()
            if event_id:
                self._first_failure_seen.pop(event_id, None)
            return "processed"

    async def _dead_letter(self, msg: Msg, exc: Exception, attempts: int, event_id: str | None, last_failure_at: str) -> None:
        first_failure_at = self._first_failure_seen.get(event_id or "", last_failure_at)
        info = DeadLetterInfo(
            original_event_id=event_id,
            consumer_name=self.durable_name,
            error_type=type(exc).__name__,
            error_message=str(exc)[:1000],
            attempt_count=attempts,
            first_failure_at=first_failure_at,
            last_failure_at=last_failure_at,
            original_subject=msg.subject,
        )
        payload = {
            "original_event_id": info.original_event_id,
            "consumer_name": info.consumer_name,
            "error_type": info.error_type,
            "error_message": info.error_message,
            "attempt_count": info.attempt_count,
            "first_failure_at": info.first_failure_at,
            "last_failure_at": info.last_failure_at,
            "original_subject": info.original_subject,
        }
        failed_subject = failed_subject_for(msg.subject)
        await self.js.publish(failed_subject, json.dumps(payload).encode("utf-8"))
        if event_id:
            self._first_failure_seen.pop(event_id, None)
        self.on_dead_letter(info)
