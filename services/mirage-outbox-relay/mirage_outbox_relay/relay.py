"""mirage-outbox-relay (Step 6, §6.3): reads infra/migrations/0003's
`outbox_events` table and publishes to NATS JetStream.

"State changes never publish to NATS inline. They write an outbox_events
row in the same transaction; mirage-outbox-relay publishes."
    SELECT event_id, topic, payload FROM outbox_events
     WHERE published_at IS NULL AND next_attempt_at <= now()
     ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 100
    -- lock batch -> publish (event_id as Nats-Msg-Id) -> await ack
    -> set published_at -> commit.

Publish-before-mark: if the process crashes between a successful NATS
publish and the `published_at` UPDATE committing, the row is picked up
again on restart and republished — safe because NATS JetStream dedups on
Nats-Msg-Id (event_id) within the stream's duplicate_window, so the
at-least-once redelivery never becomes a duplicate *business* effect
(§6.3). "Relay is single-writer per topic" is satisfied structurally: only
this relay ever inserts into outbox_events' consumer side (publishes), so
there is exactly one writer process type touching NATS for these subjects,
even if multiple instances race — `FOR UPDATE SKIP LOCKED` makes concurrent
relay instances safely partition the batch rather than double-publish.

KNOWN_ISSUES.md: this relay polls every `poll_interval_seconds` (default
0.25s per spec) rather than blocking on the `outbox_events_channel` LISTEN
the migration's trigger emits — polling is the documented correctness
backstop either way; NOTIFY-driven wake is a latency optimization deferred
as a scope decision (ADR-0016), not a missing correctness property.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import psycopg
from nats.js import JetStreamContext

from mirage_common.nats_client import publish_event

logger = logging.getLogger("mirage.outbox_relay")

ALERT_AFTER_ATTEMPTS = 10
BACKOFF_SECONDS: list[float] = [1, 5, 25, 125, 625]
DEFAULT_POLL_INTERVAL_SECONDS = 0.25
DEFAULT_BATCH_SIZE = 100


@dataclass
class RelayAlert:
    event_id: str
    topic: str
    attempts: int
    error: str


AlertCallback = Callable[[RelayAlert], None]


def _default_alert(alert: RelayAlert) -> None:
    logger.critical(
        "mirage.outbox_relay.alert",
        extra={"event_id": alert.event_id, "topic": alert.topic, "attempts": alert.attempts, "error": alert.error},
    )


@dataclass
class OutboxRelay:
    conn: psycopg.AsyncConnection
    js: JetStreamContext
    batch_size: int = DEFAULT_BATCH_SIZE
    on_alert: AlertCallback = field(default=_default_alert)

    async def relay_once(self) -> int:
        """One batch: publish every due, unpublished row. Returns the count
        successfully published (not the count attempted)."""
        published = 0
        async with self.conn.cursor() as cur:
            await cur.execute(
                "SELECT event_id, topic, payload, attempts FROM outbox_events "
                "WHERE published_at IS NULL AND next_attempt_at <= now() "
                "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT %s",
                (self.batch_size,),
            )
            rows = await cur.fetchall()
            for event_id, topic, payload, attempts in rows:
                try:
                    await publish_event(self.js, topic, payload, event_id=event_id)
                except Exception as exc:  # noqa: BLE001 -- any publish failure is retried, never silently dropped
                    new_attempts = attempts + 1
                    if new_attempts >= ALERT_AFTER_ATTEMPTS:
                        self.on_alert(RelayAlert(event_id=event_id, topic=topic, attempts=new_attempts, error=str(exc)))
                    delay = BACKOFF_SECONDS[min(new_attempts - 1, len(BACKOFF_SECONDS) - 1)]
                    await cur.execute(
                        "UPDATE outbox_events SET attempts = %s, next_attempt_at = now() + %s * interval '1 second' WHERE event_id = %s",
                        (new_attempts, delay, event_id),
                    )
                    continue
                await cur.execute("UPDATE outbox_events SET published_at = now() WHERE event_id = %s", (event_id,))
                published += 1
        await self.conn.commit()
        return published

    async def run_forever(self, *, poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS, stop_event: asyncio.Event | None = None) -> None:
        stop_event = stop_event or asyncio.Event()
        while not stop_event.is_set():
            try:
                await self.relay_once()
            except Exception:  # noqa: BLE001 -- never let one bad batch kill the relay loop
                logger.exception("mirage.outbox_relay.batch_failed")
                await self.conn.rollback()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop_event.wait(), timeout=poll_interval_seconds)
