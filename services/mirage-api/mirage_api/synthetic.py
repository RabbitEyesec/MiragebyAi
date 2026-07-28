"""The synthetic health transaction (Step 4b): generates a synthetic event,
validates it exactly as mirage-agent-ingestion would (Step 1 contract
validation — "sends it through ingestion"), publishes it through NATS
JetStream, waits for a durable consumer to pick it up and index it into
Elasticsearch, confirms it is searchable, and returns one correlation ID
tying the whole chain together.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx
from nats.js import JetStreamContext

from mirage_common.nats_client import DeadLetterAwareConsumer, publish_event
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.timestamps import now_rfc3339_ms
from mirage_contracts.ulid import generate_ulid

SYNTHETIC_SUBJECT_PREFIX = "system.health"


class SyntheticCheckTimeoutError(Exception):
    pass


class SyntheticCheckFailedError(Exception):
    pass


@dataclass(frozen=True)
class SyntheticCheckResult:
    correlation_id: str
    event_id: str
    indexed: bool
    elapsed_ms: float


async def run_synthetic_health_check(
    *,
    js: JetStreamContext,
    elasticsearch_url: str,
    stream: str = "MIRAGE_HEALTH",
    subject: str = SYNTHETIC_SUBJECT_PREFIX,
    index: str = "mirage-health",
    timeout_seconds: float = 10.0,
) -> SyntheticCheckResult:
    start = time.monotonic()
    correlation_id = generate_ulid()

    # 1. Generate a synthetic event.
    event = build_event(
        event_type="system.health",
        schema_version="1.0",
        payload={
            "component": "API",
            "status": "HEALTHY",
            "checked_at": now_rfc3339_ms(),
            "detail": f"synthetic-health-check correlation_id={correlation_id}",
        },
        source_id="mirage-api-synthetic-check",
        sequence=0,
        actor_type="SYSTEM",
        classification="SYSTEM",
        event_id=correlation_id,
    )

    # 2. "Sends it through ingestion" — the exact Step 1 contract validation
    #    mirage-agent-ingestion applies to every inbound event, run here
    #    directly since this synthetic check owns both ends of the pipe.
    validated = validate_event(event)

    # 3. Publish through NATS JetStream.
    is_new = await publish_event(js, subject, validated.envelope, event_id=correlation_id)
    if not is_new:
        raise SyntheticCheckFailedError("synthetic event_id collided with an existing message (should never happen with a ULID)")

    # 4. A durable consumer picks it up (proves the JetStream delivery path
    #    end to end, not just the publish call).
    consumer = DeadLetterAwareConsumer(
        js, stream=stream, durable_name=f"synthetic-check-{correlation_id}", filter_subject=subject,
    )
    await consumer.bind()

    received_ok = False

    async def handler(msg) -> None:
        nonlocal received_ok
        payload = json.loads(msg.data)
        if payload["event_id"] == correlation_id:
            received_ok = True

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline and not received_ok:
        msgs = await consumer.fetch(5, timeout=min(2.0, deadline - time.monotonic()))
        for msg in msgs:
            await consumer.process(msg, handler)
    if not received_ok:
        raise SyntheticCheckTimeoutError(f"synthetic event {correlation_id} was not delivered via NATS within {timeout_seconds}s")

    # 5. Store telemetry (index into Elasticsearch) + 6. confirm searchable.
    async with httpx.AsyncClient(timeout=5.0) as client:
        index_resp = await client.post(f"{elasticsearch_url}/{index}/_doc", json=validated.envelope)
        index_resp.raise_for_status()
        await client.post(f"{elasticsearch_url}/{index}/_refresh")
        search_resp = await client.get(f"{elasticsearch_url}/{index}/_search", params={"q": f"event_id:{correlation_id}"})
        search_resp.raise_for_status()
        hits = search_resp.json()["hits"]["total"]["value"]

    if hits < 1:
        raise SyntheticCheckFailedError(f"event {correlation_id} was indexed but is not searchable")

    elapsed_ms = (time.monotonic() - start) * 1000
    return SyntheticCheckResult(correlation_id=correlation_id, event_id=correlation_id, indexed=True, elapsed_ms=elapsed_ms)
