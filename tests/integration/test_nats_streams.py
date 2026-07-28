"""Integration tests: real NATS JetStream container (Step 1b).

Covers the Prompt-1 required scenarios: publish and consume, explicit
acknowledgement, redelivery, deduplication, dead-letter flow, replay,
consumer restart, one effective state change after replay — plus the exact
Step 1b acceptance line: "a poison message reaches dead-letter without
blocking the stream; a replayed message yields one effective state change."

Every test publishes to its own freshly-minted unique subject under the
dedicated `test.>` stream (see conftest.py `test_stream` fixture) so a fresh
DeliverPolicy=ALL durable consumer only ever sees that test's own messages —
not history left behind by other tests sharing the same NATS container.
The mechanism under test (`DeadLetterAwareConsumer`, `publish_event`,
`ensure_streams`) is identical to what production code uses against the real
MIRAGE_* streams (also exercised once in `test_production_streams_provision`).
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from mirage_common.nats_client import DeadLetterAwareConsumer, ensure_streams, publish_event
from mirage_common.subjects import MAX_DELIVER_ATTEMPTS, STREAM_DEFINITIONS

pytestmark = pytest.mark.integration


def _unique_subject() -> str:
    return f"test.{uuid.uuid4().hex}.health"


def _event(event_id: str | None = None, **overrides) -> dict:
    base = {
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": "system.health",
        "schema_version": "1.0",
        "component": "API",
        "status": "HEALTHY",
    }
    base.update(overrides)
    return base


async def test_production_streams_provision_idempotently(js):
    """Sanity check on the real topology: ensure_streams creates all six
    MIRAGE_* streams and is idempotent (re-running updates, doesn't error)."""
    touched_first = await ensure_streams(js, replicas_override=1)
    assert set(touched_first) == set(STREAM_DEFINITIONS)
    touched_second = await ensure_streams(js, replicas_override=1)
    assert set(touched_second) == set(STREAM_DEFINITIONS)


async def test_publish_and_consume(test_stream, js):
    subject = _unique_subject()
    event_id = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
    evt = _event(event_id)
    is_new = await publish_event(js, subject, evt, event_id=event_id)
    assert is_new is True

    consumer = DeadLetterAwareConsumer(js, stream=test_stream, durable_name=f"c-{uuid.uuid4().hex}", filter_subject=subject)
    await consumer.bind()
    msgs = await consumer.fetch(1, timeout=5)
    assert len(msgs) == 1

    received = []

    async def handler(msg):
        received.append(msg)

    result = await consumer.process(msgs[0], handler)
    assert result == "processed"
    assert len(received) == 1


async def test_explicit_ack_required_before_redelivery_window(test_stream, js):
    subject = _unique_subject()
    event_id = str(uuid.uuid4())
    await publish_event(js, subject, _event(event_id), event_id=event_id)

    durable = f"c-{uuid.uuid4().hex}"
    consumer = DeadLetterAwareConsumer(js, stream=test_stream, durable_name=durable, filter_subject=subject)
    await consumer.bind()
    msgs = await consumer.fetch(1, timeout=5)
    assert len(msgs) == 1
    # Deliberately do NOT ack/nak — message stays "in flight", not redelivered
    # immediately (JetStream AckWait default is well beyond this test's window).
    info = await js.consumer_info(test_stream, durable)
    assert info.num_ack_pending == 1
    await msgs[0].ack()


async def test_redelivery_on_handler_failure(test_stream, js):
    subject = _unique_subject()
    event_id = str(uuid.uuid4())
    await publish_event(js, subject, _event(event_id), event_id=event_id)

    consumer = DeadLetterAwareConsumer(
        js, stream=test_stream, durable_name=f"c-{uuid.uuid4().hex}", filter_subject=subject,
        backoff_seconds=[0.1, 0.1, 0.1, 0.1, 0.1],
    )
    await consumer.bind()

    attempts = 0

    async def flaky_handler(msg):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("simulated transient failure")

    outcome = None
    for _ in range(5):
        msgs = await consumer.fetch(1, timeout=5)
        if not msgs:
            continue
        outcome = await consumer.process(msgs[0], flaky_handler)
        if outcome == "processed":
            break

    assert attempts == 3
    assert outcome == "processed"


async def test_deduplication_same_event_id_stored_once(test_stream, js):
    subject = _unique_subject()
    event_id = str(uuid.uuid4())
    evt = _event(event_id)

    first = await publish_event(js, subject, evt, event_id=event_id)
    second = await publish_event(js, subject, evt, event_id=event_id)

    assert first is True
    assert second is False  # JetStream recognized the duplicate Nats-Msg-Id

    # Confirm only ONE message is actually stored for this subject.
    consumer = DeadLetterAwareConsumer(js, stream=test_stream, durable_name=f"c-{uuid.uuid4().hex}", filter_subject=subject)
    await consumer.bind()
    msgs = await consumer.fetch(5, timeout=3)
    assert len(msgs) == 1
    await msgs[0].ack()


async def test_dead_letter_flow_and_stream_stays_unblocked(test_stream, js):
    """Poison message reaches dead-letter after MAX_DELIVER_ATTEMPTS; the
    stream is not blocked — a subsequent good message on the same subject is
    still delivered normally."""
    subject = _unique_subject()
    poison_id = str(uuid.uuid4())
    await publish_event(js, subject, _event(poison_id), event_id=poison_id)

    alerts = []
    durable = f"c-{uuid.uuid4().hex}"
    consumer = DeadLetterAwareConsumer(
        js, stream=test_stream, durable_name=durable, filter_subject=subject,
        backoff_seconds=[0.05] * MAX_DELIVER_ATTEMPTS,
        on_dead_letter=lambda info: alerts.append(info),
    )
    await consumer.bind()

    from nats.js.api import ConsumerConfig

    failed_subject = f"{subject}.failed"
    dlq_durable = f"dlq-{uuid.uuid4().hex}"
    await js.add_consumer(test_stream, config=ConsumerConfig(durable_name=dlq_durable, filter_subject=failed_subject, ack_policy="explicit"))
    dlq_sub = await js.pull_subscribe_bind(dlq_durable, stream=test_stream)

    async def always_fails(msg):
        raise RuntimeError("poison message — always fails")

    outcomes = []
    for _ in range(MAX_DELIVER_ATTEMPTS + 1):
        msgs = await consumer.fetch(1, timeout=5)
        if not msgs:
            break
        outcomes.append(await consumer.process(msgs[0], always_fails))
        if outcomes[-1] == "dead_lettered":
            break

    assert outcomes[-1] == "dead_lettered"
    assert outcomes.count("retried") == MAX_DELIVER_ATTEMPTS - 1
    assert len(alerts) == 1
    assert alerts[0].original_event_id == poison_id
    assert alerts[0].attempt_count == MAX_DELIVER_ATTEMPTS

    dlq_msgs = await dlq_sub.fetch(1, timeout=5)
    assert len(dlq_msgs) == 1
    dlq_payload = json.loads(dlq_msgs[0].data)
    assert dlq_payload["original_event_id"] == poison_id
    assert dlq_payload["consumer_name"] == durable
    assert dlq_payload["attempt_count"] == MAX_DELIVER_ATTEMPTS
    assert dlq_payload["first_failure_at"] <= dlq_payload["last_failure_at"]
    await dlq_msgs[0].ack()

    # Stream stays unblocked: a fresh good message on the same subject is delivered fine.
    good_id = str(uuid.uuid4())
    await publish_event(js, subject, _event(good_id), event_id=good_id)
    good_msgs = await consumer.fetch(1, timeout=5)
    assert len(good_msgs) == 1
    good_result = await consumer.process(good_msgs[0], lambda msg: asyncio.sleep(0))
    assert good_result == "processed"


async def test_replay_yields_one_effective_state_change(test_stream, js):
    """A NEW durable consumer with DeliverPolicy=ALL re-reads stream history
    (replay). An idempotent handler using processed-event tracking (the same
    pattern Step 6's processed_events table implements) must produce exactly
    one effective state mutation even though the message is delivered again.
    """
    subject = _unique_subject()
    event_id = str(uuid.uuid4())
    await publish_event(js, subject, _event(event_id, status="DEGRADED"), event_id=event_id)

    consumer_a = DeadLetterAwareConsumer(js, stream=test_stream, durable_name=f"c-{uuid.uuid4().hex}", filter_subject=subject)
    await consumer_a.bind()
    msgs = await consumer_a.fetch(1, timeout=5)
    assert len(msgs) == 1

    effective_state: dict[str, str] = {}
    processed_events: set[str] = set()

    async def idempotent_handler(msg, applied_ids=processed_events, state=effective_state):
        payload = json.loads(msg.data)
        eid = payload["event_id"]
        if eid in applied_ids:
            return  # already applied — no-op, exactly the processed_events contract (§6.3)
        applied_ids.add(eid)
        state["status"] = payload["status"]

    await consumer_a.process(msgs[0], idempotent_handler)
    assert effective_state == {"status": "DEGRADED"}
    assert len(processed_events) == 1

    # Simulate replay: a brand-new consumer reading from the start of this subject's history.
    from nats.js.api import ConsumerConfig, DeliverPolicy

    replay_durable = f"replay-{uuid.uuid4().hex}"
    await js.add_consumer(
        test_stream,
        config=ConsumerConfig(durable_name=replay_durable, filter_subject=subject, ack_policy="explicit", deliver_policy=DeliverPolicy.ALL),
    )
    replay_sub = await js.pull_subscribe_bind(replay_durable, stream=test_stream)
    replayed = await replay_sub.fetch(1, timeout=5)
    assert len(replayed) == 1

    await idempotent_handler(replayed[0])
    await replayed[0].ack()

    # Still exactly one effective change and one processed id — replay was a no-op business-wise.
    assert effective_state == {"status": "DEGRADED"}
    assert len(processed_events) == 1


async def test_consumer_restart_resumes_without_reprocessing(test_stream, js):
    """A durable consumer that reconnects (new client instance, same durable
    name) resumes from its last acked position rather than redelivering
    already-acked messages."""
    subject = _unique_subject()
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for eid in ids:
        await publish_event(js, subject, _event(eid), event_id=eid)

    durable = f"c-{uuid.uuid4().hex}"
    consumer1 = DeadLetterAwareConsumer(js, stream=test_stream, durable_name=durable, filter_subject=subject)
    await consumer1.bind()
    first_batch = await consumer1.fetch(2, timeout=5)
    assert len(first_batch) == 2
    for m in first_batch:
        await m.ack()

    # New consumer object, SAME durable name — simulates process restart.
    consumer2 = DeadLetterAwareConsumer(js, stream=test_stream, durable_name=durable, filter_subject=subject)
    await consumer2.bind()
    remaining = await consumer2.fetch(5, timeout=5)
    remaining_ids = {json.loads(m.data)["event_id"] for m in remaining}
    for m in remaining:
        await m.ack()

    acked_ids = {json.loads(m.data)["event_id"] for m in first_batch}
    assert acked_ids.isdisjoint(remaining_ids)
    assert acked_ids | remaining_ids == set(ids)
