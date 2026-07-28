"""Integration tests for Step 7: the detection-into-cases adapter, against
real Postgres and real NATS JetStream — no mocks (ADR-0006). Covers the
Step 7 acceptance line: "An alert yields exactly one correlated case with
an immutable first lifecycle event."
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mirage_common.detection_correlation import DETECTION_ADAPTER_CONSUMER_NAME, correlate_detection
from mirage_contracts.envelope import build_event
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
async def pg_conn_with_detection_adapter(pg_conn):
    """Extends the shared pg_conn fixture with migrations 0002-0004 (minimal
    cases, full lifecycle + outbox, detection correlation)."""
    migrations = [
        "0002_cases_minimal.up.sql",
        "0003_case_lifecycle_and_outbox.up.sql",
        "0004_detection_correlation.up.sql",
    ]
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "DROP TABLE IF EXISTS audit_events, processed_events, outbox_events, "
            "case_state_transitions, cases CASCADE"
        )
        await cur.execute("DROP FUNCTION IF EXISTS notify_outbox_events() CASCADE")
        for name in migrations:
            await cur.execute((REPO_ROOT / "infra" / "migrations" / name).read_text())
    await pg_conn.commit()
    return pg_conn


def _detection(*, correlation_key: str, severity: str = "HIGH", confidence: float = 0.9) -> dict:
    return {
        "detector": "ELASTIC_DEFEND",
        "signature_id": "sig-123",
        "severity": severity,
        "confidence": confidence,
        "correlation_key": correlation_key,
        "source_refs": ["mirage-alerts:doc-1"],
    }


async def test_first_detection_creates_exactly_one_case_with_immutable_first_event(pg_conn_with_detection_adapter):
    conn = pg_conn_with_detection_adapter
    d = _detection(correlation_key="host-A:signature-123:window-1")

    result = await correlate_detection(
        conn, detection_event_id=generate_ulid(),
        detector=d["detector"], signature_id=d["signature_id"], severity=d["severity"],
        confidence=d["confidence"], correlation_key=d["correlation_key"], source_ref=d["source_refs"][0],
    )
    await conn.commit()

    assert result.created is True
    assert result.already_processed is False

    async with conn.cursor() as cur:
        await cur.execute("SELECT state, severity, correlation_key FROM cases WHERE case_id = %s", (result.case_id,))
        assert await cur.fetchone() == ("CREATED", d["severity"], d["correlation_key"])

        await cur.execute("SELECT topic, payload FROM outbox_events WHERE topic = 'investigation.case.created'")
        rows = await cur.fetchall()
        assert len(rows) == 1  # exactly one immutable first lifecycle event
        envelope = rows[0][1]
        assert envelope["payload"]["case_id"] == result.case_id
        assert envelope["payload"]["initial_state"] == "CREATED"
        assert envelope["payload"]["correlation_key"] == d["correlation_key"]


async def test_second_detection_with_same_correlation_key_attaches_to_existing_case(pg_conn_with_detection_adapter):
    conn = pg_conn_with_detection_adapter
    key = "host-B:signature-456:window-1"
    d = _detection(correlation_key=key)

    first = await correlate_detection(
        conn, detection_event_id=generate_ulid(), detector=d["detector"], signature_id=d["signature_id"],
        severity=d["severity"], confidence=d["confidence"], correlation_key=key, source_ref=d["source_refs"][0],
    )
    await conn.commit()

    second = await correlate_detection(
        conn, detection_event_id=generate_ulid(), detector=d["detector"], signature_id="sig-456-followup",
        severity="CRITICAL", confidence=0.99, correlation_key=key, source_ref="mirage-alerts:doc-2",
    )
    await conn.commit()

    assert second.created is False
    assert second.case_id == first.case_id  # exactly one case for this correlation_key

    async with conn.cursor() as cur:
        await cur.execute("SELECT count(*) FROM outbox_events WHERE topic = 'investigation.case.created'")
        assert (await cur.fetchone())[0] == 1  # still only the one immutable first event

        await cur.execute(
            "SELECT count(*) FROM audit_events WHERE action = 'detection.correlated_to_existing_case' AND target = %s",
            (first.case_id,),
        )
        assert (await cur.fetchone())[0] == 1  # the second detection's correlation is durably recorded


async def test_redelivered_detection_is_deduped_not_double_processed(pg_conn_with_detection_adapter):
    conn = pg_conn_with_detection_adapter
    key = "host-C:signature-789:window-1"
    d = _detection(correlation_key=key)
    detection_event_id = generate_ulid()

    first = await correlate_detection(
        conn, detection_event_id=detection_event_id, detector=d["detector"], signature_id=d["signature_id"],
        severity=d["severity"], confidence=d["confidence"], correlation_key=key, source_ref=d["source_refs"][0],
    )
    await conn.commit()

    # Simulates NATS at-least-once redelivery of the SAME detection event.
    replay = await correlate_detection(
        conn, detection_event_id=detection_event_id, detector=d["detector"], signature_id=d["signature_id"],
        severity=d["severity"], confidence=d["confidence"], correlation_key=key, source_ref=d["source_refs"][0],
    )
    await conn.commit()

    assert replay.already_processed is True
    assert replay.case_id == first.case_id

    async with conn.cursor() as cur:
        await cur.execute("SELECT count(*) FROM cases")
        assert (await cur.fetchone())[0] == 1
        await cur.execute("SELECT count(*) FROM outbox_events WHERE topic = 'investigation.case.created'")
        assert (await cur.fetchone())[0] == 1
        await cur.execute(
            "SELECT count(*) FROM processed_events WHERE consumer_name = %s AND event_id = %s",
            (DETECTION_ADAPTER_CONSUMER_NAME, detection_event_id),
        )
        assert (await cur.fetchone())[0] == 1  # not two rows — the redelivery didn't re-insert


async def test_adapter_never_advances_case_state_past_created(pg_conn_with_detection_adapter):
    """'Adapter never steers. Case creation + steering are operator-approved.'"""
    conn = pg_conn_with_detection_adapter
    d = _detection(correlation_key="host-D:signature-000:window-1")
    result = await correlate_detection(
        conn, detection_event_id=generate_ulid(), detector=d["detector"], signature_id=d["signature_id"],
        severity=d["severity"], confidence=d["confidence"], correlation_key=d["correlation_key"], source_ref=d["source_refs"][0],
    )
    await conn.commit()

    async with conn.cursor() as cur:
        await cur.execute("SELECT state, version FROM cases WHERE case_id = %s", (result.case_id,))
        assert await cur.fetchone() == ("CREATED", 1)  # untouched by any transition
        await cur.execute("SELECT count(*) FROM case_state_transitions WHERE case_id = %s", (result.case_id,))
        assert (await cur.fetchone())[0] == 0  # the adapter wrote zero transitions


async def test_detection_adapter_consumer_loop_processes_real_nats_events(
    pg_conn_with_detection_adapter, nats_container, mirage_streams,
):
    from mirage_worker.detection_adapter import DetectionAdapter

    from mirage_common.nats_client import DeadLetterAwareConsumer, connect, publish_event

    conn = pg_conn_with_detection_adapter
    nc, js = await connect(nats_container)
    try:
        event_a = build_event(
            event_type="detection.raised", schema_version="1.0",
            payload=_detection(correlation_key="host-E:sig-A:w1"),
            source_id="elastic-defend-adapter", sequence=1, actor_type="SYSTEM", classification="EVIDENCE",
        )
        event_b = build_event(
            event_type="detection.raised", schema_version="1.0",
            payload=_detection(correlation_key="host-F:sig-B:w1"),
            source_id="elastic-defend-adapter", sequence=2, actor_type="SYSTEM", classification="EVIDENCE",
        )
        await publish_event(js, "investigation.detection.raised", event_a, event_id=event_a["event_id"])
        await publish_event(js, "investigation.detection.raised", event_b, event_id=event_b["event_id"])

        consumer = DeadLetterAwareConsumer(
            js, stream="MIRAGE_LIFECYCLE", durable_name="test-detection-adapter",
            filter_subject="investigation.detection.raised",
        )
        await consumer.bind()
        adapter = DetectionAdapter(conn=conn, consumer=consumer)

        processed = await adapter.run_batch(batch_size=10, timeout=5.0)
        assert processed == 2

        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) FROM cases")
            assert (await cur.fetchone())[0] == 2  # two distinct correlation_keys -> two cases
            await cur.execute("SELECT count(*) FROM outbox_events WHERE topic = 'investigation.case.created'")
            assert (await cur.fetchone())[0] == 2
    finally:
        await nc.close()
