"""Integration tests for Step 6: the case state machine + transactional
outbox, against real Postgres and real NATS JetStream — no mocks
(ARCHITECTURE_DECISIONS.md ADR-0006). Covers the Step 6 acceptance line:
"A case runs every state and replays with zero conflicting-state bugs and
zero duplicate effective events."
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import psycopg
import pytest

from mirage_common.case_state_machine import (
    ALLOWED_TRANSITIONS,
    InvalidTransitionError,
    OptimisticLockConflictError,
    transition_case,
)
from mirage_common.nats_client import DeadLetterAwareConsumer
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
async def pg_conn_with_case_lifecycle(pg_conn):
    """Extends the shared pg_conn fixture (migration 0001 applied) with
    migrations 0002 (minimal cases) and 0003 (full lifecycle + outbox)."""
    migration_0002 = (REPO_ROOT / "infra" / "migrations" / "0002_cases_minimal.up.sql").read_text()
    migration_0003 = (REPO_ROOT / "infra" / "migrations" / "0003_case_lifecycle_and_outbox.up.sql").read_text()
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "DROP TABLE IF EXISTS audit_events, processed_events, outbox_events, "
            "case_state_transitions, cases CASCADE"
        )
        await cur.execute("DROP FUNCTION IF EXISTS notify_outbox_events() CASCADE")
        await cur.execute(migration_0002)
        await cur.execute(migration_0003)
    await pg_conn.commit()
    return pg_conn


async def _create_case(conn, *, case_id: str, severity: str = "HIGH", owner: str = "analyst-1") -> None:
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id, severity, owner) VALUES (%s, %s, %s)",
            (case_id, severity, owner),
        )
    await conn.commit()


async def test_case_runs_every_state_in_order_with_audit_and_outbox_rows(pg_conn_with_case_lifecycle):
    conn = pg_conn_with_case_lifecycle
    case_id = generate_ulid()
    await _create_case(conn, case_id=case_id)

    version = 1
    visited_states = ["CREATED"]
    for _ in range(len(ALLOWED_TRANSITIONS)):
        result = await transition_case(
            conn, case_id=case_id, expected_version=version,
            actor="test-operator", actor_type="ANALYST", reason="driving the full lifecycle",
        )
        await conn.commit()
        assert result.new_version == version + 1
        visited_states.append(result.to_state)
        version = result.new_version

    assert visited_states == [
        "CREATED", "ARMED", "MONITORING", "STEERING_PENDING", "SANDBOX_ACTIVE",
        "ENGAGING", "CONCLUDING", "EVIDENCE_VERIFYING", "EXPORTED", "DESTROYED",
    ]

    async with conn.cursor() as cur:
        await cur.execute("SELECT state, version FROM cases WHERE case_id = %s", (case_id,))
        final_state, final_version = await cur.fetchone()
        assert (final_state, final_version) == ("DESTROYED", 10)

        await cur.execute("SELECT from_state, to_state FROM case_state_transitions WHERE case_id = %s ORDER BY id", (case_id,))
        transitions = await cur.fetchall()
        assert [t[0] for t in transitions] == visited_states[:-1]
        assert [t[1] for t in transitions] == visited_states[1:]

        await cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert (await cur.fetchone())[0] == 18  # 9 transitions x (state_changed + audit.recorded)

        await cur.execute("SELECT COUNT(*) FROM audit_events WHERE target = %s", (case_id,))
        assert (await cur.fetchone())[0] == 9


async def test_replaying_a_transition_with_a_stale_version_is_rejected_not_double_applied(pg_conn_with_case_lifecycle):
    conn = pg_conn_with_case_lifecycle
    case_id = generate_ulid()
    await _create_case(conn, case_id=case_id)

    first = await transition_case(
        conn, case_id=case_id, expected_version=1, actor="op", actor_type="ANALYST", reason="first",
    )
    await conn.commit()
    assert (first.from_state, first.to_state, first.new_version) == ("CREATED", "ARMED", 2)

    # Simulates a retried request (e.g. a client that never saw the first
    # response and retries with the version it originally knew about).
    with pytest.raises(OptimisticLockConflictError):
        await transition_case(
            conn, case_id=case_id, expected_version=1, actor="op", actor_type="ANALYST", reason="stale replay",
        )
    await conn.rollback()

    async with conn.cursor() as cur:
        await cur.execute("SELECT state, version FROM cases WHERE case_id = %s", (case_id,))
        assert await cur.fetchone() == ("ARMED", 2)  # unchanged by the rejected replay

        await cur.execute("SELECT COUNT(*) FROM case_state_transitions WHERE case_id = %s", (case_id,))
        assert (await cur.fetchone())[0] == 1  # the rejected attempt wrote nothing (transaction rolled back)

        await cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert (await cur.fetchone())[0] == 2  # only the first transition's pair


async def test_destroyed_is_terminal(pg_conn_with_case_lifecycle):
    conn = pg_conn_with_case_lifecycle
    case_id = generate_ulid()
    await _create_case(conn, case_id=case_id)

    version = 1
    for _ in range(len(ALLOWED_TRANSITIONS)):
        result = await transition_case(
            conn, case_id=case_id, expected_version=version, actor="op", actor_type="SYSTEM", reason="advance",
        )
        await conn.commit()
        version = result.new_version

    with pytest.raises(InvalidTransitionError):
        await transition_case(
            conn, case_id=case_id, expected_version=version, actor="op", actor_type="SYSTEM", reason="past the end",
        )
    await conn.rollback()


async def test_outbox_relay_publishes_case_state_changed_to_real_nats(
    pg_conn_with_case_lifecycle, nats_container, mirage_streams,
):
    from mirage_outbox_relay.relay import OutboxRelay

    from mirage_common.nats_client import connect

    conn = pg_conn_with_case_lifecycle
    case_id = generate_ulid()
    await _create_case(conn, case_id=case_id)
    result = await transition_case(
        conn, case_id=case_id, expected_version=1, actor="op", actor_type="ANALYST", reason="arm it",
    )
    await conn.commit()

    async with conn.cursor() as cur:
        await cur.execute("SELECT published_at FROM outbox_events WHERE topic = 'investigation.case.state_changed'")
        assert (await cur.fetchone())[0] is None  # not published yet — the relay hasn't run

    nc, js = await connect(nats_container)
    try:
        relay = OutboxRelay(conn=conn, js=js)
        published_count = await relay.relay_once()
        assert published_count == 2  # case.state_changed + audit.recorded

        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT published_at FROM outbox_events WHERE topic = 'investigation.case.state_changed'"
            )
            assert (await cur.fetchone())[0] is not None

        consumer = DeadLetterAwareConsumer(
            js, stream="MIRAGE_LIFECYCLE", durable_name=f"test-{uuid.uuid4().hex}",
            filter_subject="investigation.case.state_changed",
        )
        await consumer.bind()
        deadline_msgs = await consumer.fetch(20, timeout=5.0)
        matching = [json.loads(m.data) for m in deadline_msgs if json.loads(m.data)["case_id"] == case_id]
        for m in deadline_msgs:
            await m.ack()
        assert len(matching) == 1
        assert matching[0]["payload"]["to_state"] == result.to_state
        assert matching[0]["payload"]["correlation_id"] == result.correlation_id
    finally:
        await nc.close()


async def test_outbox_relay_retries_and_alerts_after_repeated_failure(pg_conn_with_case_lifecycle, nats_container):
    """Inserts a row whose topic matches no stream's subject pattern at
    all — real JetStream publish genuinely fails (NoStreamResponseError)
    every attempt, a real failure mode, not a mock. Deliberately independent
    of whether the 6 production streams have been provisioned on this
    module-scoped NATS container by another test in this file: an unroutable
    subject fails regardless."""
    from mirage_outbox_relay.relay import ALERT_AFTER_ATTEMPTS, OutboxRelay, RelayAlert

    from mirage_common.nats_client import connect

    conn = pg_conn_with_case_lifecycle
    bogus_event_id = f"01BOGUS{uuid.uuid4().hex[:19].upper()}"
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
            (bogus_event_id, "no.stream.owns.this.subject", psycopg.types.json.Jsonb({"event_id": bogus_event_id})),
        )
    await conn.commit()

    nc, js = await connect(nats_container)
    alerts: list[RelayAlert] = []
    try:
        relay = OutboxRelay(conn=conn, js=js, on_alert=alerts.append)
        for _ in range(ALERT_AFTER_ATTEMPTS):
            published = await relay.relay_once()
            assert published == 0  # no stream owns this subject -> every publish fails
            # Fast-forward past the real exponential backoff so the test
            # doesn't have to sleep for real minutes between attempts.
            async with conn.cursor() as cur:
                await cur.execute("UPDATE outbox_events SET next_attempt_at = now() WHERE event_id = %s", (bogus_event_id,))
            await conn.commit()

        assert len(alerts) >= 1
        assert alerts[-1].attempts >= ALERT_AFTER_ATTEMPTS
        assert alerts[-1].event_id == bogus_event_id
    finally:
        await nc.close()
