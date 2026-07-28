"""Integration tests for Step 10: the live, blocking §6.5 fingerprint gate,
against real Postgres — no mocks (ARCHITECTURE_DECISIONS.md ADR-0006).
Covers Step 10's Done-when line: "The sandbox passes 100% of MUST checks
before any case enters ENGAGING."
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mirage_common.case_state_machine import InvalidTransitionError, OptimisticLockConflictError
from mirage_common.fingerprint_gate import (
    FingerprintGateBlockedError,
    enforce_fingerprint_gate_before_engaging,
)
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = json.loads((REPO_ROOT / "infra" / "fingerprint" / "dev-sandbox-baseline.v1.json").read_text())


def _passing_observed() -> dict:
    """A full observation set that satisfies every MUST and SHOULD check in
    the real Step 7b dev-sandbox baseline — the same fixture shape
    tests/unit/test_fingerprint_engine.py's own "fully passing" case uses."""
    checks = BASELINE["checks"]
    observed: dict = {}
    for name, check in checks.items():
        comparator = check["comparator"]
        expected = check["expected"]
        if comparator in ("exact", "baseline_match"):
            observed[name] = dict(expected)
        elif comparator == "required_subset":
            observed[name] = {"installed": expected["required"]}
        elif comparator == "no_file_predates_date":
            observed[name] = {"files_predating_hire_date": []}
        elif comparator == "allowed_set_forbidden_patterns":
            observed[name] = {"running": list(expected.get("allowed", []))}
        elif comparator == "range":
            lo = expected.get("min", expected.get("min_hours", 0))
            hi = expected.get("max", expected.get("max_hours", lo + 1))
            observed[name] = {"value": (lo + hi) / 2}
        else:  # pragma: no cover -- every comparator in the real baseline is one of the above
            raise AssertionError(f"unhandled comparator {comparator!r} in test fixture")
    return observed


@pytest.fixture
async def pg_conn_with_fingerprint_gate(pg_conn):
    migrations = [
        "0002_cases_minimal.up.sql",
        "0003_case_lifecycle_and_outbox.up.sql",
        "0004_detection_correlation.up.sql",
        "0005_routing_decisions.up.sql",
        "0006_sandbox_actions.up.sql",
        "0007_sandbox_fingerprint_snapshots.up.sql",
    ]
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "DROP TABLE IF EXISTS sandbox_fingerprint_snapshots, sandbox_actions, sandbox_instances, "
            "routing_decisions, audit_events, processed_events, outbox_events, case_state_transitions, cases CASCADE"
        )
        await cur.execute("DROP FUNCTION IF EXISTS notify_outbox_events() CASCADE")
        for name in migrations:
            await cur.execute((REPO_ROOT / "infra" / "migrations" / name).read_text())
    await pg_conn.commit()
    return pg_conn


async def _make_case(conn, *, state: str, version: int = 1) -> str:
    case_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id, state, version, severity) VALUES (%s, %s, %s, 'HIGH')",
            (case_id, state, version),
        )
    await conn.commit()
    return case_id


async def _write_snapshot(conn, *, sandbox_id: str, checks: dict, observed_at: str = "2026-07-25T00:00:00.000Z") -> None:
    from psycopg.types.json import Jsonb

    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO sandbox_fingerprint_snapshots (sandbox_id, checks, observed_at, source_agent_id) "
            "VALUES (%s, %s, %s, 'test-spider-agent')",
            (sandbox_id, Jsonb(checks), observed_at),
        )
    await conn.commit()


class TestFingerprintGate:
    async def test_passing_snapshot_advances_sandbox_active_to_engaging(self, pg_conn_with_fingerprint_gate):
        conn = pg_conn_with_fingerprint_gate
        case_id = await _make_case(conn, state="SANDBOX_ACTIVE", version=3)
        sandbox_id = "sandbox-pass-001"
        await _write_snapshot(conn, sandbox_id=sandbox_id, checks=_passing_observed())

        result = await enforce_fingerprint_gate_before_engaging(
            conn, case_id=case_id, sandbox_id=sandbox_id, baseline=BASELINE, expected_version=3,
            actor="test", actor_type="SYSTEM",
        )
        await conn.commit()

        assert result.from_state == "SANDBOX_ACTIVE"
        assert result.to_state == "ENGAGING"
        assert result.new_version == 4

        async with conn.cursor() as cur:
            await cur.execute("SELECT state, version FROM cases WHERE case_id = %s", (case_id,))
            state, version = await cur.fetchone()
        assert (state, version) == ("ENGAGING", 4)

        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT count(*) FROM audit_events WHERE target = %s AND action = 'fingerprint_gate.passed'", (case_id,)
            )
            (count,) = await cur.fetchone()
        assert count == 1

        async with conn.cursor() as cur:
            await cur.execute("SELECT topic FROM outbox_events WHERE topic = 'investigation.fingerprint_gate_evaluated'")
            rows = await cur.fetchall()
        assert len(rows) == 1

    async def test_missing_must_check_blocks_and_case_stays_in_sandbox_active(self, pg_conn_with_fingerprint_gate):
        conn = pg_conn_with_fingerprint_gate
        case_id = await _make_case(conn, state="SANDBOX_ACTIVE", version=1)
        sandbox_id = "sandbox-fail-001"
        broken_observed = _passing_observed()
        # Sabotage a real MUST check: a forbidden-pattern process is visible.
        broken_observed["processes_services"] = {"running": ["MirageEndpoint_debug.exe"]}
        await _write_snapshot(conn, sandbox_id=sandbox_id, checks=broken_observed)

        with pytest.raises(FingerprintGateBlockedError) as exc_info:
            await enforce_fingerprint_gate_before_engaging(
                conn, case_id=case_id, sandbox_id=sandbox_id, baseline=BASELINE, expected_version=1,
                actor="test", actor_type="SYSTEM",
            )
        assert "processes_services" in str(exc_info.value)

        # Blocked evaluations commit their own audit trail immediately
        # (module docstring) — verify it survived even though the caller
        # never explicitly committed after the exception.
        async with conn.cursor() as cur:
            await cur.execute("SELECT state, version FROM cases WHERE case_id = %s", (case_id,))
            state, version = await cur.fetchone()
        assert (state, version) == ("SANDBOX_ACTIVE", 1)

        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT count(*) FROM audit_events WHERE target = %s AND action = 'fingerprint_gate.blocked'", (case_id,)
            )
            (count,) = await cur.fetchone()
        assert count == 1

    async def test_no_snapshot_at_all_is_treated_as_a_hard_failure(self, pg_conn_with_fingerprint_gate):
        """§6.5: 'an inconsistent sandbox is worse than none' — a sandbox
        that never reported ANY fingerprint data must block exactly like a
        sandbox that reported and failed, not silently pass through."""
        conn = pg_conn_with_fingerprint_gate
        case_id = await _make_case(conn, state="SANDBOX_ACTIVE", version=1)

        with pytest.raises(FingerprintGateBlockedError) as exc_info:
            await enforce_fingerprint_gate_before_engaging(
                conn, case_id=case_id, sandbox_id="sandbox-never-reported", baseline=BASELINE, expected_version=1,
                actor="test", actor_type="SYSTEM",
            )
        assert exc_info.value.report.all_must_passed is False

        async with conn.cursor() as cur:
            await cur.execute("SELECT state FROM cases WHERE case_id = %s", (case_id,))
            (state,) = await cur.fetchone()
        assert state == "SANDBOX_ACTIVE"

    async def test_gate_is_a_noop_for_transitions_other_than_sandbox_active_to_engaging(self, pg_conn_with_fingerprint_gate):
        """A case in MONITORING calling this function still advances
        normally (to STEERING_PENDING) — the gate must never interfere with
        transitions it isn't chartered to guard."""
        conn = pg_conn_with_fingerprint_gate
        case_id = await _make_case(conn, state="MONITORING", version=1)

        result = await enforce_fingerprint_gate_before_engaging(
            conn, case_id=case_id, sandbox_id="irrelevant-sandbox", baseline=BASELINE, expected_version=1,
            actor="test", actor_type="SYSTEM",
        )
        await conn.commit()
        assert result.to_state == "STEERING_PENDING"

    async def test_invalid_transition_still_raises_the_state_machines_own_error(self, pg_conn_with_fingerprint_gate):
        conn = pg_conn_with_fingerprint_gate
        case_id = await _make_case(conn, state="DESTROYED", version=1)
        with pytest.raises(InvalidTransitionError):
            await enforce_fingerprint_gate_before_engaging(
                conn, case_id=case_id, sandbox_id="x", baseline=BASELINE, expected_version=1,
                actor="test", actor_type="SYSTEM",
            )

    async def test_stale_expected_version_is_rejected_before_any_evaluation(self, pg_conn_with_fingerprint_gate):
        conn = pg_conn_with_fingerprint_gate
        case_id = await _make_case(conn, state="SANDBOX_ACTIVE", version=5)
        await _write_snapshot(conn, sandbox_id="sandbox-stale", checks=_passing_observed())

        with pytest.raises(OptimisticLockConflictError):
            await enforce_fingerprint_gate_before_engaging(
                conn, case_id=case_id, sandbox_id="sandbox-stale", baseline=BASELINE, expected_version=1,
                actor="test", actor_type="SYSTEM",
            )
