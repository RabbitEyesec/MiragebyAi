"""Step 10: the live, blocking §6.5 fingerprint gate — "Run the fingerprint
harness live. Any MUST failure blocks advancement. An inconsistent sandbox
is worse than none." This module wraps
`mirage_common.case_state_machine.transition_case` for the ONE transition
the spec's Done-when line is about (SANDBOX_ACTIVE -> ENGAGING); every
other transition passes straight through untouched.

Asymmetric commit behavior, deliberately: a BLOCKED evaluation commits its
own audit/outbox rows immediately (before raising) so the failure record
survives even if the caller rolls back whatever transaction it was
building around this call — "an inconsistent sandbox is worse than none"
means the block itself must be durable, independent of the caller's own
transaction fate. A PASSED evaluation does NOT commit early; its audit row
and the resulting case transition commit together as one atomic unit when
the caller commits, matching every other function in this codebase's
"caller owns the transaction boundary" convention.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.case_state_machine import (
    CaseNotFoundError,
    OptimisticLockConflictError,
    TransitionResult,
    transition_case,
)
from mirage_common.fingerprint import FingerprintReport, run_fingerprint_check
from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

GATED_TRANSITION = ("SANDBOX_ACTIVE", "ENGAGING")


class FingerprintGateBlockedError(Exception):
    def __init__(self, case_id: str, report: FingerprintReport) -> None:
        failed = [r.check_name for r in report.must_checks if not r.passed]
        super().__init__(
            f"case {case_id!r}: fingerprint gate blocked SANDBOX_ACTIVE -> ENGAGING "
            f"(all_must_passed={report.all_must_passed}, should_pass_ratio={report.should_pass_ratio:.2f}, "
            f"failed_must_checks={failed})"
        )
        self.case_id = case_id
        self.report = report


@dataclass(frozen=True)
class GateEvaluation:
    passed: bool
    report: FingerprintReport


async def _evaluate_and_record(
    conn: psycopg.AsyncConnection, *, case_id: str, sandbox_id: str, baseline: dict, correlation_id: str,
) -> GateEvaluation:
    async with conn.cursor() as cur:
        await cur.execute("SELECT checks FROM sandbox_fingerprint_snapshots WHERE sandbox_id = %s", (sandbox_id,))
        row = await cur.fetchone()
    # A missing snapshot is NOT a special case — run_fingerprint_check's own
    # "no observation collected" handling for every check already implements
    # exactly the §6.5 behavior an entirely-unreported sandbox needs: every
    # MUST check fails, for real, with real evidence text, not a bespoke
    # second failure mode to keep in sync with fingerprint.py's own rules.
    observed = row[0] if row is not None else {}

    report = run_fingerprint_check(baseline, observed)
    failed_must_checks = [r.check_name for r in report.must_checks if not r.passed]

    gate_event = build_event(
        event_type="fingerprint.gate_evaluated", schema_version="1.0",
        payload={
            "case_id": case_id, "sandbox_id": sandbox_id, "baseline_version": report.baseline_version,
            "passed": report.passed, "all_must_passed": report.all_must_passed,
            "should_pass_ratio": report.should_pass_ratio, "failed_must_checks": failed_must_checks,
            "blocked": not report.passed,
        },
        source_id="mirage_common.fingerprint_gate", sequence=1,
        actor_type="SYSTEM", classification="EVIDENCE", case_id=case_id,
    )
    validated = validate_event(gate_event)
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
            (validated.envelope["event_id"], subject_for_event_type("fingerprint.gate_evaluated"), Jsonb(validated.envelope)),
        )
        audit_action = "fingerprint_gate.passed" if report.passed else "fingerprint_gate.blocked"
        detail = "MUST=100%, SHOULD>=75%" if report.passed else f"failed MUST checks: {failed_must_checks}"
        await cur.execute(
            "INSERT INTO audit_events (actor, actor_type, action, target, outcome, correlation_id, detail) "
            "VALUES (%s, 'SYSTEM', %s, %s, %s, %s, %s)",
            ("mirage_common.fingerprint_gate", audit_action, case_id, "SUCCESS" if report.passed else "FAILURE", correlation_id, detail),
        )

    return GateEvaluation(passed=report.passed, report=report)


async def enforce_fingerprint_gate_before_engaging(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    sandbox_id: str,
    baseline: dict,
    expected_version: int,
    actor: str,
    actor_type: str,
    correlation_id: str | None = None,
) -> TransitionResult:
    """Advances a case exactly like `transition_case`, except when the
    current transition is SANDBOX_ACTIVE -> ENGAGING: that one specific
    step is gated on a live §6.5 fingerprint evaluation first. Any other
    transition (or an already-invalid one) is passed straight through to
    `transition_case`, which owns all of its own state-machine validation —
    this module does not duplicate that logic.

    The optimistic-concurrency check is deliberately duplicated here (ahead
    of the fingerprint evaluation, using the identical error
    `transition_case` would eventually raise anyway) rather than left for
    `transition_case` alone to discover — a stale `expected_version` must
    fail BEFORE any evaluation audit/outbox rows are written, or a doomed
    transition would still leave a "fingerprint_gate.passed" record behind
    for a transition that never actually happened."""
    correlation_id = correlation_id or generate_ulid()

    async with conn.cursor() as cur:
        await cur.execute("SELECT state, version FROM cases WHERE case_id = %s FOR UPDATE", (case_id,))
        row = await cur.fetchone()
    if row is None:
        raise CaseNotFoundError(case_id)
    current_state, current_version = row

    if current_state != GATED_TRANSITION[0]:
        return await transition_case(
            conn, case_id=case_id, expected_version=expected_version, actor=actor,
            actor_type=actor_type, reason="advance (fingerprint gate not applicable to this transition)",
            correlation_id=correlation_id,
        )

    if current_version != expected_version:
        raise OptimisticLockConflictError(case_id, expected_version, current_version)

    evaluation = await _evaluate_and_record(conn, case_id=case_id, sandbox_id=sandbox_id, baseline=baseline, correlation_id=correlation_id)

    if not evaluation.passed:
        await conn.commit()  # durably record the block regardless of what the caller does next — see module docstring
        raise FingerprintGateBlockedError(case_id, evaluation.report)

    return await transition_case(
        conn, case_id=case_id, expected_version=expected_version, actor=actor, actor_type=actor_type,
        reason="fingerprint gate passed (§6.5: MUST=100%, SHOULD>=75%)", correlation_id=correlation_id,
    )
