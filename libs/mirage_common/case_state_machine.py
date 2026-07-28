"""The case lifecycle state machine (Step 6, Appendix B, §6.3) — the single
place a case's `state`/`version` is ever mutated. Every transition is one
Postgres transaction that: optimistically locks the case row, validates the
transition is allowed, updates `cases`, inserts one `case_state_transitions`
row, inserts one `audit_events` row, and writes both a `case.state_changed`
and an `audit.recorded` event to the transactional outbox — all-or-nothing,
so a crash mid-transition leaves no partial effect (Appendix B: "Every
state-changing transaction also writes an audit row and (where it emits an
event) an outbox row").

Retrying a transition with a stale `expected_version` (e.g. after a network
blip when the first attempt actually succeeded) is rejected with
OptimisticLockConflictError rather than double-applying — this is the
mechanism behind Step 6's "replays with zero conflicting-state bugs"
acceptance line; no separate idempotency key is needed for the state
mutation itself.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

# Linear happy-path only (spec Step 6's literal Done-when line: "A case runs
# every state..."). Non-linear transitions (abort-from-any-state, monitoring
# loops, re-engagement) are deferred until the steps that would actually
# trigger them exist (Step 7+ detection/steering logic) — see
# ARCHITECTURE_DECISIONS.md ADR-0016 rather than inventing transition rules
# the spec doesn't specify yet.
ALLOWED_TRANSITIONS: dict[str, str] = {
    "CREATED": "ARMED",
    "ARMED": "MONITORING",
    "MONITORING": "STEERING_PENDING",
    "STEERING_PENDING": "SANDBOX_ACTIVE",
    "SANDBOX_ACTIVE": "ENGAGING",
    "ENGAGING": "CONCLUDING",
    "CONCLUDING": "EVIDENCE_VERIFYING",
    "EVIDENCE_VERIFYING": "EXPORTED",
    "EXPORTED": "DESTROYED",
}

TERMINAL_STATE = "DESTROYED"


class CaseNotFoundError(Exception):
    def __init__(self, case_id: str) -> None:
        super().__init__(f"no case with case_id={case_id!r}")
        self.case_id = case_id


class OptimisticLockConflictError(Exception):
    def __init__(self, case_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"case {case_id!r}: expected_version={expected_version} does not match "
            f"current version={actual_version} (concurrent modification or stale replay)"
        )
        self.case_id = case_id
        self.expected_version = expected_version
        self.actual_version = actual_version


class InvalidTransitionError(Exception):
    def __init__(self, case_id: str, current_state: str) -> None:
        super().__init__(f"case {case_id!r} in state {current_state!r} has no further allowed transition")
        self.case_id = case_id
        self.current_state = current_state


@dataclass(frozen=True)
class TransitionResult:
    case_id: str
    from_state: str
    to_state: str
    new_version: int
    correlation_id: str


async def transition_case(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    expected_version: int,
    actor: str,
    actor_type: str,
    reason: str,
    correlation_id: str | None = None,
) -> TransitionResult:
    """Advances a case exactly one step along ALLOWED_TRANSITIONS. Caller
    owns the transaction boundary (commit/rollback) — this function only
    executes statements against `conn`, matching the pattern
    mirage_agent_ingestion.enrollment already uses."""
    correlation_id = correlation_id or generate_ulid()

    async with conn.cursor() as cur:
        await cur.execute("SELECT state, version FROM cases WHERE case_id = %s FOR UPDATE", (case_id,))
        row = await cur.fetchone()
        if row is None:
            raise CaseNotFoundError(case_id)
        current_state, current_version = row
        if current_version != expected_version:
            raise OptimisticLockConflictError(case_id, expected_version, current_version)

        to_state = ALLOWED_TRANSITIONS.get(current_state)
        if to_state is None:
            raise InvalidTransitionError(case_id, current_state)

        new_version = current_version + 1
        await cur.execute(
            "UPDATE cases SET state = %s, version = %s, updated_at = now() WHERE case_id = %s AND version = %s",
            (to_state, new_version, case_id, expected_version),
        )
        if cur.rowcount != 1:
            # Guarded by the row lock above; a real conflict would already
            # have been caught by the version check. Belt-and-braces only.
            raise OptimisticLockConflictError(case_id, expected_version, current_version)

        await cur.execute(
            "INSERT INTO case_state_transitions "
            "(case_id, from_state, to_state, actor, actor_type, reason, new_version, correlation_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (case_id, current_state, to_state, actor, actor_type, reason, new_version, correlation_id),
        )

        state_changed_event = build_event(
            event_type="case.state_changed", schema_version="1.0",
            payload={
                "case_id": case_id, "from_state": current_state, "to_state": to_state,
                "actor": actor, "actor_type": actor_type, "reason": reason,
                "new_version": new_version, "correlation_id": correlation_id,
            },
            source_id="mirage_common.case_state_machine", sequence=new_version,
            actor_type=actor_type, classification="INTERNAL", case_id=case_id,
        )
        validated = validate_event(state_changed_event)
        await _write_outbox(cur, subject_for_event_type("case.state_changed"), validated.envelope)

        audit_action = f"case.transition.{current_state}_to_{to_state}"
        await cur.execute(
            "INSERT INTO audit_events (actor, actor_type, action, target, outcome, correlation_id, detail) "
            "VALUES (%s, %s, %s, %s, 'SUCCESS', %s, %s)",
            (actor, actor_type, audit_action, case_id, correlation_id, reason),
        )
        audit_event = build_event(
            event_type="audit.recorded", schema_version="1.0",
            payload={
                "actor": actor, "actor_type": actor_type, "action": audit_action,
                "target": case_id, "outcome": "SUCCESS", "correlation_id": correlation_id, "detail": reason,
            },
            source_id="mirage_common.case_state_machine", sequence=new_version,
            actor_type=actor_type, classification="INTERNAL", case_id=case_id,
        )
        validated_audit = validate_event(audit_event)
        await _write_outbox(cur, subject_for_event_type("audit.recorded"), validated_audit.envelope)

    return TransitionResult(
        case_id=case_id, from_state=current_state, to_state=to_state,
        new_version=new_version, correlation_id=correlation_id,
    )


async def _write_outbox(cur: psycopg.AsyncCursor, topic: str, envelope: dict) -> None:
    await cur.execute(
        "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
        (envelope["event_id"], topic, Jsonb(envelope)),
    )
