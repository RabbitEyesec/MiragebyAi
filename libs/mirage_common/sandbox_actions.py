"""Shared constants + Postgres helpers for Step 9b (MirageEnvironmentController
+ mirage-sandbox-gateway): the fixed action set (Appendix I), output-tag
rules, and the `sandbox_instances`/`sandbox_actions` DB operations both the
gateway (writer of PENDING rows, recorder of results) and any future
consumer (Step 10's live fingerprint gate, Step 13's AI loop) need.

Mirrors `mirage_common.case_state_machine`'s "one function per DB
operation, caller owns the transaction" pattern.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.subjects import subject_for_command_type, subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

# The full Appendix I action set, plus the five Stage-4/Prompt-1
# framework+safe-testing actions already reserved in
# schemas/commands/sandbox.command.v1.schema.json's action_type enum. Kept
# in sync by hand with that schema and with migration 0006's CHECK
# constraint — tests/unit/test_sandbox_actions_shared.py asserts all three
# agree.
ALLOWED_ACTION_TYPES: frozenset[str] = frozenset({
    "PLACE_ARTIFACT", "MOVE_ARTIFACT", "CREATE_DECOY_DIRECTORY",
    "CHANGE_VISIBLE_METADATA", "DISPLAY_MESSAGE",
    "ENABLE_DECOY_SERVICE", "DISABLE_DECOY_SERVICE",
    "REQUEST_SNAPSHOT", "ROLLBACK_ACTION", "CONCLUDE_SESSION",
    "TEST_FILE_PLACEMENT", "TEST_METADATA_UPDATE", "SOFT_RESET", "FULL_REBUILD", "CLEAN_SHUTDOWN",
})

# Output-tag rules (spec: "Tags every output REAL_OS_OUTPUT /
# DECOY_SERVICE_OUTPUT / AI_GENERATED_INTERACTION / ANALYST_MESSAGE").
# Every action mutates real OS filesystem/metadata state EXCEPT the two
# decoy-service toggles (DECOY_SERVICE_OUTPUT — the output an intruder
# observes is the decoy service's own, not raw OS state) and
# DISPLAY_MESSAGE, whose tag is caller-supplied because the SAME action
# produces either an AI-authored or an analyst-authored message
# (Appendix I: "surface, content, output_tag" are DISPLAY_MESSAGE's own
# params) — there is no single fixed default for it.
DECOY_SERVICE_ACTIONS: frozenset[str] = frozenset({"ENABLE_DECOY_SERVICE", "DISABLE_DECOY_SERVICE"})
CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS: frozenset[str] = frozenset({"DISPLAY_MESSAGE"})
OUTPUT_TAGS: frozenset[str] = frozenset({
    "REAL_OS_OUTPUT", "DECOY_SERVICE_OUTPUT", "AI_GENERATED_INTERACTION", "ANALYST_MESSAGE",
})

# Actions whose successful execution advances the sandbox's observable
# state — these bump sandbox_instances.state_version so the NEXT command's
# expected_state_version check reflects reality. Read-only/session-control
# actions (REQUEST_SNAPSHOT, CONCLUDE_SESSION) do not mutate observable
# sandbox state themselves and so do not bump the version.
STATE_MUTATING_ACTIONS: frozenset[str] = ALLOWED_ACTION_TYPES - {"REQUEST_SNAPSHOT", "CONCLUDE_SESSION"}


def default_output_tag(action_type: str) -> str | None:
    """Returns the fixed output_tag for action_type, or None if the caller
    must supply one (DISPLAY_MESSAGE)."""
    if action_type in CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS:
        return None
    if action_type in DECOY_SERVICE_ACTIONS:
        return "DECOY_SERVICE_OUTPUT"
    return "REAL_OS_OUTPUT"


class SandboxNotFoundError(Exception):
    def __init__(self, sandbox_id: str) -> None:
        super().__init__(f"no sandbox_instance with sandbox_id={sandbox_id!r}")
        self.sandbox_id = sandbox_id


class StateVersionConflictError(Exception):
    def __init__(self, sandbox_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"sandbox {sandbox_id!r}: expected_state_version={expected_version} does not match "
            f"current state_version={actual_version} (concurrent modification or stale command)"
        )
        self.sandbox_id = sandbox_id
        self.expected_version = expected_version
        self.actual_version = actual_version


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    command_id: str
    sandbox_id: str
    case_id: str
    action_type: str
    action_params: dict
    expected_state_version: int
    issued_by: str
    policy_decision_id: str


async def ensure_sandbox_instance(
    conn: psycopg.AsyncConnection, *, sandbox_id: str, case_id: str, image_id: str, network_identity: str | None = None,
) -> int:
    """Idempotent upsert — a controller reconnecting after a network blip
    re-declares the same sandbox_id rather than erroring. Returns the
    current state_version."""
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO sandbox_instances (sandbox_id, case_id, image_id, network_identity) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (sandbox_id) DO UPDATE SET network_identity = EXCLUDED.network_identity "
            "RETURNING state_version",
            (sandbox_id, case_id, image_id, network_identity),
        )
        row = await cur.fetchone()
    assert row is not None  # noqa: S101 -- RETURNING on an INSERT ... ON CONFLICT DO UPDATE always yields exactly one row
    return row[0]


async def open_pending_action(
    conn: psycopg.AsyncConnection,
    *,
    sandbox_id: str,
    case_id: str,
    action_type: str,
    action_params: dict,
    expected_state_version: int,
    issued_by: str,
    policy_decision_id: str | None = None,
) -> PendingAction:
    """One transaction: lock the sandbox row, check optimistic concurrency,
    insert a PENDING sandbox_actions row + its outbox event. Caller owns
    commit/rollback (same convention as case_state_machine.transition_case)."""
    async with conn.cursor() as cur:
        await cur.execute("SELECT state_version FROM sandbox_instances WHERE sandbox_id = %s FOR UPDATE", (sandbox_id,))
        row = await cur.fetchone()
        if row is None:
            raise SandboxNotFoundError(sandbox_id)
        current_version = row[0]
        if current_version != expected_state_version:
            raise StateVersionConflictError(sandbox_id, expected_state_version, current_version)

        action_id = generate_ulid()
        command_id = generate_ulid()
        policy_decision_id = policy_decision_id or generate_ulid()

        await cur.execute(
            "INSERT INTO sandbox_actions "
            "(action_id, command_id, sandbox_id, case_id, action_type, action_params, "
            " expected_state_version, issued_by, policy_decision_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (action_id, command_id, sandbox_id, case_id, action_type, Jsonb(action_params),
             expected_state_version, issued_by, policy_decision_id),
        )

        command_envelope = {
            "command_id": command_id, "command_type": "sandbox.command", "schema_version": "1.0",
            "case_id": case_id, "sandbox_id": sandbox_id, "expected_state_version": expected_state_version,
            "issued_by": issued_by, "policy_decision_id": policy_decision_id,
            "params": {"action_type": action_type, "action_params": action_params},
        }
        await cur.execute(
            "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
            (command_id, subject_for_command_type("sandbox.command"), Jsonb(command_envelope)),
        )

    return PendingAction(
        action_id=action_id, command_id=command_id, sandbox_id=sandbox_id, case_id=case_id,
        action_type=action_type, action_params=action_params,
        expected_state_version=expected_state_version, issued_by=issued_by, policy_decision_id=policy_decision_id,
    )


async def record_action_result(
    conn: psycopg.AsyncConnection,
    *,
    action: PendingAction,
    status: str,
    output_tag: str | None,
    rollback_action_id: str | None,
    error_detail: str | None,
) -> int:
    """Second transaction (after the controller's real WS round trip
    completes/times out): records the result, bumps state_version on
    success for a state-mutating action, writes the sandbox.command_result
    event + an audit row. Returns the sandbox's new state_version."""
    async with conn.cursor() as cur:
        await cur.execute(
            "UPDATE sandbox_actions SET status = %s, output_tag = %s, rollback_action_id = %s, "
            "error_detail = %s, completed_at = now() WHERE action_id = %s",
            (status, output_tag, rollback_action_id, error_detail, action.action_id),
        )

        new_version = action.expected_state_version
        if status == "SUCCESS" and action.action_type in STATE_MUTATING_ACTIONS:
            new_version = action.expected_state_version + 1
            await cur.execute(
                "UPDATE sandbox_instances SET state_version = %s WHERE sandbox_id = %s AND state_version = %s",
                (new_version, action.sandbox_id, action.expected_state_version),
            )
            if cur.rowcount != 1:
                raise StateVersionConflictError(action.sandbox_id, action.expected_state_version, new_version - 1)

        result_event = build_event(
            event_type="sandbox.command_result", schema_version="1.0",
            payload={
                "command_id": action.command_id, "command_type": "sandbox.command", "status": status,
                "output_tag": output_tag or "REAL_OS_OUTPUT", "journal_entry_id": action.action_id,
                "rollback_action_id": rollback_action_id, "error_detail": error_detail,
            },
            source_id="mirage-sandbox-gateway", sequence=new_version,
            actor_type="SYSTEM", classification="EVIDENCE", case_id=action.case_id,
        )
        validated = validate_event(result_event)
        await cur.execute(
            "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
            (validated.envelope["event_id"], subject_for_event_type("sandbox.command_result"), Jsonb(validated.envelope)),
        )

        audit_action = f"sandbox_action.{action.action_type.lower()}.{status.lower()}"
        await cur.execute(
            "INSERT INTO audit_events (actor, actor_type, action, target, outcome, correlation_id, detail) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("mirage-sandbox-gateway", "SYSTEM", audit_action, action.sandbox_id,
             "SUCCESS" if status == "SUCCESS" else "FAILURE", action.command_id, error_detail or ""),
        )
        if action.action_type == "PLACE_ARTIFACT":
            await cur.execute("SELECT to_regclass('public.artifact_deployments')")
            prompt2_table = await cur.fetchone()
            if prompt2_table and prompt2_table[0] is not None:
                deployment_status = "DEPLOYED" if status == "SUCCESS" else "FAILED"
                await cur.execute(
                    """
                    UPDATE artifact_deployments
                    SET status=%s,
                        observed_sha256=CASE WHEN %s='SUCCESS' THEN expected_sha256 ELSE NULL END,
                        rollback_action_id=%s,completed_at=now()
                    WHERE sandbox_action_id=%s
                    RETURNING artifact_id
                    """,
                    (deployment_status, status, rollback_action_id, action.action_id),
                )
                deployment = await cur.fetchone()
                if deployment is not None:
                    await cur.execute(
                        """
                        UPDATE artifacts SET deployment_status=%s,
                            deployed_at=CASE WHEN %s='SUCCESS' THEN now() ELSE deployed_at END
                        WHERE artifact_id=%s
                        """,
                        (deployment_status, status, deployment[0]),
                    )
        elif action.action_type == "ROLLBACK_ACTION":
            await cur.execute("SELECT to_regclass('public.artifact_deployments')")
            prompt2_table = await cur.fetchone()
            if prompt2_table and prompt2_table[0] is not None:
                deployment_status = "REVOKED" if status == "SUCCESS" else "ROLLBACK_FAILED"
                await cur.execute(
                    """
                    UPDATE artifact_deployments
                    SET status=%s,completed_at=now()
                    WHERE rollback_action_id=%s AND status='ROLLBACK_PENDING'
                    RETURNING artifact_id
                    """,
                    (deployment_status, action.action_id),
                )
                deployment = await cur.fetchone()
                if deployment is not None:
                    await cur.execute(
                        """
                        UPDATE artifacts
                        SET deployment_status=%s,
                            approved_for_deployment=FALSE
                        WHERE artifact_id=%s
                        """,
                        (deployment_status, deployment[0]),
                    )

    return new_version
