"""Consume analyst directives and deliver approved direct messages."""
from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import httpx
import psycopg
from psycopg.types.json import Jsonb

from mirage_common.analyst import channel_disabled
from mirage_common.evidence import AcquisitionRequest, EvidenceService
from mirage_contracts.ulid import generate_ulid


async def acknowledge_directive(
    conn: psycopg.AsyncConnection,
    *,
    directive_id: str,
) -> dict:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE analyst_directives SET status='ACKNOWLEDGED',acknowledged_at=now()
            WHERE directive_id=%s AND status='SUBMITTED'
              AND (expires_at IS NULL OR expires_at > now())
            RETURNING directive_id,case_id,session_id,objective,priority
            """,
            (directive_id,),
        )
        row = await cur.fetchone()
        if row is None:
            await cur.execute(
                """
                UPDATE analyst_directives SET status='EXPIRED'
                WHERE directive_id=%s AND expires_at <= now()
                  AND status IN ('SUBMITTED','ACKNOWLEDGED','QUEUED')
                """,
                (directive_id,),
            )
            raise ValueError("directive is unavailable or expired")
    return {
        "directive_id": row[0],
        "case_id": row[1],
        "session_id": row[2],
        "objective": row[3],
        "priority": row[4],
    }


async def link_directive_result(
    conn: psycopg.AsyncConnection,
    *,
    directive_id: str,
    proposal_id: str | None,
    action_id: str | None,
    applied: bool,
    rejection_reason: str | None = None,
) -> None:
    status = "APPLIED" if applied else "REJECTED"
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE analyst_directives SET status=%s,
                applied_at=CASE WHEN %s THEN now() ELSE applied_at END,
                rejected_at=CASE WHEN NOT %s THEN now() ELSE rejected_at END,
                rejection_reason=%s,
                linked_proposal_ids=linked_proposal_ids || %s,
                linked_action_ids=linked_action_ids || %s
            WHERE directive_id=%s
            """,
            (
                status,
                applied,
                applied,
                rejection_reason,
                Jsonb([proposal_id] if proposal_id else []),
                Jsonb([action_id] if action_id else []),
                directive_id,
            ),
        )


async def apply_directive_strategy(
    conn: psycopg.AsyncConnection,
    *,
    directive_id: str,
    from_phase: str,
    to_phase: str,
    proposal_id: str | None,
    action_id: str | None,
) -> None:
    allowed = {
        "OBSERVE": {"PROFILE"},
        "PROFILE": {"ENGAGE"},
        "ENGAGE": {"DEEPEN"},
        "DEEPEN": {"VERIFY"},
        "VERIFY": {"CONTAIN"},
        "CONTAIN": {"CONCLUDE"},
    }
    if to_phase not in allowed.get(from_phase, set()):
        raise ValueError("directive requested an invalid strategy transition")
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT case_id,status,created_by FROM analyst_directives
            WHERE directive_id=%s FOR UPDATE
            """,
            (directive_id,),
        )
        directive = await cur.fetchone()
        if directive is None or directive[1] not in {"ACKNOWLEDGED", "QUEUED"}:
            raise ValueError("directive is not acknowledged for strategy application")
        await cur.execute(
            """
            INSERT INTO strategy_phase_history (
                phase_change_id,case_id,from_phase,to_phase,reason,approved_by
            ) VALUES (%s,%s,%s,%s,%s,%s)
            """,
            (
                generate_ulid(),
                directive[0],
                from_phase,
                to_phase,
                f"analyst directive {directive_id}",
                directive[2],
            ),
        )
    await link_directive_result(
        conn,
        directive_id=directive_id,
        proposal_id=proposal_id,
        action_id=action_id,
        applied=True,
    )


async def deliver_approved_message(
    conn: psycopg.AsyncConnection,
    *,
    message_id: str,
    gateway_base_url: str,
    bearer_token: str,
    evidence_service: EvidenceService,
    timeout_seconds: float = 10.0,
) -> dict:
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT case_id FROM analyst_messages WHERE message_id=%s",
            (message_id,),
        )
        message_case = await cur.fetchone()
    if message_case is None:
        raise ValueError("message not found")
    if await channel_disabled(conn, case_id=message_case[0]):
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE analyst_messages SET status='BLOCKED' WHERE message_id=%s",
                (message_id,),
            )
        raise ValueError("analyst direct-message channel is disabled")
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT m.case_id,m.session_id,m.content,m.surface,s.sandbox_id,
                   si.state_version,p.decision
            FROM analyst_messages m
            JOIN sessions s ON s.session_id=m.session_id
            JOIN sandbox_instances si ON si.sandbox_id=s.sandbox_id
            JOIN policy_decisions p ON p.decision_id=m.policy_decision_id
            WHERE m.message_id=%s AND m.status='APPROVED'
            FOR UPDATE OF m
            """,
            (message_id,),
        )
        row = await cur.fetchone()
        if row is None:
            raise ValueError("message is not approved or has no live sandbox session")
        case_id, _session_id, content, surface, sandbox_id, state_version, decision = row
        if decision not in {"ALLOW", "REQUIRE_ANALYST_APPROVAL"}:
            await cur.execute(
                "UPDATE analyst_messages SET status='BLOCKED' WHERE message_id=%s",
                (message_id,),
            )
            raise ValueError("message policy no longer permits delivery")
        await cur.execute(
            "UPDATE analyst_messages SET status='SENT' WHERE message_id=%s",
            (message_id,),
        )
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                f"{gateway_base_url.rstrip('/')}/api/v1/cases/{case_id}/sandbox-actions",
                headers={"Authorization": f"Bearer {bearer_token}"},
                json={
                    "sandbox_id": sandbox_id,
                    "action_type": "DISPLAY_MESSAGE",
                    "expected_state_version": state_version,
                    "issued_by": "ANALYST",
                    "action_params": {
                        "surface": surface,
                        "content": content,
                        "output_tag": "ANALYST_MESSAGE",
                    },
                },
            )
        response.raise_for_status()
        result = response.json()
        status = "DELIVERED" if result.get("status") == "SUCCESS" else "FAILED"
        evidence_id: str | None = None
        if status == "DELIVERED":
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended('mirage-worker.analyst',5821))"
                )
                await cur.execute(
                    """
                    SELECT COALESCE(max(source_sequence),0)+1
                    FROM evidence_objects WHERE source_id='mirage-worker.analyst'
                    """
                )
                sequence_row = await cur.fetchone()
                if sequence_row is None:
                    raise RuntimeError("unable to allocate analyst-message evidence sequence")
                source_sequence = sequence_row[0]
            delivered_evidence = await evidence_service.acquire(
                conn,
                request=AcquisitionRequest(
                    case_id=case_id,
                    session_id=_session_id,
                    evidence_type="LOG",
                    source_id="mirage-worker.analyst",
                    source_sequence=source_sequence,
                    source_certificate_serial=None,
                    related_event_ids=(
                        [result["action_id"]] if result.get("action_id") else []
                    ),
                    acquisition_time=datetime.now(UTC),
                    original_filename=f"{message_id}-analyst-message.json",
                    media_type="application/json",
                    collection_method="ANALYST_MESSAGE_DELIVERY",
                    classification="SENSITIVE",
                    metadata={
                        "message_id": message_id,
                        "surface": surface,
                        "output_tag": "ANALYST_MESSAGE",
                    },
                    required_for_export=True,
                ),
                stream=io.BytesIO(
                    json.dumps(
                        {
                            "message_id": message_id,
                            "authoritative_output_tag": "ANALYST_MESSAGE",
                            "surface": surface,
                            "content": content,
                            "delivery_result": result,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ),
                actor="mirage-worker.analyst",
            )
            evidence_id = delivered_evidence.evidence_id
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE analyst_messages SET status=%s,
                    delivered_at=CASE WHEN %s='DELIVERED' THEN now() ELSE NULL END,
                    response_event_ids=response_event_ids || %s,evidence_id=%s
                WHERE message_id=%s
                """,
                (
                    status,
                    status,
                    Jsonb([result["action_id"]] if result.get("action_id") else []),
                    evidence_id,
                    message_id,
                ),
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                SELECT author_id,'ANALYST','analyst.message.delivery',message_id,%s,%s,%s
                FROM analyst_messages WHERE message_id=%s
                """,
                (
                    "SUCCESS" if status == "DELIVERED" else "FAILURE",
                    generate_ulid(),
                    status,
                    message_id,
                ),
            )
        return result
    except Exception:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE analyst_messages SET status='FAILED' WHERE message_id=%s",
                (message_id,),
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                SELECT author_id,'ANALYST','analyst.message.delivery',message_id,
                       'FAILURE',%s,'gateway delivery failed'
                FROM analyst_messages WHERE message_id=%s
                """,
                (generate_ulid(), message_id),
            )
        raise
