"""PostgreSQL persistence boundary for Stage 6 AI orchestration."""
from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.ai import PolicyResult, Proposal, SnapshotResult
from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid


async def database_budget_allows(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    estimated_cost_gbp: Decimal,
    daily_limit_gbp: Decimal,
    monthly_limit_gbp: Decimal,
    per_case_request_limit: int,
    now: datetime | None = None,
) -> bool:
    now = now or datetime.now(UTC)
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT
              COALESCE(sum(estimated_cost_gbp) FILTER (
                WHERE created_at >= date_trunc('day', %s::timestamptz)
              ),0),
              COALESCE(sum(estimated_cost_gbp) FILTER (
                WHERE created_at >= date_trunc('month', %s::timestamptz)
              ),0),
              count(*) FILTER (WHERE case_id=%s)
            FROM ai_usage
            """,
            (now, now, case_id),
        )
        row = await cur.fetchone()
    if row is None:
        raise RuntimeError("unable to read AI usage budget ledger")
    daily, monthly, case_count = Decimal(row[0]), Decimal(row[1]), int(row[2])
    return (
        daily + estimated_cost_gbp <= daily_limit_gbp
        and monthly + estimated_cost_gbp <= monthly_limit_gbp
        and case_count < per_case_request_limit
    )


async def store_ai_usage(
    conn: psycopg.AsyncConnection,
    *,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    estimated_cost_gbp: Decimal,
    latency_ms: int,
    success: bool,
    failure_type: str | None,
    retry_count: int,
    case_id: str,
    snapshot_id: str,
    proposal_id: str | None,
    fallback_used: bool,
) -> str:
    request_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO ai_usage (
                request_id,provider,model,input_tokens,output_tokens,
                estimated_cost_gbp,request_latency_ms,success,failure_type,
                retry_count,case_id,snapshot_id,proposal_id,fallback_used
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                request_id,
                provider,
                model,
                input_tokens,
                output_tokens,
                estimated_cost_gbp,
                latency_ms,
                success,
                failure_type,
                retry_count,
                case_id,
                snapshot_id,
                proposal_id,
                fallback_used,
            ),
        )
    return request_id


async def store_snapshot(
    conn: psycopg.AsyncConnection, *, case_id: str, snapshot: SnapshotResult
) -> None:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO ai_snapshots (
                snapshot_id,case_id,snapshot_hash,snapshot_size_bytes,
                estimated_tokens,trimmed,trimmed_fields,source_event_ids,
                source_profile_version
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                snapshot.snapshot_id,
                case_id,
                snapshot.snapshot_hash,
                snapshot.snapshot_size_bytes,
                snapshot.estimated_tokens,
                snapshot.trimmed,
                Jsonb(list(snapshot.trimmed_fields)),
                Jsonb(list(snapshot.source_event_ids)),
                snapshot.source_profile_version,
            ),
        )


async def store_proposal(
    conn: psycopg.AsyncConnection,
    *,
    proposal: Proposal,
    provider_model: str,
) -> None:
    del provider_model  # provider/model usage is stored in ai_usage, not proposal content
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO ai_proposals (
                proposal_id,schema_version,case_id,snapshot_id,strategy_phase,action_type,params,
                rationale,confidence,supporting_event_ids,expected_effect,
                rollback_required,policy_reference,expires_at
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                proposal.proposal_id,
                proposal.schema_version,
                proposal.case_id,
                proposal.snapshot_id,
                proposal.strategy_phase,
                proposal.action_type,
                Jsonb(proposal.params),
                proposal.rationale,
                proposal.confidence,
                Jsonb(proposal.supporting_event_ids),
                proposal.expected_effect,
                proposal.rollback_required,
                proposal.policy_reference,
                proposal.expires_at,
            ),
        )


async def store_policy_decision(
    conn: psycopg.AsyncConnection,
    *,
    proposal: Proposal,
    result: PolicyResult,
    analyst_approval: bool | None,
) -> str:
    decision_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO policy_decisions (
                decision_id,case_id,proposal_id,policy_version,decision,
                reason_codes,constraints,analyst_approval
            ) VALUES (%s,%s,%s,%s,%s,%s,'{}'::jsonb,%s)
            """,
            (
                decision_id,
                proposal.case_id,
                proposal.proposal_id,
                result.policy_version,
                result.decision.value,
                Jsonb(list(result.reason_codes)),
                analyst_approval,
            ),
        )
        event = build_event(
            event_type="policy.decision",
            schema_version="1.0",
            payload={
                "decision_id": decision_id,
                "case_id": proposal.case_id,
                "proposal_id": proposal.proposal_id,
                "decision": result.decision.value,
                "reason_codes": list(result.reason_codes),
                "policy_version": result.policy_version,
            },
            source_id="mirage-worker.policy",
            sequence=0,
            actor_type="SYSTEM",
            classification="INTERNAL",
            case_id=proposal.case_id,
        )
        validated = validate_event(event)
        await cur.execute(
            "INSERT INTO outbox_events (event_id,topic,payload) VALUES (%s,%s,%s)",
            (
                event["event_id"],
                subject_for_event_type("policy.decision"),
                Jsonb(validated.envelope),
            ),
        )
        await cur.execute(
            """
            INSERT INTO audit_events
                (actor,actor_type,action,target,outcome,correlation_id,detail)
            VALUES ('mirage-worker.policy','SYSTEM','policy.decision',%s,%s,%s,%s)
            """,
            (
                proposal.proposal_id,
                "SUCCESS" if result.decision.value == "ALLOW" else "DENIED",
                decision_id,
                ",".join(result.reason_codes),
            ),
        )
    return decision_id
