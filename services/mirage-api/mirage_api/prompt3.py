"""Stage 9–10 authenticated dashboard, real-time, and report APIs."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field

from mirage_common.dashboard import DashboardProjector
from mirage_common.evidence import EvidenceService, export_eligibility
from mirage_common.reports import (
    REPORT_GENERATOR_VERSION,
    REPORT_SCHEMA_VERSION,
    REPORT_TEMPLATE_VERSION,
    verify_report_package,
)
from mirage_contracts.ulid import generate_ulid

READ_ROLES = ("platform_admin", "investigator", "operator", "auditor", "read_only")
GLOBAL_CASE_ROLES = frozenset({"platform_admin", "auditor"})
MAX_GRAPH_NODES = 5000
MAX_STREAM_BATCH = 100


class _StrictReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CollectionGapOverride(_StrictReportRequest):
    reason: str = Field(min_length=1, max_length=2048)
    missing_items: list[str] = Field(min_length=1, max_length=1000)
    policy_decision_id: str


class ReportCreateRequest(_StrictReportRequest):
    export_mode: Literal[
        "METADATA_ONLY", "SELECTED_EVIDENCE", "COMPLETE_CASE"
    ] = "METADATA_ONLY"
    selected_evidence_ids: list[str] = Field(default_factory=list, max_length=1000)
    collection_gap_override: CollectionGapOverride | None = None


def build_prompt3_router(
    *,
    state: Callable[[Request], Any],
    require_roles: Callable[..., Any],
    evidence_service: EvidenceService | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    dashboard_read = Depends(require_roles(*READ_ROLES))
    dashboard_operate = Depends(require_roles("platform_admin", "investigator", "operator"))
    report_create = Depends(require_roles("export", "platform_admin"))
    projector = DashboardProjector()

    async def require_case_access(
        request: Request,
        case_id: str,
        principal: Any,
        *,
        permission: str = "READ",
    ) -> None:
        if principal.roles.intersection(GLOBAL_CASE_ROLES):
            return
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT 1 FROM cases
                WHERE case_id=%s AND owner=%s
                UNION ALL
                SELECT 1 FROM dashboard_case_access
                WHERE case_id=%s AND subject=%s
                  AND permission IN (%s,'ADMIN')
                LIMIT 1
                """,
                (case_id, principal.username, case_id, principal.subject, permission),
            )
            allowed = await cur.fetchone()
        if allowed is None:
            # Deliberate 404 prevents case-ID enumeration across access boundaries.
            raise HTTPException(404, "case not found")

    async def ensure_projection(request: Request, case_id: str) -> None:
        s = state(request)
        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT 1 FROM dashboard_case_summary WHERE case_id=%s",
                    (case_id,),
                )
                present = await cur.fetchone()
            if present is None:
                try:
                    await projector.rebuild_case(conn, case_id)
                except ValueError as exc:
                    raise HTTPException(404, "case not found") from exc
                await conn.commit()

    @router.get("/dashboard/cases")
    async def dashboard_cases(request: Request, principal=dashboard_read) -> dict[str, Any]:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            if principal.roles.intersection(GLOBAL_CASE_ROLES):
                await cur.execute(
                    """
                    SELECT case_id,state,version,severity,owner,created_at
                    FROM cases ORDER BY created_at DESC LIMIT 500
                    """
                )
            else:
                await cur.execute(
                    """
                    SELECT DISTINCT c.case_id,c.state,c.version,c.severity,c.owner,c.created_at
                    FROM cases c
                    LEFT JOIN dashboard_case_access a
                      ON a.case_id=c.case_id AND a.subject=%s
                    WHERE c.owner=%s OR a.subject IS NOT NULL
                    ORDER BY c.created_at DESC LIMIT 500
                    """,
                    (principal.subject, principal.username),
                )
            rows = await cur.fetchall()
        return {
            "cases": [
                {
                    "case_id": row[0],
                    "state": row[1],
                    "version": row[2],
                    "severity": row[3],
                    "owner": row[4],
                    "created_at": _iso(row[5]),
                }
                for row in rows
            ]
        }

    @router.get("/dashboard/operations")
    async def operations_overview(request: Request, _principal=dashboard_read) -> dict[str, Any]:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT state,count(*) FROM cases GROUP BY state ORDER BY state
                """
            )
            by_state = dict(await cur.fetchall())
            await cur.execute(
                "SELECT severity,count(*) FROM cases GROUP BY severity ORDER BY severity"
            )
            by_severity = dict(await cur.fetchall())
            await cur.execute(
                """
                SELECT count(*) FILTER (WHERE status='ACTIVE'),
                       count(*) FILTER (
                           WHERE status='ACTIVE'
                             AND (last_seen_at IS NULL OR last_seen_at < now()-interval '90 seconds')
                       )
                FROM agents
                """
            )
            agent_counts = await cur.fetchone()
            await cur.execute(
                """
                SELECT count(*) FROM outbox_events
                WHERE published_at IS NULL AND attempts >= 5
                """
            )
            dead_letters = (await cur.fetchone())[0]
            await cur.execute(
                """
                SELECT count(*) FROM evidence_objects
                WHERE verification_status IN ('FAILED','MISSING','HASH_MISMATCH')
                """
            )
            evidence_failures = (await cur.fetchone())[0]
            await cur.execute(
                """
                SELECT notification_id,case_id,severity,category,title,detail,
                       acknowledged_at,created_at
                FROM dashboard_notifications
                ORDER BY created_at DESC LIMIT 50
                """
            )
            notifications = await cur.fetchall()
        return {
            "platform_health": (
                "DEGRADED" if dead_letters or evidence_failures else "HEALTHY"
            ),
            "open_cases": sum(by_state.values()) - by_state.get("DESTROYED", 0),
            "cases_by_state": by_state,
            "cases_by_severity": by_severity,
            "agent_health": {
                "active": agent_counts[0] if agent_counts else 0,
                "offline": agent_counts[1] if agent_counts else 0,
            },
            "nats_consumer_lag": {"status": "UNKNOWN", "source": "NATS monitoring"},
            "dead_letter_count": dead_letters,
            "evidence_verification_failures": evidence_failures,
            "ai_provider_status": "CONFIGURED",
            "ai_circuit_breaker_status": "SEE_CASE_AI_STATE",
            "artifact_scanner_health": "SEE_PLATFORM_HEALTH",
            "canary_collector_health": "SEE_PLATFORM_HEALTH",
            "recent_operational_alerts": [
                {
                    "notification_id": row[0],
                    "case_id": row[1],
                    "severity": row[2],
                    "category": row[3],
                    "title": row[4],
                    "detail": row[5],
                    "acknowledged_at": _iso(row[6]),
                    "created_at": _iso(row[7]),
                }
                for row in notifications
            ],
        }

    @router.get("/dashboard/cases/{case_id}")
    async def dashboard_case(
        case_id: str,
        request: Request,
        principal=dashboard_read,
        max_nodes: int = Query(default=1000, ge=1, le=MAX_GRAPH_NODES),
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        await ensure_projection(request, case_id)
        return await _read_case_model(state(request).pool, case_id, max_nodes=max_nodes)

    @router.get("/dashboard/cases/{case_id}/timeline")
    async def dashboard_timeline(
        case_id: str,
        request: Request,
        principal=dashboard_read,
        limit: int = Query(default=500, ge=1, le=2000),
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        await ensure_projection(request, case_id)
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT item_id,item_type,classification,label,description,case_id,
                       session_id,event_time,source_event_ids,source_references,
                       evidence_references,confidence,output_tag,display_metadata,
                       permissions,version
                FROM dashboard_timeline_items
                WHERE case_id=%s ORDER BY event_time,item_id LIMIT %s
                """,
                (case_id, limit),
            )
            rows = await cur.fetchall()
        return {"timeline": [_timeline_row(row) for row in rows]}

    @router.get("/dashboard/cases/{case_id}/graph")
    async def dashboard_graph(
        case_id: str,
        request: Request,
        principal=dashboard_read,
        session_id: str | None = None,
        node_type: Annotated[list[str] | None, Query()] = None,
        evidence_only: bool = False,
        max_nodes: int = Query(default=1000, ge=1, le=MAX_GRAPH_NODES),
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        await ensure_projection(request, case_id)
        return await _read_graph(
            state(request).pool,
            case_id,
            session_id=session_id,
            node_types=node_type or [],
            evidence_only=evidence_only,
            max_nodes=max_nodes,
        )

    @router.get("/dashboard/cases/{case_id}/evidence-board")
    async def evidence_board(
        case_id: str,
        request: Request,
        principal=dashboard_read,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT evidence_id,evidence_type,original_filename,media_type,size_bytes,
                       sha256,source_id,source_sequence,source_certificate_serial,
                       acquisition_time,s3_version_id,object_lock_mode,retention_until,
                       verification_status,classification,related_event_ids,
                       required_for_export
                FROM evidence_objects WHERE case_id=%s
                ORDER BY acquisition_time,evidence_id
                """,
                (case_id,),
            )
            rows = await cur.fetchall()
        return {
            "evidence": [
                {
                    "evidence_id": row[0],
                    "type": row[1],
                    "filename": row[2],
                    "media_type": row[3],
                    "size_bytes": row[4],
                    "sha256": row[5],
                    "source": row[6],
                    "sequence": row[7],
                    "certificate_serial": row[8],
                    "acquisition_time": _iso(row[9]),
                    "s3_version_id": row[10],
                    "object_lock": {
                        "mode": row[11],
                        "retention_until": _iso(row[12]),
                    },
                    "verification_status": row[13],
                    "classification": row[14],
                    "related_events": row[15],
                    "related_graph_nodes": [f"evidence_object:{row[0]}"],
                    "export_inclusion": row[16],
                }
                for row in rows
            ]
        }

    @router.get("/dashboard/cases/{case_id}/ai-state")
    async def ai_state(
        case_id: str,
        request: Request,
        principal=dashboard_read,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT p.proposal_id,p.strategy_phase,p.action_type,p.rationale,
                       p.confidence,p.supporting_event_ids,p.created_at,
                       s.snapshot_id,s.snapshot_hash,s.snapshot_size_bytes,
                       s.estimated_tokens,s.trimmed_fields,
                       d.decision_id,d.decision,d.reason_codes,d.policy_version
                FROM ai_proposals p
                JOIN ai_snapshots s ON s.snapshot_id=p.snapshot_id
                LEFT JOIN LATERAL (
                    SELECT * FROM policy_decisions
                    WHERE proposal_id=p.proposal_id ORDER BY created_at DESC LIMIT 1
                ) d ON TRUE
                WHERE p.case_id=%s ORDER BY p.created_at DESC LIMIT 1
                """,
                (case_id,),
            )
            row = await cur.fetchone()
            await cur.execute(
                """
                SELECT provider,model,sum(estimated_cost_gbp),count(*),
                       bool_or(fallback_used)
                FROM ai_usage WHERE case_id=%s GROUP BY provider,model
                ORDER BY count(*) DESC LIMIT 1
                """,
                (case_id,),
            )
            usage = await cur.fetchone()
        if row is None:
            return {"status": "EMPTY", "case_id": case_id}
        return {
            "status": "AVAILABLE",
            "case_id": case_id,
            "proposal": {
                "proposal_id": row[0],
                "strategy_phase": row[1],
                "action_type": row[2],
                "rationale": row[3],
                "confidence": row[4],
                "supporting_event_ids": row[5],
                "created_at": _iso(row[6]),
            },
            "snapshot": {
                "snapshot_id": row[7],
                "snapshot_hash": row[8],
                "size_bytes": row[9],
                "estimated_tokens": row[10],
                "trimmed_fields": row[11],
            },
            "policy": {
                "decision_id": row[12],
                "decision": row[13],
                "reason_codes": row[14],
                "policy_version": row[15],
            },
            "provider": usage[0] if usage else None,
            "model": usage[1] if usage else None,
            "cost_gbp": str(usage[2]) if usage else "0.000000",
            "request_count": usage[3] if usage else 0,
            "fallback_used": usage[4] if usage else False,
        }

    @router.get("/dashboard/cases/{case_id}/sandbox-state")
    async def sandbox_state(
        case_id: str,
        request: Request,
        principal=dashboard_read,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT sandbox_id,image_id,status,state_version,network_identity,
                       created_at,destroyed_at
                FROM sandbox_instances WHERE case_id=%s
                ORDER BY created_at DESC LIMIT 1
                """,
                (case_id,),
            )
            sandbox = await cur.fetchone()
            await cur.execute(
                """
                SELECT action_id,action_type,status,output_tag,created_at,completed_at,
                       rollback_action_id
                FROM sandbox_actions WHERE case_id=%s
                ORDER BY created_at DESC LIMIT 200
                """,
                (case_id,),
            )
            actions = await cur.fetchall()
        return {
            "sandbox": (
                {
                    "sandbox_id": sandbox[0],
                    "image_id": sandbox[1],
                    "state": sandbox[2],
                    "state_version": sandbox[3],
                    "network_identity": sandbox[4],
                    "agent_status": "UNKNOWN",
                    "controller_status": "UNKNOWN",
                    "spider_status": "UNKNOWN",
                    "build_manifest_hash": None,
                    "certificate_serial": None,
                    "created_at": _iso(sandbox[5]),
                    "destroyed_at": _iso(sandbox[6]),
                }
                if sandbox
                else None
            ),
            "action_journal": [
                {
                    "action_id": row[0],
                    "action_type": row[1],
                    "status": row[2],
                    "output_tag": row[3],
                    "created_at": _iso(row[4]),
                    "completed_at": _iso(row[5]),
                    "rollback_action_id": row[6],
                }
                for row in actions
            ],
        }

    @router.post("/dashboard/cases/{case_id}/rebuild")
    async def rebuild_dashboard_case(
        case_id: str,
        request: Request,
        principal=dashboard_operate,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal, permission="OPERATE")
        s = state(request)
        async with s.pool.connection() as conn:
            try:
                version = await projector.rebuild_case(conn, case_id)
            except ValueError as exc:
                raise HTTPException(404, "case not found") from exc
            await conn.commit()
        return {"case_id": case_id, "projection_version": version, "status": "CURRENT"}

    @router.post("/cases/{case_id}/reports", status_code=202)
    async def create_case_report(
        case_id: str,
        body: ReportCreateRequest,
        request: Request,
        principal=report_create,
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        if not 1 <= len(idempotency_key) <= 256:
            raise HTTPException(400, "Idempotency-Key must contain 1 to 256 characters")
        if body.export_mode == "SELECTED_EVIDENCE" and not body.selected_evidence_ids:
            raise HTTPException(422, "SELECTED_EVIDENCE requires selected_evidence_ids")
        if body.export_mode != "SELECTED_EVIDENCE" and body.selected_evidence_ids:
            raise HTTPException(
                422, "selected_evidence_ids is valid only for SELECTED_EVIDENCE"
            )
        s = state(request)
        async with s.pool.connection() as conn:
            eligible, reasons = await export_eligibility(conn, case_id=case_id)
            if not eligible and body.collection_gap_override is None:
                raise HTTPException(
                    409, {"code": "REPORT_NOT_ELIGIBLE", "reasons": reasons}
                )
            async with conn.cursor() as cur:
                if body.collection_gap_override is not None:
                    override = body.collection_gap_override
                    await cur.execute(
                        """
                        SELECT 1
                        FROM policy_decisions d
                        JOIN ai_proposals p ON p.proposal_id=d.proposal_id
                        WHERE d.decision_id=%s AND p.case_id=%s AND d.decision='ALLOW'
                        """,
                        (override.policy_decision_id, case_id),
                    )
                    if await cur.fetchone() is None:
                        raise HTTPException(
                            409, "collection-gap override lacks an ALLOW policy decision"
                        )
                if body.selected_evidence_ids:
                    await cur.execute(
                        """
                        SELECT evidence_id,verification_status
                        FROM evidence_objects
                        WHERE case_id=%s AND evidence_id=ANY(%s)
                        """,
                        (case_id, body.selected_evidence_ids),
                    )
                    selected = dict(await cur.fetchall())
                    absent = set(body.selected_evidence_ids) - set(selected)
                    unverified = {
                        item for item, status in selected.items() if status != "VERIFIED"
                    }
                    if absent or unverified:
                        raise HTTPException(
                            409,
                            {
                                "code": "SELECTED_EVIDENCE_NOT_ELIGIBLE",
                                "absent": sorted(absent),
                                "unverified": sorted(unverified),
                            },
                        )
                await cur.execute(
                    """
                    SELECT report_id,export_id,export_mode,status,progress,
                           template_version,report_schema_version,generator_version,
                           build_hash,source_projection_version,package_evidence_id,
                           package_sha256,verification_status,verification_errors,error,
                           created_by,created_at,started_at,completed_at
                    FROM case_reports WHERE case_id=%s AND idempotency_key=%s
                    """,
                    (case_id, idempotency_key),
                )
                existing = await cur.fetchone()
                if existing is not None:
                    return _report_row(existing)
                await cur.execute(
                    """
                    SELECT COALESCE(projection_version,version)
                    FROM dashboard_case_summary s
                    RIGHT JOIN cases c USING (case_id)
                    WHERE c.case_id=%s
                    """,
                    (case_id,),
                )
                projection = await cur.fetchone()
                if projection is None:
                    raise HTTPException(404, "case not found")
                report_id = generate_ulid()
                build_hash = _build_hash()
                override_json = (
                    body.collection_gap_override.model_dump(mode="json")
                    | {"actor": principal.username, "reasons_at_request": reasons}
                    if body.collection_gap_override
                    else None
                )
                await cur.execute(
                    """
                    INSERT INTO case_reports (
                        report_id,case_id,idempotency_key,export_mode,
                        selected_evidence_ids,template_version,report_schema_version,
                        generator_version,build_hash,source_projection_version,
                        created_by,collection_gap_override
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        report_id,
                        case_id,
                        idempotency_key,
                        body.export_mode,
                        Jsonb(sorted(set(body.selected_evidence_ids))),
                        REPORT_TEMPLATE_VERSION,
                        REPORT_SCHEMA_VERSION,
                        REPORT_GENERATOR_VERSION,
                        build_hash,
                        projection[0],
                        principal.username,
                        Jsonb(override_json) if override_json else None,
                    ),
                )
                await cur.execute(
                    """
                    INSERT INTO report_audit (report_id,actor,action,detail)
                    VALUES (%s,%s,'REPORT_REQUESTED',%s)
                    """,
                    (
                        report_id,
                        principal.username,
                        Jsonb(
                            {
                                "export_mode": body.export_mode,
                                "selected_evidence_ids": sorted(
                                    set(body.selected_evidence_ids)
                                ),
                                "collection_gap_override": override_json,
                            }
                        ),
                    ),
                )
                await cur.execute(
                    """
                    INSERT INTO audit_events
                        (actor,actor_type,action,target,outcome,correlation_id,detail)
                    VALUES (%s,'ANALYST','case.report.requested',%s,'SUCCESS',%s,%s)
                    """,
                    (
                        principal.username,
                        report_id,
                        report_id,
                        f"mode={body.export_mode}",
                    ),
                )
            await conn.commit()
        return {
            "report_id": report_id,
            "case_id": case_id,
            "status": "QUEUED",
            "progress": 0,
            "export_mode": body.export_mode,
            "build_hash": build_hash,
        }

    @router.get("/cases/{case_id}/reports")
    async def list_case_reports(
        case_id: str,
        request: Request,
        principal=dashboard_read,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                _REPORT_SELECT
                + " WHERE case_id=%s ORDER BY created_at DESC LIMIT 500",
                (case_id,),
            )
            rows = await cur.fetchall()
        return {"reports": [_report_row(row) for row in rows]}

    @router.get("/cases/{case_id}/reports/{report_id}")
    async def get_case_report(
        case_id: str,
        report_id: str,
        request: Request,
        principal=dashboard_read,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        row = await _get_report_row(state(request).pool, case_id, report_id)
        if row is None:
            raise HTTPException(404, "report not found")
        return _report_row(row)

    @router.post("/cases/{case_id}/reports/{report_id}/verify")
    async def verify_case_report(
        case_id: str,
        report_id: str,
        request: Request,
        principal=report_create,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        if evidence_service is None:
            raise HTTPException(503, "evidence storage adapter is not configured")
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT r.status,e.s3_bucket,e.s3_key,e.s3_version_id
                FROM case_reports r
                LEFT JOIN evidence_objects e ON e.evidence_id=r.package_evidence_id
                WHERE r.case_id=%s AND r.report_id=%s
                """,
                (case_id, report_id),
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(404, "report not found")
            if row[0] != "COMPLETED" or None in row[1:]:
                raise HTTPException(409, "report package is not ready")
            package_stream = await evidence_service.store.open(
                bucket=row[1], key=row[2], version_id=row[3]
            )
            try:
                package = package_stream.read()
            finally:
                package_stream.close()
            verification = verify_report_package(package)
            await cur.execute(
                """
                UPDATE case_reports
                SET verification_status=%s,verification_errors=%s
                WHERE report_id=%s
                """,
                (
                    "VERIFIED" if verification.valid else "FAILED",
                    Jsonb(list(verification.errors)),
                    report_id,
                ),
            )
            await cur.execute(
                """
                INSERT INTO report_audit (report_id,actor,action,detail)
                VALUES (%s,%s,'REPORT_VERIFIED',%s)
                """,
                (
                    report_id,
                    principal.username,
                    Jsonb(
                        {
                            "valid": verification.valid,
                            "errors": verification.errors,
                            "manifest_sha256": verification.manifest_sha256,
                        }
                    ),
                ),
            )
            await conn.commit()
        return {
            "report_id": report_id,
            "valid": verification.valid,
            "errors": verification.errors,
            "manifest_sha256": verification.manifest_sha256,
        }

    @router.post("/cases/{case_id}/reports/{report_id}/cancel")
    async def cancel_case_report(
        case_id: str,
        report_id: str,
        request: Request,
        principal=report_create,
    ) -> dict[str, Any]:
        await require_case_access(request, case_id, principal)
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT status FROM case_reports
                WHERE case_id=%s AND report_id=%s FOR UPDATE
                """,
                (case_id, report_id),
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(404, "report not found")
            if row[0] in {"COMPLETED", "FAILED", "CANCELLED"}:
                raise HTTPException(409, f"report is already {row[0]}")
            next_status = (
                "CANCELLED" if row[0] in {"QUEUED", "WAITING_FOR_EXPORT"} else "CANCEL_REQUESTED"
            )
            await cur.execute(
                """
                UPDATE case_reports
                SET status=%s,cancellation_requested_at=now(),
                    completed_at=CASE WHEN %s='CANCELLED' THEN now() ELSE completed_at END,
                    progress=CASE WHEN %s='CANCELLED' THEN 100 ELSE progress END
                WHERE report_id=%s
                """,
                (next_status, next_status, next_status, report_id),
            )
            await cur.execute(
                """
                INSERT INTO report_audit (report_id,actor,action,detail)
                VALUES (%s,%s,'REPORT_CANCELLATION_REQUESTED',%s)
                """,
                (report_id, principal.username, Jsonb({"next_status": next_status})),
            )
            await conn.commit()
        return {"report_id": report_id, "status": next_status}

    @router.get("/cases/{case_id}/reports/{report_id}/download")
    async def download_case_report(
        case_id: str,
        report_id: str,
        request: Request,
        principal=report_create,
        token: str | None = Query(default=None),
    ) -> Any:
        await require_case_access(request, case_id, principal)
        if evidence_service is None:
            raise HTTPException(503, "evidence storage adapter is not configured")
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT r.status,r.download_token_hash,r.download_token_expires_at,
                       r.download_token_used_at,e.s3_bucket,e.s3_key,e.s3_version_id
                FROM case_reports r
                LEFT JOIN evidence_objects e ON e.evidence_id=r.package_evidence_id
                WHERE r.case_id=%s AND r.report_id=%s FOR UPDATE
                """,
                (case_id, report_id),
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(404, "report not found")
            if row[0] != "COMPLETED" or None in row[4:]:
                raise HTTPException(409, "report package is not ready")
            if token is None:
                raw_token = secrets.token_urlsafe(32)
                expires_at = datetime.now(UTC) + timedelta(minutes=2)
                await cur.execute(
                    """
                    UPDATE case_reports
                    SET download_token_hash=%s,download_token_expires_at=%s,
                        download_token_used_at=NULL
                    WHERE report_id=%s
                    """,
                    (hashlib.sha256(raw_token.encode()).hexdigest(), expires_at, report_id),
                )
                await conn.commit()
                return {
                    "report_id": report_id,
                    "download_url": (
                        f"/api/v1/cases/{case_id}/reports/{report_id}/download"
                        f"?token={raw_token}"
                    ),
                    "expires_at": _iso(expires_at),
                    "single_use": True,
                }
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if (
                row[1] is None
                or not hmac.compare_digest(token_hash, row[1])
                or row[2] is None
                or row[2] <= datetime.now(UTC)
                or row[3] is not None
            ):
                raise HTTPException(410, "download token is invalid, expired, or already used")
            await cur.execute(
                """
                UPDATE case_reports SET download_token_used_at=now()
                WHERE report_id=%s
                """,
                (report_id,),
            )
            await cur.execute(
                """
                INSERT INTO report_audit (report_id,actor,action,detail)
                VALUES (%s,%s,'REPORT_DOWNLOADED',%s)
                """,
                (report_id, principal.username, Jsonb({"single_use": True})),
            )
            package_stream = await evidence_service.store.open(
                bucket=row[4], key=row[5], version_id=row[6]
            )
            await conn.commit()

        def chunks():
            try:
                while chunk := package_stream.read(1024 * 1024):
                    yield chunk
            finally:
                package_stream.close()

        return StreamingResponse(
            chunks(),
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="mirage-report-{report_id}.zip"'
                ),
                "Cache-Control": "no-store, private",
            },
        )

    @router.get("/dashboard/stream")
    async def dashboard_stream(
        request: Request,
        case_id: str,
        principal=dashboard_read,
        last_event_id_header: str | None = Header(default=None, alias="Last-Event-ID"),
        last_event_id_query: int | None = Query(default=None, alias="last_event_id"),
    ) -> StreamingResponse:
        await require_case_access(request, case_id, principal)
        try:
            resume_from = (
                int(last_event_id_header)
                if last_event_id_header is not None
                else int(last_event_id_query or 0)
            )
        except ValueError as exc:
            raise HTTPException(400, "Last-Event-ID must be an integer sequence") from exc
        roles = frozenset(principal.roles)
        s = state(request)

        async def events():
            cursor = max(0, resume_from)
            idle_ticks = 0
            while not await request.is_disconnected():
                async with s.pool.connection() as conn, conn.cursor() as cur:
                    await cur.execute(
                        """
                        SELECT sequence_id,update_id,update_type,case_id,
                               projection_version,event_time,payload,correlation_id,
                               minimum_role
                        FROM dashboard_realtime_updates
                        WHERE sequence_id>%s AND case_id=%s
                        ORDER BY sequence_id LIMIT %s
                        """,
                        (cursor, case_id, MAX_STREAM_BATCH + 1),
                    )
                    rows = await cur.fetchall()
                if len(rows) > MAX_STREAM_BATCH:
                    cursor = rows[-1][0]
                    payload = {
                        "update_id": rows[-1][1],
                        "update_type": "FULL_REFRESH_REQUIRED",
                        "case_id": case_id,
                        "projection_version": rows[-1][4],
                        "event_time": _iso(rows[-1][5]),
                        "payload": {"reason": "bounded_queue_overflow"},
                        "correlation_id": rows[-1][7],
                    }
                    yield _sse(cursor, "FULL_REFRESH_REQUIRED", payload)
                    continue
                delivered = False
                for row in rows:
                    cursor = row[0]
                    minimum_role = row[8]
                    if minimum_role and minimum_role not in roles and "platform_admin" not in roles:
                        continue
                    delivered = True
                    yield _sse(
                        cursor,
                        row[2],
                        {
                            "update_id": row[1],
                            "update_type": row[2],
                            "case_id": row[3],
                            "projection_version": row[4],
                            "event_time": _iso(row[5]),
                            "payload": row[6],
                            "correlation_id": row[7],
                        },
                    )
                if delivered:
                    idle_ticks = 0
                else:
                    idle_ticks += 1
                    if idle_ticks >= 30:
                        idle_ticks = 0
                        yield ": heartbeat\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return router


async def _read_case_model(pool: Any, case_id: str, *, max_nodes: int) -> dict[str, Any]:
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
            SELECT case_id,state,case_version,severity,confidence,owner,
                   active_session_count,evidence_verified_count,evidence_total_count,
                   unresolved_gap_count,export_eligible,projection_version,
                   freshness_status,projected_at,last_event_time
            FROM dashboard_case_summary WHERE case_id=%s
            """,
            (case_id,),
        )
        summary = await cur.fetchone()
        if summary is None:
            raise HTTPException(404, "case not found")
        await cur.execute(
            """
            SELECT item_id,item_type,classification,label,description,case_id,
                   session_id,event_time,source_event_ids,source_references,
                   evidence_references,confidence,output_tag,display_metadata,
                   permissions,version
            FROM dashboard_timeline_items WHERE case_id=%s
            ORDER BY event_time,item_id LIMIT 2000
            """,
            (case_id,),
        )
        timeline = [_timeline_row(row) for row in await cur.fetchall()]
        await cur.execute(
            """
            SELECT gap_detected,gap_from,gap_to FROM dashboard_projection_offsets
            WHERE projector_name='dashboard-v1' AND case_id=%s
            """,
            (case_id,),
        )
        offset = await cur.fetchone()
    graph = await _read_graph(pool, case_id, max_nodes=max_nodes)
    return {
        "schema_version": "1.0",
        "summary": {
            "case_id": summary[0],
            "state": summary[1],
            "version": summary[2],
            "severity": summary[3],
            "confidence": summary[4],
            "owner": summary[5],
            "active_session_count": summary[6],
            "evidence_verified_count": summary[7],
            "evidence_total_count": summary[8],
            "unresolved_gap_count": summary[9],
            "export_eligible": summary[10],
            "projection_version": summary[11],
        },
        "timeline": timeline,
        "graph": graph,
        "freshness": {
            "status": summary[12],
            "projection_version": summary[11],
            "projected_at": _iso(summary[13]),
            "last_event_time": _iso(summary[14]),
            "gap_detected": bool(offset and offset[0]),
            "gap_from": offset[1] if offset else None,
            "gap_to": offset[2] if offset else None,
        },
    }


async def _read_graph(
    pool: Any,
    case_id: str,
    *,
    session_id: str | None = None,
    node_types: list[str] | None = None,
    evidence_only: bool = False,
    max_nodes: int = 1000,
) -> dict[str, Any]:
    node_types = [item for item in (node_types or []) if item]
    conditions = ["case_id=%s"]
    params: list[Any] = [case_id]
    if session_id:
        conditions.append("(session_id=%s OR node_type='CASE')")
        params.append(session_id)
    if node_types:
        conditions.append("node_type=ANY(%s)")
        params.append(node_types)
    if evidence_only:
        conditions.append("jsonb_array_length(evidence_references)>0")
    where = sql.SQL(" AND ").join(sql.SQL(condition) for condition in conditions)
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            sql.SQL("SELECT count(*) FROM dashboard_graph_nodes WHERE {}").format(where),
            tuple(params),
        )
        total_nodes = (await cur.fetchone())[0]
        await cur.execute(
            sql.SQL(
                """
            SELECT node_id,node_type,label,case_id,session_id,event_time,
                   source_event_ids,source_references,evidence_references,
                   classification,confidence,output_tag,display_metadata,
                   permissions,version
            FROM dashboard_graph_nodes WHERE {}
            ORDER BY event_time,node_id LIMIT %s
            """,
            ).format(where),
            (*params, max_nodes),
        )
        nodes = [_node_row(row) for row in await cur.fetchall()]
        node_ids = [node["node_id"] for node in nodes]
        if node_ids:
            await cur.execute(
                """
                SELECT edge_id,edge_type,label,source_node_id,target_node_id,
                       case_id,session_id,event_time,source_event_ids,
                       source_references,evidence_references,classification,
                       confidence,output_tag,display_metadata,permissions,version
                FROM dashboard_graph_edges
                WHERE case_id=%s AND source_node_id=ANY(%s)
                  AND target_node_id=ANY(%s)
                ORDER BY event_time,edge_id
                """,
                (case_id, node_ids, node_ids),
            )
            edges = [_edge_row(row) for row in await cur.fetchall()]
        else:
            edges = []
        await cur.execute(
            "SELECT count(*) FROM dashboard_graph_edges WHERE case_id=%s",
            (case_id,),
        )
        total_edges = (await cur.fetchone())[0]
    return {
        "nodes": nodes,
        "edges": edges,
        "sampled": total_nodes > len(nodes),
        "total_nodes": total_nodes,
        "total_edges": total_edges,
    }


def _timeline_row(row: Any) -> dict[str, Any]:
    return dict(
        zip(
            (
                "item_id",
                "item_type",
                "classification",
                "label",
                "description",
                "case_id",
                "session_id",
                "event_time",
                "source_event_ids",
                "source_references",
                "evidence_references",
                "confidence",
                "output_tag",
                "display_metadata",
                "permissions",
                "version",
            ),
            (*row[:7], _iso(row[7]), *row[8:]),
            strict=True,
        )
    )


def _node_row(row: Any) -> dict[str, Any]:
    return dict(
        zip(
            (
                "node_id",
                "node_type",
                "label",
                "case_id",
                "session_id",
                "event_time",
                "source_event_ids",
                "source_references",
                "evidence_references",
                "classification",
                "confidence",
                "output_tag",
                "display_metadata",
                "permissions",
                "version",
            ),
            (*row[:5], _iso(row[5]), *row[6:]),
            strict=True,
        )
    )


def _edge_row(row: Any) -> dict[str, Any]:
    return dict(
        zip(
            (
                "edge_id",
                "edge_type",
                "label",
                "source_node_id",
                "target_node_id",
                "case_id",
                "session_id",
                "event_time",
                "source_event_ids",
                "source_references",
                "evidence_references",
                "classification",
                "confidence",
                "output_tag",
                "display_metadata",
                "permissions",
                "version",
            ),
            (*row[:7], _iso(row[7]), *row[8:]),
            strict=True,
        )
    )


def _sse(sequence_id: int, event_type: str, payload: dict[str, Any]) -> str:
    return (
        f"id: {sequence_id}\n"
        f"event: {event_type}\n"
        f"data: {json.dumps(payload, separators=(',', ':'), default=str)}\n\n"
    )


_REPORT_SELECT = """
SELECT report_id,export_id,export_mode,status,progress,
       template_version,report_schema_version,generator_version,
       build_hash,source_projection_version,package_evidence_id,
       package_sha256,verification_status,verification_errors,error,
       created_by,created_at,started_at,completed_at
FROM case_reports
"""


async def _get_report_row(pool: Any, case_id: str, report_id: str) -> Any:
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            _REPORT_SELECT + " WHERE case_id=%s AND report_id=%s",
            (case_id, report_id),
        )
        return await cur.fetchone()


def _report_row(row: Any) -> dict[str, Any]:
    return dict(
        zip(
            (
                "report_id",
                "export_id",
                "export_mode",
                "status",
                "progress",
                "template_version",
                "report_schema_version",
                "generator_version",
                "build_hash",
                "source_projection_version",
                "package_evidence_id",
                "package_sha256",
                "verification_status",
                "verification_errors",
                "error",
                "created_by",
                "created_at",
                "started_at",
                "completed_at",
            ),
            (*row[:16], _iso(row[16]), _iso(row[17]), _iso(row[18])),
            strict=True,
        )
    )


def _build_hash() -> str:
    configured = os.getenv("MIRAGE_BUILD_SHA", "").lower()
    if re_match := re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", configured):
        return re_match.group(0)
    return hashlib.sha256(b"mirage-development-unversioned-build").hexdigest()


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return str(value)
