"""Prompt 2 authenticated API surfaces. State-changing routes are audited."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field

from mirage_common.analyst import (
    AnalystChannelError,
    SlidingWindowRateLimiter,
    cancel_directive,
    channel_disabled,
    create_message,
    preview_message,
    set_channel_control,
    submit_directive,
)
from mirage_common.artifacts import ArtifactScanner, stage_upload
from mirage_common.canary import (
    InfrastructureSource,
    classify_callback,
    issue_canary_token,
    resolve_callback_source,
)
from mirage_common.evidence import (
    AcquisitionRequest,
    EvidenceNotFoundError,
    EvidenceService,
    export_eligibility,
)
from mirage_common.sandbox_actions import (
    SandboxNotFoundError,
    StateVersionConflictError,
    open_pending_action,
)
from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, canonical_json_bytes, validate_event
from mirage_contracts.ulid import generate_ulid


class _StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArtifactApprovalRequest(_StrictRequest):
    reason: str = Field(min_length=1, max_length=1024)
    classification: Literal["INERT", "CONTROLLED"]


class ArtifactDeploymentRequest(_StrictRequest):
    destination: str = Field(min_length=1, max_length=1024)


class CanaryTokenRequest(_StrictRequest):
    expires_at: datetime
    expected_usage: Literal["ONE_TIME", "REUSABLE"] = "ONE_TIME"


class DirectiveRequest(_StrictRequest):
    session_id: str | None = None
    objective: str = Field(min_length=1, max_length=512)
    priority: Literal["LOW", "NORMAL", "HIGH", "URGENT"] = "NORMAL"
    expires_at: datetime | None = None


class MessagePreviewRequest(_StrictRequest):
    surface: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=1, max_length=2048)


class MessageCreateRequest(MessagePreviewRequest):
    session_id: str
    preview_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_decision_id: str


class MessageConfirmationRequest(_StrictRequest):
    preview_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChannelControlRequest(_StrictRequest):
    reason: str = Field(min_length=1, max_length=1024)


class SignedCanaryCallbackRequest(_StrictRequest):
    payload: dict[str, Any]
    signature: str = Field(min_length=64, max_length=64)


def build_prompt2_router(
    *,
    state: Callable[[Request], Any],
    require_roles: Callable[..., Any],
    evidence_service: EvidenceService | None,
    artifact_scanner: ArtifactScanner | None,
    artifact_quarantine_dir: Path,
    canary_signing_key: bytes | None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    rate_limiter = SlidingWindowRateLimiter(
        {"analyst": 20, "case": 50, "session": 30, "surface": 15}
    )
    evidence_read = Depends(
        require_roles("investigator", "operator", "auditor", "platform_admin", "read_only")
    )
    evidence_verify = Depends(require_roles("investigator", "platform_admin"))
    export_role = Depends(require_roles("export", "platform_admin"))
    artifact_write = Depends(require_roles("investigator", "platform_admin"))
    analyst_role = Depends(require_roles("investigator", "platform_admin"))
    direct_intervention_role = Depends(
        require_roles("direct_intervention", "platform_admin")
    )
    analyst_admin = Depends(require_roles("emergency_control", "platform_admin"))

    @router.get("/cases/{case_id}/evidence")
    async def list_evidence(
        case_id: str,
        request: Request,
        _principal=evidence_read,
        limit: int = 200,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT evidence_id,session_id,evidence_type,source_id,source_sequence,
                       acquisition_time,stored_time,original_filename,media_type,size_bytes,
                       sha256,s3_bucket,s3_key,s3_version_id,object_lock_mode,retention_until,
                       verification_status,verified_at,verification_error,classification,
                       required_for_export
                FROM evidence_objects WHERE case_id=%s
                ORDER BY acquisition_time,evidence_id LIMIT %s
                """,
                (case_id, max(1, min(limit, 500))),
            )
            rows = await cur.fetchall()
        return {"evidence": [_evidence_row(row) for row in rows]}

    @router.get("/cases/{case_id}/evidence/{evidence_id}")
    async def get_evidence(
        case_id: str,
        evidence_id: str,
        request: Request,
        _principal=evidence_read,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT evidence_id,session_id,evidence_type,source_id,source_sequence,
                       acquisition_time,stored_time,original_filename,media_type,size_bytes,
                       sha256,s3_bucket,s3_key,s3_version_id,object_lock_mode,retention_until,
                       verification_status,verified_at,verification_error,classification,
                       required_for_export
                FROM evidence_objects WHERE case_id=%s AND evidence_id=%s
                """,
                (case_id, evidence_id),
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(404, "evidence not found")
            await cur.execute(
                """
                SELECT verification_id,reason,status,expected_sha256,calculated_sha256,
                       error,requested_by,attempted_at
                FROM evidence_verification_history WHERE evidence_id=%s
                ORDER BY attempted_at DESC
                """,
                (evidence_id,),
            )
            history = await cur.fetchall()
        return {
            **_evidence_row(row),
            "verification_history": [
                {
                    "verification_id": item[0],
                    "reason": item[1],
                    "status": item[2],
                    "expected_sha256": item[3],
                    "calculated_sha256": item[4],
                    "error": item[5],
                    "requested_by": item[6],
                    "attempted_at": item[7].isoformat(),
                }
                for item in history
            ],
        }

    @router.post("/cases/{case_id}/evidence/{evidence_id}/verify")
    async def verify_evidence(
        case_id: str,
        evidence_id: str,
        request: Request,
        principal=evidence_verify,
    ) -> dict:
        if evidence_service is None:
            raise HTTPException(503, "evidence storage adapter is not configured")
        s = state(request)
        async with s.pool.connection() as conn:
            try:
                status = await evidence_service.verify(
                    conn,
                    evidence_id=evidence_id,
                    reason="ANALYST_REQUEST",
                    requested_by=principal.username,
                )
            except EvidenceNotFoundError as exc:
                raise HTTPException(404, "evidence not found") from exc
            await conn.commit()
        return {"case_id": case_id, "evidence_id": evidence_id, "verification_status": status}

    @router.post("/cases/{case_id}/export")
    async def create_export(
        case_id: str,
        request: Request,
        principal=export_role,
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn:
            eligible, reasons = await export_eligibility(conn, case_id=case_id)
            if not eligible:
                raise HTTPException(409, {"code": "EXPORT_NOT_ELIGIBLE", "reasons": reasons})
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT export_id,export_version,verification_status
                    FROM evidence_exports
                    WHERE case_id=%s AND limitations @> %s::jsonb
                    """,
                    (case_id, Jsonb([f"idempotency:{idempotency_key}"])),
                )
                existing = await cur.fetchone()
                if existing:
                    return {
                        "export_id": existing[0],
                        "export_version": existing[1],
                        "verification_status": existing[2],
                    }
                await cur.execute(
                    "SELECT COALESCE(max(export_version),0)+1 FROM evidence_exports WHERE case_id=%s",
                    (case_id,),
                )
                version = (await cur.fetchone())[0]
                export_id = generate_ulid()
                await cur.execute(
                    """
                    INSERT INTO evidence_exports (
                        export_id,case_id,export_version,manifest_version,
                        verification_status,created_by,limitations
                    ) VALUES (%s,%s,%s,'1.0','PENDING',%s,%s)
                    """,
                    (
                        export_id,
                        case_id,
                        version,
                        principal.username,
                        Jsonb(
                            [
                                f"idempotency:{idempotency_key}",
                                "export queued for mirage-report-worker signing",
                            ]
                        ),
                    ),
                )
                await cur.execute(
                    """
                    INSERT INTO audit_events
                        (actor,actor_type,action,target,outcome,correlation_id,detail)
                    VALUES (%s,'ANALYST','evidence.export.requested',%s,'SUCCESS',%s,%s)
                    """,
                    (principal.username, export_id, export_id, f"version={version}"),
                )
            await conn.commit()
        return {
            "export_id": export_id,
            "export_version": version,
            "verification_status": "PENDING",
        }

    @router.get("/cases/{case_id}/exports")
    async def list_exports(
        case_id: str,
        request: Request,
        _principal=evidence_read,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT export_id,export_version,manifest_sha256,signing_algorithm,
                       verification_status,created_by,created_at,verified_at
                FROM evidence_exports WHERE case_id=%s ORDER BY export_version
                """,
                (case_id,),
            )
            rows = await cur.fetchall()
        return {"exports": [_export_row(row) for row in rows]}

    @router.get("/cases/{case_id}/exports/{export_id}")
    async def get_export(
        case_id: str,
        export_id: str,
        request: Request,
        _principal=evidence_read,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT export_id,export_version,manifest_sha256,signing_algorithm,
                       verification_status,created_by,created_at,verified_at
                FROM evidence_exports WHERE case_id=%s AND export_id=%s
                """,
                (case_id, export_id),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(404, "export not found")
        return _export_row(row)

    @router.post("/cases/{case_id}/exports/{export_id}/verify")
    async def request_export_verification(
        case_id: str,
        export_id: str,
        request: Request,
        principal=export_role,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE evidence_exports SET verification_status='PENDING',
                    verification_error=NULL,verified_at=NULL
                WHERE case_id=%s AND export_id=%s RETURNING export_id
                """,
                (case_id, export_id),
            )
            if await cur.fetchone() is None:
                raise HTTPException(404, "export not found")
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'ANALYST','evidence.export.verification_requested',
                        %s,'SUCCESS',%s,'queued')
                """,
                (principal.username, export_id, generate_ulid()),
            )
            await conn.commit()
        return {"export_id": export_id, "verification_status": "PENDING"}

    @router.post("/artifacts")
    async def upload_artifact(
        request: Request,
        file: UploadFile,
        principal=artifact_write,
        case_id: str | None = None,
    ) -> dict:
        staged = stage_upload(
            file.file,
            original_filename=file.filename or "unnamed",
            quarantine_dir=artifact_quarantine_dir,
            max_upload_mb=artifact_scanner.config.max_upload_mb if artifact_scanner else 250,
        )
        result = artifact_scanner.scan(staged) if artifact_scanner else None
        artifact_id = generate_ulid()
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO artifacts (
                    artifact_id,case_id,original_filename,sanitised_filename,media_type,
                    detected_type,size_bytes,sha256,scan_status,clamav_result,
                    yara_matches,oletools_result,archive_metadata,quarantine_location,
                    observation_levels,scanned_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                """,
                (
                    artifact_id,
                    case_id,
                    file.filename or "unnamed",
                    staged.sanitised_filename,
                    file.content_type or "application/octet-stream",
                    result.detected_type if result else None,
                    staged.size_bytes,
                    staged.sha256,
                    result.status if result else "UPLOADED",
                    Jsonb(result.clamav_result) if result else None,
                    Jsonb(list(result.yara_matches)) if result else Jsonb([]),
                    Jsonb(result.oletools_result) if result else None,
                    Jsonb(result.archive_metadata) if result else None,
                    str(staged.path),
                    Jsonb(list(result.observation_levels)) if result else Jsonb([]),
                ),
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'ANALYST','artifact.uploaded',%s,%s,%s,%s)
                """,
                (
                    principal.username,
                    artifact_id,
                    "SUCCESS" if result is None or result.status != "FAILED" else "FAILURE",
                    artifact_id,
                    result.status if result else "UPLOADED",
                ),
            )
            await conn.commit()
        return {
            "artifact_id": artifact_id,
            "sha256": staged.sha256,
            "size_bytes": staged.size_bytes,
            "scan_status": result.status if result else "UPLOADED",
            "observation_levels": result.observation_levels if result else (),
            "limitations": result.limitations if result else ("queued for mirage-artifact-scanner",),
        }

    @router.get("/artifacts/{artifact_id}")
    async def get_artifact(
        artifact_id: str, request: Request, _principal=evidence_read
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT to_jsonb(artifacts) FROM artifacts WHERE artifact_id=%s", (artifact_id,))
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(404, "artifact not found")
        return row[0]

    @router.post("/artifacts/{artifact_id}/approve")
    async def approve_artifact(
        artifact_id: str,
        body: ArtifactApprovalRequest,
        request: Request,
        principal=artifact_write,
    ) -> dict:
        classification = body.classification
        reason = body.reason
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE artifacts SET approved_for_deployment=TRUE,
                    approval_reason=%s,approved_by=%s,artifact_classification=%s,
                    scan_status='APPROVED'
                WHERE artifact_id=%s AND scan_status IN ('CLEAN','SUSPICIOUS')
                RETURNING artifact_id
                """,
                (
                    reason.strip(),
                    principal.username,
                    classification,
                    artifact_id,
                ),
            )
            if await cur.fetchone() is None:
                raise HTTPException(409, "only CLEAN/SUSPICIOUS artifacts may be approved")
            await conn.commit()
        return {"artifact_id": artifact_id, "scan_status": "APPROVED"}

    @router.post("/cases/{case_id}/artifacts/{artifact_id}/deploy")
    async def deploy_artifact(
        case_id: str,
        artifact_id: str,
        body: ArtifactDeploymentRequest,
        request: Request,
        principal=artifact_write,
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> dict:
        destination = body.destination
        if not _approved_destination(destination):
            raise HTTPException(400, "destination is outside approved mutation roots")
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT deployment_id,status FROM artifact_deployments
                WHERE case_id=%s AND idempotency_key=%s
                """,
                (case_id, idempotency_key),
            )
            existing = await cur.fetchone()
            if existing:
                return {"deployment_id": existing[0], "status": existing[1]}
            await cur.execute(
                """
                SELECT deployment_id FROM artifact_deployments
                WHERE case_id=%s AND artifact_id=%s
                  AND status IN ('PENDING','DEPLOYED','ROLLBACK_PENDING')
                LIMIT 1
                """,
                (case_id, artifact_id),
            )
            active_deployment = await cur.fetchone()
            if active_deployment is not None:
                raise HTTPException(
                    409,
                    f"artifact already has active deployment {active_deployment[0]}",
                )
            await cur.execute(
                """
                SELECT sha256,approved_for_deployment,scan_status,
                       artifact_classification
                FROM artifacts
                WHERE artifact_id=%s AND (case_id IS NULL OR case_id=%s)
                """,
                (artifact_id, case_id),
            )
            artifact = await cur.fetchone()
            if artifact is None:
                raise HTTPException(404, "artifact not found")
            if not artifact[1] or artifact[2] != "APPROVED":
                raise HTTPException(409, "artifact is not approved")
            if artifact[3] not in {"INERT", "CONTROLLED"}:
                raise HTTPException(409, "artifact classification is not deployable")
            await cur.execute("SELECT 1 FROM cases WHERE case_id=%s", (case_id,))
            if await cur.fetchone() is None:
                raise HTTPException(404, "case not found")
            deployment_id = generate_ulid()
            expires_at = datetime.now(UTC) + timedelta(minutes=5)
            download_token = secrets.token_urlsafe(32)
            download_token_hash = hashlib.sha256(download_token.encode()).hexdigest()
            download_url = (
                f"{str(request.base_url).rstrip('/')}/api/v1/internal/artifacts/"
                f"{deployment_id}/download?token={download_token}"
            )
            await cur.execute(
                """
                INSERT INTO artifact_deployments (
                    deployment_id,case_id,artifact_id,destination,
                    download_url_expires_at,download_token_hash,status,expected_sha256,
                    idempotency_key,created_by
                ) VALUES (%s,%s,%s,%s,%s,%s,'PENDING',%s,%s,%s)
                """,
                (
                    deployment_id,
                    case_id,
                    artifact_id,
                    destination,
                    expires_at,
                    download_token_hash,
                    artifact[0],
                    idempotency_key,
                    principal.username,
                ),
            )
            decision_id = generate_ulid()
            await cur.execute(
                """
                INSERT INTO policy_decisions (
                    decision_id,case_id,proposal_id,policy_version,decision,
                    reason_codes,constraints,analyst_approval
                ) VALUES (%s,%s,NULL,'artifact-deployment-1.0','ALLOW',%s,%s,TRUE)
                """,
                (
                    decision_id,
                    case_id,
                    Jsonb(["ALLOW_APPROVED_CONTROLLED_ARTIFACT"]),
                    Jsonb({"destination": destination, "artifact_id": artifact_id}),
                ),
            )
            policy_event = build_event(
                event_type="policy.decision",
                schema_version="1.0",
                payload={
                    "decision_id": decision_id,
                    "case_id": case_id,
                    "proposal_id": None,
                    "decision": "ALLOW",
                    "reason_codes": ["ALLOW_APPROVED_CONTROLLED_ARTIFACT"],
                    "policy_version": "artifact-deployment-1.0",
                },
                source_id="mirage-api.artifact-policy",
                sequence=0,
                actor_type="SYSTEM",
                classification="INTERNAL",
                case_id=case_id,
            )
            validated_policy_event = validate_event(policy_event)
            await cur.execute(
                "INSERT INTO outbox_events (event_id,topic,payload) VALUES (%s,%s,%s)",
                (
                    policy_event["event_id"],
                    subject_for_event_type("policy.decision"),
                    Jsonb(validated_policy_event.envelope),
                ),
            )
            await cur.execute(
                """
                SELECT s.sandbox_id,si.state_version
                FROM sessions s
                JOIN sandbox_instances si ON si.sandbox_id=s.sandbox_id
                WHERE s.case_id=%s AND s.status='ACTIVE' AND si.status='ACTIVE'
                ORDER BY s.created_at DESC LIMIT 1
                """,
                (case_id,),
            )
            sandbox = await cur.fetchone()
            if sandbox is None:
                raise HTTPException(409, "case has no active sandbox session")
            pending_action = await open_pending_action(
                conn,
                sandbox_id=sandbox[0],
                case_id=case_id,
                action_type="PLACE_ARTIFACT",
                action_params={
                    "artifact_id": artifact_id,
                    "destination": destination,
                    "download_url": download_url,
                    "download_url_expires_at": expires_at.isoformat(),
                    "expected_sha256": artifact[0],
                },
                expected_state_version=sandbox[1],
                issued_by="ANALYST",
                policy_decision_id=decision_id,
            )
            await cur.execute(
                """
                UPDATE artifact_deployments SET sandbox_action_id=%s
                WHERE deployment_id=%s
                """,
                (pending_action.action_id, deployment_id),
            )
            await conn.commit()
        return {
            "deployment_id": deployment_id,
            "status": "PENDING",
            "download_url_expires_at": expires_at.isoformat(),
            "download_url": download_url,
            "expected_sha256": artifact[0],
            "policy_decision_id": decision_id,
            "sandbox_action_id": pending_action.action_id,
        }

    @router.get("/internal/artifacts/{deployment_id}/download", include_in_schema=False)
    async def download_artifact(
        deployment_id: str,
        token: str,
        request: Request,
    ) -> FileResponse:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT a.quarantine_location,a.sanitised_filename,a.sha256
                FROM artifact_deployments d
                JOIN artifacts a ON a.artifact_id=d.artifact_id
                WHERE d.deployment_id=%s AND d.download_token_hash=%s
                  AND d.status='PENDING' AND d.download_consumed_at IS NULL
                  AND d.download_url_expires_at > now()
                FOR UPDATE OF d
                """,
                (deployment_id, token_hash),
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(410, "download token is invalid, expired, or consumed")
            path = Path(row[0])
            if not path.is_file() or _sha256_path(path) != row[2]:
                raise HTTPException(409, "quarantined artifact is missing or has changed")
            await cur.execute(
                "UPDATE artifact_deployments SET download_consumed_at=now() WHERE deployment_id=%s",
                (deployment_id,),
            )
            await conn.commit()
        return FileResponse(
            path,
            media_type="application/octet-stream",
            filename=row[1],
            headers={"X-Mirage-Artifact-SHA256": row[2]},
        )

    @router.get("/cases/{case_id}/artifacts")
    async def list_case_artifacts(
        case_id: str, request: Request, _principal=evidence_read
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT to_jsonb(artifacts) FROM artifacts WHERE case_id=%s ORDER BY created_at",
                (case_id,),
            )
            rows = await cur.fetchall()
        return {"artifacts": [row[0] for row in rows]}

    @router.post("/cases/{case_id}/artifacts/{artifact_id}/revoke")
    async def revoke_artifact(
        case_id: str,
        artifact_id: str,
        request: Request,
        principal=artifact_write,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT d.deployment_id,d.status,d.sandbox_action_id,
                       sa.sandbox_id,si.state_version
                FROM artifact_deployments d
                LEFT JOIN sandbox_actions sa ON sa.action_id=d.sandbox_action_id
                LEFT JOIN sandbox_instances si ON si.sandbox_id=sa.sandbox_id
                WHERE case_id=%s AND artifact_id=%s
                  AND status IN ('PENDING','DEPLOYED')
                FOR UPDATE OF d
                """,
                (case_id, artifact_id),
            )
            deployments = await cur.fetchall()
            if len(deployments) > 1:
                raise HTTPException(
                    409,
                    "multiple active deployments require operator reconciliation",
                )
            rollback_action_id: str | None = None
            response_status = "REVOKED"
            if deployments:
                deployment_id, deployment_status, target_action_id, sandbox_id, version = (
                    deployments[0]
                )
                if deployment_status == "DEPLOYED":
                    if target_action_id is None or sandbox_id is None or version is None:
                        raise HTTPException(
                            409,
                            "deployed artifact has no recoverable sandbox action journal",
                        )
                    decision_id = generate_ulid()
                    await cur.execute(
                        """
                        INSERT INTO policy_decisions (
                            decision_id,case_id,policy_version,decision,reason_codes,
                            constraints,analyst_approval
                        ) VALUES (
                            %s,%s,'artifact-revocation-1.0','ALLOW',%s,%s,TRUE
                        )
                        """,
                        (
                            decision_id,
                            case_id,
                            Jsonb(["ALLOW_ANALYST_ARTIFACT_ROLLBACK"]),
                            Jsonb(
                                {
                                    "artifact_id": artifact_id,
                                    "deployment_id": deployment_id,
                                    "target_action_id": target_action_id,
                                }
                            ),
                        ),
                    )
                    try:
                        rollback = await open_pending_action(
                            conn,
                            sandbox_id=sandbox_id,
                            case_id=case_id,
                            action_type="ROLLBACK_ACTION",
                            action_params={"target_action_id": target_action_id},
                            expected_state_version=version,
                            issued_by="ANALYST",
                            policy_decision_id=decision_id,
                        )
                    except (SandboxNotFoundError, StateVersionConflictError) as exc:
                        raise HTTPException(409, str(exc)) from exc
                    rollback_action_id = rollback.action_id
                    response_status = "ROLLBACK_PENDING"
                    await cur.execute(
                        """
                        UPDATE artifact_deployments
                        SET status='ROLLBACK_PENDING',rollback_action_id=%s,
                            completed_at=NULL
                        WHERE deployment_id=%s
                        """,
                        (rollback_action_id, deployment_id),
                    )
                else:
                    await cur.execute(
                        """
                        UPDATE artifact_deployments
                        SET status='REVOKED',completed_at=now()
                        WHERE deployment_id=%s
                        """,
                        (deployment_id,),
                    )
            await cur.execute(
                """
                UPDATE artifacts SET approved_for_deployment=FALSE,
                    deployment_status=%s
                WHERE artifact_id=%s
                """,
                (response_status, artifact_id),
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'ANALYST','artifact.revoked',%s,'SUCCESS',%s,%s)
                """,
                (
                    principal.username,
                    artifact_id,
                    generate_ulid(),
                    (
                        f"rollback action {rollback_action_id} queued"
                        if rollback_action_id
                        else "pending deployment revoked"
                    ),
                ),
            )
            await conn.commit()
        return {
            "artifact_id": artifact_id,
            "status": response_status,
            "rollback_action_id": rollback_action_id,
        }

    @router.post("/cases/{case_id}/artifacts/{artifact_id}/canary-tokens")
    async def create_artifact_canary_token(
        case_id: str,
        artifact_id: str,
        body: CanaryTokenRequest,
        request: Request,
        principal=artifact_write,
    ) -> dict:
        try:
            expires_at = body.expires_at
            s = state(request)
            async with s.pool.connection() as conn:
                token = await issue_canary_token(
                    conn,
                    case_id=case_id,
                    artifact_id=artifact_id,
                    expires_at=expires_at,
                    expected_usage=body.expected_usage,
                )
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        INSERT INTO audit_events
                            (actor,actor_type,action,target,outcome,correlation_id,detail)
                        VALUES (%s,'ANALYST','canary.token.created',%s,'SUCCESS',%s,%s)
                        """,
                        (
                            principal.username,
                            token.token_id,
                            token.token_id,
                            token.expected_usage,
                        ),
                    )
                await conn.commit()
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return {
            "token_id": token.token_id,
            "public_token": token.public_token,
            "expires_at": token.expires_at.isoformat(),
            "expected_usage": token.expected_usage,
        }

    @router.post("/cases/{case_id}/canary-tokens/{token_id}/revoke")
    async def revoke_canary_token(
        case_id: str,
        token_id: str,
        request: Request,
        principal=artifact_write,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE canary_tokens SET status='REVOKED',revoked_at=now()
                WHERE case_id=%s AND token_id=%s AND status IN ('ACTIVE','USED')
                RETURNING token_id
                """,
                (case_id, token_id),
            )
            if await cur.fetchone() is None:
                raise HTTPException(409, "canary token cannot be revoked")
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'ANALYST','canary.token.revoked',%s,'SUCCESS',%s,'revoked')
                """,
                (principal.username, token_id, generate_ulid()),
            )
            await conn.commit()
        return {"token_id": token_id, "status": "REVOKED"}

    @router.get("/cases/{case_id}/canary-callbacks")
    async def list_canary_callbacks(
        case_id: str,
        request: Request,
        _principal=evidence_read,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT c.callback_id,c.classification,c.confidence,
                       CASE WHEN c.classification='EXTERNAL_CALLBACK'
                            THEN c.network_indicator ELSE NULL END,
                       c.uncertainty,c.token_id,t.artifact_id,c.callback_time,
                       c.evidence_id,c.rule_version,c.analyst_review_required
                FROM canary_callbacks c
                JOIN canary_tokens t ON t.token_id=c.token_id
                WHERE t.case_id=%s
                ORDER BY c.callback_time,c.callback_id
                """,
                (case_id,),
            )
            rows = await cur.fetchall()
        fields = (
            "callback_id",
            "classification",
            "confidence",
            "network_indicator",
            "uncertainty",
            "token_id",
            "artifact_id",
            "callback_time",
            "evidence_id",
            "rule_version",
            "analyst_review_required",
        )
        callbacks = [dict(zip(fields, row, strict=True)) for row in rows]
        for callback in callbacks:
            callback["callback_time"] = callback["callback_time"].isoformat()
        return {"callbacks": callbacks}

    @router.post("/cases/{case_id}/directive")
    async def directive(
        case_id: str,
        body: DirectiveRequest,
        request: Request,
        principal=analyst_role,
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> dict:
        s = state(request)
        if not rate_limiter.consume(
            dimensions={
                "analyst": principal.username,
                "case": case_id,
                "session": body.session_id or case_id,
                "surface": "DIRECTIVE",
            }
        ):
            raise HTTPException(429, "analyst directive rate limit exceeded")
        try:
            async with s.pool.connection() as conn:
                result = await submit_directive(
                    conn,
                    case_id=case_id,
                    session_id=body.session_id,
                    objective=body.objective,
                    priority=body.priority,
                    created_by=principal.username,
                    expires_at=body.expires_at,
                    idempotency_key=idempotency_key,
                )
                await conn.commit()
        except (AnalystChannelError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return {
            "directive_id": result.directive_id,
            "status": result.status,
            "objective": result.objective,
        }

    @router.get("/cases/{case_id}/directives")
    async def list_directives(
        case_id: str, request: Request, _principal=analyst_role
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE analyst_directives SET status='EXPIRED'
                WHERE case_id=%s AND expires_at <= now()
                  AND status IN ('SUBMITTED','ACKNOWLEDGED','QUEUED')
                """,
                (case_id,),
            )
            await cur.execute(
                "SELECT to_jsonb(analyst_directives) FROM analyst_directives WHERE case_id=%s ORDER BY created_at",
                (case_id,),
            )
            rows = await cur.fetchall()
            await conn.commit()
        return {"directives": [row[0] for row in rows]}

    @router.post("/cases/{case_id}/directives/{directive_id}/cancel")
    async def cancel(
        case_id: str,
        directive_id: str,
        request: Request,
        principal=analyst_role,
    ) -> dict:
        s = state(request)
        try:
            async with s.pool.connection() as conn:
                status = await cancel_directive(
                    conn, case_id=case_id, directive_id=directive_id, actor=principal.username
                )
                await conn.commit()
        except AnalystChannelError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"directive_id": directive_id, "status": status}

    @router.post("/cases/{case_id}/messages/preview")
    async def message_preview(
        case_id: str,
        body: MessagePreviewRequest,
        _principal=direct_intervention_role,
    ) -> dict:
        try:
            result = preview_message(
                case_id=case_id,
                surface=body.surface,
                content=body.content,
            )
        except AnalystChannelError as exc:
            raise HTTPException(400, str(exc)) from exc
        return result.__dict__

    @router.post("/cases/{case_id}/messages")
    async def message(
        case_id: str,
        body: MessageCreateRequest,
        request: Request,
        principal=direct_intervention_role,
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> dict:
        dimensions = {
            "analyst": principal.username,
            "case": case_id,
            "session": body.session_id,
            "surface": body.surface,
        }
        if not rate_limiter.consume(dimensions=dimensions):
            raise HTTPException(429, "analyst message rate limit exceeded")
        s = state(request)
        try:
            async with s.pool.connection() as conn:
                result = await create_message(
                    conn,
                    case_id=case_id,
                    session_id=body.session_id,
                    author_id=principal.username,
                    content=body.content,
                    surface=body.surface,
                    supplied_preview_hash=body.preview_hash,
                    policy_decision_id=body.policy_decision_id,
                    idempotency_key=idempotency_key,
                )
                await conn.commit()
        except AnalystChannelError as exc:
            raise HTTPException(409, str(exc)) from exc
        return result

    @router.post("/cases/{case_id}/messages/{message_id}/confirm")
    async def confirm_message(
        case_id: str,
        message_id: str,
        body: MessageConfirmationRequest,
        request: Request,
        principal=direct_intervention_role,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            if await channel_disabled(conn, case_id=case_id):
                raise HTTPException(409, "analyst direct-message channel is disabled")
            await cur.execute(
                """
                UPDATE analyst_messages SET status='APPROVED',confirmed_at=now()
                WHERE case_id=%s AND message_id=%s AND author_id=%s
                  AND status='PENDING_CONFIRMATION' AND preview_hash=%s
                RETURNING message_id
                """,
                (case_id, message_id, principal.username, body.preview_hash),
            )
            if await cur.fetchone() is None:
                raise HTTPException(409, "message confirmation rejected")
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'ANALYST','analyst.message.confirmed',%s,'SUCCESS',%s,'confirmed')
                """,
                (principal.username, message_id, generate_ulid()),
            )
            await conn.commit()
        return {"message_id": message_id, "status": "APPROVED"}

    @router.post("/cases/{case_id}/messages/{message_id}/cancel")
    async def cancel_message(
        case_id: str,
        message_id: str,
        request: Request,
        principal=direct_intervention_role,
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE analyst_messages SET status='CANCELLED'
                WHERE case_id=%s AND message_id=%s AND author_id=%s
                  AND status IN ('DRAFT','PREVIEWED','PENDING_CONFIRMATION','APPROVED')
                RETURNING message_id
                """,
                (case_id, message_id, principal.username),
            )
            if await cur.fetchone() is None:
                raise HTTPException(409, "message cannot be cancelled")
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'ANALYST','analyst.message.cancelled',%s,'SUCCESS',%s,'cancelled')
                """,
                (principal.username, message_id, generate_ulid()),
            )
            await conn.commit()
        return {"message_id": message_id, "status": "CANCELLED"}

    @router.get("/cases/{case_id}/messages")
    async def list_messages(
        case_id: str, request: Request, _principal=direct_intervention_role
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT to_jsonb(analyst_messages) FROM analyst_messages WHERE case_id=%s ORDER BY created_at",
                (case_id,),
            )
            rows = await cur.fetchall()
        return {"messages": [row[0] for row in rows]}

    @router.post("/cases/{case_id}/analyst-channel/disable")
    async def disable_case_analyst_channel(
        case_id: str,
        body: ChannelControlRequest,
        request: Request,
        principal=analyst_admin,
    ) -> dict:
        reason = body.reason
        s = state(request)
        async with s.pool.connection() as conn:
            await set_channel_control(
                conn,
                scope="CASE",
                case_id=case_id,
                disabled=True,
                changed_by=principal.username,
                reason=reason.strip(),
            )
            await conn.commit()
        return {"scope": "CASE", "case_id": case_id, "disabled": True}

    @router.post("/cases/{case_id}/analyst-channel/enable")
    async def enable_case_analyst_channel(
        case_id: str,
        body: ChannelControlRequest,
        request: Request,
        principal=analyst_admin,
    ) -> dict:
        reason = body.reason
        s = state(request)
        async with s.pool.connection() as conn:
            await set_channel_control(
                conn,
                scope="CASE",
                case_id=case_id,
                disabled=False,
                changed_by=principal.username,
                reason=reason.strip(),
            )
            await conn.commit()
        return {"scope": "CASE", "case_id": case_id, "disabled": False}

    @router.post("/platform/analyst-channel/disable")
    async def disable_platform_analyst_channel(
        body: ChannelControlRequest,
        request: Request,
        principal=analyst_admin,
    ) -> dict:
        reason = body.reason
        s = state(request)
        async with s.pool.connection() as conn:
            await set_channel_control(
                conn,
                scope="PLATFORM",
                case_id=None,
                disabled=True,
                changed_by=principal.username,
                reason=reason.strip(),
            )
            await conn.commit()
        return {"scope": "PLATFORM", "disabled": True}

    @router.post("/platform/analyst-channel/enable")
    async def enable_platform_analyst_channel(
        body: ChannelControlRequest,
        request: Request,
        principal=analyst_admin,
    ) -> dict:
        reason = body.reason
        s = state(request)
        async with s.pool.connection() as conn:
            await set_channel_control(
                conn,
                scope="PLATFORM",
                case_id=None,
                disabled=False,
                changed_by=principal.username,
                reason=reason.strip(),
            )
            await conn.commit()
        return {"scope": "PLATFORM", "disabled": False}

    @router.post("/internal/canary/callback", include_in_schema=False)
    async def ingest_canary_callback(
        body: SignedCanaryCallbackRequest,
        request: Request,
        signature_header: str = Header(alias="X-Mirage-Canary-Signature"),
    ) -> dict:
        if canary_signing_key is None or evidence_service is None:
            raise HTTPException(503, "canary ingestion is not configured")
        payload = body.payload
        signature = body.signature
        expected = hmac.new(
            canary_signing_key, canonical_json_bytes(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature) or not hmac.compare_digest(
            signature, signature_header
        ):
            raise HTTPException(401, "callback signature invalid")
        try:
            callback_time = datetime.fromisoformat(
                str(payload["callback_time"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, "invalid callback time") from exc
        s = state(request)
        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT token_id,case_id,artifact_id,expires_at,revoked_at,
                           expected_usage,status
                    FROM canary_tokens WHERE public_token_hash=%s FOR UPDATE
                    """,
                    (
                        hashlib.sha256(
                            str(payload.get("public_token", "")).encode()
                        ).hexdigest(),
                    ),
                )
                token = await cur.fetchone()
                if token is None:
                    raise HTTPException(404, "unknown canary token")
                token_id, case_id, artifact_id, expires_at, revoked_at, usage, status = token
                if revoked_at is not None or status == "REVOKED":
                    raise HTTPException(410, "canary token revoked")
                if callback_time >= expires_at or status == "EXPIRED":
                    await cur.execute(
                        "UPDATE canary_tokens SET status='EXPIRED' WHERE token_id=%s",
                        (token_id,),
                    )
                    await conn.commit()
                    raise HTTPException(410, "canary token expired")
                await cur.execute(
                    "SELECT 1 FROM canary_callbacks WHERE collector_request_id=%s",
                    (payload.get("collector_request_id"),),
                )
                if await cur.fetchone():
                    raise HTTPException(409, "callback replay detected")
                if usage == "ONE_TIME" and status == "USED":
                    raise HTTPException(409, "one-time token replay detected")
                await cur.execute(
                    """
                    SELECT source_id,cidr::text,category,valid_from,valid_until,
                           confidence,trusted_proxy
                    FROM infrastructure_sources
                    WHERE valid_from <= %s AND (valid_until IS NULL OR valid_until > %s)
                    """,
                    (callback_time, callback_time),
                )
                source_rows = await cur.fetchall()
                await cur.execute(
                    """
                    SELECT COALESCE(max(source_sequence),0)+1
                    FROM evidence_objects WHERE source_id='mirage-canary-collector'
                    """
                )
                source_sequence = (await cur.fetchone())[0]
            sources = [
                InfrastructureSource(
                    row[0], row[1], row[2], row[3], row[4], row[5], row[6]
                )
                for row in source_rows
            ]
            resolved_ip, conflict = resolve_callback_source(
                peer_ip=str(payload.get("source_ip", "")),
                forwarded_for=str(payload.get("forwarded_for") or "") or None,
                callback_time=callback_time,
                sources=sources,
            )
            classification = classify_callback(
                source_ip=resolved_ip,
                callback_time=callback_time,
                sources=sources,
                forwarding_conflict=conflict,
            )
            evidence = await evidence_service.acquire(
                conn,
                request=AcquisitionRequest(
                    case_id=case_id,
                    session_id=None,
                    evidence_type="CANARY_CALLBACK",
                    source_id="mirage-canary-collector",
                    source_sequence=source_sequence,
                    source_certificate_serial=None,
                    related_event_ids=[],
                    acquisition_time=callback_time,
                    original_filename=None,
                    media_type="application/json",
                    collection_method="SIGNED_CANARY_CALLBACK",
                    classification="SENSITIVE",
                    metadata={
                        "token_id": token_id,
                        "artifact_id": artifact_id,
                        "classification": classification.classification,
                        "rule_version": classification.rule_version,
                    },
                    required_for_export=True,
                ),
                stream=io.BytesIO(
                    json.dumps(
                        body.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ),
                actor="mirage-canary-collector",
            )
            async with conn.cursor() as cur:
                callback_id = generate_ulid()
                await cur.execute(
                    """
                    INSERT INTO canary_callbacks (
                        callback_id,token_id,callback_time,source_ip,
                        forwarded_source_metadata,user_agent,request_path,referrer,
                        http_method,tls_metadata,collector_request_id,event_signature,
                        classification,confidence,network_indicator,uncertainty,
                        rule_version,analyst_review_required,evidence_id
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        callback_id,
                        token_id,
                        callback_time,
                        resolved_ip,
                        Jsonb({"forwarded_for": payload.get("forwarded_for")}),
                        payload.get("user_agent"),
                        payload.get("request_path", ""),
                        payload.get("referrer"),
                        payload.get("http_method", "GET"),
                        Jsonb(payload.get("tls_metadata") or {}),
                        payload.get("collector_request_id"),
                        signature,
                        classification.classification,
                        classification.confidence,
                        classification.network_indicator,
                        classification.uncertainty,
                        classification.rule_version,
                        classification.analyst_review_required,
                        evidence.evidence_id,
                    ),
                )
                if usage == "ONE_TIME":
                    await cur.execute(
                        "UPDATE canary_tokens SET status='USED' WHERE token_id=%s",
                        (token_id,),
                    )
                await cur.execute(
                    "UPDATE canary_tokens SET classification_status=%s WHERE token_id=%s",
                    (classification.classification, token_id),
                )
                callback_event = build_event(
                    event_type="canary.callback",
                    schema_version="1.0",
                    payload={
                        "callback_id": callback_id,
                        "token_id": token_id,
                        "callback_time": callback_time.isoformat().replace("+00:00", "Z"),
                        "source_ip": resolved_ip,
                        "classification": classification.classification,
                        "confidence": classification.confidence,
                        "rule_version": classification.rule_version,
                        "signature": signature,
                    },
                    source_id="mirage-api.canary-ingestion",
                    sequence=source_sequence,
                    actor_type="SYSTEM",
                    classification="EVIDENCE",
                    case_id=case_id,
                )
                validated_callback_event = validate_event(callback_event)
                await cur.execute(
                    "INSERT INTO outbox_events (event_id,topic,payload) VALUES (%s,%s,%s)",
                    (
                        callback_event["event_id"],
                        subject_for_event_type("canary.callback"),
                        Jsonb(validated_callback_event.envelope),
                    ),
                )
                await cur.execute(
                    """
                    INSERT INTO audit_events
                        (actor,actor_type,action,target,outcome,correlation_id,detail)
                    VALUES ('mirage-api.canary-ingestion','SYSTEM','canary.callback.classified',
                            %s,'SUCCESS',%s,%s)
                    """,
                    (
                        callback_id,
                        callback_id,
                        f"{classification.classification}:{classification.rule_version}",
                    ),
                )
            await conn.commit()
        return {
            "callback_id": callback_id,
            "classification": classification.classification,
            "evidence_id": evidence.evidence_id,
        }

    return router


def _evidence_row(row: tuple) -> dict:
    fields = (
        "evidence_id", "session_id", "evidence_type", "source_id", "source_sequence",
        "acquisition_time", "stored_time", "original_filename", "media_type", "size_bytes",
        "sha256", "s3_bucket", "s3_key", "s3_version_id", "object_lock_mode",
        "retention_until", "verification_status", "verified_at", "verification_error",
        "classification", "required_for_export",
    )
    result = dict(zip(fields, row, strict=True))
    for key in ("acquisition_time", "stored_time", "retention_until", "verified_at"):
        if result[key]:
            result[key] = result[key].isoformat()
    return result


def _export_row(row: tuple) -> dict:
    fields = (
        "export_id", "export_version", "manifest_sha256", "signing_algorithm",
        "verification_status", "created_by", "created_at", "verified_at",
    )
    result = dict(zip(fields, row, strict=True))
    result["created_at"] = result["created_at"].isoformat()
    if result["verified_at"]:
        result["verified_at"] = result["verified_at"].isoformat()
    return result


def _approved_destination(destination: str) -> bool:
    if "\x00" in destination:
        return False
    if "\\" in destination or (len(destination) > 1 and destination[1] == ":"):
        windows_path = PureWindowsPath(destination)
        windows_roots = (
            PureWindowsPath("C:/Mirage"),
            PureWindowsPath("C:/Users/Public/Documents/Mirage"),
        )
        return (
            windows_path.is_absolute()
            and ".." not in windows_path.parts
            and any(
                windows_path == root or windows_path.is_relative_to(root)
                for root in windows_roots
            )
        )
    posix_path = PurePosixPath(destination)
    posix_root = PurePosixPath("/sandbox/mirage")
    return (
        posix_path.is_absolute()
        and ".." not in posix_path.parts
        and (posix_path == posix_root or posix_path.is_relative_to(posix_root))
    )


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
