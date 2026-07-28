"""Generate, sign, store, and ledger a complete deterministic export."""
from __future__ import annotations

import base64
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.evidence import (
    AcquisitionRequest,
    EvidenceService,
    ObjectStore,
    export_eligibility,
)
from mirage_common.evidence_export import (
    FIXED_ZIP_TIME,
    ManifestSigner,
    TimestampProvider,
    build_manifest,
    sign_manifest,
    verify_export_package,
)


class ExportNotEligibleError(Exception):
    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


async def generate_export(
    conn: psycopg.AsyncConnection,
    *,
    export_id: str,
    evidence_service: EvidenceService,
    object_store: ObjectStore,
    signer: ManifestSigner,
    timestamp_provider: TimestampProvider,
) -> str:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT case_id,export_version,created_by,created_at
            FROM evidence_exports WHERE export_id=%s FOR UPDATE
            """,
            (export_id,),
        )
        export_row = await cur.fetchone()
        if export_row is None:
            raise ValueError("export not found")
    case_id, export_version, created_by, created_at = export_row
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT evidence_id FROM evidence_objects
            WHERE case_id=%s AND required_for_export
              AND evidence_type NOT IN ('EXPORT','MANIFEST','SIGNATURE','VERIFICATION_REPORT')
            ORDER BY evidence_id
            """,
            (case_id,),
        )
        pre_export_evidence_ids = [row[0] for row in await cur.fetchall()]
    for evidence_id in pre_export_evidence_ids:
        await evidence_service.verify(
            conn,
            evidence_id=evidence_id,
            reason="PRE_EXPORT",
            requested_by="mirage-report-worker",
        )
    eligible, reasons = await export_eligibility(conn, case_id=case_id)
    if not eligible:
        raise ExportNotEligibleError(reasons)
    data = await _load_manifest_data(conn, case_id)
    provisional = {
        "case": data["case"],
        "evidence_objects": data["evidence"],
        "export_id": export_id,
        "export_version": export_version,
    }
    import hashlib

    from mirage_contracts.envelope import canonical_json_bytes

    timestamp = timestamp_provider.timestamp(hashlib.sha256(canonical_json_bytes(provisional)).digest())
    limitations = [
        "Mirage exports are evidence-ready, not a claim of court admissibility.",
    ]
    if not timestamp.independently_trusted:
        limitations.append("Timestamp source is local development and not independently trusted.")
    if signer.key_id.startswith("LOCAL_"):
        limitations.append("Local development signing key is not AWS KMS.")
    manifest = build_manifest(
        case=data["case"],
        sessions=data["sessions"],
        timeline=data["timeline"],
        evidence=data["evidence"],
        collection_gaps=data["gaps"],
        analyst_actions=data["analyst"],
        ai_actions=data["ai"],
        policy_decisions=data["policy"],
        export_id=export_id,
        export_version=export_version,
        created_at=created_at.isoformat().replace("+00:00", "Z"),
        created_by=created_by,
        kms_key_arn=signer.key_id,
        trusted_timestamp=timestamp,
        limitations=limitations,
    )
    signed = sign_manifest(manifest, signer)
    report = _verification_report(signed.manifest_sha256, data["evidence"], limitations)
    package_path = await _write_package(object_store, data["evidence"], signed, report)
    try:
        # Build-time self-check using the actual key just used to sign (not
        # extracted from the archive after the fact) — proves the signing
        # step itself worked. This is not a substitute for an operator/
        # verifier independently trusting this key out of band.
        independent_report = verify_export_package(
            package_path, public_key_pem=signer.public_key_pem()
        )
        if not independent_report.valid:
            raise RuntimeError(
                "generated export failed independent verification: "
                + "; ".join(independent_report.errors)
            )
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('mirage-report-worker',5821))"
            )
            await cur.execute(
                "SELECT COALESCE(max(source_sequence),0) FROM evidence_objects WHERE source_id='mirage-report-worker'"
            )
            sequence_row = await cur.fetchone()
            if sequence_row is None:
                raise RuntimeError("unable to read report-worker source sequence")
            sequence = sequence_row[0]
        manifest_evidence = await evidence_service.acquire(
            conn,
            request=_request(
                case_id, "MANIFEST", sequence + 1, created_at, f"{export_id}-manifest.json"
            ),
            stream=_bytes_stream(signed.canonical_bytes),
            actor="mirage-report-worker",
        )
        signature_evidence = await evidence_service.acquire(
            conn,
            request=_request(
                case_id, "SIGNATURE", sequence + 2, created_at, f"{export_id}-manifest.sig"
            ),
            stream=_bytes_stream(signed.signature),
            actor="mirage-report-worker",
        )
        report_evidence = await evidence_service.acquire(
            conn,
            request=_request(
                case_id,
                "VERIFICATION_REPORT",
                sequence + 3,
                created_at,
                f"{export_id}-verification.txt",
            ),
            stream=_bytes_stream(report.encode()),
            actor="mirage-report-worker",
        )
        with package_path.open("rb") as package_stream:
            package_evidence = await evidence_service.acquire(
                conn,
                request=_request(
                    case_id, "EXPORT", sequence + 4, created_at, f"{export_id}.zip"
                ),
                stream=package_stream,
                actor="mirage-report-worker",
            )
        for component in (
            manifest_evidence,
            signature_evidence,
            report_evidence,
            package_evidence,
        ):
            component_status = await evidence_service.verify(
                conn,
                evidence_id=component.evidence_id,
                reason="EXPORT_COMPONENT_VERIFICATION",
                requested_by="mirage-report-worker",
            )
            if component_status != "VERIFIED":
                raise RuntimeError(
                    f"export component {component.evidence_id} verification is {component_status}"
                )
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO trusted_timestamps (
                    timestamp_id,source_type,source_name,timestamp_time,token,
                    record_json,independently_trusted
                ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    timestamp.timestamp_id,
                    timestamp.source_type,
                    timestamp.source_name,
                    datetime.fromisoformat(timestamp.timestamp_time.replace("Z", "+00:00")),
                    base64.b64decode(timestamp.token_base64)
                    if timestamp.token_base64
                    else None,
                    Jsonb(timestamp.record),
                    timestamp.independently_trusted,
                ),
            )
            await cur.execute(
                """
                UPDATE evidence_exports SET manifest_sha256=%s,kms_key_arn=%s,
                    kms_signature=%s,signing_algorithm='RSASSA_PSS_SHA_256',
                    signed_at=now(),trusted_timestamp_id=%s,
                    verification_status='VERIFIED',verified_at=now(),
                    export_evidence_id=%s,limitations=%s
                WHERE export_id=%s
                """,
                (
                    signed.manifest_sha256,
                    signer.key_id,
                    signed.signature,
                    timestamp.timestamp_id,
                    package_evidence.evidence_id,
                    Jsonb(limitations),
                    export_id,
                ),
            )
            for ordinal, item in enumerate(data["evidence"]):
                await cur.execute(
                    """
                    INSERT INTO evidence_export_items
                        (export_id,evidence_id,ordinal,sha256_at_export)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (export_id, item["evidence_id"], ordinal, item["sha256"]),
                )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES ('mirage-report-worker','SYSTEM','evidence.export.signed',
                        %s,'SUCCESS',%s,%s)
                """,
                (
                    export_id,
                    export_id,
                    (
                        f"manifest={manifest_evidence.evidence_id};"
                        f"signature={signature_evidence.evidence_id};"
                        f"report={report_evidence.evidence_id};"
                        f"package={package_evidence.evidence_id}"
                    ),
                ),
            )
        return package_evidence.evidence_id
    finally:
        package_path.unlink(missing_ok=True)


async def _load_manifest_data(conn: psycopg.AsyncConnection, case_id: str) -> dict[str, Any]:
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT case_id,state,version,severity,owner,created_at,updated_at FROM cases WHERE case_id=%s",
            (case_id,),
        )
        case = await cur.fetchone()
        if case is None:
            raise ValueError("case not found")
        await cur.execute(
            "SELECT session_id,protocol,broker_id,status,created_at,ended_at FROM sessions WHERE case_id=%s",
            (case_id,),
        )
        sessions = await cur.fetchall()
        await cur.execute(
            """
            SELECT from_state,to_state,actor,actor_type,reason,new_version,
                   correlation_id,at
            FROM case_state_transitions WHERE case_id=%s
            """,
            (case_id,),
        )
        timeline = await cur.fetchall()
        await cur.execute(
            """
            SELECT evidence_id,evidence_type,source_id,source_sequence,
                   source_certificate_serial,related_event_ids,acquisition_time,
                   stored_time,original_filename,media_type,size_bytes,sha256,
                   s3_bucket,s3_key,s3_version_id,object_lock_mode,retention_until,
                   verification_status,verified_at,collection_method,classification,
                   metadata_json
            FROM evidence_objects
            WHERE case_id=%s AND evidence_type NOT IN ('EXPORT','MANIFEST','SIGNATURE','VERIFICATION_REPORT')
            """,
            (case_id,),
        )
        evidence = await cur.fetchall()
        await cur.execute(
            """
            SELECT gap_id,evidence_type,source_id,sequence_from,sequence_to,
                   required,reason,resolved_at,resolution,created_at
            FROM evidence_collection_gaps WHERE case_id=%s
            """,
            (case_id,),
        )
        gaps = await cur.fetchall()
        await cur.execute(
            """
            SELECT directive_id,session_id,objective,priority,status,created_by,
                   created_at,expires_at,linked_proposal_ids,linked_action_ids
            FROM analyst_directives WHERE case_id=%s
            """,
            (case_id,),
        )
        directives = await cur.fetchall()
        await cur.execute(
            """
            SELECT message_id,session_id,author_id,surface,output_tag,preview_hash,
                   confirmation_required,status,delivered_at,response_event_ids,created_at
                   ,evidence_id
            FROM analyst_messages WHERE case_id=%s
            """,
            (case_id,),
        )
        messages = await cur.fetchall()
        await cur.execute(
            """
            SELECT proposal_id,schema_version,snapshot_id,strategy_phase,action_type,params,
                   rationale,confidence,supporting_event_ids,expected_effect,
                   rollback_required,expires_at,created_at
            FROM ai_proposals WHERE case_id=%s
            """,
            (case_id,),
        )
        ai = await cur.fetchall()
        await cur.execute(
            """
            SELECT decision_id,proposal_id,policy_version,decision,reason_codes,
                   constraints,analyst_approval,created_at
            FROM policy_decisions WHERE case_id=%s
            """,
            (case_id,),
        )
        policy = await cur.fetchall()
    return {
        "case": _dict(
            ("case_id", "state", "version", "severity", "owner", "created_at", "updated_at"),
            case,
        ),
        "sessions": [
            _dict(("session_id", "protocol", "broker_id", "status", "created_at", "ended_at"), row)
            for row in sessions
        ],
        "timeline": [
            _dict(
                (
                    "from_state", "to_state", "actor", "actor_type", "reason",
                    "new_version", "correlation_id", "at",
                ),
                row,
            )
            for row in timeline
        ],
        "evidence": [
            _dict(
                (
                    "evidence_id", "evidence_type", "source_id", "source_sequence",
                    "source_certificate_serial", "related_event_ids", "acquisition_time",
                    "stored_time", "original_filename", "media_type", "size_bytes",
                    "sha256", "s3_bucket", "s3_key", "s3_version_id", "object_lock_mode",
                    "retention_until", "verification_status", "verified_at",
                    "collection_method", "classification", "metadata",
                ),
                row,
            )
            for row in evidence
        ],
        "gaps": [
            _dict(
                (
                    "gap_id", "evidence_type", "source_id", "sequence_from", "sequence_to",
                    "required", "reason", "resolved_at", "resolution", "created_at",
                ),
                row,
            )
            for row in gaps
        ],
        "analyst": [
            _dict(
                (
                    "id", "session_id", "objective", "priority", "status", "created_by",
                    "created_at", "expires_at", "linked_proposal_ids", "linked_action_ids",
                ),
                row,
            )
            | {"action_type": "DIRECTIVE"}
            for row in directives
        ]
        + [
            _dict(
                (
                    "id", "session_id", "author_id", "surface", "output_tag",
                    "preview_hash", "confirmation_required", "status", "delivered_at",
                    "response_event_ids", "created_at", "evidence_id",
                ),
                row,
            )
            | {"action_type": "DIRECT_MESSAGE"}
            for row in messages
        ],
        "ai": [
            _dict(
                (
                    "id", "schema_version", "snapshot_id", "strategy_phase", "action_type", "params",
                    "rationale", "confidence", "supporting_event_ids", "expected_effect",
                    "rollback_required", "expires_at", "created_at",
                ),
                row,
            )
            for row in ai
        ],
        "policy": [
            _dict(
                (
                    "decision_id", "proposal_id", "policy_version", "decision",
                    "reason_codes", "constraints", "analyst_approval", "created_at",
                ),
                row,
            )
            for row in policy
        ],
    }


async def _write_package(
    store: ObjectStore,
    evidence: list[dict[str, Any]],
    signed: Any,
    report: str,
) -> Path:
    temp = tempfile.NamedTemporaryFile(prefix="mirage-export-", suffix=".zip", delete=False)
    path = Path(temp.name)
    temp.close()
    with zipfile.ZipFile(path, "w") as zf:
        _write_member(zf, "manifest.json", signed.canonical_bytes)
        _write_member(zf, "manifest.sha256", f"{signed.manifest_sha256}\n".encode())
        _write_member(zf, "manifest.sig", signed.signature)
        _write_member(zf, "public-key.pem", signed.public_key_pem)
        _write_member(zf, "verification-report.txt", report.encode())
        for item in signed.manifest["evidence_objects"]:
            stream = await store.open(
                bucket=item["s3_bucket"],
                key=item["s3_key"],
                version_id=item["s3_version_id"],
            )
            info = zipfile.ZipInfo(f"objects/{item['evidence_id']}", FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            try:
                with zf.open(info, "w") as target:
                    while chunk := stream.read(1024 * 1024):
                        target.write(chunk)
            finally:
                stream.close()
    return path


def _write_member(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


def _verification_report(
    manifest_sha256: str,
    evidence: list[dict[str, Any]],
    limitations: list[str],
) -> str:
    lines = [
        "Mirage Evidence Export Verification Report",
        f"Manifest SHA-256: {manifest_sha256}",
        f"Evidence objects: {len(evidence)}",
        "All included objects were VERIFIED before export: yes",
        "",
        "Limitations:",
    ]
    lines.extend(f"- {limitation}" for limitation in limitations)
    lines.extend(
        [
            "",
            "Independent verification:",
            "  scripts/verify-evidence-export <package.zip> [--public-key kms-public.pem]",
        ]
    )
    return "\n".join(lines) + "\n"


def _dict(fields: tuple[str, ...], row: tuple) -> dict[str, Any]:
    result = dict(zip(fields, row, strict=True))
    for key, value in list(result.items()):
        if isinstance(value, datetime):
            result[key] = value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return result


def _request(
    case_id: str,
    evidence_type: str,
    sequence: int,
    created_at: datetime,
    filename: str,
) -> AcquisitionRequest:
    return AcquisitionRequest(
        case_id=case_id,
        session_id=None,
        evidence_type=evidence_type,
        source_id="mirage-report-worker",
        source_sequence=sequence,
        source_certificate_serial=None,
        related_event_ids=[],
        acquisition_time=created_at,
        original_filename=filename,
        media_type=(
            "application/zip"
            if evidence_type == "EXPORT"
            else "application/octet-stream"
            if evidence_type == "SIGNATURE"
            else "application/json"
            if evidence_type == "MANIFEST"
            else "text/plain"
        ),
        collection_method="REPORT_WORKER_EXPORT",
        classification="SENSITIVE",
        metadata={"export_component": evidence_type},
        required_for_export=False,
    )


def _bytes_stream(data: bytes):
    import io

    return io.BytesIO(data)
