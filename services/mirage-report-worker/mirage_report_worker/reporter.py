"""Report job orchestration layered on the Stage 5 evidence export pipeline."""
from __future__ import annotations

import hashlib
import io
import json
import time
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.evidence import (
    AcquisitionRequest,
    EvidenceService,
    ObjectStore,
)
from mirage_common.evidence_export import ManifestSigner
from mirage_common.reports import (
    build_report_model,
    create_report_artifacts,
    create_report_package,
    verify_report_package,
)
from mirage_common.telemetry import core_metrics, traced_operation
from mirage_contracts.envelope import canonical_json_bytes
from mirage_contracts.ulid import generate_ulid
from mirage_report_worker.exporter import _load_manifest_data


async def process_next_report(
    conn: psycopg.AsyncConnection,
    *,
    evidence_service: EvidenceService,
    object_store: ObjectStore,
    signer: ManifestSigner,
) -> bool:
    """Advance one locked report job; return whether a job was found."""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT report_id,case_id,export_id,export_mode,selected_evidence_ids,
                   template_version,report_schema_version,generator_version,build_hash,
                   source_projection_version,status,created_by,created_at,timeout_at
            FROM case_reports
            WHERE status IN ('QUEUED','WAITING_FOR_EXPORT','CANCEL_REQUESTED')
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED LIMIT 1
            """
        )
        row = await cur.fetchone()
    if row is None:
        return False
    (
        report_id,
        case_id,
        export_id,
        export_mode,
        selected_ids,
        _template_version,
        _schema_version,
        _generator_version,
        build_hash,
        projection_version,
        status,
        created_by,
        created_at,
        timeout_at,
    ) = row
    if status == "CANCEL_REQUESTED":
        await _set_cancelled(conn, report_id, created_by)
        return True
    if timeout_at <= datetime.now(UTC):
        await _set_failed(conn, report_id, "report generation timeout elapsed")
        return True
    if export_id is None:
        export_id = await _queue_evidence_export(conn, case_id, report_id, created_by)
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE case_reports
                SET export_id=%s,status='WAITING_FOR_EXPORT',progress=10
                WHERE report_id=%s
                """,
                (export_id, report_id),
            )
            await _audit(
                cur,
                report_id,
                "mirage-report-worker",
                "EVIDENCE_EXPORT_QUEUED",
                {"export_id": export_id},
            )
        return True
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT verification_status,manifest_sha256
            FROM evidence_exports WHERE export_id=%s
            """,
            (export_id,),
        )
        export = await cur.fetchone()
    if export is None:
        await _set_failed(conn, report_id, "linked evidence export is missing")
        return True
    if export[0] == "FAILED":
        await _set_failed(conn, report_id, "linked evidence export failed verification")
        return True
    if export[0] != "VERIFIED":
        return False

    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE case_reports
            SET status='GENERATING',progress=35,started_at=COALESCE(started_at,now())
            WHERE report_id=%s
            """,
            (report_id,),
        )
    await conn.commit()
    try:
        started = time.perf_counter()
        with traced_operation(
            "mirage.report.generate",
            attributes={
                "case_id": case_id,
                "correlation_id": report_id,
                "operation": "report_generation",
            },
        ):
            data = await _load_report_data(conn, case_id)
        evidence_manifest = await _read_evidence_manifest(
            conn, object_store, case_id, export_id
        )
        model = build_report_model(
            data,
            report_id=report_id,
            export_id=export_id,
            created_by=created_by,
            created_at=_iso(created_at),
            build_hash=build_hash,
            source_projection_version=projection_version,
            evidence_manifest_id=export_id,
            limitations=[
                "This report is evidence-ready and is not itself a claim of court admissibility.",
                "The report inherits the signature and trusted-time limitations in its manifest.",
            ],
        )
        artifacts = create_report_artifacts(model)
        evidence_bytes = await _selected_evidence_bytes(
            object_store,
            data["evidence"],
            export_mode=export_mode,
            selected_ids={str(value) for value in selected_ids},
        )
        generated = create_report_package(
            artifacts,
            signer=signer,
            export_mode=export_mode,
            evidence_manifest=evidence_manifest,
            evidence_objects=evidence_bytes,
        )
        # Build-time self-check using the actual key just used to sign (not
        # extracted from the archive after the fact) — proves the signing
        # step itself worked. This is not a substitute for an operator/
        # verifier independently trusting this key out of band.
        report = verify_report_package(
            generated.package,
            public_key_pem=signer.public_key_pem(),
            expected_evidence_manifest_sha256=hashlib.sha256(
                canonical_json_bytes(evidence_manifest)
            ).hexdigest(),
        )
        if not report.valid:
            raise RuntimeError(
                "independent report verification failed: " + "; ".join(report.errors)
            )
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT status FROM case_reports WHERE report_id=%s FOR UPDATE",
                (report_id,),
            )
            current = await cur.fetchone()
            if current is None or current[0] == "CANCEL_REQUESTED":
                await _set_cancelled(conn, report_id, created_by)
                return True
            await cur.execute(
                """
                UPDATE case_reports SET status='VERIFYING',progress=85
                WHERE report_id=%s
                """,
                (report_id,),
            )
            await cur.execute(
                """
                SELECT COALESCE(max(source_sequence),0)
                FROM evidence_objects WHERE source_id='mirage-report-worker'
                """
            )
            sequence_row = await cur.fetchone()
            if sequence_row is None:
                raise RuntimeError("could not allocate report-worker evidence sequence")
            sequence = sequence_row[0] + 1
        package_evidence = await evidence_service.acquire(
            conn,
            request=AcquisitionRequest(
                case_id=case_id,
                session_id=None,
                evidence_type="EXPORT",
                source_id="mirage-report-worker",
                source_sequence=sequence,
                source_certificate_serial=None,
                related_event_ids=[],
                acquisition_time=created_at,
                original_filename=f"{report_id}-report-package.zip",
                media_type="application/zip",
                collection_method="REPORT_WORKER_REPORT",
                classification="SENSITIVE",
                metadata={
                    "report_id": report_id,
                    "export_id": export_id,
                    "manifest_sha256": generated.manifest_sha256,
                },
                required_for_export=False,
            ),
            stream=io.BytesIO(generated.package),
            actor="mirage-report-worker",
            correlation_id=report_id,
        )
        verification = await evidence_service.verify(
            conn,
            evidence_id=package_evidence.evidence_id,
            reason="REPORT_PACKAGE_VERIFICATION",
            requested_by="mirage-report-worker",
        )
        if verification != "VERIFIED":
            raise RuntimeError(f"stored report verification status is {verification}")
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE case_reports
                SET status='COMPLETED',progress=100,completed_at=now(),
                    package_evidence_id=%s,package_sha256=%s,
                    verification_status='VERIFIED',verification_errors='[]'::jsonb,
                    error=NULL
                WHERE report_id=%s
                """,
                (package_evidence.evidence_id, generated.package_sha256, report_id),
            )
            await _audit(
                cur,
                report_id,
                "mirage-report-worker",
                "REPORT_COMPLETED",
                {
                    "package_evidence_id": package_evidence.evidence_id,
                    "package_sha256": generated.package_sha256,
                },
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (
                    'mirage-report-worker','SYSTEM','case.report.generated',
                    %s,'SUCCESS',%s,%s
                )
                """,
                (report_id, report_id, f"evidence={package_evidence.evidence_id}"),
            )
        core_metrics()["report_generation_duration"].record(
            (time.perf_counter() - started) * 1000
        )
        return True
    except Exception as exc:
        core_metrics()["report_generation_failure"].add(1)
        await conn.rollback()
        await _set_failed(conn, report_id, f"{type(exc).__name__}: {exc}"[:2048])
        return True


async def _queue_evidence_export(
    conn: psycopg.AsyncConnection,
    case_id: str,
    report_id: str,
    created_by: str,
) -> str:
    export_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT COALESCE(max(export_version),0)+1 FROM evidence_exports WHERE case_id=%s",
            (case_id,),
        )
        version_row = await cur.fetchone()
        if version_row is None:
            raise RuntimeError("could not allocate evidence export version")
        version = version_row[0]
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
                created_by,
                Jsonb([f"report:{report_id}", "queued by case report workflow"]),
            ),
        )
    return export_id


async def _read_evidence_manifest(
    conn: psycopg.AsyncConnection,
    store: ObjectStore,
    case_id: str,
    export_id: str,
) -> dict[str, Any]:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT s3_bucket,s3_key,s3_version_id FROM evidence_objects
            WHERE case_id=%s AND evidence_type='MANIFEST'
              AND original_filename=%s
              AND verification_status='VERIFIED'
            ORDER BY stored_time DESC LIMIT 1
            """,
            (case_id, f"{export_id}-manifest.json"),
        )
        row = await cur.fetchone()
    if row is None:
        raise RuntimeError("verified canonical evidence manifest object is missing")
    stream = await store.open(bucket=row[0], key=row[1], version_id=row[2])
    try:
        value = json.load(stream)
    finally:
        stream.close()
    if not isinstance(value, dict):
        raise RuntimeError("evidence manifest root is not an object")
    return value


async def _selected_evidence_bytes(
    store: ObjectStore,
    evidence: list[dict[str, Any]],
    *,
    export_mode: str,
    selected_ids: set[str],
) -> dict[str, bytes]:
    if export_mode == "METADATA_ONLY":
        return {}
    available = {str(item["evidence_id"]): item for item in evidence}
    include = set(available) if export_mode == "COMPLETE_CASE" else selected_ids
    if unknown := include - set(available):
        raise RuntimeError(f"selected evidence is absent from ledger: {sorted(unknown)}")
    result: dict[str, bytes] = {}
    for evidence_id in sorted(include):
        item = available[evidence_id]
        stream = await store.open(
            bucket=item["s3_bucket"],
            key=item["s3_key"],
            version_id=item["s3_version_id"],
        )
        try:
            result[evidence_id] = stream.read()
        finally:
            stream.close()
    return result


async def _load_report_data(
    conn: psycopg.AsyncConnection, case_id: str
) -> dict[str, Any]:
    data = await _load_manifest_data(conn, case_id)
    analyst = data.pop("analyst")
    data["directives"] = [
        item | {"directive_id": item["id"]}
        for item in analyst
        if item["action_type"] == "DIRECTIVE"
    ]
    data["messages"] = [
        item | {"message_id": item["id"]}
        for item in analyst
        if item["action_type"] == "DIRECT_MESSAGE"
    ]
    data["ai"] = [item | {"proposal_id": item["id"]} for item in data["ai"]]
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT item_id,item_type,classification,label,description,event_time,
                   source_event_ids,evidence_references,confidence,output_tag
            FROM dashboard_timeline_items WHERE case_id=%s
            ORDER BY event_time,item_id
            """,
            (case_id,),
        )
        data["dashboard_timeline"] = [
            _row(
                (
                    "item_id",
                    "item_type",
                    "classification",
                    "label",
                    "description",
                    "event_time",
                    "source_event_ids",
                    "evidence_references",
                    "confidence",
                    "output_tag",
                ),
                row,
            )
            for row in await cur.fetchall()
        ]
        await cur.execute(
            """
            SELECT node_id,node_type,label,event_time,source_event_ids,
                   evidence_references,confidence,output_tag
            FROM dashboard_graph_nodes WHERE case_id=%s ORDER BY event_time,node_id
            """,
            (case_id,),
        )
        data["graph_nodes"] = [
            _row(
                (
                    "node_id",
                    "node_type",
                    "label",
                    "event_time",
                    "source_event_ids",
                    "evidence_references",
                    "confidence",
                    "output_tag",
                ),
                row,
            )
            for row in await cur.fetchall()
        ]
        await cur.execute(
            """
            SELECT id,match_key,target,created_at,valid_until
            FROM routing_decisions WHERE case_id=%s ORDER BY created_at,id
            """,
            (case_id,),
        )
        data["routing_decisions"] = [
            _row(
                ("decision_id", "protocol", "target", "created_at", "revoked_at"),
                row,
            )
            for row in await cur.fetchall()
        ]
        await cur.execute(
            """
            SELECT sandbox_id,image_id,status,state_version,created_at,destroyed_at
            FROM sandbox_instances WHERE case_id=%s ORDER BY created_at,sandbox_id
            """,
            (case_id,),
        )
        data["sandboxes"] = [
            _row(
                (
                    "sandbox_id",
                    "image_id",
                    "status",
                    "state_version",
                    "created_at",
                    "destroyed_at",
                ),
                row,
            )
            for row in await cur.fetchall()
        ]
        await cur.execute(
            """
            SELECT action_id,action_type,status,output_tag,created_at,completed_at
            FROM sandbox_actions WHERE case_id=%s ORDER BY created_at,action_id
            """,
            (case_id,),
        )
        data["sandbox_actions"] = [
            _row(
                (
                    "action_id",
                    "action_type",
                    "status",
                    "output_tag",
                    "created_at",
                    "completed_at",
                ),
                row,
            )
            for row in await cur.fetchall()
        ]
    return data


async def _set_cancelled(
    conn: psycopg.AsyncConnection, report_id: str, actor: str
) -> None:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE case_reports
            SET status='CANCELLED',progress=100,completed_at=now(),
                verification_status='FAILED',error='cancelled by request'
            WHERE report_id=%s
            """,
            (report_id,),
        )
        await _audit(cur, report_id, actor, "REPORT_CANCELLED", {})


async def _set_failed(
    conn: psycopg.AsyncConnection, report_id: str, error: str
) -> None:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE case_reports
            SET status='FAILED',progress=100,completed_at=now(),
                verification_status='FAILED',error=%s,
                verification_errors=%s
            WHERE report_id=%s
            """,
            (error, Jsonb([error]), report_id),
        )
        await _audit(cur, report_id, "mirage-report-worker", "REPORT_FAILED", {"error": error})


async def _audit(
    cur: psycopg.AsyncCursor,
    report_id: str,
    actor: str,
    action: str,
    detail: dict[str, Any],
) -> None:
    await cur.execute(
        """
        INSERT INTO report_audit (report_id,actor,action,detail)
        VALUES (%s,%s,%s,%s)
        """,
        (report_id, actor, action, Jsonb(detail)),
    )


def _row(fields: tuple[str, ...], row: tuple[Any, ...]) -> dict[str, Any]:
    result = dict(zip(fields, row, strict=True))
    for key, value in result.items():
        if isinstance(value, datetime):
            result[key] = _iso(value)
    return result


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
