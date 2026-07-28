from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from mirage_report_worker.reporter import process_next_report

from mirage_common.dashboard import DashboardProjector
from mirage_common.evidence import AcquisitionRequest, EvidenceService, MemoryObjectStore
from mirage_common.evidence_export import LocalDevelopmentSigner
from mirage_common.reports import (
    REPORT_GENERATOR_VERSION,
    REPORT_SCHEMA_VERSION,
    REPORT_TEMPLATE_VERSION,
)
from mirage_contracts.envelope import canonical_json_bytes
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


@pytest_asyncio.fixture(scope="module")
async def dashboard_conn(postgres_container):
    dsn = (
        f"host={postgres_container.get_container_host_ip()} "
        f"port={postgres_container.get_exposed_port(5432)} "
        f"user={postgres_container.username} password={postgres_container.password} "
        f"dbname={postgres_container.dbname}"
    )
    conn = await psycopg.AsyncConnection.connect(dsn)
    for migration in sorted((ROOT / "infra" / "migrations").glob("*.up.sql")):
        await conn.execute(migration.read_text())
    await conn.commit()
    yield conn
    await conn.close()


async def test_00_dashboard_migration_upgrade_downgrade_upgrade(dashboard_conn) -> None:
    conn = dashboard_conn
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT table_name FROM information_schema.tables
            WHERE table_schema='public' AND table_name LIKE 'dashboard_%'
            """
        )
        names = {row[0] for row in await cur.fetchall()}
    assert {
        "dashboard_case_summary",
        "dashboard_timeline_items",
        "dashboard_graph_nodes",
        "dashboard_graph_edges",
        "dashboard_projection_offsets",
        "dashboard_notifications",
        "dashboard_saved_views",
        "dashboard_user_preferences",
    }.issubset(names)
    await conn.execute(
        (ROOT / "infra" / "migrations" / "0009_dashboard_read_model.down.sql").read_text()
    )
    await conn.commit()
    async with conn.cursor() as cur:
        await cur.execute("SELECT to_regclass('public.dashboard_case_summary')")
        assert (await cur.fetchone())[0] is None
        await cur.execute("SELECT to_regclass('public.evidence_objects')")
        assert (await cur.fetchone())[0] == "evidence_objects"
    await conn.execute(
        (ROOT / "infra" / "migrations" / "0009_dashboard_read_model.up.sql").read_text()
    )
    await conn.commit()


async def test_projection_is_idempotent_gap_aware_and_rebuildable(dashboard_conn) -> None:
    conn = dashboard_conn
    case_id = generate_ulid()
    evidence_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id,severity,owner) VALUES (%s,'HIGH','investigator')",
            (case_id,),
        )
    await conn.commit()
    projector = DashboardProjector()

    def event(sequence: int, event_id: str) -> dict:
        now = datetime.now(UTC).isoformat()
        return {
            "event_id": event_id,
            "event_type": "spider.observation",
            "schema_version": "1.0",
            "event_time": now,
            "ingest_time": now,
            "case_id": case_id,
            "session_id": None,
            "source_id": "spider-test",
            "sequence": sequence,
            "actor_type": "AGENT",
            "classification": "SENSITIVE",
            "payload": {
                "observation_type": "PROCESS",
                "summary": "<b>powershell</b>",
                "evidence_id": evidence_id,
                "output_tag": "UNTRUSTED_INTRUDER_OUTPUT",
            },
        }

    first_id, third_id = generate_ulid(), generate_ulid()
    first = await projector.project_event(conn, event(1, first_id))
    await conn.commit()
    duplicate = await projector.project_event(conn, event(1, first_id))
    await conn.commit()
    gap = await projector.project_event(conn, event(3, third_id))
    await conn.commit()

    assert first.applied and first.projection_version == 1
    assert duplicate.duplicate and not duplicate.applied
    assert gap.applied and gap.gap_detected and gap.projection_version == 2
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT count(*) FROM dashboard_timeline_items WHERE case_id=%s",
            (case_id,),
        )
        assert (await cur.fetchone())[0] == 2
        await cur.execute(
            """
            SELECT gap_detected,gap_from,gap_to FROM dashboard_projection_offsets
            WHERE projector_name='dashboard-v1' AND case_id=%s
            """,
            (case_id,),
        )
        assert await cur.fetchone() == (True, 2, 2)
        await cur.execute(
            """
            SELECT source_event_ids,evidence_references,classification,output_tag,label
            FROM dashboard_graph_nodes
            WHERE case_id=%s AND node_type='PROCESS' ORDER BY event_time LIMIT 1
            """,
            (case_id,),
        )
        node = await cur.fetchone()
        assert node[0] == [first_id]
        assert node[1] == [evidence_id]
        assert node[2:4] == ("OBSERVED_FACT", "UNTRUSTED_INTRUDER_OUTPUT")
        assert "<b>" not in node[4]

    version = await projector.rebuild_case(conn, case_id)
    await conn.commit()
    assert version >= 3
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT freshness_status FROM dashboard_case_summary WHERE case_id=%s
            """,
            (case_id,),
        )
        assert (await cur.fetchone())[0] == "CURRENT"
        await cur.execute(
            """
            SELECT gap_detected FROM dashboard_projection_offsets
            WHERE projector_name='dashboard-v1' AND case_id=%s
            """,
            (case_id,),
        )
        assert (await cur.fetchone())[0] is False


async def test_report_worker_generates_verifies_and_ledgers_package(
    dashboard_conn,
) -> None:
    conn = dashboard_conn
    case_id, export_id, report_id = generate_ulid(), generate_ulid(), generate_ulid()
    store = MemoryObjectStore()
    evidence_service = EvidenceService(store=store)
    signer = LocalDevelopmentSigner(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id,severity,owner) VALUES (%s,'HIGH','report-analyst')",
            (case_id,),
        )
    evidence = await evidence_service.acquire(
        conn,
        request=AcquisitionRequest(
            case_id=case_id,
            session_id=None,
            evidence_type="LOG",
            source_id="report-test-source",
            source_sequence=1,
            source_certificate_serial=None,
            related_event_ids=[generate_ulid()],
            acquisition_time=datetime.now(UTC),
            original_filename="activity-分析.log",
            media_type="text/plain",
            collection_method="INTEGRATION_TEST",
            classification="SENSITIVE",
            metadata={"display": "<script>not executable</script>"},
        ),
        stream=io.BytesIO(b"controlled report evidence"),
        actor="report-test",
    )
    assert (
        await evidence_service.verify(
            conn,
            evidence_id=evidence.evidence_id,
            reason="REPORT_TEST",
            requested_by="report-test",
        )
        == "VERIFIED"
    )
    evidence_manifest = {
        "manifest_version": "1.0",
        "evidence_objects": [
            {
                "evidence_id": evidence.evidence_id,
                "evidence_type": "LOG",
                "source_id": "report-test-source",
                "source_sequence": 1,
                "acquisition_time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "sha256": evidence.sha256,
                "s3_bucket": evidence.bucket,
                "s3_key": evidence.key,
                "s3_version_id": evidence.version_id,
            }
        ],
    }
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO evidence_exports (
                export_id,case_id,export_version,manifest_version,manifest_sha256,
                verification_status,created_by,verified_at
            ) VALUES (%s,%s,1,'1.0',%s,'VERIFIED','report-analyst',now())
            """,
            (
                export_id,
                case_id,
                hashlib.sha256(canonical_json_bytes(evidence_manifest)).hexdigest(),
            ),
        )
    manifest_evidence = await evidence_service.acquire(
        conn,
        request=AcquisitionRequest(
            case_id=case_id,
            session_id=None,
            evidence_type="MANIFEST",
            source_id="mirage-report-worker",
            source_sequence=1,
            source_certificate_serial=None,
            related_event_ids=[],
            acquisition_time=datetime.now(UTC),
            original_filename=f"{export_id}-manifest.json",
            media_type="application/json",
            collection_method="INTEGRATION_TEST",
            classification="SENSITIVE",
            metadata={"export_id": export_id},
            required_for_export=False,
        ),
        stream=io.BytesIO(canonical_json_bytes(evidence_manifest)),
        actor="mirage-report-worker",
    )
    await evidence_service.verify(
        conn,
        evidence_id=manifest_evidence.evidence_id,
        reason="REPORT_TEST",
        requested_by="report-test",
    )
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO case_reports (
                report_id,case_id,export_id,idempotency_key,export_mode,
                template_version,report_schema_version,generator_version,
                build_hash,source_projection_version,status,created_by
            ) VALUES (%s,%s,%s,'report-test-key','METADATA_ONLY',%s,%s,%s,%s,1,
                      'WAITING_FOR_EXPORT','report-analyst')
            """,
            (
                report_id,
                case_id,
                export_id,
                REPORT_TEMPLATE_VERSION,
                REPORT_SCHEMA_VERSION,
                REPORT_GENERATOR_VERSION,
                "b" * 40,
            ),
        )
    await conn.commit()

    assert await process_next_report(
        conn,
        evidence_service=evidence_service,
        object_store=store,
        signer=signer,
    )
    await conn.commit()
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT status,progress,verification_status,package_evidence_id,
                   package_sha256,error
            FROM case_reports WHERE report_id=%s
            """,
            (report_id,),
        )
        row = await cur.fetchone()
        assert row[:3] == ("COMPLETED", 100, "VERIFIED"), row
        assert row[3] and len(row[4]) == 64 and row[5] is None
        await cur.execute(
            "SELECT count(*) FROM report_audit WHERE report_id=%s",
            (report_id,),
        )
        assert (await cur.fetchone())[0] >= 1


async def test_report_cancelled_and_failed_states_are_durable(dashboard_conn) -> None:
    conn = dashboard_conn
    store = MemoryObjectStore()
    service = EvidenceService(store=store)
    signer = LocalDevelopmentSigner(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    case_id = generate_ulid()
    failed_export, cancelled_report, failed_report = (
        generate_ulid(),
        generate_ulid(),
        generate_ulid(),
    )
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id,severity,owner) VALUES (%s,'LOW','report-analyst')",
            (case_id,),
        )
        await cur.execute(
            """
            INSERT INTO evidence_exports (
                export_id,case_id,export_version,manifest_version,
                verification_status,verification_error,created_by
            ) VALUES (%s,%s,1,'1.0','FAILED','injected failure','report-analyst')
            """,
            (failed_export, case_id),
        )
        for report_id, export_id, status, key in (
            (cancelled_report, None, "CANCEL_REQUESTED", "cancel-key"),
            (failed_report, failed_export, "WAITING_FOR_EXPORT", "fail-key"),
        ):
            await cur.execute(
                """
                INSERT INTO case_reports (
                    report_id,case_id,export_id,idempotency_key,export_mode,
                    template_version,report_schema_version,generator_version,
                    build_hash,status,created_by
                ) VALUES (%s,%s,%s,%s,'METADATA_ONLY',%s,%s,%s,%s,%s,'report-analyst')
                """,
                (
                    report_id,
                    case_id,
                    export_id,
                    key,
                    REPORT_TEMPLATE_VERSION,
                    REPORT_SCHEMA_VERSION,
                    REPORT_GENERATOR_VERSION,
                    "c" * 40,
                    status,
                ),
            )
    await conn.commit()
    for _ in range(2):
        assert await process_next_report(
            conn,
            evidence_service=service,
            object_store=store,
            signer=signer,
        )
        await conn.commit()
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT report_id,status FROM case_reports WHERE case_id=%s",
            (case_id,),
        )
        states = dict(await cur.fetchall())
    assert states[cancelled_report] == "CANCELLED"
    assert states[failed_report] == "FAILED"
