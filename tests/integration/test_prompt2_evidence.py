from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
import pytest_asyncio
from mirage_outbox_relay.relay import OutboxRelay

from mirage_common.analyst import (
    AnalystChannelError,
    channel_disabled,
    create_message,
    preview_message,
    set_channel_control,
)
from mirage_common.evidence import (
    AcquisitionRequest,
    EvidenceService,
    MemoryObjectStore,
    export_eligibility,
)
from mirage_common.nats_client import DeadLetterAwareConsumer
from mirage_common.sandbox_actions import open_pending_action, record_action_result
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


@pytest_asyncio.fixture(scope="module")
async def prompt2_conn(postgres_container):
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


async def test_prompt2_migration_upgrade_downgrade_upgrade(prompt2_conn) -> None:
    conn = prompt2_conn
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT table_name FROM information_schema.tables
            WHERE table_schema='public'
              AND table_name IN (
                'evidence_objects','evidence_exports','behaviour_profiles',
                'ai_snapshots','artifacts','canary_tokens','analyst_directives',
                'analyst_messages'
              )
            """
        )
        assert {row[0] for row in await cur.fetchall()} == {
            "evidence_objects",
            "evidence_exports",
            "behaviour_profiles",
            "ai_snapshots",
            "artifacts",
            "canary_tokens",
            "analyst_directives",
            "analyst_messages",
        }
    # Later Prompt 3 migrations have foreign keys to Prompt 2 tables. Exercise
    # the real ordered rollback boundary instead of using CASCADE (which could
    # silently discard a dashboard/report schema in an operator rollback).
    downs = [
        ROOT / "infra/migrations/0010_case_reports.down.sql",
        ROOT / "infra/migrations/0009_dashboard_read_model.down.sql",
        ROOT / "infra/migrations/0008_prompt2_stages_5_to_8.down.sql",
    ]
    ups = [
        ROOT / "infra/migrations/0008_prompt2_stages_5_to_8.up.sql",
        ROOT / "infra/migrations/0009_dashboard_read_model.up.sql",
        ROOT / "infra/migrations/0010_case_reports.up.sql",
    ]
    for migration in downs:
        await conn.execute(migration.read_text())
    await conn.commit()
    async with conn.cursor() as cur:
        await cur.execute("SELECT to_regclass('public.evidence_objects')")
        assert (await cur.fetchone())[0] is None
        await cur.execute("SELECT to_regclass('public.cases')")
        assert (await cur.fetchone())[0] == "cases"
    for migration in ups:
        await conn.execute(migration.read_text())
    await conn.commit()


@pytest.mark.usefixtures("mirage_streams")
async def test_evidence_acquire_verify_outbox_and_failures(
    prompt2_conn, js
) -> None:
    conn = prompt2_conn
    case_id, session_id = generate_ulid(), generate_ulid()
    source_id = "spider-evidence-test"
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id,severity,owner) VALUES (%s,'HIGH','analyst')",
            (case_id,),
        )
        await cur.execute(
            """
            INSERT INTO sessions (session_id,case_id,protocol,status)
            VALUES (%s,%s,'HTTPS','ACTIVE')
            """,
            (session_id, case_id),
        )
        await cur.execute(
            """
            INSERT INTO agents (
                agent_id,role,certificate_profile,certificate_serial,
                certificate_not_after,build_hash,host_fingerprint,status
            ) VALUES (%s,'SPIDER','MirageSpider','SERIAL-EVIDENCE',
                      now()+interval '1 day',%s,%s,'ACTIVE')
            """,
            (source_id, "a" * 64, "b" * 64),
        )
    await conn.commit()
    store = MemoryObjectStore()
    service = EvidenceService(store=store)
    request = AcquisitionRequest(
        case_id=case_id,
        session_id=session_id,
        evidence_type="LOG",
        source_id=source_id,
        source_sequence=1,
        source_certificate_serial="SERIAL-EVIDENCE",
        related_event_ids=[generate_ulid()],
        acquisition_time=datetime.now(UTC),
        original_filename="../../activity.log",
        media_type="text/plain",
        collection_method="SPIDER_STREAM",
        classification="SENSITIVE",
        metadata={"required": True},
    )
    record = await service.acquire(
        conn, request=request, stream=io.BytesIO(b"immutable evidence"), actor=source_id
    )
    duplicate = await service.acquire(
        conn, request=request, stream=io.BytesIO(b"immutable evidence"), actor=source_id
    )
    await conn.commit()
    assert duplicate == record
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT count(*) FROM evidence_objects WHERE source_id=%s AND source_sequence=1",
            (source_id,),
        )
        assert (await cur.fetchone())[0] == 1
    assert record.verification_status == "PENDING"
    assert record.key.startswith(f"cases/{case_id}/logs/")

    consumer = DeadLetterAwareConsumer(
        js,
        stream="MIRAGE_EVIDENCE",
        durable_name=f"prompt2-evidence-{generate_ulid().lower()}",
        filter_subject="evidence.created",
    )
    await consumer.bind()
    relay = OutboxRelay(conn, js)
    assert await relay.relay_once() == 1
    messages = await consumer.fetch(1, timeout=3)
    assert len(messages) == 1
    await messages[0].ack()

    assert await service.verify(
        conn,
        evidence_id=record.evidence_id,
        reason="AFTER_ACQUISITION",
        requested_by="mirage-worker",
    ) == "VERIFIED"
    await conn.commit()
    eligible, reasons = await export_eligibility(conn, case_id=case_id)
    assert eligible and not reasons

    store.objects[(record.key, record.version_id)] = b"corrupted"
    assert await service.verify(
        conn,
        evidence_id=record.evidence_id,
        reason="PRE_EXPORT",
        requested_by="auditor",
    ) == "HASH_MISMATCH"
    await conn.commit()
    del store.objects[(record.key, record.version_id)]
    assert await service.verify(
        conn,
        evidence_id=record.evidence_id,
        reason="ANALYST_REQUEST",
        requested_by="auditor",
    ) == "MISSING"
    await conn.commit()
    eligible, reasons = await export_eligibility(conn, case_id=case_id)
    assert not eligible
    assert any("MISSING" in reason for reason in reasons)


async def test_collection_gap_blocks_only_when_required_and_unresolved(prompt2_conn) -> None:
    conn = prompt2_conn
    case_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id,severity,owner) VALUES (%s,'LOW','analyst')",
            (case_id,),
        )
        await cur.execute(
            """
            INSERT INTO evidence_collection_gaps (
                gap_id,case_id,evidence_type,required,reason,documented_by
            ) VALUES (%s,%s,'SCREENSHOT',FALSE,'optional UI unavailable','analyst')
            """,
            (generate_ulid(), case_id),
        )
    await conn.commit()
    assert (await export_eligibility(conn, case_id=case_id))[0]
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO evidence_collection_gaps (
                gap_id,case_id,evidence_type,required,reason,documented_by
            ) VALUES (%s,%s,'RAW_TELEMETRY',TRUE,'sequence gap','analyst')
            """,
            (generate_ulid(), case_id),
        )
    await conn.commit()
    assert not (await export_eligibility(conn, case_id=case_id))[0]


async def test_analyst_emergency_controls_confirmation_and_replay(prompt2_conn) -> None:
    conn = prompt2_conn
    case_id, session_id, decision_id = generate_ulid(), generate_ulid(), generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO cases (case_id,state,severity,owner)
            VALUES (%s,'ENGAGING','MEDIUM','analyst')
            """,
            (case_id,),
        )
        await cur.execute(
            """
            INSERT INTO sessions (session_id,case_id,protocol,status)
            VALUES (%s,%s,'HTTPS','ACTIVE')
            """,
            (session_id, case_id),
        )
        await cur.execute(
            """
            INSERT INTO policy_decisions (
                decision_id,case_id,policy_version,decision,reason_codes,
                analyst_approval
            ) VALUES (%s,%s,'message-test-1.0','ALLOW','["ALLOW_TEST"]',TRUE)
            """,
            (decision_id, case_id),
        )
    normal = preview_message(
        case_id=case_id,
        surface="DECOY_WEB_CHAT",
        content="The diagnostic service is available.",
    )
    created = await create_message(
        conn,
        case_id=case_id,
        session_id=session_id,
        author_id="analyst",
        content=normal.content,
        surface=normal.surface,
        supplied_preview_hash=normal.preview_hash,
        policy_decision_id=decision_id,
        idempotency_key="normal-message",
    )
    replay = await create_message(
        conn,
        case_id=case_id,
        session_id=session_id,
        author_id="analyst",
        content=normal.content,
        surface=normal.surface,
        supplied_preview_hash=normal.preview_hash,
        policy_decision_id=decision_id,
        idempotency_key="normal-message",
    )
    assert replay["message_id"] == created["message_id"]
    await set_channel_control(
        conn,
        scope="PLATFORM",
        case_id=None,
        disabled=True,
        changed_by="platform-admin",
        reason="Prompt 2 emergency test",
    )
    assert await channel_disabled(conn, case_id=case_id)
    with pytest.raises(AnalystChannelError, match="disabled"):
        await create_message(
            conn,
            case_id=case_id,
            session_id=session_id,
            author_id="analyst",
            content=normal.content,
            surface=normal.surface,
            supplied_preview_hash=normal.preview_hash,
            policy_decision_id=decision_id,
            idempotency_key="blocked-message",
        )
    await set_channel_control(
        conn,
        scope="PLATFORM",
        case_id=None,
        disabled=False,
        changed_by="platform-admin",
        reason="Controlled re-enable",
    )
    sensitive = preview_message(
        case_id=case_id,
        surface="DECOY_TERMINAL_BANNER",
        content="Enter your credential to continue.",
    )
    pending = await create_message(
        conn,
        case_id=case_id,
        session_id=session_id,
        author_id="analyst",
        content=sensitive.content,
        surface=sensitive.surface,
        supplied_preview_hash=sensitive.preview_hash,
        policy_decision_id=decision_id,
        idempotency_key="sensitive-message",
    )
    assert pending["status"] == "PENDING_CONFIRMATION"
    await conn.commit()


async def test_artifact_deployment_result_and_rollback_reconciliation(
    prompt2_conn,
) -> None:
    conn = prompt2_conn
    case_id, artifact_id, deployment_id = (
        generate_ulid(),
        generate_ulid(),
        generate_ulid(),
    )
    sandbox_id = f"sandbox-{generate_ulid().lower()}"
    sha256 = "c" * 64
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO cases (case_id,severity,owner) VALUES (%s,'MEDIUM','analyst')",
            (case_id,),
        )
        await cur.execute(
            """
            INSERT INTO sandbox_instances (sandbox_id,case_id,image_id,status)
            VALUES (%s,%s,'prompt2-rollback-test','ACTIVE')
            """,
            (sandbox_id, case_id),
        )
        await cur.execute(
            """
            INSERT INTO artifacts (
                artifact_id,case_id,original_filename,sanitised_filename,
                media_type,size_bytes,sha256,scan_status,
                quarantine_location,approved_for_deployment,
                artifact_classification
            ) VALUES (
                %s,%s,'bait.txt','bait.txt','text/plain',4,%s,'APPROVED',
                '/tmp/bait.txt',TRUE,'INERT'
            )
            """,
            (artifact_id, case_id, sha256),
        )
    place = await open_pending_action(
        conn,
        sandbox_id=sandbox_id,
        case_id=case_id,
        action_type="PLACE_ARTIFACT",
        action_params={"destination": "/sandbox/mirage/bait.txt"},
        expected_state_version=0,
        issued_by="ANALYST",
    )
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO artifact_deployments (
                deployment_id,case_id,artifact_id,destination,
                download_url_expires_at,download_token_hash,status,
                expected_sha256,sandbox_action_id,idempotency_key,created_by
            ) VALUES (
                %s,%s,%s,'/sandbox/mirage/bait.txt',now()+interval '5 minutes',
                %s,'PENDING',%s,%s,'rollback-reconciliation','analyst'
            )
            """,
            (
                deployment_id,
                case_id,
                artifact_id,
                "d" * 64,
                sha256,
                place.action_id,
            ),
        )
    assert (
        await record_action_result(
            conn,
            action=place,
            status="SUCCESS",
            output_tag="REAL_OS_OUTPUT",
            rollback_action_id=None,
            error_detail=None,
        )
        == 1
    )
    rollback = await open_pending_action(
        conn,
        sandbox_id=sandbox_id,
        case_id=case_id,
        action_type="ROLLBACK_ACTION",
        action_params={"target_action_id": place.action_id},
        expected_state_version=1,
        issued_by="ANALYST",
    )
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE artifact_deployments
            SET status='ROLLBACK_PENDING',rollback_action_id=%s
            WHERE deployment_id=%s
            """,
            (rollback.action_id, deployment_id),
        )
    assert (
        await record_action_result(
            conn,
            action=rollback,
            status="SUCCESS",
            output_tag="REAL_OS_OUTPUT",
            rollback_action_id=place.action_id,
            error_detail=None,
        )
        == 2
    )
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT d.status,a.deployment_status,a.approved_for_deployment
            FROM artifact_deployments d
            JOIN artifacts a ON a.artifact_id=d.artifact_id
            WHERE d.deployment_id=%s
            """,
            (deployment_id,),
        )
        assert await cur.fetchone() == ("REVOKED", "REVOKED", False)
    await conn.commit()
