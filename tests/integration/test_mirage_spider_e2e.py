"""End-to-end test: MirageSpider's real business logic (service_logic.py)
against a REAL mirage-agent-ingestion server (real uvicorn process, real
TCP, real TLS — not an in-process ASGI transport) backed by real Postgres
and real step-ca. This is the strongest available local proxy for "a test
Spider enrolls" without an actual Windows host — mirrors
test_mirage_endpoint_e2e.py's scope exactly, for the same reason.

Telemetry/tamper submission's mTLS + Nginx-header requirement is
intentionally NOT exercised against the live server here (KNOWN_ISSUES.md:
the mTLS-terminating Nginx listener is Step 8b work, same boundary Step 4's
heartbeat test already documents) — tests/integration/test_agent_ingestion_api.py
covers the server-side telemetry contract directly (in-process ASGI, proxy
headers set explicitly), and tests/unit/test_spider_service_logic.py covers
SpiderServiceLogic's tamper-priority/ordering behavior against a fake
transport. What THIS file adds on top: real enrollment over real mTLS, real
local queue/sequence orchestration through SpiderServiceLogic, and a real
network call proving the "never lost even when the send genuinely fails"
guarantee holds against an actual (not simulated) rejection.
"""
from __future__ import annotations

import uuid

import pytest
from mirage_agent_ingestion.enrollment import create_enrollment_token
from mirage_spider.service_logic import SpiderServiceLogic

from mirage_common.agent_http_client import AgentHttpClient
from mirage_common.agent_keys import LocalFileKeyProvider
from mirage_common.agent_queue import EncryptedEventQueue

pytestmark = pytest.mark.integration

TEST_BUILD_HASH = "d" * 64


async def _allow_build_hash(pg_conn, role: str, build_hash: str = TEST_BUILD_HASH) -> None:
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (build_hash, role, "test"),
        )
    await pg_conn.commit()


async def test_spider_enrolls_against_a_real_live_server_and_queues_ordered_case_tagged_events(
    tmp_path, pg_conn, ca_config, live_agent_ingestion_server,
):
    await _allow_build_hash(pg_conn, "SPIDER")
    agent_subject = f"spider-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="SPIDER", subject=agent_subject, sans=[agent_subject], created_by="test",
    )

    client = AgentHttpClient(
        base_url=live_agent_ingestion_server["base_url"], root_ca_path=live_agent_ingestion_server["root_ca_path"],
    )
    queue = EncryptedEventQueue(tmp_path / "queue.db", LocalFileKeyProvider(tmp_path / "queue.key"))
    logic = SpiderServiceLogic(
        client=client, queue=queue,
        identity_state_path=tmp_path / "identity.json", cert_dir=tmp_path / "certs",
        build_hash=TEST_BUILD_HASH,
    )

    assert not logic.is_enrolled()
    identity = await logic.enroll(enrollment_token=minted.token, subject=agent_subject)
    assert logic.is_enrolled()
    assert identity.certificate_path.exists()
    assert identity.certificate_key_path.exists()

    reloaded = logic.load_identity()
    assert reloaded.agent_id == identity.agent_id
    assert reloaded.certificate_serial == identity.certificate_serial

    # "Read-only" claim: nothing about enroll/observe/report touches
    # anything outside this agent's own state files — no assertion needed
    # beyond the structural fact that SpiderServiceLogic exposes no
    # filesystem/process-mutation method at all (reviewed in KNOWN_ISSUES.md
    # the same way Step 4's "never execute arbitrary server commands" was).

    case_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    seq1 = logic.record_observation(identity, observation_type="PROCESS_START", subject="cmd.exe", case_id=case_id)
    seq2 = logic.record_observation(identity, observation_type="FILE_CREATE", subject="C:\\decoy\\notes.txt", case_id=case_id)
    seq3 = logic.record_observation(identity, observation_type="NETWORK_CONNECTION", subject="10.0.4.55:445", case_id=case_id)

    assert (seq1, seq2, seq3) == (1, 2, 3)
    assert queue.pending_count() == 3

    queued = queue.peek_batch()
    assert [e["sequence"] for _row_id, e in queued] == [1, 2, 3]
    assert all(e["case_id"] == case_id for _row_id, e in queued)
    assert all(e["event_type"] == "spider.observation" for _row_id, e in queued)
    assert [e["payload"]["subject"] for _row_id, e in queued] == ["cmd.exe", "C:\\decoy\\notes.txt", "10.0.4.55:445"]

    payload = logic.build_heartbeat_payload(identity, uptime_seconds=42)
    assert payload["agent_id"] == identity.agent_id
    assert payload["role"] == "SPIDER"
    assert payload["queue_depth"] == 3


async def test_spider_sequence_survives_restart_with_zero_loss(tmp_path, pg_conn, ca_config, live_agent_ingestion_server):
    """Step 5 Definition of Done: 'sequence survives a 5-min outage with
    zero loss.' Simulated here as a service restart (fresh SpiderServiceLogic
    object, same on-disk queue.db) — the honest local proxy for an outage,
    since a real 5-minute wall-clock outage isn't practical in a test suite."""
    await _allow_build_hash(pg_conn, "SPIDER")
    agent_subject = f"spider-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="SPIDER", subject=agent_subject, sans=[agent_subject], created_by="test",
    )
    client = AgentHttpClient(
        base_url=live_agent_ingestion_server["base_url"], root_ca_path=live_agent_ingestion_server["root_ca_path"],
    )
    queue_path = tmp_path / "queue.db"
    key_provider = LocalFileKeyProvider(tmp_path / "queue.key")

    queue1 = EncryptedEventQueue(queue_path, key_provider)
    logic1 = SpiderServiceLogic(
        client=client, queue=queue1, identity_state_path=tmp_path / "identity.json",
        cert_dir=tmp_path / "certs", build_hash=TEST_BUILD_HASH,
    )
    identity = await logic1.enroll(enrollment_token=minted.token, subject=agent_subject)
    logic1.record_observation(identity, observation_type="PROCESS_START", subject="a.exe")
    logic1.record_observation(identity, observation_type="PROCESS_START", subject="b.exe")
    # "Outage": nothing sent yet, service stops.
    queue1.close()

    # "Restart": brand-new logic object, same on-disk queue and identity.
    queue2 = EncryptedEventQueue(queue_path, key_provider)
    logic2 = SpiderServiceLogic(
        client=client, queue=queue2, identity_state_path=tmp_path / "identity.json",
        cert_dir=tmp_path / "certs", build_hash=TEST_BUILD_HASH,
    )
    reloaded_identity = logic2.load_identity()
    assert reloaded_identity.agent_id == identity.agent_id

    # Sequence continues, does not reset — the third event gets sequence=3.
    seq3 = logic2.record_observation(reloaded_identity, observation_type="PROCESS_STOP", subject="a.exe")
    assert seq3 == 3
    assert queue2.pending_count() == 3  # all three, including the two from "before the outage" — zero loss

    queued = queue2.peek_batch()
    assert [e["sequence"] for _row_id, e in queued] == [1, 2, 3]


async def test_spider_tamper_event_falls_back_to_the_durable_queue_on_a_real_send_failure(
    tmp_path, pg_conn, ca_config, live_agent_ingestion_server,
):
    """Against the live server (no Nginx in front of it in this test, so the
    mTLS-derived proxy headers auth_dependency requires are genuinely
    absent — see module docstring), a tamper submission genuinely fails.
    record_tamper()'s contract is that ANY failure falls back to the durable
    queue rather than losing the event — proven here against a real,
    unscripted rejection, not a simulated one (the success/immediate-delivery
    path is covered against a fake transport in
    tests/unit/test_spider_service_logic.py)."""
    await _allow_build_hash(pg_conn, "SPIDER")
    agent_subject = f"spider-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="SPIDER", subject=agent_subject, sans=[agent_subject], created_by="test",
    )
    client = AgentHttpClient(
        base_url=live_agent_ingestion_server["base_url"], root_ca_path=live_agent_ingestion_server["root_ca_path"],
    )
    queue = EncryptedEventQueue(tmp_path / "queue.db", LocalFileKeyProvider(tmp_path / "queue.key"))
    logic = SpiderServiceLogic(
        client=client, queue=queue, identity_state_path=tmp_path / "identity.json",
        cert_dir=tmp_path / "certs", build_hash=TEST_BUILD_HASH,
    )
    identity = await logic.enroll(enrollment_token=minted.token, subject=agent_subject)

    delivered = await logic.record_tamper(identity, tamper_type="PROCESS_KILL_ATTEMPT", detail="taskkill /IM MirageSpider.exe")

    assert delivered is False  # real rejection (missing proxy headers) — not lost, though
    assert queue.pending_count() == 1
    _row_id, queued_event = queue.peek_batch()[0]
    assert queued_event["event_type"] == "spider.tamper"
    assert queued_event["payload"]["tamper_type"] == "PROCESS_KILL_ATTEMPT"
