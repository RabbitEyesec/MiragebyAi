"""End-to-end test: MirageEndpoint's real business logic (service_logic.py)
against a REAL mirage-agent-ingestion server (real uvicorn process, real TCP,
real TLS — not an in-process ASGI transport) backed by real Postgres and
real step-ca. This is the strongest available local proxy for "a test agent
enrolls" without an actual Windows host.

Heartbeat's mTLS + Nginx-header requirement is intentionally NOT exercised
here (KNOWN_ISSUES.md: the mTLS-terminating Nginx listener is Step 8b work);
tests/integration/test_agent_ingestion_api.py already covers heartbeat
authorization logic directly against the app.
"""
from __future__ import annotations

import uuid

import pytest
from mirage_agent_ingestion.enrollment import create_enrollment_token
from mirage_endpoint.service_logic import EndpointServiceLogic

from mirage_common.agent_http_client import AgentHttpClient
from mirage_common.agent_keys import LocalFileKeyProvider
from mirage_common.agent_queue import EncryptedEventQueue

pytestmark = pytest.mark.integration

TEST_BUILD_HASH = "c" * 64


async def test_endpoint_enrolls_against_a_real_live_server(tmp_path, pg_conn, ca_config, live_agent_ingestion_server):
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_subject = f"endpoint-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_subject, sans=[agent_subject], created_by="test",
    )

    client = AgentHttpClient(
        base_url=live_agent_ingestion_server["base_url"], root_ca_path=live_agent_ingestion_server["root_ca_path"],
    )
    queue = EncryptedEventQueue(tmp_path / "queue.db", LocalFileKeyProvider(tmp_path / "queue.key"))
    logic = EndpointServiceLogic(
        client=client, queue=queue,
        identity_state_path=tmp_path / "identity.json", cert_dir=tmp_path / "certs",
        build_hash=TEST_BUILD_HASH,
    )

    assert not logic.is_enrolled()
    identity = await logic.enroll(enrollment_token=minted.token, subject=agent_subject)
    assert logic.is_enrolled()

    reloaded = logic.load_identity()
    assert reloaded.agent_id == identity.agent_id
    assert reloaded.certificate_serial == identity.certificate_serial
    assert identity.certificate_path.exists()
    assert identity.certificate_key_path.exists()

    payload = logic.build_heartbeat_payload(identity, uptime_seconds=42)
    assert payload["agent_id"] == identity.agent_id
    assert payload["queue_depth"] == 0

    logic.enqueue_event({"event_type": "system.health"}, enqueued_at="2026-07-25T00:00:00.000Z")
    payload2 = logic.build_heartbeat_payload(identity, uptime_seconds=43)
    assert payload2["queue_depth"] == 1


async def _allow_build_hash(pg_conn, role: str, build_hash: str = TEST_BUILD_HASH) -> None:
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (build_hash, role, "test"),
        )
    await pg_conn.commit()
