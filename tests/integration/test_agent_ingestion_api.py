"""Integration tests for the mirage-agent-ingestion FastAPI app
(POST /api/v1/enroll, POST /api/v1/agents/{id}/heartbeat,
POST /api/v1/agents/{id}/telemetry) — real Postgres, real step-ca, real
NATS JetStream, in-process ASGI transport (httpx.AsyncClient against the app
directly; no separate network hop, but every layer underneath is real).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from mirage_agent_ingestion.app import create_app
from mirage_agent_ingestion.enrollment import create_enrollment_token, enroll_agent, revoke_agent

from mirage_common.mtls_auth import CLIENT_SERIAL_HEADER, PROXY_SHARED_SECRET_HEADER
from mirage_common.nats_client import DeadLetterAwareConsumer
from mirage_contracts.envelope import build_event

pytestmark = pytest.mark.integration

PROXY_SECRET = "test-proxy-shared-secret"  # secret-scan: ignore (test-only placeholder)
TEST_BUILD_HASH = "b" * 64
REPO_ROOT = Path(__file__).resolve().parents[2]


def _generate_csr(common_name: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
async def app(pg_conn, pg_dsn, ca_config, nats_container):
    # pg_conn fixture only applies migration 0001 by default; every test in
    # this file exercises POST /telemetry, which now depends on migration
    # 0011's idempotent-replay receipts table (Priority 2 crash-safety fix),
    # so it's applied here once for the whole module rather than repeated
    # per test the way the fingerprint-snapshot test applies 0007 for itself.
    migration_0011 = (
        REPO_ROOT / "infra" / "migrations" / "0011_agent_telemetry_receipts.up.sql"
    ).read_text()
    async with pg_conn.cursor() as cur:
        await cur.execute("DROP TABLE IF EXISTS agent_telemetry_receipts CASCADE")
        await cur.execute(migration_0011)
    await pg_conn.commit()

    # pg_conn fixture (already applies migration 0001) forces schema setup
    # before the app's own connection pool opens against the same database.
    application = create_app(pg_dsn=pg_dsn, ca=ca_config, proxy_shared_secret=PROXY_SECRET, nats_url=nats_container)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client,
    ):
        yield client, application


async def _allow_build_hash(pg_conn, role: str, build_hash: str = TEST_BUILD_HASH) -> None:
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (build_hash, role, "test"),
        )
    await pg_conn.commit()


async def test_enroll_endpoint_issues_certificate(app, pg_conn, ca_config):
    client, application = app
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"

    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )

    response = await client.post(
        "/api/v1/enroll",
        json={
            "enrollment_token": minted.token,
            "role": "ENDPOINT",
            "csr_pem": _generate_csr(agent_id),
            "host_fingerprint": "AA:BB:CC:DD:EE:FF",
            "build_hash": TEST_BUILD_HASH,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["agent_id"] == agent_id
    assert body["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")


async def test_enroll_endpoint_rejects_reused_token(app, pg_conn, ca_config):
    client, application = app
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"

    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )
    payload = {
        "enrollment_token": minted.token,
        "role": "ENDPOINT",
        "csr_pem": _generate_csr(agent_id),
        "host_fingerprint": "AA:BB:CC:DD:EE:FF",
        "build_hash": TEST_BUILD_HASH,
    }

    first = await client.post("/api/v1/enroll", json=payload)
    assert first.status_code == 200

    second = await client.post("/api/v1/enroll", json=payload)
    assert second.status_code == 401
    body = second.json()
    assert body["error_code"] == "TOKEN_EXPIRED_OR_REUSED_OR_UNKNOWN"


async def test_heartbeat_requires_proxy_headers(app, pg_conn, ca_config):
    client, application = app
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"

    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )
    enrolled = await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="00:11:22:33:44:55", build_hash=TEST_BUILD_HASH,
    )

    heartbeat_body = {
        "agent_id": agent_id, "role": "ENDPOINT", "build_hash": TEST_BUILD_HASH,
        "version": "1.0.0", "certificate_serial": enrolled.certificate_serial,
        "uptime_seconds": 5, "health_state": "HEALTHY",
    }

    # No headers at all -> rejected before touching business logic.
    no_auth = await client.post(f"/api/v1/agents/{agent_id}/heartbeat", json=heartbeat_body)
    assert no_auth.status_code == 401

    # Correct proxy secret + correct serial -> accepted.
    ok = await client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        json=heartbeat_body,
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial},
    )
    assert ok.status_code == 200, ok.text

    # Correct proxy secret but WRONG serial (impersonation attempt) -> rejected.
    wrong_serial = await client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        json=heartbeat_body,
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: "0"},
    )
    assert wrong_serial.status_code == 403


async def test_heartbeat_rejected_for_revoked_agent(app, pg_conn, ca_config):
    client, application = app
    await _allow_build_hash(pg_conn, "SPIDER")
    agent_id = f"spider-{uuid.uuid4().hex}.mirage.local"

    minted = await create_enrollment_token(
        pg_conn, ca_config, role="SPIDER", subject=agent_id, sans=[agent_id], created_by="test",
    )
    enrolled = await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="11:22:33:44:55:66", build_hash=TEST_BUILD_HASH,
    )
    await revoke_agent(pg_conn, ca_config, agent_id=agent_id, reason="test revocation")

    heartbeat_body = {
        "agent_id": agent_id, "role": "SPIDER", "build_hash": TEST_BUILD_HASH,
        "version": "1.0.0", "certificate_serial": enrolled.certificate_serial,
        "uptime_seconds": 5, "health_state": "HEALTHY",
    }

    response = await client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        json=heartbeat_body,
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial},
    )
    assert response.status_code == 403


async def _enrolled_spider(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "SPIDER")
    agent_id = f"spider-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="SPIDER", subject=agent_id, sans=[agent_id], created_by="test",
    )
    enrolled = await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="AA:AA:AA:AA:AA:AA", build_hash=TEST_BUILD_HASH,
    )
    return agent_id, enrolled


def _observation_event(*, agent_id: str, sequence: int, case_id: str | None = None) -> dict:
    return build_event(
        event_type="spider.observation", schema_version="1.0",
        payload={"observation_type": "PROCESS_START", "subject": "cmd.exe", "observed_at": "2026-07-25T00:00:00.000Z"},
        source_id=agent_id, sequence=sequence, actor_type="SPIDER_AGENT", classification="EVIDENCE",
        case_id=case_id,
    )


async def test_telemetry_endpoint_accepts_and_publishes_a_spider_observation(app, pg_conn, ca_config, mirage_streams):
    client, application = app
    agent_id, enrolled = await _enrolled_spider(pg_conn, ca_config)
    event = _observation_event(agent_id=agent_id, sequence=1, case_id="01ARZ3NDEKTSV4RRFFQ69G5FAV")

    resp = await client.post(
        f"/api/v1/agents/{agent_id}/telemetry",
        json=event,
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["sequence"] == 1

    published = await _await_published_event(
        application.state.mirage.js, stream="MIRAGE_TELEMETRY", subject="telemetry.sandbox.observation", event_id=event["event_id"],
    )
    assert published["case_id"] == "01ARZ3NDEKTSV4RRFFQ69G5FAV"


async def test_telemetry_endpoint_rejects_out_of_order_sequence(app, pg_conn, ca_config, mirage_streams):
    client, application = app
    agent_id, enrolled = await _enrolled_spider(pg_conn, ca_config)
    headers = {PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial}

    first = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=_observation_event(agent_id=agent_id, sequence=1), headers=headers)
    assert first.status_code == 202

    replay = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=_observation_event(agent_id=agent_id, sequence=1), headers=headers)
    assert replay.status_code == 409

    stale = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=_observation_event(agent_id=agent_id, sequence=0), headers=headers)
    assert stale.status_code == 409

    advances = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=_observation_event(agent_id=agent_id, sequence=2), headers=headers)
    assert advances.status_code == 202


async def test_telemetry_endpoint_idempotently_replays_the_exact_same_event(
    app, pg_conn, ca_config, mirage_streams
):
    """Priority 2 crash-safety fix (migration 0011): an agent that durably
    got a 202 for this exact (agent_id, sequence, event_id) but crashed
    before recording its own local ack must be able to resend the identical
    event and get the SAME successful acknowledgement — not the 409 that
    would previously wedge the local queue permanently, since last_sequence
    had already advanced past it server-side."""
    client, application = app
    agent_id, enrolled = await _enrolled_spider(pg_conn, ca_config)
    headers = {PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial}
    event = _observation_event(agent_id=agent_id, sequence=1)

    first = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=event, headers=headers)
    assert first.status_code == 202
    assert first.json()["replay"] is False

    # "Crash after send, before local ack": the agent never recorded that
    # this specific event was acknowledged, so it resends the identical
    # bytes (same event_id) on its next flush attempt.
    retry = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=event, headers=headers)
    assert retry.status_code == 202, retry.text
    assert retry.json()["event_id"] == first.json()["event_id"] == event["event_id"]
    assert retry.json()["replay"] is True

    # A third, fourth, ... replay is equally safe — not just a one-time
    # allowance.
    third = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=event, headers=headers)
    assert third.status_code == 202
    assert third.json()["replay"] is True

    # The replay must not have published a second copy to NATS — "at-least-
    # once delivery, effectively-once business effect."
    published = await _await_published_event(
        application.state.mirage.js,
        stream="MIRAGE_TELEMETRY",
        subject="telemetry.sandbox.observation",
        event_id=event["event_id"],
    )
    assert published["event_id"] == event["event_id"]

    # The agent's cursor still advances normally for the NEXT real event.
    advances = await client.post(
        f"/api/v1/agents/{agent_id}/telemetry", json=_observation_event(agent_id=agent_id, sequence=2), headers=headers
    )
    assert advances.status_code == 202
    assert advances.json()["replay"] is False


async def test_telemetry_endpoint_rejects_disallowed_event_type(app, pg_conn, ca_config, mirage_streams):
    client, application = app
    agent_id, enrolled = await _enrolled_spider(pg_conn, ca_config)
    smuggled = build_event(
        event_type="case.created", schema_version="1.0", payload={"severity": "HIGH"},
        source_id=agent_id, sequence=1, actor_type="SPIDER_AGENT", classification="INTERNAL",
    )
    resp = await client.post(
        f"/api/v1/agents/{agent_id}/telemetry", json=smuggled,
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial},
    )
    assert resp.status_code == 400


async def test_telemetry_tamper_event_routes_to_audit_stream(app, pg_conn, ca_config, mirage_streams):
    client, application = app
    agent_id, enrolled = await _enrolled_spider(pg_conn, ca_config)
    tamper = build_event(
        event_type="spider.tamper", schema_version="1.0",
        payload={"tamper_type": "SERVICE_STOP_ATTEMPT", "detail": "sc.exe stop MirageSpider", "observed_at": "2026-07-25T00:00:00.000Z"},
        source_id=agent_id, sequence=1, actor_type="SPIDER_AGENT", classification="EVIDENCE",
    )
    resp = await client.post(
        f"/api/v1/agents/{agent_id}/telemetry", json=tamper,
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial},
    )
    assert resp.status_code == 202, resp.text

    published = await _await_published_event(
        application.state.mirage.js, stream="MIRAGE_AUDIT", subject="audit.spider.tamper", event_id=tamper["event_id"],
    )
    assert published["payload"]["tamper_type"] == "SERVICE_STOP_ATTEMPT"


async def test_telemetry_fingerprint_snapshot_upserts_the_latest_observation_cache(app, pg_conn, ca_config, mirage_streams):
    """Step 10's live gate reads sandbox_fingerprint_snapshots directly
    (see libs/mirage_common/fingerprint_gate.py) — this is the write side:
    a real spider.fingerprint_snapshot submission must land there, and a
    SECOND submission for the same sandbox_id must overwrite (not
    duplicate) the row, since the gate only ever cares about the latest."""
    from pathlib import Path

    migration_0007 = (Path(__file__).resolve().parents[2] / "infra" / "migrations" / "0007_sandbox_fingerprint_snapshots.up.sql").read_text()
    async with pg_conn.cursor() as cur:
        await cur.execute("DROP TABLE IF EXISTS sandbox_fingerprint_snapshots CASCADE")
        await cur.execute(migration_0007)
    await pg_conn.commit()

    client, application = app
    agent_id, enrolled = await _enrolled_spider(pg_conn, ca_config)
    headers = {PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: enrolled.certificate_serial}

    def _snapshot_event(sequence: int, hostname: str) -> dict:
        return build_event(
            event_type="spider.fingerprint_snapshot", schema_version="1.0",
            payload={
                "sandbox_id": "sandbox-e2e-001",
                "observed_at": "2026-07-25T00:00:00.000Z",
                "checks": {
                    "hostname_domain": {"hostname": hostname, "domain": "MIRAGE"},
                    "user_profiles_and_sids": {"profiles": []},
                    "installed_software": {"installed": []},
                    "file_timestamps": {"files_predating_hire_date": []},
                    "processes_services": {"running": []},
                    "network": {"mac_oui": "00:11:22", "dns_servers": [], "domain": "MIRAGE"},
                    "uptime": {"value": 10},
                    "decoy_service_banners": {},
                },
            },
            source_id=agent_id, sequence=sequence, actor_type="SPIDER_AGENT", classification="EVIDENCE",
        )

    first = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=_snapshot_event(1, "WKS-FIRST"), headers=headers)
    assert first.status_code == 202, first.text

    async with pg_conn.cursor() as cur:
        await cur.execute("SELECT checks, source_agent_id FROM sandbox_fingerprint_snapshots WHERE sandbox_id = 'sandbox-e2e-001'")
        checks, source_agent_id = await cur.fetchone()
    assert checks["hostname_domain"]["hostname"] == "WKS-FIRST"
    assert source_agent_id == agent_id

    second = await client.post(f"/api/v1/agents/{agent_id}/telemetry", json=_snapshot_event(2, "WKS-SECOND"), headers=headers)
    assert second.status_code == 202, second.text

    async with pg_conn.cursor() as cur:
        await cur.execute("SELECT checks FROM sandbox_fingerprint_snapshots WHERE sandbox_id = 'sandbox-e2e-001'")
        rows = await cur.fetchall()
    assert len(rows) == 1  # upsert, not a second row
    assert rows[0][0]["hostname_domain"]["hostname"] == "WKS-SECOND"

    published = await _await_published_event(
        application.state.mirage.js, stream="MIRAGE_TELEMETRY", subject="telemetry.sandbox.fingerprint_snapshot", event_id=second.json()["event_id"],
    )
    assert published["payload"]["sandbox_id"] == "sandbox-e2e-001"


async def _await_published_event(js, *, stream: str, subject: str, event_id: str, timeout: float = 5.0) -> dict:
    """Binds a fresh durable consumer and polls until the message with this
    exact event_id shows up, ack'ing everything it sees along the way.
    DeliverPolicy.ALL means a fresh consumer replays the WHOLE subject
    history (other tests in this module publish to these same real
    production subjects on the same module-scoped NATS container) — filtering
    by event_id, not by "the first/only message," is what makes this immune
    to that co-mingling instead of assuming test execution order."""
    import time

    consumer = DeadLetterAwareConsumer(
        js, stream=stream, durable_name=f"test-{uuid.uuid4().hex}", filter_subject=subject,
    )
    await consumer.bind()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msgs = await consumer.fetch(20, timeout=min(2.0, deadline - time.monotonic()))
        for msg in msgs:
            body = json.loads(msg.data)
            await msg.ack()
            if body["event_id"] == event_id:
                return body
    raise TimeoutError(f"event_id={event_id!r} was not published to {subject!r} within {timeout}s")
