"""Integration tests for Step 8a: the /route decision API + steering
approval, against real Postgres, real NATS, real Keycloak, and a real
BROKER_CLIENT agent identity (enrolled the same way Step 3 already proved).
Covers the Step 8a acceptance line: "Given an approved decision, /route
returns the sandbox for the matching key and the endpoint otherwise,
logging the steering event."
"""
from __future__ import annotations

import uuid
from pathlib import Path

import httpx
import psycopg
import pytest
from mirage_agent_ingestion.enrollment import create_enrollment_token, enroll_agent
from mirage_api.app import create_app
from mirage_api.health import HealthCheckConfig

from mirage_common.mtls_auth import CLIENT_SERIAL_HEADER, PROXY_SHARED_SECRET_HEADER

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY_SECRET = "test-routing-api-proxy-secret"  # secret-scan: ignore (test-only placeholder)


@pytest.fixture
async def pg_conn_with_routing(pg_conn):
    """Extends the shared pg_conn fixture (migration 0001) with migrations
    0002-0005 (cases, lifecycle+outbox, detection correlation, routing)."""
    migrations = [
        "0002_cases_minimal.up.sql",
        "0003_case_lifecycle_and_outbox.up.sql",
        "0004_detection_correlation.up.sql",
        "0005_routing_decisions.up.sql",
    ]
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "DROP TABLE IF EXISTS routing_decisions, audit_events, processed_events, "
            "outbox_events, case_state_transitions, cases CASCADE"
        )
        await cur.execute("DROP FUNCTION IF EXISTS notify_outbox_events() CASCADE")
        for name in migrations:
            await cur.execute((REPO_ROOT / "infra" / "migrations" / name).read_text())
    await pg_conn.commit()
    return pg_conn


@pytest.fixture
def health_config(postgres_container, nats_monitoring_url, elasticsearch_url, keycloak_realm) -> HealthCheckConfig:
    return HealthCheckConfig(
        postgres_dsn=(
            f"host={postgres_container.get_container_host_ip()} port={postgres_container.get_exposed_port(5432)} "
            f"user={postgres_container.username} password={postgres_container.password} dbname={postgres_container.dbname}"
        ),
        nats_monitoring_url=nats_monitoring_url, elasticsearch_url=elasticsearch_url,
        keycloak_issuer_url=keycloak_realm["issuer"],
        step_ca_url="https://127.0.0.1:1", step_ca_root_cert_path="/dev/null", agent_ingestion_url=None,
    )


@pytest.fixture
async def app_client(pg_conn_with_routing, pg_dsn, nats_container, mirage_streams, elasticsearch_url, keycloak_realm, health_config):
    application = create_app(
        pg_dsn=pg_dsn, nats_url=nats_container, health_config=health_config,
        elasticsearch_url=elasticsearch_url, oidc_issuer_url=keycloak_realm["issuer"],
        proxy_shared_secret=PROXY_SECRET,
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client,
    ):
        yield client, application, keycloak_realm


async def _token_for(keycloak_realm: dict, username: str) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{keycloak_realm['base_url']}/realms/mirage/protocol/openid-connect/token",
            data={
                "client_id": "mirage-dashboard", "username": username,
                "password": keycloak_realm["dev_user_password"], "grant_type": "password",
            },
        )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def _enrolled_broker(pg_conn_with_routing, ca_config, *, role: str = "BROKER_CLIENT") -> str:
    """Returns a real certificate_serial for a freshly-enrolled agent of the
    given role, via the exact same Step 3 enrollment logic every other test
    module in this suite already uses."""
    async with pg_conn_with_routing.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, %s, 'test') ON CONFLICT DO NOTHING",
            ("f" * 64, role),
        )
    await pg_conn_with_routing.commit()

    agent_id = f"broker-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn_with_routing, ca_config, role=role, subject=agent_id, sans=[agent_id], created_by="test",
    )
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(agent_id)]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    enrolled = await enroll_agent(
        pg_conn_with_routing, ca_config, enrollment_token=minted.token,
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(), host_fingerprint="AA:BB:CC:00:11:22", build_hash="f" * 64,
    )
    return enrolled.certificate_serial


async def _create_case(conn: psycopg.AsyncConnection) -> str:
    from mirage_contracts.ulid import generate_ulid

    case_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO cases (case_id, severity, owner) VALUES (%s, 'HIGH', 'analyst-1')", (case_id,))
    await conn.commit()
    return case_id


async def test_route_defaults_to_endpoint_when_no_decision_exists(app_client, pg_conn_with_routing, ca_config):
    client, _app, _kc = app_client
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"HTTP|listener-1|10.0.0.5|{uuid.uuid4().hex}"

    resp = await client.get(
        "/route", params={"match_key": match_key, "protocol": "HTTP"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"upstream": "ENDPOINT", "cached": False}


async def test_route_requires_mtls_headers(app_client):
    client, _app, _kc = app_client
    resp = await client.get("/route", params={"match_key": "x", "protocol": "HTTP"})
    assert resp.status_code == 401


async def test_route_rejects_non_broker_role(app_client, pg_conn_with_routing, ca_config):
    client, _app, _kc = app_client
    endpoint_serial = await _enrolled_broker(pg_conn_with_routing, ca_config, role="ENDPOINT")
    resp = await client.get(
        "/route", params={"match_key": "x", "protocol": "HTTP"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: endpoint_serial},
    )
    assert resp.status_code == 403


async def test_steer_then_route_returns_sandbox_for_matching_key(app_client, pg_conn_with_routing, ca_config):
    client, _app, kc = app_client
    case_id = await _create_case(pg_conn_with_routing)
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"SSH|bastion-1|10.0.0.9|{uuid.uuid4().hex}"

    token = await _token_for(kc, "dev-platform-admin")
    steer_resp = await client.post(
        f"/api/v1/cases/{case_id}/steer",
        json={"match_key": match_key, "protocol": "SSH", "target": "SANDBOX"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert steer_resp.status_code == 200, steer_resp.text
    assert steer_resp.json()["target"] == "SANDBOX"

    route_resp = await client.get(
        "/route", params={"match_key": match_key, "protocol": "SSH"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )
    assert route_resp.status_code == 200, route_resp.text
    assert route_resp.json() == {"upstream": "SANDBOX", "cached": False}

    # A different, never-steered match_key still gets the safe default.
    other_resp = await client.get(
        "/route", params={"match_key": f"SSH|bastion-1|10.0.0.9|{uuid.uuid4().hex}", "protocol": "SSH"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )
    assert other_resp.json()["upstream"] == "ENDPOINT"


async def test_route_resolves_rdp_match_key_to_endpoint_by_default(app_client, pg_conn_with_routing, ca_config):
    """Priority 5 (RDP steering): proves the exact request contract
    infra/broker/rdp's plugin design is specified against — canonical
    match_key `RDP|<gateway-listener-id>|<client-ip>|<principal>`,
    protocol=RDP — is real and correct against the actual running /route
    endpoint, independent of whether the plugin itself has been compiled on
    a Windows host."""
    client, _app, _kc = app_client
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"RDP|rdgw-1|10.0.0.12|{uuid.uuid4().hex}"

    resp = await client.get(
        "/route", params={"match_key": match_key, "protocol": "RDP"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"upstream": "ENDPOINT", "cached": False}


async def test_steer_then_route_returns_sandbox_for_rdp_match_key(app_client, pg_conn_with_routing, ca_config):
    client, _app, kc = app_client
    case_id = await _create_case(pg_conn_with_routing)
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"RDP|rdgw-1|10.0.0.12|{uuid.uuid4().hex}"

    token = await _token_for(kc, "dev-platform-admin")
    steer_resp = await client.post(
        f"/api/v1/cases/{case_id}/steer",
        json={"match_key": match_key, "protocol": "RDP", "target": "SANDBOX"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert steer_resp.status_code == 200, steer_resp.text
    assert steer_resp.json()["target"] == "SANDBOX"

    route_resp = await client.get(
        "/route", params={"match_key": match_key, "protocol": "RDP"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )
    assert route_resp.status_code == 200, route_resp.text
    assert route_resp.json() == {"upstream": "SANDBOX", "cached": False}


async def test_steer_requires_platform_admin(app_client, pg_conn_with_routing):
    client, _app, kc = app_client
    case_id = await _create_case(pg_conn_with_routing)
    token = await _token_for(kc, "dev-read-only")
    resp = await client.post(
        f"/api/v1/cases/{case_id}/steer",
        json={"match_key": "x", "protocol": "HTTP", "target": "SANDBOX"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


async def test_steer_rejects_overlapping_active_decision_for_same_match_key(app_client, pg_conn_with_routing):
    client, _app, kc = app_client
    case_id = await _create_case(pg_conn_with_routing)
    match_key = f"RDP|gateway-1|10.0.0.20|{uuid.uuid4().hex}"
    token = await _token_for(kc, "dev-platform-admin")

    first = await client.post(
        f"/api/v1/cases/{case_id}/steer",
        json={"match_key": match_key, "protocol": "RDP", "target": "SANDBOX"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert first.status_code == 200

    second = await client.post(
        f"/api/v1/cases/{case_id}/steer",
        json={"match_key": match_key, "protocol": "RDP", "target": "ENDPOINT"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert second.status_code == 409


async def test_route_cache_serves_second_call_from_cache(app_client, pg_conn_with_routing, ca_config):
    client, _app, _kc = app_client
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"HTTP|listener-1|10.0.0.30|{uuid.uuid4().hex}"
    headers = {PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial}

    first = await client.get("/route", params={"match_key": match_key, "protocol": "HTTP"}, headers=headers)
    assert first.json()["cached"] is False

    second = await client.get("/route", params={"match_key": match_key, "protocol": "HTTP"}, headers=headers)
    assert second.json() == {"upstream": first.json()["upstream"], "cached": True}


async def test_route_sets_x_mirage_upstream_response_header(app_client, pg_conn_with_routing, ca_config):
    """Step 8b's Nginx HTTP broker reads this header via auth_request_set
    (auth_request subrequests can only capture response HEADERS, not JSON
    bodies) — this is the exact contract that mechanism depends on."""
    client, _app, _kc = app_client
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"HTTP|listener-1|10.0.0.31|{uuid.uuid4().hex}"
    resp = await client.get(
        "/route", params={"match_key": match_key, "protocol": "HTTP"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )
    assert resp.headers["X-Mirage-Upstream"] == resp.json()["upstream"] == "ENDPOINT"


async def test_steering_decision_recorded_events_are_published_via_outbox(app_client, pg_conn_with_routing, ca_config):
    """§6.1: 'steering recorded on case timeline' — every decision write and
    every /route resolution durably records a steering.decision_recorded
    outbox row (this test checks the outbox table directly; NATS delivery
    of this SAME event_type/subject is already proven for other event types
    throughout Steps 6-7's test suites)."""
    client, _app, kc = app_client
    case_id = await _create_case(pg_conn_with_routing)
    broker_serial = await _enrolled_broker(pg_conn_with_routing, ca_config)
    match_key = f"HTTP|listener-2|10.0.0.40|{uuid.uuid4().hex}"
    token = await _token_for(kc, "dev-platform-admin")

    await client.post(
        f"/api/v1/cases/{case_id}/steer",
        json={"match_key": match_key, "protocol": "HTTP", "target": "SANDBOX"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await client.get(
        "/route", params={"match_key": match_key, "protocol": "HTTP"},
        headers={PROXY_SHARED_SECRET_HEADER: PROXY_SECRET, CLIENT_SERIAL_HEADER: broker_serial},
    )

    async with pg_conn_with_routing.cursor() as cur:
        # `payload` stores the WHOLE envelope (event_id, event_type, ...,
        # payload: {...}) — the action lives inside the envelope's own
        # nested `payload` object, same structure Step 6/7's outbox rows use.
        await cur.execute(
            "SELECT payload->'payload'->>'action' FROM outbox_events "
            "WHERE topic = 'steering.decision_recorded' ORDER BY created_at"
        )
        actions = [row[0] for row in await cur.fetchall()]
    assert actions == ["CREATED", "SELECTED"]
