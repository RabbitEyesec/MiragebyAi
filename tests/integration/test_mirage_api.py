"""Integration tests for mirage-api (Step 4b): real Postgres, real NATS,
real Elasticsearch, real Keycloak. Covers every Step 4b acceptance line:
"Authenticated admin can view health", "Unauthorized role is refused",
"Dependency failure changes health status", "Synthetic event is traceable
end to end."
"""
from __future__ import annotations

import httpx
import pytest
from mirage_api.app import create_app
from mirage_api.health import HealthCheckConfig

pytestmark = pytest.mark.integration


@pytest.fixture
async def pg_conn_with_cases(pg_conn):
    """Extends the shared pg_conn fixture (migration 0001 already applied)
    with migration 0002 (cases) for this module's tests."""
    from pathlib import Path

    migration_sql = (
        Path(__file__).resolve().parents[2] / "infra" / "migrations" / "0002_cases_minimal.up.sql"
    ).read_text()
    async with pg_conn.cursor() as cur:
        await cur.execute("DROP TABLE IF EXISTS cases CASCADE")
        await cur.execute(migration_sql)
    await pg_conn.commit()
    return pg_conn


@pytest.fixture
def health_config(postgres_container, nats_monitoring_url, elasticsearch_url, keycloak_realm) -> HealthCheckConfig:
    return HealthCheckConfig(
        postgres_dsn=(
            f"host={postgres_container.get_container_host_ip()} port={postgres_container.get_exposed_port(5432)} "
            f"user={postgres_container.username} password={postgres_container.password} dbname={postgres_container.dbname}"
        ),
        nats_monitoring_url=nats_monitoring_url,
        elasticsearch_url=elasticsearch_url,
        keycloak_issuer_url=keycloak_realm["issuer"],
        # step-ca is not part of this module's fixture set (no test here
        # depends on it being real) — deliberately unreachable so its
        # UNHEALTHY result is a known constant, not a source of flakiness.
        step_ca_url="https://127.0.0.1:1",
        step_ca_root_cert_path="/dev/null",
        agent_ingestion_url=None,
    )


@pytest.fixture
async def app_client(pg_conn_with_cases, pg_dsn, nats_container, mirage_streams, elasticsearch_url, keycloak_realm, health_config):
    application = create_app(
        pg_dsn=pg_dsn, nats_url=nats_container, health_config=health_config,
        elasticsearch_url=elasticsearch_url, oidc_issuer_url=keycloak_realm["issuer"],
        proxy_shared_secret="test-mirage-api-proxy-secret",  # secret-scan: ignore (test-only placeholder)
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


async def test_platform_admin_can_view_health(app_client):
    client, _app, kc = app_client
    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "status" in body
    component_names = {c["component"] for c in body["components"]}
    assert component_names == {
        "POSTGRES", "NATS", "ELASTICSEARCH", "KEYCLOAK", "STEP_CA",
        "AGENT_INGESTION", "SANDBOX_GATEWAY", "OUTBOX_RELAY", "WORKER",
    }
    not_built = {c["component"]: c["status"] for c in body["components"] if c["component"] in {"SANDBOX_GATEWAY", "OUTBOX_RELAY", "WORKER"}}
    assert all(status == "UNKNOWN" for status in not_built.values())  # honest, not fabricated HEALTHY


async def test_unauthorized_role_is_refused(app_client):
    """Step 4b acceptance: 'Unauthorized role is refused.'"""
    client, _app, kc = app_client
    token = await _token_for(kc, "dev-read-only")
    resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


async def test_no_token_is_rejected(app_client):
    client, _app, _kc = app_client
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 401


async def test_dependency_failure_changes_health_status(app_client):
    """Step 4b acceptance: 'Dependency failure changes health status.'
    Points POSTGRES at an unreachable host — a real connection failure, not
    a mocked one — and confirms it flips overall status to UNHEALTHY."""
    client, app, kc = app_client
    app.state.mirage.health_config = HealthCheckConfig(
        postgres_dsn="host=127.0.0.1 port=1 dbname=nonexistent connect_timeout=1",  # nothing listens on port 1
        nats_monitoring_url=app.state.mirage.health_config.nats_monitoring_url,
        elasticsearch_url=app.state.mirage.health_config.elasticsearch_url,
        keycloak_issuer_url=app.state.mirage.health_config.keycloak_issuer_url,
        step_ca_url=app.state.mirage.health_config.step_ca_url,
        step_ca_root_cert_path=app.state.mirage.health_config.step_ca_root_cert_path,
        agent_ingestion_url=None,
    )
    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.get("/api/v1/health", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "UNHEALTHY"
    pg_result = next(c for c in body["components"] if c["component"] == "POSTGRES")
    assert pg_result["status"] == "UNHEALTHY"


async def test_list_agents_queries_real_postgres(app_client, pg_conn_with_cases):
    client, _app, kc = app_client
    async with pg_conn_with_cases.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO agents (agent_id, role, certificate_profile, certificate_serial, certificate_not_after, build_hash, host_fingerprint)
            VALUES ('test-agent-1', 'ENDPOINT', 'MirageEndpoint', '999', now() + interval '1 day', %s, 'fp')
            """,
            ("a" * 64,),
        )
    await pg_conn_with_cases.commit()

    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    agent_ids = {a["agent_id"] for a in resp.json()["agents"]}
    assert "test-agent-1" in agent_ids


async def test_list_agents_flags_a_telemetry_gap_for_an_active_agent_that_has_never_reported(
    app_client, pg_conn_with_cases
):
    """Priority 1 (revised) telemetry-gap detection: an ACTIVE agent with no
    last_seen_at at all (enrolled but never heard from) must be flagged —
    real evidence a heartbeat/telemetry pipeline is broken, not a cosmetic
    NULL."""
    client, _app, kc = app_client
    async with pg_conn_with_cases.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO agents (agent_id, role, certificate_profile, certificate_serial, certificate_not_after, build_hash, host_fingerprint)
            VALUES ('test-agent-never-seen', 'SPIDER', 'MirageSpider', '888', now() + interval '1 day', %s, 'fp')
            """,
            ("b" * 64,),
        )
    await pg_conn_with_cases.commit()

    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    agent = next(a for a in resp.json()["agents"] if a["agent_id"] == "test-agent-never-seen")
    assert agent["telemetry_gap"] is True
    assert agent["seconds_since_last_seen"] is None


async def test_list_agents_does_not_flag_a_gap_for_a_recently_seen_agent(app_client, pg_conn_with_cases):
    client, _app, kc = app_client
    async with pg_conn_with_cases.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO agents (agent_id, role, certificate_profile, certificate_serial, certificate_not_after, build_hash, host_fingerprint, last_seen_at)
            VALUES ('test-agent-fresh', 'SPIDER', 'MirageSpider', '777', now() + interval '1 day', %s, 'fp', now())
            """,
            ("c" * 64,),
        )
    await pg_conn_with_cases.commit()

    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    agent = next(a for a in resp.json()["agents"] if a["agent_id"] == "test-agent-fresh")
    assert agent["telemetry_gap"] is False
    assert agent["seconds_since_last_seen"] < 90


async def test_list_cases_queries_real_postgres(app_client, pg_conn_with_cases):
    client, _app, kc = app_client
    async with pg_conn_with_cases.cursor() as cur:
        await cur.execute("INSERT INTO cases (case_id, severity, owner) VALUES ('case-1', 'HIGH', 'analyst-1')")
    await pg_conn_with_cases.commit()

    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    case_ids = {c["case_id"] for c in resp.json()["cases"]}
    assert "case-1" in case_ids


async def test_synthetic_health_check_is_traceable_end_to_end(app_client):
    """Step 4b acceptance: 'Synthetic event is traceable end to end' — one
    correlation ID that was generated, published through NATS, and is
    confirmed searchable in Elasticsearch."""
    client, _app, kc = app_client
    token = await _token_for(kc, "dev-platform-admin")
    resp = await client.post("/internal/synthetic-health-check", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["indexed"] is True
    assert len(body["correlation_id"]) == 26  # canonical ULID length
