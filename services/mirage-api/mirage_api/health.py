"""Dependency health checks (Step 4b). Every check is a REAL network call —
no fake success. Services not yet built in Prompt 1 (sandbox gateway,
outbox relay, worker) report UNKNOWN with an honest reason rather than a
fabricated HEALTHY, matching this repo's "no fake success" rule.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import psycopg

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
UNHEALTHY = "UNHEALTHY"
UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class HealthResult:
    component: str
    status: str
    detail: str | None
    latency_ms: float | None


@dataclass(frozen=True)
class HealthCheckConfig:
    postgres_dsn: str
    nats_monitoring_url: str  # e.g. http://localhost:8222/healthz
    elasticsearch_url: str
    keycloak_issuer_url: str
    step_ca_url: str
    step_ca_root_cert_path: str
    agent_ingestion_url: str | None = None


async def _timed(component: str, fn) -> HealthResult:
    start = time.monotonic()
    try:
        detail = await fn()
        latency = (time.monotonic() - start) * 1000
        return HealthResult(component, HEALTHY, detail, latency)
    except Exception as exc:  # noqa: BLE001 -- any failure means UNHEALTHY, by design
        latency = (time.monotonic() - start) * 1000
        return HealthResult(component, UNHEALTHY, str(exc)[:300], latency)


async def check_postgres(dsn: str) -> HealthResult:
    async def _check() -> str:
        async with await psycopg.AsyncConnection.connect(dsn, connect_timeout=3) as conn, conn.cursor() as cur:
            await cur.execute("SELECT 1")
            await cur.fetchone()
        return "SELECT 1 succeeded"

    return await _timed("POSTGRES", _check)


async def check_nats(monitoring_url: str) -> HealthResult:
    async def _check() -> str:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(monitoring_url)
        resp.raise_for_status()
        return f"HTTP {resp.status_code}"

    return await _timed("NATS", _check)


async def check_elasticsearch(url: str) -> HealthResult:
    async def _check() -> str:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{url}/_cluster/health")
        resp.raise_for_status()
        body = resp.json()
        if body["status"] == "red":
            raise RuntimeError(f"cluster status red: {body}")
        return f"cluster status {body['status']}"

    return await _timed("ELASTICSEARCH", _check)


async def check_keycloak(issuer_url: str) -> HealthResult:
    async def _check() -> str:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{issuer_url}/.well-known/openid-configuration")
        resp.raise_for_status()
        return "OIDC discovery document reachable"

    return await _timed("KEYCLOAK", _check)


async def check_step_ca(ca_url: str, root_cert_path: str) -> HealthResult:
    async def _check() -> str:
        async with httpx.AsyncClient(verify=root_cert_path, timeout=3) as client:
            resp = await client.get(f"{ca_url}/health")
        resp.raise_for_status()
        return "CA /health OK"

    return await _timed("STEP_CA", _check)


async def check_agent_ingestion(base_url: str | None) -> HealthResult:
    if base_url is None:
        return HealthResult("AGENT_INGESTION", UNKNOWN, "no agent-ingestion URL configured", None)

    async def _check() -> str:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{base_url}/health")
        resp.raise_for_status()
        return "reachable"

    return await _timed("AGENT_INGESTION", _check)


def check_not_yet_built(component: str) -> HealthResult:
    """SANDBOX_GATEWAY, OUTBOX_RELAY, WORKER are not built in Prompt 1 (later
    stages). UNKNOWN, not HEALTHY — this repo does not fabricate success for
    a component that does not exist yet."""
    return HealthResult(component, UNKNOWN, "not implemented in Prompt 1 (see IMPLEMENTATION_STATUS.md)", None)


async def run_all_checks(config: HealthCheckConfig) -> list[HealthResult]:
    return [
        await check_postgres(config.postgres_dsn),
        await check_nats(config.nats_monitoring_url),
        await check_elasticsearch(config.elasticsearch_url),
        await check_keycloak(config.keycloak_issuer_url),
        await check_step_ca(config.step_ca_url, config.step_ca_root_cert_path),
        await check_agent_ingestion(config.agent_ingestion_url),
        check_not_yet_built("SANDBOX_GATEWAY"),
        check_not_yet_built("OUTBOX_RELAY"),
        check_not_yet_built("WORKER"),
    ]


def overall_status(results: list[HealthResult]) -> str:
    statuses = {r.status for r in results}
    if UNHEALTHY in statuses:
        return UNHEALTHY
    if DEGRADED in statuses:
        return DEGRADED
    # UNKNOWN-only results (not-yet-built components) don't drag a
    # correctly-functioning Prompt-1 system down to "degraded" — but any
    # REAL dependency failing does.
    return HEALTHY
