"""mirage-api FastAPI app — Step 4b's early engineering console
(GET /api/v1/health, /agents, /events/recent, /cases, the synthetic
health-check transaction — every route platform_admin-only via Keycloak
bearer token) plus Step 8a's /route decision API and steering-approval
endpoint (Appendix B, §6.1): "mirage-api owns routing_decisions and
exposes /route."
"""
from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import nats
import psycopg
import psycopg_pool
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from nats.aio.client import Client as NATSClient
from nats.js import JetStreamContext

from mirage_api.health import HealthCheckConfig, overall_status, run_all_checks
from mirage_api.prompt2 import build_prompt2_router
from mirage_api.prompt3 import build_prompt3_router
from mirage_api.synthetic import (
    SyntheticCheckFailedError,
    SyntheticCheckTimeoutError,
    run_synthetic_health_check,
)
from mirage_common.artifacts import ArtifactScanner
from mirage_common.evidence import EvidenceService
from mirage_common.mtls_auth import (
    CLIENT_SERIAL_HEADER,
    PROXY_SHARED_SECRET_HEADER,
    require_client_certificate_serial,
)
from mirage_common.oidc import (
    InsufficientRoleError,
    OidcVerifier,
    TokenInvalidError,
    require_any_role,
)
from mirage_common.routing import RouteCache, resolve_route, write_routing_decision
from mirage_common.telemetry import core_metrics, traced_operation

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class ApiState:
    pool: psycopg_pool.AsyncConnectionPool
    nats_conn: NATSClient
    js: JetStreamContext
    health_config: HealthCheckConfig
    elasticsearch_url: str
    oidc: OidcVerifier
    proxy_shared_secret: str
    route_cache: RouteCache = field(default_factory=RouteCache)


# Matches the pre-existing 90-second export-eligibility staleness check
# (mirage_api.prompt3's report-generation gate) — one definition of "how
# stale is too stale" for an ACTIVE agent, reused rather than redefined.
TELEMETRY_GAP_THRESHOLD_SECONDS = 90


def create_app(
    *,
    pg_dsn: str,
    nats_url: str,
    health_config: HealthCheckConfig,
    elasticsearch_url: str,
    oidc_issuer_url: str,
    proxy_shared_secret: str,
    evidence_service: EvidenceService | None = None,
    artifact_scanner: ArtifactScanner | None = None,
    artifact_quarantine_dir: Path = Path("/tmp/mirage-artifact-quarantine"),
    canary_signing_key: bytes | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = psycopg_pool.AsyncConnectionPool(pg_dsn, open=False)
        await pool.open()
        nc = await nats.connect(servers=nats_url)
        js = nc.jetstream()
        app.state.mirage = ApiState(
            pool=pool, nats_conn=nc, js=js, health_config=health_config,
            elasticsearch_url=elasticsearch_url, oidc=OidcVerifier(oidc_issuer_url),
            proxy_shared_secret=proxy_shared_secret,
        )
        yield
        await pool.close()
        await nc.close()

    app = FastAPI(title="mirage-api", version="0.1.0", lifespan=lifespan)
    instruments = core_metrics()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        started = time.perf_counter()
        with traced_operation(
            "mirage.api.request",
            attributes={
                "http.request.method": request.method,
                "http.route": request.url.path,
                "operation": "api_request",
            },
        ) as span:
            instruments["api_request_total"].add(1)
            try:
                response = await call_next(request)
            except Exception:
                instruments["api_error_total"].add(1)
                raise
            span.set_attribute("http.response.status_code", response.status_code)
            if response.status_code >= 500:
                instruments["api_error_total"].add(1)
            instruments["api_request_latency"].record(
                (time.perf_counter() - started) * 1000
            )
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
            "form-action 'self'; connect-src 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def state(request: Request) -> ApiState:
        return request.app.state.mirage

    def require_roles(*roles: str):
        def dependency(
            request: Request,
            creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
        ):
            if creds is None:
                raise HTTPException(status_code=401, detail="missing bearer token")
            s = state(request)
            try:
                principal = s.oidc.verify(creds.credentials)
            except TokenInvalidError as exc:
                raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc
            try:
                require_any_role(principal, *roles)
            except InsufficientRoleError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            return principal

        return dependency

    require_platform_admin = require_roles("platform_admin")

    def require_broker_client(request: Request) -> str:
        """/route's auth: mTLS via the same Nginx-header contract
        mirage-agent-ingestion uses (Step 4's KNOWN_ISSUES boundary applies
        identically here) — brokers are machine clients with their own
        BROKER_CLIENT certificate identity (Step 3's role enum), not human
        operators with OIDC tokens."""
        s = state(request)
        client_serial = require_client_certificate_serial(
            proxy_auth=request.headers.get(PROXY_SHARED_SECRET_HEADER),
            client_serial=request.headers.get(CLIENT_SERIAL_HEADER),
            expected_proxy_secret=s.proxy_shared_secret,
        )
        return client_serial

    @app.get("/api/v1/health")
    async def health(request: Request, _principal=Depends(require_platform_admin)) -> dict:
        s = state(request)
        results = await run_all_checks(s.health_config)
        return {
            "status": overall_status(results),
            "components": [
                {"component": r.component, "status": r.status, "detail": r.detail, "latency_ms": r.latency_ms}
                for r in results
            ],
        }

    @app.get("/api/v1/agents")
    async def list_agents(request: Request, _principal=Depends(require_platform_admin)) -> dict:
        # Priority 1 (revised) telemetry-gap detection: an ACTIVE agent that
        # has gone quiet longer than TELEMETRY_GAP_THRESHOLD_SECONDS is
        # flagged here — this is agent/Fleet-liveness gap detection
        # (distinct from evidence_collection_gaps' sequence-continuity
        # gaps), surfaced once, at the same rollup every other agent-health
        # consumer already reads.
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT agent_id, role, certificate_profile, status, enrolled_at, last_seen_at, last_sequence FROM agents ORDER BY enrolled_at DESC LIMIT 200"
            )
            rows = await cur.fetchall()
        now = datetime.now(UTC)
        agents = []
        for r in rows:
            last_seen_at = r[5]
            if last_seen_at is None:
                seconds_since_last_seen = None
                telemetry_gap = r[3] == "ACTIVE"
            else:
                seconds_since_last_seen = (now - last_seen_at).total_seconds()
                telemetry_gap = r[3] == "ACTIVE" and seconds_since_last_seen > TELEMETRY_GAP_THRESHOLD_SECONDS
            agents.append(
                {
                    "agent_id": r[0], "role": r[1], "certificate_profile": r[2], "status": r[3],
                    "enrolled_at": r[4].isoformat() if r[4] else None,
                    "last_seen_at": last_seen_at.isoformat() if last_seen_at else None,
                    "last_sequence": r[6],
                    "telemetry_gap": telemetry_gap,
                    "seconds_since_last_seen": seconds_since_last_seen,
                }
            )
        return {"agents": agents}

    @app.get("/api/v1/events/recent")
    async def recent_events(request: Request, limit: int = 50, _principal=Depends(require_platform_admin)) -> dict:
        import httpx

        s = state(request)
        limit = max(1, min(limit, 200))
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{s.elasticsearch_url}/mirage-telemetry-endpoint,mirage-telemetry-sandbox,mirage-health/_search",
                json={"size": limit, "sort": [{"ingest_time": "desc"}]},
            )
        if resp.status_code == 404:
            return {"events": []}  # no data streams created yet — honest empty result, not an error
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
        return {"events": [h["_source"] for h in hits]}

    @app.get("/api/v1/cases")
    async def list_cases(request: Request, _principal=Depends(require_platform_admin)) -> dict:
        s = state(request)
        async with s.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT case_id, state, version, severity, owner, created_at FROM cases ORDER BY created_at DESC LIMIT 200")
            rows = await cur.fetchall()
        return {
            "cases": [
                {"case_id": r[0], "state": r[1], "version": r[2], "severity": r[3], "owner": r[4], "created_at": r[5].isoformat()}
                for r in rows
            ]
        }

    @app.post("/api/v1/cases/{case_id}/steer")
    async def steer_case(case_id: str, body: dict, request: Request, _principal=Depends(require_platform_admin)) -> dict:
        """'Analyst approves steering -> mirage-api writes routing_decisions'
        (§6.1). body: {match_key, protocol, target}. Body is deliberately a
        raw dict (not a generated model) — same two-layer rationale as
        mirage-agent-ingestion's telemetry endpoint: FastAPI enforces "it's a
        JSON object," `write_routing_decision` enforces the real shape via
        its own typed parameters and the DB's own constraints."""
        s = state(request)
        for field_name in ("match_key", "protocol", "target"):
            if field_name not in body:
                raise HTTPException(status_code=400, detail=f"missing required field: {field_name}")
        if body["target"] not in ("ENDPOINT", "SANDBOX"):
            raise HTTPException(status_code=400, detail="target must be ENDPOINT or SANDBOX")
        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1 FROM cases WHERE case_id = %s", (case_id,))
                if await cur.fetchone() is None:
                    raise HTTPException(status_code=404, detail="unknown case")
            try:
                decision = await write_routing_decision(
                    conn, case_id=case_id, match_key=body["match_key"], protocol=body["protocol"],
                    target=body["target"], created_by=_principal.username,
                )
            except psycopg.errors.ExclusionViolation as exc:
                await conn.rollback()
                raise HTTPException(status_code=409, detail="an active decision already covers this match_key") from exc
            await conn.commit()
        return {
            "decision_id": decision.decision_id, "case_id": decision.case_id, "match_key": decision.match_key,
            "target": decision.target, "version": decision.version,
        }

    @app.get("/route")
    async def route(
        match_key: str, protocol: str, request: Request, response: Response,
        _client_serial: str = Depends(require_broker_client),
    ) -> dict:
        """The read side of §6.1's flow. 1-second in-memory TTL cache in
        front of Postgres; a cache hit skips the audit-event publish (the
        DB round-trip on a miss is what "selects a backend" durably records
        — see libs/mirage_common/routing.py's module docstring). Also sets
        `X-Mirage-Upstream` as a response HEADER (not just the JSON body) —
        Step 8b's Nginx HTTP broker uses `auth_request_set` to read exactly
        this header, since auth_request subrequests can only capture
        response headers, not JSON bodies."""
        s = state(request)
        cached = s.route_cache.get(match_key)
        if cached is not None:
            response.headers["X-Mirage-Upstream"] = cached
            return {"upstream": cached, "cached": True}
        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT status, role FROM agents WHERE certificate_serial = %s", (_client_serial,)
                )
                row = await cur.fetchone()
            if row is None or row[0] != "ACTIVE" or row[1] not in ("BROKER_CLIENT", "INTERNAL_CONTROL"):
                raise HTTPException(status_code=403, detail="caller is not an active broker/internal-control agent")
            target = await resolve_route(conn, match_key=match_key, protocol=protocol)
            await conn.commit()
        s.route_cache.set(match_key, target)
        response.headers["X-Mirage-Upstream"] = target
        return {"upstream": target, "cached": False}

    @app.post("/internal/synthetic-health-check")
    async def synthetic_health_check(request: Request, _principal=Depends(require_platform_admin)) -> dict:
        s = state(request)
        try:
            result = await run_synthetic_health_check(js=s.js, elasticsearch_url=s.elasticsearch_url)
        except (SyntheticCheckTimeoutError, SyntheticCheckFailedError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "correlation_id": result.correlation_id,
            "indexed": result.indexed,
            "elapsed_ms": result.elapsed_ms,
        }

    app.include_router(
        build_prompt2_router(
            state=state,
            require_roles=require_roles,
            evidence_service=evidence_service,
            artifact_scanner=artifact_scanner,
            artifact_quarantine_dir=artifact_quarantine_dir,
            canary_signing_key=canary_signing_key,
        )
    )
    app.include_router(
        build_prompt3_router(
            state=state,
            require_roles=require_roles,
            evidence_service=evidence_service,
        )
    )

    return app
