"""mirage-agent-ingestion FastAPI app: agent enrolment, heartbeat, and
telemetry ingestion (Appendix F, Step 3/4/5). Request/response bodies are
the SAME generated Pydantic models the contracts package produces from
/schemas — no hand-written duplicate types (Appendix A generation rule) —
except the telemetry body, which is deliberately untyped at the FastAPI
layer (see submit_telemetry's docstring).
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import nats
import psycopg_pool
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from nats.aio.client import Client as NATSClient
from nats.js import JetStreamContext
from psycopg.types.json import Jsonb

from mirage_agent_ingestion.enrollment import CaConfig, enroll_agent, is_agent_active
from mirage_agent_ingestion.errors import EnrollmentError
from mirage_common.mtls_auth import (
    CLIENT_SERIAL_HEADER,
    PROXY_SHARED_SECRET_HEADER,
    require_client_certificate_serial,
)
from mirage_common.nats_client import publish_event
from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import validate_event
from mirage_contracts.errors import ContractError
from mirage_contracts.generated import (
    ApiEnrollRequestV1,
    ApiEnrollResponseV1,
    ApiError,
    EventsAgentHeartbeatV1,
)
from mirage_contracts.timestamps import now_rfc3339_ms
from mirage_contracts.ulid import generate_ulid

ENROLLMENT_ERROR_STATUS: dict[str, int] = {
    "TOKEN_EXPIRED_OR_REUSED_OR_UNKNOWN": 401,
    "BUILD_HASH_NOT_ALLOWLISTED": 403,
    "HOST_FINGERPRINT_INVALID": 400,
    "CSR_INVALID": 400,
    "CA_SIGNING_ERROR": 502,
}

# event_type values this endpoint will accept and forward. Deliberately a
# small allowlist, not "anything with a registered schema" — an agent must
# never be able to smuggle e.g. case.created or steering.decision_recorded
# through its own telemetry channel.
ALLOWED_TELEMETRY_EVENT_TYPES = frozenset({"spider.observation", "spider.tamper", "spider.fingerprint_snapshot"})


@dataclass
class AppState:
    pool: psycopg_pool.AsyncConnectionPool
    ca: CaConfig
    proxy_shared_secret: str
    nats_conn: NATSClient
    js: JetStreamContext


def create_app(*, pg_dsn: str, ca: CaConfig, proxy_shared_secret: str, nats_url: str) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = psycopg_pool.AsyncConnectionPool(pg_dsn, open=False)
        await pool.open()
        nc = await nats.connect(servers=nats_url)
        js = nc.jetstream()
        app.state.mirage = AppState(
            pool=pool, ca=ca, proxy_shared_secret=proxy_shared_secret, nats_conn=nc, js=js,
        )
        yield
        await pool.close()
        await nc.close()

    app = FastAPI(title="mirage-agent-ingestion", version="0.1.0", lifespan=lifespan)

    def state(request: Request) -> AppState:
        return request.app.state.mirage

    def auth_dependency(request: Request) -> str:
        s = state(request)
        return require_client_certificate_serial(
            proxy_auth=request.headers.get(PROXY_SHARED_SECRET_HEADER),
            client_serial=request.headers.get(CLIENT_SERIAL_HEADER),
            expected_proxy_secret=s.proxy_shared_secret,
        )

    @app.get("/health")
    async def health(request: Request) -> dict:
        """Unauthenticated liveness probe — used by mirage-api's Step 4b
        health rollup (AGENT_INGESTION row) and by container orchestration.
        Deliberately does NOT report on Postgres/step-ca reachability itself
        (that would duplicate mirage-api's own dependency checks); a 200
        here means "the process is up and serving," nothing more."""
        s = state(request)
        return {"status": "ok", "pool_open": not s.pool.closed}

    def api_error(request: Request, http_status: int, error_code: str, message: str) -> JSONResponse:
        err = ApiError(
            error_code=error_code,
            message=message,
            correlation_id=generate_ulid(),
            http_status=http_status,
            details=None,
        )
        return JSONResponse(status_code=http_status, content=err.model_dump())

    @app.exception_handler(EnrollmentError)
    async def enrollment_error_handler(request: Request, exc: EnrollmentError) -> JSONResponse:
        status = ENROLLMENT_ERROR_STATUS.get(exc.reason, 400)
        return api_error(request, status, exc.reason, str(exc) or exc.reason)

    @app.exception_handler(ContractError)
    async def contract_error_handler(request: Request, exc: ContractError) -> JSONResponse:
        # Every contract rejection (unknown event_type, bad envelope,
        # integrity mismatch, oversized payload, ...) is a client error —
        # never enters NATS or Elastic (Step 1's own rejection contract).
        return api_error(request, 400, exc.error_code, exc.message)

    @app.post("/api/v1/enroll", response_model=ApiEnrollResponseV1)
    async def enroll(body: ApiEnrollRequestV1, request: Request) -> ApiEnrollResponseV1:
        s = state(request)
        async with s.pool.connection() as conn:
            result = await enroll_agent(
                conn,
                s.ca,
                enrollment_token=body.enrollment_token,
                csr_pem=body.csr_pem,
                host_fingerprint=body.host_fingerprint,
                build_hash=body.build_hash,
            )
        return ApiEnrollResponseV1(
            agent_id=result.agent_id,
            certificate_pem=result.certificate_pem,
            certificate_chain_pem=result.certificate_chain_pem,
            certificate_serial=result.certificate_serial,
            not_after=result.not_after,
        )

    @app.post("/api/v1/agents/{agent_id}/heartbeat")
    async def heartbeat(
        agent_id: str,
        body: EventsAgentHeartbeatV1,
        request: Request,
        *,
        client_serial: str = Depends(auth_dependency),
    ) -> dict:
        s = state(request)
        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT certificate_serial, status FROM agents WHERE agent_id = %s", (agent_id,))
                row = await cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown agent")
            actual_serial, status = row
            if actual_serial != client_serial:
                # The mTLS cert presented does not belong to this agent_id —
                # never trust the request body's own claims about identity.
                raise HTTPException(status_code=403, detail="certificate/agent mismatch")
            if status != "ACTIVE" or not await is_agent_active(conn, certificate_serial=client_serial):
                raise HTTPException(status_code=403, detail="agent is revoked")

            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE agents SET last_seen_at = now(), last_sequence = GREATEST(last_sequence, %s) WHERE agent_id = %s",
                    (0, agent_id),
                )
            await conn.commit()
        return {"status": "ok", "server_time": now_rfc3339_ms()}

    @app.post("/api/v1/agents/{agent_id}/telemetry", status_code=202)
    async def submit_telemetry(
        agent_id: str,
        body: dict,
        request: Request,
        *,
        client_serial: str = Depends(auth_dependency),
    ) -> dict:
        """Accepts ONE already-built event envelope (Step 5: MirageSpider's
        primary transport, reusable by any future agent role). `body` is
        intentionally typed as a raw dict, not a generated Pydantic model —
        this is the API-level shape check (FastAPI/Starlette rejecting
        anything that isn't a JSON object); the real, authoritative
        structural + payload validation is `validate_event()` below, exactly
        mirroring mirage-api's synthetic health check's two-layer pattern.
        Ordering is enforced for real: `sequence` must strictly increase per
        agent, checked and advanced inside one row-locked transaction, so a
        replayed or out-of-order submission is rejected (409), not silently
        accepted (Step 5 acceptance: "events arrive ordered").
        """
        s = state(request)
        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT certificate_serial, status, last_sequence FROM agents WHERE agent_id = %s FOR UPDATE",
                    (agent_id,),
                )
                row = await cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown agent")
            actual_serial, status, last_sequence = row
            if actual_serial != client_serial:
                raise HTTPException(status_code=403, detail="certificate/agent mismatch")
            if status != "ACTIVE" or not await is_agent_active(conn, certificate_serial=client_serial):
                raise HTTPException(status_code=403, detail="agent is revoked")

            event_type = body.get("event_type")
            if event_type not in ALLOWED_TELEMETRY_EVENT_TYPES:
                raise HTTPException(status_code=400, detail=f"event_type {event_type!r} is not submittable via this endpoint")
            if body.get("source_id") != agent_id:
                # Never trust the body's own claim about who produced it —
                # same principle as the heartbeat handler's serial check.
                raise HTTPException(status_code=403, detail="source_id does not match the authenticated agent")

            sequence = body.get("sequence")
            if not isinstance(sequence, int):
                raise HTTPException(status_code=400, detail=f"sequence {sequence!r} must be an integer")

            # Idempotent replay: an agent that durably received a 202 for
            # this exact (agent_id, sequence, event_id) but crashed before
            # recording its own local ack will retry it. Recognizing that
            # and returning the SAME acknowledgement (rather than a 409) is
            # what makes "crash after send, before ack" safe instead of a
            # permanent head-of-queue deadlock — see migration 0011.
            submitted_event_id = body.get("event_id")
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT event_id FROM agent_telemetry_receipts WHERE agent_id=%s AND sequence=%s",
                    (agent_id, sequence),
                )
                receipt = await cur.fetchone()
            if receipt is not None:
                receipt_event_id = receipt[0]
                if receipt_event_id == submitted_event_id:
                    return {
                        "status": "accepted",
                        "event_id": receipt_event_id,
                        "sequence": sequence,
                        "replay": True,
                    }
                raise HTTPException(
                    status_code=409,
                    detail=f"sequence {sequence} was already used by a different event",
                )
            if sequence <= last_sequence:
                raise HTTPException(
                    status_code=409,
                    detail=f"sequence {sequence!r} is not greater than last recorded sequence {last_sequence}",
                )

            # ingest_time is authoritatively stamped here, on receipt — never
            # trusted from the agent's clock (envelope.schema.json's own
            # description says as much).
            event = {**body, "ingest_time": now_rfc3339_ms()}
            validated = validate_event(event)

            await publish_event(s.js, subject_for_event_type(event_type), validated.envelope, event_id=event["event_id"])

            if event_type == "spider.fingerprint_snapshot":
                # Step 10's live gate reads this "latest observation cache"
                # directly (Postgres, not NATS/Elasticsearch) so a blocking
                # SANDBOX_ACTIVE -> ENGAGING check is one indexed lookup, not
                # a telemetry-pipeline query. No FK to sandbox_instances
                # (Step 9b) — see the migration's own comment: Spider's
                # reporting must not depend on the Controller's lifecycle.
                payload = event["payload"]
                async with conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO sandbox_fingerprint_snapshots (sandbox_id, checks, observed_at, source_agent_id) "
                        "VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (sandbox_id) DO UPDATE SET "
                        "checks = EXCLUDED.checks, observed_at = EXCLUDED.observed_at, "
                        "received_at = now(), source_agent_id = EXCLUDED.source_agent_id",
                        (payload["sandbox_id"], Jsonb(payload["checks"]), payload["observed_at"], agent_id),
                    )

            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO agent_telemetry_receipts (agent_id, sequence, event_id) VALUES (%s, %s, %s)",
                    (agent_id, sequence, event["event_id"]),
                )
                await cur.execute(
                    "UPDATE agents SET last_seen_at = now(), last_sequence = %s WHERE agent_id = %s",
                    (sequence, agent_id),
                )
            await conn.commit()
        return {"status": "accepted", "event_id": event["event_id"], "sequence": sequence, "replay": False}

    return app
