"""mirage-sandbox-gateway (Step 9b, Appendix G): the WSS endpoint
MirageEnvironmentController instances connect out to, and the HTTP API an
analyst (or, from Step 13 onward, the AI orchestration loop — out of
Prompt 1's scope) uses to issue one structured sandbox action (Appendix I)
and get back a real, awaited result.

Delivery model: issuing a command opens a Postgres transaction (optimistic
concurrency check against sandbox_instances.state_version, a PENDING
sandbox_actions row, an outbox row for audit/history), commits, then pushes
the command directly over the sandbox's live WebSocket connection and
awaits the real result with a bounded timeout — a synchronous RPC-style
round trip layered on top of the same transactional-outbox discipline
every other state change in this system uses (see ARCHITECTURE_DECISIONS.md
ADR-0022 for why this is not a §6.3 violation).
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import nats
import psycopg_pool
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from nats.aio.client import Client as NATSClient
from nats.js import JetStreamContext

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
from mirage_common.sandbox_actions import (
    ALLOWED_ACTION_TYPES,
    PendingAction,
    SandboxNotFoundError,
    StateVersionConflictError,
    ensure_sandbox_instance,
    open_pending_action,
    record_action_result,
)

bearer_scheme = HTTPBearer(auto_error=False)

DEFAULT_COMMAND_TIMEOUT_SECONDS = 30.0


@dataclass
class GatewayState:
    pool: psycopg_pool.AsyncConnectionPool
    nats_conn: NATSClient
    js: JetStreamContext
    oidc: OidcVerifier
    proxy_shared_secret: str
    command_timeout_seconds: float
    live_connections: dict[str, WebSocket] = field(default_factory=dict)
    pending_by_sandbox: dict[str, dict[str, asyncio.Future]] = field(default_factory=dict)


def create_app(
    *, pg_dsn: str, nats_url: str, oidc_issuer_url: str, proxy_shared_secret: str,
    command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = psycopg_pool.AsyncConnectionPool(pg_dsn, open=False)
        await pool.open()
        nc = await nats.connect(servers=nats_url)
        js = nc.jetstream()
        app.state.mirage = GatewayState(
            pool=pool, nats_conn=nc, js=js, oidc=OidcVerifier(oidc_issuer_url),
            proxy_shared_secret=proxy_shared_secret, command_timeout_seconds=command_timeout_seconds,
        )
        yield
        await pool.close()
        await nc.close()

    app = FastAPI(title="mirage-sandbox-gateway", version="0.1.0", lifespan=lifespan)

    def state(conn: Request | WebSocket) -> GatewayState:
        return conn.app.state.mirage

    def require_platform_admin(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
        if creds is None:
            raise HTTPException(status_code=401, detail="missing bearer token")
        s = state(request)
        try:
            principal = s.oidc.verify(creds.credentials)
        except TokenInvalidError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc
        try:
            require_any_role(principal, "platform_admin")
        except InsufficientRoleError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return principal

    @app.get("/health")
    async def health(request: Request) -> dict:
        s = state(request)
        return {"status": "ok", "pool_open": not s.pool.closed, "live_sandboxes": len(s.live_connections)}

    @app.websocket("/api/v1/sandboxes/{sandbox_id}/connect")
    async def sandbox_connect(websocket: WebSocket, sandbox_id: str, case_id: str, image_id: str) -> None:
        """MirageEnvironmentController's own outbound connection (Appendix
        G: "Channel: Outbound WSS -> Sandbox Gateway"). Authenticated via
        the SAME mTLS header-forwarding contract every other Mirage
        endpoint uses (mtls_auth.py) — headers arrive on the WS upgrade
        request exactly like a normal HTTP request."""
        s = state(websocket)
        try:
            client_serial = require_client_certificate_serial(
                proxy_auth=websocket.headers.get(PROXY_SHARED_SECRET_HEADER),
                client_serial=websocket.headers.get(CLIENT_SERIAL_HEADER),
                expected_proxy_secret=s.proxy_shared_secret,
            )
        except HTTPException:
            await websocket.close(code=4401)
            return

        async with s.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT status, role FROM agents WHERE certificate_serial = %s", (client_serial,))
                row = await cur.fetchone()
            if row is None or row[0] != "ACTIVE" or row[1] != "ENV_CONTROLLER":
                await websocket.close(code=4403)
                return
            await ensure_sandbox_instance(conn, sandbox_id=sandbox_id, case_id=case_id, image_id=image_id)
            await conn.commit()

        await websocket.accept()
        s.live_connections[sandbox_id] = websocket
        try:
            while True:
                raw = await websocket.receive_text()
                result = json.loads(raw)
                action_id = result.get("action_id")
                pending = s.pending_by_sandbox.get(sandbox_id, {})
                future = pending.pop(action_id, None) if action_id else None
                if future is not None and not future.done():
                    future.set_result(result)
        except WebSocketDisconnect:
            pass
        finally:
            if s.live_connections.get(sandbox_id) is websocket:
                del s.live_connections[sandbox_id]
            for future in s.pending_by_sandbox.pop(sandbox_id, {}).values():
                if not future.done():
                    future.set_exception(ConnectionError(f"sandbox {sandbox_id!r} controller disconnected mid-command"))

    @app.post("/api/v1/cases/{case_id}/sandbox-actions")
    async def issue_sandbox_action(
        case_id: str, body: dict, request: Request, *, _principal=Depends(require_platform_admin),
    ) -> dict:
        """'A structured action executes and rolls back with full audit'
        (Step 9b Done-when). body is deliberately a raw dict — same
        two-layer rationale /steer already established: FastAPI enforces
        "it's a JSON object," ALLOWED_ACTION_TYPES + open_pending_action's
        own typed parameters + the DB's own CHECK constraints enforce the
        real shape."""
        s = state(request)
        for field_name in ("sandbox_id", "action_type", "expected_state_version"):
            if field_name not in body:
                raise HTTPException(status_code=400, detail=f"missing required field: {field_name}")
        action_type = body["action_type"]
        if action_type not in ALLOWED_ACTION_TYPES:
            raise HTTPException(status_code=400, detail=f"unknown action_type: {action_type!r}")
        issued_by = body.get("issued_by", "ANALYST")
        if issued_by not in ("AI", "ANALYST", "SYSTEM"):
            raise HTTPException(status_code=400, detail=f"issued_by must be AI/ANALYST/SYSTEM, got {issued_by!r}")
        sandbox_id = body["sandbox_id"]
        action_params = body.get("action_params") or {}

        async with s.pool.connection() as conn:
            try:
                action = await open_pending_action(
                    conn, sandbox_id=sandbox_id, case_id=case_id, action_type=action_type,
                    action_params=action_params, expected_state_version=body["expected_state_version"], issued_by=issued_by,
                )
            except SandboxNotFoundError as exc:
                await conn.rollback()
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except StateVersionConflictError as exc:
                await conn.rollback()
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            await conn.commit()

        status_, output_tag, error_detail = await _dispatch_to_live_controller(s, action)

        rollback_action_id = None
        if action.action_type == "ROLLBACK_ACTION" and status_ == "SUCCESS":
            rollback_action_id = action.action_params.get("target_action_id")

        async with s.pool.connection() as conn:
            new_version = await record_action_result(
                conn, action=action, status=status_, output_tag=output_tag,
                rollback_action_id=rollback_action_id, error_detail=error_detail,
            )
            await conn.commit()

        return {
            "action_id": action.action_id, "command_id": action.command_id, "status": status_,
            "output_tag": output_tag, "error_detail": error_detail, "new_state_version": new_version,
            "rollback_action_id": rollback_action_id,
        }

    async def _dispatch_to_live_controller(s: GatewayState, action: PendingAction) -> tuple[str, str | None, str | None]:
        ws = s.live_connections.get(action.sandbox_id)
        if ws is None:
            return "FAILED", None, f"no live controller connection for sandbox_id={action.sandbox_id!r}"

        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        s.pending_by_sandbox.setdefault(action.sandbox_id, {})[action.action_id] = future
        frame = {
            "action_id": action.action_id, "command_id": action.command_id, "case_id": action.case_id,
            "sandbox_id": action.sandbox_id, "expected_state_version": action.expected_state_version,
            "issued_by": action.issued_by, "policy_decision_id": action.policy_decision_id,
            "action_type": action.action_type, "action_params": action.action_params,
        }
        try:
            await ws.send_text(json.dumps(frame))
            result = await asyncio.wait_for(future, timeout=s.command_timeout_seconds)
            return result["status"], result.get("output_tag"), result.get("error_detail")
        except TimeoutError:
            return "TIMEOUT", None, "no result received from the sandbox controller within the command timeout"
        except (ConnectionError, RuntimeError) as exc:
            return "FAILED", None, str(exc)
        finally:
            s.pending_by_sandbox.get(action.sandbox_id, {}).pop(action.action_id, None)

    return app
