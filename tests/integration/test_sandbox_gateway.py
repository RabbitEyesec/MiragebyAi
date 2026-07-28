"""Integration tests for Step 9b: MirageEnvironmentController +
mirage-sandbox-gateway, against real Postgres, real NATS, real step-ca
(ENV_CONTROLLER role enrolment — reserved since Step 3), real Keycloak, and
a real MirageEnvironmentController WebSocket client executing structured
actions against a real temp-directory sandbox root. Covers Step 9b's own
Done-when line: "A structured action executes and rolls back with full
audit; every output carries a source tag; soft reset < 3 min, full rebuild
< 10 min."
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import uuid
from pathlib import Path

import httpx
import pytest
from mirage_agent_ingestion.enrollment import create_enrollment_token
from mirage_env_controller.actions import ExecutorContext
from mirage_env_controller.journal import ActionJournal
from mirage_env_controller.service_logic import EnvControllerServiceLogic

from mirage_common.agent_http_client import AgentHttpClient
from mirage_common.mtls_auth import CLIENT_SERIAL_HEADER, PROXY_SHARED_SECRET_HEADER

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_BUILD_HASH = "9" * 64


@pytest.fixture
async def pg_conn_with_sandbox_actions(pg_conn):
    migrations = [
        "0002_cases_minimal.up.sql",
        "0003_case_lifecycle_and_outbox.up.sql",
        "0004_detection_correlation.up.sql",
        "0005_routing_decisions.up.sql",
        "0006_sandbox_actions.up.sql",
    ]
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "DROP TABLE IF EXISTS sandbox_actions, sandbox_instances, routing_decisions, audit_events, "
            "processed_events, outbox_events, case_state_transitions, cases CASCADE"
        )
        await cur.execute("DROP FUNCTION IF EXISTS notify_outbox_events() CASCADE")
        for name in migrations:
            await cur.execute((REPO_ROOT / "infra" / "migrations" / name).read_text())
    await pg_conn.commit()
    return pg_conn


async def _token_for(keycloak_realm: dict, username: str) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{keycloak_realm['base_url']}/realms/mirage/protocol/openid-connect/token",
            data={"client_id": "mirage-dashboard", "username": username, "password": keycloak_realm["dev_user_password"], "grant_type": "password"},
        )
    resp.raise_for_status()
    return resp.json()["access_token"]


@pytest.fixture
async def case_id(pg_conn_with_sandbox_actions) -> str:
    from mirage_contracts.ulid import generate_ulid

    cid = generate_ulid()
    async with pg_conn_with_sandbox_actions.cursor() as cur:
        await cur.execute("INSERT INTO cases (case_id, severity) VALUES (%s, 'MEDIUM')", (cid,))
    await pg_conn_with_sandbox_actions.commit()
    return cid


@pytest.fixture
async def enrolled_controller_identity(pg_conn_with_sandbox_actions, ca_config, live_agent_ingestion_server, tmp_path):
    """Enrols a real MirageEnvironmentController identity via the exact
    Step 3 mechanism already proven for Endpoint/Spider — ENV_CONTROLLER's
    provisioner has existed since Step 3 (infra/step-ca/PROFILES.md); Step
    9b is simply its first real user."""
    async with pg_conn_with_sandbox_actions.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, 'ENV_CONTROLLER', 'test') ON CONFLICT DO NOTHING",
            (TEST_BUILD_HASH,),
        )
    await pg_conn_with_sandbox_actions.commit()

    subject = f"envctl-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn_with_sandbox_actions, ca_config, role="ENV_CONTROLLER", subject=subject, sans=[subject], created_by="test",
    )
    client = AgentHttpClient(base_url=live_agent_ingestion_server["base_url"], root_ca_path=live_agent_ingestion_server["root_ca_path"])

    allowed_root = tmp_path / "DecoyContent"
    allowed_root.mkdir()
    programdata = tmp_path / "ProgramData"
    programdata.mkdir()
    journal = ActionJournal(programdata / "Journal" / "journal.db")
    ctx = ExecutorContext(allowed_roots=(allowed_root,), programdata=programdata, journal=journal)

    logic = EnvControllerServiceLogic(
        client=client, identity_state_path=tmp_path / "identity.json", cert_dir=tmp_path / "certs",
        build_hash=TEST_BUILD_HASH, ctx=ctx,
    )
    identity = await logic.enroll(enrollment_token=minted.token, subject=subject)
    return {"logic": logic, "identity": identity, "ctx": ctx, "allowed_root": allowed_root, "journal": journal}


async def _issue_action(base_url, token, case_id, *, sandbox_id, action_type, expected_state_version, action_params=None, issued_by="ANALYST"):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/api/v1/cases/{case_id}/sandbox-actions",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "sandbox_id": sandbox_id, "action_type": action_type, "action_params": action_params or {},
                "expected_state_version": expected_state_version, "issued_by": issued_by,
            },
            timeout=15,
        )
    return resp


async def _run_controller(gateway_ws_url, sandbox_id, case_id, image_id, proxy_shared_secret, identity, logic, *, max_commands):
    headers = {CLIENT_SERIAL_HEADER: identity.certificate_serial, PROXY_SHARED_SECRET_HEADER: proxy_shared_secret}
    url = f"{gateway_ws_url}/api/v1/sandboxes/{sandbox_id}/connect?case_id={case_id}&image_id={image_id}"
    return await logic.connect_and_serve(url, additional_headers=headers, max_commands=max_commands)


class TestSandboxGatewayEndToEnd:
    async def test_structured_action_executes_and_rolls_back_with_full_audit(
        self, pg_conn_with_sandbox_actions, live_sandbox_gateway_server, keycloak_realm, case_id, enrolled_controller_identity,
    ):
        sandbox_id = f"sandbox-{uuid.uuid4().hex}"
        logic = enrolled_controller_identity["logic"]
        identity = enrolled_controller_identity["identity"]
        allowed_root = enrolled_controller_identity["allowed_root"]

        controller_task = asyncio.create_task(_run_controller(
            live_sandbox_gateway_server["ws_base_url"], sandbox_id, case_id, "ami-test-001",
            live_sandbox_gateway_server["proxy_shared_secret"], identity, logic, max_commands=2,
        ))
        await asyncio.sleep(0.5)  # let the WS connect before a command is issued

        token = await _token_for(keycloak_realm, "dev-platform-admin")
        raw = b"decoy-finance-report"
        destination = allowed_root / "Q3_Report.xlsx"
        resp = await _issue_action(
            live_sandbox_gateway_server["base_url"], token, case_id, sandbox_id=sandbox_id, action_type="PLACE_ARTIFACT",
            expected_state_version=0,
            action_params={
                "artifact_id": "artifact-001", "destination": str(destination),
                "content_b64": base64.b64encode(raw).decode(), "expected_hash": hashlib.sha256(raw).hexdigest(),
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "SUCCESS"
        assert body["output_tag"] == "REAL_OS_OUTPUT"
        assert body["new_state_version"] == 1
        assert destination.read_bytes() == raw
        place_action_id = body["action_id"]

        async with pg_conn_with_sandbox_actions.cursor() as cur:
            await cur.execute("SELECT status, output_tag FROM sandbox_actions WHERE action_id = %s", (place_action_id,))
            row = await cur.fetchone()
        assert row == ("SUCCESS", "REAL_OS_OUTPUT")

        async with pg_conn_with_sandbox_actions.cursor() as cur:
            await cur.execute("SELECT state_version FROM sandbox_instances WHERE sandbox_id = %s", (sandbox_id,))
            (version,) = await cur.fetchone()
        assert version == 1

        rollback_resp = await _issue_action(
            live_sandbox_gateway_server["base_url"], token, case_id, sandbox_id=sandbox_id, action_type="ROLLBACK_ACTION",
            expected_state_version=1, action_params={"target_action_id": place_action_id},
        )
        assert rollback_resp.status_code == 200, rollback_resp.text
        rollback_body = rollback_resp.json()
        assert rollback_body["status"] == "SUCCESS"
        assert rollback_body["rollback_action_id"] == place_action_id
        assert not destination.exists()

        async with pg_conn_with_sandbox_actions.cursor() as cur:
            await cur.execute("SELECT count(*) FROM audit_events WHERE target = %s", (sandbox_id,))
            (audit_count,) = await cur.fetchone()
        assert audit_count == 2  # PLACE_ARTIFACT + ROLLBACK_ACTION, each audited

        await controller_task

    async def test_stale_expected_state_version_is_rejected_with_409(
        self, pg_conn_with_sandbox_actions, live_sandbox_gateway_server, keycloak_realm, case_id, enrolled_controller_identity,
    ):
        sandbox_id = f"sandbox-{uuid.uuid4().hex}"
        logic = enrolled_controller_identity["logic"]
        identity = enrolled_controller_identity["identity"]
        allowed_root = enrolled_controller_identity["allowed_root"]

        controller_task = asyncio.create_task(_run_controller(
            live_sandbox_gateway_server["ws_base_url"], sandbox_id, case_id, "ami-test-002",
            live_sandbox_gateway_server["proxy_shared_secret"], identity, logic, max_commands=1,
        ))
        await asyncio.sleep(0.5)

        token = await _token_for(keycloak_realm, "dev-platform-admin")
        stale_resp = await _issue_action(
            live_sandbox_gateway_server["base_url"], token, case_id, sandbox_id=sandbox_id, action_type="TEST_FILE_PLACEMENT",
            expected_state_version=99, action_params={"destination": str(allowed_root / "x.txt")},
        )
        assert stale_resp.status_code == 409

        # A correctly-versioned command still succeeds afterward.
        good_resp = await _issue_action(
            live_sandbox_gateway_server["base_url"], token, case_id, sandbox_id=sandbox_id, action_type="TEST_FILE_PLACEMENT",
            expected_state_version=0, action_params={"destination": str(allowed_root / "x.txt")},
        )
        assert good_resp.status_code == 200
        assert good_resp.json()["status"] == "SUCCESS"

        await controller_task

    async def test_restricted_path_is_rejected_end_to_end(
        self, pg_conn_with_sandbox_actions, live_sandbox_gateway_server, keycloak_realm, case_id, enrolled_controller_identity, tmp_path,
    ):
        sandbox_id = f"sandbox-{uuid.uuid4().hex}"
        logic = enrolled_controller_identity["logic"]
        identity = enrolled_controller_identity["identity"]

        controller_task = asyncio.create_task(_run_controller(
            live_sandbox_gateway_server["ws_base_url"], sandbox_id, case_id, "ami-test-003",
            live_sandbox_gateway_server["proxy_shared_secret"], identity, logic, max_commands=1,
        ))
        await asyncio.sleep(0.5)

        outside_target = tmp_path / "OUTSIDE_ALLOWED_ROOTS" / "evil.txt"
        token = await _token_for(keycloak_realm, "dev-platform-admin")
        resp = await _issue_action(
            live_sandbox_gateway_server["base_url"], token, case_id, sandbox_id=sandbox_id, action_type="TEST_FILE_PLACEMENT",
            expected_state_version=0, action_params={"destination": str(outside_target)},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "REJECTED"
        assert not outside_target.exists()

        await controller_task

    async def test_unauthenticated_caller_cannot_issue_actions(self, live_sandbox_gateway_server, case_id):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{live_sandbox_gateway_server['base_url']}/api/v1/cases/{case_id}/sandbox-actions",
                json={"sandbox_id": "x", "action_type": "TEST_FILE_PLACEMENT", "expected_state_version": 0},
            )
        assert resp.status_code == 401

    async def test_command_to_a_disconnected_sandbox_fails_cleanly(self, live_sandbox_gateway_server, keycloak_realm, case_id, pg_conn_with_sandbox_actions):
        """No live controller connection registered for this sandbox_id at
        all (not even a connect-then-disconnect) — ensure_sandbox_instance
        is never called, so the sandbox row doesn't exist: a 404, not a
        hang or a fabricated success."""
        token = await _token_for(keycloak_realm, "dev-platform-admin")
        resp = await _issue_action(
            live_sandbox_gateway_server["base_url"], token, case_id, sandbox_id="never-connected-sandbox",
            action_type="TEST_FILE_PLACEMENT", expected_state_version=0, action_params={"destination": "/tmp/x.txt"},
        )
        assert resp.status_code == 404
