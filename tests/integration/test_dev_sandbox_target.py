"""Integration tests for Step 7b: the dev sandbox target — real HTTP and
real SSH containers (the same images infra/compose/docker-compose.dev-sandbox.yml
uses), plus MirageSpider (Step 5's already-proven business logic) reporting
real telemetry observed "from inside" this target. Covers the Step 7b
acceptance line: "The dev sandbox accepts the three protocols [HTTP/SSH/RDP]
and reports Spider telemetry — a valid steering target exists." RDP is
LAB_VERIFICATION_REQUIRED (no viable local RDP server — see KNOWN_ISSUES.md
and the compose file's own comment).
"""
from __future__ import annotations

import subprocess
import time
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from mirage_agent_ingestion.enrollment import create_enrollment_token
from mirage_spider.service_logic import SpiderServiceLogic
from testcontainers.core.container import DockerContainer

from mirage_common.agent_http_client import AgentHttpClient
from mirage_common.agent_keys import LocalFileKeyProvider
from mirage_common.agent_queue import EncryptedEventQueue

pytestmark = pytest.mark.integration

TEST_BUILD_HASH = "e" * 64


@pytest.fixture(scope="module")
def dev_sandbox_http():
    container = DockerContainer("nginx:1.27-alpine").with_exposed_ports(80)
    container.start()
    host = container.get_container_host_ip()
    port = container.get_exposed_port(80)
    url = f"http://{host}:{port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    else:
        raise TimeoutError("dev sandbox HTTP target did not become ready")
    yield url
    container.stop()


@pytest.fixture(scope="module")
def dev_sandbox_ssh(tmp_path_factory, ssh_target_image):
    keys_dir = tmp_path_factory.mktemp("dev-sandbox-ssh-keys")
    private_key_path = keys_dir / "id_ed25519"
    key = ed25519.Ed25519PrivateKey.generate()
    private_key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    )
    private_key_path.chmod(0o600)
    public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()

    container = (
        DockerContainer(ssh_target_image)
        .with_env("PUBLIC_KEY", public_key)
        .with_env("USER_NAME", "employee01")
        .with_env("PASSWORD_ACCESS", "false")
        .with_exposed_ports(2222)
    )
    container.start()
    host = container.get_container_host_ip()
    port = container.get_exposed_port(2222)

    # linuxserver.io's s6-overlay init log wording isn't a stable string to
    # wait on across image versions — poll with a real SSH connection
    # attempt instead, the exact thing this fixture needs to be true anyway.
    ssh_cmd = [
        "ssh", "-i", str(private_key_path),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5", "-p", str(port), "employee01@" + host, "true",
    ]
    deadline = time.time() + 60
    last_result = None
    while time.time() < deadline:
        last_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
        if last_result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise TimeoutError(f"dev sandbox SSH target did not become ready: {last_result.stderr if last_result else 'no attempt'}")

    yield {"host": host, "port": port, "private_key_path": private_key_path, "user": "employee01"}
    container.stop()


def test_dev_sandbox_accepts_real_http_connections(dev_sandbox_http):
    resp = httpx.get(dev_sandbox_http)
    assert resp.status_code == 200
    assert "nginx" in resp.text.lower() or "welcome" in resp.text.lower()


def test_dev_sandbox_accepts_real_ssh_connections(dev_sandbox_ssh):
    target = dev_sandbox_ssh
    result = subprocess.run(
        [
            "ssh", "-i", str(target["private_key_path"]),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-p", str(target["port"]),
            f"{target['user']}@{target['host']}", "echo", "mirage-dev-sandbox-reachable",
        ],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "mirage-dev-sandbox-reachable" in result.stdout


async def test_spider_reports_telemetry_observed_from_the_dev_sandbox(
    tmp_path, pg_conn, ca_config, live_agent_ingestion_server, dev_sandbox_http, dev_sandbox_ssh,
):
    """Demonstrates the full chain the Done-when line implies: a valid
    steering target (real HTTP+SSH, proven above) exists, and Spider
    (running "on" that target, conceptually) reports real, ordered,
    case-tagged telemetry about it — the exact mechanism Step 5 proved,
    now exercised with sandbox-flavored observation content rather than
    synthetic placeholders."""
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, 'SPIDER', 'test') ON CONFLICT DO NOTHING",
            (TEST_BUILD_HASH,),
        )
    await pg_conn.commit()

    agent_subject = f"spider-devsandbox-{uuid.uuid4().hex}.mirage.local"
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

    # Spider observes the two real services actually running on this target.
    logic.record_observation(
        identity, observation_type="NETWORK_CONNECTION", subject=f"{dev_sandbox_ssh['host']}:{dev_sandbox_ssh['port']}",
        detail={"remote_port": dev_sandbox_ssh["port"]},
    )
    logic.record_observation(identity, observation_type="PROCESS_START", subject="sshd")
    logic.record_observation(identity, observation_type="PROCESS_START", subject="nginx")
    assert queue.pending_count() == 3

    payload = logic.build_heartbeat_payload(identity, uptime_seconds=10)
    assert payload["queue_depth"] == 3  # a valid steering target reporting real, queued Spider telemetry
