"""Integration test for Step 8c's SSH broker (Appendix H.2): a REAL OpenSSH
bastion (infra/broker/ssh/mirage-route-selector.sh, unmodified from what
ships) whose ForceCommand calls a REAL mirage-api /route before selecting
between two REAL backend SSH targets, then execs a NEW bastion-authenticated
SSH session into whichever backend was selected. Covers the Step
8b/8c/8d Done-when line for the SSH leg: "Each protocol routes to the
sandbox per decision... no mid-session migration claim exists" — backend
selection happens once, before the backend channel opens, per §6.2.
"""
from __future__ import annotations

import contextlib
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from mirage_agent_ingestion.enrollment import create_enrollment_token, enroll_agent
from testcontainers.core.container import DockerContainer

from mirage_common.routing import write_routing_decision
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
SELECTOR_SCRIPT = REPO_ROOT / "infra" / "broker" / "ssh" / "mirage-route-selector.sh"


@pytest.fixture
async def pg_conn_with_routing(pg_conn):
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


async def _enrolled_ssh_broker_serial(pg_conn_with_routing, ca_config) -> str:
    async with pg_conn_with_routing.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, 'BROKER_CLIENT', 'test') ON CONFLICT DO NOTHING",
            ("b" * 64,),
        )
    await pg_conn_with_routing.commit()

    agent_id = f"ssh-broker-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn_with_routing, ca_config, role="BROKER_CLIENT", subject=agent_id, sans=[agent_id], created_by="test",
    )
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
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
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(), host_fingerprint="BB:11:CC:22:DD:33", build_hash="b" * 64,
    )
    return enrolled.certificate_serial


def _generate_ssh_keypair(path: Path) -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
    path.chmod(0o600)
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _wait_for_ssh(private_key_path: Path, port: int, host: str = "localhost", user: str = "employee01", timeout: float = 60.0) -> None:
    cmd = [
        "ssh", "-i", str(private_key_path),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5", "-p", str(port), f"{user}@{host}", "true",
    ]
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if last.returncode == 0:
            return
        time.sleep(1)
    raise TimeoutError(f"ssh target on port {port} did not become ready: {last.stderr if last else 'no attempt'}")


@pytest.fixture(scope="module")
def bastion_backend_keypair(tmp_path_factory):
    keys_dir = tmp_path_factory.mktemp("bastion-backend-key")
    private_path = keys_dir / "bastion_backend_key"
    public_key = _generate_ssh_keypair(private_path)
    return {"private_path": private_path, "public_key": public_key}


@pytest.fixture(scope="module")
def client_bastion_keypair(tmp_path_factory):
    keys_dir = tmp_path_factory.mktemp("client-bastion-key")
    private_path = keys_dir / "client_to_bastion_key"
    public_key = _generate_ssh_keypair(private_path)
    return {"private_path": private_path, "public_key": public_key}


def _write_marker(container: DockerContainer, value: str) -> None:
    """Mark a backend so a landed session can prove WHICH container it is in.

    exec_run's exit status was previously discarded, so a failed write showed
    up much later as a baffling `cat: /marker: No such file or directory` from
    the test itself — indistinguishable from the broker routing to the wrong
    place. Fail here, where the cause is still visible."""
    code, output = container.get_wrapped_container().exec_run(["sh", "-c", f"echo {value} > /marker"])
    assert code == 0, f"could not write /marker into {value} backend: {output!r}"


@pytest.fixture
def ssh_backends(bastion_backend_keypair, ssh_target_image):
    """Two real, distinguishable SSH backends — 'employee' (ENDPOINT) and
    'sandbox' (SANDBOX) — both trusting the SAME bastion backend key
    (Appendix H.2: the bastion authenticates onward with its own identity),
    each marked with a distinct hostname so the test can prove WHICH one a
    connection actually landed in."""
    employee = (
        DockerContainer(ssh_target_image)
        .with_env("PUBLIC_KEY", bastion_backend_keypair["public_key"])
        .with_env("USER_NAME", "employee01")
        .with_env("PASSWORD_ACCESS", "false")
        .with_exposed_ports(2222)
    )
    sandbox = (
        DockerContainer(ssh_target_image)
        .with_env("PUBLIC_KEY", bastion_backend_keypair["public_key"])
        .with_env("USER_NAME", "employee01")
        .with_env("PASSWORD_ACCESS", "false")
        .with_exposed_ports(2222)
    )
    employee.start()
    sandbox.start()

    _wait_for_ssh(bastion_backend_keypair["private_path"], employee.get_exposed_port(2222), host=employee.get_container_host_ip())
    _wait_for_ssh(bastion_backend_keypair["private_path"], sandbox.get_exposed_port(2222), host=sandbox.get_container_host_ip())

    _write_marker(employee, "EMPLOYEE_BACKEND")
    _write_marker(sandbox, "SANDBOX_BACKEND")

    yield {"employee": employee, "sandbox": sandbox}
    employee.stop()
    sandbox.stop()


def _assert_force_command_installed(bastion: DockerContainer) -> None:
    """Prove the bastion really is a broker before any test trusts it to route.

    The selector is installed by a /custom-cont-init.d script, and s6-overlay
    skips that script SILENTLY when it is not owned by root and not marked
    executable — logging only `is not an executable file` — leaving sshd up as
    an ordinary SSH server with no ForceCommand at all. Routing tests then
    "connect fine" and run the client's command on the bastion itself, which
    surfaces as `cat: /marker: No such file or directory`: a failure that reads
    like bad routing but is really a missing install.

    Verified directly (mirage-route-selector.sh mounted from a checkout owned
    by a non-root uid, as on a Linux CI runner): mode 644 => skipped, no
    ForceCommand; mode 755 => executed, ForceCommand present. Docker Desktop
    hides it by presenting bind-mounted files as root-owned, so the script's
    mode must stay 755 in git. Assert the observable post-conditions here so a
    regression names itself instead of masquerading as a routing bug."""
    container = bastion.get_wrapped_container()
    code, output = container.exec_run(["sh", "-c", "grep -c '^ForceCommand /usr/local/bin/mirage-route-select' /config/sshd/sshd_config"])
    assert code == 0 and output.decode().strip() != "0", (
        "the bastion's sshd_config has no ForceCommand — /custom-cont-init.d/"
        "00-install-selector.sh did not run. Check that "
        "infra/broker/ssh/mirage-route-selector.sh is mode 755 in git "
        f"(container init log follows)\n{container.logs().decode(errors='replace')[-4000:]}"
    )
    code, _ = container.exec_run(["test", "-x", "/usr/local/bin/mirage-route-select"])
    assert code == 0, "selector script was not installed executable on the bastion"


@pytest.fixture
async def ssh_bastion(pg_conn_with_routing, ca_config, live_mirage_api_server, ssh_backends, bastion_backend_keypair, client_bastion_keypair, ssh_target_image):
    broker_serial = await _enrolled_ssh_broker_serial(pg_conn_with_routing, ca_config)

    import docker

    client = docker.from_env()
    network_name = "mirage-test-ssh-broker-net"
    try:
        network = client.networks.create(network_name, driver="bridge")
    except docker.errors.APIError:
        network = client.networks.get(network_name)

    network.connect(ssh_backends["employee"].get_wrapped_container().id, aliases=["employee-ssh-backend"])
    network.connect(ssh_backends["sandbox"].get_wrapped_container().id, aliases=["sandbox-ssh-backend"])

    bastion = (
        DockerContainer(ssh_target_image)
        .with_env("PUBLIC_KEY", client_bastion_keypair["public_key"])
        .with_env("USER_NAME", "employee01")
        .with_env("PASSWORD_ACCESS", "false")
        .with_env("MIRAGE_API_URL", live_mirage_api_server["base_url_container"])
        .with_env("MIRAGE_BROKER_CERT_SERIAL", broker_serial)
        .with_env("MIRAGE_BROKER_PROXY_SECRET", live_mirage_api_server["proxy_shared_secret"])
        .with_env("MIRAGE_SANDBOX_SSH_HOST", "sandbox-ssh-backend")
        .with_env("MIRAGE_SANDBOX_SSH_PORT", "2222")
        .with_env("MIRAGE_EMPLOYEE_SSH_HOST", "employee-ssh-backend")
        .with_env("MIRAGE_EMPLOYEE_SSH_PORT", "2222")
        .with_volume_mapping(str(SELECTOR_SCRIPT), "/custom-cont-init.d/00-install-selector.sh", mode="ro")
        .with_volume_mapping(str(bastion_backend_keypair["private_path"]), "/config/.ssh/bastion_backend_key", mode="ro")
        .with_exposed_ports(2222)
        .with_kwargs(
            # Joined at CREATION, not connected afterwards. The backends are
            # reachable only by their aliases on this user-defined network, and
            # those aliases resolve only through Docker's embedded DNS
            # (127.0.0.11), which a container gets when it joins such a network.
            # Starting on the default bridge and connecting after meant the
            # first SSH session could reach sshd before name resolution worked.
            network=network_name,
            # host.docker.internal is a Docker Desktop (macOS/Windows) built-in;
            # native Linux Docker (e.g. GitHub Actions runners) needs it mapped
            # explicitly, or mirage-route-select's curl to MIRAGE_API_URL fails
            # to reach the host. host-gateway is a no-op where the mapping
            # already exists.
            extra_hosts={"host.docker.internal": "host-gateway"},
        )
    )
    bastion.start()

    host = bastion.get_container_host_ip()
    port = bastion.get_exposed_port(2222)
    _wait_for_ssh(client_bastion_keypair["private_path"], port, host=host)
    _assert_force_command_installed(bastion)

    yield {"host": host, "port": port, "private_key_path": client_bastion_keypair["private_path"]}

    bastion.stop()
    for _name, container in ssh_backends.items():
        with contextlib.suppress(docker.errors.APIError):
            network.disconnect(container.get_wrapped_container().id, force=True)
    network.remove()


async def _create_case(conn) -> str:
    case_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO cases (case_id, severity, owner) VALUES (%s, 'HIGH', 'analyst-1')", (case_id,))
    await conn.commit()
    return case_id


def _ssh_through_bastion(bastion: dict, command: str) -> str:
    result = subprocess.run(
        [
            "ssh", "-i", str(bastion["private_key_path"]),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-p", str(bastion["port"]),
            f"employee01@{bastion['host']}", command,
        ],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    return result.stdout.strip()


async def test_ssh_broker_routes_to_employee_by_default(ssh_bastion, pg_conn_with_routing):
    """No routing decision exists for this connection -> /route's own
    default (ENDPOINT) -> the bastion's ForceCommand execs into the
    employee backend. This is a real, new SSH session landing in a real,
    different container — not a claim about an existing connection."""
    output = _ssh_through_bastion(ssh_bastion, "cat /marker")
    assert output == "EMPLOYEE_BACKEND"


async def test_ssh_broker_routes_to_sandbox_per_approved_decision(ssh_bastion, pg_conn_with_routing):
    """The real Step 8a mechanism, end to end, for the SSH broker: a
    routing_decisions row written for THIS connection's real match_key
    causes the bastion's ForceCommand to exec into the sandbox backend on
    the very next connection."""
    case_id = await _create_case(pg_conn_with_routing)

    first = _ssh_through_bastion(ssh_bastion, "cat /marker")
    assert first == "EMPLOYEE_BACKEND"

    async with pg_conn_with_routing.cursor() as cur:
        await cur.execute(
            "SELECT payload->'payload'->>'match_key' FROM outbox_events "
            "WHERE topic = 'steering.decision_recorded' ORDER BY created_at DESC LIMIT 1"
        )
        row = await cur.fetchone()
    assert row is not None
    real_match_key = row[0]
    assert real_match_key.startswith("SSH|bastion-1|")

    await write_routing_decision(
        pg_conn_with_routing, case_id=case_id, match_key=real_match_key, protocol="SSH",
        target="SANDBOX", created_by="test-analyst",
    )
    await pg_conn_with_routing.commit()

    # §6.1's 1-second in-memory TTL cache — real behavior, not test flakiness.
    time.sleep(1.1)

    second = _ssh_through_bastion(ssh_bastion, "cat /marker")
    assert second == "SANDBOX_BACKEND"
