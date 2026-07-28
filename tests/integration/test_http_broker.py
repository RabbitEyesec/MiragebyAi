"""Integration test for Step 8b's HTTP broker (Appendix H.1): a REAL Nginx
container (infra/broker/http/nginx.conf.template, unmodified from what
ships) calling a REAL mirage-api /route before selecting between two REAL
backend containers. Covers the Step 8b/8c/8d Done-when line for the HTTP
leg: "Each protocol routes to the sandbox per decision... no mid-session
migration claim exists" (each request re-resolves the route fresh; there is
no persistent connection being "moved").
"""
from __future__ import annotations

import contextlib
import time
import uuid
from pathlib import Path

import httpx
import pytest
from mirage_agent_ingestion.enrollment import create_enrollment_token, enroll_agent
from testcontainers.core.container import DockerContainer

from mirage_common.routing import write_routing_decision
from mirage_contracts.ulid import generate_ulid

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
NGINX_TEMPLATE = REPO_ROOT / "infra" / "broker" / "http" / "nginx.conf.template"


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


async def _enrolled_http_broker_serial(pg_conn_with_routing, ca_config) -> str:
    """A real, enrolled BROKER_CLIENT agent's certificate_serial — mirage-api's
    /route rejects anything else with 403 (Step 8a's own defense-in-depth
    check), so the broker container needs a genuine identity, not a
    placeholder string."""
    async with pg_conn_with_routing.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, 'BROKER_CLIENT', 'test') ON CONFLICT DO NOTHING",
            ("a" * 64,),
        )
    await pg_conn_with_routing.commit()

    agent_id = f"http-broker-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn_with_routing, ca_config, role="BROKER_CLIENT", subject=agent_id, sans=[agent_id], created_by="test",
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
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(), host_fingerprint="AA:00:BB:11:CC:22", build_hash="a" * 64,
    )
    return enrolled.certificate_serial


@pytest.fixture
def broker_backends():
    """Two real, distinguishable HTTP backends — 'employee' (ENDPOINT) and
    'sandbox' (SANDBOX) — each just nginx serving a distinct static
    response body, so the test can prove WHICH one the broker actually
    routed to."""
    employee = DockerContainer("nginx:1.27-alpine").with_exposed_ports(80)
    employee.start()
    sandbox = DockerContainer("nginx:1.27-alpine").with_exposed_ports(80)
    sandbox.start()

    def _write_marker(container: DockerContainer, marker: str) -> None:
        # Exit status was previously discarded, so a failed write only showed
        # up later as the broker appearing to route to the wrong backend.
        code, output = container.get_wrapped_container().exec_run(
            ["sh", "-c", f"echo -n {marker} > /usr/share/nginx/html/index.html"]
        )
        assert code == 0, f"could not write {marker} marker: {output!r}"

    _write_marker(employee, "EMPLOYEE_BACKEND")
    _write_marker(sandbox, "SANDBOX_BACKEND")

    yield {"employee": employee, "sandbox": sandbox}
    employee.stop()
    sandbox.stop()


@pytest.fixture
async def http_broker(pg_conn_with_routing, ca_config, live_mirage_api_server, broker_backends):
    """pg_conn_with_routing is listed first so its migrations are guaranteed
    to run before this fixture's own health-check polling loop below makes
    its first real request through nginx to mirage-api's /route — that
    request hits the DB for real, so the schema must already exist."""
    broker_serial = await _enrolled_http_broker_serial(pg_conn_with_routing, ca_config)

    network_name = "mirage-test-broker-net"
    import docker

    client = docker.from_env()
    try:
        network = client.networks.create(network_name, driver="bridge")
    except docker.errors.APIError:
        network = client.networks.get(network_name)

    for name, container in broker_backends.items():
        network.connect(container.get_wrapped_container().id, aliases=[f"{name}-backend"])

    broker = (
        DockerContainer("nginx:1.27-alpine")
        .with_env("MIRAGE_API_URL", live_mirage_api_server["base_url_container"])
        .with_env("MIRAGE_BROKER_CERT_SERIAL", broker_serial)
        .with_env("MIRAGE_BROKER_PROXY_SECRET", live_mirage_api_server["proxy_shared_secret"])
        .with_env("SANDBOX_UPSTREAM", "sandbox-backend:80")
        .with_env("EMPLOYEE_UPSTREAM", "employee-backend:80")
        .with_volume_mapping(str(NGINX_TEMPLATE), "/etc/nginx/templates/nginx.conf.template", mode="ro")
        .with_command(
            "sh -c \"envsubst '$MIRAGE_API_URL $MIRAGE_BROKER_CERT_SERIAL $MIRAGE_BROKER_PROXY_SECRET "
            "$SANDBOX_UPSTREAM $EMPLOYEE_UPSTREAM' < /etc/nginx/templates/nginx.conf.template "
            "> /etc/nginx/nginx.conf && exec nginx -g 'daemon off;'\""
        )
        .with_exposed_ports(8080)
        .with_kwargs(
            # Joined at CREATION, not connected afterwards. nginx.conf.template
            # declares `resolver 127.0.0.11` — Docker's embedded DNS, which a
            # container only gets by being on a user-defined network. Started on
            # the default bridge, nginx had no resolver for the whole window in
            # which this fixture polls: the auth_request subrequest to
            # MIRAGE_API_URL could not resolve, nginx answered 500 (an
            # auth_request whose subrequest errors is a 500, NOT the 502 this
            # loop used to wait for), and the poll ran out. Docker Desktop
            # happens to answer on 127.0.0.11 from the default bridge too, which
            # is why this only ever failed on native Linux.
            network=network_name,
            # host.docker.internal is a Docker Desktop (macOS/Windows) built-in;
            # native Linux Docker (e.g. GitHub Actions runners) needs it mapped
            # explicitly, or DNS resolution for MIRAGE_API_URL hangs and the
            # readiness poll below times out. host-gateway is a no-op where the
            # mapping already exists.
            extra_hosts={"host.docker.internal": "host-gateway"},
        )
    )
    broker.start()

    host = broker.get_container_host_ip()
    port = broker.get_exposed_port(8080)
    base_url = f"http://{host}:{port}"

    # Readiness here means only "nginx is listening and speaking HTTP" — which
    # status it returns is what the tests themselves assert. The previous
    # version accepted a fixed set of codes and, worse, only slept inside the
    # `except` branch: any unlisted status (such as that 500) spun the CPU flat
    # out until the deadline instead of retrying calmly.
    deadline = time.time() + 60
    last_error: object = "no attempt"
    while time.time() < deadline:
        try:
            httpx.get(base_url, timeout=2)
            break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(0.5)
    else:
        logs = broker.get_wrapped_container().logs().decode(errors="replace")[-4000:]
        raise TimeoutError(f"http broker did not start ({last_error})\nnginx logs:\n{logs}")

    yield base_url
    broker.stop()
    for _name, container in broker_backends.items():
        # already disconnected (e.g. the container itself already stopped)
        with contextlib.suppress(docker.errors.APIError):
            network.disconnect(container.get_wrapped_container().id, force=True)
    network.remove()


async def _create_case(conn) -> str:
    case_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO cases (case_id, severity, owner) VALUES (%s, 'HIGH', 'analyst-1')", (case_id,))
    await conn.commit()
    return case_id


async def test_http_broker_routes_to_employee_by_default(http_broker, pg_conn_with_routing):
    """No routing decision exists for this connection -> /route's own
    default (ENDPOINT) -> the broker selects the employee backend.
    Depends on pg_conn_with_routing directly (not just transitively via
    http_broker/live_mirage_api_server) so the migrations it applies are
    guaranteed to have run before this test's first real request."""
    resp = httpx.get(http_broker, timeout=10)
    assert resp.status_code == 200
    assert resp.text == "EMPLOYEE_BACKEND"


async def test_http_broker_routes_to_sandbox_per_approved_decision(http_broker, pg_conn_with_routing):
    """The real Step 8a mechanism, end to end: a routing_decisions row
    written for THIS connection's real match_key causes the broker to
    select the sandbox backend on the very next request — proving /route
    genuinely drives Nginx's upstream choice, not a hardcoded config.
    The real match_key is discovered from the FIRST request's own
    steering.decision_recorded outbox row (Docker's NAT'd source IP as
    nginx observes it is not worth predicting — reading back what actually
    happened is more robust than guessing it in advance)."""
    case_id = await _create_case(pg_conn_with_routing)

    first = httpx.get(http_broker, timeout=10)
    assert first.text == "EMPLOYEE_BACKEND"  # confirms a real /route round-trip already happened

    async with pg_conn_with_routing.cursor() as cur:
        await cur.execute(
            "SELECT payload->'payload'->>'match_key' FROM outbox_events "
            "WHERE topic = 'steering.decision_recorded' ORDER BY created_at DESC LIMIT 1"
        )
        row = await cur.fetchone()
    assert row is not None
    real_match_key = row[0]

    await write_routing_decision(
        pg_conn_with_routing, case_id=case_id, match_key=real_match_key, protocol="HTTP",
        target="SANDBOX", created_by="test-analyst",
    )
    await pg_conn_with_routing.commit()

    # §6.1's own 1-second in-memory TTL cache means the FIRST request's
    # cached ENDPOINT result would otherwise still be served — this sleep
    # is the real cache's real behavior, not test flakiness.
    time.sleep(1.1)

    second = httpx.get(http_broker, timeout=10)
    assert second.status_code == 200
    assert second.text == "SANDBOX_BACKEND"
