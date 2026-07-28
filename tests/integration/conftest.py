"""Shared fixtures for integration tests: real Docker containers via
testcontainers, not mocks or fakes (ARCHITECTURE_DECISIONS.md ADR-0006).
"""
from __future__ import annotations

import time
from pathlib import Path

import httpx
import nats
import psycopg
import pytest
import pytest_asyncio
from testcontainers.community.postgres import PostgresContainer
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

REPO_ROOT = Path(__file__).resolve().parents[2]

# Pinned, not :latest. Two reasons, both observed in CI rather than guessed:
# a floating tag silently re-pulls a different sshd/s6-overlay build between
# runs (so a green suite proves nothing about the next one), and every fixture
# that referenced the floating tag independently raced the same registry.
SSH_TARGET_IMAGE = "lscr.io/linuxserver/openssh-server:10.3_p1-r0-ls232"


def pull_image_with_retry(image: str, *, attempts: int = 5) -> str:
    """Pull `image` once per session, retrying registry rate limits.

    lscr.io rate-limits anonymous pulls per source IP, and GitHub's hosted
    runners share egress addresses — so a run can fail on a pull that has
    nothing to do with this code:

        docker.errors.APIError: 500 Server Error ... images/create...
        ("toomanyrequests: retry-after: 254.631µs, allowed: 44000/minute")

    testcontainers pulls lazily inside `.start()`, which turns that transient
    429 into a fixture ERROR. Pulling here, up front and with backoff, keeps
    the retry in one place instead of once per fixture, and leaves the image
    warm in the local cache so `.start()` never reaches the network at all.
    Genuine failures (bad tag, no such repository) still raise on the last
    attempt — this retries rate limiting, it does not mask a missing image.
    """
    import docker

    client = docker.from_env()
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            client.images.get(image)
            return image
        except docker.errors.ImageNotFound:
            pass
        try:
            client.images.pull(image)
            return image
        except docker.errors.APIError as exc:  # noqa: PERF203 -- retry loop
            last = exc
            if "toomanyrequests" not in str(exc).lower() and "429" not in str(exc):
                raise
            time.sleep(2**attempt)
    raise RuntimeError(f"could not pull {image} after {attempts} attempts") from last


@pytest.fixture(scope="session")
def ssh_target_image() -> str:
    """The SSH target image, guaranteed present locally before any fixture
    that needs it calls `.start()`."""
    return pull_image_with_retry(SSH_TARGET_IMAGE)


@pytest.fixture(scope="module")
def _nats_docker_container():
    container = DockerContainer("nats:2.10-alpine").with_command("-js -m 8222").with_exposed_ports(4222, 8222)
    container.waiting_for(LogMessageWaitStrategy("Server is ready"))
    container.start()
    yield container
    container.stop()


@pytest.fixture(scope="module")
def nats_container(_nats_docker_container):
    host = _nats_docker_container.get_container_host_ip()
    port = _nats_docker_container.get_exposed_port(4222)
    return f"nats://{host}:{port}"


@pytest.fixture(scope="module")
def nats_monitoring_url(_nats_docker_container):
    host = _nats_docker_container.get_container_host_ip()
    port = _nats_docker_container.get_exposed_port(8222)
    return f"http://{host}:{port}/healthz"


@pytest_asyncio.fixture
async def nats_conn(nats_container: str):
    nc = await nats.connect(servers=nats_container)
    yield nc
    await nc.close()


@pytest_asyncio.fixture
async def mirage_streams(nats_container: str):
    """Provisions the real MIRAGE_* JetStream streams (the same
    ensure_streams() production code uses, via scripts/provision-nats-streams)
    onto the module's ephemeral NATS container. Any test whose app publishes
    to a subject owned by one of those streams (e.g. system.health,
    telemetry.sandbox.*, audit.*) needs this — JetStream returns "no
    responders" if no stream is bound to the subject yet."""
    from mirage_common.nats_client import connect, ensure_streams

    nc, js = await connect(nats_container)
    try:
        await ensure_streams(js, replicas_override=1)
    finally:
        await nc.close()


@pytest_asyncio.fixture
async def js(nats_conn):
    return nats_conn.jetstream()


@pytest_asyncio.fixture
async def test_stream(js):
    """A dedicated, wildcard-subject stream isolated from the production
    MIRAGE_* topology, so each test can mint its own unique subject
    (`test.<uuid>.*`) and get a truly clean DeliverPolicy=ALL history —
    binding a fresh durable consumer to a shared production subject would
    otherwise replay every earlier test's messages on that same subject.
    """
    from nats.js.api import RetentionPolicy, StreamConfig

    await js.add_stream(
        config=StreamConfig(
            name="TEST_MIRAGE_SPINE",
            subjects=["test.>"],
            retention=RetentionPolicy.LIMITS,
            max_age=3600.0,
            max_bytes=64 * 1024 * 1024,
            num_replicas=1,
            duplicate_window=120.0,
        )
    )
    return "TEST_MIRAGE_SPINE"


# ---------------------------------------------------------------------------
# Postgres — real container, migration 0001 applied directly (Step 3 tests
# don't need the full Stage 2 / Step 6 schema).
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def postgres_container():
    with PostgresContainer("postgres:16.4", username="mirage_test", password="mirage_test", dbname="mirage_test") as pg:
        yield pg


@pytest_asyncio.fixture
async def pg_conn(postgres_container: PostgresContainer):
    dsn = (
        f"host={postgres_container.get_container_host_ip()} "
        f"port={postgres_container.get_exposed_port(5432)} "
        f"user={postgres_container.username} password={postgres_container.password} "
        f"dbname={postgres_container.dbname}"
    )
    conn = await psycopg.AsyncConnection.connect(dsn)
    migration_sql = (REPO_ROOT / "infra" / "migrations" / "0001_agents_and_enrollment.up.sql").read_text()
    async with conn.cursor() as cur:
        await cur.execute("DROP TABLE IF EXISTS certificate_history, agents, enrollment_tokens, build_hash_allowlist CASCADE")
        await cur.execute(migration_sql)
    await conn.commit()
    yield conn
    await conn.close()


@pytest.fixture
def pg_dsn(postgres_container: PostgresContainer) -> str:
    return (
        f"host={postgres_container.get_container_host_ip()} "
        f"port={postgres_container.get_exposed_port(5432)} "
        f"user={postgres_container.username} password={postgres_container.password} "
        f"dbname={postgres_container.dbname}"
    )


# ---------------------------------------------------------------------------
# step-ca — real ephemeral container, provisioned with the five Mirage
# profiles via the SAME library (mirage_common.step_ca_admin) that
# scripts/bootstrap-step-ca-provisioners uses against the persistent dev
# container. Module-scoped: provisioning + restart takes a few seconds, so
# it is done once per test module, not per test.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def step_ca_container(tmp_path_factory):
    from mirage_common.step_ca_admin import add_provisioners, fetch_root_cert, has_step_cli

    if not has_step_cli():
        pytest.skip("step CLI not on PATH (brew install step) — required to provision test CA")

    container = (
        DockerContainer("smallstep/step-ca:0.27.4")
        .with_env("DOCKER_STEPCA_INIT_NAME", "Mirage Test CA")
        .with_env("DOCKER_STEPCA_INIT_DNS_NAMES", "localhost,step-ca-test")
        .with_env("DOCKER_STEPCA_INIT_PROVISIONER_NAME", "mirage-enrollment")
        .with_env("DOCKER_STEPCA_INIT_PASSWORD", "mirage_test_local_only")
        .with_exposed_ports(9000)
    )
    container.start()
    try:
        docker_name = container.get_wrapped_container().name

        host = container.get_container_host_ip()
        port = container.get_exposed_port(9000)
        _wait_for_step_ca_http(host, port)

        keys_dir = tmp_path_factory.mktemp("step-ca-keys")
        add_provisioners(docker_name, password="mirage_dev_local_only", keys_out_dir=keys_dir)

        # Restarting the container can remap the published port; re-resolve after restart.
        container.get_wrapped_container().reload()
        port = container.get_exposed_port(9000)
        _wait_for_step_ca_http(host, port)

        root_cert_path = keys_dir / "root_ca.crt"
        fetch_root_cert(docker_name, root_cert_path)

        yield {"ca_url": f"https://{host}:{port}", "root_cert_path": str(root_cert_path), "keys_dir": keys_dir}
    finally:
        # try/finally (not a bare post-yield call) so a TimeoutError from
        # either _wait_for_step_ca_http call above still stops the
        # container instead of leaking it — see KNOWN_ISSUES.md's Step 9b
        # fixture-leak entry (P12 honesty-audit remediation).
        container.stop()


@pytest.fixture
def ca_config(step_ca_container):
    from mirage_agent_ingestion.enrollment import CaConfig
    from mirage_agent_ingestion.provisioners import DevFileProvisionerSource

    return CaConfig(
        ca_url=step_ca_container["ca_url"],
        root_cert_path=step_ca_container["root_cert_path"],
        provisioners=DevFileProvisionerSource(keys_dir=step_ca_container["keys_dir"]),
    )


@pytest.fixture
def live_agent_ingestion_server(tmp_path, pg_conn, pg_dsn, ca_config, step_ca_container, nats_container, mirage_streams):
    """Runs the real mirage-agent-ingestion FastAPI app under a real uvicorn
    server, over real TLS (server cert issued by the SAME test step-ca,
    internal-control profile), on a real TCP port, in a background thread —
    the strongest available local proxy for "a test agent enrolls" without
    an actual Windows host. Shared by MirageEndpoint's and MirageSpider's
    E2E tests (Step 4 / Step 5), since both talk to the exact same server."""
    import asyncio
    import json as _json
    import threading
    import time as _time

    import httpx as _httpx
    import uvicorn
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from mirage_agent_ingestion.app import create_app

    from mirage_common.step_ca_client import (
        decrypt_provisioner_key,
        fetch_root_fingerprint,
        mint_enrollment_token,
        sign_csr,
    )

    keys_dir = step_ca_container["keys_dir"]
    pub = _json.loads((keys_dir / "mirage-internal-control.pub.json").read_text())
    priv_jwe = (keys_dir / "mirage-internal-control.priv.json").read_text()
    provisioner_key = decrypt_provisioner_key(priv_jwe, pub, "mirage_dev_local_only")
    root_fp = fetch_root_fingerprint(str(keys_dir / "root_ca.crt"))
    minted = mint_enrollment_token(
        provisioner_name="mirage-internal-control", provisioner_key=provisioner_key,
        subject="localhost", sans=["localhost"],
        ca_sign_url=f"{ca_config.ca_url}/1.0/sign", root_fingerprint=root_fp,
    )
    server_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(server_key, hashes.SHA256(), default_backend())
    )
    issued = sign_csr(
        ca_url=ca_config.ca_url, root_cert_path=ca_config.root_cert_path,
        csr_pem=server_csr.public_bytes(serialization.Encoding.PEM).decode(), token=minted.token,
    )
    server_cert_path = tmp_path / "server.crt"
    server_key_path = tmp_path / "server.key"
    server_cert_path.write_text(issued.certificate_chain_pem)
    server_key_path.write_bytes(
        server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )

    application = create_app(pg_dsn=pg_dsn, ca=ca_config, proxy_shared_secret="e2e-test-secret", nats_url=nats_container)
    port = 20000 + (hash(str(tmp_path)) % 5000)

    config = uvicorn.Config(
        application, host="127.0.0.1", port=port,
        ssl_certfile=str(server_cert_path), ssl_keyfile=str(server_key_path),
        log_level="warning",
    )
    server = uvicorn.Server(config)

    def run() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    deadline = _time.time() + 15
    while _time.time() < deadline:
        try:
            _httpx.get(f"https://localhost:{port}/openapi.json", verify=str(keys_dir / "root_ca.crt"), timeout=1)
            break
        except Exception:  # noqa: BLE001
            _time.sleep(0.3)
    else:
        raise TimeoutError("live agent-ingestion server did not start")

    yield {"base_url": f"https://localhost:{port}", "root_ca_path": str(keys_dir / "root_ca.crt")}
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
async def live_mirage_api_server(pg_dsn, nats_container, mirage_streams, elasticsearch_url):
    """Runs the real mirage-api FastAPI app under a real uvicorn server,
    plain HTTP, bound to 0.0.0.0 (not just 127.0.0.1) so real Docker
    containers (Step 8b/8c's HTTP/SSH broker containers) can reach it via
    `host.docker.internal` — mirage-api itself has no Dockerfile yet
    (containerizing every service is Task #17's job), so this is the
    strongest available local proxy for "the brokers call a real mirage-api"
    without that packaging work existing yet.
    """
    import asyncio
    import threading
    import time as _time

    import httpx as _httpx
    import uvicorn
    from mirage_api.app import create_app
    from mirage_api.health import HealthCheckConfig

    health_config = HealthCheckConfig(
        postgres_dsn=pg_dsn, nats_monitoring_url="http://127.0.0.1:1/healthz",
        elasticsearch_url=elasticsearch_url, keycloak_issuer_url="http://127.0.0.1:1",
        step_ca_url="https://127.0.0.1:1", step_ca_root_cert_path="/dev/null", agent_ingestion_url=None,
    )
    application = create_app(
        pg_dsn=pg_dsn, nats_url=nats_container, health_config=health_config,
        elasticsearch_url=elasticsearch_url, oidc_issuer_url="http://127.0.0.1:1/realms/unused",
        proxy_shared_secret="broker-test-proxy-secret",  # secret-scan: ignore (test-only placeholder)
    )
    port = 28000 + (hash(id(application)) % 4000)
    config = uvicorn.Config(application, host="0.0.0.0", port=port, log_level="warning")  # noqa: S104 -- test-only, containers must reach it via host.docker.internal
    server = uvicorn.Server(config)

    def run() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    deadline = _time.time() + 15
    while _time.time() < deadline:
        try:
            if _httpx.get(f"http://127.0.0.1:{port}/openapi.json", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            _time.sleep(0.3)
    else:
        raise TimeoutError("live mirage-api server did not start")

    yield {
        "base_url_host": f"http://127.0.0.1:{port}",
        "base_url_container": f"http://host.docker.internal:{port}",
        "proxy_shared_secret": "broker-test-proxy-secret",
    }
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
async def live_sandbox_gateway_server(pg_dsn, nats_container, mirage_streams, keycloak_realm):
    """Runs the real mirage-sandbox-gateway FastAPI app (Step 9b) under a
    real uvicorn server on a real TCP port — needed (unlike the ASGITransport
    in-process pattern Step 8a's HTTP-only tests use) because a real
    MirageEnvironmentController connects with a real `websockets` TCP
    client, not an in-process ASGI call."""
    import asyncio
    import threading
    import time as _time

    import httpx as _httpx
    import uvicorn
    from mirage_sandbox_gateway.app import create_app

    proxy_shared_secret = "sandbox-gateway-test-proxy-secret"  # secret-scan: ignore (test-only placeholder)
    application = create_app(
        pg_dsn=pg_dsn, nats_url=nats_container, oidc_issuer_url=keycloak_realm["issuer"],
        proxy_shared_secret=proxy_shared_secret, command_timeout_seconds=10.0,
    )
    port = 29000 + (hash(id(application)) % 3000)
    config = uvicorn.Config(application, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    def run() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    deadline = _time.time() + 15
    while _time.time() < deadline:
        try:
            if _httpx.get(f"http://127.0.0.1:{port}/health", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            _time.sleep(0.3)
    else:
        raise TimeoutError("live sandbox gateway server did not start")

    yield {
        "base_url": f"http://127.0.0.1:{port}",
        "ws_base_url": f"ws://127.0.0.1:{port}",
        "proxy_shared_secret": proxy_shared_secret,
    }
    server.should_exit = True
    thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Elasticsearch — real container, security disabled (matches
# infra/compose/docker-compose.development.yml's dev configuration).
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def elasticsearch_url():
    from testcontainers.community.elasticsearch import ElasticSearchContainer

    container = (
        ElasticSearchContainer(image="docker.elastic.co/elasticsearch/elasticsearch:8.15.0")
        .with_env("discovery.type", "single-node")
        .with_env("xpack.security.enabled", "false")
        .with_env("ES_JAVA_OPTS", "-Xms512m -Xmx512m")
        .with_exposed_ports(9200)
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(9200)
        url = f"http://{host}:{port}"

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                if httpx.get(f"{url}/_cluster/health", timeout=2).status_code == 200:
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
        else:
            raise TimeoutError("elasticsearch did not become healthy")

        yield url
    finally:
        # try/finally (not a bare post-yield call) so a TimeoutError from the
        # health-check loop above still stops the container instead of
        # leaking it — see KNOWN_ISSUES.md's Step 9b fixture-leak entry
        # (P12 honesty-audit remediation).
        container.stop()


# ---------------------------------------------------------------------------
# Keycloak — real ephemeral container, provisioned with the "mirage" realm
# (5 roles, 1 client, 5 dev users — one per role) via the SAME library
# (mirage_common.keycloak_admin) scripts/bootstrap-keycloak-realm uses
# against the persistent dev container.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keycloak_realm():
    from mirage_common.keycloak_admin import bootstrap_realm

    container = (
        DockerContainer("quay.io/keycloak/keycloak:25.0")
        .with_command("start-dev")
        .with_env("KEYCLOAK_ADMIN", "admin")
        .with_env("KEYCLOAK_ADMIN_PASSWORD", "mirage_test_local_only")
        .with_env("KC_PROXY_HEADERS", "xforwarded")
        .with_exposed_ports(8080)
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(8080)
        base_url = f"http://{host}:{port}"

        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                if (
                    httpx.get(
                        f"{base_url}/realms/master/.well-known/openid-configuration",
                        headers={"X-Forwarded-Proto": "https"},
                        timeout=2,
                    ).status_code
                    == 200
                ):
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
        else:
            raise TimeoutError("keycloak did not become healthy")

        bootstrap_realm(
            base_url,
            admin_user="admin",
            admin_password="mirage_test_local_only",
            dev_user_password="mirage_test_local_only",
            allow_http=True,
        )

        yield {"base_url": base_url, "issuer": f"{base_url}/realms/mirage", "dev_user_password": "mirage_test_local_only"}
    finally:
        # try/finally around the WHOLE setup (not just the health-check
        # branch this already had) — bootstrap_realm() itself could also
        # raise and previously would have leaked the container just the
        # same way the health-check timeout used to (P12 honesty-audit
        # remediation; see KNOWN_ISSUES.md's Step 9b fixture-leak entry).
        container.stop()


def _wait_for_step_ca_http(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            resp = httpx.get(f"https://{host}:{port}/health", verify=False, timeout=2.0)  # noqa: S501 -- bootstrapping trust, verified below
            if resp.status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
        time.sleep(0.5)
    raise TimeoutError(f"step-ca did not become healthy within {timeout}s: {last_exc}")
