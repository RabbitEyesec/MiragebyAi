"""Static validation of the Compose split (Priority 9): development,
production, and test files. These call `docker compose config` — real
static resolution/validation, no containers started, the same category of
check as `terraform validate`/`fmt` in test_terraform_network_policy.py —
so they run everywhere Docker is installed without needing the dev stack up.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "infra" / "compose"
PRODUCTION_FILE = COMPOSE_DIR / "docker-compose.production.yml"
DEVELOPMENT_FILE = COMPOSE_DIR / "docker-compose.development.yml"
TEST_FILE = COMPOSE_DIR / "docker-compose.test.yml"

REQUIRED_PRODUCTION_ENV = {
    "MIRAGE_POSTGRES_USER": "x",
    "MIRAGE_POSTGRES_PASSWORD": "x",
    "MIRAGE_POSTGRES_DB": "x",
    "MIRAGE_PROXY_SHARED_SECRET": "x",
    "MIRAGE_ELASTIC_PASSWORD": "x",
    "MIRAGE_KEYCLOAK_ADMIN_USER": "x",
    "MIRAGE_KEYCLOAK_ADMIN_PASSWORD": "x",
    "MIRAGE_KEYCLOAK_PUBLIC_URL": "https://keycloak.example.com",
    "MIRAGE_KEYCLOAK_INTERNAL_ISSUER_URL": "https://keycloak.internal.example.com",
    "MIRAGE_API_IMAGE": "registry.example.com/mirage-api@sha256:" + "a" * 64,
    "MIRAGE_DASHBOARD_IMAGE": "registry.example.com/mirage-dashboard@sha256:" + "a" * 64,
    "MIRAGE_AGENT_INGESTION_IMAGE": "registry.example.com/mirage-agent-ingestion@sha256:" + "a" * 64,
    "MIRAGE_SANDBOX_GATEWAY_IMAGE": "registry.example.com/mirage-sandbox-gateway@sha256:" + "a" * 64,
    "MIRAGE_WORKER_IMAGE": "registry.example.com/mirage-worker@sha256:" + "a" * 64,
    "MIRAGE_ARTIFACT_SCANNER_IMAGE": "registry.example.com/mirage-artifact-scanner@sha256:" + "a" * 64,
    "MIRAGE_REPORT_WORKER_IMAGE": "registry.example.com/mirage-report-worker@sha256:" + "a" * 64,
    "MIRAGE_OUTBOX_RELAY_IMAGE": "registry.example.com/mirage-outbox-relay@sha256:" + "a" * 64,
    "MIRAGE_EVIDENCE_BUCKET": "x",
    "MIRAGE_EVIDENCE_REGION": "us-east-1",
    "MIRAGE_EVIDENCE_ENDPOINT_URL": "https://s3.us-east-1.amazonaws.com",
    "MIRAGE_EVIDENCE_RETENTION_DAYS": "365",
    "MIRAGE_KMS_SIGNING_KEY_ARN": "arn:aws:kms:us-east-1:123456789012:key/x",
    "MIRAGE_CANARY_INGESTION_HMAC": "x",
    "MIRAGE_OIDC_CLIENT_SECRET": "x",
    "MIRAGE_DASHBOARD_PUBLIC_URL": "https://dashboard.example.com",
    "MIRAGE_SESSION_SECRET": "x" * 32,
    "MIRAGE_EXPORT_SIGNER": "arn:aws:kms:us-east-1:123456789012:key/export",
}


def _write_env_file(path: Path, values: dict[str, str]) -> None:
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")


def _compose_config(compose_files: list[Path], env_file: Path | None) -> dict:
    command = ["docker", "compose"]
    if env_file is not None:
        command += ["--env-file", str(env_file)]
    for compose_file in compose_files:
        command += ["-f", str(compose_file)]
    command += ["config", "--format", "json"]
    result = subprocess.run(command, capture_output=True, text=True, cwd=ROOT, check=False)
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def test_production_compose_fails_closed_with_no_secrets_configured():
    result = _compose_config([PRODUCTION_FILE], env_file=None)
    assert result["returncode"] != 0
    assert "required variable" in result["stderr"] or "is missing a value" in result["stderr"]


def test_production_compose_resolves_cleanly_with_real_looking_values(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = _compose_config([PRODUCTION_FILE], env_file)
    assert result["returncode"] == 0, result["stderr"]
    config = json.loads(result["stdout"])
    assert "mirage-api" in config["services"]


def test_production_compose_has_no_build_context_and_no_minio(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = _compose_config([PRODUCTION_FILE], env_file)
    config = json.loads(result["stdout"])
    for name, service in config["services"].items():
        assert "build" not in service, f"{name} must deploy a pinned image digest, not build from source"
        assert "minio" not in service.get("image", ""), f"{name} must not use MinIO in production"


def test_production_compose_keycloak_never_runs_start_dev(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = _compose_config([PRODUCTION_FILE], env_file)
    config = json.loads(result["stdout"])
    command = config["services"]["keycloak"].get("command", [])
    assert "start-dev" not in command


def test_production_compose_step_ca_has_no_auto_init_variables(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = _compose_config([PRODUCTION_FILE], env_file)
    config = json.loads(result["stdout"])
    env = config["services"]["step-ca"].get("environment", {})
    assert not any(key.startswith("DOCKER_STEPCA_INIT_") for key in env)


def test_production_compose_ports_are_loopback_only(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = _compose_config([PRODUCTION_FILE], env_file)
    config = json.loads(result["stdout"])
    for name, service in config["services"].items():
        for port in service.get("ports", []):
            if isinstance(port, dict):
                assert port.get("host_ip") in ("127.0.0.1", "::1"), f"{name} publishes a non-loopback port"


def test_production_compose_app_services_are_hardened(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = _compose_config([PRODUCTION_FILE], env_file)
    config = json.loads(result["stdout"])
    app_services = [
        "mirage-api", "mirage-dashboard", "mirage-agent-ingestion", "mirage-sandbox-gateway",
        "mirage-worker", "mirage-artifact-scanner", "mirage-report-worker", "mirage-outbox-relay",
    ]
    for name in app_services:
        service = config["services"][name]
        assert service.get("read_only") is True, f"{name} must run with a read-only root filesystem"
        assert service.get("cap_drop") == ["ALL"], f"{name} must drop all Linux capabilities"
        assert "no-new-privileges:true" in service.get("security_opt", []), f"{name} must set no-new-privileges"


def test_development_and_test_compose_merge_cleanly_with_ephemeral_state(tmp_path: Path):
    """docker-compose.test.yml is an override, not a duplicate — see its own
    file header for why. This proves the merge actually produces the
    intended ephemeral, fail-fast shape."""
    env_file = tmp_path / "test.env"
    _write_env_file(
        env_file,
        {
            "MIRAGE_PROXY_SHARED_SECRET": "x",
            "MIRAGE_SESSION_SECRET": "x" * 32,
        },
    )
    result = _compose_config([DEVELOPMENT_FILE, TEST_FILE], env_file)
    assert result["returncode"] == 0, result["stderr"]
    config = json.loads(result["stdout"])
    assert config["name"] == "mirage-test"
    postgres = config["services"]["postgres"]
    assert postgres.get("restart") == "no"
    assert postgres.get("tmpfs") == ["/var/lib/postgresql/data"]
    assert not postgres.get("volumes")
    assert config["services"]["mirage-api"]["environment"]["MIRAGE_ENV"] == "test"


def test_guard_script_rejects_a_leaked_development_value(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    tampered = {**REQUIRED_PRODUCTION_ENV, "MIRAGE_POSTGRES_PASSWORD": "mirage_dev_local_only"}
    _write_env_file(env_file, tampered)
    result = subprocess.run(
        ["python3", "scripts/validate-production-compose", "--env-file", str(env_file)],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )
    assert result.returncode == 1
    assert "development-only value" in result.stderr


def test_guard_script_passes_with_clean_values(tmp_path: Path):
    env_file = tmp_path / "prod.env"
    _write_env_file(env_file, REQUIRED_PRODUCTION_ENV)
    result = subprocess.run(
        ["python3", "scripts/validate-production-compose", "--env-file", str(env_file)],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )
    assert result.returncode == 0, result.stderr
