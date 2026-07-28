"""Unit tests for the Bootstrap Gate configuration schema and validate-config.

Run: pytest tests/unit/test_config_schema.py -m unit
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "config" / "schema.json"
VALIDATE_CONFIG = REPO_ROOT / "scripts" / "validate-config"

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.mark.parametrize(
    "example_file",
    [
        "config/development.example.yaml",
        "config/acceptance.example.yaml",
        "config/production.example.yaml",
    ],
)
def test_example_configs_validate_against_schema(schema: dict, example_file: str) -> None:
    data = yaml.safe_load((REPO_ROOT / example_file).read_text())
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(data))
    assert not errors, f"{example_file} failed schema validation: {[e.message for e in errors]}"


def test_schema_rejects_missing_mandatory_section(schema: dict) -> None:
    data = yaml.safe_load((REPO_ROOT / "config/development.example.yaml").read_text())
    del data["postgres"]
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(data))
    assert any("postgres" in e.message for e in errors)


def test_schema_rejects_unknown_top_level_field(schema: dict) -> None:
    data = yaml.safe_load((REPO_ROOT / "config/development.example.yaml").read_text())
    data["totally_unknown_field"] = "should not be allowed"
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(data))
    assert errors, "unknown top-level field must be rejected (additionalProperties: false)"


def test_schema_rejects_malformed_cidr(schema: dict) -> None:
    data = yaml.safe_load((REPO_ROOT / "config/development.example.yaml").read_text())
    data["network"]["vpc_cidr"] = "not-a-cidr"
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(data))
    assert errors


def test_acceptance_requires_secrets_manager_sourced_credentials(schema: dict) -> None:
    """Outside development, credentials_source must be secrets_manager, never env."""
    data = yaml.safe_load((REPO_ROOT / "config/acceptance.example.yaml").read_text())
    data["postgres"]["credentials_source"] = "env"
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(data))
    assert errors, "acceptance config with env-sourced postgres credentials must fail validation"


def _run_validate_config(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATE_CONFIG), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_accepts_valid_development_config() -> None:
    result = _run_validate_config("config/development.example.yaml")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VALID" in result.stdout


def test_cli_rejects_missing_file() -> None:
    result = _run_validate_config("config/does-not-exist.yaml")
    assert result.returncode != 0
    assert "not found" in result.stdout.lower()


def test_cli_strict_mode_rejects_placeholders() -> None:
    result = _run_validate_config("config/acceptance.example.yaml", "--strict")
    assert result.returncode != 0
    assert "placeholder" in result.stdout.lower()


def test_cli_non_strict_mode_allows_placeholders_in_example_file() -> None:
    result = _run_validate_config("config/acceptance.example.yaml")
    assert result.returncode == 0, result.stdout + result.stderr


def test_cli_scan_secrets_passes_on_clean_tree() -> None:
    result = _run_validate_config("--scan-secrets")
    assert result.returncode == 0, result.stdout + result.stderr


def test_cli_scan_secrets_detects_planted_secret(tmp_path: Path) -> None:
    probe = REPO_ROOT / "tests" / "unit" / "_scratch_secret_probe.yaml"
    probe.write_text('aws_access_key_id: "AKIAABCDEFGHIJKLMNOP"\n')  # secret-scan: ignore (test fixture) gitleaks:allow
    try:
        result = _run_validate_config("--scan-secrets")
        assert result.returncode != 0
        assert "AKIA" in result.stdout or "aws access key" in result.stdout.lower()
    finally:
        probe.unlink()
