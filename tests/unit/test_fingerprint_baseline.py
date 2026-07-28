"""Unit test for Step 7b's fingerprint baseline artifact — pure JSON Schema
validation, no Docker. Step 10's fingerprint gate harness is the thing that
runs actual comparisons against a baseline like this one; this test only
confirms the baseline this step ships is well-formed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
FINGERPRINT_DIR = REPO_ROOT / "infra" / "fingerprint"

EXPECTED_CHECKS = {
    "hostname_domain", "user_profiles_and_sids", "installed_software", "file_timestamps",
    "processes_services", "network", "uptime", "decoy_service_banners",
}


def _load(name: str) -> dict:
    return json.loads((FINGERPRINT_DIR / name).read_text())


def test_dev_sandbox_baseline_validates_against_the_schema():
    schema = _load("baseline.schema.json")
    baseline = _load("dev-sandbox-baseline.v1.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(baseline), key=lambda e: list(e.absolute_path))
    assert not errors, [e.message for e in errors]


def test_baseline_covers_every_spec_6_5_check():
    baseline = _load("dev-sandbox-baseline.v1.json")
    assert set(baseline["checks"]) == EXPECTED_CHECKS


def test_must_level_checks_match_spec_6_5_table():
    """§6.5: hostname/domain, user profiles, installed software, file
    timestamps, processes/services, and network are MUST; uptime and decoy
    banners are SHOULD."""
    baseline = _load("dev-sandbox-baseline.v1.json")
    must_checks = {
        "hostname_domain", "user_profiles_and_sids", "installed_software",
        "file_timestamps", "processes_services", "network",
    }
    should_checks = {"uptime", "decoy_service_banners"}
    for name in must_checks:
        assert baseline["checks"][name]["level"] == "MUST", name
    for name in should_checks:
        assert baseline["checks"][name]["level"] == "SHOULD", name


def test_forbidden_process_patterns_include_mirage_and_spider():
    baseline = _load("dev-sandbox-baseline.v1.json")
    forbidden = baseline["checks"]["processes_services"]["expected"]["forbidden_patterns"]
    assert "Mirage*" in forbidden
    assert "Spider*" in forbidden
