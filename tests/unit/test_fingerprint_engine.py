"""Unit tests for the §6.5 fingerprint comparator engine
(libs/mirage_common/fingerprint.py) — pure Python, no Docker, no OS access.
Uses the real Step 7b baseline (infra/fingerprint/dev-sandbox-baseline.v1.json)
so these tests exercise the exact same data shape Step 9a/10 will feed it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mirage_common.fingerprint import run_fingerprint_check

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE = json.loads((REPO_ROOT / "infra" / "fingerprint" / "dev-sandbox-baseline.v1.json").read_text())


def _fully_passing_observation() -> dict:
    checks = BASELINE["checks"]
    return {
        "hostname_domain": {"hostname": "SANDBOX-DEV01", "domain": "mirage.local"},
        "user_profiles_and_sids": {"profiles": ["mirage.local\\employee01"]},
        "installed_software": {"installed": [*checks["installed_software"]["expected"]["required"], "KB5001234", "some other app"]},
        "file_timestamps": {"files_predating_hire_date": []},
        "processes_services": {"running": ["explorer.exe", "svchost.exe", "MirageSpider", "MirageEnvironmentController"]},
        "network": {"mac_oui": "00:1A:2B", "dns_servers": ["10.0.20.2"], "domain": "mirage.local"},
        "uptime": {"value": 48},
        "decoy_service_banners": {"http_server_header": "Microsoft-IIS/10.0", "ssh_banner": "SSH-2.0-OpenSSH_for_Windows_8.1"},
    }


def test_fully_passing_observation_passes_overall():
    report = run_fingerprint_check(BASELINE, _fully_passing_observation())
    assert report.all_must_passed
    assert report.should_pass_ratio == 1.0
    assert report.passed is True
    assert len(report.results) == 8


def test_missing_observation_fails_that_check():
    observed = _fully_passing_observation()
    del observed["hostname_domain"]
    report = run_fingerprint_check(BASELINE, observed)
    hostname_result = next(r for r in report.results if r.check_name == "hostname_domain")
    assert hostname_result.passed is False
    assert hostname_result.evidence == "no observation collected"
    assert report.passed is False


def test_forbidden_process_pattern_fails_hard():
    """§6.5: 'Immediate failure on any visible Mirage-named process/service.'"""
    observed = _fully_passing_observation()
    observed["processes_services"] = {"running": ["explorer.exe", "MirageSuspiciousThing"]}
    report = run_fingerprint_check(BASELINE, observed)
    proc_result = next(r for r in report.results if r.check_name == "processes_services")
    assert proc_result.passed is False
    assert "MirageSuspiciousThing" in proc_result.evidence
    assert report.passed is False  # a MUST-level failure fails the whole report


def test_a_legitimate_process_not_in_allowed_set_does_not_fail_alone():
    """allowed_set is informational context — only forbidden_patterns is a
    hard gate (see fingerprint.py's own comparator docstring)."""
    observed = _fully_passing_observation()
    observed["processes_services"] = {"running": ["explorer.exe", "some_legit_unlisted_process.exe"]}
    report = run_fingerprint_check(BASELINE, observed)
    proc_result = next(r for r in report.results if r.check_name == "processes_services")
    assert proc_result.passed is True


def test_file_predating_hire_date_fails():
    observed = _fully_passing_observation()
    observed["file_timestamps"] = {"files_predating_hire_date": ["C:\\old_file.txt"]}
    report = run_fingerprint_check(BASELINE, observed)
    ts_result = next(r for r in report.results if r.check_name == "file_timestamps")
    assert ts_result.passed is False
    assert report.passed is False


def test_missing_required_software_fails():
    observed = _fully_passing_observation()
    observed["installed_software"] = {"installed": ["Sysmon"]}  # missing Elastic Agent, MirageSpider, ...
    report = run_fingerprint_check(BASELINE, observed)
    sw_result = next(r for r in report.results if r.check_name == "installed_software")
    assert sw_result.passed is False
    assert "Elastic Agent" in sw_result.evidence
    assert report.passed is False


def test_should_level_failure_alone_does_not_fail_the_report_above_threshold():
    """§6.5: 'MUST 100%, SHOULD >= 75%.' Only 2 SHOULD checks exist in this
    baseline (uptime, decoy_service_banners) — failing just one gives a 50%
    SHOULD pass ratio, which is BELOW the 75% threshold, so the overall
    report correctly still fails; this test asserts that specific boundary,
    not a false claim that any single SHOULD failure is always tolerated."""
    observed = _fully_passing_observation()
    observed["uptime"] = {"value": 2}  # below min_hours=4
    report = run_fingerprint_check(BASELINE, observed)
    assert report.all_must_passed is True
    assert report.should_pass_ratio == 0.5
    assert report.passed is False  # 50% < 75% threshold


def test_decoy_banner_mismatch_is_should_level_not_must():
    observed = _fully_passing_observation()
    observed["decoy_service_banners"] = {"http_server_header": "nginx/1.0", "ssh_banner": "wrong"}
    report = run_fingerprint_check(BASELINE, observed)
    banner_result = next(r for r in report.results if r.check_name == "decoy_service_banners")
    assert banner_result.level == "SHOULD"
    assert banner_result.passed is False
    assert report.all_must_passed is True  # MUST checks are unaffected
