"""Unit tests for the fingerprint gate's pure Python surface
(libs/mirage_common/fingerprint_gate.py) — no database. The Postgres-backed
evaluate/transition logic requires a real connection and is covered in
tests/integration/test_fingerprint_gate.py.
"""
from __future__ import annotations

import pytest

from mirage_common.fingerprint import CheckResult, FingerprintReport
from mirage_common.fingerprint_gate import GATED_TRANSITION, FingerprintGateBlockedError

pytestmark = pytest.mark.unit


def test_gated_transition_is_sandbox_active_to_engaging():
    """Step 10's own Done-when line names this exact transition."""
    assert GATED_TRANSITION == ("SANDBOX_ACTIVE", "ENGAGING")


def _report(*, all_must_passed: bool, failed_names: list[str]) -> FingerprintReport:
    results = [
        CheckResult(
            check_name=name, comparator="exact", level="MUST", expected={}, observed={},
            passed=(name not in failed_names), evidence="test",
        )
        for name in ["hostname_domain", "processes_services", *failed_names]
    ]
    return FingerprintReport(target_id="t1", baseline_version="1.0.0", results=results)


def test_blocked_error_message_includes_failed_must_check_names():
    report = _report(all_must_passed=False, failed_names=["processes_services"])
    err = FingerprintGateBlockedError("01ARZ3NDEKTSV4RRFFQ69G5FAV", report)
    assert "processes_services" in str(err)
    assert "01ARZ3NDEKTSV4RRFFQ69G5FAV" in str(err)
    assert err.case_id == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    assert err.report is report


def test_blocked_error_with_no_failed_must_checks_still_constructs():
    """Defensive: even if somehow constructed with an all-MUST-passed
    report (shouldn't happen in practice — the gate only raises this when
    evaluation.passed is False), the error must not itself crash."""
    report = _report(all_must_passed=True, failed_names=[])
    err = FingerprintGateBlockedError("01ARZ3NDEKTSV4RRFFQ69G5FAV", report)
    assert "failed_must_checks=[]" in str(err)
