from __future__ import annotations

import json
import zipfile
from pathlib import Path

from mirage_common.acceptance import (
    LOCAL_SUBSTITUTIONS,
    NUMERIC_REQUIREMENTS,
    SCENARIO_STEPS,
    acceptance_specification,
    run_local_acceptance,
    verify_acceptance_package,
)

ROOT = Path(__file__).resolve().parents[3]


def test_machine_readable_spec_is_complete_and_uses_no_implicit_pass() -> None:
    fixture = json.loads(
        (ROOT / "tests/acceptance/fixtures/acceptance-spec.json").read_text()
    )
    specification = acceptance_specification()
    assert len(NUMERIC_REQUIREMENTS) == 25
    assert len(SCENARIO_STEPS) == 36
    assert [item["requirement_id"] for item in specification["numeric_targets"]] == fixture[
        "numeric_target_ids"
    ]
    assert specification["allowed_results"] == ["PASS", "FAIL", "NOT_RUN", "BLOCKED"]
    assert len(LOCAL_SUBSTITUTIONS) == 9


def test_local_stage_0_12_acceptance_produces_signed_verifiable_outputs(
    tmp_path: Path,
) -> None:
    result = run_local_acceptance(tmp_path)
    assert result["result"] == "PASS"
    assert result["accepted"] is False
    assert result["profile_b_status"] == "LAB_VERIFICATION_REQUIRED"
    assert len(result["scenario_results"]) == 36
    assert all(item["result"] == "PASS" for item in result["scenario_results"])
    assert len(result["numeric_results"]) == 25
    assert any(item["result"] == "NOT_RUN" for item in result["numeric_results"])
    assert len(result["profile_b_results"]) == 25
    assert all(item["result"] == "NOT_RUN" for item in result["profile_b_results"])
    assert [item["step"] for item in result["profile_b_scenario_results"]] == list(
        range(1, 37)
    )
    assert all(
        item["result"] == "NOT_RUN"
        for item in result["profile_b_scenario_results"]
    )
    assert result["independent_verification"]["valid"] is True
    required = {
        "acceptance-results.json",
        "acceptance-results.html",
        "acceptance-results.pdf",
        "acceptance-results.docx",
        "test-command-log.txt",
        "environment-inventory.json",
        "performance-results.json",
        "failure-results.json",
        "security-results.json",
        "load-results.json",
        "installer-results.json",
        "teardown-results.json",
        "acceptance-manifest.json",
        "acceptance-manifest.sig",
        "acceptance-public-key.pem",
        "acceptance-package.zip",
        "independent-verification-report.json",
    }
    assert required.issubset({path.name for path in tmp_path.iterdir()})


def test_independent_verifier_rejects_tampering(tmp_path: Path) -> None:
    run_local_acceptance(tmp_path)
    package = tmp_path / "acceptance-package.zip"
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tampered, "w") as target:
        for info in source.infolist():
            content = source.read(info.filename)
            if info.filename == "security-results.json":
                content += b"tampered"
            target.writestr(info, content)
    result = verify_acceptance_package(tampered)
    assert result["valid"] is False
    assert "hash mismatch: security-results.json" in result["errors"]
