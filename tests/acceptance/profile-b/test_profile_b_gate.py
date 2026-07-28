from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from mirage_common.acceptance import (
    NUMERIC_REQUIREMENTS,
    PROFILE_B_REQUIREMENTS,
    SCENARIO_STEPS,
    acceptance_specification,
    package_profile_b_result,
    verify_acceptance_package,
)


def _passing_measurement(requirement_id: str):
    return {
        "NUM-01": 2.5,
        "NUM-02": 1.5,
        "NUM-03": 15,
        "NUM-04": 0,
        "NUM-05": 0,
        "NUM-06": 1000,
        "NUM-07": 10,
        "NUM-08": 16384,
        "NUM-09": 4000,
        "NUM-10": True,
        "NUM-11": 250,
        "NUM-12": 29,
        "NUM-13": 100,
        "NUM-14": 20,
        "NUM-15": 2.5,
        "NUM-16": 9,
        "NUM-17": 59,
        "NUM-18": 30,
        "NUM-19": 90,
        "NUM-20": {"messages_threshold": 10000, "seconds_threshold": 30},
        "NUM-21": 100,
        "NUM-22": 0,
        "NUM-23": 0,
        "NUM-24": 0,
        "NUM-25": 0,
    }[requirement_id]


def test_profile_b_plan_requires_real_external_systems_and_two_runs() -> None:
    value = acceptance_specification()
    assert tuple(value["profile_b_required_environment"]) == PROFILE_B_REQUIREMENTS
    assert "twice" in value["repeat_rule"]
    assert "clean teardown" in value["repeat_rule"]


def test_one_complete_profile_b_run_is_signed_but_cannot_be_accepted(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw"
    output = tmp_path / "packaged"
    raw.mkdir()
    evidence = raw / "evidence"
    evidence.mkdir()
    (evidence / "controlled-measurement.json").write_text('{"source":"profile-b"}\n')
    started = "2026-07-27T00:00:00Z"
    ended = "2026-07-27T00:30:00Z"
    numeric = [
        {
            "requirement_id": requirement.requirement_id,
            "description": requirement.description,
            "target": requirement.target,
            "measured_value": _passing_measurement(requirement.requirement_id),
            "unit": requirement.unit,
            "environment": "Profile B AWS/Windows lab",
            "profile": "PROFILE_B",
            "start_time": started,
            "end_time": ended,
            "evidence": ["evidence/controlled-measurement.json"],
            "result": "PASS",
            "limitation": "",
        }
        for requirement in NUMERIC_REQUIREMENTS
    ]
    scenario = [
        {
            "step": step,
            "description": description,
            "environment": "Profile B AWS/Windows lab",
            "profile": "PROFILE_B",
            "start_time": started,
            "end_time": ended,
            "evidence": ["evidence/controlled-measurement.json"],
            "result": "PASS",
            "limitation": "",
        }
        for step, description in enumerate(SCENARIO_STEPS, start=1)
    ]
    (raw / "acceptance-results.json").write_text(
        json.dumps(
            {
                "profile": "PROFILE_B",
                "numeric_results": numeric,
                "scenario_results": scenario,
            }
        )
    )
    for name in (
        "environment-inventory.json",
        "performance-results.json",
        "failure-results.json",
        "security-results.json",
        "load-results.json",
        "installer-results.json",
        "teardown-results.json",
    ):
        (raw / name).write_text("{}\n")
    (raw / "test-command-log.txt").write_text("controlled Profile B command log\n")
    result = package_profile_b_result(raw, output)
    assert result["result"] == "PASS"
    assert result["accepted"] is False
    assert result["profile_b_status"] == "RUN_PASSED_ONCE_SECOND_CLEAN_RUN_REQUIRED"
    # Independent re-verification requires an externally-sourced trusted key —
    # simulate an operator who received the signer key out of band, rather
    # than trusting whatever key happens to be embedded in the package.
    with zipfile.ZipFile(output / "acceptance-package.zip") as archive:
        trusted_key = archive.read("acceptance-public-key.pem")
    verification = verify_acceptance_package(
        output / "acceptance-package.zip", public_key=trusted_key
    )
    assert verification["valid"], verification["errors"]
    assert not verify_acceptance_package(output / "acceptance-package.zip")["valid"]
    with zipfile.ZipFile(output / "acceptance-package.zip") as archive:
        assert "evidence/controlled-measurement.json" in archive.namelist()
    numeric[0]["measured_value"] = 3
    (raw / "acceptance-results.json").write_text(
        json.dumps(
            {
                "profile": "PROFILE_B",
                "numeric_results": numeric,
                "scenario_results": scenario,
            }
        )
    )
    with pytest.raises(ValueError, match="does not satisfy target"):
        package_profile_b_result(raw, tmp_path / "invalid")
