from __future__ import annotations

import json
from pathlib import Path

import pytest

from mirage_common.resilience import (
    SCENARIOS,
    run_local_scenario,
    run_profile_b_scenario,
)


def test_all_thirteen_failure_scenarios_have_complete_executable_definitions() -> None:
    assert [item.test_id for item in SCENARIOS] == [
        f"FAIL-{index:02d}" for index in range(1, 14)
    ]
    for item in SCENARIOS:
        assert item.preconditions
        assert item.trigger
        assert item.detection_mechanism
        assert item.expected_alert
        assert item.expected_safe_state
        assert item.expected_data_behaviour
        assert item.recovery_procedure
        assert item.lab_command.startswith("scripts/run-failure-scenario")


@pytest.mark.parametrize(
    "test_id",
    [item.test_id for item in SCENARIOS if item.locally_executable],
)
def test_local_fault_recovery_has_no_loss_or_duplicate_effective_state(
    test_id: str,
) -> None:
    result = run_local_scenario(test_id)
    assert result["result"] == "PASS", result
    assert result["missing_event_count"] == 0
    assert result["duplicate_count"] == 0


@pytest.mark.parametrize(
    "test_id",
    [item.test_id for item in SCENARIOS if not item.locally_executable],
)
def test_lab_fault_has_exact_non_successful_execution_gate(test_id: str) -> None:
    result = run_local_scenario(test_id)
    assert result["result"] == "NOT_RUN"
    assert "Execute:" in result["limitation"]


def test_profile_b_runner_requires_confirmation_and_executes_recovery(
    tmp_path: Path,
) -> None:
    recipe = tmp_path / "recipe.json"
    recipe.write_text(
        json.dumps(
            {
                "schema_version": "mirage.failure-recipe/1.0",
                "scenarios": {
                    "FAIL-01": {
                        stage: {
                            "argv": ["/usr/bin/true"],
                            "expected_exit_codes": [0],
                            "timeout_seconds": 2,
                        }
                        for stage in ("precheck", "trigger", "detect", "recover", "verify")
                    }
                },
            }
        )
    )
    with pytest.raises(ValueError, match="FAULT FAIL-01 PROFILE_B"):
        run_profile_b_scenario("FAIL-01", recipe_path=recipe, confirmation="wrong")
    result = run_profile_b_scenario(
        "FAIL-01",
        recipe_path=recipe,
        confirmation="FAULT FAIL-01 PROFILE_B",
    )
    assert result["result"] == "PASS"
    assert [item["stage"] for item in result["commands"]] == [
        "precheck",
        "trigger",
        "detect",
        "recover",
        "verify",
    ]
