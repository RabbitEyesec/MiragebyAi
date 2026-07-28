from __future__ import annotations

from pathlib import Path

import pytest

from mirage_common.teardown import (
    TEARDOWN_STEPS,
    CloudResource,
    EvidenceGapOverride,
    LocalCloudAdapter,
    TeardownBlocked,
    TeardownWorkflow,
)

CASE = "01J00000000000000000000000"


def _resources() -> list[CloudResource]:
    return [
        CloudResource("sandbox-1", "mirage", "test", CASE, "sandbox"),
        CloudResource("compute-1", "mirage", "test", CASE, "compute"),
        CloudResource("volume-1", "mirage", "test", CASE, "volume"),
        CloudResource("credential-1", "mirage", "test", CASE, "credential"),
        CloudResource("token-1", "mirage", "test", CASE, "token"),
        CloudResource("endpoint-1", "mirage", "test", CASE, "public_endpoint"),
        CloudResource(
            "evidence-1",
            "mirage",
            "test",
            CASE,
            "evidence",
            temporary=False,
            protected_evidence=True,
        ),
        CloudResource("other-case", "mirage", "test", "other", "compute"),
        CloudResource("other-project", "not-mirage", "test", CASE, "compute"),
    ]


def _workflow(tmp_path: Path, adapter: LocalCloudAdapter, **kwargs) -> TeardownWorkflow:
    return TeardownWorkflow(
        adapter=adapter,
        environment="test",
        case_id=CASE,
        journal=tmp_path / "teardown-journal.json",
        **kwargs,
    )


def test_dry_run_is_exact_filtered_and_orders_all_25_steps(tmp_path: Path) -> None:
    workflow = _workflow(tmp_path, LocalCloudAdapter(_resources()))
    plan = workflow.plan()
    assert plan["project"] == "mirage"
    assert plan["environment"] == "test"
    assert plan["case_id"] == CASE
    assert [item["step"] for item in plan["steps"]] == list(TEARDOWN_STEPS)
    assert len(plan["steps"]) == 25
    assert [item["resource_id"] for item in plan["protected_resources"]] == ["evidence-1"]
    assert all(item["case_id"] == CASE for item in plan["temporary_resources"])


def test_teardown_preserves_evidence_revokes_identity_and_leaves_zero_temp(
    tmp_path: Path,
) -> None:
    adapter = LocalCloudAdapter(_resources())
    workflow = _workflow(tmp_path, adapter)
    result = workflow.execute(confirmation=f"mirage:test:{CASE}")
    assert [entry["step"] for entry in result["entries"]] == list(TEARDOWN_STEPS)
    assert result["state"]["case_state"] == "DESTROYED"
    assert not workflow.identity_can_reconnect("sandbox-cert")
    assert not workflow.identity_can_reconnect("agent-cert")
    remaining = adapter.inventory(project="mirage", environment="test", case_id=CASE)
    assert [item.resource_id for item in remaining] == ["evidence-1"]
    second = workflow.execute(confirmation=f"mirage:test:{CASE}")
    assert len(second["entries"]) == 25


def test_teardown_blocks_before_destruction_on_unverified_evidence(
    tmp_path: Path,
) -> None:
    adapter = LocalCloudAdapter(_resources())
    workflow = _workflow(tmp_path, adapter, required_evidence_verified=False)
    with pytest.raises(TeardownBlocked, match="required evidence is not VERIFIED"):
        workflow.execute(confirmation=f"mirage:test:{CASE}")
    assert adapter.resources["sandbox-1"].active


def test_authorised_gap_override_is_audited_and_prominent(tmp_path: Path) -> None:
    override = EvidenceGapOverride(
        reason="sensor failed during controlled outage",
        missing_items=("event-sequence-50",),
        actor="lead-analyst",
        policy_decision_id="01J00000000000000000000001",
        policy_allows=True,
    )
    workflow = _workflow(
        tmp_path,
        LocalCloudAdapter(_resources()),
        required_evidence_verified=False,
        override=override,
    )
    result = workflow.execute(confirmation=f"mirage:test:{CASE}")
    override_audit = next(
        item for item in result["state"]["audit"] if item["action"] == "evidence_gap_override"
    )
    assert override_audit["reason"] == override.reason
    assert override_audit["missing_items"] == list(override.missing_items)


@pytest.mark.parametrize(
    ("flag", "message"),
    [
        ("queue_drain_succeeds", "queue drain failed"),
        ("final_snapshot_succeeds", "final snapshot failed"),
        ("export_verified", "independent export verification failed"),
        ("certificate_revocation_succeeds", "certificate revocation failed"),
        ("inventory_complete", "resource inventory is incomplete"),
    ],
)
def test_mandatory_failure_blocks(flag: str, message: str, tmp_path: Path) -> None:
    with pytest.raises(TeardownBlocked, match=message):
        _workflow(tmp_path, LocalCloudAdapter(_resources()), **{flag: False}).execute(
            confirmation=f"mirage:test:{CASE}"
        )


def test_interrupted_teardown_resumes_idempotently(tmp_path: Path) -> None:
    adapter = LocalCloudAdapter(_resources(), fail_once_at="capture_final_snapshot")
    workflow = _workflow(tmp_path, adapter)
    with pytest.raises(TeardownBlocked, match="injected interruption"):
        workflow.execute(confirmation=f"mirage:test:{CASE}")
    resumed = _workflow(tmp_path, adapter)
    result = resumed.execute(confirmation=f"mirage:test:{CASE}")
    passed = [entry for entry in result["entries"] if entry["result"] == "PASS"]
    assert len({entry["step"] for entry in passed}) == 25
    assert result["state"]["case_state"] == "DESTROYED"


def test_broad_or_wrong_confirmation_is_refused(tmp_path: Path) -> None:
    workflow = _workflow(tmp_path, LocalCloudAdapter(_resources()))
    with pytest.raises(ValueError, match=f"mirage:test:{CASE}"):
        workflow.execute(confirmation="mirage:test")
    with pytest.raises(ValueError, match="exact Project=mirage"):
        workflow.adapter.inventory(project="*", environment="test", case_id=None)
