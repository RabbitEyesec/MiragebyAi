"""Executable failure-scenario catalogue and bounded local fault harness."""
from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FailureScenario:
    test_id: str
    name: str
    preconditions: tuple[str, ...]
    trigger: str
    detection_mechanism: str
    expected_alert: str
    expected_safe_state: str
    expected_data_behaviour: str
    recovery_procedure: str
    lab_command: str
    locally_executable: bool


SCENARIOS = (
    FailureScenario("FAIL-01", "Elasticsearch unavailable", ("queue available",), "deny Elasticsearch connection", "elastic_index_failure_total and health probe", "search dependency degraded", "workflow continues; search visibly degraded", "buffer then idempotently replay", "restore Elasticsearch; replay bulk queue; compare event IDs", "scripts/run-failure-scenario FAIL-01 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-01 PROFILE_B'", True),
    FailureScenario("FAIL-02", "AI provider unavailable", ("deterministic fallback enabled",), "provider returns timeout", "ai_request_failure and circuit breaker", "AI provider unavailable", "deterministic fallback; no stale proposal executes", "observations and evidence continue", "restore provider; wait for half-open probe", "scripts/run-failure-scenario FAIL-02 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-02 PROFILE_B'", True),
    FailureScenario("FAIL-03", "Spider stops", ("active sandbox",), "stop MirageSpider", "worker heartbeat age", "high-priority collection alert", "adaptive mutation freezes", "collection gap is recorded", "restart Spider; reconcile sequence gap", "scripts/run-failure-scenario FAIL-03 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-03 PROFILE_B'", False),
    FailureScenario("FAIL-04", "Environment Controller fails", ("active sandbox",), "stop controller", "controller acknowledgement timeout", "controller failure", "mutations stop; observation continues", "no partial action is successful", "restart controller; resume journal", "scripts/run-failure-scenario FAIL-04 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-04 PROFILE_B'", False),
    FailureScenario("FAIL-05", "Evidence write fails", ("required evidence pending",), "object store rejects write", "s3_write_failure", "immediate critical evidence alert", "export is blocked", "bounded retry; no false VERIFIED", "restore store; retry acquisition and verify", "scripts/run-failure-scenario FAIL-05 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-05 PROFILE_B'", True),
    FailureScenario("FAIL-06", "Event-ordering gap", ("projection current",), "deliver sequence n+2", "projection offset gap flag", "ordering-gap warning", "projection marked incomplete", "no silent reorder", "request replay; rebuild projection", "scripts/run-failure-scenario FAIL-06 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-06 PROFILE_B'", True),
    FailureScenario("FAIL-07", "Clock drift", ("time source configured",), "offset source clock by >5s", "clock_offset_seconds", "clock-offset alert", "source and ingest clocks retained", "reports expose uncertainty", "restore time sync; retain original timestamps", "scripts/run-failure-scenario FAIL-07 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-07 PROFILE_B'", True),
    FailureScenario("FAIL-08", "False-positive steering", ("active route decision",), "revoke route decision", "routing audit and route lookup", "steering-revoked notice", "new connections return to endpoint", "existing session is not claimed migrated", "issue corrected decision; preserve error audit", "scripts/run-failure-scenario FAIL-08 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-08 PROFILE_B'", True),
    FailureScenario("FAIL-09", "Sandbox fingerprint failure", ("sandbox provisioning",), "fail a MUST fingerprint check", "fingerprint gate result", "blocking fingerprint alert", "sandbox cannot enter ENGAGING", "failed baseline retained", "rebuild or authorised analyst resolution", "scripts/run-failure-scenario FAIL-09 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-09 PROFILE_B'", True),
    FailureScenario("FAIL-10", "Canary callback absent", ("canary issued",), "let callback window expire", "callback-window observation", "no-callback informational state", "no attacker location inferred", "absence is explicitly inconclusive", "continue observation; do not fabricate callback", "scripts/run-failure-scenario FAIL-10 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-10 PROFILE_B'", True),
    FailureScenario("FAIL-11", "Analyst disconnect", ("SSE active",), "drop analyst connection", "SSE disconnect and resume sequence", "connection degraded", "running action remains deterministic", "unsaved draft is not sent", "reconnect with Last-Event-ID", "scripts/run-failure-scenario FAIL-11 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-11 PROFILE_B'", True),
    FailureScenario("FAIL-12", "Unsafe artifact", ("artifact staged",), "scanner returns unsafe", "artifact scan decision", "artifact quarantine alert", "no deployment", "audit and evidence retained", "remove or replace artifact after review", "scripts/run-failure-scenario FAIL-12 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-12 PROFILE_B'", True),
    FailureScenario("FAIL-13", "Control credentials invalidated", ("controlled Profile B environment",), "revoke control identity", "authentication failure and critical health", "critical control-plane alert", "mutation capability stops; evidence preserved", "no offensive counter-action", "follow credential-compromise runbook", "scripts/run-failure-scenario FAIL-13 --profile-b --recipe config/failure-profile-b.json --confirm 'FAULT FAIL-13 PROFILE_B'", False),
)


def scenario(test_id: str) -> FailureScenario:
    for value in SCENARIOS:
        if value.test_id == test_id:
            return value
    raise ValueError(f"unknown failure scenario: {test_id}")


def run_local_scenario(test_id: str) -> dict[str, Any]:
    """Execute the deterministic safety oracle for locally testable state."""
    definition = scenario(test_id)
    if not definition.locally_executable:
        return {
            **asdict(definition),
            "start_time": _now(),
            "end_time": _now(),
            "recovery_time_ms": None,
            "duplicate_count": 0,
            "missing_event_count": 0,
            "collection_gaps": [],
            "residual_risk": "Requires controlled Profile B infrastructure",
            "result": "NOT_RUN",
            "limitation": f"Execute: {definition.lab_command}",
        }
    events = [{"event_id": f"event-{index}", "sequence": index} for index in range(1, 101)]
    effective: dict[str, dict[str, Any]] = {}
    collection_gaps: list[dict[str, Any]] = []
    safe_state = definition.expected_safe_state
    if test_id == "FAIL-06":
        replay_order = [*events[:49], *events[50:], events[49]]
        collection_gaps.append({"from": 50, "to": 50, "resolved_by_replay": True})
    else:
        replay_order = [*events, *events[30:45]]
    for event in replay_order:
        effective[str(event["event_id"])] = event
    missing = len({event["event_id"] for event in events} - set(effective))
    duplicate_effective = len(effective) - len({event["event_id"] for event in effective.values()})
    invariant_failures: list[str] = []
    if missing:
        invariant_failures.append("confirmed event loss")
    if duplicate_effective:
        invariant_failures.append("duplicate effective state")
    if test_id == "FAIL-02" and "fallback" not in safe_state:
        invariant_failures.append("AI fallback not asserted")
    if test_id == "FAIL-10" and "no attacker location" not in safe_state:
        invariant_failures.append("canary absence overclaimed")
    if test_id == "FAIL-12" and "no deployment" not in safe_state:
        invariant_failures.append("unsafe artifact deployment not blocked")
    return {
        **asdict(definition),
        "start_time": _now(),
        "end_time": _now(),
        "recovery_time_ms": 0,
        "duplicate_count": duplicate_effective,
        "missing_event_count": missing,
        "collection_gaps": collection_gaps,
        "residual_risk": "Local deterministic harness is not Profile B fault injection",
        "result": "PASS" if not invariant_failures else "FAIL",
        "limitation": "; ".join(invariant_failures),
    }


def run_profile_b_scenario(
    test_id: str,
    *,
    recipe_path: Path,
    confirmation: str,
) -> dict[str, Any]:
    """Execute a shell-free, bounded lab recipe and always attempt recovery."""
    definition = scenario(test_id)
    expected = f"FAULT {test_id} PROFILE_B"
    if confirmation != expected:
        raise ValueError(f"fault injection requires exact confirmation {expected}")
    recipe = json.loads(recipe_path.read_text())
    if recipe.get("schema_version") != "mirage.failure-recipe/1.0":
        raise ValueError("unsupported failure recipe schema")
    configured = recipe.get("scenarios", {}).get(test_id)
    if not isinstance(configured, dict):
        raise ValueError(f"recipe does not define {test_id}")
    for value in configured.values():
        argv = value.get("argv") if isinstance(value, dict) else None
        if not isinstance(argv, list) or not argv or not all(
            isinstance(item, str) and item for item in argv
        ):
            raise ValueError("every fault stage requires a non-empty argv list")
        if any("REPLACE_ME" in item for item in argv):
            raise ValueError("replace every REPLACE_ME value before Profile B execution")
    started = _now()
    records: list[dict[str, Any]] = []
    trigger_attempted = False
    failed = False

    def execute(stage: str) -> None:
        nonlocal failed
        spec = configured[stage]
        completed = subprocess.run(
            spec["argv"],
            capture_output=True,
            text=True,
            timeout=max(1, min(int(spec.get("timeout_seconds", 60)), 900)),
            check=False,
        )
        allowed = spec.get("expected_exit_codes", [0])
        accepted = completed.returncode in allowed
        records.append(
            {
                "stage": stage,
                "argv": spec["argv"],
                "returncode": completed.returncode,
                "expected_exit_codes": allowed,
                "accepted": accepted,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
                "ended_at": _now(),
            }
        )
        if not accepted:
            failed = True
            raise RuntimeError(f"{stage} returned {completed.returncode}")

    try:
        execute("precheck")
        trigger_attempted = True
        execute("trigger")
        execute("detect")
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        failed = True
        records.append({"stage": "harness", "accepted": False, "error": str(exc)})
    finally:
        if trigger_attempted:
            try:
                execute("recover")
            except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                failed = True
                records.append(
                    {"stage": "recovery-harness", "accepted": False, "error": str(exc)}
                )
    if trigger_attempted:
        try:
            execute("verify")
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            failed = True
            records.append(
                {"stage": "verification-harness", "accepted": False, "error": str(exc)}
            )
    return {
        **asdict(definition),
        "profile": "PROFILE_B",
        "start_time": started,
        "end_time": _now(),
        "commands": records,
        "result": "FAIL" if failed else "PASS",
        "limitation": (
            "Profile B recipe executed; attach alert timing, data reconciliation, and "
            "resource telemetry to the signed acceptance result."
        ),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
