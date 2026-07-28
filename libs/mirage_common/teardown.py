"""Safe ordered Mirage teardown with exact tag filters and resumable journal."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

TEARDOWN_STEPS = (
    "block_analyst_directives",
    "block_direct_messages",
    "block_ai_mutations",
    "block_artifact_deployments",
    "mark_case_concluding",
    "drain_queues",
    "record_remaining_gaps",
    "capture_final_snapshot",
    "capture_final_fingerprint",
    "verify_required_evidence",
    "generate_final_report",
    "generate_final_manifest",
    "sign_report_and_manifest",
    "independently_verify_export",
    "revoke_sandbox_certificate",
    "revoke_temporary_agent_certificates",
    "terminate_sandbox_sessions",
    "destroy_sandbox",
    "remove_temporary_compute_and_volumes",
    "remove_temporary_credentials_and_tokens",
    "remove_temporary_public_endpoints",
    "preserve_evidence_resources",
    "run_inventory",
    "confirm_no_disallowed_resources",
    "mark_case_destroyed",
)


class TeardownBlocked(RuntimeError):
    pass


@dataclass
class CloudResource:
    resource_id: str
    project: str
    environment: str
    case_id: str | None
    resource_type: str
    temporary: bool = True
    protected_evidence: bool = False
    active: bool = True


@dataclass(frozen=True)
class EvidenceGapOverride:
    reason: str
    missing_items: tuple[str, ...]
    actor: str
    policy_decision_id: str
    policy_allows: bool

    def validate(self) -> None:
        if not self.reason.strip() or not self.missing_items or not self.actor.strip():
            raise ValueError("override requires reason, missing items, and actor")
        if not self.policy_decision_id or not self.policy_allows:
            raise ValueError("override requires an ALLOW policy decision")


class CloudAdapter(Protocol):
    def inventory(self, *, project: str, environment: str, case_id: str | None) -> list[CloudResource]: ...
    def deactivate(self, resource_id: str) -> None: ...


class LocalCloudAdapter:
    """Deterministic in-memory adapter used by the destructive workflow tests."""

    def __init__(
        self,
        resources: list[CloudResource],
        *,
        fail_once_at: str | None = None,
    ) -> None:
        self.resources = {item.resource_id: item for item in resources}
        self.fail_once_at = fail_once_at
        self.failed = False

    def inventory(
        self, *, project: str, environment: str, case_id: str | None
    ) -> list[CloudResource]:
        if project != "mirage" or not environment:
            raise ValueError("exact Project=mirage and Environment filters are required")
        return [
            item
            for item in self.resources.values()
            if item.active
            and item.project == project
            and item.environment == environment
            and (case_id is None or item.case_id == case_id)
        ]

    def deactivate(self, resource_id: str) -> None:
        resource = self.resources.get(resource_id)
        if resource is None:
            return
        resource.active = False

    def maybe_fail(self, step: str) -> None:
        if self.fail_once_at == step and not self.failed:
            self.failed = True
            raise RuntimeError(f"injected interruption at {step}")


class AwsCloudAdapter:
    """AWS inventory adapter. Destruction stays service-specific and tag bounded."""

    def __init__(self, *, region: str | None = None) -> None:
        import boto3

        self.client = boto3.client("resourcegroupstaggingapi", region_name=region)

    def inventory(
        self, *, project: str, environment: str, case_id: str | None
    ) -> list[CloudResource]:
        if project != "mirage" or not environment:
            raise ValueError("exact Project=mirage and Environment filters are required")
        filters = [
            {"Key": "Project", "Values": [project]},
            {"Key": "Environment", "Values": [environment]},
        ]
        if case_id:
            filters.append({"Key": "CaseId", "Values": [case_id]})
        paginator = self.client.get_paginator("get_resources")
        resources: list[CloudResource] = []
        for page in paginator.paginate(TagFilters=filters):
            for item in page.get("ResourceTagMappingList", []):
                tags = {value["Key"]: value["Value"] for value in item.get("Tags", [])}
                resource_id = item["ResourceARN"]
                resources.append(
                    CloudResource(
                        resource_id=resource_id,
                        project=tags.get("Project", ""),
                        environment=tags.get("Environment", ""),
                        case_id=tags.get("CaseId"),
                        resource_type=resource_id.split(":")[2],
                        temporary=tags.get("Temporary", "true").lower() == "true",
                        protected_evidence=tags.get("EvidenceRetention") == "protected",
                    )
                )
        return resources

    def deactivate(self, resource_id: str) -> None:
        raise TeardownBlocked(
            "AWS resource destruction requires the service-specific Profile B adapter; "
            f"no broad delete was attempted for {resource_id}"
        )


class TeardownWorkflow:
    def __init__(
        self,
        *,
        adapter: CloudAdapter,
        environment: str,
        case_id: str,
        journal: Path,
        required_evidence_verified: bool = True,
        export_verified: bool = True,
        queue_drain_succeeds: bool = True,
        final_snapshot_succeeds: bool = True,
        certificate_revocation_succeeds: bool = True,
        inventory_complete: bool = True,
        override: EvidenceGapOverride | None = None,
    ) -> None:
        if not environment or not case_id:
            raise ValueError("explicit environment and case identity are required")
        self.adapter = adapter
        self.environment = environment
        self.case_id = case_id
        self.journal = journal
        self.required_evidence_verified = required_evidence_verified
        self.export_verified = export_verified
        self.queue_drain_succeeds = queue_drain_succeeds
        self.final_snapshot_succeeds = final_snapshot_succeeds
        self.certificate_revocation_succeeds = certificate_revocation_succeeds
        self.inventory_complete = inventory_complete
        self.override = override
        self.state: dict[str, Any] = {
            "case_state": "ENGAGING",
            "directives_allowed": True,
            "messages_allowed": True,
            "ai_mutations_allowed": True,
            "artifact_deployments_allowed": True,
            "revoked_identities": set(),
            "audit": [],
        }

    def plan(self) -> dict[str, Any]:
        inventory = self.adapter.inventory(
            project="mirage",
            environment=self.environment,
            case_id=self.case_id,
        )
        return {
            "dry_run": True,
            "project": "mirage",
            "environment": self.environment,
            "case_id": self.case_id,
            "protected_resources": [
                asdict(item) for item in inventory if item.protected_evidence
            ],
            "temporary_resources": [
                asdict(item)
                for item in inventory
                if item.temporary and not item.protected_evidence
            ],
            "steps": [
                {"number": index, "step": step}
                for index, step in enumerate(TEARDOWN_STEPS, 1)
            ],
        }

    def execute(self, *, confirmation: str) -> dict[str, Any]:
        expected = f"mirage:{self.environment}:{self.case_id}"
        if confirmation != expected:
            raise ValueError(f"teardown requires exact confirmation {expected}")
        journal = self._read_journal()
        completed = {item["step"] for item in journal.get("entries", []) if item["result"] == "PASS"}
        entries = list(journal.get("entries", []))
        for number, step in enumerate(TEARDOWN_STEPS, 1):
            if step in completed:
                continue
            started_at = _now()
            try:
                if isinstance(self.adapter, LocalCloudAdapter):
                    self.adapter.maybe_fail(step)
                detail = self._apply(step)
                result = "PASS"
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                result = "BLOCKED"
            entries.append(
                {
                    "number": number,
                    "step": step,
                    "started_at": started_at,
                    "ended_at": _now(),
                    "result": result,
                    "detail": detail,
                }
            )
            self._write_journal({"entries": entries, "state": self._serialisable_state()})
            if result != "PASS":
                raise TeardownBlocked(f"{step}: {detail}")
        return self._read_journal()

    def identity_can_reconnect(self, identity: str) -> bool:
        return identity not in self.state["revoked_identities"]

    def _apply(self, step: str) -> str:
        simple_flags = {
            "block_analyst_directives": "directives_allowed",
            "block_direct_messages": "messages_allowed",
            "block_ai_mutations": "ai_mutations_allowed",
            "block_artifact_deployments": "artifact_deployments_allowed",
        }
        if step in simple_flags:
            self.state[simple_flags[step]] = False
            return "new operation blocked"
        if step == "mark_case_concluding":
            self.state["case_state"] = "CONCLUDING"
        elif step == "drain_queues" and not self.queue_drain_succeeds:
            raise TeardownBlocked("queue drain failed")
        elif step == "record_remaining_gaps":
            if not self.required_evidence_verified:
                if self.override is None:
                    self.state["audit"].append({"action": "evidence_gap_detected"})
                else:
                    self.override.validate()
                    self.state["audit"].append(
                        {"action": "evidence_gap_override", **asdict(self.override)}
                    )
        elif step == "capture_final_snapshot" and not self.final_snapshot_succeeds:
            raise TeardownBlocked("final snapshot failed")
        elif step == "verify_required_evidence":
            if not self.required_evidence_verified and self.override is None:
                raise TeardownBlocked("required evidence is not VERIFIED")
        elif step == "independently_verify_export" and not self.export_verified:
            raise TeardownBlocked("independent export verification failed")
        elif step in {"revoke_sandbox_certificate", "revoke_temporary_agent_certificates"}:
            if not self.certificate_revocation_succeeds:
                raise TeardownBlocked("certificate revocation failed")
            self.state["revoked_identities"].add(
                "sandbox-cert" if step == "revoke_sandbox_certificate" else "agent-cert"
            )
        elif step in {
            "destroy_sandbox",
            "remove_temporary_compute_and_volumes",
            "remove_temporary_credentials_and_tokens",
            "remove_temporary_public_endpoints",
        }:
            types = {
                "destroy_sandbox": {"sandbox"},
                "remove_temporary_compute_and_volumes": {"compute", "volume"},
                "remove_temporary_credentials_and_tokens": {"credential", "token"},
                "remove_temporary_public_endpoints": {"public_endpoint"},
            }[step]
            for resource in self.adapter.inventory(
                project="mirage",
                environment=self.environment,
                case_id=self.case_id,
            ):
                if (
                    resource.resource_type in types
                    and resource.temporary
                    and not resource.protected_evidence
                ):
                    self.adapter.deactivate(resource.resource_id)
        elif step == "preserve_evidence_resources":
            protected = [
                resource
                for resource in self.adapter.inventory(
                    project="mirage",
                    environment=self.environment,
                    case_id=self.case_id,
                )
                if resource.protected_evidence
            ]
            if not protected:
                raise TeardownBlocked("protected evidence allowlist is empty")
        elif step == "run_inventory" and not self.inventory_complete:
            raise TeardownBlocked("resource inventory is incomplete")
        elif step == "confirm_no_disallowed_resources":
            remaining = [
                resource
                for resource in self.adapter.inventory(
                    project="mirage",
                    environment=self.environment,
                    case_id=self.case_id,
                )
                if resource.temporary and not resource.protected_evidence
            ]
            if remaining:
                raise TeardownBlocked(
                    "temporary resources remain: "
                    + ",".join(resource.resource_id for resource in remaining)
                )
        elif step == "mark_case_destroyed":
            self.state["case_state"] = "DESTROYED"
        return "completed"

    def _serialisable_state(self) -> dict[str, Any]:
        return {
            **self.state,
            "revoked_identities": sorted(self.state["revoked_identities"]),
        }

    def _read_journal(self) -> dict[str, Any]:
        if not self.journal.exists():
            return {}
        value = json.loads(self.journal.read_text())
        state = value.get("state")
        if state:
            self.state.update(state)
            self.state["revoked_identities"] = set(state.get("revoked_identities", []))
        return value

    def _write_journal(self, value: dict[str, Any]) -> None:
        self.journal.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.journal.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.journal)


def local_cli(*, dry_run_default: bool = False) -> int:
    parser = argparse.ArgumentParser(description="Plan or run exact-filter Mirage teardown.")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true", default=dry_run_default)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    state = json.loads(args.state.read_text())
    adapter = LocalCloudAdapter([CloudResource(**item) for item in state["resources"]])
    workflow = TeardownWorkflow(
        adapter=adapter,
        environment=args.environment,
        case_id=args.case_id,
        journal=args.journal,
        required_evidence_verified=state.get("required_evidence_verified", True),
        export_verified=state.get("export_verified", True),
        queue_drain_succeeds=state.get("queue_drain_succeeds", True),
        final_snapshot_succeeds=state.get("final_snapshot_succeeds", True),
        certificate_revocation_succeeds=state.get("certificate_revocation_succeeds", True),
        inventory_complete=state.get("inventory_complete", True),
    )
    result = (
        workflow.execute(confirmation=args.confirm or "")
        if args.execute
        else workflow.plan()
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
