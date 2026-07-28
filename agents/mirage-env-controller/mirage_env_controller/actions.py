"""The Controller's structured-action executor (Appendix I). Pure Python,
no pywin32 import anywhere in this module (same ADR-0002 cross-platform-
testable pattern `mirage_spider.service_logic`/`mirage_endpoint.service_logic`
already established) — everything here runs and is tested on any OS; the
Windows-specific pieces two actions would ideally use for real
(ENABLE/DISABLE_DECOY_SERVICE's real `sc.exe`/win32service calls,
CHANGE_VISIBLE_METADATA's Windows file-attribute bits) are clearly marked
below as the seam `win_service.py` would extend on a real Windows host —
see KNOWN_ISSUES.md.

Every handler enforces Appendix G's "Privilege: Only approved mutation
dirs/services" itself, in code — `_resolve_within_roots` rejects any
target path (after resolving `..` traversal) that escapes the configured
`allowed_roots`, regardless of what a command's params request. This is
policy enforcement inside the one process capable of touching the
filesystem, not merely a suggestion the gateway is trusted to have already
checked.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from mirage_common.sandbox_actions import (
    ALLOWED_ACTION_TYPES,
    CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS,
    OUTPUT_TAGS,
    default_output_tag,
)
from mirage_env_controller.journal import ActionJournal


class RestrictedPathError(Exception):
    pass


class UnknownActionTypeError(Exception):
    pass


class DecoyServiceController(ABC):
    """Platform abstraction for ENABLE/DISABLE_DECOY_SERVICE (ADR-0002
    pattern: this module stays pywin32-free and cross-platform testable;
    the real implementation lives in mirage_env_controller.windows_actions,
    the only place besides win_service.py allowed to import pywin32)."""

    @abstractmethod
    def enable(self, service_id: str, config_profile: dict | None) -> None: ...

    @abstractmethod
    def disable(self, service_id: str) -> dict | None:
        """Returns opaque prior-state data this SAME controller's own
        enable() knows how to interpret on rollback, or None if the service
        was already disabled."""

    @abstractmethod
    def is_enabled(self, service_id: str) -> bool: ...


class UnapprovedServiceError(Exception):
    pass


# Only services explicitly registered here may ever be targeted by
# ENABLE/DISABLE_DECOY_SERVICE — never an arbitrary caller-supplied Windows
# service name (Appendix G: "approved registered service identifiers"),
# the same restricted-allowlist principle _resolve_within_roots enforces
# for the filesystem side. Kept here (not in windows_actions.py) so the
# allowlist and its rejection behavior are unit-testable on any OS —
# resolving a service_id needs no pywin32 call, only the actual
# StartService/StopService calls do.
APPROVED_DECOY_SERVICES: dict[str, str] = {
    # service_id -> real Windows service name registered on the golden image
    "decoy-print-spooler": "MirageDecoyPrintSpooler",
    "decoy-remote-registry": "MirageDecoyRemoteRegistry",
    "decoy-ftp": "MirageDecoyFtp",
}


def resolve_approved_service_name(service_id: str) -> str:
    try:
        return APPROVED_DECOY_SERVICES[service_id]
    except KeyError:
        raise UnapprovedServiceError(f"{service_id!r} is not an approved decoy service") from None


@dataclass
class MarkerFileDecoyServiceController(DecoyServiceController):
    """Development/non-Windows adapter — a marker file stands in for real
    Windows Service Control Manager state. This proves the structured-
    action/policy/rollback/audit pipeline for real; it is NOT itself a
    claim that a Windows service was started or stopped. Production must
    use mirage_env_controller.windows_actions.WindowsDecoyServiceController
    — see build_executor_context()'s environment-gated selection."""

    allowed_roots: tuple[Path, ...]

    def _marker_path(self, service_id: str) -> Path:
        resolve_approved_service_name(service_id)  # raises UnapprovedServiceError if not allowlisted
        return self.allowed_roots[0] / "_decoy_services" / f"{service_id}.enabled"

    def enable(self, service_id: str, config_profile: dict | None) -> None:
        marker = self._marker_path(service_id)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({"config_profile": config_profile}))

    def disable(self, service_id: str) -> dict | None:
        marker = self._marker_path(service_id)
        if not marker.exists():
            return None
        config_profile = json.loads(marker.read_text()).get("config_profile")
        marker.unlink()
        return {"config_profile": config_profile}

    def is_enabled(self, service_id: str) -> bool:
        return self._marker_path(service_id).exists()


class MetadataAttributeController(ABC):
    """Platform abstraction for CHANGE_VISIBLE_METADATA's Windows-specific
    attribute bits (hidden/read-only/owner) — the portable timestamp fields
    (accessed_time/modified_time) are handled directly by
    _apply_metadata_fields() below on every platform via os.utime; this
    controller only ever sees the fields os.utime cannot set."""

    @abstractmethod
    def apply(self, path: Path, fields: dict) -> dict:
        """Applies whichever Windows-specific fields are present in
        `fields`, returning the PRIOR value of exactly those fields (for
        rollback)."""


class NoopMetadataAttributeController(MetadataAttributeController):
    """Development/non-Windows default — Windows-specific attribute fields
    (hidden/read_only) are silently not applied (matching this handler's
    pre-existing behavior of only ever touching timestamps); this is a
    known, documented gap on non-Windows hosts, not a fabricated success."""

    def apply(self, path: Path, fields: dict) -> dict:
        return {}


@dataclass(frozen=True)
class ActionOutcome:
    status: str  # SUCCESS | FAILED | REJECTED
    output_tag: str | None
    rollback_definition: dict | None
    error_detail: str | None
    elapsed_seconds: float = 0.0


def _resolve_within_roots(raw_path: str, allowed_roots: tuple[Path, ...]) -> Path:
    if not raw_path:
        raise RestrictedPathError("empty path")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        raise RestrictedPathError(f"path must be absolute: {raw_path!r}")
    resolved = candidate.resolve(strict=False)  # normalizes '..' traversal without requiring the path to exist yet
    for root in allowed_roots:
        root_resolved = root.resolve(strict=False)
        if resolved == root_resolved or root_resolved in resolved.parents:
            return resolved
    raise RestrictedPathError(f"{raw_path!r} resolves outside all approved mutation roots {[str(r) for r in allowed_roots]}")


def _apply_metadata_fields(path: Path, fields: dict) -> None:
    """Portable subset of Appendix I's CHANGE_VISIBLE_METADATA "approved
    fields" — modified/accessed timestamps via the real, cross-platform
    os.utime. Windows-specific attribute bits (hidden/read-only/owner) are
    NOT implemented here; they need win32file/pywin32 calls this module
    deliberately keeps out (see module docstring) — LAB_VERIFICATION_REQUIRED,
    tracked in KNOWN_ISSUES.md."""
    import os

    stat = path.stat()
    atime = fields.get("accessed_time", stat.st_atime)
    mtime = fields.get("modified_time", stat.st_mtime)
    if isinstance(atime, str):
        import datetime

        atime = datetime.datetime.fromisoformat(atime.replace("Z", "+00:00")).timestamp()
    if isinstance(mtime, str):
        import datetime

        mtime = datetime.datetime.fromisoformat(mtime.replace("Z", "+00:00")).timestamp()
    os.utime(path, (atime, mtime))


# --- Individual action handlers -------------------------------------------
# Each returns (rollback_definition: dict, error_detail: str | None). A
# raised RestrictedPathError is caught by execute_action() and turned into
# REJECTED; any other exception becomes FAILED. Success is implicit
# (no exception, error_detail None).

def _place_artifact(params: dict, allowed_roots: tuple[Path, ...]) -> tuple[dict, str | None]:
    destination = _resolve_within_roots(params["destination"], allowed_roots)
    content_b64 = params.get("content_b64")
    download_url = params.get("download_url")
    expected_hash = params.get("expected_sha256") or params.get("expected_hash")
    if download_url:
        from urllib.parse import urlparse

        import httpx

        parsed = urlparse(download_url)
        local_hosts = {"localhost", "127.0.0.1", "host.docker.internal", "mirage-api"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in local_hosts
        ):
            raise ValueError("artifact download URL must use HTTPS outside local development")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp_path = destination.with_name(f".{destination.name}.mirage-download")
        digest = hashlib.sha256()
        size = 0
        try:
            with (
                httpx.Client(timeout=30.0, follow_redirects=False) as client,
                client.stream("GET", download_url) as response,
                temp_path.open("wb") as target,
            ):
                response.raise_for_status()
                for chunk in response.iter_bytes(1024 * 1024):
                    size += len(chunk)
                    if size > 250 * 1024 * 1024:
                        raise ValueError("artifact download exceeds 250 MB")
                    digest.update(chunk)
                    target.write(chunk)
            actual_hash = digest.hexdigest()
            if not expected_hash or expected_hash != actual_hash:
                raise ValueError(
                    "downloaded artifact SHA-256 does not match the approved deployment"
                )
            temp_path.replace(destination)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
    elif content_b64 is not None:
        import base64

        content = base64.b64decode(content_b64)
        actual_hash = hashlib.sha256(content).hexdigest()
        if expected_hash and expected_hash != actual_hash:
            raise ValueError(
                f"expected_hash {expected_hash!r} does not match computed sha256 "
                f"{actual_hash!r} — refusing to place"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    else:
        raise ValueError("PLACE_ARTIFACT requires a bounded download_url or content_b64")
    visible_metadata = params.get("visible_metadata") or {}
    if visible_metadata:
        _apply_metadata_fields(destination, visible_metadata)
    return {"kind": "delete_file", "path": str(destination)}, None


def _move_artifact(params: dict, allowed_roots: tuple[Path, ...]) -> tuple[dict, str | None]:
    source = _resolve_within_roots(params["source"], allowed_roots)
    destination = _resolve_within_roots(params["destination"], allowed_roots)
    if not source.exists():
        raise FileNotFoundError(f"source does not exist: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    return {"kind": "move_file", "path": str(destination), "destination": str(source)}, None


def _create_decoy_directory(params: dict, allowed_roots: tuple[Path, ...]) -> tuple[dict, str | None]:
    path = _resolve_within_roots(params["path"], allowed_roots)
    path.mkdir(parents=True, exist_ok=True)
    metadata_profile = params.get("metadata_profile")
    if metadata_profile:
        (path / ".mirage_metadata_profile.json").write_text(json.dumps(metadata_profile))
    return {"kind": "delete_directory", "path": str(path)}, None


def _change_visible_metadata(
    params: dict, allowed_roots: tuple[Path, ...], *, attribute_controller: MetadataAttributeController
) -> tuple[dict, str | None]:
    target = _resolve_within_roots(params["target"], allowed_roots)
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    approved_fields = params["approved_fields"]
    prior_state = params["prior_state"]  # required by Appendix I — also what rollback restores
    _apply_metadata_fields(target, approved_fields)
    # Windows-specific attribute bits (hidden/read_only) are a caller-
    # supplied subset of approved_fields that os.utime cannot set —
    # delegated to the platform controller; on non-Windows/dev this is a
    # documented no-op (NoopMetadataAttributeController), never a fabricated
    # success.
    attribute_controller.apply(target, approved_fields)
    return {"kind": "restore_metadata", "path": str(target), "prior_state": prior_state}, None


def _display_message(params: dict, allowed_roots: tuple[Path, ...]) -> tuple[dict, str | None]:
    output_tag = params.get("output_tag")
    if output_tag not in ("AI_GENERATED_INTERACTION", "ANALYST_MESSAGE"):
        raise ValueError(f"DISPLAY_MESSAGE requires output_tag in AI_GENERATED_INTERACTION/ANALYST_MESSAGE, got {output_tag!r}")
    log_path = allowed_roots[0] / "_messages.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"surface": params["surface"], "content": params["content"], "output_tag": output_tag, "at": time.time()}
    with log_path.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return {"kind": "noop"}, None


def _enable_decoy_service(
    params: dict, allowed_roots: tuple[Path, ...], *, controller: DecoyServiceController
) -> tuple[dict, str | None]:
    service_id = params["service_id"]
    controller.enable(service_id, params.get("config_profile"))
    return {"kind": "disable_decoy_service", "service_id": service_id}, None


def _disable_decoy_service(
    params: dict, allowed_roots: tuple[Path, ...], *, controller: DecoyServiceController
) -> tuple[dict, str | None]:
    service_id = params["service_id"]
    prior_state = controller.disable(service_id)
    return {"kind": "enable_decoy_service", "service_id": service_id, "prior_state": prior_state}, None


def _request_snapshot(params: dict, allowed_roots: tuple[Path, ...], *, snapshots_dir: Path) -> tuple[dict, str | None]:
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshots_dir / f"snapshot-{int(time.time() * 1000)}.tar.gz"
    with tarfile.open(snapshot_path, "w:gz") as tar:
        for root in allowed_roots:
            if root.exists():
                tar.add(root, arcname=root.name)
    return {"kind": "delete_file", "path": str(snapshot_path)}, None


def _conclude_session(params: dict, allowed_roots: tuple[Path, ...], *, programdata: Path) -> tuple[dict, str | None]:
    marker = programdata / "session_concluded.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"reason": params["reason"], "concluded_at": time.time()}))
    return {"kind": "delete_file", "path": str(marker)}, None


def _test_file_placement(params: dict, allowed_roots: tuple[Path, ...]) -> tuple[dict, str | None]:
    destination = _resolve_within_roots(params["destination"], allowed_roots)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(params.get("content", "mirage-self-test"))
    return {"kind": "delete_file", "path": str(destination)}, None


def _test_metadata_update(params: dict, allowed_roots: tuple[Path, ...]) -> tuple[dict, str | None]:
    target = _resolve_within_roots(params["target"], allowed_roots)
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    prior_state = {"modified_time": target.stat().st_mtime}
    _apply_metadata_fields(target, {"modified_time": params["modified_time"]})
    return {"kind": "restore_metadata", "path": str(target), "prior_state": prior_state}, None


def _wipe_and_reseed(allowed_roots: tuple[Path, ...], baseline_snapshot: Path | None) -> None:
    for root in allowed_roots:
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
    if baseline_snapshot is not None and baseline_snapshot.exists():
        with tarfile.open(baseline_snapshot, "r:gz") as tar:
            tar.extractall(allowed_roots[0].parent)  # noqa: S202 -- baseline_snapshot is a Mirage-controlled build artifact, not intruder-supplied input


def _soft_reset(params: dict, allowed_roots: tuple[Path, ...], *, baseline_snapshot: Path | None) -> tuple[dict, str | None]:
    """Spec: 'soft reset < 3 min.' Restores the approved mutation roots
    (decoy content only) from the golden-image baseline — does NOT touch
    sandbox_instances.state_version (that reset is the gateway's job, since
    it's Postgres state this process has no access to)."""
    _wipe_and_reseed(allowed_roots, baseline_snapshot)
    return {"kind": "noop"}, None


def _full_rebuild(params: dict, allowed_roots: tuple[Path, ...], *, baseline_snapshot: Path | None, programdata: Path) -> tuple[dict, str | None]:
    """Spec: 'full rebuild < 10 min.' Locally: a deeper wipe than
    SOFT_RESET — also clears the local journal and any session-concluded
    marker, simulating 'replace the instance from the golden AMI' as
    closely as a non-AWS environment can. The REAL AWS EC2
    terminate-and-relaunch-from-golden-AMI operation is
    LAB_VERIFICATION_REQUIRED — see KNOWN_ISSUES.md; this proves the
    Controller's OWN reset mechanism and its real elapsed time locally,
    not the AWS instance-replacement latency."""
    _wipe_and_reseed(allowed_roots, baseline_snapshot)
    marker = programdata / "session_concluded.json"
    if marker.exists():
        marker.unlink()
    return {"kind": "noop"}, None


def _clean_shutdown(params: dict, allowed_roots: tuple[Path, ...], *, programdata: Path) -> tuple[dict, str | None]:
    marker = programdata / "shutdown_requested.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"reason": params.get("reason", ""), "at": time.time()}))
    return {"kind": "delete_file", "path": str(marker)}, None


# --- Rollback application ---------------------------------------------------

def _apply_rollback_definition(
    definition: dict, allowed_roots: tuple[Path, ...], *, decoy_service_controller: DecoyServiceController
) -> None:
    kind = definition["kind"]
    if kind == "noop":
        return
    if kind == "delete_file":
        path = _resolve_within_roots(definition["path"], allowed_roots)
        if path.exists():
            path.unlink()
        return
    if kind == "delete_directory":
        path = _resolve_within_roots(definition["path"], allowed_roots)
        if path.exists():
            shutil.rmtree(path)
        return
    if kind == "move_file":
        source = _resolve_within_roots(definition["path"], allowed_roots)
        destination = _resolve_within_roots(definition["destination"], allowed_roots)
        if source.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(destination))
        return
    if kind == "restore_metadata":
        path = _resolve_within_roots(definition["path"], allowed_roots)
        if path.exists():
            _apply_metadata_fields(path, definition["prior_state"])
        return
    if kind == "enable_decoy_service":
        decoy_service_controller.enable(definition["service_id"], definition.get("prior_state"))
        return
    if kind == "disable_decoy_service":
        decoy_service_controller.disable(definition["service_id"])
        return
    raise ValueError(f"unknown rollback definition kind: {kind!r}")


# --- Dispatcher --------------------------------------------------------------

@dataclass(frozen=True)
class ExecutorContext:
    allowed_roots: tuple[Path, ...]
    programdata: Path
    journal: ActionJournal
    baseline_snapshot: Path | None = None
    # Defaults are the portable development adapters (ADR-0002 pattern).
    # Real Windows deployments must pass
    # mirage_env_controller.windows_actions.WindowsDecoyServiceController /
    # WindowsMetadataAttributeController explicitly — see win_service.py's
    # construction of ExecutorContext, which is the only place besides this
    # module allowed to import pywin32.
    decoy_service_controller: DecoyServiceController = field(default=None)  # type: ignore[assignment]
    metadata_attribute_controller: MetadataAttributeController = field(
        default_factory=NoopMetadataAttributeController
    )

    def __post_init__(self) -> None:
        if self.decoy_service_controller is None:
            object.__setattr__(
                self, "decoy_service_controller", MarkerFileDecoyServiceController(self.allowed_roots)
            )

    @property
    def snapshots_dir(self) -> Path:
        return self.programdata / "Snapshots"


def execute_action(action_type: str, action_params: dict, *, ctx: ExecutorContext, action_id: str, recorded_at: str) -> ActionOutcome:
    if action_type not in ALLOWED_ACTION_TYPES:
        raise UnknownActionTypeError(action_type)

    if action_type == "ROLLBACK_ACTION":
        return _execute_rollback_action(action_params, ctx=ctx, action_id=action_id, recorded_at=recorded_at)

    handler_needs_extra_ctx = {
        "REQUEST_SNAPSHOT": lambda p: _request_snapshot(p, ctx.allowed_roots, snapshots_dir=ctx.snapshots_dir),
        "CONCLUDE_SESSION": lambda p: _conclude_session(p, ctx.allowed_roots, programdata=ctx.programdata),
        "SOFT_RESET": lambda p: _soft_reset(p, ctx.allowed_roots, baseline_snapshot=ctx.baseline_snapshot),
        "FULL_REBUILD": lambda p: _full_rebuild(p, ctx.allowed_roots, baseline_snapshot=ctx.baseline_snapshot, programdata=ctx.programdata),
        "CLEAN_SHUTDOWN": lambda p: _clean_shutdown(p, ctx.allowed_roots, programdata=ctx.programdata),
    }
    controller_handlers = {
        "CHANGE_VISIBLE_METADATA": lambda p: _change_visible_metadata(
            p, ctx.allowed_roots, attribute_controller=ctx.metadata_attribute_controller
        ),
        "ENABLE_DECOY_SERVICE": lambda p: _enable_decoy_service(
            p, ctx.allowed_roots, controller=ctx.decoy_service_controller
        ),
        "DISABLE_DECOY_SERVICE": lambda p: _disable_decoy_service(
            p, ctx.allowed_roots, controller=ctx.decoy_service_controller
        ),
    }
    simple_handlers = {
        "PLACE_ARTIFACT": _place_artifact,
        "MOVE_ARTIFACT": _move_artifact,
        "CREATE_DECOY_DIRECTORY": _create_decoy_directory,
        "DISPLAY_MESSAGE": _display_message,
        "TEST_FILE_PLACEMENT": _test_file_placement,
        "TEST_METADATA_UPDATE": _test_metadata_update,
    }

    start = time.monotonic()
    try:
        if action_type in handler_needs_extra_ctx:
            rollback_definition, error_detail = handler_needs_extra_ctx[action_type](action_params)
        elif action_type in controller_handlers:
            rollback_definition, error_detail = controller_handlers[action_type](action_params)
        else:
            rollback_definition, error_detail = simple_handlers[action_type](action_params, ctx.allowed_roots)
    except (RestrictedPathError, UnapprovedServiceError) as exc:
        elapsed = time.monotonic() - start
        ctx.journal.record(action_id=action_id, action_type=action_type, action_params=action_params,
                            rollback_definition=None, status="REJECTED", recorded_at=recorded_at)
        return ActionOutcome(status="REJECTED", output_tag=None, rollback_definition=None, error_detail=str(exc), elapsed_seconds=elapsed)
    except Exception as exc:  # noqa: BLE001 -- any handler failure is reported as FAILED, never silently swallowed
        elapsed = time.monotonic() - start
        ctx.journal.record(action_id=action_id, action_type=action_type, action_params=action_params,
                            rollback_definition=None, status="FAILED", recorded_at=recorded_at)
        return ActionOutcome(status="FAILED", output_tag=None, rollback_definition=None, error_detail=str(exc), elapsed_seconds=elapsed)

    elapsed = time.monotonic() - start
    output_tag = action_params.get("output_tag") if action_type in CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS else default_output_tag(action_type)
    assert output_tag in OUTPUT_TAGS  # noqa: S101 -- invariant: every successful action carries a valid, known tag (Appendix G)
    ctx.journal.record(action_id=action_id, action_type=action_type, action_params=action_params,
                        rollback_definition=rollback_definition, status="SUCCESS", recorded_at=recorded_at)
    return ActionOutcome(status="SUCCESS", output_tag=output_tag, rollback_definition=rollback_definition, error_detail=None, elapsed_seconds=elapsed)


def _execute_rollback_action(params: dict, *, ctx: ExecutorContext, action_id: str, recorded_at: str) -> ActionOutcome:
    target_action_id = params["target_action_id"]
    entry = ctx.journal.get(target_action_id)
    start = time.monotonic()
    if entry is None:
        elapsed = time.monotonic() - start
        return ActionOutcome(status="REJECTED", output_tag=None, rollback_definition=None,
                              error_detail=f"no journal entry for target_action_id={target_action_id!r}", elapsed_seconds=elapsed)
    if entry["status"] != "SUCCESS":
        elapsed = time.monotonic() - start
        return ActionOutcome(status="REJECTED", output_tag=None, rollback_definition=None,
                              error_detail=f"target action {target_action_id!r} is not in SUCCESS state (rollback definition may not exist)",
                              elapsed_seconds=elapsed)
    definition = entry["rollback_definition"]
    try:
        if definition is not None:
            _apply_rollback_definition(
                definition, ctx.allowed_roots, decoy_service_controller=ctx.decoy_service_controller
            )
    except Exception as exc:  # noqa: BLE001
        elapsed = time.monotonic() - start
        ctx.journal.record(action_id=action_id, action_type="ROLLBACK_ACTION", action_params=params,
                            rollback_definition=None, status="FAILED", recorded_at=recorded_at)
        return ActionOutcome(status="FAILED", output_tag=None, rollback_definition=None, error_detail=str(exc), elapsed_seconds=elapsed)

    elapsed = time.monotonic() - start
    ctx.journal.mark_status(target_action_id, "ROLLED_BACK")
    ctx.journal.record(action_id=action_id, action_type="ROLLBACK_ACTION", action_params=params,
                        rollback_definition={"kind": "noop"}, status="SUCCESS", recorded_at=recorded_at)
    return ActionOutcome(status="SUCCESS", output_tag=default_output_tag("ROLLBACK_ACTION"), rollback_definition={"kind": "noop"},
                          error_detail=None, elapsed_seconds=elapsed)
