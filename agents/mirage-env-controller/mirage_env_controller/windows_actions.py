"""Real Windows implementations of the Controller's platform-abstracted
action handlers (Priority 8: replacing marker-file simulation with real
controlled mutations). The ONLY module besides win_service.py allowed to
import pywin32 (ADR-0002 boundary) — everything else in
mirage_env_controller, including the approved-service allowlist and
rejection logic these classes rely on, stays cross-platform testable.

Cannot be imported or run outside Windows, and is therefore
LAB_VERIFICATION_REQUIRED like win_service.py — see LAB_EXECUTION_CHECKLIST.md.
The logic this module is thin around (which service names are approved,
what a REJECTED vs FAILED outcome means, the rollback/journal/audit
pipeline) is fully unit-tested in tests/unit/test_env_controller_actions.py
against MarkerFileDecoyServiceController; what ONLY a real Windows host can
prove is that win32serviceutil.StartService/StopService and
win32file.SetFileAttributes actually change real OS state.
"""
from __future__ import annotations

import sys

if sys.platform != "win32":
    raise ImportError("mirage_env_controller.windows_actions is Windows-only — see ADR-0002")

import win32file
import win32service
import win32serviceutil
from pywintypes import error as PyWinError

from mirage_env_controller.actions import (
    DecoyServiceController,
    MetadataAttributeController,
    resolve_approved_service_name,
)

# From winerror.h — duplicated as plain ints (rather than importing the
# winerror module) because these two are the only codes this module treats
# as "already in the desired state, not a real failure"; keeping the
# dependency surface minimal.
_ERROR_SERVICE_ALREADY_RUNNING = 1056
_ERROR_SERVICE_NOT_ACTIVE = 1062


class WindowsDecoyServiceController(DecoyServiceController):
    """Real Windows Service Control Manager control via pywin32's
    win32serviceutil — StartService/StopService/QueryServiceStatus against
    an approved, pre-registered decoy service on the golden image."""

    def enable(self, service_id: str, config_profile: dict | None) -> None:
        service_name = resolve_approved_service_name(service_id)
        try:
            win32serviceutil.StartService(service_name)
        except PyWinError as exc:
            if exc.winerror != _ERROR_SERVICE_ALREADY_RUNNING:
                raise

    def disable(self, service_id: str) -> dict | None:
        service_name = resolve_approved_service_name(service_id)
        was_running = self.is_enabled(service_id)
        try:
            win32serviceutil.StopService(service_name)
        except PyWinError as exc:
            if exc.winerror != _ERROR_SERVICE_NOT_ACTIVE:
                raise
        return {"was_running": True} if was_running else None

    def is_enabled(self, service_id: str) -> bool:
        service_name = resolve_approved_service_name(service_id)
        status = win32serviceutil.QueryServiceStatus(service_name)
        return bool(status[1] == win32service.SERVICE_RUNNING)


class WindowsMetadataAttributeController(MetadataAttributeController):
    """Real Windows file-attribute bits (hidden/read-only) via pywin32's
    win32file — the subset of CHANGE_VISIBLE_METADATA's approved fields
    os.utime cannot set."""

    def apply(self, path, fields: dict) -> dict:
        prior: dict = {}
        if "hidden" not in fields and "read_only" not in fields:
            return prior
        attrs = win32file.GetFileAttributes(str(path))
        prior["hidden"] = bool(attrs & win32file.FILE_ATTRIBUTE_HIDDEN)
        prior["read_only"] = bool(attrs & win32file.FILE_ATTRIBUTE_READONLY)
        if "hidden" in fields:
            attrs = (
                attrs | win32file.FILE_ATTRIBUTE_HIDDEN
                if fields["hidden"]
                else attrs & ~win32file.FILE_ATTRIBUTE_HIDDEN
            )
        if "read_only" in fields:
            attrs = (
                attrs | win32file.FILE_ATTRIBUTE_READONLY
                if fields["read_only"]
                else attrs & ~win32file.FILE_ATTRIBUTE_READONLY
            )
        win32file.SetFileAttributes(str(path), attrs)
        return prior
