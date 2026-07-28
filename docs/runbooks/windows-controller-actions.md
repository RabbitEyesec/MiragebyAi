# Windows controller actions

## What changed

`ENABLE_DECOY_SERVICE`/`DISABLE_DECOY_SERVICE` and CHANGE_VISIBLE_METADATA's
Windows-specific attribute fields (hidden/read-only) previously had no real
Windows implementation at all — only a portable marker-file stand-in
(`_decoy_services/<id>.enabled`) and `os.utime`-only timestamp support.
Real implementations now exist behind a platform abstraction, matching the
same ADR-0002 pattern `win_service.py` already established:

- `mirage_env_controller.actions.DecoyServiceController` /
  `MetadataAttributeController` — the portable interfaces.
- `mirage_env_controller.actions.MarkerFileDecoyServiceController` /
  `NoopMetadataAttributeController` — the development/non-Windows defaults
  (unchanged behavior from before this fix, just formalized as explicit
  classes instead of inline marker-file code).
- `mirage_env_controller.windows_actions.WindowsDecoyServiceController` /
  `WindowsMetadataAttributeController` — real `win32serviceutil`
  StartService/StopService/QueryServiceStatus and `win32file`
  GetFileAttributes/SetFileAttributes calls. Windows-only (same
  `sys.platform != "win32"` import guard as `win_service.py`); wired into
  `ExecutorContext` construction in `win_service.py` so a real Windows
  service actually uses them, never the marker-file/no-op defaults.

## The approved-service allowlist

Only `mirage_env_controller.actions.APPROVED_DECOY_SERVICES` entries may
ever be targeted — an unregistered `service_id` is rejected (`REJECTED`,
not `FAILED`) before any Windows API call is attempted, by both the
development and the Windows controller (the allowlist check lives in the
cross-platform `resolve_approved_service_name()`, not duplicated per
controller). Add a new decoy service by registering it on the golden image
(Packer provisioner) and adding its `service_id -> Windows service name`
mapping here.

## Tests

`tests/unit/test_env_controller_actions.py` proves, without any Windows
host or pywin32 mock:

- Enable/disable round-trips through the marker-file controller.
- An unregistered `service_id` is rejected before touching the filesystem.
- Rolling back a `DISABLE_DECOY_SERVICE` action re-enables the service via
  the same controller the original action used.
- `CHANGE_VISIBLE_METADATA`'s Windows-specific fields are delegated to
  whatever `metadata_attribute_controller` is configured (proven with a
  fake controller standing in for the real Windows one).

`windows_actions.py` itself cannot be imported or executed on this
platform (same constraint as `win_service.py`) — it is statically
typechecked (`make typecheck` includes it; `pyproject.toml`'s mypy
overrides list `win32file`/`pywintypes` alongside the pre-existing pywin32
stub modules) but its actual Windows API calls are
`WINDOWS_VERIFICATION_REQUIRED`.

## What's still lab work

Real SCM state changes, ACL application on the golden image's dedicated
service account, and file-attribute verification against a real decoy file
on a real Windows sandbox remain `WINDOWS_VERIFICATION_REQUIRED` — this fix
replaces marker-file simulation with real, reviewable Windows API call code
and a real cross-platform-testable policy/rollback/audit pipeline around
it, not a claim that it has been exercised against a live Windows host.
