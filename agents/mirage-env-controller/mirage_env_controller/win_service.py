"""Windows service shim — the ONLY module in mirage_env_controller that
imports pywin32 (ADR-0002 pattern). Everything behavioral lives in
service_logic.py / actions.py / journal.py, all importable and tested on
any OS. This file cannot be imported or run outside Windows and is
therefore LAB_VERIFICATION_REQUIRED — see LAB_EXECUTION_CHECKLIST.md.

Installed under config.SERVICE_ACCOUNT — a dedicated restricted account,
never LocalSystem (Appendix G). The account itself and its filesystem/
service ACL grants are provisioned by the golden image's own installer
(Step 9a's install-mirage-env-controller.ps1 placeholder), not by this
Python process — a service cannot grant itself privilege it doesn't already
hold.

Interlock design (Appendix G: "If the Spider fails, adaptive actions
freeze. The two are never combined."): before serving any command, the
main loop checks the paired MirageSpider agent's own liveness
(`agents.last_seen_at`, the exact row mirage-api's health rollup already
reads) via the SAME control-plane the Controller already talks to — no new
mechanism, no direct Spider<->Controller channel, matching the spec's "the
two are never combined."
"""
from __future__ import annotations

import asyncio
import sys
import threading

if sys.platform != "win32":
    raise ImportError("mirage_env_controller.win_service is Windows-only — see ADR-0002")

import servicemanager
import win32event
import win32service
import win32serviceutil

from mirage_common.agent_http_client import AgentHttpClient
from mirage_env_controller.actions import ExecutorContext
from mirage_env_controller.config import SERVICE_DISPLAY_NAME, SERVICE_NAME, ControllerPaths
from mirage_env_controller.journal import ActionJournal
from mirage_env_controller.service_logic import EnvControllerServiceLogic
from mirage_env_controller.windows_actions import (
    WindowsDecoyServiceController,
    WindowsMetadataAttributeController,
)

RECONNECT_BACKOFF_SECONDS = 5


class MirageEnvironmentControllerService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = "Executes structured, policy-restricted sandbox mutation actions on behalf of the Mirage control plane."

    def __init__(self, args) -> None:
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._worker_thread: threading.Thread | None = None
        self._running = False

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self) -> None:
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""),
        )
        self._running = True
        self._worker_thread = threading.Thread(target=self._run_asyncio_loop, daemon=True)
        self._worker_thread.start()
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)

    def _run_asyncio_loop(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        paths = ControllerPaths.from_env()
        paths.logs_dir.mkdir(parents=True, exist_ok=True)
        for root in paths.allowed_mutation_roots:
            root.mkdir(parents=True, exist_ok=True)

        journal = ActionJournal(paths.journal_db)
        ctx = ExecutorContext(
            allowed_roots=paths.allowed_mutation_roots,
            programdata=paths.programdata,
            journal=journal,
            # Real Windows Service Control Manager / file-attribute control —
            # never the portable marker-file/no-op development defaults
            # (Priority 8: no marker-file simulation of a real action on a
            # real Windows host).
            decoy_service_controller=WindowsDecoyServiceController(),
            metadata_attribute_controller=WindowsMetadataAttributeController(),
        )

        client = AgentHttpClient(base_url=_read_control_plane_url(paths), root_ca_path=_read_root_ca_path(paths))
        logic = EnvControllerServiceLogic(
            client=client, identity_state_path=paths.programdata / "identity.json",
            cert_dir=paths.programdata / "certs", build_hash=_read_build_hash(), ctx=ctx,
        )

        if not logic.is_enrolled():
            token = _read_bootstrap_enrollment_token(paths)
            await logic.enroll(enrollment_token=token)

        identity = logic.load_identity()
        gateway_ws_url = _read_gateway_ws_url(paths)
        proxy_headers = _read_proxy_headers(paths, identity)

        while self._running:
            try:
                await logic.connect_and_serve(gateway_ws_url, additional_headers=proxy_headers)
            except Exception:  # noqa: BLE001 -- a dropped connection reconnects; it never crashes the service
                servicemanager.LogErrorMsg("MirageEnvironmentController lost connection to mirage-sandbox-gateway; reconnecting")
            for _ in range(RECONNECT_BACKOFF_SECONDS):
                if not self._running:
                    break
                import time

                time.sleep(1)


def _read_control_plane_url(paths: ControllerPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["control_plane_url"]


def _read_root_ca_path(paths: ControllerPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["root_ca_path"]


def _read_gateway_ws_url(paths: ControllerPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["sandbox_gateway_ws_url"]


def _read_build_hash() -> str:
    from mirage_env_controller import __build_hash__

    return __build_hash__


def _read_bootstrap_enrollment_token(paths: ControllerPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["bootstrap_enrollment_token"]


def _read_proxy_headers(paths: ControllerPaths, identity) -> dict:
    """mirage-sandbox-gateway's WS endpoint authenticates the same way every
    other mTLS-fronted Mirage endpoint does (Nginx terminates TLS, forwards
    the verified serial via a header — mtls_auth.py's documented contract,
    reused here rather than inventing a second auth mechanism for WS)."""
    import yaml

    from mirage_common.mtls_auth import CLIENT_SERIAL_HEADER, PROXY_SHARED_SECRET_HEADER

    cfg = yaml.safe_load(paths.config_file.read_text())
    return {CLIENT_SERIAL_HEADER: identity.certificate_serial, PROXY_SHARED_SECRET_HEADER: cfg["proxy_shared_secret"]}


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(MirageEnvironmentControllerService)
