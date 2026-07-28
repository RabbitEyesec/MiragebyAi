"""Windows service shim — the ONLY module in mirage_endpoint that imports
pywin32 (ADR-0002). Deliberately thin: every behavior lives in
service_logic.py / queue.py / client.py, all importable and tested on any
OS. This file cannot be imported or run outside Windows and is therefore
LAB_VERIFICATION_REQUIRED — see LAB_EXECUTION_CHECKLIST.md.

Installed as a Windows service named config.SERVICE_NAME running under the
LocalService/dedicated account configured by the MSI (installers/endpoint).
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time

if sys.platform != "win32":
    raise ImportError("mirage_endpoint.win_service is Windows-only — see ADR-0002")

import servicemanager
import win32event
import win32service
import win32serviceutil

from mirage_common.agent_http_client import AgentHttpClient
from mirage_common.agent_keys import DpapiKeyProvider
from mirage_common.agent_queue import EncryptedEventQueue
from mirage_endpoint.config import SERVICE_DISPLAY_NAME, SERVICE_NAME, EndpointPaths
from mirage_endpoint.service_logic import EndpointServiceLogic

HEARTBEAT_INTERVAL_SECONDS = 30
QUEUE_FLUSH_INTERVAL_SECONDS = 5


class MirageEndpointService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = "Streams Sysmon and endpoint telemetry to the Mirage control plane."

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
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._running = True
        self._worker_thread = threading.Thread(target=self._run_asyncio_loop, daemon=True)
        self._worker_thread.start()
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)

    def _run_asyncio_loop(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        paths = EndpointPaths.from_env()
        paths.logs_dir.mkdir(parents=True, exist_ok=True)
        (paths.programdata / "Queue").mkdir(parents=True, exist_ok=True)

        key_provider = DpapiKeyProvider(paths.queue_key, description="mirage-endpoint-queue-key")
        queue = EncryptedEventQueue(paths.queue_db, key_provider)

        client = AgentHttpClient(base_url=_read_control_plane_url(paths), root_ca_path=_read_root_ca_path(paths))
        logic = EndpointServiceLogic(
            client=client,
            queue=queue,
            identity_state_path=paths.programdata / "identity.json",
            cert_dir=paths.programdata / "certs",
            build_hash=_read_build_hash(),
        )

        if not logic.is_enrolled():
            token = _read_bootstrap_enrollment_token(paths)
            await logic.enroll(enrollment_token=token)

        identity = logic.load_identity()
        started_at = time.monotonic()

        while self._running:
            uptime = int(time.monotonic() - started_at)
            try:
                await logic.send_heartbeat(identity, uptime_seconds=uptime)
            except Exception:  # noqa: BLE001 -- never let a heartbeat failure kill the service loop
                servicemanager.LogErrorMsg("MirageEndpoint heartbeat failed; will retry")

            # MirageEndpoint's own local queue has no concrete producer of
            # real telemetry yet (Sysmon/OS telemetry ships via the separate
            # Elastic Agent -> Fleet path per the topology table, not through
            # this queue) — the transport this would call now exists for
            # real (mirage_common.agent_http_client.AgentHttpClient.submit_telemetry,
            # built for Step 5/MirageSpider, identical wire contract), it
            # simply has nothing genuine to send from this agent yet.
            logic.flush_queue(lambda event: True)

            for _ in range(HEARTBEAT_INTERVAL_SECONDS):
                if not self._running:
                    break
                time.sleep(1)


def _read_control_plane_url(paths: EndpointPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["control_plane_url"]


def _read_root_ca_path(paths: EndpointPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["root_ca_path"]


def _read_build_hash() -> str:
    # Stamped into the MSI at build time (installers/endpoint/build.ps1) —
    # the running binary's own SHA-256, matching Step 3's build-hash allowlist.
    from mirage_endpoint import __build_hash__

    return __build_hash__


def _read_bootstrap_enrollment_token(paths: EndpointPaths) -> str:
    import yaml

    return yaml.safe_load(paths.config_file.read_text())["bootstrap_enrollment_token"]


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(MirageEndpointService)
