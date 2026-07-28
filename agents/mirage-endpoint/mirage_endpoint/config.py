"""MirageEndpoint exact on-disk/registry layout (Step 4 requirement: "Define
exact paths: Program files, ProgramData, Logs, Queue, Certificate store,
Registry keys, Service name, Event-log provider").

Production values are real Windows paths; overridable via environment
variables so the SAME dataclass is usable in local dev/tests on macOS/Linux
without conditional code scattered through the rest of the agent.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SERVICE_NAME = "MirageEndpoint"
SERVICE_DISPLAY_NAME = "Mirage Endpoint Telemetry Service"
EVENT_LOG_PROVIDER = "MirageEndpoint"

# Registry keys (HKLM) — configuration + enrollment state. Never the private
# key itself (that lives in the Windows certificate store, see below).
REGISTRY_ROOT = r"SOFTWARE\Mirage\Endpoint"
REGISTRY_KEY_AGENT_ID = "AgentId"
REGISTRY_KEY_CERT_THUMBPRINT = "CertificateThumbprint"
REGISTRY_KEY_ENROLLED_AT = "EnrolledAt"

# Certificate store: local machine "Mirage" store (created by the MSI),
# never CurrentUser (this is a machine-wide LocalService-run agent).
CERT_STORE_LOCATION = "LocalMachine"
CERT_STORE_NAME = "Mirage"

DEFAULT_PROGRAM_FILES = r"C:\Program Files\Mirage\Endpoint"
DEFAULT_PROGRAMDATA = r"C:\ProgramData\Mirage\Endpoint"


@dataclass(frozen=True)
class EndpointPaths:
    program_files: Path
    programdata: Path

    @property
    def logs_dir(self) -> Path:
        return self.programdata / "Logs"

    @property
    def queue_db(self) -> Path:
        return self.programdata / "Queue" / "queue.db"

    @property
    def queue_key(self) -> Path:
        return self.programdata / "Queue" / "queue.key.protected"

    @property
    def config_file(self) -> Path:
        return self.programdata / "config.yaml"

    @classmethod
    def from_env(cls) -> EndpointPaths:
        return cls(
            program_files=Path(os.environ.get("MIRAGE_ENDPOINT_PROGRAM_FILES", DEFAULT_PROGRAM_FILES)),
            programdata=Path(os.environ.get("MIRAGE_ENDPOINT_PROGRAMDATA", DEFAULT_PROGRAMDATA)),
        )

    @classmethod
    def for_testing(cls, root: Path) -> EndpointPaths:
        return cls(program_files=root / "ProgramFiles", programdata=root / "ProgramData")
