"""MirageSpider's exact on-disk/registry layout (Appendix G: same category of
"exact paths" requirement Step 4 specified for MirageEndpoint). Mirrors
`mirage_endpoint.config.EndpointPaths` exactly, with Spider's own
service/account identity — notably: LocalService, never LocalMachine-wide
write access, matching Appendix G's "Privilege: Read telemetry only /
Never: writes to sandbox, runs as LocalSystem."
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SERVICE_NAME = "MirageSpider"
SERVICE_DISPLAY_NAME = "Mirage Spider Sandbox Sensing Service"
EVENT_LOG_PROVIDER = "MirageSpider"

# Read-only, LocalService — never LocalSystem (Appendix G). The MSI grants
# this account read access to telemetry sources only; it owns nothing else
# on the sandbox host.
SERVICE_ACCOUNT = "NT AUTHORITY\\LocalService"

REGISTRY_ROOT = r"SOFTWARE\Mirage\Spider"
REGISTRY_KEY_AGENT_ID = "AgentId"
REGISTRY_KEY_CERT_THUMBPRINT = "CertificateThumbprint"
REGISTRY_KEY_ENROLLED_AT = "EnrolledAt"

CERT_STORE_LOCATION = "LocalMachine"
CERT_STORE_NAME = "Mirage"

DEFAULT_PROGRAM_FILES = r"C:\Program Files\Mirage\Spider"
DEFAULT_PROGRAMDATA = r"C:\ProgramData\Mirage\Spider"


@dataclass(frozen=True)
class SpiderPaths:
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
    def from_env(cls) -> SpiderPaths:
        return cls(
            program_files=Path(os.environ.get("MIRAGE_SPIDER_PROGRAM_FILES", DEFAULT_PROGRAM_FILES)),
            programdata=Path(os.environ.get("MIRAGE_SPIDER_PROGRAMDATA", DEFAULT_PROGRAMDATA)),
        )

    @classmethod
    def for_testing(cls, root: Path) -> SpiderPaths:
        return cls(program_files=root / "ProgramFiles", programdata=root / "ProgramData")
