"""MirageEnvironmentController's exact on-disk/registry layout and
restricted-privilege configuration (Appendix G): "Account: Dedicated
restricted service account... Privilege: Only approved mutation dirs/
services... Never: Runs as LocalSystem." Mirrors
`mirage_spider.config.SpiderPaths` structurally; the account and allowed-
mutation-roots fields are new (Spider never mutates anything).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

SERVICE_NAME = "MirageEnvironmentController"
SERVICE_DISPLAY_NAME = "Mirage Environment Controller"
EVENT_LOG_PROVIDER = "MirageEnvironmentController"

# A dedicated restricted account, never LocalSystem and never LocalService
# (LocalService is Spider's read-only account per Appendix G's own table —
# the Controller needs a DIFFERENT, still-restricted account because it
# mutates files, unlike Spider). The real account is provisioned by the
# golden image's install script (Step 9a's placeholder
# install-mirage-env-controller.ps1, added once this module exists); this
# constant documents the contract that installer must satisfy.
SERVICE_ACCOUNT = "MirageSandbox\\svc-mirage-envctl"

REGISTRY_ROOT = r"SOFTWARE\Mirage\EnvironmentController"
REGISTRY_KEY_AGENT_ID = "AgentId"
REGISTRY_KEY_CERT_THUMBPRINT = "CertificateThumbprint"
REGISTRY_KEY_ENROLLED_AT = "EnrolledAt"

CERT_STORE_LOCATION = "LocalMachine"
CERT_STORE_NAME = "Mirage"

DEFAULT_PROGRAM_FILES = r"C:\Program Files\Mirage\EnvironmentController"
DEFAULT_PROGRAMDATA = r"C:\ProgramData\Mirage\EnvironmentController"

# Appendix G: "Privilege: Only approved mutation dirs/services." The
# executor (actions.py) refuses to touch any path outside these roots,
# regardless of what a command's params request — this is the "restricted
# privilege" enforced in code, not merely by OS ACLs (defense in depth,
# same reasoning ADR-0013 already applied to certificate revocation).
DEFAULT_ALLOWED_MUTATION_ROOTS = (
    r"C:\Mirage\DecoyContent",
    r"C:\Users\Public\Mirage",
)


@dataclass(frozen=True)
class ControllerPaths:
    program_files: Path
    programdata: Path
    allowed_mutation_roots: tuple[Path, ...] = field(default_factory=tuple)

    @property
    def logs_dir(self) -> Path:
        return self.programdata / "Logs"

    @property
    def journal_db(self) -> Path:
        return self.programdata / "Journal" / "journal.db"

    @property
    def config_file(self) -> Path:
        return self.programdata / "config.yaml"

    @classmethod
    def from_env(cls) -> ControllerPaths:
        roots_env = os.environ.get("MIRAGE_ENVCTL_ALLOWED_ROOTS", "")
        roots = tuple(Path(p) for p in roots_env.split(os.pathsep) if p) or tuple(
            Path(p) for p in DEFAULT_ALLOWED_MUTATION_ROOTS
        )
        return cls(
            program_files=Path(os.environ.get("MIRAGE_ENVCTL_PROGRAM_FILES", DEFAULT_PROGRAM_FILES)),
            programdata=Path(os.environ.get("MIRAGE_ENVCTL_PROGRAMDATA", DEFAULT_PROGRAMDATA)),
            allowed_mutation_roots=roots,
        )

    @classmethod
    def for_testing(cls, root: Path, *, allowed_mutation_roots: tuple[Path, ...] | None = None) -> ControllerPaths:
        mutation_roots = allowed_mutation_roots if allowed_mutation_roots is not None else (root / "DecoyContent",)
        return cls(program_files=root / "ProgramFiles", programdata=root / "ProgramData", allowed_mutation_roots=mutation_roots)
