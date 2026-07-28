"""Local-queue encryption key sourcing, shared by every Windows agent
(MirageEndpoint, MirageSpider — Step 4/Step 5).

Production (Windows): the service's local encrypted queue key is protected
via DPAPI (`CryptProtectData`), scoped to the machine (`LocalSystem`/service
account), so the encrypted blob on disk is useless off that specific
Windows host even if exfiltrated. Import-guarded — `pywin32` only exists on
Windows (ADR-0002).

Development/test (any OS): a key file with restrictive permissions,
functionally equivalent for local testing but NOT what ships.
"""
from __future__ import annotations

import os
import stat
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.fernet import Fernet


class KeyProvider(ABC):
    @abstractmethod
    def get_or_create_key(self) -> bytes: ...


class LocalFileKeyProvider(KeyProvider):
    """Dev/test only. Real deployments use DpapiKeyProvider."""

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path

    def get_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        if os.name != "nt":
            os.chmod(self.key_path, stat.S_IRUSR | stat.S_IWUSR)
        return key


class DpapiKeyProvider(KeyProvider):
    """Windows-only. Encrypts a freshly-generated Fernet key at rest via
    DPAPI (CryptProtectData with no additional entropy — scoped to the
    local machine, matching a LocalService-run agent's threat model: an
    attacker who cannot execute code on THIS host as a privileged user
    cannot decrypt the queue even with the raw file)."""

    def __init__(self, protected_key_path: Path, *, description: str = "mirage-agent-queue-key") -> None:
        self.protected_key_path = protected_key_path
        self.description = description

    def get_or_create_key(self) -> bytes:
        import win32crypt  # noqa: PLC0415 -- Windows-only import, deliberately deferred

        if self.protected_key_path.exists():
            blob = self.protected_key_path.read_bytes()
            _desc, key = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
            return key

        key = Fernet.generate_key()
        blob = win32crypt.CryptProtectData(key, self.description, None, None, None, 0)
        self.protected_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.protected_key_path.write_bytes(blob)
        return key
