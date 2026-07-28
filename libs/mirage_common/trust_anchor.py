"""External trust anchor resolution for Mirage signature verification.

A signed package (release, evidence export, report, acceptance, or install
report) must never establish its own trust root. Every verifier in this
project must compare the signature against a public key sourced from
OUTSIDE the package being verified — an explicit `--trusted-public-key` file,
or a trust-store directory of independently-distributed trusted keys — never
against a public key merely because it was found inside the archive under
verification.

The embedded key a package carries (e.g. `public-keys/release-signing.pem`)
remains useful as informational signer metadata and as a fingerprint to look
up in the trust store, but its BYTES are never used for cryptographic
verification unless an external source vouches for that exact fingerprint.
This is what stops the attack: attacker generates a new keypair, modifies a
package, re-signs it, and embeds their own public key — the fingerprint of
that attacker key will not appear in any externally-configured trust store,
so verification fails regardless of what the attacker put inside the ZIP.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

TRUST_STORE_ENV_VAR = "MIRAGE_TRUST_STORE_DIR"
DEFAULT_TRUST_STORE_DIR = Path("/etc/mirage/trust/release-keys")
REVOKED_FILENAME = "revoked.json"


def fingerprint(key_bytes: bytes) -> str:
    """SHA-256 fingerprint of raw PEM public key bytes."""
    return hashlib.sha256(key_bytes).hexdigest()


@dataclass(frozen=True)
class TrustResolution:
    key_bytes: bytes | None
    fingerprint: str | None
    source: str | None  # "explicit-key" | "trust-store"
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.key_bytes is not None and not self.errors


def _load_trust_store(trust_store_dir: Path) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    if not trust_store_dir.is_dir():
        return keys
    for path in sorted(trust_store_dir.glob("*.pem")):
        data = path.read_bytes()
        keys[fingerprint(data)] = data
    return keys


def _load_revoked(trust_store_dir: Path) -> frozenset[str]:
    revoked_path = trust_store_dir / REVOKED_FILENAME
    if not revoked_path.is_file():
        return frozenset()
    try:
        payload = json.loads(revoked_path.read_text())
    except json.JSONDecodeError:
        return frozenset()
    if not isinstance(payload, list):
        return frozenset()
    return frozenset(str(item) for item in payload)


def resolve_trust_store_dir(trust_store_dir: Path | None) -> Path:
    if trust_store_dir is not None:
        return trust_store_dir
    env_value = os.environ.get(TRUST_STORE_ENV_VAR)
    return Path(env_value) if env_value else DEFAULT_TRUST_STORE_DIR


def resolve_trusted_key(
    *,
    explicit_key_bytes: bytes | None = None,
    trust_store_dir: Path | None = None,
    embedded_key_bytes: bytes | None,
) -> TrustResolution:
    """Resolve the key bytes to use for cryptographic verification.

    `explicit_key_bytes` (from a caller-supplied `--trusted-public-key` file)
    always wins and is used as-is — the caller has already vouched for it.

    Otherwise, `embedded_key_bytes` (whatever the package under verification
    claims its signer key is) is used ONLY to compute a fingerprint, which
    must match a key already present in the trust store. The KEY BYTES
    RETURNED are the trust store's own copy, never the package's copy.

    If no explicit key is given and the trust store has no keys at all (not
    configured), verification fails closed rather than silently trusting the
    package's embedded key.
    """
    if explicit_key_bytes is not None:
        return TrustResolution(explicit_key_bytes, fingerprint(explicit_key_bytes), "explicit-key", ())

    store_dir = resolve_trust_store_dir(trust_store_dir)
    trusted_keys = _load_trust_store(store_dir)
    if not trusted_keys:
        return TrustResolution(
            None,
            None,
            None,
            (
                "no external trust anchor configured: pass --trusted-public-key, "
                f"or populate a trust store directory ({store_dir}) with trusted "
                "public keys — a package's own embedded key is never trusted "
                "by default",
            ),
        )

    if embedded_key_bytes is None:
        return TrustResolution(None, None, None, ("package has no signer key to match against the trust store",))

    embedded_fingerprint = fingerprint(embedded_key_bytes)
    revoked = _load_revoked(store_dir)
    if embedded_fingerprint in revoked:
        return TrustResolution(None, embedded_fingerprint, None, (f"signer key is revoked: {embedded_fingerprint}",))
    if embedded_fingerprint not in trusted_keys:
        return TrustResolution(
            None,
            embedded_fingerprint,
            None,
            (f"signer key fingerprint is not in the trusted store: {embedded_fingerprint}",),
        )
    return TrustResolution(trusted_keys[embedded_fingerprint], embedded_fingerprint, "trust-store", ())
