"""Signature trust anchor tests (F-01 / Priority 11).

Proves that Mirage's signed-package verifiers (release, install report,
evidence export, report package, acceptance package) never establish trust
from a key embedded in the package under verification — trust must always
come from something external: an explicit key, or a trust-store directory
whose contents the verifying party controls independently of the package.

The core adversarial scenario every one of these tests defends against:
an attacker modifies a signed package, generates their own keypair, re-signs
the modified content, and embeds their own public key at the path the format
expects. A verifier that falls back to "whatever key is embedded" would
report this tampered package as valid. These verifiers must not.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mirage_common.acceptance import run_local_acceptance, verify_acceptance_package
from mirage_common.release import build_release, verify_release
from mirage_common.trust_anchor import fingerprint, resolve_trusted_key
from mirage_contracts.envelope import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[2]


def _keypair(path: Path) -> tuple[Path, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return path, public_bytes


# --- resolve_trusted_key unit behaviour -------------------------------------


def test_fails_closed_with_no_explicit_key_and_no_trust_store(tmp_path: Path) -> None:
    empty_store = tmp_path / "empty-store"
    result = resolve_trusted_key(
        trust_store_dir=empty_store,
        embedded_key_bytes=b"whatever the package claims",
    )
    assert result.key_bytes is None
    assert any("no external trust anchor configured" in error for error in result.errors)


def test_explicit_key_always_wins_over_trust_store(tmp_path: Path) -> None:
    _, explicit_bytes = _keypair(tmp_path / "explicit.pem")
    result = resolve_trusted_key(
        explicit_key_bytes=explicit_bytes,
        trust_store_dir=tmp_path / "nonexistent-store",
        embedded_key_bytes=b"irrelevant",
    )
    assert result.key_bytes == explicit_bytes
    assert result.source == "explicit-key"
    assert not result.errors


def test_trust_store_matches_by_fingerprint_not_by_trusting_the_embedded_bytes(
    tmp_path: Path,
) -> None:
    store = tmp_path / "trust-store"
    store.mkdir()
    _, trusted_bytes = _keypair(tmp_path / "trusted.pem")
    (store / "release-signer.pem").write_bytes(trusted_bytes)
    result = resolve_trusted_key(trust_store_dir=store, embedded_key_bytes=trusted_bytes)
    assert result.ok
    assert result.key_bytes == trusted_bytes
    assert result.source == "trust-store"
    assert result.fingerprint == fingerprint(trusted_bytes)


def test_trust_store_rejects_a_fingerprint_it_does_not_contain(tmp_path: Path) -> None:
    store = tmp_path / "trust-store"
    store.mkdir()
    _, trusted_bytes = _keypair(tmp_path / "trusted.pem")
    (store / "release-signer.pem").write_bytes(trusted_bytes)
    _, attacker_bytes = _keypair(tmp_path / "attacker.pem")
    result = resolve_trusted_key(trust_store_dir=store, embedded_key_bytes=attacker_bytes)
    assert result.key_bytes is None
    assert any("not in the trusted store" in error for error in result.errors)


def test_revoked_fingerprint_is_rejected_even_if_present_in_store(tmp_path: Path) -> None:
    store = tmp_path / "trust-store"
    store.mkdir()
    _, trusted_bytes = _keypair(tmp_path / "trusted.pem")
    (store / "release-signer.pem").write_bytes(trusted_bytes)
    (store / "revoked.json").write_text(json.dumps([fingerprint(trusted_bytes)]))
    result = resolve_trusted_key(trust_store_dir=store, embedded_key_bytes=trusted_bytes)
    assert result.key_bytes is None
    assert any("revoked" in error for error in result.errors)


def test_trust_store_supports_rotation_with_multiple_valid_keys(tmp_path: Path) -> None:
    store = tmp_path / "trust-store"
    store.mkdir()
    _, old_bytes = _keypair(tmp_path / "old.pem")
    _, new_bytes = _keypair(tmp_path / "new.pem")
    (store / "old-signer.pem").write_bytes(old_bytes)
    (store / "new-signer.pem").write_bytes(new_bytes)
    for candidate in (old_bytes, new_bytes):
        result = resolve_trusted_key(trust_store_dir=store, embedded_key_bytes=candidate)
        assert result.ok, result.errors


# --- end-to-end adversarial scenario against a real verifier ---------------


def test_attacker_cannot_forge_trust_by_re_signing_with_their_own_embedded_key(
    tmp_path: Path,
) -> None:
    """The exact attack Priority 11 describes: attacker takes a legitimately
    released package, modifies a file, regenerates their own keypair, signs
    the modified manifest with it, and embeds their own public key at the
    path the release format expects. An operator who has a trust store
    containing only the REAL release key must reject this package outright —
    unlike the old behavior, where omitting `--public-key` fell back to
    whatever key the package itself carried."""
    real_key_path, real_public_bytes = _keypair(tmp_path / "real-release-key.pem")
    legitimate_package = tmp_path / "mirage-release.zip"
    build_release(ROOT, version="1.0.0-test", output=legitimate_package, signing_key=real_key_path)

    attacker_key_path, attacker_public_bytes = _keypair(tmp_path / "attacker-key.pem")
    forged_package = tmp_path / "mirage-release-forged.zip"
    attacker_private_key = serialization.load_pem_private_key(
        attacker_key_path.read_bytes(), password=None
    )
    with (
        zipfile.ZipFile(legitimate_package, "r") as source,
        zipfile.ZipFile(forged_package, "w") as target,
    ):
        manifest_bytes = source.read("release-manifest.json")
        manifest = json.loads(manifest_bytes)
        # Attacker tampers with a real file's content but leaves the manifest's
        # claimed hash alone, then re-signs the (now internally consistent
        # with itself, but not with reality) manifest with their own key —
        # the strongest-case attack, not a sloppy one.
        tampered_config = b"tampered-config-payload"
        manifest["files"]["config/schema.json"] = {
            "sha256": hashlib.sha256(tampered_config).hexdigest(),
            "size_bytes": len(tampered_config),
        }
        new_manifest_bytes = canonical_json_bytes(manifest)
        forged_signature = attacker_private_key.sign(
            new_manifest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        for name in source.namelist():
            if name == "release-manifest.json":
                target.writestr(name, new_manifest_bytes)
            elif name == "release-manifest.sig":
                target.writestr(name, forged_signature)
            elif name == "public-keys/release-signing.pem":
                target.writestr(name, attacker_public_bytes)
            elif name == "config/schema.json":
                target.writestr(name, tampered_config)
            else:
                target.writestr(name, source.read(name))

    trust_store = tmp_path / "operator-trust-store"
    trust_store.mkdir()
    (trust_store / "release-signer.pem").write_bytes(real_public_bytes)

    # The legitimate package verifies fine against the real trust store.
    legitimate_result = verify_release(legitimate_package, trust_store_dir=trust_store)
    assert legitimate_result["valid"], legitimate_result["errors"]

    # The forged package — internally self-consistent, signed by a real key,
    # with a real embedded public key — must still fail, because that key's
    # fingerprint is not the one the operator trusts.
    forged_result = verify_release(forged_package, trust_store_dir=trust_store)
    assert not forged_result["valid"]
    assert any(
        "not in the trusted store" in error or "no external trust anchor" in error
        for error in forged_result["errors"]
    )

    # Also confirm: verifying with no trust configuration at all (the old
    # default-fallback behavior) must fail closed rather than silently
    # trusting the attacker's embedded key.
    no_trust_result = verify_release(forged_package, trust_store_dir=tmp_path / "no-such-dir")
    assert not no_trust_result["valid"]


def test_acceptance_package_self_signed_replacement_is_rejected(tmp_path: Path) -> None:
    """Same attack shape against the acceptance package format: an attacker
    who possesses a completed acceptance package cannot simply replace its
    embedded key and re-sign to make an operator's independent verification
    pass, if that operator supplies (or has configured) a real trust anchor."""
    output = tmp_path / "acceptance"
    result = run_local_acceptance(output)
    assert result["independent_verification"]["valid"] is True
    package = output / "acceptance-package.zip"

    with zipfile.ZipFile(package) as archive:
        real_public_bytes = archive.read("acceptance-public-key.pem")

    attacker_key_path, attacker_public_bytes = _keypair(tmp_path / "attacker-key.pem")
    attacker_private_key = serialization.load_pem_private_key(
        attacker_key_path.read_bytes(), password=None
    )
    forged = tmp_path / "forged-acceptance-package.zip"
    with zipfile.ZipFile(package, "r") as source, zipfile.ZipFile(forged, "w") as target:
        manifest_bytes = source.read("acceptance-manifest.json")
        manifest = json.loads(manifest_bytes)
        new_manifest_bytes = canonical_json_bytes(manifest)
        forged_signature = attacker_private_key.sign(
            new_manifest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        for name in source.namelist():
            if name == "acceptance-manifest.sig":
                target.writestr(name, forged_signature)
            elif name == "acceptance-public-key.pem":
                target.writestr(name, attacker_public_bytes)
            else:
                target.writestr(name, source.read(name))

    trust_store = tmp_path / "operator-trust-store"
    trust_store.mkdir()
    (trust_store / "acceptance-signer.pem").write_bytes(real_public_bytes)

    forged_verification = verify_acceptance_package(forged, trust_store_dir=trust_store)
    assert not forged_verification["valid"]

    no_trust_verification = verify_acceptance_package(forged)
    assert not no_trust_verification["valid"]


def test_default_trust_store_env_var_is_respected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / "env-configured-store"
    store.mkdir()
    _, trusted_bytes = _keypair(tmp_path / "trusted.pem")
    (store / "signer.pem").write_bytes(trusted_bytes)
    monkeypatch.setenv("MIRAGE_TRUST_STORE_DIR", str(store))
    result = resolve_trusted_key(embedded_key_bytes=trusted_bytes)
    assert result.ok
    assert result.source == "trust-store"
