"""Deterministic Mirage release bundle construction and offline verification."""
from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mirage_common.trust_anchor import resolve_trusted_key
from mirage_contracts.envelope import canonical_json_bytes

RELEASE_MANIFEST_VERSION = "mirage-release/1.0"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def build_release(
    root: Path,
    *,
    version: str,
    output: Path,
    signing_key: Path,
    endpoint_package: Path | None = None,
    sandbox_package: Path | None = None,
) -> dict[str, Any]:
    if not version or any(character not in "0123456789.-abcdefghijklmnopqrstuvwxyz" for character in version.lower()):
        raise ValueError("version contains unsupported characters")
    private_key = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 3072:
        raise ValueError("release signing key must be an RSA private key of at least 3072 bits")
    entries: dict[str, bytes] = {}
    for relative in (
        "scripts/install-server",
        "scripts/upgrade-server",
        "scripts/rollback-server",
        "scripts/uninstall-server",
        "scripts/verify-install-report",
        "scripts/install-mirage-package",
        "installers/endpoint/Product.wxs",
        "installers/endpoint/Bundle.wxs",
        "installers/endpoint/build.ps1",
        "installers/sandbox/Product.wxs",
        "installers/sandbox/bootstrap.ps1",
        "config/schema.json",
        "docs/runbooks/server-installer.md",
        "docs/runbooks/endpoint-installer.md",
        "docs/runbooks/sandbox-installer.md",
        "docs/runbooks/release-verification.md",
    ):
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(relative)
        entries[relative] = path.read_bytes()
    wheel_name, wheel_bytes = _build_wheel(root)
    entries[f"packages/{wheel_name}"] = wheel_bytes
    for name, optional_path in (
        ("packages/MirageEndpoint.msi", endpoint_package),
        ("packages/MirageSandbox.msi", sandbox_package),
    ):
        if optional_path is not None:
            entries[name] = optional_path.read_bytes()
    entries["manifests/contracts.json"] = canonical_json_bytes(
        _path_manifest(root, root / "schemas", "*.json")
    )
    entries["manifests/migrations.json"] = canonical_json_bytes(
        _path_manifest(root, root / "infra" / "migrations", "*.sql")
    )
    entries["sbom/mirage-source.cdx.json"] = canonical_json_bytes(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "mirage",
                    "version": version,
                }
            },
            "components": _dependency_components(root),
        }
    )
    entries["container-image-digests.json"] = canonical_json_bytes(
        {
            "images": [],
            "limitation": (
                "Image digests are populated by CI release builds; this source bundle "
                "does not claim that container images were pushed."
            ),
        }
    )
    entries["public-keys/release-signing.pem"] = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    entries["RELEASE-NOTES.md"] = (
        f"# Mirage {version}\n\n"
        "Controlled-lab release bundle. Verify signatures and hashes before installation.\n"
    ).encode()
    entries["UPGRADE.md"] = b"Run scripts/upgrade-server only after scripts/verify-release succeeds.\n"
    entries["ROLLBACK.md"] = b"Use scripts/rollback-server with the recorded prior release and explicit confirmation.\n"
    entries["KNOWN-LIMITATIONS.md"] = (
        b"Windows compilation, Authenticode signing, and Profile B acceptance are "
        b"LAB_VERIFICATION_REQUIRED until their result records say PASS.\n"
    )
    files = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
        for name, data in sorted(entries.items())
    }
    manifest = {
        "manifest_version": RELEASE_MANIFEST_VERSION,
        "release_version": version,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "builder_platform": platform.platform(),
        "files": files,
        "signature_algorithm": "RSA-PSS-SHA256",
    }
    manifest_bytes = canonical_json_bytes(manifest)
    signature = private_key.sign(
        manifest_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        _write(archive, "release-manifest.json", manifest_bytes)
        _write(archive, "release-manifest.sig", signature)
        for name, data in sorted(entries.items()):
            _write(archive, name, data)
    return {
        "path": str(output),
        "sha256": _sha256(output),
        "file_count": len(entries),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def verify_release(
    package: Path,
    *,
    public_key: Path | None = None,
    trust_store_dir: Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    with zipfile.ZipFile(package, "r") as archive:
        listed = archive.namelist()
        names = set(listed)
        if len(names) != len(listed):
            errors.append("duplicate ZIP member")
        required = {"release-manifest.json", "release-manifest.sig"}
        errors.extend(f"missing file: {name}" for name in sorted(required - names))
        if "release-manifest.json" not in names:
            return {"valid": False, "errors": errors}
        manifest_bytes = archive.read("release-manifest.json")
        manifest = json.loads(manifest_bytes)
        if canonical_json_bytes(manifest) != manifest_bytes:
            errors.append("release manifest is not canonical")
        if manifest.get("manifest_version") != RELEASE_MANIFEST_VERSION:
            errors.append("unsupported release manifest version")
        declared = manifest.get("files")
        if not isinstance(declared, dict):
            declared = {}
            errors.append("files manifest is invalid")
        expected = {"release-manifest.json", "release-manifest.sig", *declared}
        errors.extend(f"unexpected file: {name}" for name in sorted(names - expected))
        for name, detail in sorted(declared.items()):
            if name not in names:
                errors.append(f"missing file: {name}")
                continue
            data = archive.read(name)
            if hashlib.sha256(data).hexdigest() != detail.get("sha256"):
                errors.append(f"hash mismatch: {name}")
            if len(data) != detail.get("size_bytes"):
                errors.append(f"size mismatch: {name}")
        embedded_key_bytes = (
            archive.read("public-keys/release-signing.pem")
            if "public-keys/release-signing.pem" in names
            else None
        )
        trust = resolve_trusted_key(
            explicit_key_bytes=public_key.read_bytes() if public_key else None,
            trust_store_dir=trust_store_dir,
            embedded_key_bytes=embedded_key_bytes,
        )
        errors.extend(trust.errors)
        key_bytes = trust.key_bytes
        if key_bytes is None or "release-manifest.sig" not in names:
            errors.append("release signature verification could not proceed")
        else:
            key = serialization.load_pem_public_key(key_bytes)
            if not isinstance(key, rsa.RSAPublicKey):
                errors.append("release public key is not RSA")
            else:
                try:
                    key.verify(
                        archive.read("release-manifest.sig"),
                        manifest_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=hashes.SHA256().digest_size,
                        ),
                        hashes.SHA256(),
                    )
                except InvalidSignature:
                    errors.append("release signature mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "package_sha256": _sha256(package),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }


def generate_install_report(
    journal: Path,
    *,
    output: Path,
    signing_key: Path,
) -> dict[str, Any]:
    record = json.loads(journal.read_text())
    record["report_version"] = "mirage-install-report/1.0"
    record["generated_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    private_key = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < 3072:
        raise ValueError("install report signing key must be RSA 3072 bits or stronger")
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    record["signer_information"] = {
        "signature_algorithm": "RSA-PSS-SHA256",
        "public_key_sha256": hashlib.sha256(public_key_bytes).hexdigest(),
        "signature_member": "install-report.sig",
        "public_key_member": "public-key.pem",
    }
    required = (
        "installer_version",
        "package_sha256",
        "container_image_digests",
        "sbom_hashes",
        "configuration_sha256",
        "migration_versions",
        "contract_versions",
        "service_health",
        "synthetic_transaction_result",
        "installed_time",
        "host_fingerprint",
    )
    missing = [name for name in required if name not in record]
    if missing:
        raise ValueError(f"installation journal is missing report fields: {missing}")
    content = canonical_json_bytes(record)
    signature = private_key.sign(
        content,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        _write(archive, "install-report.json", content)
        _write(archive, "install-report.sig", signature)
        _write(
            archive,
            "public-key.pem",
            public_key_bytes,
        )
    return {"path": str(output), "sha256": _sha256(output)}


def verify_install_report(
    package: Path,
    *,
    public_key: Path | None = None,
    trust_store_dir: Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = {"install-report.json", "install-report.sig", "public-key.pem"}
    try:
        with zipfile.ZipFile(package) as archive:
            listed = archive.namelist()
            names = set(listed)
            if len(names) != len(listed):
                errors.append("duplicate ZIP member")
            errors.extend(f"missing file: {name}" for name in sorted(required - names))
            errors.extend(f"unexpected file: {name}" for name in sorted(names - required))
            if required - names:
                return {"valid": False, "errors": errors, "package_sha256": _sha256(package)}
            content = archive.read("install-report.json")
            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                report = {}
                errors.append("install report is not valid JSON")
            if report and canonical_json_bytes(report) != content:
                errors.append("install report is not canonical")
            embedded_key_bytes = archive.read("public-key.pem")
            trust = resolve_trusted_key(
                explicit_key_bytes=public_key.read_bytes() if public_key is not None else None,
                trust_store_dir=trust_store_dir,
                embedded_key_bytes=embedded_key_bytes,
            )
            errors.extend(trust.errors)
            key_bytes = trust.key_bytes
            if key_bytes is None:
                errors.append("install report signature verification could not proceed")
            else:
                key = serialization.load_pem_public_key(key_bytes)
                if not isinstance(key, rsa.RSAPublicKey):
                    errors.append("install report public key is not RSA")
                else:
                    try:
                        key.verify(
                            archive.read("install-report.sig"),
                            content,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=hashes.SHA256().digest_size,
                            ),
                            hashes.SHA256(),
                        )
                    except InvalidSignature:
                        errors.append("install report signature mismatch")
            signer = report.get("signer_information", {}) if isinstance(report, dict) else {}
            if key_bytes is not None and signer.get("public_key_sha256") != trust.fingerprint:
                errors.append("install report signer fingerprint mismatch")
            if signer.get("signature_algorithm") != "RSA-PSS-SHA256":
                errors.append("unsupported install report signature algorithm")
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        errors.append(f"invalid install report package: {exc}")
    return {
        "valid": not errors,
        "errors": errors,
        "package_sha256": _sha256(package),
    }


def _build_wheel(root: Path) -> tuple[str, bytes]:
    """Builds a real wheel of the whole `mirage` distribution
    (pyproject.toml's "one dependency set, one venv" packaging) and returns
    its (filename, bytes). Every release script (`scripts/install-server`
    etc.) does `from mirage_common... import ...` — those packages exist
    nowhere in this repository as something a clean host could just copy;
    they are only ever real once installed from this wheel. Without it, a
    release ZIP's own scripts cannot run on a server that has never seen
    this source tree, which defeats the entire point of a standalone
    release (see docs/runbooks/release-clean-room.md)."""
    with tempfile.TemporaryDirectory(prefix="mirage-release-wheel-") as wheel_dir:
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(root), "--no-deps", "-w", wheel_dir],
            check=True,
            capture_output=True,
        )
        wheels = list(Path(wheel_dir).glob("mirage-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected exactly one built mirage wheel, found {wheels}")
        return wheels[0].name, wheels[0].read_bytes()


def _path_manifest(root: Path, directory: Path, pattern: str) -> dict[str, Any]:
    return {
        "files": [
            {
                "path": str(path.relative_to(root)),
                "sha256": _sha256(path),
            }
            for path in sorted(directory.rglob(pattern))
        ]
    }


def _dependency_components(root: Path) -> list[dict[str, str]]:
    components: list[dict[str, str]] = []
    pyproject = (root / "pyproject.toml").read_text()
    for name, version in sorted(
        set(
            (match.group(1), match.group(2))
            for match in re.finditer(
                r'"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([A-Za-z0-9_.+-]+)"',
                pyproject,
            )
        )
    ):
        components.append({"type": "library", "name": name, "version": version})
    lock = json.loads((root / "dashboard" / "package-lock.json").read_text())
    for path, value in sorted(lock.get("packages", {}).items()):
        if not path.startswith("node_modules/") or not value.get("version"):
            continue
        components.append(
            {
                "type": "library",
                "name": path.removeprefix("node_modules/"),
                "version": str(value["version"]),
            }
        )
    return components


def _write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
