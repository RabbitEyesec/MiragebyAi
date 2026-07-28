from __future__ import annotations

import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mirage_common.release import (
    build_release,
    generate_install_report,
    verify_install_report,
    verify_release,
)
from mirage_common.server_installer import SUPPORTED_OPERATIONS, ServerInstaller, server_plan

ROOT = Path(__file__).resolve().parents[2]


def _private_key(path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _trusted_public_key_path(private_key_path: Path, output_path: Path) -> Path:
    """Simulate an operator who received the signer's public key out of band —
    verification must never trust whatever key happens to be embedded in the
    package under test."""
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    output_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return output_path


def test_server_installer_has_all_26_ordered_install_steps() -> None:
    """26, not the original 25 — Priority 10 added a required
    "python-package" step (installs the release's bundled Mirage wheel into
    a dedicated venv) between preflight/secret validation and Compose
    deploy, because every other step's `.venv/bin/python scripts/...`
    command needs mirage_common/mirage_contracts to actually be installed
    first on a clean host that has never seen this source repository."""
    plan = server_plan("install")
    assert len(plan) == 26
    assert [step.number for step in plan] == list(range(1, 27))
    assert len({step.step_id for step in plan}) == 26
    assert plan[0].step_id == "preflight"
    assert plan[-1].step_id == "report"
    assert "python-package" in {step.step_id for step in plan}


@pytest.mark.parametrize("operation", SUPPORTED_OPERATIONS)
def test_every_server_operation_has_machine_readable_dry_run(
    tmp_path: Path, operation: str
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("environment: test\n")
    installer = ServerInstaller(
        root=tmp_path,
        environment="test",
        config=config,
        journal=tmp_path / "journal.json",
    )
    result = installer.run(operation, dry_run=True)
    assert result["operation"] == operation
    assert result["dry_run"] is True
    assert result["steps"]


def test_destructive_server_operation_requires_exact_confirmation(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("environment: test\n")
    installer = ServerInstaller(
        root=tmp_path,
        environment="test",
        config=config,
        journal=tmp_path / "journal.json",
    )
    with pytest.raises(ValueError, match="mirage:test"):
        installer.run("uninstall", dry_run=False, confirmation="wrong")


def test_windows_installer_sources_are_hardened_and_secret_free() -> None:
    for relative in (
        "installers/endpoint/Product.wxs",
        "installers/endpoint/Bundle.wxs",
        "installers/sandbox/Product.wxs",
    ):
        ElementTree.parse(ROOT / relative)
    endpoint = (ROOT / "installers/endpoint/Bundle.wxs").read_text()
    sandbox = (ROOT / "installers/sandbox/bootstrap.ps1").read_text()
    assert "FleetEnrollmentToken" not in endpoint
    assert "--enrollment-token=" not in endpoint
    assert "MirageFleetBootstrap.exe" in endpoint
    assert "169.254.169.254/latest/api/token" in sandbox
    assert "fingerprint gate failed; READY is blocked" in sandbox
    for forbidden in ("AI_API_KEY=", "AWS_SECRET_ACCESS_KEY=", "password="):
        assert forbidden not in endpoint + sandbox


def test_signed_release_builds_verifies_and_detects_tampering(tmp_path: Path) -> None:
    key = tmp_path / "release-key.pem"
    package = tmp_path / "mirage-release.zip"
    _private_key(key)
    result = build_release(ROOT, version="1.0.0-test", output=package, signing_key=key)
    assert result["file_count"] >= 15
    trusted_key = _trusted_public_key_path(key, tmp_path / "trusted-release-key.pem")
    verified = verify_release(package, public_key=trusted_key)
    assert verified["valid"], verified["errors"]
    assert not verify_release(package)["valid"]
    tampered = tmp_path / "tampered.zip"
    with (
        zipfile.ZipFile(package, "r") as source,
        zipfile.ZipFile(tampered, "w") as target,
    ):
        for name in source.namelist():
            target.writestr(
                name,
                b"tampered" if name == "config/schema.json" else source.read(name),
            )
    invalid = verify_release(tampered)
    assert not invalid["valid"]
    assert "hash mismatch: config/schema.json" in invalid["errors"]


def test_release_has_no_private_key_or_secret_literal(tmp_path: Path) -> None:
    key = tmp_path / "release-key.pem"
    package = tmp_path / "mirage-release.zip"
    _private_key(key)
    build_release(ROOT, version="1.0.0-test", output=package, signing_key=key)
    with zipfile.ZipFile(package) as archive:
        assert all("private" not in name.lower() for name in archive.namelist())
        combined = b"\n".join(archive.read(name) for name in archive.namelist())
    assert b"BEGIN PRIVATE KEY" not in combined
    assert key.read_bytes() not in combined


def test_signed_install_report_contains_required_inventory_and_verifies(
    tmp_path: Path,
) -> None:
    key = tmp_path / "report-key.pem"
    journal = tmp_path / "journal.json"
    report = tmp_path / "install-report.zip"
    _private_key(key)
    journal.write_text(
        json.dumps(
            {
                "installer_version": "1.0.0",
                "package_sha256": "a" * 64,
                "container_image_digests": [
                    {"image": "registry.example/mirage-api", "digest": f"sha256:{'b' * 64}"}
                ],
                "sbom_hashes": {"sbom/mirage-source.cdx.json": "c" * 64},
                "configuration_sha256": "d" * 64,
                "migration_versions": ["infra/migrations/0010_reports.up.sql"],
                "contract_versions": ["schemas/reports/report.schema.json"],
                "service_health": {"step_id": "health", "status": "PASS"},
                "synthetic_transaction_result": {
                    "step_id": "synthetic",
                    "status": "PASS",
                },
                "installed_time": "2026-07-27T00:00:00Z",
                "host_fingerprint": "e" * 64,
            }
        )
    )
    generate_install_report(journal, output=report, signing_key=key)
    trusted_key = _trusted_public_key_path(key, tmp_path / "trusted-report-key.pem")
    verified = verify_install_report(report, public_key=trusted_key)
    assert verified["valid"], verified["errors"]
    assert not verify_install_report(report)["valid"]
    with zipfile.ZipFile(report) as archive:
        content = json.loads(archive.read("install-report.json"))
    assert content["signer_information"]["signature_algorithm"] == "RSA-PSS-SHA256"
    assert content["container_image_digests"][0]["digest"].startswith("sha256:")


def test_install_report_verifier_rejects_tampering(tmp_path: Path) -> None:
    key = tmp_path / "report-key.pem"
    journal = tmp_path / "journal.json"
    report = tmp_path / "install-report.zip"
    tampered = tmp_path / "tampered-install-report.zip"
    _private_key(key)
    journal.write_text(
        json.dumps(
            {
                "installer_version": "1.0.0",
                "package_sha256": None,
                "container_image_digests": [],
                "sbom_hashes": {},
                "configuration_sha256": "d" * 64,
                "migration_versions": [],
                "contract_versions": [],
                "service_health": {"status": "PASS"},
                "synthetic_transaction_result": {"status": "PASS"},
                "installed_time": "2026-07-27T00:00:00Z",
                "host_fingerprint": "e" * 64,
            }
        )
    )
    generate_install_report(journal, output=report, signing_key=key)
    with zipfile.ZipFile(report) as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            value = source.read(name)
            if name == "install-report.json":
                value += b"tampered"
            target.writestr(name, value)
    verified = verify_install_report(tampered)
    assert not verified["valid"]
