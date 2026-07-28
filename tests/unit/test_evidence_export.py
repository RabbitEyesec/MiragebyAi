from __future__ import annotations

import hashlib
import io
import zipfile

from cryptography.hazmat.primitives.asymmetric import rsa

from mirage_common.evidence_export import (
    LocalDevelopmentSigner,
    LocalDevelopmentTimestampProvider,
    build_manifest,
    canonical_manifest_bytes,
    create_export_package,
    sign_manifest,
    sort_evidence,
    verify_export_package,
)
from mirage_contracts.ulid import generate_ulid


def _items() -> tuple[list[dict], dict[str, bytes]]:
    one, two = generate_ulid(), generate_ulid()
    objects = {one: b"one", two: b"two"}
    evidence = [
        {
            "evidence_id": two,
            "evidence_type": "LOG",
            "acquisition_time": "2026-01-01T00:00:02Z",
            "source_id": "spider",
            "source_sequence": 2,
            "sha256": hashlib.sha256(objects[two]).hexdigest(),
            "s3_version_id": "2",
        },
        {
            "evidence_id": one,
            "evidence_type": "LOG",
            "acquisition_time": "2026-01-01T00:00:01Z",
            "source_id": "spider",
            "source_sequence": 1,
            "sha256": hashlib.sha256(objects[one]).hexdigest(),
            "s3_version_id": "1",
        },
    ]
    return evidence, objects


def _manifest() -> tuple[dict, dict[str, bytes]]:
    evidence, objects = _items()
    timestamp = LocalDevelopmentTimestampProvider().timestamp(b"\0" * 32)
    manifest = build_manifest(
        case={"case_id": generate_ulid(), "state": "EVIDENCE_VERIFYING"},
        sessions=[],
        timeline=[],
        evidence=evidence,
        collection_gaps=[],
        analyst_actions=[],
        ai_actions=[],
        policy_decisions=[],
        export_id=generate_ulid(),
        export_version=1,
        created_at="2026-01-01T00:00:00Z",
        created_by="auditor",
        kms_key_arn="LOCAL_DEVELOPMENT_KEY_NOT_KMS",
        trusted_timestamp=timestamp,
        limitations=["local signer is not KMS"],
    )
    return manifest, objects


def test_canonical_manifest_and_sort_are_deterministic() -> None:
    manifest, _ = _manifest()
    first = canonical_manifest_bytes(manifest)
    second = canonical_manifest_bytes(dict(reversed(list(manifest.items()))))
    assert first == second
    assert manifest["evidence_objects"] == sort_evidence(manifest["evidence_objects"])


def test_signed_export_verifies_and_modified_export_fails() -> None:
    manifest, objects = _manifest()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = LocalDevelopmentSigner(key)
    signed = sign_manifest(manifest, signer)
    package = create_export_package(signed, objects=objects, report="local test")
    # An externally-trusted key must be supplied — the package's own embedded
    # key is never trusted on its own.
    assert verify_export_package(package, public_key_pem=signer.public_key_pem()).valid
    assert not verify_export_package(package).valid

    source = io.BytesIO(package)
    output = io.BytesIO()
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(output, "w") as outgoing:
        for name in incoming.namelist():
            data = incoming.read(name)
            if name.startswith("objects/"):
                data += b"tampered"
            outgoing.writestr(name, data)
    report = verify_export_package(output.getvalue())
    assert not report.valid
    assert any("hash mismatch" in error for error in report.errors)


def test_local_timestamp_is_never_labelled_independently_trusted() -> None:
    timestamp = LocalDevelopmentTimestampProvider().timestamp(b"x" * 32)
    assert timestamp.source_type == "LOCAL_DEVELOPMENT"
    assert timestamp.independently_trusted is False
    assert "NOT INDEPENDENTLY TRUSTED" in timestamp.record["warning"]
