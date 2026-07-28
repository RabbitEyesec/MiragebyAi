"""Deterministic evidence export manifests, signing, packaging, and verification."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from mirage_common.trust_anchor import resolve_trusted_key
from mirage_contracts.envelope import canonical_json_bytes
from mirage_contracts.ulid import generate_ulid

MANIFEST_VERSION = "1.0"
SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256"
EVIDENCE_SORT_FIELDS = (
    "evidence_type",
    "acquisition_time",
    "source_id",
    "source_sequence",
    "evidence_id",
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class ExportIntegrityError(Exception):
    pass


class ManifestSigner(Protocol):
    key_id: str

    def sign_digest(self, digest: bytes) -> bytes: ...

    def public_key_pem(self) -> bytes: ...


class KmsManifestSigner:
    """AWS KMS asymmetric signer. boto3 resolves IAM role credentials."""

    def __init__(self, key_arn: str, *, region: str | None = None) -> None:
        import boto3

        self.key_id = key_arn
        self._kms = boto3.client("kms", region_name=region)

    def sign_digest(self, digest: bytes) -> bytes:
        result = self._kms.sign(
            KeyId=self.key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=SIGNING_ALGORITHM,
        )
        return result["Signature"]

    def public_key_pem(self) -> bytes:
        result = self._kms.get_public_key(KeyId=self.key_id)
        public_key = serialization.load_der_public_key(result["PublicKey"])
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class LocalDevelopmentSigner:
    """Local test signer, explicitly labelled as not KMS verification."""

    key_id = "LOCAL_DEVELOPMENT_KEY_NOT_KMS"

    def __init__(self, private_key: Any) -> None:
        self._private_key = private_key

    def sign_digest(self, digest: bytes) -> bytes:
        return self._private_key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            utils.Prehashed(hashes.SHA256()),
        )

    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


@dataclass(frozen=True)
class TrustedTimestamp:
    timestamp_id: str
    source_type: str
    source_name: str
    timestamp_time: str
    independently_trusted: bool
    token_base64: str | None
    record: dict[str, Any]


class TimestampProvider(Protocol):
    def timestamp(self, digest: bytes) -> TrustedTimestamp: ...


class LocalDevelopmentTimestampProvider:
    def timestamp(self, digest: bytes) -> TrustedTimestamp:
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        return TrustedTimestamp(
            timestamp_id=generate_ulid(),
            source_type="LOCAL_DEVELOPMENT",
            source_name="local-system-clock",
            timestamp_time=now,
            independently_trusted=False,
            token_base64=None,
            record={
                "manifest_digest_sha256": digest.hex(),
                "warning": "LOCAL DEVELOPMENT CLOCK; NOT INDEPENDENTLY TRUSTED",
            },
        )


class Rfc3161TimestampProvider:
    def __init__(
        self,
        authority_url: str,
        *,
        timeout_seconds: float = 10.0,
        ca_file: str | Path | None = None,
    ) -> None:
        self.authority_url = authority_url
        self.timeout_seconds = timeout_seconds
        self.ca_file = Path(ca_file) if ca_file else None

    def timestamp(self, digest: bytes) -> TrustedTimestamp:
        import httpx

        openssl = shutil.which("openssl")
        if openssl is None:
            raise RuntimeError("OpenSSL is required to construct and validate RFC 3161 requests")
        with tempfile.TemporaryDirectory(prefix="mirage-rfc3161-") as temp_dir:
            query_path = Path(temp_dir) / "request.tsq"
            response_path = Path(temp_dir) / "response.tsr"
            query = subprocess.run(
                [
                    openssl,
                    "ts",
                    "-query",
                    "-digest",
                    digest.hex(),
                    "-sha256",
                    "-cert",
                    "-out",
                    str(query_path),
                ],
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if query.returncode != 0:
                raise RuntimeError("OpenSSL could not construct RFC 3161 request")
            response = httpx.post(
                self.authority_url,
                content=query_path.read_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            response_path.write_bytes(response.content)
            parsed = subprocess.run(
                [openssl, "ts", "-reply", "-in", str(response_path), "-text"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if parsed.returncode != 0 or "Status: Granted." not in parsed.stdout:
                raise RuntimeError(
                    "timestamp authority returned an invalid or ungranted RFC 3161 response"
                )
            timestamp_match = re.search(
                r"^Time stamp:\s+(.+)$", parsed.stdout, flags=re.MULTILINE
            )
            if timestamp_match is None:
                raise RuntimeError("RFC 3161 response omitted timestamp time")
            timestamp_time = datetime.strptime(
                timestamp_match.group(1).strip(), "%b %d %H:%M:%S %Y GMT"
            ).replace(tzinfo=UTC)
            independently_trusted = False
            trust_detail = (
                "RFC 3161 structure and message imprint validated; trust chain not configured"
            )
            if self.ca_file is not None:
                verified = subprocess.run(
                    [
                        openssl,
                        "ts",
                        "-verify",
                        "-queryfile",
                        str(query_path),
                        "-in",
                        str(response_path),
                        "-CAfile",
                        str(self.ca_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if verified.returncode != 0:
                    raise RuntimeError("RFC 3161 timestamp trust-chain verification failed")
                independently_trusted = True
                trust_detail = (
                    "RFC 3161 message imprint and configured CA trust chain validated"
                )
        return TrustedTimestamp(
            timestamp_id=generate_ulid(),
            source_type="RFC3161",
            source_name=self.authority_url,
            timestamp_time=timestamp_time.isoformat().replace("+00:00", "Z"),
            independently_trusted=independently_trusted,
            token_base64=base64.b64encode(response.content).decode("ascii"),
            record={
                "response_content_type": response.headers.get("content-type"),
                "trust_validation": trust_detail,
                "message_imprint_sha256": digest.hex(),
            },
        )


def sort_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            item["evidence_type"],
            item["acquisition_time"],
            item["source_id"],
            int(item["source_sequence"]),
            item["evidence_id"],
        ),
    )


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return canonical_json_bytes(manifest)


def build_manifest(
    *,
    case: dict[str, Any],
    sessions: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    collection_gaps: list[dict[str, Any]],
    analyst_actions: list[dict[str, Any]],
    ai_actions: list[dict[str, Any]],
    policy_decisions: list[dict[str, Any]],
    export_id: str,
    export_version: int,
    created_at: str,
    created_by: str,
    kms_key_arn: str,
    trusted_timestamp: TrustedTimestamp,
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "export_id": export_id,
        "export_version": export_version,
        "export_creation_time": created_at,
        "export_creator": created_by,
        "case": case,
        "sessions": sorted(sessions, key=lambda x: (x.get("created_at", ""), x["session_id"])),
        "case_state_timeline": sorted(
            timeline, key=lambda x: (x.get("at", ""), x.get("new_version", 0))
        ),
        "evidence_objects": sort_evidence(evidence),
        "collection_gaps": sorted(collection_gaps, key=lambda x: x["gap_id"]),
        "analyst_actions": sorted(
            analyst_actions, key=lambda x: (x.get("created_at", ""), x.get("id", ""))
        ),
        "ai_actions": sorted(ai_actions, key=lambda x: (x.get("created_at", ""), x.get("id", ""))),
        "policy_decisions": sorted(
            policy_decisions, key=lambda x: (x.get("created_at", ""), x.get("decision_id", ""))
        ),
        "signing": {
            "kms_key_arn": kms_key_arn,
            "algorithm": SIGNING_ALGORITHM,
            "payload": "SHA256(canonical-manifest-without-signature)",
        },
        "trusted_timestamp": {
            "timestamp_id": trusted_timestamp.timestamp_id,
            "source_type": trusted_timestamp.source_type,
            "source_name": trusted_timestamp.source_name,
            "timestamp_time": trusted_timestamp.timestamp_time,
            "independently_trusted": trusted_timestamp.independently_trusted,
            "token_base64": trusted_timestamp.token_base64,
            "record": trusted_timestamp.record,
        },
        "limitations": limitations,
    }


@dataclass(frozen=True)
class SignedManifest:
    manifest: dict[str, Any]
    canonical_bytes: bytes
    manifest_sha256: str
    signature: bytes
    public_key_pem: bytes


def sign_manifest(manifest: dict[str, Any], signer: ManifestSigner) -> SignedManifest:
    canonical = canonical_manifest_bytes(manifest)
    digest = hashlib.sha256(canonical).digest()
    signature = signer.sign_digest(digest)
    return SignedManifest(manifest, canonical, digest.hex(), signature, signer.public_key_pem())


def _write_zip_bytes(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, data)


def create_export_package(
    signed: SignedManifest,
    *,
    objects: dict[str, bytes],
    report: str,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        _write_zip_bytes(zf, "manifest.json", signed.canonical_bytes)
        _write_zip_bytes(zf, "manifest.sha256", f"{signed.manifest_sha256}\n".encode())
        _write_zip_bytes(zf, "manifest.sig", signed.signature)
        _write_zip_bytes(zf, "public-key.pem", signed.public_key_pem)
        _write_zip_bytes(zf, "verification-report.txt", report.encode("utf-8"))
        for evidence_id in sorted(objects):
            _write_zip_bytes(zf, f"objects/{evidence_id}", objects[evidence_id])
    return buffer.getvalue()


def verify_signature(
    *, public_key_pem: bytes, digest: bytes, signature: bytes
) -> None:
    public_key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ExportIntegrityError("manifest public key is not RSA")
    public_key.verify(
        signature,
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        utils.Prehashed(hashes.SHA256()),
    )


@dataclass(frozen=True)
class VerificationReport:
    valid: bool
    errors: tuple[str, ...]
    manifest_sha256: str | None


def verify_export_package(
    package: bytes | str | Path,
    *,
    public_key_pem: bytes | None = None,
    trust_store_dir: Path | None = None,
) -> VerificationReport:
    errors: list[str] = []
    source: io.BytesIO | str | Path
    source = io.BytesIO(package) if isinstance(package, bytes) else package
    try:
        with zipfile.ZipFile(source, "r") as zf:
            name_list = zf.namelist()
            names = set(name_list)
            if len(names) != len(name_list):
                errors.append("package contains duplicate member names")
            required = {
                "manifest.json",
                "manifest.sha256",
                "manifest.sig",
                "verification-report.txt",
            }
            for missing in sorted(required - names):
                errors.append(f"missing required package member: {missing}")
            if errors:
                return VerificationReport(False, tuple(errors), None)
            manifest_bytes = zf.read("manifest.json")
            manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
            recorded = zf.read("manifest.sha256").decode().strip()
            if manifest_sha256 != recorded:
                errors.append("manifest hash mismatch")
            try:
                manifest = json.loads(manifest_bytes)
            except json.JSONDecodeError as exc:
                return VerificationReport(False, (f"manifest JSON invalid: {exc}",), manifest_sha256)
            if canonical_manifest_bytes(manifest) != manifest_bytes:
                errors.append("manifest is not canonical JSON")
            if manifest.get("manifest_version") != MANIFEST_VERSION:
                errors.append("unsupported manifest version")
            if manifest.get("signing", {}).get("algorithm") != SIGNING_ALGORITHM:
                errors.append("unsupported signing algorithm")
            evidence = manifest.get("evidence_objects")
            if not isinstance(evidence, list):
                errors.append("manifest evidence_objects must be an array")
                evidence = []
            valid_evidence: list[dict[str, Any]] = []
            required_evidence_fields = {
                "evidence_id",
                "evidence_type",
                "acquisition_time",
                "source_id",
                "source_sequence",
                "sha256",
                "s3_version_id",
            }
            for index, item in enumerate(evidence):
                if not isinstance(item, dict):
                    errors.append(f"evidence item {index} is not an object")
                    continue
                if missing_fields := required_evidence_fields - item.keys():
                    errors.append(
                        f"evidence item {index} missing fields: {sorted(missing_fields)}"
                    )
                    continue
                if not isinstance(item["evidence_id"], str) or not isinstance(
                    item["sha256"], str
                ):
                    errors.append(f"evidence item {index} has invalid identifier/hash types")
                    continue
                valid_evidence.append(item)
            try:
                if valid_evidence != sort_evidence(valid_evidence):
                    errors.append("evidence list is not deterministically sorted")
            except (KeyError, TypeError, ValueError):
                errors.append("evidence list contains invalid deterministic-sort fields")
            expected_names = {
                f"objects/{item['evidence_id']}" for item in valid_evidence
            }
            actual_names = {name for name in names if name.startswith("objects/")}
            for missing in sorted(expected_names - actual_names):
                errors.append(f"missing object: {missing}")
            for unexpected in sorted(actual_names - expected_names):
                errors.append(f"unexpected object: {unexpected}")
            for item in valid_evidence:
                name = f"objects/{item['evidence_id']}"
                if name in names:
                    actual_hash = hashlib.sha256(zf.read(name)).hexdigest()
                    if actual_hash != item["sha256"]:
                        errors.append(f"hash mismatch: {name}")
            embedded_key = zf.read("public-key.pem") if "public-key.pem" in names else None
            trust = resolve_trusted_key(
                explicit_key_bytes=public_key_pem,
                trust_store_dir=trust_store_dir,
                embedded_key_bytes=embedded_key,
            )
            errors.extend(trust.errors)
            if trust.key_bytes is not None:
                try:
                    verify_signature(
                        public_key_pem=trust.key_bytes,
                        digest=bytes.fromhex(manifest_sha256),
                        signature=zf.read("manifest.sig"),
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"signature verification failed: {type(exc).__name__}")
    except (zipfile.BadZipFile, OSError) as exc:
        return VerificationReport(False, (f"invalid export package: {exc}",), None)
    return VerificationReport(not errors, tuple(errors), manifest_sha256)
