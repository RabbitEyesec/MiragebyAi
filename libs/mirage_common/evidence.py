"""Stage 5 evidence acquisition, immutable ledger, and verification.

The service streams bytes through a bounded disk spool while hashing, then
uploads through an object-store adapter. PostgreSQL receives metadata only.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePath
from typing import BinaryIO, Protocol, cast

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

CHUNK_SIZE = 1024 * 1024
EVIDENCE_CATEGORIES = frozenset(
    {"raw", "artifacts", "screenshots", "logs", "snapshots", "exports", "manifests"}
)
TYPE_CATEGORIES = {
    "RAW_TELEMETRY": "raw",
    "ARTIFACT": "artifacts",
    "SCREENSHOT": "screenshots",
    "LOG": "logs",
    "SNAPSHOT": "snapshots",
    "EXPORT": "exports",
    "MANIFEST": "manifests",
    "SIGNATURE": "manifests",
    "VERIFICATION_REPORT": "exports",
    "CANARY_CALLBACK": "raw",
}
DEFAULT_MAX_BYTES = {
    "RAW_TELEMETRY": 64 * 1024 * 1024,
    "ARTIFACT": 250 * 1024 * 1024,
    "SCREENSHOT": 50 * 1024 * 1024,
    "LOG": 250 * 1024 * 1024,
    "SNAPSHOT": 32 * 1024 * 1024,
    "EXPORT": 2 * 1024 * 1024 * 1024,
    "MANIFEST": 4 * 1024 * 1024,
    "SIGNATURE": 64 * 1024,
    "VERIFICATION_REPORT": 8 * 1024 * 1024,
    "CANARY_CALLBACK": 256 * 1024,
}


class EvidenceError(Exception):
    pass


class EvidenceTooLargeError(EvidenceError):
    pass


class EvidenceSourceError(EvidenceError):
    pass


class EvidenceNotFoundError(EvidenceError):
    pass


class ObjectMissingError(EvidenceError):
    pass


@dataclass(frozen=True)
class EvidenceStorageConfig:
    bucket: str
    region: str
    object_lock_mode: str
    retention_days: int
    multipart_threshold_mb: int
    max_retries: int
    request_timeout_seconds: int
    kms_signing_key_arn: str
    endpoint_url: str | None = None

    def __post_init__(self) -> None:
        if not self.bucket or "/" in self.bucket:
            raise ValueError("MIRAGE_EVIDENCE_BUCKET must be a bucket name, not a path")
        if self.object_lock_mode not in {"GOVERNANCE", "COMPLIANCE"}:
            raise ValueError("MIRAGE_EVIDENCE_OBJECT_LOCK_MODE must be GOVERNANCE or COMPLIANCE")
        if self.retention_days < 1 or self.multipart_threshold_mb < 5:
            raise ValueError("retention must be positive and multipart threshold at least 5 MB")
        if not 0 <= self.max_retries <= 10 or not 1 <= self.request_timeout_seconds <= 300:
            raise ValueError("invalid evidence retry/timeout configuration")
        if not self.kms_signing_key_arn:
            raise ValueError("MIRAGE_KMS_SIGNING_KEY_ARN is required")


@dataclass(frozen=True)
class StoredObject:
    bucket: str
    key: str
    version_id: str
    object_lock_mode: str | None
    retention_until: datetime | None


class ObjectStore(Protocol):
    async def put(
        self,
        *,
        key: str,
        stream: BinaryIO,
        size_bytes: int,
        media_type: str,
        sha256: str,
        correlation_id: str,
    ) -> StoredObject: ...

    async def open(self, *, bucket: str, key: str, version_id: str) -> BinaryIO: ...


class S3ObjectStore:
    """AWS SDK adapter. Credentials are intentionally absent from config:
    boto3's default chain resolves the workload IAM role."""

    def __init__(self, config: EvidenceStorageConfig) -> None:
        self.config = config
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise RuntimeError("install the aws extra to use S3ObjectStore") from exc
        self._transfer_config = __import__(
            "boto3.s3.transfer", fromlist=["TransferConfig"]
        ).TransferConfig(
            multipart_threshold=config.multipart_threshold_mb * 1024 * 1024,
            multipart_chunksize=max(5, config.multipart_threshold_mb) * 1024 * 1024,
            max_concurrency=4,
            use_threads=True,
        )
        client_kwargs: dict[str, object] = {
            "region_name": config.region,
            "endpoint_url": config.endpoint_url,
            "config": Config(
                retries={"max_attempts": config.max_retries, "mode": "standard"},
                connect_timeout=config.request_timeout_seconds,
                read_timeout=config.request_timeout_seconds,
            ),
        }
        if config.endpoint_url:
            # Local S3-compatible test/dev endpoints deliberately use explicit
            # process environment credentials. A shared boto3 default session
            # caches the first credential set it sees, which is wrong when an
            # integration process starts multiple isolated MinIO instances.
            client_kwargs["aws_access_key_id"] = os.environ.get("AWS_ACCESS_KEY_ID")
            client_kwargs["aws_secret_access_key"] = os.environ.get(
                "AWS_SECRET_ACCESS_KEY"
            )
            client_kwargs["aws_session_token"] = os.environ.get("AWS_SESSION_TOKEN")
        self._client = boto3.client("s3", **client_kwargs)

    async def put(
        self,
        *,
        key: str,
        stream: BinaryIO,
        size_bytes: int,
        media_type: str,
        sha256: str,
        correlation_id: str,
    ) -> StoredObject:
        del size_bytes
        retention = datetime.now(UTC) + timedelta(days=self.config.retention_days)

        def upload() -> StoredObject:
            stream.seek(0)
            extra = {
                "ContentType": media_type,
                "Metadata": {"sha256": sha256, "correlation-id": correlation_id},
                "ObjectLockMode": self.config.object_lock_mode,
                "ObjectLockRetainUntilDate": retention,
            }
            # AWS uses managed server-side encryption. Local S3-compatible
            # endpoints do not claim encryption because MinIO requires a
            # separately configured KES before accepting SSE-S3.
            if not self.config.endpoint_url:
                extra["ServerSideEncryption"] = "AES256"
            self._client.upload_fileobj(
                stream,
                self.config.bucket,
                key,
                ExtraArgs=extra,
                Config=self._transfer_config,
            )
            head = self._client.head_object(Bucket=self.config.bucket, Key=key)
            version_id = head.get("VersionId")
            if not version_id:
                raise EvidenceError("S3 did not return a version ID; bucket versioning is required")
            return StoredObject(
                bucket=self.config.bucket,
                key=key,
                version_id=version_id,
                object_lock_mode=head.get("ObjectLockMode", self.config.object_lock_mode),
                retention_until=head.get("ObjectLockRetainUntilDate", retention),
            )

        return await asyncio.to_thread(upload)

    async def open(self, *, bucket: str, key: str, version_id: str) -> BinaryIO:
        if bucket != self.config.bucket:
            raise EvidenceError("ledger bucket does not match configured evidence bucket")

        def download() -> BinaryIO:
            try:
                response = self._client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
            except Exception as exc:
                response_meta = getattr(exc, "response", {})
                code = response_meta.get("Error", {}).get("Code")
                if code in {"NoSuchKey", "NoSuchVersion", "404"}:
                    raise ObjectMissingError(key) from exc
                raise
            spool = tempfile.SpooledTemporaryFile(max_size=CHUNK_SIZE, mode="w+b")
            body = response["Body"]
            while True:
                chunk = body.read(CHUNK_SIZE)
                if not chunk:
                    break
                spool.write(chunk)
            spool.seek(0)
            return cast(BinaryIO, spool)

        return await asyncio.to_thread(download)


class MemoryObjectStore:
    """Deterministic unit-test adapter only. Never production verification."""

    def __init__(self, bucket: str = "unit-evidence") -> None:
        self.bucket = bucket
        self.objects: dict[tuple[str, str], bytes] = {}
        self._versions: dict[str, int] = {}

    async def put(
        self,
        *,
        key: str,
        stream: BinaryIO,
        size_bytes: int,
        media_type: str,
        sha256: str,
        correlation_id: str,
    ) -> StoredObject:
        del media_type, sha256, correlation_id
        stream.seek(0)
        data = stream.read()
        if len(data) != size_bytes:
            raise EvidenceError("stream size changed between acquisition and storage")
        version = str(self._versions.get(key, 0) + 1)
        self._versions[key] = int(version)
        self.objects[(key, version)] = data
        return StoredObject(self.bucket, key, version, "GOVERNANCE", datetime.now(UTC))

    async def open(self, *, bucket: str, key: str, version_id: str) -> BinaryIO:
        if bucket != self.bucket or (key, version_id) not in self.objects:
            raise ObjectMissingError(key)
        return io.BytesIO(self.objects[(key, version_id)])


def sanitise_filename(filename: str | None) -> str | None:
    if filename is None:
        return None
    name = PurePath(filename.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    name = re.sub(r"_+", "_", name)
    if not name:
        name = "unnamed"
    return name[:128]


def evidence_s3_key(
    *, case_id: str, category: str, evidence_id: str, original_filename: str | None = None
) -> str:
    if category not in EVIDENCE_CATEGORIES:
        raise ValueError(f"unsupported evidence category: {category}")
    if not re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", case_id):
        raise ValueError("case_id must be a canonical ULID")
    if not re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", evidence_id):
        raise ValueError("evidence_id must be a canonical ULID")
    safe = sanitise_filename(original_filename)
    suffix = f"-{safe}" if safe else ""
    return f"cases/{case_id}/{category}/{evidence_id}{suffix}"


def stream_hash(stream: BinaryIO, *, max_bytes: int) -> tuple[BinaryIO, int, str]:
    spool = tempfile.SpooledTemporaryFile(max_size=CHUNK_SIZE, mode="w+b")
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            spool.close()
            raise EvidenceTooLargeError(f"evidence exceeds {max_bytes} bytes")
        digest.update(chunk)
        spool.write(chunk)
    spool.seek(0)
    return cast(BinaryIO, spool), size, digest.hexdigest()


@dataclass(frozen=True)
class AcquisitionRequest:
    case_id: str
    session_id: str | None
    evidence_type: str
    source_id: str
    source_sequence: int
    source_certificate_serial: str | None
    related_event_ids: list[str]
    acquisition_time: datetime
    original_filename: str | None
    media_type: str
    collection_method: str
    classification: str
    metadata: dict
    required_for_export: bool = True


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    case_id: str
    sha256: str
    size_bytes: int
    bucket: str
    key: str
    version_id: str
    verification_status: str


class EvidenceService:
    def __init__(
        self,
        *,
        store: ObjectStore,
        max_bytes_by_type: dict[str, int] | None = None,
    ) -> None:
        self.store = store
        self.max_bytes_by_type = {**DEFAULT_MAX_BYTES, **(max_bytes_by_type or {})}

    async def acquire(
        self,
        conn: psycopg.AsyncConnection,
        *,
        request: AcquisitionRequest,
        stream: BinaryIO,
        actor: str,
        correlation_id: str | None = None,
    ) -> EvidenceRecord:
        correlation_id = correlation_id or generate_ulid()
        evidence_id = generate_ulid()
        max_bytes = self.max_bytes_by_type.get(request.evidence_type)
        category = TYPE_CATEGORIES.get(request.evidence_type)
        if max_bytes is None or category is None:
            raise EvidenceError(f"unsupported evidence type: {request.evidence_type}")
        spool, size_bytes, sha256 = stream_hash(stream, max_bytes=max_bytes)
        key = evidence_s3_key(
            case_id=request.case_id,
            category=category,
            evidence_id=evidence_id,
            original_filename=request.original_filename,
        )

        async with conn.cursor() as cur:
            # Serialise sequence validation for a source for the duration of
            # the transaction. This prevents concurrent uploads from both
            # passing the max-sequence check and creating orphaned versions.
            await cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 5821))",
                (request.source_id,),
            )
            await cur.execute("SELECT state FROM cases WHERE case_id = %s", (request.case_id,))
            if await cur.fetchone() is None:
                spool.close()
                raise EvidenceError("unknown case")
            if request.session_id:
                await cur.execute(
                    "SELECT 1 FROM sessions WHERE session_id = %s AND case_id = %s",
                    (request.session_id, request.case_id),
                )
                if await cur.fetchone() is None:
                    spool.close()
                    raise EvidenceError("session does not belong to case")
            if request.source_certificate_serial:
                await cur.execute(
                    "SELECT status, certificate_serial FROM agents WHERE agent_id = %s",
                    (request.source_id,),
                )
                source = await cur.fetchone()
                if (
                    source is None
                    or source[0] != "ACTIVE"
                    or source[1] != request.source_certificate_serial
                ):
                    spool.close()
                    raise EvidenceSourceError("source authentication failed")
            await cur.execute(
                """
                SELECT evidence_id,case_id,session_id,evidence_type,sha256,size_bytes,
                       s3_bucket,s3_key,s3_version_id,verification_status
                FROM evidence_objects
                WHERE source_id=%s AND source_sequence=%s
                """,
                (request.source_id, request.source_sequence),
            )
            existing = await cur.fetchone()
            if existing is not None:
                spool.close()
                if (
                    existing[1] != request.case_id
                    or existing[2] != request.session_id
                    or existing[3] != request.evidence_type
                    or existing[4] != sha256
                    or existing[5] != size_bytes
                ):
                    raise EvidenceSourceError(
                        "source sequence replayed with different evidence metadata or bytes"
                    )
                return EvidenceRecord(
                    evidence_id=existing[0],
                    case_id=existing[1],
                    sha256=existing[4],
                    size_bytes=existing[5],
                    bucket=existing[6],
                    key=existing[7],
                    version_id=existing[8],
                    verification_status=existing[9],
                )
            await cur.execute(
                "SELECT COALESCE(max(source_sequence), -1) FROM evidence_objects WHERE source_id = %s",
                (request.source_id,),
            )
            sequence_row = await cur.fetchone()
            if sequence_row is None:
                spool.close()
                raise EvidenceError("unable to read source sequence")
            max_sequence = sequence_row[0]
            if request.source_sequence <= max_sequence:
                spool.close()
                raise EvidenceSourceError("source sequence is replayed or out of order")

        try:
            stored = await self.store.put(
                key=key,
                stream=spool,
                size_bytes=size_bytes,
                media_type=request.media_type,
                sha256=sha256,
                correlation_id=correlation_id,
            )
        finally:
            spool.close()

        now = datetime.now(UTC)
        safe_filename = sanitise_filename(request.original_filename)
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO evidence_objects (
                    evidence_id, case_id, session_id, evidence_type, source_id,
                    source_sequence, source_certificate_serial, related_event_ids,
                    acquisition_time, stored_time, original_filename, media_type,
                    size_bytes, sha256, s3_bucket, s3_key, s3_version_id,
                    object_lock_mode, retention_until, verification_status,
                    collection_method, classification, metadata_json,
                    required_for_export
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    'PENDING',%s,%s,%s,%s
                )
                """,
                (
                    evidence_id,
                    request.case_id,
                    request.session_id,
                    request.evidence_type,
                    request.source_id,
                    request.source_sequence,
                    request.source_certificate_serial,
                    Jsonb(request.related_event_ids),
                    request.acquisition_time,
                    now,
                    safe_filename,
                    request.media_type,
                    size_bytes,
                    sha256,
                    stored.bucket,
                    stored.key,
                    stored.version_id,
                    stored.object_lock_mode,
                    stored.retention_until,
                    request.collection_method,
                    request.classification,
                    Jsonb(request.metadata),
                    request.required_for_export,
                ),
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor, actor_type, action, target, outcome, correlation_id, detail)
                VALUES (%s, 'AGENT', 'evidence.acquired', %s, 'SUCCESS', %s, %s)
                """,
                (actor, evidence_id, correlation_id, f"{request.evidence_type}:{size_bytes}"),
            )
            event = build_event(
                event_type="evidence.created",
                schema_version="1.0",
                payload={
                    "evidence_id": evidence_id,
                    "case_id": request.case_id,
                    "evidence_type": request.evidence_type,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "s3_key": stored.key,
                    "s3_version_id": stored.version_id,
                    "verification_status": "PENDING",
                },
                source_id="mirage-worker.evidence",
                sequence=request.source_sequence,
                actor_type="SYSTEM",
                classification="EVIDENCE",
                case_id=request.case_id,
                session_id=request.session_id,
            )
            validated = validate_event(event)
            await cur.execute(
                "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s,%s,%s)",
                (
                    event["event_id"],
                    subject_for_event_type("evidence.created"),
                    Jsonb(validated.envelope),
                ),
            )
        return EvidenceRecord(
            evidence_id,
            request.case_id,
            sha256,
            size_bytes,
            stored.bucket,
            stored.key,
            stored.version_id,
            "PENDING",
        )

    async def verify(
        self,
        conn: psycopg.AsyncConnection,
        *,
        evidence_id: str,
        reason: str,
        requested_by: str,
    ) -> str:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT case_id, session_id, sha256, s3_bucket, s3_key, s3_version_id
                FROM evidence_objects WHERE evidence_id = %s FOR UPDATE
                """,
                (evidence_id,),
            )
            row = await cur.fetchone()
            if row is None:
                raise EvidenceNotFoundError(evidence_id)
        case_id, session_id, expected, bucket, key, version_id = row
        calculated: str | None = None
        error: str | None = None
        try:
            stream = await self.store.open(bucket=bucket, key=key, version_id=version_id)
            digest = hashlib.sha256()
            try:
                while True:
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                stream.close()
            calculated = digest.hexdigest()
            status = "VERIFIED" if calculated == expected else "HASH_MISMATCH"
            if status == "HASH_MISMATCH":
                error = "calculated SHA-256 differs from immutable ledger"
        except ObjectMissingError:
            status = "MISSING"
            error = "object missing at exact bucket/key/version"
        except Exception as exc:  # noqa: BLE001
            status = "FAILED"
            error = f"{type(exc).__name__}: {exc}"[:1024]

        verification_id = generate_ulid()
        event_type = "evidence.verified" if status == "VERIFIED" else "evidence.verification_failed"
        payload = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "verification_id": verification_id,
            "status": status,
            "reason": reason,
        }
        if status == "VERIFIED":
            payload["sha256"] = expected
        else:
            payload.update(
                {
                    "expected_sha256": expected,
                    "calculated_sha256": calculated,
                    "error": error,
                }
            )
        event = build_event(
            event_type=event_type,
            schema_version="1.0",
            payload=payload,
            source_id="mirage-worker.evidence-verifier",
            sequence=0,
            actor_type="SYSTEM",
            classification="INTERNAL",
            case_id=case_id,
            session_id=session_id,
        )
        validated = validate_event(event)
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO evidence_verification_history (
                    verification_id,evidence_id,reason,status,expected_sha256,
                    calculated_sha256,error,requested_by
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    verification_id,
                    evidence_id,
                    reason,
                    status,
                    expected,
                    calculated,
                    error,
                    requested_by,
                ),
            )
            await cur.execute(
                """
                UPDATE evidence_objects
                SET verification_status=%s, verified_at=CASE WHEN %s='VERIFIED' THEN now() ELSE NULL END,
                    verification_error=%s, updated_at=now()
                WHERE evidence_id=%s
                """,
                (status, status, error, evidence_id),
            )
            await cur.execute(
                """
                INSERT INTO audit_events
                    (actor,actor_type,action,target,outcome,correlation_id,detail)
                VALUES (%s,'SYSTEM',%s,%s,%s,%s,%s)
                """,
                (
                    requested_by,
                    f"evidence.verification.{status.lower()}",
                    evidence_id,
                    "SUCCESS" if status == "VERIFIED" else "FAILURE",
                    verification_id,
                    error or reason,
                ),
            )
            await cur.execute(
                "INSERT INTO outbox_events (event_id,topic,payload) VALUES (%s,%s,%s)",
                (event["event_id"], subject_for_event_type(event_type), Jsonb(validated.envelope)),
            )
        return status


async def export_eligibility(conn: psycopg.AsyncConnection, *, case_id: str) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT evidence_id, verification_status FROM evidence_objects
            WHERE case_id=%s AND required_for_export
              AND evidence_type NOT IN ('EXPORT','MANIFEST')
            """,
            (case_id,),
        )
        for evidence_id, status in await cur.fetchall():
            if status != "VERIFIED":
                reasons.append(f"required evidence {evidence_id} is {status}")
        await cur.execute(
            """
            SELECT gap_id, reason FROM evidence_collection_gaps
            WHERE case_id=%s AND required AND resolved_at IS NULL
            """,
            (case_id,),
        )
        reasons.extend(f"required collection gap {gap_id}: {reason}" for gap_id, reason in await cur.fetchall())
    return not reasons, reasons


async def verify_case_evidence(
    conn: psycopg.AsyncConnection,
    *,
    service: EvidenceService,
    case_id: str,
    reason: str,
    requested_by: str,
    sample_limit: int | None = None,
) -> dict[str, str]:
    """Verify a deterministic case sample for scheduled/final-case hooks."""
    if reason not in {"SCHEDULED_SAMPLE", "FINAL_CASE_CONCLUSION", "PRE_EXPORT"}:
        raise ValueError("unsupported case verification reason")
    query = """
        SELECT evidence_id FROM evidence_objects
        WHERE case_id=%s AND evidence_type NOT IN ('EXPORT','MANIFEST','SIGNATURE')
        ORDER BY sha256,evidence_id
    """
    params: tuple[object, ...] = (case_id,)
    if sample_limit is not None:
        if sample_limit < 1:
            raise ValueError("sample_limit must be positive")
        query += " LIMIT %s"
        params = (case_id, sample_limit)
    async with conn.cursor() as cur:
        await cur.execute(query, params)
        evidence_ids = [row[0] for row in await cur.fetchall()]
    results: dict[str, str] = {}
    for evidence_id in evidence_ids:
        results[evidence_id] = await service.verify(
            conn,
            evidence_id=evidence_id,
            reason=reason,
            requested_by=requested_by,
        )
    return results
