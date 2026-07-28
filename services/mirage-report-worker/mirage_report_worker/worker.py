from __future__ import annotations

import asyncio
import os

import psycopg
from cryptography.hazmat.primitives.asymmetric import rsa

from mirage_common.evidence import EvidenceService, EvidenceStorageConfig, S3ObjectStore
from mirage_common.evidence_export import (
    KmsManifestSigner,
    LocalDevelopmentSigner,
    LocalDevelopmentTimestampProvider,
    ManifestSigner,
    Rfc3161TimestampProvider,
)
from mirage_common.telemetry import configure_otel
from mirage_report_worker.exporter import ExportNotEligibleError, generate_export
from mirage_report_worker.reporter import process_next_report


def _dsn() -> str:
    return (
        f"host={os.environ['MIRAGE_POSTGRES_HOST']} "
        f"port={os.environ.get('MIRAGE_POSTGRES_PORT', '5432')} "
        f"user={os.environ['MIRAGE_POSTGRES_USER']} "
        f"password={os.environ['MIRAGE_POSTGRES_PASSWORD']} "
        f"dbname={os.environ['MIRAGE_POSTGRES_DB']}"
    )


def _storage() -> S3ObjectStore:
    return S3ObjectStore(
        EvidenceStorageConfig(
            bucket=os.environ["MIRAGE_EVIDENCE_BUCKET"],
            region=os.environ["MIRAGE_EVIDENCE_REGION"],
            object_lock_mode=os.environ["MIRAGE_EVIDENCE_OBJECT_LOCK_MODE"],
            retention_days=int(os.environ["MIRAGE_EVIDENCE_RETENTION_DAYS"]),
            multipart_threshold_mb=int(os.environ["MIRAGE_EVIDENCE_MULTIPART_THRESHOLD_MB"]),
            max_retries=int(os.environ["MIRAGE_EVIDENCE_MAX_RETRIES"]),
            request_timeout_seconds=int(
                os.environ["MIRAGE_EVIDENCE_REQUEST_TIMEOUT_SECONDS"]
            ),
            kms_signing_key_arn=os.environ["MIRAGE_KMS_SIGNING_KEY_ARN"],
            endpoint_url=os.environ.get("MIRAGE_EVIDENCE_ENDPOINT_URL"),
        )
    )


async def run() -> None:
    store = _storage()
    evidence_service = EvidenceService(store=store)
    if os.getenv("MIRAGE_EXPORT_SIGNER", "KMS") == "LOCAL_DEVELOPMENT":
        signer: ManifestSigner = LocalDevelopmentSigner(
            rsa.generate_private_key(public_exponent=65537, key_size=3072)
        )
    else:
        signer = KmsManifestSigner(
            os.environ["MIRAGE_KMS_SIGNING_KEY_ARN"],
            region=os.environ["MIRAGE_EVIDENCE_REGION"],
        )
    timestamp_url = os.getenv("MIRAGE_RFC3161_AUTHORITY_URL")
    timestamp = (
        Rfc3161TimestampProvider(
            timestamp_url,
            ca_file=os.getenv("MIRAGE_RFC3161_CA_FILE"),
        )
        if timestamp_url
        else LocalDevelopmentTimestampProvider()
    )
    while True:
        async with await psycopg.AsyncConnection.connect(_dsn()) as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT export_id FROM evidence_exports
                    WHERE verification_status='PENDING' AND manifest_sha256 IS NULL
                    ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
                    """
                )
                row = await cur.fetchone()
            if row is None:
                await conn.rollback()
                processed = await process_next_report(
                    conn,
                    evidence_service=evidence_service,
                    object_store=store,
                    signer=signer,
                )
                if processed:
                    await conn.commit()
                else:
                    await conn.rollback()
                    await asyncio.sleep(0.25)
                continue
            try:
                await generate_export(
                    conn,
                    export_id=row[0],
                    evidence_service=evidence_service,
                    object_store=store,
                    signer=signer,
                    timestamp_provider=timestamp,
                )
                await conn.commit()
            except ExportNotEligibleError as exc:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        UPDATE evidence_exports SET verification_status='FAILED',
                            verification_error=%s WHERE export_id=%s
                        """,
                        (f"ExportNotEligibleError: {exc}"[:1024], row[0]),
                    )
                # Pre-export verification history and any failure status are
                # deliberately committed for investigation.
                await conn.commit()
            except Exception as exc:  # noqa: BLE001
                await conn.rollback()
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        UPDATE evidence_exports SET verification_status='FAILED',
                            verification_error=%s WHERE export_id=%s
                        """,
                        (f"{type(exc).__name__}: {exc}"[:1024], row[0]),
                    )
                await conn.commit()


def main() -> None:
    if endpoint := os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        configure_otel(
            service_name="mirage-report-worker",
            endpoint=endpoint,
            environment=os.getenv("MIRAGE_ENV", "development"),
        )
    asyncio.run(run())
