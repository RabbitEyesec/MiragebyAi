"""Database-backed artifact scanner worker."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.artifacts import ArtifactScanner, ArtifactScannerConfig, StagedArtifact
from mirage_common.telemetry import configure_otel
from mirage_contracts.ulid import generate_ulid


async def scan_artifact_record(
    conn: psycopg.AsyncConnection,
    *,
    artifact_id: str,
    scanner: ArtifactScanner,
) -> str:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT quarantine_location,sanitised_filename,size_bytes,sha256
            FROM artifacts WHERE artifact_id=%s FOR UPDATE
            """,
            (artifact_id,),
        )
        row = await cur.fetchone()
        if row is None:
            raise ValueError("artifact not found")
        await cur.execute(
            "UPDATE artifacts SET scan_status='SCANNING' WHERE artifact_id=%s",
            (artifact_id,),
        )
    staged = StagedArtifact(Path(row[0]), row[1], row[2], row[3])
    result = scanner.scan(staged)
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE artifacts SET scan_status=%s,detected_type=%s,clamav_result=%s,
                yara_matches=%s,oletools_result=%s,archive_metadata=%s,
                observation_levels=%s,scanned_at=now()
            WHERE artifact_id=%s
            """,
            (
                result.status,
                result.detected_type,
                Jsonb(result.clamav_result),
                Jsonb(list(result.yara_matches)),
                Jsonb(result.oletools_result),
                Jsonb(result.archive_metadata),
                Jsonb(list(result.observation_levels)),
                artifact_id,
            ),
        )
        await cur.execute(
            """
            INSERT INTO audit_events
                (actor,actor_type,action,target,outcome,correlation_id,detail)
            VALUES ('mirage-artifact-scanner','SYSTEM','artifact.scanned',%s,%s,%s,%s)
            """,
            (
                artifact_id,
                "SUCCESS" if result.status not in {"FAILED"} else "FAILURE",
                generate_ulid(),
                result.status,
            ),
        )
    return result.status


def _dsn() -> str:
    return (
        f"host={os.environ['MIRAGE_POSTGRES_HOST']} "
        f"port={os.environ.get('MIRAGE_POSTGRES_PORT', '5432')} "
        f"user={os.environ['MIRAGE_POSTGRES_USER']} "
        f"password={os.environ['MIRAGE_POSTGRES_PASSWORD']} "
        f"dbname={os.environ['MIRAGE_POSTGRES_DB']}"
    )


def _config() -> ArtifactScannerConfig:
    return ArtifactScannerConfig(
        max_upload_mb=int(os.getenv("ARTIFACT_MAX_UPLOAD_MB", "250")),
        max_archive_depth=int(os.getenv("ARTIFACT_MAX_ARCHIVE_DEPTH", "3")),
        max_archive_members=int(os.getenv("ARTIFACT_MAX_ARCHIVE_MEMBERS", "1000")),
        max_expanded_mb=int(os.getenv("ARTIFACT_MAX_EXPANDED_MB", "500")),
        max_compression_ratio=float(os.getenv("ARTIFACT_MAX_COMPRESSION_RATIO", "100")),
        per_member_max_mb=int(os.getenv("ARTIFACT_MAX_MEMBER_MB", "250")),
        scan_timeout_seconds=int(os.getenv("ARTIFACT_SCAN_TIMEOUT_SECONDS", "120")),
        clamav_timeout_seconds=int(os.getenv("ARTIFACT_CLAMAV_TIMEOUT_SECONDS", "60")),
        yara_timeout_seconds=int(os.getenv("ARTIFACT_YARA_TIMEOUT_SECONDS", "30")),
        oletools_timeout_seconds=int(os.getenv("ARTIFACT_OLETOOLS_TIMEOUT_SECONDS", "30")),
        yara_rules_path=os.getenv("ARTIFACT_YARA_RULES_PATH"),
        clamav_database_path=os.getenv("ARTIFACT_CLAMAV_DATABASE_PATH"),
    )


async def run_worker() -> None:
    scanner = ArtifactScanner(_config())
    while True:
        async with (
            await psycopg.AsyncConnection.connect(_dsn()) as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                """
                SELECT artifact_id FROM artifacts
                WHERE scan_status IN ('UPLOADED','QUARANTINED')
                ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
                """
            )
            row = await cur.fetchone()
            if row is None:
                await conn.rollback()
            else:
                await scan_artifact_record(conn, artifact_id=row[0], scanner=scanner)
                await conn.commit()
        await asyncio.sleep(0.25 if row is None else 0)


def main() -> None:
    if endpoint := os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        configure_otel(
            service_name="mirage-artifact-scanner",
            endpoint=endpoint,
            environment=os.getenv("MIRAGE_ENV", "development"),
        )
    asyncio.run(run_worker())
