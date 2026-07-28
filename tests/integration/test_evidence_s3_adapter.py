from __future__ import annotations

import io
import time

import boto3
import httpx
import pytest
from testcontainers.core.container import DockerContainer

from mirage_common.evidence import EvidenceStorageConfig, S3ObjectStore

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def minio_endpoint():
    access_key = "mirage_test_minio"
    secret_key = "mirage_test_local_only_minio"
    container = (
        DockerContainer("minio/minio:RELEASE.2025-04-22T22-12-26Z")
        .with_command("server /data")
        .with_env("MINIO_ROOT_USER", access_key)
        .with_env("MINIO_ROOT_PASSWORD", secret_key)
        .with_exposed_ports(9000)
    )
    container.start()
    endpoint = (
        f"http://{container.get_container_host_ip()}:{container.get_exposed_port(9000)}"
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            if httpx.get(f"{endpoint}/minio/health/ready", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.5)
    else:
        container.stop()
        raise TimeoutError("MinIO did not become healthy")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
    client.create_bucket(Bucket="mirage-evidence", ObjectLockEnabledForBucket=True)
    client.put_bucket_versioning(
        Bucket="mirage-evidence", VersioningConfiguration={"Status": "Enabled"}
    )
    yield {
        "endpoint": endpoint,
        "access_key": access_key,
        "secret_key": secret_key,
        "client": client,
    }
    container.stop()


@pytest.mark.asyncio
async def test_real_s3_compatible_version_and_object_lock(
    minio_endpoint, monkeypatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", minio_endpoint["access_key"])
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", minio_endpoint["secret_key"])
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    config = EvidenceStorageConfig(
        bucket="mirage-evidence",
        region="us-east-1",
        object_lock_mode="GOVERNANCE",
        retention_days=1,
        multipart_threshold_mb=5,
        max_retries=2,
        request_timeout_seconds=5,
        kms_signing_key_arn="LOCAL_DEV_NO_KMS",
        endpoint_url=minio_endpoint["endpoint"],
    )
    store = S3ObjectStore(config)
    data = b"real S3-compatible evidence bytes"
    stored = await store.put(
        key="cases/01ARZ3NDEKTSV4RRFFQ69G5FAV/logs/01ARZ3NDEKTSV4RRFFQ69G5FAW-test.log",
        stream=io.BytesIO(data),
        size_bytes=len(data),
        media_type="text/plain",
        sha256="e45d2c8191dbd0c4260817981ee7ac75afd2340639ff983c24f5bdfe16d25873",
        correlation_id="01ARZ3NDEKTSV4RRFFQ69G5FAX",
    )
    assert stored.version_id
    assert stored.object_lock_mode == "GOVERNANCE"
    stream = await store.open(
        bucket=stored.bucket, key=stored.key, version_id=stored.version_id
    )
    try:
        assert stream.read() == data
    finally:
        stream.close()
