"""Integration tests: Step 3 trust/enrolment/rotation, against a real
Postgres container and a real ephemeral step-ca container (provisioned with
the five Mirage certificate profiles). Covers every Step 3 acceptance line:
"agent enrols over mTLS" (well, over the CSR-sign flow that produces the
mTLS-usable cert), "token reuse fails", "invalid build hash fails",
"renewal preserves identity", "destroyed sandbox's cert is refused" /
"revoked certificate is refused".
"""
from __future__ import annotations

import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from mirage_agent_ingestion.enrollment import (
    CaConfig,
    create_enrollment_token,
    enroll_agent,
    is_agent_active,
    renew_agent,
    revoke_agent,
)
from mirage_agent_ingestion.errors import BuildHashNotAllowedError, EnrollmentTokenInvalidError
from mirage_agent_ingestion.provisioners import DevFileProvisionerSource

pytestmark = pytest.mark.integration

TEST_BUILD_HASH = "a" * 64


def _generate_csr(common_name: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def ca_config(step_ca_container) -> CaConfig:
    return CaConfig(
        ca_url=step_ca_container["ca_url"],
        root_cert_path=step_ca_container["root_cert_path"],
        provisioners=DevFileProvisionerSource(keys_dir=step_ca_container["keys_dir"]),
    )


async def _allow_build_hash(pg_conn, role: str, build_hash: str = TEST_BUILD_HASH) -> None:
    async with pg_conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO build_hash_allowlist (build_hash, role, label) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (build_hash, role, "test"),
        )
    await pg_conn.commit()


async def test_full_enrollment_flow_issues_certificate(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"

    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )
    csr = _generate_csr(agent_id)

    result = await enroll_agent(
        pg_conn, ca_config,
        enrollment_token=minted.token, csr_pem=csr,
        host_fingerprint="AA:BB:CC:DD:EE:FF", build_hash=TEST_BUILD_HASH,
    )

    assert result.agent_id == agent_id
    assert result.role == "ENDPOINT"
    assert result.certificate_profile == "MirageEndpoint"
    assert result.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert await is_agent_active(pg_conn, certificate_serial=result.certificate_serial)


async def test_token_reuse_fails(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )

    # First use succeeds.
    await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="AA:BB:CC:DD:EE:FF", build_hash=TEST_BUILD_HASH,
    )

    # Second use of the SAME token must fail — token reuse.
    with pytest.raises(EnrollmentTokenInvalidError):
        await enroll_agent(
            pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
            host_fingerprint="AA:BB:CC:DD:EE:FF", build_hash=TEST_BUILD_HASH,
        )


async def test_expired_token_rejected(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"
    # ttl_seconds=0 -> expires immediately (exp == iat means "now" is already >= exp on any check a moment later).
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test", ttl_seconds=0,
    )
    import asyncio

    await asyncio.sleep(1.1)

    with pytest.raises(EnrollmentTokenInvalidError):
        await enroll_agent(
            pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
            host_fingerprint="AA:BB:CC:DD:EE:FF", build_hash=TEST_BUILD_HASH,
        )


async def test_invalid_build_hash_fails(pg_conn, ca_config):
    # Deliberately do NOT allowlist this build hash.
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )

    with pytest.raises(BuildHashNotAllowedError):
        await enroll_agent(
            pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
            host_fingerprint="AA:BB:CC:DD:EE:FF", build_hash="f" * 64,
        )

    # The token is consumed even on this failure — by design, a one-time
    # token is single-shot regardless of outcome, so it cannot be used as a
    # retry oracle for guessing an allowlisted build hash.
    with pytest.raises(EnrollmentTokenInvalidError):
        await enroll_agent(
            pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
            host_fingerprint="AA:BB:CC:DD:EE:FF", build_hash=TEST_BUILD_HASH,
        )


async def test_renewal_preserves_identity(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "SPIDER")
    agent_id = f"spider-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="SPIDER", subject=agent_id, sans=[agent_id], created_by="test",
    )
    first = await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="11:22:33:44:55:66", build_hash=TEST_BUILD_HASH,
    )

    renewed = await renew_agent(pg_conn, ca_config, agent_id=agent_id, csr_pem=_generate_csr(agent_id))

    assert renewed.agent_id == first.agent_id  # identity preserved
    assert renewed.certificate_serial != first.certificate_serial  # cert rotated
    assert await is_agent_active(pg_conn, certificate_serial=renewed.certificate_serial)


async def test_revoked_certificate_is_refused(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "ENV_CONTROLLER")
    agent_id = f"env-controller-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENV_CONTROLLER", subject=agent_id, sans=[agent_id], created_by="test",
    )
    result = await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="AA:BB:CC:00:11:22", build_hash=TEST_BUILD_HASH,
    )
    assert await is_agent_active(pg_conn, certificate_serial=result.certificate_serial)

    await revoke_agent(pg_conn, ca_config, agent_id=agent_id, reason="sandbox destroyed")

    # This IS the "revoked-client connection rejection" / "destroyed
    # sandbox's cert is refused" check — every connection-admission path
    # calls is_agent_active() before honoring a request.
    assert not await is_agent_active(pg_conn, certificate_serial=result.certificate_serial)


async def test_destroyed_sandbox_identity_cannot_reconnect(pg_conn, ca_config):
    """Simulates the Step 3 acceptance line 'a destroyed sandbox's cert is
    refused': an ENV_CONTROLLER-role agent (the sandbox's identity) is
    revoked, and any subsequent connection-admission check for it fails —
    permanently, not just until some cache expires."""
    await _allow_build_hash(pg_conn, "ENV_CONTROLLER")
    agent_id = f"sandbox-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENV_CONTROLLER", subject=agent_id, sans=[agent_id], created_by="test",
    )
    result = await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="DE:AD:BE:EF:00:01", build_hash=TEST_BUILD_HASH,
    )

    await revoke_agent(pg_conn, ca_config, agent_id=agent_id, reason="sandbox destroyed")

    for _ in range(3):  # "cannot reconnect" — checked repeatedly, never flips back
        assert not await is_agent_active(pg_conn, certificate_serial=result.certificate_serial)


async def test_certificate_history_records_full_lifecycle(pg_conn, ca_config):
    await _allow_build_hash(pg_conn, "ENDPOINT")
    agent_id = f"endpoint-{uuid.uuid4().hex}.mirage.local"
    minted = await create_enrollment_token(
        pg_conn, ca_config, role="ENDPOINT", subject=agent_id, sans=[agent_id], created_by="test",
    )
    await enroll_agent(
        pg_conn, ca_config, enrollment_token=minted.token, csr_pem=_generate_csr(agent_id),
        host_fingerprint="00:11:22:33:44:55", build_hash=TEST_BUILD_HASH,
    )
    await renew_agent(pg_conn, ca_config, agent_id=agent_id, csr_pem=_generate_csr(agent_id))
    await revoke_agent(pg_conn, ca_config, agent_id=agent_id, reason="test teardown")

    async with pg_conn.cursor() as cur:
        await cur.execute(
            "SELECT action FROM certificate_history WHERE agent_id = %s ORDER BY at", (agent_id,)
        )
        actions = [row[0] for row in await cur.fetchall()]

    assert actions == ["ISSUED", "RENEWED", "REVOKED"]
