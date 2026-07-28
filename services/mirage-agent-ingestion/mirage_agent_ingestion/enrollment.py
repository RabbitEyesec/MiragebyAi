"""Core Step 3 enrollment/renewal/revocation logic — the 10-step sequence
from the Prompt-1 brief, implemented against a real Postgres connection and
a real step-ca instance (via libs/mirage_common/step_ca_client).

Deliberately framework-agnostic (no FastAPI import here) so it is fully
unit/integration-testable without an HTTP server; Step 4b wires this to
`POST /api/v1/enroll`.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt as pyjwt
import psycopg
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from mirage_agent_ingestion.errors import (
    BuildHashNotAllowedError,
    CaSigningError,
    EnrollmentTokenInvalidError,
    HostFingerprintInvalidError,
)
from mirage_agent_ingestion.provisioners import ROLE_TO_PROFILE, ProvisionerSource
from mirage_common.step_ca_client import CsrSigningError as _StepCaHttpError
from mirage_common.step_ca_client import (
    MintedToken,
    fetch_root_fingerprint,
    mint_enrollment_token,
    revoke_certificate,
    sign_csr,
)

VALID_ROLES = frozenset(ROLE_TO_PROFILE)


@dataclass(frozen=True)
class CaConfig:
    ca_url: str  # e.g. "https://localhost:9000"
    root_cert_path: str
    provisioners: ProvisionerSource


@dataclass(frozen=True)
class EnrollResult:
    agent_id: str
    role: str
    certificate_profile: str
    certificate_pem: str
    certificate_chain_pem: str
    certificate_serial: str
    not_after: str


def _serial_base10(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    return str(cert.serial_number)


# ---------------------------------------------------------------------------
# Step 1-3 of the sequence: control plane creates + stores a one-time token.
# ---------------------------------------------------------------------------

async def create_enrollment_token(
    conn: psycopg.AsyncConnection,
    ca: CaConfig,
    *,
    role: str,
    subject: str,
    sans: list[str],
    created_by: str,
    ttl_seconds: int = 300,
) -> MintedToken:
    if role not in VALID_ROLES:
        raise ValueError(f"unknown role: {role!r}")

    provisioner_key = ca.provisioners.get_key(role)
    provisioner_name = ca.provisioners.provisioner_name(role)
    root_fp = fetch_root_fingerprint(ca.root_cert_path)

    minted = mint_enrollment_token(
        provisioner_name=provisioner_name,
        provisioner_key=provisioner_key,
        subject=subject,
        sans=sans,
        ca_sign_url=f"{ca.ca_url}/1.0/sign",
        root_fingerprint=root_fp,
        ttl_seconds=ttl_seconds,
    )

    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO enrollment_tokens (token_id, role, provisioner_name, subject, sans, expires_at, created_by)
            VALUES (%s, %s, %s, %s, %s, to_timestamp(%s), %s)
            """,
            (uuid.UUID(minted.jti), role, provisioner_name, subject, sans, minted.expires_at, created_by),
        )
    await conn.commit()
    return minted


# ---------------------------------------------------------------------------
# Steps 4-10: agent presents token + CSR + host_fingerprint + build_hash.
# ---------------------------------------------------------------------------

async def enroll_agent(
    conn: psycopg.AsyncConnection,
    ca: CaConfig,
    *,
    enrollment_token: str,
    csr_pem: str,
    host_fingerprint: str,
    build_hash: str,
) -> EnrollResult:
    try:
        unverified = pyjwt.decode(enrollment_token, options={"verify_signature": False})
    except pyjwt.PyJWTError as exc:
        raise EnrollmentTokenInvalidError() from exc

    jti = unverified.get("jti")
    if not jti:
        raise EnrollmentTokenInvalidError()

    if not host_fingerprint or len(host_fingerprint) > 256:
        raise HostFingerprintInvalidError()
    if not build_hash or not all(c in "0123456789abcdef" for c in build_hash.lower()) or len(build_hash) != 64:
        raise BuildHashNotAllowedError()

    # Step 6: validate token + invalidate transactionally in one statement —
    # zero rows updated means unknown, already-used, or expired (Step 3
    # acceptance: "token reuse fails").
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE enrollment_tokens
               SET used_at = now(), used_by_agent_id = %s
             WHERE token_id = %s AND used_at IS NULL AND expires_at > now()
             RETURNING role, provisioner_name, subject, sans
            """,
            (unverified.get("sub"), uuid.UUID(jti)),
        )
        row = await cur.fetchone()
        if row is None:
            await conn.commit()  # commit so a concurrent racer's outcome is visible
            raise EnrollmentTokenInvalidError()
        role, _provisioner_name, subject, _sans = row

        # Build-hash allowlist check (Step 3: "invalid build hash fails").
        await cur.execute(
            "SELECT 1 FROM build_hash_allowlist WHERE build_hash = %s AND role = %s",
            (build_hash, role),
        )
        allowed = await cur.fetchone()
        if allowed is None:
            await conn.commit()
            raise BuildHashNotAllowedError()

    try:
        issued = sign_csr(ca_url=ca.ca_url, root_cert_path=ca.root_cert_path, csr_pem=csr_pem, token=enrollment_token)
    except _StepCaHttpError as exc:
        await conn.commit()
        raise CaSigningError(str(exc)) from exc

    serial = _serial_base10(issued.certificate_pem)
    agent_id = subject
    profile = ROLE_TO_PROFILE[role]

    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO agents (agent_id, role, certificate_profile, certificate_serial, certificate_not_after,
                                 build_hash, host_fingerprint)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (agent_id) DO UPDATE SET
                certificate_profile = EXCLUDED.certificate_profile,
                certificate_serial = EXCLUDED.certificate_serial,
                certificate_not_after = EXCLUDED.certificate_not_after,
                build_hash = EXCLUDED.build_hash,
                host_fingerprint = EXCLUDED.host_fingerprint,
                status = 'ACTIVE',
                revoked_at = NULL,
                revoked_reason = NULL
            """,
            (agent_id, role, profile, serial, issued.not_after, build_hash, host_fingerprint),
        )
        await cur.execute(
            "INSERT INTO certificate_history (agent_id, certificate_serial, action, detail) VALUES (%s, %s, 'ISSUED', %s)",
            (agent_id, serial, f"enrolled via token {jti}"),
        )
    await conn.commit()

    return EnrollResult(
        agent_id=agent_id,
        role=role,
        certificate_profile=profile,
        certificate_pem=issued.certificate_pem,
        certificate_chain_pem=issued.certificate_chain_pem,
        certificate_serial=serial,
        not_after=issued.not_after,
    )


# ---------------------------------------------------------------------------
# Renewal — preserves agent_id (identity), rotates certificate_serial.
# ---------------------------------------------------------------------------

async def renew_agent(
    conn: psycopg.AsyncConnection,
    ca: CaConfig,
    *,
    agent_id: str,
    csr_pem: str,
    ttl_seconds: int = 300,
) -> EnrollResult:
    async with conn.cursor() as cur:
        await cur.execute("SELECT role, status FROM agents WHERE agent_id = %s", (agent_id,))
        row = await cur.fetchone()
    if row is None:
        from mirage_agent_ingestion.errors import AgentNotFoundError

        raise AgentNotFoundError(agent_id)
    role, status = row
    if status != "ACTIVE":
        from mirage_agent_ingestion.errors import AgentAlreadyRevokedError

        raise AgentAlreadyRevokedError(agent_id)

    provisioner_key = ca.provisioners.get_key(role)
    provisioner_name = ca.provisioners.provisioner_name(role)
    root_fp = fetch_root_fingerprint(ca.root_cert_path)
    minted = mint_enrollment_token(
        provisioner_name=provisioner_name,
        provisioner_key=provisioner_key,
        subject=agent_id,
        sans=[agent_id],
        ca_sign_url=f"{ca.ca_url}/1.0/sign",
        root_fingerprint=root_fp,
        ttl_seconds=ttl_seconds,
    )
    try:
        issued = sign_csr(ca_url=ca.ca_url, root_cert_path=ca.root_cert_path, csr_pem=csr_pem, token=minted.token)
    except _StepCaHttpError as exc:
        raise CaSigningError(str(exc)) from exc

    serial = _serial_base10(issued.certificate_pem)
    profile = ROLE_TO_PROFILE[role]

    async with conn.cursor() as cur:
        # agent_id is UNCHANGED — this IS the "renewal preserves identity" guarantee.
        await cur.execute(
            "UPDATE agents SET certificate_serial = %s, certificate_not_after = %s WHERE agent_id = %s",
            (serial, issued.not_after, agent_id),
        )
        await cur.execute(
            "INSERT INTO certificate_history (agent_id, certificate_serial, action, detail) VALUES (%s, %s, 'RENEWED', %s)",
            (agent_id, serial, "renewed"),
        )
    await conn.commit()

    return EnrollResult(
        agent_id=agent_id,
        role=role,
        certificate_profile=profile,
        certificate_pem=issued.certificate_pem,
        certificate_chain_pem=issued.certificate_chain_pem,
        certificate_serial=serial,
        not_after=issued.not_after,
    )


def renewal_due(*, not_after_epoch: float, issued_at_epoch: float, now_epoch: float | None = None) -> bool:
    """Step 3 rule: auto-renew before 20% of the certificate's lifetime remains."""
    now_epoch = now_epoch if now_epoch is not None else time.time()
    total_lifetime = not_after_epoch - issued_at_epoch
    remaining = not_after_epoch - now_epoch
    if total_lifetime <= 0:
        return True
    return (remaining / total_lifetime) <= 0.20


# ---------------------------------------------------------------------------
# Revocation — Postgres-authoritative + passive step-ca revocation (ADR-0013).
# ---------------------------------------------------------------------------

async def revoke_agent(conn: psycopg.AsyncConnection, ca: CaConfig, *, agent_id: str, reason: str) -> None:
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT role, certificate_serial, status FROM agents WHERE agent_id = %s", (agent_id,)
        )
        row = await cur.fetchone()
    if row is None:
        from mirage_agent_ingestion.errors import AgentNotFoundError

        raise AgentNotFoundError(agent_id)
    role, serial, status = row
    if status == "REVOKED":
        return  # idempotent — already revoked

    async with conn.cursor() as cur:
        await cur.execute(
            "UPDATE agents SET status = 'REVOKED', revoked_at = now(), revoked_reason = %s WHERE agent_id = %s",
            (reason, agent_id),
        )
        await cur.execute(
            "INSERT INTO certificate_history (agent_id, certificate_serial, action, detail) VALUES (%s, %s, 'REVOKED', %s)",
            (agent_id, serial, reason),
        )
    await conn.commit()

    # Best-effort step-ca-level passive revocation — Postgres above is already
    # authoritative for connection admission (ADR-0013), so a CA-side failure
    # here does not leave the agent able to reconnect.
    provisioner_key = ca.provisioners.get_key(role)
    provisioner_name = ca.provisioners.provisioner_name(role)
    root_fp = fetch_root_fingerprint(ca.root_cert_path)
    minted = mint_enrollment_token(
        provisioner_name=provisioner_name,
        provisioner_key=provisioner_key,
        subject=agent_id,
        sans=[agent_id],
        ca_sign_url=f"{ca.ca_url}/1.0/revoke",
        root_fingerprint=root_fp,
        ttl_seconds=60,
    )
    revoke_certificate(
        ca_url=ca.ca_url, root_cert_path=ca.root_cert_path, serial_base10=serial, token=minted.token, reason=reason,
    )


async def is_agent_active(conn: psycopg.AsyncConnection, *, certificate_serial: str) -> bool:
    """The actual "revoked-client connection rejection" check — call this on
    every connection/event-acceptance path before honoring a request."""
    async with conn.cursor() as cur:
        await cur.execute("SELECT status FROM agents WHERE certificate_serial = %s", (certificate_serial,))
        row = await cur.fetchone()
    return row is not None and row[0] == "ACTIVE"
