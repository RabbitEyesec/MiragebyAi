"""step-ca client: decrypt a provisioner's encrypted JWK, mint a one-time
enrollment bootstrap JWT ("ott" in step-ca's own terminology) for a specific
certificate profile, and submit a CSR to step-ca's /1.0/sign endpoint
(Step 3, Appendix G certificate profiles).

The exact bootstrap-token claim shape and /1.0/sign request/response
contract below were verified empirically against a real running step-ca
container (not guessed from documentation) — see TEST_RESULTS.md §Step3.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import httpx
import jwt as pyjwt
from jwcrypto import jwa as _jwa
from jwcrypto import jwe as _jwe
from jwcrypto import jwk as _jwk

# step-ca's own `step crypto jwk create` uses PBES2 with a 600,000-iteration
# PBKDF2 (a deliberately high, secure iteration count) to encrypt provisioner
# private keys. jwcrypto's default safety cap (16,384) rejects that as
# "too large" — raise it once, module-level. This is not weakening anything;
# it accommodates a KNOWN-GOOD high iteration count from our own trusted CA
# tooling, not attacker-supplied input.
_jwa.default_max_pbkdf2_iterations = 1_000_000


class StepCaError(Exception):
    """Base class for step-ca client failures. Never leaks the CA private key."""


class CsrSigningError(StepCaError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"step-ca /1.0/sign failed ({status_code}): {detail}")
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class DecryptedProvisionerKey:
    private_key_pem: bytes
    public_jwk: dict
    kid: str


def decrypt_provisioner_key(encrypted_jwk_json: str, public_jwk: dict, password: str) -> DecryptedProvisionerKey:
    """Decrypt a step-ca JWK provisioner's encrypted private key (JWE compact
    or general JSON serialization, as produced by `step crypto jwk create`).
    """
    envelope = _jwe.JWE()
    envelope.deserialize(encrypted_jwk_json)
    envelope.decrypt(_jwk.JWK.from_password(password))
    key = _jwk.JWK.from_json(envelope.payload.decode())
    pem = key.export_to_pem(private_key=True, password=None)
    return DecryptedProvisionerKey(private_key_pem=pem, public_jwk=public_jwk, kid=public_jwk["kid"])


@dataclass(frozen=True)
class MintedToken:
    token: str
    jti: str
    expires_at: int  # unix epoch seconds


def mint_enrollment_token(
    *,
    provisioner_name: str,
    provisioner_key: DecryptedProvisionerKey,
    subject: str,
    sans: list[str],
    ca_sign_url: str,
    root_fingerprint: str,
    ttl_seconds: int = 300,
) -> MintedToken:
    """Mint a step-ca JWK-provisioner bootstrap token ("ott"). Claims match
    exactly what `step ca token` produces (verified empirically): aud, exp,
    iat, iss, jti, nbf, sans, sha (root fingerprint), sub, user.

    `ttl_seconds` is deliberately short (default 5 minutes) — this is the
    ONE-TIME ENROLLMENT TOKEN's validity window, not the resulting
    certificate's lifetime (that is controlled by the provisioner's
    `claims.defaultTLSCertDuration` in ca.json, see infra/step-ca/PROFILES.md).
    """
    now = int(time.time())
    exp = now + ttl_seconds
    jti = uuid.uuid4().hex
    claims = {
        "aud": ca_sign_url,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "iss": provisioner_name,
        "jti": jti,
        "sans": sans,
        "sha": root_fingerprint,
        "sub": subject,
        "user": {},
    }
    token = pyjwt.encode(
        claims,
        provisioner_key.private_key_pem,
        algorithm="ES256",
        headers={"kid": provisioner_key.kid},
    )
    return MintedToken(token=token, jti=jti, expires_at=exp)


@dataclass(frozen=True)
class IssuedCertificate:
    certificate_pem: str
    certificate_chain_pem: str
    not_after: str


def sign_csr(*, ca_url: str, root_cert_path: str, csr_pem: str, token: str, timeout: float = 10.0) -> IssuedCertificate:
    """POST /1.0/sign — exchange a CSR + bootstrap token for a signed cert."""
    with httpx.Client(verify=root_cert_path, timeout=timeout) as client:
        response = client.post(f"{ca_url}/1.0/sign", json={"csr": csr_pem, "ott": token})
    # step-ca returns 201 Created on success (verified empirically), not 200.
    if response.status_code != 201:
        raise CsrSigningError(response.status_code, response.text)
    body = response.json()
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    leaf = x509.load_pem_x509_certificate(body["crt"].encode(), default_backend())
    not_after = leaf.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    chain_pem = "\n".join(body.get("certChain", [body["crt"]]))
    return IssuedCertificate(certificate_pem=body["crt"], certificate_chain_pem=chain_pem, not_after=not_after)


def revoke_certificate(
    *,
    ca_url: str,
    root_cert_path: str,
    serial_base10: str,
    token: str,
    reason: str,
    reason_code: int = 0,
    timeout: float = 10.0,
) -> None:
    """POST /1.0/revoke. `token`'s `aud` claim must be `<ca_url>/1.0/revoke`
    (mint via mint_enrollment_token with that as ca_sign_url).

    Always requests PASSIVE revocation (`passive: true`) — verified
    empirically that this step-ca's badgerv2 storage backend returns
    501 "non-passive revocation not implemented" for active/immediate
    (CRL/OCSP-backed) revocation, but supports passive revocation cleanly
    (200 OK). Passive revocation means the certificate can never be
    RENEWED again from this point on; it remains cryptographically valid
    for whatever remains of its lifetime. Combined with Mirage's short
    (<=24h for agent certs) lifetimes and our own Postgres-authoritative
    `agents.status` check on every connection (the actual "revoked-client
    connection rejection" enforcement point — see
    mirage_agent_ingestion.enrollment.is_agent_active), this is a complete,
    defense-in-depth revocation story: Postgres gives immediate rejection,
    passive CA revocation guarantees the certificate can't outlive that by
    renewing itself. See ARCHITECTURE_DECISIONS.md ADR-0013.
    """
    with httpx.Client(verify=root_cert_path, timeout=timeout) as client:
        response = client.post(
            f"{ca_url}/1.0/revoke",
            json={"serial": serial_base10, "ott": token, "reasonCode": reason_code, "reason": reason, "passive": True},
        )
    if response.status_code != 200:
        raise CsrSigningError(response.status_code, response.text)


def fetch_root_fingerprint(root_cert_path: str) -> str:
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    with open(root_cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
