"""Typed enrollment failures — each maps to a distinct agent.enrollment_failed
reason (schemas/events/agent.enrollment_failed.v1.schema.json) and a distinct
API error_code once the HTTP layer wraps these (Step 4b)."""
from __future__ import annotations


class EnrollmentError(Exception):
    reason: str = "UNKNOWN"


class EnrollmentTokenInvalidError(EnrollmentError):
    """Covers unknown token, already-used token (reuse), and expired token —
    deliberately one error for all three: the transactional UPDATE that
    detects them (`WHERE used_at IS NULL AND expires_at > now()`) cannot
    distinguish which case applied without a second query, and from a
    security standpoint they should be indistinguishable to the caller
    anyway (no information leak about *why* a token didn't work)."""

    reason = "TOKEN_EXPIRED_OR_REUSED_OR_UNKNOWN"


class BuildHashNotAllowedError(EnrollmentError):
    reason = "BUILD_HASH_NOT_ALLOWLISTED"


class HostFingerprintInvalidError(EnrollmentError):
    reason = "HOST_FINGERPRINT_INVALID"


class CsrInvalidError(EnrollmentError):
    reason = "CSR_INVALID"


class CaSigningError(EnrollmentError):
    reason = "CA_SIGNING_ERROR"


class AgentNotFoundError(Exception):
    pass


class AgentAlreadyRevokedError(Exception):
    pass
