"""Opaque canary tokens, signed callback events, and pre-display classification."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg

from mirage_contracts.envelope import canonical_json_bytes
from mirage_contracts.ulid import generate_ulid

INTERNAL_CATEGORIES = frozenset(
    {
        "SANDBOX_ENI",
        "ENDPOINT_ENI",
        "MIRAGE_PROXY",
        "NGINX_BROKER",
        "SSH_BASTION",
        "RD_GATEWAY",
        "NAT",
        "VPN_EGRESS",
        "TEST_INFRASTRUCTURE",
    }
)
SCANNER_CATEGORIES = frozenset(
    {"SECURITY_SCANNER", "EMAIL_SCANNER", "AV_GATEWAY", "BROWSER_SECURITY_SCANNER"}
)
RULE_VERSION = "1.0"


@dataclass(frozen=True)
class CanaryToken:
    token_id: str
    public_token: str
    public_token_hash: str
    case_id: str
    artifact_id: str
    created_at: datetime
    expires_at: datetime
    expected_usage: str
    signing_version: str


def create_canary_token(
    *,
    case_id: str,
    artifact_id: str,
    expires_at: datetime,
    expected_usage: str,
    signing_version: str = "1",
) -> CanaryToken:
    if expected_usage not in {"ONE_TIME", "REUSABLE"}:
        raise ValueError("expected_usage must be ONE_TIME or REUSABLE")
    public = secrets.token_urlsafe(32)
    return CanaryToken(
        token_id=generate_ulid(),
        public_token=public,
        public_token_hash=hashlib.sha256(public.encode()).hexdigest(),
        case_id=case_id,
        artifact_id=artifact_id,
        created_at=datetime.now(UTC),
        expires_at=expires_at,
        expected_usage=expected_usage,
        signing_version=signing_version,
    )


def token_hash(public_token: str) -> str:
    return hashlib.sha256(public_token.encode()).hexdigest()


async def issue_canary_token(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    artifact_id: str,
    expires_at: datetime,
    expected_usage: str,
    signing_version: str = "1",
) -> CanaryToken:
    token = create_canary_token(
        case_id=case_id,
        artifact_id=artifact_id,
        expires_at=expires_at,
        expected_usage=expected_usage,
        signing_version=signing_version,
    )
    if expires_at <= token.created_at:
        raise ValueError("canary token expiry must be in the future")
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT 1 FROM artifacts
            WHERE artifact_id=%s AND (case_id IS NULL OR case_id=%s)
            """,
            (artifact_id, case_id),
        )
        if await cur.fetchone() is None:
            raise ValueError("artifact does not belong to case")
        await cur.execute(
            """
            INSERT INTO canary_tokens (
                token_id,public_token_hash,case_id,artifact_id,created_at,
                expires_at,expected_usage,status,signing_version,
                classification_status
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,'ACTIVE',%s,'PENDING')
            """,
            (
                token.token_id,
                token.public_token_hash,
                token.case_id,
                token.artifact_id,
                token.created_at,
                token.expires_at,
                token.expected_usage,
                token.signing_version,
            ),
        )
    return token


@dataclass(frozen=True)
class InfrastructureSource:
    source_id: str
    cidr: str
    category: str
    valid_from: datetime
    valid_until: datetime | None
    confidence: float
    trusted_proxy: bool = False

    def contains(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return address in ipaddress.ip_network(self.cidr, strict=False)

    def valid_at(self, at: datetime) -> bool:
        return self.valid_from <= at and (self.valid_until is None or at < self.valid_until)


@dataclass(frozen=True)
class CallbackClassification:
    classification: str
    confidence: float
    network_indicator: str | None
    uncertainty: str
    analyst_review_required: bool
    rule_version: str = RULE_VERSION


def _matching_sources(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    at: datetime,
    sources: list[InfrastructureSource],
) -> list[InfrastructureSource]:
    return [source for source in sources if source.valid_at(at) and source.contains(address)]


def resolve_callback_source(
    *,
    peer_ip: str,
    forwarded_for: str | None,
    callback_time: datetime,
    sources: list[InfrastructureSource],
) -> tuple[str, bool]:
    peer = ipaddress.ip_address(peer_ip)
    peer_sources = _matching_sources(peer, callback_time, sources)
    peer_is_trusted_proxy = any(source.trusted_proxy for source in peer_sources)
    if not forwarded_for or not peer_is_trusted_proxy:
        return str(peer), False
    forwarded_tokens = [token.strip() for token in forwarded_for.split(",") if token.strip()]
    try:
        forwarded = [ipaddress.ip_address(token) for token in forwarded_tokens]
    except ValueError:
        return str(peer), True
    if not forwarded:
        return str(peer), True
    # First address is the original client under the configured trusted-proxy
    # contract. Multiple different forwarded addresses are retained as an
    # uncertainty flag and must classify UNKNOWN.
    conflict = len({str(address) for address in forwarded}) > 1
    return str(forwarded[0]), conflict


def classify_callback(
    *,
    source_ip: str,
    callback_time: datetime,
    sources: list[InfrastructureSource],
    forwarding_conflict: bool = False,
) -> CallbackClassification:
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return CallbackClassification(
            "UNKNOWN_SOURCE_CALLBACK", 0.0, None, "invalid source address", True
        )
    matches = _matching_sources(address, callback_time, sources)
    categories = {source.category for source in matches}
    if forwarding_conflict or (categories & INTERNAL_CATEGORIES and categories & SCANNER_CATEGORIES):
        return CallbackClassification(
            "UNKNOWN_SOURCE_CALLBACK",
            0.25,
            None,
            "conflicting forwarding or infrastructure-source signals",
            True,
        )
    if categories & INTERNAL_CATEGORIES:
        return CallbackClassification(
            "IN_SANDBOX_CALLBACK",
            max(source.confidence for source in matches),
            None,
            "controlled Mirage infrastructure; never an attacker location",
            False,
        )
    if categories & SCANNER_CATEGORIES:
        return CallbackClassification(
            "SECURITY_SCANNER_CALLBACK",
            max(source.confidence for source in matches),
            None,
            "configured security scanner; no attacker attribution",
            False,
        )
    if matches:
        return CallbackClassification(
            "UNKNOWN_SOURCE_CALLBACK",
            max(source.confidence for source in matches),
            None,
            "source matched an unclassified infrastructure range",
            True,
        )
    if any(source.contains(address) for source in sources):
        return CallbackClassification(
            "UNKNOWN_SOURCE_CALLBACK",
            0.25,
            None,
            "source matches only stale infrastructure records; analyst review required",
            True,
        )
    return CallbackClassification(
        "EXTERNAL_CALLBACK",
        0.75,
        str(address),
        "network indicator only; VPN, proxy, NAT, and shared-network uncertainty applies",
        False,
    )


@dataclass(frozen=True)
class SignedCallback:
    payload: dict[str, Any]
    signature: str


def sign_callback_event(payload: dict[str, Any], signing_key: bytes) -> SignedCallback:
    signature = hmac.new(signing_key, canonical_json_bytes(payload), hashlib.sha256).hexdigest()
    return SignedCallback(payload=dict(payload), signature=signature)


def verify_callback_signature(event: SignedCallback, signing_key: bytes) -> bool:
    expected = hmac.new(
        signing_key, canonical_json_bytes(event.payload), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, event.signature)


def build_callback_payload(
    *,
    token_id: str,
    source_ip: str,
    request_path: str,
    http_method: str,
    collector_request_id: str,
    classification: CallbackClassification,
    callback_time: datetime | None = None,
    user_agent: str | None = None,
    referrer: str | None = None,
    forwarded_source_metadata: dict[str, Any] | None = None,
    tls_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    callback_time = callback_time or datetime.now(UTC)
    return {
        "callback_id": generate_ulid(),
        "token_id": token_id,
        "callback_time": callback_time.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "forwarded_source_metadata": forwarded_source_metadata or {},
        "user_agent": user_agent,
        "request_path": request_path,
        "referrer": referrer,
        "http_method": http_method,
        "tls_metadata": tls_metadata or {},
        "collector_request_id": collector_request_id,
        "classification": classification.classification,
        "confidence": classification.confidence,
        "network_indicator": classification.network_indicator,
        "uncertainty": classification.uncertainty,
        "rule_version": classification.rule_version,
        "analyst_review_required": classification.analyst_review_required,
    }


def serialise_callback_evidence(event: SignedCallback) -> bytes:
    return json.dumps(
        {"payload": event.payload, "signature": event.signature},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
