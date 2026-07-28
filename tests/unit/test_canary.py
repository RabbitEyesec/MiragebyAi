from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mirage_common.canary import (
    InfrastructureSource,
    classify_callback,
    create_canary_token,
    resolve_callback_source,
)
from mirage_contracts.ulid import generate_ulid

NOW = datetime(2026, 7, 26, tzinfo=UTC)


def _source(cidr: str, category: str, **kwargs) -> InfrastructureSource:
    return InfrastructureSource(
        generate_ulid(),
        cidr,
        category,
        kwargs.get("valid_from", NOW - timedelta(days=1)),
        kwargs.get("valid_until", NOW + timedelta(days=1)),
        0.95,
        kwargs.get("trusted_proxy", False),
    )


@pytest.mark.parametrize(
    ("address", "category", "expected"),
    [
        ("10.0.1.2", "SANDBOX_ENI", "IN_SANDBOX_CALLBACK"),
        ("10.0.2.2", "NGINX_BROKER", "IN_SANDBOX_CALLBACK"),
        ("10.0.3.2", "NAT", "IN_SANDBOX_CALLBACK"),
        ("10.0.4.2", "SECURITY_SCANNER", "SECURITY_SCANNER_CALLBACK"),
    ],
)
def test_controlled_sources_never_display_as_attacker(
    address: str, category: str, expected: str
) -> None:
    result = classify_callback(
        source_ip=address, callback_time=NOW, sources=[_source(f"{address}/32", category)]
    )
    assert result.classification == expected
    assert result.network_indicator is None


def test_external_ipv4_and_ipv6_get_network_indicator_only() -> None:
    for address in ("203.0.113.9", "2001:db8::9"):
        result = classify_callback(source_ip=address, callback_time=NOW, sources=[])
        assert result.classification == "EXTERNAL_CALLBACK"
        assert result.network_indicator == address
        assert "VPN" in result.uncertainty


def test_stale_source_not_used_and_forwarded_header_trusted_only_from_proxy() -> None:
    stale = _source(
        "10.1.0.0/16",
        "SANDBOX_ENI",
        valid_from=NOW - timedelta(days=2),
        valid_until=NOW - timedelta(days=1),
    )
    assert (
        classify_callback(source_ip="10.1.2.3", callback_time=NOW, sources=[stale]).classification
        == "UNKNOWN_SOURCE_CALLBACK"
    )
    proxy = _source("192.0.2.1/32", "MIRAGE_PROXY", trusted_proxy=True)
    resolved, conflict = resolve_callback_source(
        peer_ip="192.0.2.1",
        forwarded_for="203.0.113.4, 203.0.113.5",
        callback_time=NOW,
        sources=[proxy],
    )
    assert resolved == "203.0.113.4"
    assert conflict


def test_token_is_opaque_and_contains_no_case_metadata() -> None:
    case_id = generate_ulid()
    token = create_canary_token(
        case_id=case_id,
        artifact_id=generate_ulid(),
        expires_at=NOW + timedelta(days=1),
        expected_usage="ONE_TIME",
    )
    assert case_id not in token.public_token
    assert len(token.public_token_hash) == 64
