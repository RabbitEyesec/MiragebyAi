"""Unit tests for AgentHttpClient.submit_telemetry's acknowledgement
verification (Priority 2: "Agent verifies acknowledgement identity and
contents") using httpx.MockTransport — no real network, no Docker. Real
end-to-end delivery against a live mirage-agent-ingestion is covered by
tests/integration/test_mirage_spider_e2e.py and
tests/integration/test_agent_delivery_idempotency.py.
"""
from __future__ import annotations

import httpx
import pytest

from mirage_common.agent_http_client import (
    AgentHttpClient,
    TelemetryAckMismatch,
    TelemetrySubmitFailed,
)

pytestmark = pytest.mark.unit

_EVENT = {"event_id": "evt-real-001", "event_type": "spider.observation", "sequence": 1}


def _client(handler) -> AgentHttpClient:
    return AgentHttpClient(
        "https://agent-ingestion.mirage.local",
        root_ca_path="/dev/null",
        transport=httpx.MockTransport(handler),
    )


async def test_matching_acknowledgement_is_accepted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "accepted", "event_id": "evt-real-001", "sequence": 1})

    result = await _client(handler).submit_telemetry(
        agent_id="agent-1", client_cert_path="/dev/null", client_key_path="/dev/null", event=_EVENT
    )
    assert result["event_id"] == "evt-real-001"


async def test_acknowledgement_naming_a_different_event_id_is_rejected() -> None:
    """The exact scenario Priority 2 warns about: a 2xx status alone is not
    proof of durable acceptance of THIS event — the body must actually name
    it. A stale, cached, or misrouted response naming some other event_id
    must never be treated as this event having been accepted."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "accepted", "event_id": "evt-some-other-event", "sequence": 1})

    with pytest.raises(TelemetryAckMismatch) as exc_info:
        await _client(handler).submit_telemetry(
            agent_id="agent-1", client_cert_path="/dev/null", client_key_path="/dev/null", event=_EVENT
        )
    assert exc_info.value.submitted_event_id == "evt-real-001"
    assert exc_info.value.acknowledged_event_id == "evt-some-other-event"


async def test_acknowledgement_missing_event_id_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"status": "accepted"})

    with pytest.raises(TelemetryAckMismatch):
        await _client(handler).submit_telemetry(
            agent_id="agent-1", client_cert_path="/dev/null", client_key_path="/dev/null", event=_EVENT
        )


async def test_non_202_status_raises_telemetry_submit_failed_with_status_code() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, text="sequence 1 is not greater than last recorded sequence 5")

    with pytest.raises(TelemetrySubmitFailed) as exc_info:
        await _client(handler).submit_telemetry(
            agent_id="agent-1", client_cert_path="/dev/null", client_key_path="/dev/null", event=_EVENT
        )
    assert exc_info.value.status_code == 409


async def test_replayed_acknowledgement_with_matching_event_id_is_accepted() -> None:
    """Server-side idempotent replay (migration 0011) returns replay=True
    but the SAME event_id — the client must treat this exactly like a fresh
    acceptance and ack its local queue row."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202, json={"status": "accepted", "event_id": "evt-real-001", "sequence": 1, "replay": True}
        )

    result = await _client(handler).submit_telemetry(
        agent_id="agent-1", client_cert_path="/dev/null", client_key_path="/dev/null", event=_EVENT
    )
    assert result["replay"] is True
    assert result["event_id"] == "evt-real-001"
