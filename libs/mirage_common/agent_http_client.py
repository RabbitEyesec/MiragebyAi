"""HTTP client for Windows agents (MirageEndpoint, MirageSpider) ->
mirage-agent-ingestion. Shared because every agent role speaks the exact
same three calls (enroll/heartbeat/telemetry) — only the `role` and payload
contents differ, both already caller-supplied parameters, not hardcoded.

Enrollment (`POST /api/v1/enroll`) uses plain TLS — no client certificate
exists yet (that is the entire point of enrollment). Every call AFTER
enrollment (`heartbeat`, `submit_telemetry`) presents the issued client
certificate for mTLS, matching the topology's "Endpoint/Spider agent -> 443
mTLS -> Agent Ingestion" row. The Nginx listener that terminates that mTLS
and forwards the verified serial to the backend (mirage_agent_ingestion.auth)
is built in Step 8b — see KNOWN_ISSUES.md for the current scope boundary;
this client is written against the real target contract regardless.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx


class EnrollmentFailed(Exception):
    def __init__(self, status_code: int, body: dict) -> None:
        super().__init__(f"enrollment failed ({status_code}): {body.get('message', body)}")
        self.status_code = status_code
        self.body = body


class HeartbeatFailed(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"heartbeat failed ({status_code}): {detail}")
        self.status_code = status_code


class TelemetrySubmitFailed(Exception):
    """The server rejected the submission outright (non-202). `status_code`
    lets callers distinguish permanent rejections (4xx — the event itself
    is invalid, retrying identical bytes will never succeed) from transient
    ones (5xx, connection errors) that should be retried."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"telemetry submit failed ({status_code}): {detail}")
        self.status_code = status_code
        self.detail = detail


class TelemetryAckMismatch(Exception):
    """The server returned 202, but the acknowledgement body doesn't name
    the event we actually submitted. A bare 2xx is never sufficient proof of
    durable acceptance — see docs/architecture/event-delivery.md. Treated as
    a transient failure: never ack locally when this is raised."""

    def __init__(self, submitted_event_id: str | None, acknowledged_event_id: object) -> None:
        super().__init__(
            f"acknowledgement named event_id {acknowledged_event_id!r}, "
            f"expected {submitted_event_id!r}"
        )
        self.submitted_event_id = submitted_event_id
        self.acknowledged_event_id = acknowledged_event_id


@dataclass(frozen=True)
class EnrollmentResult:
    agent_id: str
    certificate_pem: str
    certificate_chain_pem: str
    certificate_serial: str
    not_after: str


class AgentHttpClient:
    def __init__(
        self,
        base_url: str,
        root_ca_path: str,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.root_ca_path = root_ca_path
        self.timeout = timeout
        # Test seam only (httpx.MockTransport) — production callers never
        # pass this, so real requests are entirely unaffected.
        self._transport = transport

    async def enroll(
        self, *, enrollment_token: str, role: str, csr_pem: str, host_fingerprint: str, build_hash: str
    ) -> EnrollmentResult:
        async with httpx.AsyncClient(
            verify=self.root_ca_path, timeout=self.timeout, transport=self._transport
        ) as client:
            response = await client.post(
                f"{self.base_url}/api/v1/enroll",
                json={
                    "enrollment_token": enrollment_token,
                    "role": role,
                    "csr_pem": csr_pem,
                    "host_fingerprint": host_fingerprint,
                    "build_hash": build_hash,
                },
            )
        if response.status_code != 200:
            raise EnrollmentFailed(response.status_code, response.json())
        body = response.json()
        return EnrollmentResult(
            agent_id=body["agent_id"],
            certificate_pem=body["certificate_pem"],
            certificate_chain_pem=body["certificate_chain_pem"],
            certificate_serial=body["certificate_serial"],
            not_after=body["not_after"],
        )

    async def heartbeat(
        self, *, agent_id: str, client_cert_path: str, client_key_path: str, payload: dict
    ) -> dict:
        async with httpx.AsyncClient(
            verify=self.root_ca_path,
            cert=(client_cert_path, client_key_path),
            timeout=self.timeout,
            transport=self._transport,
        ) as client:
            response = await client.post(f"{self.base_url}/api/v1/agents/{agent_id}/heartbeat", json=payload)
        if response.status_code != 200:
            raise HeartbeatFailed(response.status_code, response.text)
        return response.json()

    async def submit_telemetry(
        self, *, agent_id: str, client_cert_path: str, client_key_path: str, event: dict
    ) -> dict:
        """Submit one already-built event envelope (Step 5). Raises
        TelemetrySubmitFailed on any non-2xx response, including 409
        (sequence out of order or already claimed by a different event) —
        callers decide whether that's retryable based on `status_code`.

        Raises TelemetryAckMismatch if the server responds 202 but the
        acknowledgement body doesn't name the exact event_id submitted — a
        bare 2xx status is never treated as sufficient proof of durable
        acceptance on its own (Priority 2: "Agent verifies acknowledgement
        identity and contents"). Only returns normally once both the status
        code AND the acknowledged identity have been verified — the return
        value is safe for a caller to treat as "the server durably accepted
        exactly this event" and ack its local queue row accordingly.
        """
        async with httpx.AsyncClient(
            verify=self.root_ca_path,
            cert=(client_cert_path, client_key_path),
            timeout=self.timeout,
            transport=self._transport,
        ) as client:
            response = await client.post(f"{self.base_url}/api/v1/agents/{agent_id}/telemetry", json=event)
        if response.status_code != 202:
            raise TelemetrySubmitFailed(response.status_code, response.text)
        body = response.json()
        acknowledged_event_id = body.get("event_id")
        if acknowledged_event_id != event.get("event_id"):
            raise TelemetryAckMismatch(event.get("event_id"), acknowledged_event_id)
        return body
