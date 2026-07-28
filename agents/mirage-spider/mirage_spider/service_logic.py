"""MirageSpider's OS-independent business logic — everything the Windows
service shim (win_service.py) delegates to. No pywin32 import anywhere in
this module, so it unit/integration-tests on any OS (ADR-0002 pattern,
reused from mirage_endpoint).

Appendix G: "Purpose: Observe (read-only)... Never: writes to sandbox, runs
as LocalSystem... Local state: Encrypted queue, sequence store... Tamper +
health high-priority." This module has no code path that writes to the
sandbox filesystem/registry/services it observes — only reads (process
list, filesystem metadata, registry values) feed record_observation(); the
high-priority handling for tamper events is record_tamper()'s
send-immediately-else-durable-queue design, distinct from the routine
batched path record_observation()/flush_queue() use.
"""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mirage_common.agent_http_client import (
    AgentHttpClient,
    TelemetryAckMismatch,
    TelemetrySubmitFailed,
)
from mirage_common.agent_queue import EncryptedEventQueue
from mirage_contracts.envelope import build_event
from mirage_contracts.timestamps import now_rfc3339_ms

AGENT_VERSION = "0.1.0"
AGENT_ROLE = "SPIDER"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    certificate_pem: str
    certificate_serial: str
    certificate_key_path: Path
    certificate_path: Path
    not_after: str


class SpiderServiceLogic:
    def __init__(
        self,
        *,
        client: AgentHttpClient,
        queue: EncryptedEventQueue,
        identity_state_path: Path,
        cert_dir: Path,
        build_hash: str,
    ) -> None:
        self.client = client
        self.queue = queue
        self.identity_state_path = identity_state_path
        self.cert_dir = cert_dir
        self.build_hash = build_hash

    def is_enrolled(self) -> bool:
        return self.identity_state_path.exists()

    def load_identity(self) -> AgentIdentity:
        state = json.loads(self.identity_state_path.read_text())
        return AgentIdentity(
            agent_id=state["agent_id"],
            certificate_pem=Path(state["certificate_path"]).read_text(),
            certificate_serial=state["certificate_serial"],
            certificate_key_path=Path(state["certificate_key_path"]),
            certificate_path=Path(state["certificate_path"]),
            not_after=state["not_after"],
        )

    @staticmethod
    def host_fingerprint() -> str:
        """See mirage_endpoint.service_logic.host_fingerprint's docstring —
        identical reasoning, same portable dev/test stand-in for the real
        Windows machine GUID."""
        return f"{socket.getfqdn()}:{socket.gethostname()}"

    async def enroll(self, *, enrollment_token: str, subject: str | None = None) -> AgentIdentity:
        subject = subject or f"spider-{socket.gethostname()}.mirage.local"
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(subject)]), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        result = await self.client.enroll(
            enrollment_token=enrollment_token,
            role=AGENT_ROLE,
            csr_pem=csr_pem,
            host_fingerprint=self.host_fingerprint(),
            build_hash=self.build_hash,
        )

        self.cert_dir.mkdir(parents=True, exist_ok=True)
        cert_path = self.cert_dir / "spider.crt"
        key_path = self.cert_dir / "spider.key"
        cert_path.write_text(result.certificate_pem)
        key_path.write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        )

        identity = AgentIdentity(
            agent_id=result.agent_id,
            certificate_pem=result.certificate_pem,
            certificate_serial=result.certificate_serial,
            certificate_key_path=key_path,
            certificate_path=cert_path,
            not_after=result.not_after,
        )
        self.identity_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.identity_state_path.write_text(json.dumps({
            "agent_id": identity.agent_id,
            "certificate_serial": identity.certificate_serial,
            "certificate_key_path": str(identity.certificate_key_path),
            "certificate_path": str(identity.certificate_path),
            "not_after": identity.not_after,
        }))
        return identity

    def build_heartbeat_payload(self, identity: AgentIdentity, *, uptime_seconds: int, health_state: str = "HEALTHY") -> dict:
        return {
            "agent_id": identity.agent_id,
            "role": AGENT_ROLE,
            "build_hash": self.build_hash,
            "version": AGENT_VERSION,
            "certificate_serial": identity.certificate_serial,
            "uptime_seconds": uptime_seconds,
            "health_state": health_state,
            "queue_depth": self.queue.pending_count(),
        }

    async def send_heartbeat(self, identity: AgentIdentity, *, uptime_seconds: int) -> dict:
        payload = self.build_heartbeat_payload(identity, uptime_seconds=uptime_seconds)
        return await self.client.heartbeat(
            agent_id=identity.agent_id,
            client_cert_path=str(identity.certificate_path),
            client_key_path=str(identity.certificate_key_path),
            payload=payload,
        )

    # --- Telemetry -----------------------------------------------------

    def record_observation(
        self,
        identity: AgentIdentity,
        *,
        observation_type: str,
        subject: str,
        detail: dict | None = None,
        case_id: str | None = None,
        session_id: str | None = None,
        process_guid: str | None = None,
        correlation_id: str | None = None,
    ) -> int:
        """Low-noise, routine telemetry — queued locally and drained by
        flush_queue() on the normal cadence (Appendix G: 'low-noise, not
        invisible'). Returns the local sequence number assigned.

        Every observation automatically carries `host_id` (this sandbox's
        stable host fingerprint — the same join key Elastic Agent's own
        `host.id` uses) so it can be correlated against Elastic Agent's
        independently-collected Sysmon/Windows Event Log data for the same
        host, per docs/architecture/windows-telemetry.md — Spider does not
        re-collect what Elastic Agent already owns, it links to it.
        `process_guid`/`correlation_id` are supplied by the caller when
        this specific observation concerns a known process or a specific
        cross-source action (e.g. a controller action's action_id)."""
        sequence = self.queue.next_sequence()
        merged_detail: dict[str, object] = dict(detail) if detail else {}
        merged_detail.setdefault("host_id", self.host_fingerprint())
        if process_guid is not None:
            merged_detail["process_guid"] = process_guid
        if correlation_id is not None:
            merged_detail["correlation_id"] = correlation_id
        payload: dict[str, object] = {
            "observation_type": observation_type,
            "subject": subject,
            "observed_at": now_rfc3339_ms(),
            "detail": merged_detail,
        }
        event = build_event(
            event_type="spider.observation", schema_version="1.0", payload=payload,
            source_id=identity.agent_id, sequence=sequence, actor_type="SPIDER_AGENT",
            classification="EVIDENCE", case_id=case_id, session_id=session_id,
        )
        self.queue.enqueue(event, enqueued_at=now_rfc3339_ms())
        return sequence

    async def record_tamper(self, identity: AgentIdentity, *, tamper_type: str, detail: str) -> bool:
        """High-priority path (Appendix G: 'Tamper + health high-priority').
        Attempts delivery immediately rather than waiting for the next
        flush_queue() cycle; on any failure it durably falls back to the
        same encrypted local queue routine telemetry uses, so a tamper
        event is never silently lost even mid-outage — it just arrives
        late instead of immediately. Returns True if delivered immediately,
        False if it fell back to the queue."""
        sequence = self.queue.next_sequence()
        event = build_event(
            event_type="spider.tamper", schema_version="1.0",
            payload={"tamper_type": tamper_type, "detail": detail, "observed_at": now_rfc3339_ms()},
            source_id=identity.agent_id, sequence=sequence, actor_type="SPIDER_AGENT", classification="EVIDENCE",
        )
        try:
            await self.client.submit_telemetry(
                agent_id=identity.agent_id,
                client_cert_path=str(identity.certificate_path),
                client_key_path=str(identity.certificate_key_path),
                event=event,
            )
            return True
        except Exception:  # noqa: BLE001 -- any failure (network, 5xx, ...) falls back to the durable queue
            self.queue.enqueue(event, enqueued_at=now_rfc3339_ms())
            return False

    async def submit_fingerprint_snapshot(self, identity: AgentIdentity, *, sandbox_id: str, checks: dict) -> bool:
        """Step 10's live gate reads the latest one of these per sandbox_id
        before allowing SANDBOX_ACTIVE -> ENGAGING — freshness matters the
        same way it does for record_tamper, so this uses the identical
        immediate-send-else-durable-fallback pattern rather than the
        routine batched queue path. `checks` is {check_name: {...}} in the
        exact shape libs/mirage_common/fingerprint.py::run_fingerprint_check
        expects — collecting the underlying OS observations is a real
        Windows host's job (mirroring Step 9a's PowerShell harness), not
        this cross-platform module's; the caller supplies `checks` already
        built."""
        sequence = self.queue.next_sequence()
        event = build_event(
            event_type="spider.fingerprint_snapshot", schema_version="1.0",
            payload={"sandbox_id": sandbox_id, "checks": checks, "observed_at": now_rfc3339_ms()},
            source_id=identity.agent_id, sequence=sequence, actor_type="SPIDER_AGENT", classification="EVIDENCE",
        )
        try:
            await self.client.submit_telemetry(
                agent_id=identity.agent_id,
                client_cert_path=str(identity.certificate_path),
                client_key_path=str(identity.certificate_key_path),
                event=event,
            )
            return True
        except Exception:  # noqa: BLE001 -- any failure (network, 5xx, ...) falls back to the durable queue
            self.queue.enqueue(event, enqueued_at=now_rfc3339_ms())
            return False

    # 4xx status codes where the event itself is structurally invalid and
    # will never succeed no matter how many times identical bytes are
    # resent — safe to dead-letter immediately rather than retry forever.
    # 403/409 are deliberately excluded: 403 can mean "agent revoked" (a
    # property of the agent, not this event — retrying later after the
    # agent is re-enrolled could succeed) and 409 can mean an ordering
    # conflict that resolves itself once earlier events are delivered.
    _PERMANENT_REJECTION_STATUS_CODES = frozenset({400})

    async def flush_queue(self, identity: AgentIdentity, *, batch_size: int = 100) -> int:
        """Drains the local queue via real HTTP submission, order-preserving
        and partial-failure-safe — the async analogue of
        mirage_endpoint.service_logic.EndpointServiceLogic.flush_queue,
        wired to a real transport (Step 5 closes the gap Step 4 documented
        as deferred to 'Step 5's shared pattern').

        Each event is acked individually immediately after its own send is
        confirmed (both a 202 status AND a matching acknowledged event_id —
        see AgentHttpClient.submit_telemetry), not batched until the whole
        peek_batch() page finishes. This matters for crash safety: if the
        process dies between one event's confirmed send and the next, at
        most that single row is left PENDING despite the server having
        already durably accepted it — and the server's idempotent replay
        path (migration 0011) makes resending it on the next attempt safe,
        rather than the previous behavior of a permanent 409 deadlock.
        """
        total_sent = 0
        while True:
            batch = self.queue.peek_batch(limit=batch_size)
            if not batch:
                break
            progressed = False
            for row_id, event in batch:
                try:
                    await self.client.submit_telemetry(
                        agent_id=identity.agent_id,
                        client_cert_path=str(identity.certificate_path),
                        client_key_path=str(identity.certificate_key_path),
                        event=event,
                    )
                except TelemetrySubmitFailed as exc:
                    if exc.status_code in self._PERMANENT_REJECTION_STATUS_CODES:
                        self.queue.dead_letter([row_id], error=str(exc))
                        progressed = True
                        continue  # this event can never succeed; move on to the next
                    self.queue.record_attempt_failure(row_id, error=str(exc))
                    break  # transient — stop, preserve order, retry from here next time
                except TelemetryAckMismatch as exc:
                    self.queue.record_attempt_failure(row_id, error=str(exc))
                    break  # never ack on an unverified/mismatched acknowledgement
                else:
                    self.queue.ack([row_id])
                    total_sent += 1
                    progressed = True
            if not progressed:
                break
        return total_sent
