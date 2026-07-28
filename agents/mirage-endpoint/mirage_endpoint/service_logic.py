"""MirageEndpoint's OS-independent business logic — everything the Windows
service shim (win_service.py) delegates to. No pywin32 import anywhere in
this module, so it unit/integration-tests on any OS (ADR-0002).
"""
from __future__ import annotations

import json
import platform
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mirage_common.agent_http_client import AgentHttpClient
from mirage_common.agent_queue import EncryptedEventQueue

AGENT_VERSION = "0.1.0"
AGENT_ROLE = "ENDPOINT"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    certificate_pem: str
    certificate_serial: str
    certificate_key_path: Path
    certificate_path: Path
    not_after: str


class EndpointServiceLogic:
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
        """A stable, low-entropy machine identifier for enrollment's
        host-fingerprint field. Real deployments derive this from Windows
        machine GUID (HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid);
        hostname is used here as the portable dev/test equivalent — both are
        simply "a string identifying this specific host," not a security
        boundary by themselves (the certificate + token are)."""
        return f"{platform.node()}:{socket.gethostname()}"

    async def enroll(self, *, enrollment_token: str, subject: str | None = None) -> AgentIdentity:
        """`subject` MUST match the subject/SANs the enrollment token was
        minted for (step-ca rejects a CSR whose CN doesn't match — verified
        empirically, see TEST_RESULTS.md §Step4). Defaults to a
        hostname-derived value for a real deployed agent; callers that
        pre-provisioned a token for a specific hostname (the normal
        control-plane-initiated flow — spec Step 3 item 1: "control plane
        creates one-time token") pass that exact value instead."""
        subject = subject or f"endpoint-{socket.gethostname()}.mirage.local"
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
        cert_path = self.cert_dir / "endpoint.crt"
        key_path = self.cert_dir / "endpoint.key"
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

    def enqueue_event(self, event: dict, *, enqueued_at: str) -> int:
        return self.queue.enqueue(event, enqueued_at=enqueued_at)

    def flush_queue(self, send_fn, *, batch_size: int = 100) -> int:
        """Drains the local queue via `send_fn(event) -> bool`, acking only
        what actually succeeded — the exact "outage replay" contract
        exercised in tests/unit/test_endpoint_queue.py, wired to a real
        transport here.

        `send_fn` must return True ONLY after verifying a durable,
        identity-matched server acknowledgement (not merely a 2xx status) —
        see AgentHttpClient.submit_telemetry and the caller wiring in
        mirage-spider's SpiderServiceLogic.flush_queue for the real contract
        this is built against.

        Each row is acked individually, immediately after send_fn returns
        True — not batched until the end of the loop — so a crash between
        one event's successful send and the next minimizes what remains
        unacknowledged to at most the single in-flight event, which the
        server's idempotent replay path (migration 0011) makes safe to
        resend on the next attempt.
        """
        total_sent = 0
        while True:
            batch = self.queue.peek_batch(limit=batch_size)
            if not batch:
                break
            progressed = False
            for row_id, event in batch:
                if not send_fn(event):
                    break  # stop at first failure — preserve order, retry from here next time
                self.queue.ack([row_id])
                total_sent += 1
                progressed = True
            if not progressed:
                break
        return total_sent
