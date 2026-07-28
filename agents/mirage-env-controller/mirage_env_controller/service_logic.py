"""MirageEnvironmentController's OS-independent business logic — the
Windows service shim (win_service.py) delegates everything here, same
ADR-0002 pattern as mirage_spider/mirage_endpoint. Enrolment reuses the
IDENTICAL mechanism Spider/Endpoint already prove (step-ca, role=
ENV_CONTROLLER — provisioned since Step 3, see infra/step-ca/PROFILES.md)
over plain mTLS HTTPS; the live command channel is a SEPARATE outbound WSS
connection to mirage-sandbox-gateway (Appendix G: "Channel: Outbound WSS ->
Sandbox Gateway" — distinct from Spider's HTTPS telemetry channel because
commands need real-time server push, not periodic batch drain).
"""
from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

import websockets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mirage_common.agent_http_client import AgentHttpClient
from mirage_contracts.timestamps import now_rfc3339_ms
from mirage_env_controller.actions import ExecutorContext, execute_action

AGENT_VERSION = "0.1.0"
AGENT_ROLE = "ENV_CONTROLLER"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    certificate_pem: str
    certificate_serial: str
    certificate_key_path: Path
    certificate_path: Path
    not_after: str


class EnvControllerServiceLogic:
    def __init__(self, *, client: AgentHttpClient, identity_state_path: Path, cert_dir: Path, build_hash: str, ctx: ExecutorContext) -> None:
        self.client = client
        self.identity_state_path = identity_state_path
        self.cert_dir = cert_dir
        self.build_hash = build_hash
        self.ctx = ctx

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
        return f"{socket.getfqdn()}:{socket.gethostname()}"

    async def enroll(self, *, enrollment_token: str, subject: str | None = None) -> AgentIdentity:
        subject = subject or f"envctl-{socket.gethostname()}.mirage.local"
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(subject)]), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        result = await self.client.enroll(
            enrollment_token=enrollment_token, role=AGENT_ROLE, csr_pem=csr_pem,
            host_fingerprint=self.host_fingerprint(), build_hash=self.build_hash,
        )

        self.cert_dir.mkdir(parents=True, exist_ok=True)
        cert_path = self.cert_dir / "envctl.crt"
        key_path = self.cert_dir / "envctl.key"
        cert_path.write_text(result.certificate_pem)
        key_path.write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        )

        identity = AgentIdentity(
            agent_id=result.agent_id, certificate_pem=result.certificate_pem,
            certificate_serial=result.certificate_serial, certificate_key_path=key_path,
            certificate_path=cert_path, not_after=result.not_after,
        )
        self.identity_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.identity_state_path.write_text(json.dumps({
            "agent_id": identity.agent_id, "certificate_serial": identity.certificate_serial,
            "certificate_key_path": str(identity.certificate_key_path), "certificate_path": str(identity.certificate_path),
            "not_after": identity.not_after,
        }))
        return identity

    def execute_command_frame(self, frame: dict) -> dict:
        """Executes one command frame received over the WSS channel and
        returns the result frame to send back. Split out from
        connect_and_serve() so it is directly unit-testable without a real
        WebSocket connection."""
        outcome = execute_action(
            frame["action_type"], frame.get("action_params") or {},
            ctx=self.ctx, action_id=frame["action_id"], recorded_at=now_rfc3339_ms(),
        )
        return {
            "action_id": frame["action_id"], "command_id": frame["command_id"],
            "status": outcome.status, "output_tag": outcome.output_tag, "error_detail": outcome.error_detail,
        }

    async def connect_and_serve(self, ws_url: str, *, additional_headers: dict, max_commands: int | None = None) -> int:
        """Connects to mirage-sandbox-gateway and processes command frames
        until the connection closes (or `max_commands` frames have been
        handled — test-only bound so integration tests don't need to race
        a real service's normal run-forever loop). Returns the number of
        commands processed."""
        processed = 0
        async with websockets.connect(ws_url, additional_headers=additional_headers) as ws:
            async for raw in ws:
                frame = json.loads(raw)
                result = self.execute_command_frame(frame)
                await ws.send(json.dumps(result))
                processed += 1
                if max_commands is not None and processed >= max_commands:
                    break
        return processed
