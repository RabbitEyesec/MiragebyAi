"""Unit tests for MirageSpider's business logic (Step 5) — no Docker, no
network: a fake async transport stands in for AgentHttpClient so the
tamper-priority and ordered-flush behaviors are tested deterministically.
Real end-to-end delivery (real Postgres/NATS/step-ca) is covered by
tests/integration/test_mirage_spider_e2e.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from mirage_spider.service_logic import AgentIdentity, SpiderServiceLogic

from mirage_common.agent_http_client import TelemetryAckMismatch, TelemetrySubmitFailed
from mirage_common.agent_keys import LocalFileKeyProvider
from mirage_common.agent_queue import EncryptedEventQueue

pytestmark = pytest.mark.unit


class _FakeClient:
    """Duck-typed stand-in for AgentHttpClient.submit_telemetry — records
    every call and can be scripted to fail on demand."""

    def __init__(
        self,
        *,
        fail_next: int = 0,
        fail_always: bool = False,
        permanent_reject_event_ids: frozenset[str] = frozenset(),
        mismatch_ack_event_ids: frozenset[str] = frozenset(),
        pending_count_at_call: list[int] | None = None,
        queue: EncryptedEventQueue | None = None,
    ) -> None:
        self.sent: list[dict] = []
        self.fail_next = fail_next
        self.fail_always = fail_always
        self.permanent_reject_event_ids = permanent_reject_event_ids
        self.mismatch_ack_event_ids = mismatch_ack_event_ids
        # If given, records queue.pending_count() observed at the START of
        # each call — lets a test prove acks happen incrementally rather
        # than only after the whole batch finishes.
        self._pending_count_at_call = pending_count_at_call
        self._queue = queue

    async def submit_telemetry(self, *, agent_id: str, client_cert_path: str, client_key_path: str, event: dict) -> dict:
        if self._pending_count_at_call is not None and self._queue is not None:
            self._pending_count_at_call.append(self._queue.pending_count())
        if event["event_id"] in self.permanent_reject_event_ids:
            raise TelemetrySubmitFailed(400, f"event_type {event['event_type']!r} is not submittable via this endpoint")
        if event["event_id"] in self.mismatch_ack_event_ids:
            raise TelemetryAckMismatch(event["event_id"], "some-other-event-id")
        if self.fail_always or self.fail_next > 0:
            if self.fail_next > 0:
                self.fail_next -= 1
            raise TelemetrySubmitFailed(502, "simulated failure")
        self.sent.append(event)
        return {"status": "accepted", "event_id": event["event_id"], "sequence": event["sequence"]}


def _identity(tmp_path: Path) -> AgentIdentity:
    cert = tmp_path / "spider.crt"
    key = tmp_path / "spider.key"
    cert.write_text("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
    key.write_bytes(b"stub-key")
    return AgentIdentity(
        agent_id="spider-test.mirage.local", certificate_pem=cert.read_text(),
        certificate_serial="1", certificate_key_path=key, certificate_path=cert,
        not_after="2026-08-01T00:00:00.000Z",
    )


def _logic(tmp_path: Path, client) -> SpiderServiceLogic:
    queue = EncryptedEventQueue(tmp_path / "queue.db", LocalFileKeyProvider(tmp_path / "queue.key"))
    return SpiderServiceLogic(
        client=client, queue=queue, identity_state_path=tmp_path / "identity.json",
        cert_dir=tmp_path / "certs", build_hash="a" * 64,
    )


def test_record_observation_auto_populates_host_id_for_elastic_agent_correlation(tmp_path: Path):
    logic = _logic(tmp_path, _FakeClient())
    identity = _identity(tmp_path)

    logic.record_observation(identity, observation_type="PROCESS_START", subject="cmd.exe")

    _row_id, event = logic.queue.peek_batch()[0]
    assert event["payload"]["detail"]["host_id"] == logic.host_fingerprint()


def test_record_observation_threads_process_guid_and_correlation_id(tmp_path: Path):
    logic = _logic(tmp_path, _FakeClient())
    identity = _identity(tmp_path)

    logic.record_observation(
        identity, observation_type="PROCESS_START", subject="cmd.exe",
        process_guid="{4F1A2B3C-0001-0000-0000-000000001234}", correlation_id="ACTION0000000000000000099",
    )

    _row_id, event = logic.queue.peek_batch()[0]
    detail = event["payload"]["detail"]
    assert detail["process_guid"] == "{4F1A2B3C-0001-0000-0000-000000001234}"
    assert detail["correlation_id"] == "ACTION0000000000000000099"
    assert detail["host_id"] == logic.host_fingerprint()  # still auto-populated alongside caller-supplied fields


def test_record_observation_assigns_increasing_case_tagged_sequence(tmp_path: Path):
    logic = _logic(tmp_path, _FakeClient())
    identity = _identity(tmp_path)

    seq1 = logic.record_observation(identity, observation_type="PROCESS_START", subject="cmd.exe", case_id="01ARZ3NDEKTSV4RRFFQ69G5FAV")
    seq2 = logic.record_observation(identity, observation_type="FILE_CREATE", subject="C:\\decoy\\notes.txt")

    assert (seq1, seq2) == (1, 2)
    batch = logic.queue.peek_batch()
    assert len(batch) == 2
    _row_id, first_event = batch[0]
    assert first_event["event_type"] == "spider.observation"
    assert first_event["actor_type"] == "SPIDER_AGENT"
    assert first_event["case_id"] == "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    assert first_event["sequence"] == 1
    assert first_event["payload"]["subject"] == "cmd.exe"


async def test_tamper_event_sends_immediately_and_never_touches_queue_on_success(tmp_path: Path):
    client = _FakeClient()
    logic = _logic(tmp_path, client)
    identity = _identity(tmp_path)

    delivered = await logic.record_tamper(identity, tamper_type="SERVICE_STOP_ATTEMPT", detail="sc.exe stop MirageSpider")

    assert delivered is True
    assert len(client.sent) == 1
    assert client.sent[0]["event_type"] == "spider.tamper"
    assert logic.queue.pending_count() == 0  # high-priority path bypassed the routine queue entirely


async def test_tamper_event_falls_back_to_durable_queue_on_send_failure(tmp_path: Path):
    client = _FakeClient(fail_always=True)
    logic = _logic(tmp_path, client)
    identity = _identity(tmp_path)

    delivered = await logic.record_tamper(identity, tamper_type="LOG_CLEARED", detail="Security event log cleared")

    assert delivered is False
    assert client.sent == []
    assert logic.queue.pending_count() == 1
    _row_id, queued_event = logic.queue.peek_batch()[0]
    assert queued_event["event_type"] == "spider.tamper"  # nothing lost, just delayed


async def test_flush_queue_drains_in_order_and_stops_at_first_failure(tmp_path: Path):
    client = _FakeClient(fail_next=1)  # 1st send fails (simulated outage tail), rest succeed
    logic = _logic(tmp_path, client)
    identity = _identity(tmp_path)

    for i in range(3):
        logic.record_observation(identity, observation_type="PROCESS_START", subject=f"proc-{i}.exe")
    assert logic.queue.pending_count() == 3

    sent_count = await logic.flush_queue(identity)

    assert sent_count == 0  # first attempt failed -> stops immediately, order preserved
    assert logic.queue.pending_count() == 3  # nothing acked, safe to retry

    sent_count_2 = await logic.flush_queue(identity)
    assert sent_count_2 == 3
    assert logic.queue.pending_count() == 0
    assert [e["payload"]["subject"] for e in client.sent] == ["proc-0.exe", "proc-1.exe", "proc-2.exe"]


async def test_fingerprint_snapshot_sends_immediately_and_never_touches_queue_on_success(tmp_path: Path):
    """Step 10's live gate reads the latest snapshot per sandbox_id — same
    freshness requirement as a tamper event, so this uses the identical
    immediate-send priority path."""
    client = _FakeClient()
    logic = _logic(tmp_path, client)
    identity = _identity(tmp_path)

    checks = {"hostname_domain": {"hostname": "WKS-042", "domain": "MIRAGE"}}
    delivered = await logic.submit_fingerprint_snapshot(identity, sandbox_id="sandbox-001", checks=checks)

    assert delivered is True
    assert len(client.sent) == 1
    sent = client.sent[0]
    assert sent["event_type"] == "spider.fingerprint_snapshot"
    assert sent["payload"]["sandbox_id"] == "sandbox-001"
    assert sent["payload"]["checks"] == checks
    assert logic.queue.pending_count() == 0


async def test_fingerprint_snapshot_falls_back_to_durable_queue_on_send_failure(tmp_path: Path):
    client = _FakeClient(fail_always=True)
    logic = _logic(tmp_path, client)
    identity = _identity(tmp_path)

    delivered = await logic.submit_fingerprint_snapshot(identity, sandbox_id="sandbox-001", checks={})

    assert delivered is False
    assert client.sent == []
    assert logic.queue.pending_count() == 1
    _row_id, queued_event = logic.queue.peek_batch()[0]
    assert queued_event["event_type"] == "spider.fingerprint_snapshot"


async def test_flush_queue_acks_each_event_immediately_not_only_after_the_whole_batch(tmp_path: Path):
    """Priority 2's crash-safety property: acking per-event (not batched at
    the end of the loop) shrinks the "server accepted it but we crashed
    before recording our own ack" window to at most one event, instead of up
    to a whole batch_size page."""
    pending_observed: list[int] = []
    logic = _logic(tmp_path, None)  # placeholder, replaced below once queue exists
    client = _FakeClient(pending_count_at_call=pending_observed, queue=logic.queue)
    logic.client = client
    identity = _identity(tmp_path)

    for i in range(3):
        logic.record_observation(identity, observation_type="PROCESS_START", subject=f"proc-{i}.exe")

    sent_count = await logic.flush_queue(identity)

    assert sent_count == 3
    # Each successive call observed pending_count() one lower than the last —
    # proof that the previous event was already acked before this call
    # started, not left pending until the whole batch finished.
    assert pending_observed == [3, 2, 1]
    assert logic.queue.pending_count() == 0


async def test_flush_queue_dead_letters_permanently_invalid_event_and_continues_past_it(tmp_path: Path):
    client = _FakeClient()
    logic = _logic(tmp_path, client)
    identity = _identity(tmp_path)

    identity_events = [
        logic.record_observation(identity, observation_type="PROCESS_START", subject=f"proc-{i}.exe")
        for i in range(3)
    ]
    assert len(identity_events) == 3
    _bad_row_id, bad_event = logic.queue.peek_batch()[1]
    client.permanent_reject_event_ids = frozenset({bad_event["event_id"]})

    sent_count = await logic.flush_queue(identity)

    assert sent_count == 2  # the 2 good events, not the permanently-rejected one
    assert logic.queue.pending_count() == 0
    assert logic.queue.dead_letter_count() == 1
    assert [e["payload"]["subject"] for e in client.sent] == ["proc-0.exe", "proc-2.exe"]


async def test_flush_queue_never_acks_on_acknowledgement_identity_mismatch(tmp_path: Path):
    """A 202 whose body names a different event_id must never be treated as
    this event having been durably accepted — the row stays PENDING for
    retry, and nothing after it in order is sent this cycle."""
    logic = _logic(tmp_path, None)
    identity = _identity(tmp_path)
    logic.record_observation(identity, observation_type="PROCESS_START", subject="proc-0.exe")
    _row_id, mismatched_event = logic.queue.peek_batch()[0]
    logic.record_observation(identity, observation_type="PROCESS_START", subject="proc-1.exe")
    client = _FakeClient(mismatch_ack_event_ids=frozenset({mismatched_event["event_id"]}))
    logic.client = client

    sent_count = await logic.flush_queue(identity)

    assert sent_count == 0
    assert logic.queue.pending_count() == 2  # neither event acked; order preserved for retry
    assert client.sent == []
