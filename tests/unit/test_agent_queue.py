"""Unit tests for the shared encrypted local queue + sequence store used by
every Windows agent (Step 4 local acceptance: "Queue sequence persists
across restart", "Outage replay tests pass"; reused as-is by MirageSpider
in Step 5).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mirage_common.agent_keys import LocalFileKeyProvider
from mirage_common.agent_queue import EncryptedEventQueue, QueueCapacityExceeded

pytestmark = pytest.mark.unit


def _make_queue(tmp_path: Path) -> EncryptedEventQueue:
    return EncryptedEventQueue(tmp_path / "queue.db", LocalFileKeyProvider(tmp_path / "queue.key"))


def test_enqueue_and_peek_roundtrips_event_data(tmp_path: Path):
    q = _make_queue(tmp_path)
    row_id = q.enqueue({"event_type": "agent.heartbeat", "n": 1}, enqueued_at="2026-07-25T00:00:00.000Z")
    batch = q.peek_batch()
    assert len(batch) == 1
    assert batch[0][0] == row_id
    assert batch[0][1] == {"event_type": "agent.heartbeat", "n": 1}


def test_data_at_rest_is_encrypted_not_plaintext(tmp_path: Path):
    q = _make_queue(tmp_path)
    q.enqueue({"secret_marker": "SHOULD_NOT_APPEAR_IN_RAW_FILE"}, enqueued_at="2026-07-25T00:00:00.000Z")
    q.close()
    raw = (tmp_path / "queue.db").read_bytes()
    assert b"SHOULD_NOT_APPEAR_IN_RAW_FILE" not in raw


def test_ack_removes_from_pending(tmp_path: Path):
    q = _make_queue(tmp_path)
    id1 = q.enqueue({"n": 1}, enqueued_at="t")
    q.enqueue({"n": 2}, enqueued_at="t")
    assert q.pending_count() == 2
    q.ack([id1])
    assert q.pending_count() == 1
    remaining = q.peek_batch()
    assert [e["n"] for _id, e in remaining] == [2]


def test_sequence_persists_and_never_repeats_across_restart(tmp_path: Path):
    db_path = tmp_path / "queue.db"
    key_provider = LocalFileKeyProvider(tmp_path / "queue.key")

    q1 = EncryptedEventQueue(db_path, key_provider)
    seqs_before = [q1.next_sequence() for _ in range(5)]
    assert seqs_before == [1, 2, 3, 4, 5]
    q1.close()  # simulates a service stop/crash

    # "Restart": brand-new queue object, same db file.
    q2 = EncryptedEventQueue(db_path, key_provider)
    assert q2.current_sequence() == 5
    seqs_after = [q2.next_sequence() for _ in range(3)]
    assert seqs_after == [6, 7, 8]  # continues, never resets to 0 or repeats


def test_outage_replay_drains_queue_in_order_once_reconnected(tmp_path: Path):
    """Simulates: network outage -> N events queued locally -> connectivity
    restored -> a flush loop sends them in enqueue order and acks only what
    actually got a confirmed send, leaving nothing duplicated or lost."""
    q = _make_queue(tmp_path)

    # "Outage": five events accumulate with nowhere to send.
    for n in range(5):
        q.enqueue({"n": n}, enqueued_at=f"t{n}")
    assert q.pending_count() == 5

    # "Reconnected": a flush loop drains in batches, sending is simulated by
    # a list a fake transport appends to; only successfully "sent" events are acked.
    sent: list[int] = []

    def fake_send(event: dict) -> bool:
        sent.append(event["n"])
        return True

    while True:
        batch = q.peek_batch(limit=2)
        if not batch:
            break
        acked_ids = [row_id for row_id, event in batch if fake_send(event)]
        q.ack(acked_ids)

    assert sent == [0, 1, 2, 3, 4]  # strict order, nothing skipped, nothing duplicated
    assert q.pending_count() == 0


def test_outage_replay_leaves_unacked_events_for_retry_on_partial_failure(tmp_path: Path):
    q = _make_queue(tmp_path)
    for n in range(3):
        q.enqueue({"n": n}, enqueued_at=f"t{n}")

    batch = q.peek_batch(limit=10)
    # Simulate: first event send fails (e.g. connection drops mid-batch) —
    # only ack what actually succeeded.
    succeeded_ids = [row_id for row_id, event in batch if event["n"] != 0]
    q.ack(succeeded_ids)

    assert q.pending_count() == 1
    remaining = q.peek_batch()
    assert remaining[0][1]["n"] == 0  # the failed one is still there for the next retry


def test_dead_letter_removes_event_from_pending_without_deleting_it(tmp_path: Path):
    q = _make_queue(tmp_path)
    row_id = q.enqueue({"n": 1}, enqueued_at="t")
    q.enqueue({"n": 2}, enqueued_at="t")

    q.dead_letter([row_id], error="event_type not submittable via this endpoint")

    assert q.pending_count() == 1  # dead-lettered event no longer blocks/counts as pending
    assert q.dead_letter_count() == 1
    remaining = q.peek_batch()
    assert [e["n"] for _id, e in remaining] == [2]  # the other event is still deliverable


def test_record_attempt_failure_increments_without_changing_pending_status(tmp_path: Path):
    q = _make_queue(tmp_path)
    row_id = q.enqueue({"n": 1}, enqueued_at="t")

    attempts_1 = q.record_attempt_failure(row_id, error="502 upstream unavailable")
    attempts_2 = q.record_attempt_failure(row_id, error="502 upstream unavailable")

    assert (attempts_1, attempts_2) == (1, 2)
    assert q.pending_count() == 1  # still retry-eligible, not dead-lettered
    assert q.peek_batch()[0][1]["n"] == 1


def test_enqueue_refuses_once_capacity_is_reached(tmp_path: Path):
    q = EncryptedEventQueue(
        tmp_path / "queue.db", LocalFileKeyProvider(tmp_path / "queue.key"), max_queue_size=2
    )
    q.enqueue({"n": 1}, enqueued_at="t")
    q.enqueue({"n": 2}, enqueued_at="t")

    with pytest.raises(QueueCapacityExceeded):
        q.enqueue({"n": 3}, enqueued_at="t")

    assert q.pending_count() == 2  # refused, not silently dropped or overwritten


def test_corrupt_queue_file_is_quarantined_and_replaced_with_a_fresh_one(tmp_path: Path):
    db_path = tmp_path / "queue.db"
    key_provider = LocalFileKeyProvider(tmp_path / "queue.key")

    q = EncryptedEventQueue(db_path, key_provider)
    q.enqueue({"n": 1}, enqueued_at="t")
    q.close()

    # Simulate on-disk corruption (e.g. a crash mid-write, bad sectors).
    db_path.write_bytes(b"this is not a valid sqlite file at all")

    recovered = EncryptedEventQueue(db_path, key_provider)
    try:
        assert recovered.recovered_from_corruption is True
        assert recovered.pending_count() == 0  # fresh queue, the corrupt data is quarantined not lost
        quarantined = list(tmp_path.glob("queue.db.corrupt-*"))
        assert len(quarantined) == 1
        # Service can keep operating: enqueue/flush works normally afterward.
        recovered.enqueue({"n": 2}, enqueued_at="t")
        assert recovered.pending_count() == 1
    finally:
        recovered.close()
