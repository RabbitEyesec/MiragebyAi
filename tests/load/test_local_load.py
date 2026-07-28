from __future__ import annotations

from mirage_common.load_test import LOCAL_REDUCED, PROFILE_B, run_load


def test_reduced_load_replays_outage_without_loss_or_duplicate_state() -> None:
    report = run_load(LOCAL_REDUCED)
    measurements = report["measurements"]
    assert report["result"] == "PASS"
    assert measurements["confirmed_event_loss"] == 0
    assert measurements["duplicate_effective_changes"] == 0
    assert measurements["max_queue_depth"] > 0
    assert measurements["buffer_capacity_minutes"] >= 15
    assert measurements["p99_latency_ms"] >= measurements["p95_latency_ms"]
    assert report["limitation"]


def test_profile_b_definition_is_exact_and_not_run_by_local_test() -> None:
    assert PROFILE_B.target_events_per_second == 1000
    assert PROFILE_B.duration_seconds == 300
    assert PROFILE_B.outage_seconds == 300
    assert PROFILE_B.buffer_minutes == 15
