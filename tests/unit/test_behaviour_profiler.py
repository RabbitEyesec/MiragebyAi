from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mirage_common.behaviour import BehaviourEvent, assess_skill, normalise_behaviour_event
from mirage_contracts.ulid import generate_ulid

NOW = datetime(2026, 7, 26, tzinfo=UTC)


def _event(kind: str, offset: int) -> BehaviourEvent:
    return BehaviourEvent(
        generate_ulid(),
        generate_ulid(),
        generate_ulid(),
        "COMMAND",
        kind,
        NOW + timedelta(seconds=offset),
        kind,
        1.0,
        1.0,
        {},
    )


def test_novice_and_advanced_behaviour() -> None:
    novice = assess_skill(
        [_event("COMMAND_SYNTAX_ERROR", 1), _event("REPEATED_BASIC_ERROR", 2), _event("FAILED_WITHOUT_RECOVERY", 3)],
        as_of=NOW + timedelta(minutes=1),
    )
    assert novice.band == "NOVICE"
    advanced = assess_skill(
        [_event("ERROR_RECOVERY", 1), _event("TOOL_CHAINING", 2), _event("PRIVILEGE_AWARENESS", 3)],
        as_of=NOW + timedelta(minutes=1),
    )
    assert advanced.band in {"ADVANCED", "EXPERT"}
    assert len(advanced.supporting_event_ids) <= 8


def test_sparse_contradictory_out_of_order_replay_is_deterministic() -> None:
    events = [
        _event("TOOL_CHAINING", 3),
        _event("COMMAND_SYNTAX_ERROR", 1),
        _event("ERROR_RECOVERY", 2),
    ]
    one = assess_skill(events, as_of=NOW + timedelta(minutes=1), profile_version=7)
    two = assess_skill(list(reversed(events)), as_of=NOW + timedelta(minutes=1), profile_version=7)
    assert one == two
    assert "contradictory operational indicators" in one.uncertainties
    sparse = assess_skill(events[:2], as_of=NOW + timedelta(minutes=1))
    assert sparse.band == "UNKNOWN"


def test_confidence_decay_and_no_identity_inference() -> None:
    recent = [_event("TOOL_CHAINING", 1), _event("ERROR_RECOVERY", 2), _event("PRIVILEGE_AWARENESS", 3)]
    near = assess_skill(recent, as_of=NOW + timedelta(days=1))
    old = assess_skill(recent, as_of=NOW + timedelta(days=120))
    assert old.confidence < near.confidence
    normalised = normalise_behaviour_event(
        {
            "event_id": generate_ulid(),
            "case_id": generate_ulid(),
            "session_id": generate_ulid(),
            "category": "TOOL",
            "behaviour_type": "TOOL_CHAINING",
            "event_time": NOW,
            "summary": "used two tools",
            "attributes": {"person_name": "Mallory", "tool": "native"},
        }
    )
    assert "person_name" not in normalised.attributes
    assert len(near.summary.encode()) <= 2048
