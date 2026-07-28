"""Unit tests for the NATS stream/subject topology (libs/mirage_common/subjects.py)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from mirage_common.subjects import (
    DEDUP_WINDOW_SECONDS,
    EVENT_TYPE_SUBJECTS,
    MAX_RETRY_HORIZON_SECONDS,
    STREAM_DEFINITIONS,
    failed_subject_for,
    stream_for_subject,
    subject_for_command_type,
    subject_for_event_type,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_six_streams_defined():
    assert set(STREAM_DEFINITIONS) == {
        "MIRAGE_TELEMETRY", "MIRAGE_LIFECYCLE", "MIRAGE_ACTIONS",
        "MIRAGE_EVIDENCE", "MIRAGE_AUDIT", "MIRAGE_HEALTH",
    }


def test_dedup_window_exceeds_max_retry_horizon():
    """§6.3: 'the NATS dedup window exceeds the maximum retry horizon.'"""
    for stream in STREAM_DEFINITIONS.values():
        assert stream.duplicate_window_seconds > MAX_RETRY_HORIZON_SECONDS, stream.name
        # NATS requires duplicate_window <= max_age.
        assert stream.duplicate_window_seconds <= stream.max_age_seconds, stream.name


def test_dedup_window_constant_matches_stream_defaults():
    assert DEDUP_WINDOW_SECONDS > MAX_RETRY_HORIZON_SECONDS


def test_every_schema_event_type_has_a_subject():
    """Every events/*.v<N>.schema.json's implied event_type must be routable."""
    events_dir = REPO_ROOT / "schemas" / "events"
    missing = []
    for schema_file in events_dir.glob("*.v*.schema.json"):
        event_type = re.sub(r"\.v[0-9]+\.schema\.json$", "", schema_file.name)
        if event_type not in EVENT_TYPE_SUBJECTS:
            missing.append(event_type)
    assert not missing, f"event types with no NATS subject mapping: {missing}"


def test_subject_for_event_type_unknown_raises():
    with pytest.raises(ValueError):
        subject_for_event_type("no.such.event")


def test_subject_for_command_type_unknown_raises():
    with pytest.raises(ValueError):
        subject_for_command_type("no.such.command")


def test_failed_subject_naming():
    assert failed_subject_for("sandbox.command") == "sandbox.command.failed"


@pytest.mark.parametrize(
    "subject,expected_stream",
    [
        ("agent.heartbeat", "MIRAGE_HEALTH"),
        ("system.health", "MIRAGE_HEALTH"),
        ("investigation.case.created", "MIRAGE_LIFECYCLE"),
        ("steering.decision_recorded", "MIRAGE_LIFECYCLE"),
        ("sandbox.command", "MIRAGE_ACTIONS"),
        ("sandbox.result", "MIRAGE_ACTIONS"),
        ("telemetry.endpoint.process", "MIRAGE_TELEMETRY"),
        ("telemetry.sandbox.file", "MIRAGE_TELEMETRY"),
        ("audit.recorded", "MIRAGE_AUDIT"),
        ("audit.agent.enrolled", "MIRAGE_AUDIT"),
        ("evidence.created", "MIRAGE_EVIDENCE"),
        ("canary.callback", "MIRAGE_EVIDENCE"),
    ],
)
def test_stream_for_subject(subject: str, expected_stream: str):
    assert stream_for_subject(subject) == expected_stream


def test_all_event_type_subjects_map_to_a_declared_stream():
    for event_type, subject in EVENT_TYPE_SUBJECTS.items():
        assert stream_for_subject(subject) is not None, f"{event_type} -> {subject} matches no stream"
