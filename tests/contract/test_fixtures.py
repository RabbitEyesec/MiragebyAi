"""Contract tests: golden fixtures under /fixtures must validate (or fail)
exactly as expected via mirage_contracts.validate_event / validate_command.

This is the Step 1 acceptance test: "current fixtures validate; previous
compatible fixtures validate; invalid fixtures fail with expected typed
errors."
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

from mirage_contracts import (  # noqa: E402
    EnvelopeValidationError,
    IntegrityMismatchError,
    PayloadTooLargeError,
    PayloadValidationError,
    UnknownCommandTypeError,
    UnsupportedSchemaVersionError,
    validate_command,
    validate_event,
)

pytestmark = pytest.mark.contract

EVENT_FIXTURES_DIR = REPO_ROOT / "fixtures" / "events" / "agent.heartbeat"
COMMAND_FIXTURES_DIR = REPO_ROOT / "fixtures" / "commands" / "sandbox.command"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


# name -> expected outcome. None means "must validate successfully".
EVENT_EXPECTATIONS: dict[str, type[Exception] | None] = {
    "valid_current": None,
    "valid_previous": None,
    "invalid_id": EnvelopeValidationError,
    "invalid_timestamp": EnvelopeValidationError,
    "unknown_field": EnvelopeValidationError,
    "oversized_payload": PayloadTooLargeError,
    "unsupported_version": UnsupportedSchemaVersionError,
    "missing_required_field": PayloadValidationError,
    "integrity_mismatch": IntegrityMismatchError,
}


@pytest.mark.parametrize("fixture_name,expected_error", sorted(EVENT_EXPECTATIONS.items()))
def test_event_fixture(fixture_name: str, expected_error: type[Exception] | None) -> None:
    instance = _load(EVENT_FIXTURES_DIR / f"{fixture_name}.json")
    if expected_error is None:
        result = validate_event(instance)
        assert result.event_type == "agent.heartbeat"
    else:
        with pytest.raises(expected_error):
            validate_event(instance)


def test_all_required_fixture_kinds_present() -> None:
    """Guards against silently deleting one of the 8 fixture kinds the brief requires."""
    required = {
        "valid_current",
        "valid_previous",
        "invalid_id",
        "invalid_timestamp",
        "unknown_field",
        "oversized_payload",
        "unsupported_version",
        "missing_required_field",
    }
    present = {p.stem for p in EVENT_FIXTURES_DIR.glob("*.json")}
    assert required.issubset(present)


COMMAND_EXPECTATIONS: dict[str, type[Exception] | None] = {
    "valid_current": None,
    "unsupported_version": UnsupportedSchemaVersionError,
    "unknown_action_type": PayloadValidationError,
}


@pytest.mark.parametrize("fixture_name,expected_error", sorted(COMMAND_EXPECTATIONS.items()))
def test_command_fixture(fixture_name: str, expected_error: type[Exception] | None) -> None:
    instance = _load(COMMAND_FIXTURES_DIR / f"{fixture_name}.json")
    if expected_error is None:
        result = validate_command(instance)
        assert result.command_type == "sandbox.command"
    else:
        with pytest.raises(expected_error):
            validate_command(instance)


def test_unknown_command_type_is_rejected() -> None:
    instance = _load(COMMAND_FIXTURES_DIR / "valid_current.json")
    instance = dict(instance)
    instance["command_type"] = "sandbox.nonexistent_command_family"
    with pytest.raises(UnknownCommandTypeError):
        validate_command(instance)
