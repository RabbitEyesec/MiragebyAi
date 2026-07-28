"""High-level validate/construct API for event and command envelopes.

This is the ONE place application code should call to accept an inbound
event or command: it validates envelope structure, checks the payload cap,
resolves and validates the payload against its registered schema, and
enforces the major-version compatibility rule (Step 1 / §Appendix C).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from mirage_contracts.errors import (
    EnvelopeValidationError,
    IntegrityMismatchError,
    PayloadTooLargeError,
    PayloadValidationError,
    UnknownCommandTypeError,
    UnknownEventTypeError,
    UnsupportedSchemaVersionError,
)
from mirage_contracts.registry import commands_registry, events_registry, parse_schema_version
from mirage_contracts.timestamps import now_rfc3339_ms
from mirage_contracts.ulid import generate_ulid

MAX_PAYLOAD_BYTES = 256 * 1024


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used for both size checks and integrity.sha256."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


@dataclass(frozen=True)
class ValidatedEvent:
    envelope: dict
    payload: dict
    event_type: str
    major_version: int


@dataclass(frozen=True)
class ValidatedCommand:
    envelope: dict
    params: dict
    command_type: str
    major_version: int


def _envelope_errors(validator, instance: dict) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    ]


def validate_event(instance: dict, *, supported_majors: set[int] | None = None) -> ValidatedEvent:
    """Validate a raw event dict end-to-end. Raises a typed ContractError subclass on failure.

    Rejection happens BEFORE any NATS publish or Elasticsearch write — callers
    must call this at the ingestion boundary, not after.
    """
    envelope_errors = _envelope_errors(events_registry.envelope_validator, instance)
    if envelope_errors:
        raise EnvelopeValidationError(envelope_errors)

    payload_bytes = len(canonical_json_bytes(instance["payload"]))
    if payload_bytes > MAX_PAYLOAD_BYTES:
        raise PayloadTooLargeError(payload_bytes)

    expected_sha256 = sha256_hex(instance["payload"])
    actual_sha256 = instance["integrity"]["sha256"]
    if expected_sha256 != actual_sha256:
        raise IntegrityMismatchError(expected=actual_sha256, actual=expected_sha256)

    event_type = instance["event_type"]
    major, _minor = parse_schema_version(instance["schema_version"])

    registered_majors = events_registry.supported_majors(event_type)
    if not registered_majors:
        raise UnknownEventTypeError(event_type)

    allowed = supported_majors if supported_majors is not None else registered_majors
    if major not in allowed:
        raise UnsupportedSchemaVersionError(event_type, instance["schema_version"], allowed)

    validator = events_registry.get_validator(event_type, major)
    assert validator is not None
    payload_errors = _envelope_errors(validator, instance["payload"])
    if payload_errors:
        raise PayloadValidationError(event_type, payload_errors)

    return ValidatedEvent(envelope=instance, payload=instance["payload"], event_type=event_type, major_version=major)


def validate_command(instance: dict, *, supported_majors: set[int] | None = None) -> ValidatedCommand:
    envelope_errors = _envelope_errors(commands_registry.envelope_validator, instance)
    if envelope_errors:
        raise EnvelopeValidationError(envelope_errors)

    command_type = instance["command_type"]
    major, _minor = parse_schema_version(instance["schema_version"])

    registered_majors = commands_registry.supported_majors(command_type)
    if not registered_majors:
        raise UnknownCommandTypeError(command_type)

    allowed = supported_majors if supported_majors is not None else registered_majors
    if major not in allowed:
        raise UnsupportedSchemaVersionError(command_type, instance["schema_version"], allowed)

    validator = commands_registry.get_validator(command_type, major)
    assert validator is not None
    params_errors = _envelope_errors(validator, instance["params"])
    if params_errors:
        raise PayloadValidationError(command_type, params_errors)

    return ValidatedCommand(envelope=instance, params=instance["params"], command_type=command_type, major_version=major)


def build_event(
    *,
    event_type: str,
    schema_version: str,
    payload: dict,
    source_id: str,
    sequence: int,
    actor_type: str,
    classification: str,
    case_id: str | None = None,
    session_id: str | None = None,
    event_id: str | None = None,
    event_time: str | None = None,
) -> dict:
    """Construct a well-formed event envelope dict (does not validate — call
    validate_event() on the result if you need to confirm it before publishing).
    """
    now = now_rfc3339_ms()
    return {
        "event_id": event_id or generate_ulid(),
        "event_type": event_type,
        "schema_version": schema_version,
        "event_time": event_time or now,
        "ingest_time": now,
        "case_id": case_id,
        "session_id": session_id,
        "source_id": source_id,
        "sequence": sequence,
        "actor_type": actor_type,
        "integrity": {"sha256": sha256_hex(payload)},
        "classification": classification,
        "payload": payload,
    }
