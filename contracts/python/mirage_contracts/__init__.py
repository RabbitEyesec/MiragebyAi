"""Mirage shared contracts: event/command envelopes, ULIDs, timestamps,
schema registry, and typed validation errors. Generated Pydantic models live
in mirage_contracts.generated (see `make generate-contracts`).
"""
from mirage_contracts.envelope import build_event, validate_command, validate_event
from mirage_contracts.errors import (
    ContractError,
    EnvelopeValidationError,
    IntegrityMismatchError,
    InvalidTimestampError,
    InvalidUlidError,
    MalformedSchemaVersionError,
    PayloadTooLargeError,
    PayloadValidationError,
    UnknownCommandTypeError,
    UnknownEventTypeError,
    UnsupportedSchemaVersionError,
)
from mirage_contracts.timestamps import is_valid_rfc3339_ms, now_rfc3339_ms
from mirage_contracts.ulid import generate_ulid, is_valid_ulid

__all__ = [
    "build_event",
    "validate_event",
    "validate_command",
    "ContractError",
    "EnvelopeValidationError",
    "IntegrityMismatchError",
    "PayloadValidationError",
    "PayloadTooLargeError",
    "UnknownEventTypeError",
    "UnknownCommandTypeError",
    "UnsupportedSchemaVersionError",
    "MalformedSchemaVersionError",
    "InvalidUlidError",
    "InvalidTimestampError",
    "generate_ulid",
    "is_valid_ulid",
    "now_rfc3339_ms",
    "is_valid_rfc3339_ms",
]
