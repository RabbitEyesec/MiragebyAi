"""Typed contract-validation errors.

Every rejection the contracts package can produce is a distinct, catchable
type — never a bare ValueError/jsonschema.ValidationError leaking out — so
callers (mirage-agent-ingestion, mirage-api, ...) can map each to the correct
API error_code (schemas/api/error.schema.json) and, per Step 1's acceptance
line, so an unsupported schema_version is rejected typed, not silently
accepted.
"""
from __future__ import annotations


class ContractError(Exception):
    """Base class for every typed contract-validation failure."""

    error_code: str = "CONTRACT_ERROR"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message!r}, {self.context!r})"


class InvalidUlidError(ContractError):
    error_code = "INVALID_ULID"

    def __init__(self, field: str, value: object) -> None:
        super().__init__(f"{field!r} is not a canonical uppercase ULID: {value!r}", field=field, value=value)


class InvalidTimestampError(ContractError):
    error_code = "INVALID_TIMESTAMP"

    def __init__(self, field: str, value: object) -> None:
        super().__init__(
            f"{field!r} is not a canonical RFC3339-with-milliseconds UTC timestamp: {value!r}",
            field=field,
            value=value,
        )


class UnknownEventTypeError(ContractError):
    error_code = "UNKNOWN_EVENT_TYPE"

    def __init__(self, event_type: str) -> None:
        super().__init__(f"no schema registered for event_type={event_type!r}", event_type=event_type)


class UnknownCommandTypeError(ContractError):
    error_code = "UNKNOWN_COMMAND_TYPE"

    def __init__(self, command_type: str) -> None:
        super().__init__(f"no schema registered for command_type={command_type!r}", command_type=command_type)


class UnsupportedSchemaVersionError(ContractError):
    """Unsupported MAJOR schema_version. Per spec: rejected, never enters NATS or Elastic."""

    error_code = "UNSUPPORTED_SCHEMA_VERSION"

    def __init__(self, type_name: str, schema_version: str, supported_majors: set[int]) -> None:
        super().__init__(
            f"{type_name!r} schema_version {schema_version!r} has unsupported major version "
            f"(supported: {sorted(supported_majors)})",
            type_name=type_name,
            schema_version=schema_version,
            supported_majors=sorted(supported_majors),
        )


class MalformedSchemaVersionError(ContractError):
    error_code = "MALFORMED_SCHEMA_VERSION"

    def __init__(self, schema_version: object) -> None:
        super().__init__(f"schema_version is not '<major>.<minor>': {schema_version!r}", schema_version=schema_version)


class EnvelopeValidationError(ContractError):
    """Envelope-level structural failure (unknown field, missing field, bad type, ...)."""

    error_code = "ENVELOPE_VALIDATION_ERROR"

    def __init__(self, errors: list[str]) -> None:
        super().__init__(f"envelope failed validation: {errors}", errors=errors)
        self.errors = errors


class PayloadValidationError(ContractError):
    """Payload failed the schema registered for (type, schema_version major)."""

    error_code = "PAYLOAD_VALIDATION_ERROR"

    def __init__(self, type_name: str, errors: list[str]) -> None:
        super().__init__(f"payload for {type_name!r} failed validation: {errors}", type_name=type_name, errors=errors)
        self.errors = errors


class IntegrityMismatchError(ContractError):
    error_code = "INTEGRITY_MISMATCH"

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"integrity.sha256 {expected!r} does not match computed payload hash {actual!r}",
            expected=expected,
            actual=actual,
        )


class PayloadTooLargeError(ContractError):
    error_code = "PAYLOAD_TOO_LARGE"
    MAX_BYTES = 256 * 1024

    def __init__(self, actual_bytes: int) -> None:
        super().__init__(
            f"payload is {actual_bytes} bytes, exceeds the {self.MAX_BYTES}-byte cap",
            actual_bytes=actual_bytes,
            max_bytes=self.MAX_BYTES,
        )
