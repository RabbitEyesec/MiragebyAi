"""Canonical uppercase ULID generation and validation.

Validation is hand-written against the Crockford Base32 ULID spec rather than
delegated entirely to a single library's internal representation, so the
exact same regex can be mirrored byte-for-byte in TypeScript
(contracts/typescript/src/ulid.ts) and in every JSON Schema's `pattern`
(see docs/adr — ADR-0010).
"""
from __future__ import annotations

import re as _re

from ulid import ULID as _ULID

# First character restricted to 0-7 because a 128-bit ULID's 48-bit timestamp
# component caps the leading base32 symbol; the remaining 25 symbols are the
# Crockford Base32 alphabet (I, L, O, U excluded).
ULID_PATTERN = r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"

_ULID_RE = _re.compile(ULID_PATTERN)


def generate_ulid() -> str:
    """Generate a new canonical uppercase ULID."""
    return str(_ULID()).upper()


def is_valid_ulid(value: str) -> bool:
    """True iff value is a canonical uppercase ULID (26 chars, Crockford Base32)."""
    return isinstance(value, str) and bool(_ULID_RE.match(value))


def require_valid_ulid(value: str, *, field: str = "id") -> str:
    """Return value unchanged if it is a valid canonical ULID, else raise."""
    if not is_valid_ulid(value):
        from mirage_contracts.errors import InvalidUlidError

        raise InvalidUlidError(field=field, value=value)
    return value
