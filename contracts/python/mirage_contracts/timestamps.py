"""RFC3339 UTC timestamps with millisecond precision, canonical 'Z' suffix.

Mirage never writes '+00:00' — always 'Z' — so string comparison/sorting of
timestamps is safe without parsing. See ARCHITECTURE_DECISIONS.md.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

RFC3339_MS_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
_RFC3339_MS_RE = re.compile(RFC3339_MS_PATTERN)


def now_rfc3339_ms() -> str:
    """Current UTC time as RFC3339 with millisecond precision and 'Z' suffix."""
    return to_rfc3339_ms(datetime.now(UTC))


def to_rfc3339_ms(dt: datetime) -> str:
    """Format a timezone-aware datetime as canonical RFC3339-with-milliseconds."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def is_valid_rfc3339_ms(value: str) -> bool:
    if not isinstance(value, str) or not _RFC3339_MS_RE.match(value):
        return False
    try:
        parse_rfc3339_ms(value)
    except ValueError:
        return False
    return True


def parse_rfc3339_ms(value: str) -> datetime:
    if not _RFC3339_MS_RE.match(value):
        raise ValueError(f"not a canonical RFC3339-with-milliseconds timestamp: {value!r}")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
