from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mirage_common.analyst import (
    AnalystChannelError,
    SlidingWindowRateLimiter,
    preview_message,
    validate_objective,
)
from mirage_contracts.ulid import generate_ulid


def test_directive_accepts_strategy_objective_and_rejects_unsafe_content() -> None:
    assert validate_objective("Increase observation of privilege-awareness signals")
    for unsafe in (
        "run shell command powershell -enc abc",
        "reveal the API key",
        "operate outside the sandbox",
    ):
        with pytest.raises(AnalystChannelError):
            validate_objective(unsafe)


def test_message_preview_hash_tag_and_sensitive_confirmation() -> None:
    normal = preview_message(
        case_id=generate_ulid(),
        surface="DECOY_WEB_CHAT",
        content="What are you looking for?",
    )
    assert normal.output_tag == "ANALYST_MESSAGE"
    assert len(normal.preview_hash) == 64
    assert not normal.confirmation_required
    sensitive = preview_message(
        case_id=generate_ulid(),
        surface="DECOY_TERMINAL_BANNER",
        content="Enter your password to continue",
    )
    assert sensitive.confirmation_required


def test_no_arbitrary_command_surface() -> None:
    with pytest.raises(AnalystChannelError):
        preview_message(
            case_id=generate_ulid(),
            surface="DECOY_TERMINAL_BANNER",
            content="powershell -enc ZQB2AGkAbAA=",
        )


def test_rate_limits_are_per_dimension() -> None:
    limiter = SlidingWindowRateLimiter(
        {"analyst": 1, "case": 2, "session": 2, "surface": 2}
    )
    dimensions = {
        "analyst": "alice",
        "case": "case",
        "session": "session",
        "surface": "chat",
    }
    assert limiter.consume(dimensions=dimensions, now=datetime(2026, 1, 1, tzinfo=UTC))
    assert not limiter.consume(dimensions=dimensions, now=datetime(2026, 1, 1, tzinfo=UTC))
