"""Pure-logic unit tests for mirage_agent_ingestion.enrollment — no Docker,
no network. Full flow tests (real Postgres + real step-ca) live in
tests/integration/test_step_ca_enrollment.py.
"""
from __future__ import annotations

import pytest
from mirage_agent_ingestion.enrollment import renewal_due

pytestmark = pytest.mark.unit


def test_renewal_due_at_20_percent_remaining():
    """Step 3 rule: auto-renew before 20% of certificate lifetime remains."""
    issued_at = 0.0
    not_after = 100.0  # 100s lifetime, for round numbers
    assert renewal_due(not_after_epoch=not_after, issued_at_epoch=issued_at, now_epoch=79.0) is False
    assert renewal_due(not_after_epoch=not_after, issued_at_epoch=issued_at, now_epoch=81.0) is True
    assert renewal_due(not_after_epoch=not_after, issued_at_epoch=issued_at, now_epoch=100.0) is True


def test_renewal_due_handles_zero_or_negative_lifetime():
    assert renewal_due(not_after_epoch=10.0, issued_at_epoch=10.0, now_epoch=5.0) is True
    assert renewal_due(not_after_epoch=5.0, issued_at_epoch=10.0, now_epoch=5.0) is True
