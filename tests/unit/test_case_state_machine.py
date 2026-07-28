"""Unit tests for the case state graph itself (libs/mirage_common/case_state_machine.py)
— pure Python, no database. The transition-execution logic (row locking,
outbox/audit writes) requires a real Postgres connection and is covered in
tests/integration/test_case_state_machine.py.
"""
from __future__ import annotations

import pytest

from mirage_common.case_state_machine import ALLOWED_TRANSITIONS, TERMINAL_STATE

pytestmark = pytest.mark.unit

SPEC_STATE_ORDER = [
    "CREATED", "ARMED", "MONITORING", "STEERING_PENDING", "SANDBOX_ACTIVE",
    "ENGAGING", "CONCLUDING", "EVIDENCE_VERIFYING", "EXPORTED", "DESTROYED",
]


def test_transition_graph_matches_the_spec_linear_order():
    walked = ["CREATED"]
    state = "CREATED"
    while state in ALLOWED_TRANSITIONS:
        state = ALLOWED_TRANSITIONS[state]
        walked.append(state)
    assert walked == SPEC_STATE_ORDER


def test_terminal_state_has_no_outgoing_transition():
    assert TERMINAL_STATE == "DESTROYED"
    assert TERMINAL_STATE not in ALLOWED_TRANSITIONS


def test_every_non_terminal_spec_state_has_exactly_one_outgoing_edge():
    for state in SPEC_STATE_ORDER[:-1]:
        assert state in ALLOWED_TRANSITIONS
    assert len(ALLOWED_TRANSITIONS) == len(SPEC_STATE_ORDER) - 1


def test_no_state_is_reachable_from_two_different_predecessors():
    targets = list(ALLOWED_TRANSITIONS.values())
    assert len(targets) == len(set(targets))  # no two edges point at the same state
