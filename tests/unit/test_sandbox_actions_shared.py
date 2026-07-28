"""Consistency tests for Step 9b's fixed action set: the same 15 action
types must agree across three independently-maintained places — the JSON
Schema (source of truth for the wire contract), the Postgres CHECK
constraint (source of truth for what can ever be stored), and
mirage_common.sandbox_actions.ALLOWED_ACTION_TYPES (source of truth for
what application code will execute). A hand-maintained Postgres CHECK
constraint can't reference a JSON Schema file, so this test is what keeps
the three from silently drifting apart.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mirage_common.sandbox_actions import (
    ALLOWED_ACTION_TYPES,
    CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS,
    DECOY_SERVICE_ACTIONS,
    OUTPUT_TAGS,
    STATE_MUTATING_ACTIONS,
    default_output_tag,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "commands" / "sandbox.command.v1.schema.json"
MIGRATION_PATH = REPO_ROOT / "infra" / "migrations" / "0006_sandbox_actions.up.sql"


def test_schema_enum_matches_python_constant():
    schema = json.loads(SCHEMA_PATH.read_text())
    schema_enum = set(schema["properties"]["action_type"]["enum"])
    assert schema_enum == ALLOWED_ACTION_TYPES


def test_migration_check_constraint_matches_python_constant():
    sql = MIGRATION_PATH.read_text()
    match = re.search(r"action_type\s+TEXT NOT NULL CHECK \(action_type IN \((.*?)\)\)", sql, re.DOTALL)
    assert match is not None, "could not find action_type CHECK constraint in migration 0006"
    values = set(re.findall(r"'([A-Z_]+)'", match.group(1)))
    assert values == ALLOWED_ACTION_TYPES


def test_decoy_service_and_caller_supplied_sets_are_disjoint_and_subsets():
    assert DECOY_SERVICE_ACTIONS <= ALLOWED_ACTION_TYPES
    assert CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS <= ALLOWED_ACTION_TYPES
    assert DECOY_SERVICE_ACTIONS.isdisjoint(CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS)


def test_state_mutating_actions_excludes_only_read_only_ones():
    assert {"REQUEST_SNAPSHOT", "CONCLUDE_SESSION"} == ALLOWED_ACTION_TYPES - STATE_MUTATING_ACTIONS


@pytest.mark.parametrize("action_type", sorted(ALLOWED_ACTION_TYPES - CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS))
def test_default_output_tag_is_always_a_known_tag(action_type):
    tag = default_output_tag(action_type)
    assert tag in OUTPUT_TAGS


@pytest.mark.parametrize("action_type", sorted(CALLER_SUPPLIED_OUTPUT_TAG_ACTIONS))
def test_caller_supplied_actions_have_no_default_tag(action_type):
    assert default_output_tag(action_type) is None


@pytest.mark.parametrize("action_type", sorted(DECOY_SERVICE_ACTIONS))
def test_decoy_service_actions_default_to_decoy_service_output(action_type):
    assert default_output_tag(action_type) == "DECOY_SERVICE_OUTPUT"
