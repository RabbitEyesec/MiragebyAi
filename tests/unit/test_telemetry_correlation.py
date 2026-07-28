"""Proves Spider and Elastic Agent produce complementary, not duplicate,
effective telemetry (Priority 1, revised) — see
docs/architecture/windows-telemetry.md.
"""
from __future__ import annotations

import pytest

from mirage_common.telemetry_correlation import (
    MIRAGE_SPECIFIC_OBSERVATION_TYPES,
    OBSERVATION_TYPES_OWNED_BY_ELASTIC_AGENT,
    ElasticAgentEvent,
    is_duplicate_of_elastic_agent_event,
    is_owned_by_elastic_agent,
)

pytestmark = pytest.mark.unit

_PROCESS_GUID = "{4F1A2B3C-0001-0000-0000-000000001234}"
_OTHER_PROCESS_GUID = "{4F1A2B3C-0002-0000-0000-000000005678}"
_HOST_ID = "WKS-042"


def _spider_observation(*, host_id=_HOST_ID, process_guid=_PROCESS_GUID) -> dict:
    detail: dict = {"host_id": host_id, "pid": 4321}
    if process_guid is not None:
        detail["process_guid"] = process_guid
    return {
        "observation_type": "PROCESS_START",
        "subject": "cmd.exe",
        "detail": detail,
        "observed_at": "2026-07-27T00:00:00.000Z",
    }


def test_matching_host_and_process_guid_is_a_confirmed_duplicate():
    observation = _spider_observation()
    elastic_event = ElasticAgentEvent(
        host_id=_HOST_ID, process_guid=_PROCESS_GUID, event_type="process_start", timestamp="2026-07-27T00:00:00.100Z"
    )
    assert is_duplicate_of_elastic_agent_event(observation, elastic_event) is True


def test_different_process_guid_is_not_a_duplicate():
    observation = _spider_observation()
    elastic_event = ElasticAgentEvent(
        host_id=_HOST_ID, process_guid=_OTHER_PROCESS_GUID, event_type="process_start", timestamp="2026-07-27T00:00:00.100Z"
    )
    assert is_duplicate_of_elastic_agent_event(observation, elastic_event) is False


def test_different_host_is_not_a_duplicate_even_with_the_same_process_guid():
    observation = _spider_observation(host_id="WKS-999")
    elastic_event = ElasticAgentEvent(
        host_id=_HOST_ID, process_guid=_PROCESS_GUID, event_type="process_start", timestamp="2026-07-27T00:00:00.100Z"
    )
    assert is_duplicate_of_elastic_agent_event(observation, elastic_event) is False


def test_missing_process_guid_on_spider_side_makes_no_correlation_claim():
    """A false "this is a duplicate" would hide a real, distinct event from
    an analyst — worse than simply not claiming a correlation."""
    observation = _spider_observation(process_guid=None)
    elastic_event = ElasticAgentEvent(
        host_id=_HOST_ID, process_guid=_PROCESS_GUID, event_type="process_start", timestamp="2026-07-27T00:00:00.100Z"
    )
    assert is_duplicate_of_elastic_agent_event(observation, elastic_event) is False


def test_missing_process_guid_on_elastic_side_makes_no_correlation_claim():
    observation = _spider_observation()
    elastic_event = ElasticAgentEvent(
        host_id=_HOST_ID, process_guid=None, event_type="process_start", timestamp="2026-07-27T00:00:00.100Z"
    )
    assert is_duplicate_of_elastic_agent_event(observation, elastic_event) is False


def test_observation_with_no_detail_at_all_makes_no_correlation_claim():
    observation = {"observation_type": "PROCESS_START", "subject": "cmd.exe", "observed_at": "2026-07-27T00:00:00.000Z"}
    elastic_event = ElasticAgentEvent(
        host_id=_HOST_ID, process_guid=_PROCESS_GUID, event_type="process_start", timestamp="2026-07-27T00:00:00.100Z"
    )
    assert is_duplicate_of_elastic_agent_event(observation, elastic_event) is False


@pytest.mark.parametrize(
    "observation_type",
    ["PROCESS_START", "PROCESS_STOP", "FILE_CREATE", "FILE_MODIFY", "FILE_DELETE", "NETWORK_CONNECTION", "REGISTRY_MODIFY"],
)
def test_process_file_network_registry_types_are_classified_as_elastic_agent_owned(observation_type):
    assert is_owned_by_elastic_agent(observation_type) is True


@pytest.mark.parametrize(
    "observation_type",
    [
        "ARTIFACT_INTERACTION",
        "DECOY_INTERACTION",
        "CONTROLLER_ACTION_OBSERVED",
        "ANALYST_INTERACTION_OBSERVED",
        "AI_INTERACTION_OBSERVED",
        "USER_INTERACTION_INDICATOR",
    ],
)
def test_mirage_specific_types_are_not_classified_as_elastic_agent_owned(observation_type):
    assert is_owned_by_elastic_agent(observation_type) is False
    assert observation_type in MIRAGE_SPECIFIC_OBSERVATION_TYPES


def test_owned_and_mirage_specific_sets_are_disjoint_and_together_cover_every_schema_enum_value():
    """Every observation_type in the JSON Schema enum must be classified as
    exactly one of "owned by Elastic Agent" or "Mirage-specific" — an
    unclassified type would silently escape this module's dedup reasoning."""
    import json
    from pathlib import Path

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas" / "events" / "spider.observation.v1.schema.json").read_text()
    )
    schema_enum = set(schema["properties"]["observation_type"]["enum"])
    classified = OBSERVATION_TYPES_OWNED_BY_ELASTIC_AGENT | MIRAGE_SPECIFIC_OBSERVATION_TYPES
    assert not (OBSERVATION_TYPES_OWNED_BY_ELASTIC_AGENT & MIRAGE_SPECIFIC_OBSERVATION_TYPES)
    assert schema_enum == classified
