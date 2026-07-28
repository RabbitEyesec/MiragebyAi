"""Correlates MirageSpider's own observations against Elastic Agent's
independently-collected Sysmon/Windows Event Log data for the same host —
this is what proves Spider and Elastic Agent produce complementary, not
duplicate, effective telemetry (Priority 1, revised). See
docs/architecture/windows-telemetry.md for the full ownership split.

Elastic Agent (via Fleet, the Windows/Sysmon integration) is the sole owner
of raw Sysmon process/file/network/registry event ingestion. MirageSpider's
own PROCESS_START/PROCESS_STOP/FILE_*/NETWORK_CONNECTION/REGISTRY_MODIFY
observation types predate that ownership split and remain in schema for the
fingerprint-gate and dev-sandbox-target use cases that still read them
directly from Postgres rather than Elasticsearch — but any NEW consumer
(the dashboard, a report, an analyst view) that shows both Spider's own
observations and Elastic Agent's Sysmon data for the same case must use
`is_duplicate_of_elastic_agent_event` to avoid presenting one real action as
two separate pieces of evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

# Spider observation_type values that describe the same category of event
# Elastic Agent's Windows/Sysmon integration already collects natively.
# Kept in schema for the pre-existing fingerprint-gate/dev-sandbox-target
# consumers (Postgres-direct, not Elasticsearch) — NOT evidence that Spider
# is the intended collector for these categories going forward.
OBSERVATION_TYPES_OWNED_BY_ELASTIC_AGENT = frozenset(
    {
        "PROCESS_START",
        "PROCESS_STOP",
        "FILE_CREATE",
        "FILE_MODIFY",
        "FILE_DELETE",
        "NETWORK_CONNECTION",
        "REGISTRY_MODIFY",
    }
)

# Signals Elastic Agent has no way to observe at all — real-time decoy
# interaction, controller action outcomes, analyst/AI interaction surfaces,
# user-interaction indicators, and Spider's own tamper/health reporting.
# This is what Spider is FOR, post-Priority-1-revision.
MIRAGE_SPECIFIC_OBSERVATION_TYPES = frozenset(
    {
        "ARTIFACT_INTERACTION",
        "DECOY_INTERACTION",
        "CONTROLLER_ACTION_OBSERVED",
        "ANALYST_INTERACTION_OBSERVED",
        "AI_INTERACTION_OBSERVED",
        "USER_INTERACTION_INDICATOR",
    }
)


def is_owned_by_elastic_agent(observation_type: str) -> bool:
    return observation_type in OBSERVATION_TYPES_OWNED_BY_ELASTIC_AGENT


@dataclass(frozen=True)
class ElasticAgentEvent:
    """The subset of an Elastic Agent Sysmon-derived document this module
    needs — not a full ECS field mapping. `host_id` matches Elastic's own
    `host.id`; `process_guid` matches Sysmon's `ProcessGuid` field, both in
    the same braced-GUID format Sysmon itself emits."""

    host_id: str
    process_guid: str | None
    event_type: str
    timestamp: str


def is_duplicate_of_elastic_agent_event(
    spider_observation: dict, elastic_event: ElasticAgentEvent
) -> bool:
    """True if `spider_observation` (a spider.observation payload — the
    dict with observation_type/subject/detail/observed_at) and
    `elastic_event` describe the SAME underlying real-world event, not two
    independent pieces of evidence.

    Matches on (host_id, process_guid) — the strongest available
    correlation key, the same one Sysmon itself uses to link a process's
    own start/stop/network/file events together. Deliberately returns
    False (no correlation claim) whenever either side lacks a
    process_guid, rather than guessing from subject text or timestamp
    proximity — a false "these are duplicates" would hide a real, distinct
    event from an analyst, which is worse than an unclaimed correlation.
    """
    detail = spider_observation.get("detail") or {}
    spider_host_id = detail.get("host_id")
    spider_process_guid = detail.get("process_guid")
    if not spider_host_id or not spider_process_guid or not elastic_event.process_guid:
        return False
    return bool(spider_host_id == elastic_event.host_id and spider_process_guid == elastic_event.process_guid)
