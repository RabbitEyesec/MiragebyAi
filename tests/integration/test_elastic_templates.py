"""Integration tests: Mirage's Elastic ILM policy / ingest pipeline /
component + index templates (Step 4, Appendix E), applied to a real
ephemeral Elasticsearch 8.15 container via the exact same
scripts/provision-elastic-templates logic used against the dev stack —
verified for real: an event round-trips through search, @timestamp is
derived correctly, and dynamic:strict rejects an unexpected top-level field.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from mirage_contracts.envelope import build_event

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def provisioned_elastic(elasticsearch_url: str) -> str:
    env = {**os.environ, "MIRAGE_ELASTIC_URL": elasticsearch_url}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "provision-elastic-templates")],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return elasticsearch_url


def _heartbeat_event(**overrides) -> dict:
    payload = {
        "agent_id": "endpoint-test.mirage.local", "role": "ENDPOINT", "build_hash": "a" * 64,
        "version": "1.0.0", "certificate_serial": "1", "uptime_seconds": 42, "health_state": "HEALTHY",
    }
    evt = build_event(
        event_type="agent.heartbeat", schema_version="1.1", payload=payload,
        source_id="endpoint-test.mirage.local", sequence=1, actor_type="ENDPOINT_AGENT", classification="INTERNAL",
    )
    evt.update(overrides)
    return evt


def test_event_round_trips_through_search(provisioned_elastic: str):
    evt = _heartbeat_event()
    r = httpx.post(f"{provisioned_elastic}/mirage-telemetry-endpoint/_doc", json=evt)
    assert r.status_code == 201, r.text

    httpx.post(f"{provisioned_elastic}/mirage-telemetry-endpoint/_refresh")
    r2 = httpx.get(f"{provisioned_elastic}/mirage-telemetry-endpoint/_search")
    result = r2.json()
    assert result["hits"]["total"]["value"] >= 1
    hit = result["hits"]["hits"][0]["_source"]
    assert hit["event_type"] == "agent.heartbeat"
    assert hit["payload"]["agent_id"] == "endpoint-test.mirage.local"


def test_timestamp_pipeline_derives_at_timestamp_from_ingest_time(provisioned_elastic: str):
    evt = _heartbeat_event()
    r = httpx.post(f"{provisioned_elastic}/mirage-telemetry-endpoint/_doc", json=evt)
    assert r.status_code == 201
    doc_id = r.json()["_id"]

    httpx.post(f"{provisioned_elastic}/mirage-telemetry-endpoint/_refresh")
    r2 = httpx.get(f"{provisioned_elastic}/mirage-telemetry-endpoint/_search", params={"q": f"_id:{doc_id}"})
    hit = r2.json()["hits"]["hits"][0]["_source"]
    assert hit["@timestamp"][:19] == evt["ingest_time"][:19]  # same instant, allow format/precision drift only


def test_dynamic_strict_rejects_unexpected_top_level_field(provisioned_elastic: str):
    evt = _heartbeat_event()
    evt["totally_unexpected_field"] = "should be rejected"
    r = httpx.post(f"{provisioned_elastic}/mirage-telemetry-endpoint/_doc", json=evt)
    assert r.status_code == 400
    assert "strict_dynamic_mapping_exception" in r.text or "document_parsing_exception" in r.text


def test_ilm_policy_and_index_template_are_registered(provisioned_elastic: str):
    ilm = httpx.get(f"{provisioned_elastic}/_ilm/policy/mirage-telemetry-ilm-policy")
    assert ilm.status_code == 200
    policy = ilm.json()["mirage-telemetry-ilm-policy"]["policy"]
    assert policy["phases"]["delete"]["min_age"] == "7d"

    tmpl = httpx.get(f"{provisioned_elastic}/_index_template/mirage-telemetry-endpoint")
    assert tmpl.status_code == 200
