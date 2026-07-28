from __future__ import annotations

from datetime import UTC, datetime

from mirage_common.dashboard import (
    EDGE_TYPES,
    NODE_TYPES,
    classify_event,
    event_to_records,
    safe_display_text,
    sanitise_display_metadata,
    stable_id,
)
from mirage_contracts.ulid import generate_ulid


def _event(**overrides):
    event_id = generate_ulid()
    case_id = generate_ulid()
    value = {
        "event_id": event_id,
        "event_type": "ai.proposal",
        "schema_version": "1.0",
        "event_time": datetime.now(UTC).isoformat(),
        "ingest_time": datetime.now(UTC).isoformat(),
        "case_id": case_id,
        "session_id": None,
        "source_id": "mirage-worker",
        "sequence": 1,
        "actor_type": "SYSTEM",
        "classification": "INTERNAL",
        "payload": {
            "summary": "<script>alert('x')</script>",
            "confidence": 0.7,
            "evidence_id": generate_ulid(),
            "output_tag": "AI_GENERATED_INTERACTION",
        },
    }
    value.update(overrides)
    return value


def test_safe_display_text_escapes_and_truncates_hostile_content() -> None:
    escaped = safe_display_text("<img src=x onerror=alert(1)>", limit=20)
    assert "<" not in escaped
    assert escaped.endswith("…")
    assert len(escaped) == 20


def test_sanitise_metadata_bounds_nesting_and_array_size() -> None:
    result = sanitise_display_metadata(
        {"<unsafe>": ["<b>value</b>"] * 80, "deep": {"a": {"b": {"c": {"d": {"e": 1}}}}}}
    )
    assert "&lt;unsafe&gt;" in result
    assert len(result["&lt;unsafe&gt;"]) == 50
    assert "<b>" not in result["&lt;unsafe&gt;"][0]
    assert "[TRUNCATED]" in str(result)


def test_fact_correlation_inference_and_analyst_classification_are_distinct() -> None:
    assert classify_event("spider.observation") == "OBSERVED_FACT"
    assert classify_event("detection.raised") == "DETERMINISTIC_CORRELATION"
    assert classify_event("ai.proposal") == "AI_INFERENCE"
    assert classify_event("analyst.directive") == "ANALYST_ACTION"
    assert classify_event("case.state_changed") == "SYSTEM_ACTION"


def test_event_conversion_preserves_one_canonical_pivot_set() -> None:
    event = _event()
    timeline, node, edge = event_to_records(event, version=4)
    evidence_id = event["payload"]["evidence_id"]
    assert timeline["source_event_ids"] == node["source_event_ids"] == edge["source_event_ids"]
    assert (
        timeline["evidence_references"]
        == node["evidence_references"]
        == edge["evidence_references"]
        == [evidence_id]
    )
    assert timeline["classification"] == node["classification"] == edge["classification"]
    assert timeline["output_tag"] == node["output_tag"] == edge["output_tag"]
    assert node["node_type"] in NODE_TYPES
    assert edge["edge_type"] in EDGE_TYPES
    assert "<script>" not in node["label"]


def test_stable_ids_are_deterministic_and_order_sensitive() -> None:
    assert stable_id("node", "a", "b") == stable_id("node", "a", "b")
    assert stable_id("node", "a", "b") != stable_id("node", "b", "a")
