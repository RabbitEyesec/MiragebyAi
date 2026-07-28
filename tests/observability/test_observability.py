from __future__ import annotations

from pathlib import Path

import yaml

from mirage_common.telemetry import (
    CORRELATION_FIELDS,
    METRIC_NAMES,
    core_metrics,
    safe_attributes,
)

ROOT = Path(__file__).resolve().parents[2]


def test_complete_metric_catalogue_is_instantiable() -> None:
    instruments = core_metrics()
    assert set(instruments) == set(METRIC_NAMES)
    assert len(METRIC_NAMES) == 40


def test_trace_attributes_keep_correlation_and_drop_sensitive_content() -> None:
    attributes = safe_attributes(
        {
            **{field: f"value-{field}" for field in CORRELATION_FIELDS},
            "operation": "report_generation",
            "password": "must-not-appear",
            "api_key": "must-not-appear",
            "prompt": "hostile prompt",
            "evidence_bytes": b"content",
            "random_high_cardinality": "drop",
        }
    )
    assert set(CORRELATION_FIELDS).issubset(attributes)
    assert "operation" in attributes
    assert "password" not in attributes
    assert "api_key" not in attributes
    assert "prompt" not in attributes
    assert "evidence_bytes" not in attributes
    assert "random_high_cardinality" not in attributes


def test_alert_thresholds_match_numeric_requirements() -> None:
    rules = yaml.safe_load((ROOT / "infra/otel/alert-rules.yaml").read_text())
    serialised = str(rules)
    for required in (
        "worker_heartbeat_age > 60",
        "agent_heartbeat_delay > 30",
        "agent_heartbeat_delay > 90",
        "nats_consumer_lag_messages > 10000",
        "nats_consumer_lag_seconds > 30",
        "clock_offset_seconds) > 5",
        "evidence_verification_failure",
        "s3_write_failure",
        "nats_dead_letter_total",
        "certificate_expiry_seconds",
        "dashboard_projection_lag",
        "policy_deny_total",
    ):
        assert required in serialised
    assert all(rule["for"] == "0s" for group in rules["groups"] for rule in group["rules"])


def test_collector_drops_sensitive_attributes_before_export() -> None:
    collector = yaml.safe_load((ROOT / "infra/otel/collector.yaml").read_text())
    actions = collector["processors"]["attributes/drop-sensitive"]["actions"]
    assert {item["key"] for item in actions} >= {
        "password",
        "secret",
        "credential",
        "api_key",
        "prompt",
        "evidence_bytes",
    }
    assert collector["service"]["pipelines"]["traces"]["processors"][1] == "attributes/drop-sensitive"
