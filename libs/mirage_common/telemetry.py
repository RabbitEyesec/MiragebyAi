"""Secret-safe OpenTelemetry setup and Prompt 2 metric instruments."""
from __future__ import annotations

import contextlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

METRIC_NAMES = (
    "api_request_total",
    "api_request_latency",
    "api_error_total",
    "websocket_connection_count",
    "sse_connection_count",
    "realtime_update_latency",
    "nats_consumer_lag_messages",
    "nats_consumer_lag_seconds",
    "nats_redelivery_total",
    "nats_dead_letter_total",
    "outbox_pending_count",
    "outbox_oldest_age_seconds",
    "elastic_index_failure_total",
    "elastic_index_latency",
    "postgres_pool_active",
    "postgres_pool_wait",
    "postgres_transaction_failure",
    "agent_heartbeat_delay",
    "certificate_expiry_seconds",
    "sandbox_controller_latency",
    "sandbox_action_failure",
    "ai_request_latency",
    "ai_request_failure",
    "ai_timeout_total",
    "ai_fallback_total",
    "ai_estimated_cost_gbp",
    "policy_allow_total",
    "policy_deny_total",
    "artifact_scan_duration",
    "artifact_scan_failure",
    "evidence_verification_failure",
    "s3_write_failure",
    "report_generation_duration",
    "report_generation_failure",
    "canary_callback_total",
    "canary_external_total",
    "clock_offset_seconds",
    "worker_heartbeat_age",
    "dashboard_projection_lag",
    "teardown_failure_total",
)
CORRELATION_FIELDS = frozenset(
    {
        "correlation_id",
        "case_id",
        "session_id",
        "event_id",
        "action_id",
        "proposal_id",
        "policy_decision_id",
        "evidence_id",
        "artifact_id",
        "source_id",
        "actor_type",
    }
)
FORBIDDEN_ATTRIBUTE_FRAGMENTS = (
    "secret",
    "password",
    "credential",
    "api_key",
    "token",
    "prompt",
    "evidence_bytes",
    "hostile_content",
)


def configure_otel(*, service_name: str, endpoint: str, environment: str) -> None:
    """Configure OTLP/HTTP without attaching secrets or hostile content."""
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "mirage",
            "deployment.environment.name": environment,
        }
    )
    trace_provider = TracerProvider(resource=resource)
    trace_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
    )
    trace.set_tracer_provider(trace_provider)
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=f"{endpoint.rstrip('/')}/v1/metrics")
    )
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[metric_reader]))


@dataclass(frozen=True)
class AIMetrics:
    request_total: Any
    request_latency: Any
    request_failure: Any
    timeout_total: Any
    fallback_total: Any
    policy_allow: Any
    policy_deny: Any
    policy_require_approval: Any
    input_tokens: Any
    output_tokens: Any
    estimated_cost_gbp: Any
    snapshot_trim_total: Any
    circuit_breaker_state: Any


def ai_metrics() -> AIMetrics:
    meter = metrics.get_meter("mirage.ai")
    return AIMetrics(
        request_total=meter.create_counter("ai_request_total"),
        request_latency=meter.create_histogram("ai_request_latency", unit="ms"),
        request_failure=meter.create_counter("ai_request_failure"),
        timeout_total=meter.create_counter("ai_timeout_total"),
        fallback_total=meter.create_counter("ai_fallback_total"),
        policy_allow=meter.create_counter("ai_policy_allow"),
        policy_deny=meter.create_counter("ai_policy_deny"),
        policy_require_approval=meter.create_counter("ai_policy_require_approval"),
        input_tokens=meter.create_counter("ai_input_tokens"),
        output_tokens=meter.create_counter("ai_output_tokens"),
        estimated_cost_gbp=meter.create_counter("ai_estimated_cost_gbp", unit="GBP"),
        snapshot_trim_total=meter.create_counter("ai_snapshot_trim_total"),
        circuit_breaker_state=meter.create_up_down_counter("ai_circuit_breaker_state"),
    )


def evidence_meter():
    return metrics.get_meter("mirage.evidence")


def artifact_meter():
    return metrics.get_meter("mirage.artifacts")


def core_metrics() -> dict[str, Any]:
    """Create the complete stable instrument catalogue."""
    meter = metrics.get_meter("mirage.core")
    histograms = {
        name
        for name in METRIC_NAMES
        if name.endswith(("_latency", "_duration", "_seconds", "_wait", "_delay", "_lag"))
    }
    up_down = {
        "websocket_connection_count",
        "sse_connection_count",
        "postgres_pool_active",
        "outbox_pending_count",
        "nats_consumer_lag_messages",
    }
    result: dict[str, Any] = {}
    for name in METRIC_NAMES:
        if name in histograms:
            result[name] = meter.create_histogram(name)
        elif name in up_down:
            result[name] = meter.create_up_down_counter(name)
        else:
            result[name] = meter.create_counter(name)
    return result


def safe_attributes(values: Mapping[str, Any]) -> dict[str, str | int | float | bool]:
    """Allow only correlation identifiers and low-cardinality operational fields."""
    allowed = CORRELATION_FIELDS | {
        "component",
        "operation",
        "status",
        "result",
        "http.request.method",
        "http.route",
        "http.response.status_code",
        "messaging.destination.name",
    }
    safe: dict[str, str | int | float | bool] = {}
    for key, value in values.items():
        lowered = key.lower()
        if key not in allowed or any(fragment in lowered for fragment in FORBIDDEN_ATTRIBUTE_FRAGMENTS):
            continue
        if isinstance(value, str | int | float | bool):
            safe[key] = value if not isinstance(value, str) else value[:256]
    return safe


@contextlib.contextmanager
def traced_operation(
    name: str,
    *,
    attributes: Mapping[str, Any] | None = None,
) -> Iterator[Any]:
    with trace.get_tracer("mirage.core").start_as_current_span(
        name,
        attributes=safe_attributes(attributes or {}),
    ) as span:
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc, attributes={"exception.escaped": True})
            span.set_attribute("result", "ERROR")
            raise
