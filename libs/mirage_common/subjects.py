"""NATS JetStream stream/subject topology (spec Appendix D, Step 1b).

This is the single place that maps a Mirage `event_type` (dot-namespaced,
matches the JSON Schema filename convention in /schemas) to a concrete NATS
subject, and declares the six streams that own those subjects. Every
publisher (mirage-outbox-relay, agents via mirage-agent-ingestion, the
sandbox gateway) imports `subject_for_event_type` rather than hand-building
subject strings, so the mapping can never drift between services.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StreamDefinition:
    name: str
    subjects: list[str]
    max_age_seconds: int
    max_bytes: int
    num_replicas: int
    duplicate_window_seconds: int
    description: str


# Retry backoff: 5 attempts (spec: "after five failed consumer deliveries").
# Delays chosen so the dedup window (below) safely exceeds the worst-case
# cumulative retry horizon, satisfying §6.3 "the NATS dedup window exceeds
# the maximum retry horizon."
REDELIVERY_BACKOFF_SECONDS: list[float] = [1, 5, 25, 125, 625]
MAX_DELIVER_ATTEMPTS = 5
MAX_RETRY_HORIZON_SECONDS = sum(REDELIVERY_BACKOFF_SECONDS)  # 781s ≈ 13 minutes

# Dedup window generously exceeds MAX_RETRY_HORIZON_SECONDS for every stream
# that declares dedup (see Appendix D). Two hours is deliberately far beyond
# the ~13-minute worst case so redelivery jitter, consumer restarts, or a
# slow handler can never let a duplicate slip through as a "new" message.
DEDUP_WINDOW_SECONDS = 2 * 60 * 60

# NATS JetStream default cap on `duplicate_window` is bounded by the stream's
# `max_age` in some configurations — max_age must be >= DEDUP_WINDOW_SECONDS
# wherever dedup is declared, enforced by STREAM_DEFINITIONS below and a unit
# test (tests/unit/test_subjects.py).

STREAM_DEFINITIONS: dict[str, StreamDefinition] = {
    "MIRAGE_TELEMETRY": StreamDefinition(
        name="MIRAGE_TELEMETRY",
        # ">" already matches every token after the prefix, including
        # ".failed" dead-letter subjects — NATS subject syntax forbids ">"
        # followed by further tokens, so no separate ".failed" entry is
        # needed (or valid) here, unlike the literal-subject streams below.
        subjects=["telemetry.endpoint.>", "telemetry.sandbox.>"],
        max_age_seconds=24 * 60 * 60,
        max_bytes=2 * 1024 * 1024 * 1024,
        num_replicas=1,
        duplicate_window_seconds=DEDUP_WINDOW_SECONDS,
        description="Endpoint/sandbox telemetry (Sysmon/Spider events), 24h retention per Appendix D.",
    ),
    "MIRAGE_LIFECYCLE": StreamDefinition(
        name="MIRAGE_LIFECYCLE",
        subjects=["investigation.>", "steering.>"],
        max_age_seconds=30 * 24 * 60 * 60,
        max_bytes=1 * 1024 * 1024 * 1024,
        num_replicas=1,
        duplicate_window_seconds=DEDUP_WINDOW_SECONDS,
        description="Case/investigation lifecycle events and steering decisions.",
    ),
    "MIRAGE_ACTIONS": StreamDefinition(
        name="MIRAGE_ACTIONS",
        subjects=["ai.proposal", "ai.proposal.failed", "policy.decision", "policy.decision.failed", "sandbox.command", "sandbox.command.failed", "sandbox.result", "sandbox.result.failed"],
        max_age_seconds=30 * 24 * 60 * 60,
        max_bytes=1 * 1024 * 1024 * 1024,
        num_replicas=1,
        duplicate_window_seconds=DEDUP_WINDOW_SECONDS,
        description="AI proposals, policy decisions, sandbox commands + results.",
    ),
    "MIRAGE_EVIDENCE": StreamDefinition(
        name="MIRAGE_EVIDENCE",
        subjects=[
            "evidence.created", "evidence.created.failed",
            "evidence.verified", "evidence.verified.failed",
            "evidence.verification_failed", "evidence.verification_failed.failed",
            "canary.callback", "canary.callback.failed",
        ],
        max_age_seconds=30 * 24 * 60 * 60,
        max_bytes=512 * 1024 * 1024,
        num_replicas=1,
        duplicate_window_seconds=DEDUP_WINDOW_SECONDS,
        description="Evidence lifecycle and canary callbacks.",
    ),
    "MIRAGE_AUDIT": StreamDefinition(
        name="MIRAGE_AUDIT",
        subjects=["audit.>", "analyst.>"],
        max_age_seconds=365 * 24 * 60 * 60,
        max_bytes=1 * 1024 * 1024 * 1024,
        num_replicas=1,
        duplicate_window_seconds=DEDUP_WINDOW_SECONDS,
        description="Immutable audit trail — long retention (1 year) per Appendix D.",
    ),
    "MIRAGE_HEALTH": StreamDefinition(
        name="MIRAGE_HEALTH",
        subjects=["system.health", "system.health.failed", "agent.heartbeat", "agent.heartbeat.failed"],
        max_age_seconds=60 * 60,
        max_bytes=128 * 1024 * 1024,
        num_replicas=1,
        # Health/heartbeat traffic is high-frequency and low-value-per-message;
        # a short dedup window still exceeds the retry horizon without
        # needlessly holding a huge in-memory dedup index for a short-lived stream.
        duplicate_window_seconds=int(max(MAX_RETRY_HORIZON_SECONDS * 2, 30 * 60)),
        description="Agent heartbeats and system health — short retention per Appendix D.",
    ),
}


# event_type -> concrete NATS subject. Every event_type registered in
# /schemas MUST have an entry here (tests/unit/test_subjects.py enforces this).
EVENT_TYPE_SUBJECTS: dict[str, str] = {
    "agent.heartbeat": "agent.heartbeat",
    "agent.enrolled": "audit.agent.enrolled",
    "agent.enrollment_failed": "audit.agent.enrollment_failed",
    "agent.enrollment_revoked": "audit.agent.enrollment_revoked",
    "agent.certificate_renewed": "audit.agent.certificate_renewed",
    "case.created": "investigation.case.created",
    "case.state_changed": "investigation.case.state_changed",
    "detection.raised": "investigation.detection.raised",
    "steering.decision_recorded": "steering.decision_recorded",
    "sandbox.command_result": "sandbox.result",
    "audit.recorded": "audit.recorded",
    "system.health": "system.health",
    "spider.observation": "telemetry.sandbox.observation",
    # Tamper attempts are inherently security-relevant regardless of case
    # outcome, so they go straight to the immutable audit stream rather than
    # the short-retention telemetry stream (schemas/events/spider.tamper.v1).
    "spider.tamper": "audit.spider.tamper",
    "spider.fingerprint_snapshot": "telemetry.sandbox.fingerprint_snapshot",
    # Step 10's live gate decision — lifecycle-adjacent (gates a case
    # transition), not raw telemetry, so it goes on MIRAGE_LIFECYCLE
    # alongside case.state_changed/case.created rather than MIRAGE_TELEMETRY.
    "fingerprint.gate_evaluated": "investigation.fingerprint_gate_evaluated",
    "evidence.created": "evidence.created",
    "evidence.verified": "evidence.verified",
    "evidence.verification_failed": "evidence.verification_failed",
    "policy.decision": "policy.decision",
    "analyst.directive": "analyst.directive",
    "canary.callback": "canary.callback",
}

# command_type -> concrete NATS subject (MIRAGE_ACTIONS stream).
COMMAND_TYPE_SUBJECTS: dict[str, str] = {
    "sandbox.command": "sandbox.command",
}


def subject_for_event_type(event_type: str) -> str:
    try:
        return EVENT_TYPE_SUBJECTS[event_type]
    except KeyError as exc:
        raise ValueError(f"no NATS subject mapped for event_type={event_type!r}") from exc


def subject_for_command_type(command_type: str) -> str:
    try:
        return COMMAND_TYPE_SUBJECTS[command_type]
    except KeyError as exc:
        raise ValueError(f"no NATS subject mapped for command_type={command_type!r}") from exc


def failed_subject_for(subject: str) -> str:
    """Dead-letter subject for a given concrete (non-wildcard) subject."""
    return f"{subject}.failed"


def stream_for_subject(subject: str) -> str | None:
    """Best-effort reverse lookup: which stream a concrete subject belongs to."""
    for stream in STREAM_DEFINITIONS.values():
        for pattern in stream.subjects:
            if _subject_matches(pattern, subject):
                return stream.name
    return None


def _subject_matches(pattern: str, subject: str) -> bool:
    p_tokens = pattern.split(".")
    s_tokens = subject.split(".")
    for i, p in enumerate(p_tokens):
        if p == ">":
            return True
        if i >= len(s_tokens):
            return False
        if p == "*":
            continue
        if p != s_tokens[i]:
            return False
    return len(p_tokens) == len(s_tokens)
