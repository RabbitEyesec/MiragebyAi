"""Detection-into-cases correlation (Step 7): "Consume detections; dedup;
correlate into one case; assign severity + confidence; publish
investigation.created via outbox. Adapter never steers. Case creation +
steering are operator-approved."

This module is the correlation DECISION (one Postgres transaction: dedup
check, correlate-or-create, outbox write) — `mirage_worker.detection_adapter`
owns the NATS consumer loop that calls it per message. Deliberately does not
call `mirage_common.case_state_machine.transition_case` for anything: a
newly-created case starts and stays in CREATED — advancing it (ARMED and
beyond) is operator-approved, out of this module's authority by design.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

DETECTION_ADAPTER_CONSUMER_NAME = "mirage-detection-adapter"


@dataclass(frozen=True)
class CorrelationResult:
    case_id: str
    created: bool  # True: a brand-new case was created. False: correlated into an existing one.
    already_processed: bool  # True: this exact detection_event_id was already handled (redelivery) — no new effect.


async def correlate_detection(
    conn: psycopg.AsyncConnection,
    *,
    detection_event_id: str,
    detector: str,
    signature_id: str,
    severity: str,
    confidence: float,
    correlation_key: str,
    source_ref: str,
) -> CorrelationResult:
    """One Postgres transaction. Caller owns commit/rollback (same pattern
    as case_state_machine.transition_case)."""
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT 1 FROM processed_events WHERE consumer_name = %s AND event_id = %s",
            (DETECTION_ADAPTER_CONSUMER_NAME, detection_event_id),
        )
        if await cur.fetchone() is not None:
            await cur.execute("SELECT case_id FROM cases WHERE correlation_key = %s", (correlation_key,))
            row = await cur.fetchone()
            # A prior run already correlated this exact detection; the case
            # it produced is looked up for the caller's benefit, not re-created.
            return CorrelationResult(case_id=row[0] if row else "", created=False, already_processed=True)

        await cur.execute("SELECT case_id FROM cases WHERE correlation_key = %s", (correlation_key,))
        existing = await cur.fetchone()

        if existing is not None:
            case_id = existing[0]
            created = False
            await cur.execute(
                "INSERT INTO audit_events (actor, actor_type, action, target, outcome, correlation_id, detail) "
                "VALUES (%s, 'SYSTEM', 'detection.correlated_to_existing_case', %s, 'SUCCESS', %s, %s)",
                (DETECTION_ADAPTER_CONSUMER_NAME, case_id, detection_event_id, f"{detector}:{signature_id} ({source_ref})"),
            )
        else:
            case_id = generate_ulid()
            created = True
            await cur.execute(
                "INSERT INTO cases (case_id, severity, correlation_key, owner) VALUES (%s, %s, %s, NULL)",
                (case_id, severity, correlation_key),
            )
            case_created_event = build_event(
                event_type="case.created", schema_version="1.0",
                payload={
                    "case_id": case_id, "severity": severity, "correlation_key": correlation_key,
                    "source_detection_ids": [detection_event_id], "initial_state": "CREATED",
                },
                source_id=DETECTION_ADAPTER_CONSUMER_NAME, sequence=1,
                actor_type="SYSTEM", classification="INTERNAL", case_id=case_id,
            )
            validated = validate_event(case_created_event)
            await cur.execute(
                "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
                (validated.envelope["event_id"], subject_for_event_type("case.created"), Jsonb(validated.envelope)),
            )
            await cur.execute(
                "INSERT INTO audit_events (actor, actor_type, action, target, outcome, correlation_id, detail) "
                "VALUES (%s, 'SYSTEM', 'case.created', %s, 'SUCCESS', %s, %s)",
                (DETECTION_ADAPTER_CONSUMER_NAME, case_id, detection_event_id, f"{detector}:{signature_id} confidence={confidence} ({source_ref})"),
            )

        await cur.execute(
            "INSERT INTO processed_events (consumer_name, event_id, result_hash) VALUES (%s, %s, %s)",
            (DETECTION_ADAPTER_CONSUMER_NAME, detection_event_id, case_id),
        )

    return CorrelationResult(case_id=case_id, created=created, already_processed=False)
