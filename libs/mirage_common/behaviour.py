"""Evidence-backed deterministic behaviour profiling and skill assessment."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from mirage_contracts.ulid import generate_ulid

SKILL_BANDS = ("UNKNOWN", "NOVICE", "INTERMEDIATE", "ADVANCED", "EXPERT")
IDENTITY_TERMS = frozenset({"name", "identity", "nationality", "gender", "age", "person"})
SIGNAL_SCORES = {
    "COMMAND_SYNTAX_ERROR": -2.0,
    "REPEATED_BASIC_ERROR": -2.0,
    "FAILED_WITHOUT_RECOVERY": -1.0,
    "COMMAND_SYNTAX_ACCURATE": 1.0,
    "ERROR_RECOVERY": 2.0,
    "TOOL_CHAINING": 2.0,
    "DISCOVERY_BREADTH": 1.5,
    "PRIVILEGE_AWARENESS": 2.0,
    "OPSEC_BEHAVIOUR": 2.0,
    "SANDBOX_DETECTION_ATTEMPT": 2.0,
    "NATIVE_TOOL_PROFICIENCY": 1.5,
    "AUTOMATED_FRAMEWORK_USE": 1.5,
    "PERSISTENCE_ATTEMPT": 1.0,
}


@dataclass(frozen=True)
class BehaviourEvent:
    event_id: str
    case_id: str
    session_id: str
    category: str
    behaviour_type: str
    event_time: datetime
    summary: str
    confidence: float
    evidence_strength: float
    attributes: dict[str, Any]


@dataclass(frozen=True)
class BehaviourObservation:
    observation_id: str
    event: BehaviourEvent


@dataclass(frozen=True)
class SkillAssessment:
    band: str
    confidence: float
    supporting_event_ids: tuple[str, ...]
    contradictory_event_ids: tuple[str, ...]
    uncertainties: tuple[str, ...]
    profile_version: int
    last_updated: datetime
    summary: str


def normalise_behaviour_event(raw: dict[str, Any]) -> BehaviourEvent:
    attrs = dict(raw.get("attributes") or {})
    if any(term in key.lower() for key in attrs for term in IDENTITY_TERMS):
        attrs = {
            key: value
            for key, value in attrs.items()
            if not any(term in key.lower() for term in IDENTITY_TERMS)
        }
    summary = str(raw.get("summary", ""))[:512]
    return BehaviourEvent(
        event_id=str(raw["event_id"]),
        case_id=str(raw["case_id"]),
        session_id=str(raw["session_id"]),
        category=str(raw["category"]),
        behaviour_type=str(raw["behaviour_type"]),
        event_time=raw["event_time"],
        summary=summary,
        confidence=max(0.0, min(float(raw.get("confidence", 1.0)), 1.0)),
        evidence_strength=max(0.0, min(float(raw.get("evidence_strength", 1.0)), 1.0)),
        attributes=attrs,
    )


def _band_for(score: float, count: int) -> str:
    if count < 3:
        return "UNKNOWN"
    if score < -0.25:
        return "NOVICE"
    if score < 0.75:
        return "INTERMEDIATE"
    if score < 1.5:
        return "ADVANCED"
    return "EXPERT"


def assess_skill(
    events: list[BehaviourEvent],
    *,
    as_of: datetime | None = None,
    profile_version: int = 1,
) -> SkillAssessment:
    as_of = as_of or datetime.now(UTC)
    ordered = sorted(events, key=lambda event: (event.event_time, event.event_id))
    scored: list[tuple[float, BehaviourEvent]] = []
    for event in ordered:
        base = SIGNAL_SCORES.get(event.behaviour_type, 0.0)
        age_days = max(0.0, (as_of - event.event_time).total_seconds() / 86400)
        decay = max(0.25, 1.0 - age_days / 90.0)
        weighted = base * event.confidence * event.evidence_strength * decay
        if weighted:
            scored.append((weighted, event))
    denominator = sum(abs(value) for value, _ in scored) or 1.0
    score = sum(value for value, _ in scored) / max(1.0, len(scored))
    confidence = min(0.98, denominator / (denominator + 4.0))
    if len(scored) < 3:
        confidence = min(confidence, 0.35)
    band = _band_for(score, len(scored))
    positives = sorted(
        ((value, event) for value, event in scored if value > 0),
        key=lambda item: (-item[0], item[1].event_time, item[1].event_id),
    )
    negatives = sorted(
        ((value, event) for value, event in scored if value < 0),
        key=lambda item: (item[0], item[1].event_time, item[1].event_id),
    )
    primary = positives if band in {"INTERMEDIATE", "ADVANCED", "EXPERT"} else negatives
    supporting = tuple(event.event_id for _, event in primary[:8])
    contradictory = tuple(
        event.event_id for _, event in (negatives if primary is positives else positives)[:8]
    )
    uncertainties: list[str] = []
    if len(scored) < 3:
        uncertainties.append("sparse evidence")
    if positives and negatives:
        uncertainties.append("contradictory operational indicators")
    if any(event.event_time > as_of for _, event in scored):
        uncertainties.append("future-dated telemetry excluded from temporal confidence")
    summary_data: dict[str, object] = {
        "scope": "operational skill only; no human identity inference",
        "band": band,
        "confidence": round(confidence, 4),
        "signals_observed": len(scored),
        "supporting_event_ids": list(supporting),
        "contradictory_event_ids": list(contradictory),
        "uncertainties": uncertainties,
    }
    summary = json.dumps(summary_data, sort_keys=True, separators=(",", ":"))
    contradictory_summary_ids = summary_data["contradictory_event_ids"]
    assert isinstance(contradictory_summary_ids, list)
    while len(summary.encode("utf-8")) > 2048 and contradictory_summary_ids:
        contradictory_summary_ids.pop()
        summary = json.dumps(summary_data, sort_keys=True, separators=(",", ":"))
    return SkillAssessment(
        band=band,
        confidence=confidence,
        supporting_event_ids=supporting,
        contradictory_event_ids=contradictory,
        uncertainties=tuple(uncertainties),
        profile_version=profile_version,
        last_updated=as_of,
        summary=summary,
    )


async def update_profile(
    conn: psycopg.AsyncConnection,
    *,
    events: list[BehaviourEvent],
    as_of: datetime | None = None,
) -> SkillAssessment:
    if not events:
        raise ValueError("at least one behaviour event is required")
    case_id, session_id = events[0].case_id, events[0].session_id
    if any(event.case_id != case_id or event.session_id != session_id for event in events):
        raise ValueError("one profile update cannot mix cases or sessions")
    async with conn.cursor() as cur:
        for event in sorted(events, key=lambda item: (item.event_time, item.event_id)):
            await cur.execute(
                """
                INSERT INTO behaviour_observations (
                    observation_id,case_id,session_id,category,behaviour_type,
                    event_time,source_event_ids,confidence,evidence_strength,
                    summary,attributes
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (observation_id) DO NOTHING
                """,
                (
                    event.event_id,
                    case_id,
                    session_id,
                    event.category,
                    event.behaviour_type,
                    event.event_time,
                    Jsonb([event.event_id]),
                    event.confidence,
                    event.evidence_strength,
                    event.summary,
                    Jsonb(event.attributes),
                ),
            )
        await cur.execute(
            """
            SELECT observation_id,category,behaviour_type,event_time,summary,
                   confidence,evidence_strength,attributes
            FROM behaviour_observations
            WHERE case_id=%s AND session_id=%s ORDER BY event_time,observation_id
            """,
            (case_id, session_id),
        )
        all_rows = await cur.fetchall()
        await cur.execute(
            "SELECT COALESCE(profile_version,0) FROM behaviour_profiles WHERE case_id=%s AND session_id=%s",
            (case_id, session_id),
        )
        version_row = await cur.fetchone()
        version = (version_row[0] if version_row else 0) + 1
    effective = [
        BehaviourEvent(
            event_id=row[0],
            case_id=case_id,
            session_id=session_id,
            category=row[1],
            behaviour_type=row[2],
            event_time=row[3],
            summary=row[4],
            confidence=row[5],
            evidence_strength=row[6],
            attributes=row[7],
        )
        for row in all_rows
    ]
    assessment = assess_skill(effective, as_of=as_of, profile_version=version)
    assessment_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO behaviour_profiles
                (case_id,session_id,profile_version,summary,last_event_time,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (case_id,session_id) DO UPDATE SET
                profile_version=EXCLUDED.profile_version,summary=EXCLUDED.summary,
                last_event_time=EXCLUDED.last_event_time,updated_at=EXCLUDED.updated_at
            """,
            (
                case_id,
                session_id,
                version,
                assessment.summary,
                max(event.event_time for event in effective),
                assessment.last_updated,
            ),
        )
        await cur.execute(
            """
            INSERT INTO skill_assessments (
                assessment_id,case_id,session_id,band,confidence,
                contradictory_event_ids,uncertainties,profile_version,last_updated
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                assessment_id,
                case_id,
                session_id,
                assessment.band,
                assessment.confidence,
                Jsonb(list(assessment.contradictory_event_ids)),
                Jsonb(list(assessment.uncertainties)),
                version,
                assessment.last_updated,
            ),
        )
        for ordinal, event_id in enumerate(assessment.supporting_event_ids):
            await cur.execute(
                "INSERT INTO skill_supporting_events (assessment_id,event_id,ordinal) VALUES (%s,%s,%s)",
                (assessment_id, event_id, ordinal),
            )
        await cur.execute(
            """
            INSERT INTO behaviour_summary_history
                (case_id,session_id,profile_version,summary,effective_event_ids)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (
                case_id,
                session_id,
                version,
                assessment.summary,
                Jsonb([event.event_id for event in effective]),
            ),
        )
    return assessment
