"""Canonical Stage 9 dashboard projection and graph conversion.

The projection is deliberately rebuildable. Domain tables remain authoritative
for workflow state and Elasticsearch remains authoritative for searchable
telemetry; these compact rows exist only to serve authenticated analyst views.
"""
from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import psycopg
from psycopg.types.json import Jsonb

from mirage_contracts.ulid import generate_ulid

PROJECTOR_NAME = "dashboard-v1"
MAX_LABEL_LENGTH = 256
MAX_DESCRIPTION_LENGTH = 2048

NODE_TYPES = frozenset(
    {
        "CASE",
        "SESSION",
        "HOST",
        "USER",
        "PROCESS",
        "FILE",
        "DIRECTORY",
        "IP_ADDRESS",
        "NETWORK_CONNECTION",
        "ALERT",
        "DETECTION",
        "ARTIFACT",
        "CANARY_TOKEN",
        "CANARY_CALLBACK",
        "AI_SNAPSHOT",
        "AI_PROPOSAL",
        "POLICY_DECISION",
        "SANDBOX_ACTION",
        "ANALYST_DIRECTIVE",
        "ANALYST_MESSAGE",
        "EVIDENCE_OBJECT",
        "EXPORT",
        "CERTIFICATE",
        "AGENT",
    }
)
EDGE_TYPES = frozenset(
    {
        "OBSERVED_ON",
        "SPAWNED",
        "READ",
        "WROTE",
        "CREATED",
        "MOVED",
        "CONNECTED_TO",
        "AUTHENTICATED_AS",
        "TRIGGERED",
        "CORRELATED_WITH",
        "SUPPORTED_BY",
        "PROPOSED",
        "ALLOWED_BY",
        "DENIED_BY",
        "EXECUTED_AS",
        "CAUSED",
        "DEPLOYED_TO",
        "CALLBACK_FOR",
        "DIRECTED",
        "MESSAGED",
        "PRESERVED_AS",
        "INCLUDED_IN",
        "SIGNED_BY",
        "BELONGS_TO",
    }
)
OUTPUT_TAGS = frozenset(
    {
        "REAL_OS_OUTPUT",
        "DECOY_SERVICE_OUTPUT",
        "AI_GENERATED_INTERACTION",
        "ANALYST_MESSAGE",
        "UNTRUSTED_INTRUDER_OUTPUT",
    }
)
STATEMENT_CLASSIFICATIONS = frozenset(
    {
        "OBSERVED_FACT",
        "DETERMINISTIC_CORRELATION",
        "AI_INFERENCE",
        "ANALYST_ACTION",
        "SYSTEM_ACTION",
    }
)

EVENT_NODE_TYPES = {
    "case.created": "CASE",
    "case.state_changed": "CASE",
    "detection.raised": "DETECTION",
    "spider.observation": "PROCESS",
    "spider.fingerprint_snapshot": "HOST",
    "fingerprint.gate_evaluated": "HOST",
    "evidence.created": "EVIDENCE_OBJECT",
    "evidence.verified": "EVIDENCE_OBJECT",
    "evidence.verification_failed": "EVIDENCE_OBJECT",
    "ai.snapshot": "AI_SNAPSHOT",
    "ai.proposal": "AI_PROPOSAL",
    "policy.decision": "POLICY_DECISION",
    "sandbox.command_result": "SANDBOX_ACTION",
    "artifact.scanned": "ARTIFACT",
    "artifact.deployed": "ARTIFACT",
    "canary.callback": "CANARY_CALLBACK",
    "analyst.directive": "ANALYST_DIRECTIVE",
    "analyst.message": "ANALYST_MESSAGE",
    "evidence.exported": "EXPORT",
}


def safe_display_text(value: Any, *, limit: int = MAX_LABEL_LENGTH) -> str:
    """Escape and truncate content before it can become a graph label."""
    text = " ".join(str(value if value is not None else "").split())
    escaped = html.escape(text, quote=True)
    if len(escaped) <= limit:
        return escaped
    return escaped[: max(0, limit - 1)] + "…"


def sanitise_display_metadata(value: Any, *, depth: int = 0) -> Any:
    """Bound arbitrary display metadata without retaining hostile raw blobs."""
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            safe_display_text(key, limit=64): sanitise_display_metadata(item, depth=depth + 1)
            for key, item in list(value.items())[:50]
        }
    if isinstance(value, list):
        return [sanitise_display_metadata(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, str):
        return safe_display_text(value, limit=1024)
    if value is None or isinstance(value, bool | int | float):
        return value
    return safe_display_text(value, limit=1024)


def stable_id(kind: str, *parts: Any) -> str:
    material = "\x1f".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
    return f"{kind}:{digest}"


def classify_event(event_type: str, actor_type: str | None = None) -> str:
    lowered = event_type.lower()
    actor = (actor_type or "").upper()
    if lowered.startswith("ai."):
        return "AI_INFERENCE"
    if lowered.startswith("analyst.") or actor == "ANALYST":
        return "ANALYST_ACTION"
    if lowered.startswith(("detection.", "steering.", "fingerprint.", "policy.")):
        return "DETERMINISTIC_CORRELATION"
    if lowered.startswith(("spider.", "agent.", "canary.", "evidence.")):
        return "OBSERVED_FACT"
    return "SYSTEM_ACTION"


def node_type_for_event(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "spider.observation":
        observation_type = str(payload.get("observation_type", "")).upper()
        return {
            "PROCESS": "PROCESS",
            "FILE": "FILE",
            "DIRECTORY": "DIRECTORY",
            "NETWORK": "NETWORK_CONNECTION",
            "AUTHENTICATION": "USER",
        }.get(observation_type, "HOST")
    return EVENT_NODE_TYPES.get(event_type, "ALERT")


def event_to_records(event: dict[str, Any], *, version: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Convert one validated domain event into canonical timeline/node/edge rows."""
    event_id = str(event["event_id"])
    case_id = str(event["case_id"])
    event_type = str(event["event_type"])
    session_id = event.get("session_id")
    raw_payload = event.get("payload")
    payload: dict[str, Any] = (
        cast(dict[str, Any], raw_payload) if isinstance(raw_payload, dict) else {}
    )
    event_time = _as_datetime(event["event_time"])
    classification = classify_event(event_type, event.get("actor_type"))
    label_value = (
        payload.get("summary")
        or payload.get("reason")
        or payload.get("action_type")
        or payload.get("objective")
        or event_type.replace(".", " ").title()
    )
    label = safe_display_text(label_value)
    description = safe_display_text(payload.get("description", label_value), limit=MAX_DESCRIPTION_LENGTH)
    evidence_refs = _string_list(
        payload.get("evidence_ids")
        or ([payload["evidence_id"]] if payload.get("evidence_id") else [])
    )
    output_tag = payload.get("output_tag")
    if output_tag not in OUTPUT_TAGS:
        output_tag = None
    confidence = _confidence(payload.get("confidence"))
    source_ref = {
        "source_type": "DOMAIN_EVENT",
        "source_id": safe_display_text(event.get("source_id", "unknown"), limit=256),
        "source_sequence": int(event.get("sequence", 0)),
        "event_id": event_id,
    }
    node_id = stable_id("node", event_id)
    timeline = {
        "item_id": stable_id("timeline", event_id),
        "case_id": case_id,
        "session_id": session_id,
        "item_type": event_type,
        "classification": classification,
        "label": label,
        "description": description,
        "event_time": event_time,
        "source_event_ids": [event_id],
        "source_references": [source_ref],
        "evidence_references": evidence_refs,
        "confidence": confidence,
        "output_tag": output_tag,
        "display_metadata": sanitise_display_metadata(
            {
                "actor_type": event.get("actor_type"),
                "classification": event.get("classification"),
                "correlation_id": payload.get("correlation_id"),
            }
        ),
        "permissions": ["dashboard:read"],
        "version": version,
        "source_event_id": event_id,
    }
    node = {
        "node_id": node_id,
        "node_type": node_type_for_event(event_type, payload),
        "label": label,
        "case_id": case_id,
        "session_id": session_id,
        "event_time": event_time,
        "source_event_ids": [event_id],
        "source_references": [source_ref],
        "evidence_references": evidence_refs,
        "classification": classification,
        "confidence": confidence,
        "output_tag": output_tag,
        "display_metadata": sanitise_display_metadata({"event_type": event_type}),
        "permissions": ["dashboard:read"],
        "version": version,
    }
    edge: dict[str, Any] = {
        "edge_id": stable_id("edge", node_id, case_id, "BELONGS_TO"),
        "edge_type": "BELONGS_TO",
        "label": "belongs to case",
        "source_node_id": node_id,
        "target_node_id": case_node_id(case_id),
        "case_id": case_id,
        "session_id": session_id,
        "event_time": event_time,
        "source_event_ids": [event_id],
        "source_references": [source_ref],
        "evidence_references": evidence_refs,
        "classification": classification,
        "confidence": confidence,
        "output_tag": output_tag,
        "display_metadata": {},
        "permissions": ["dashboard:read"],
        "version": version,
    }
    return timeline, node, edge


def case_node_id(case_id: str) -> str:
    return f"case:{case_id}"


@dataclass(frozen=True)
class ProjectionResult:
    applied: bool
    duplicate: bool
    gap_detected: bool
    projection_version: int


class DashboardProjector:
    """Idempotent, gap-aware projector for compact real-time updates."""

    async def project_event(
        self,
        conn: psycopg.AsyncConnection,
        event: dict[str, Any],
    ) -> ProjectionResult:
        case_id = event.get("case_id")
        if not case_id:
            return ProjectionResult(False, False, False, 0)
        event_id = str(event["event_id"])
        sequence = int(event.get("sequence", 0))
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT projection_version FROM dashboard_projected_events
                WHERE projector_name=%s AND event_id=%s
                """,
                (PROJECTOR_NAME, event_id),
            )
            duplicate = await cur.fetchone()
            if duplicate:
                return ProjectionResult(False, True, False, int(duplicate[0]))
            await cur.execute(
                """
                INSERT INTO dashboard_projection_offsets
                    (projector_name,case_id)
                VALUES (%s,%s) ON CONFLICT DO NOTHING
                """,
                (PROJECTOR_NAME, case_id),
            )
            await cur.execute(
                """
                SELECT projection_version,last_source_sequence
                FROM dashboard_projection_offsets
                WHERE projector_name=%s AND case_id=%s FOR UPDATE
                """,
                (PROJECTOR_NAME, case_id),
            )
            offset = await cur.fetchone()
            if offset is None:
                raise RuntimeError("dashboard projection offset disappeared")
            version = int(offset[0]) + 1
            prior_sequence = int(offset[1])
            gap_detected = prior_sequence > 0 and sequence > prior_sequence + 1
            await self._upsert_summary(cur, case_id, version, event)
            await self._ensure_case_node(cur, case_id, version, event)
            timeline, node, edge = event_to_records(event, version=version)
            await self._upsert_timeline(cur, timeline)
            await self._upsert_node(cur, node)
            await self._upsert_edge(cur, edge)
            await cur.execute(
                """
                INSERT INTO dashboard_projected_events
                    (projector_name,event_id,case_id,source_sequence,projection_version)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (PROJECTOR_NAME, event_id, case_id, sequence, version),
            )
            await cur.execute(
                """
                UPDATE dashboard_projection_offsets SET
                    projection_version=%s,
                    last_source_sequence=GREATEST(last_source_sequence,%s),
                    last_event_id=%s,last_event_time=%s,
                    gap_detected=gap_detected OR %s,
                    gap_from=CASE WHEN %s THEN %s ELSE gap_from END,
                    gap_to=CASE WHEN %s THEN %s ELSE gap_to END,
                    updated_at=now()
                WHERE projector_name=%s AND case_id=%s
                """,
                (
                    version,
                    sequence,
                    event_id,
                    _as_datetime(event["event_time"]),
                    gap_detected,
                    gap_detected,
                    prior_sequence + 1,
                    gap_detected,
                    sequence - 1,
                    PROJECTOR_NAME,
                    case_id,
                ),
            )
            if gap_detected:
                await cur.execute(
                    """
                    UPDATE dashboard_case_summary SET
                        freshness_status='GAP_DETECTED',projected_at=now()
                    WHERE case_id=%s
                    """,
                    (case_id,),
                )
                await self._create_gap_notification(
                    cur,
                    case_id=case_id,
                    event_id=event_id,
                    gap_from=prior_sequence + 1,
                    gap_to=sequence - 1,
                    projection_version=version,
                )
            await self._publish_update(
                cur,
                update_type="TIMELINE_APPENDED",
                case_id=case_id,
                projection_version=version,
                event_time=_as_datetime(event["event_time"]),
                payload={"timeline_item": _jsonable(timeline), "graph_node": _jsonable(node)},
                correlation_id=str(
                    event.get("correlation_id")
                    or event.get("payload", {}).get("correlation_id")
                    or event_id
                ),
            )
        return ProjectionResult(True, False, gap_detected, version)

    async def rebuild_case(self, conn: psycopg.AsyncConnection, case_id: str) -> int:
        """Rebuild one case deterministically from authoritative domain rows."""
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM cases WHERE case_id=%s", (case_id,))
            if await cur.fetchone() is None:
                raise ValueError("case not found")
            await cur.execute(
                """
                INSERT INTO dashboard_projection_offsets
                    (projector_name,case_id)
                VALUES (%s,%s) ON CONFLICT DO NOTHING
                """,
                (PROJECTOR_NAME, case_id),
            )
            await cur.execute(
                """
                UPDATE dashboard_case_summary SET freshness_status='REBUILDING'
                WHERE case_id=%s
                """,
                (case_id,),
            )
            await cur.execute("DELETE FROM dashboard_graph_edges WHERE case_id=%s", (case_id,))
            await cur.execute("DELETE FROM dashboard_graph_nodes WHERE case_id=%s", (case_id,))
            await cur.execute("DELETE FROM dashboard_timeline_items WHERE case_id=%s", (case_id,))
            await cur.execute(
                "DELETE FROM dashboard_projected_events WHERE projector_name=%s AND case_id=%s",
                (PROJECTOR_NAME, case_id),
            )
            await cur.execute(
                """
                UPDATE dashboard_projection_offsets SET
                    last_source_sequence=0,last_event_id=NULL,last_event_time=NULL,
                    gap_detected=FALSE,gap_from=NULL,gap_to=NULL,updated_at=now()
                WHERE projector_name=%s AND case_id=%s
                """,
                (PROJECTOR_NAME, case_id),
            )
            await cur.execute(
                """
                SELECT event_id,payload FROM outbox_events
                WHERE payload->>'case_id'=%s
                ORDER BY created_at,event_id
                """,
                (case_id,),
            )
            events = [row[1] for row in await cur.fetchall() if isinstance(row[1], dict)]
        for event in events:
            if event.get("case_id") == case_id and event.get("event_id"):
                await self.project_event(conn, event)
        if not events:
            await self._project_authoritative_snapshot(conn, case_id)
        async with conn.cursor() as cur:
            await self._refresh_summary(cur, case_id)
            await cur.execute(
                """
                UPDATE dashboard_projection_offsets
                SET gap_detected=FALSE,gap_from=NULL,gap_to=NULL,updated_at=now()
                WHERE projector_name=%s AND case_id=%s
                RETURNING projection_version
                """,
                (PROJECTOR_NAME, case_id),
            )
            row = await cur.fetchone()
            version = int(row[0]) if row else 0
            await cur.execute(
                """
                UPDATE dashboard_case_summary SET
                    freshness_status='CURRENT',projected_at=now()
                WHERE case_id=%s
                """,
                (case_id,),
            )
            await self._publish_update(
                cur,
                update_type="CASE_UPDATED",
                case_id=case_id,
                projection_version=version,
                event_time=datetime.now(UTC),
                payload={"full_refresh": True},
                correlation_id=generate_ulid(),
            )
        return version

    async def rebuild_all(self, conn: psycopg.AsyncConnection) -> dict[str, int]:
        async with conn.cursor() as cur:
            await cur.execute("SELECT case_id FROM cases ORDER BY case_id")
            case_ids = [row[0] for row in await cur.fetchall()]
        return {case_id: await self.rebuild_case(conn, case_id) for case_id in case_ids}

    async def _project_authoritative_snapshot(
        self, conn: psycopg.AsyncConnection, case_id: str
    ) -> None:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT case_id,state,version,severity,owner,created_at
                FROM cases WHERE case_id=%s
                """,
                (case_id,),
            )
            case_row = await cur.fetchone()
            if case_row is None:
                raise ValueError("case not found")
            await cur.execute(
                """
                INSERT INTO dashboard_projection_offsets
                    (projector_name,case_id,projection_version)
                VALUES (%s,%s,1)
                ON CONFLICT (projector_name,case_id)
                DO UPDATE SET projection_version=dashboard_projection_offsets.projection_version+1
                RETURNING projection_version
                """,
                (PROJECTOR_NAME, case_id),
            )
            version_row = await cur.fetchone()
            if version_row is None:
                raise RuntimeError("dashboard projection offset update returned no row")
            version = int(version_row[0])
            await self._upsert_summary(
                cur,
                case_id,
                version,
                {"event_time": case_row[5], "event_id": case_id},
            )
            await self._ensure_case_node(
                cur,
                case_id,
                version,
                {"event_time": case_row[5], "event_id": case_id},
            )
            await cur.execute(
                """
                SELECT session_id,protocol,status,created_at
                FROM sessions WHERE case_id=%s ORDER BY created_at,session_id
                """,
                (case_id,),
            )
            sessions = await cur.fetchall()
            for session_id, protocol, status, created_at in sessions:
                await self._upsert_snapshot_entity(
                    cur,
                    case_id=case_id,
                    entity_id=session_id,
                    node_type="SESSION",
                    label=f"{protocol} session",
                    event_time=created_at,
                    version=version,
                    classification="OBSERVED_FACT",
                    metadata={"status": status, "protocol": protocol},
                    session_id=session_id,
                )
            await cur.execute(
                """
                SELECT evidence_id,evidence_type,acquisition_time,source_id,
                       source_sequence,related_event_ids,classification
                FROM evidence_objects WHERE case_id=%s
                ORDER BY acquisition_time,evidence_id
                """,
                (case_id,),
            )
            for row in await cur.fetchall():
                evidence_id, evidence_type, event_time, source_id, source_sequence, event_ids, classification = row
                await self._upsert_snapshot_entity(
                    cur,
                    case_id=case_id,
                    entity_id=evidence_id,
                    node_type="EVIDENCE_OBJECT",
                    label=f"{evidence_type} evidence",
                    event_time=event_time,
                    version=version,
                    classification="OBSERVED_FACT",
                    evidence_refs=[evidence_id],
                    source_event_ids=_string_list(event_ids),
                    metadata={
                        "source_id": source_id,
                        "source_sequence": source_sequence,
                        "evidence_classification": classification,
                    },
                )
            for table, id_column, node_type, label_column, time_column, classification in (
                ("ai_snapshots", "snapshot_id", "AI_SNAPSHOT", "snapshot_hash", "created_at", "AI_INFERENCE"),
                ("ai_proposals", "proposal_id", "AI_PROPOSAL", "action_type", "created_at", "AI_INFERENCE"),
                ("policy_decisions", "decision_id", "POLICY_DECISION", "decision", "created_at", "DETERMINISTIC_CORRELATION"),
                ("sandbox_actions", "action_id", "SANDBOX_ACTION", "action_type", "created_at", "SYSTEM_ACTION"),
                ("artifacts", "artifact_id", "ARTIFACT", "sanitised_filename", "created_at", "OBSERVED_FACT"),
                ("canary_tokens", "token_id", "CANARY_TOKEN", "status", "created_at", "SYSTEM_ACTION"),
                ("analyst_directives", "directive_id", "ANALYST_DIRECTIVE", "objective", "created_at", "ANALYST_ACTION"),
                ("analyst_messages", "message_id", "ANALYST_MESSAGE", "surface", "created_at", "ANALYST_ACTION"),
                ("evidence_exports", "export_id", "EXPORT", "verification_status", "created_at", "SYSTEM_ACTION"),
            ):
                await cur.execute(
                    f"""
                    SELECT {id_column},{label_column},{time_column}
                    FROM {table} WHERE case_id=%s
                    ORDER BY {time_column},{id_column}
                    """,
                    (case_id,),
                )
                for entity_id, label, event_time in await cur.fetchall():
                    await self._upsert_snapshot_entity(
                        cur,
                        case_id=case_id,
                        entity_id=entity_id,
                        node_type=node_type,
                        label=f"{node_type.replace('_', ' ').title()}: {label}",
                        event_time=event_time,
                        version=version,
                        classification=classification,
                        output_tag="ANALYST_MESSAGE" if node_type == "ANALYST_MESSAGE" else None,
                    )
            await cur.execute(
                """
                SELECT callback.callback_id,callback.classification,callback.callback_time
                FROM canary_callbacks callback
                JOIN canary_tokens token ON token.token_id=callback.token_id
                WHERE token.case_id=%s
                ORDER BY callback.callback_time,callback.callback_id
                """,
                (case_id,),
            )
            for entity_id, label, event_time in await cur.fetchall():
                await self._upsert_snapshot_entity(
                    cur,
                    case_id=case_id,
                    entity_id=entity_id,
                    node_type="CANARY_CALLBACK",
                    label=f"Canary Callback: {label}",
                    event_time=event_time,
                    version=version,
                    classification="OBSERVED_FACT",
                )

    async def _upsert_snapshot_entity(
        self,
        cur: psycopg.AsyncCursor[Any],
        *,
        case_id: str,
        entity_id: str,
        node_type: str,
        label: str,
        event_time: datetime,
        version: int,
        classification: str,
        metadata: dict[str, Any] | None = None,
        session_id: str | None = None,
        evidence_refs: list[str] | None = None,
        source_event_ids: list[str] | None = None,
        output_tag: str | None = None,
    ) -> None:
        node_id = f"{node_type.lower()}:{entity_id}"
        node = {
            "node_id": node_id,
            "node_type": node_type,
            "label": safe_display_text(label),
            "case_id": case_id,
            "session_id": session_id,
            "event_time": event_time,
            "source_event_ids": source_event_ids or [],
            "source_references": [{"source_type": "DOMAIN_ROW", "source_id": entity_id}],
            "evidence_references": evidence_refs or [],
            "classification": classification,
            "confidence": None,
            "output_tag": output_tag,
            "display_metadata": sanitise_display_metadata(metadata or {}),
            "permissions": ["dashboard:read"],
            "version": version,
        }
        await self._upsert_node(cur, node)
        edge: dict[str, Any] = {
            "edge_id": stable_id("edge", node_id, case_id, "BELONGS_TO"),
            "edge_type": "BELONGS_TO",
            "label": "belongs to case",
            "source_node_id": node_id,
            "target_node_id": case_node_id(case_id),
            "case_id": case_id,
            "session_id": session_id,
            "event_time": event_time,
            "source_event_ids": source_event_ids or [],
            "source_references": [{"source_type": "DOMAIN_ROW", "source_id": entity_id}],
            "evidence_references": evidence_refs or [],
            "classification": classification,
            "confidence": None,
            "output_tag": output_tag,
            "display_metadata": {},
            "permissions": ["dashboard:read"],
            "version": version,
        }
        await self._upsert_edge(cur, edge)
        timeline = {
            "item_id": stable_id("timeline", node_type, entity_id),
            "case_id": case_id,
            "session_id": session_id,
            "item_type": node_type,
            "classification": classification,
            "label": node["label"],
            "description": node["label"],
            "event_time": event_time,
            "source_event_ids": source_event_ids or [],
            "source_references": node["source_references"],
            "evidence_references": evidence_refs or [],
            "confidence": None,
            "output_tag": output_tag,
            "display_metadata": node["display_metadata"],
            "permissions": ["dashboard:read"],
            "version": version,
            "source_event_id": stable_id("source", node_type, entity_id),
        }
        await self._upsert_timeline(cur, timeline)

    async def _ensure_case_node(
        self,
        cur: psycopg.AsyncCursor[Any],
        case_id: str,
        version: int,
        event: dict[str, Any],
    ) -> None:
        event_time = _as_datetime(event.get("event_time", datetime.now(UTC)))
        await self._upsert_node(
            cur,
            {
                "node_id": case_node_id(case_id),
                "node_type": "CASE",
                "label": safe_display_text(f"Case {case_id}"),
                "case_id": case_id,
                "session_id": None,
                "event_time": event_time,
                "source_event_ids": _string_list([event.get("event_id")]),
                "source_references": [{"source_type": "CASE", "source_id": case_id}],
                "evidence_references": [],
                "classification": "SYSTEM_ACTION",
                "confidence": None,
                "output_tag": None,
                "display_metadata": {},
                "permissions": ["dashboard:read"],
                "version": version,
            },
        )

    async def _upsert_summary(
        self,
        cur: psycopg.AsyncCursor[Any],
        case_id: str,
        version: int,
        event: dict[str, Any],
    ) -> None:
        await cur.execute(
            """
            INSERT INTO dashboard_case_summary (
                case_id,projection_version,state,case_version,severity,owner,
                last_event_time,source_event_ids
            )
            SELECT case_id,%s,state,version,severity,owner,%s,%s
            FROM cases WHERE case_id=%s
            ON CONFLICT (case_id) DO UPDATE SET
                projection_version=EXCLUDED.projection_version,
                state=EXCLUDED.state,case_version=EXCLUDED.case_version,
                severity=EXCLUDED.severity,owner=EXCLUDED.owner,
                last_event_time=GREATEST(
                    dashboard_case_summary.last_event_time,EXCLUDED.last_event_time
                ),
                source_event_ids=(
                    SELECT jsonb_agg(DISTINCT value)
                    FROM jsonb_array_elements(
                        dashboard_case_summary.source_event_ids || EXCLUDED.source_event_ids
                    )
                ),
                projected_at=now()
            """,
            (
                version,
                _as_datetime(event["event_time"]),
                Jsonb([str(event["event_id"])]),
                case_id,
            ),
        )
        await self._refresh_summary(cur, case_id)

    async def _refresh_summary(self, cur: psycopg.AsyncCursor[Any], case_id: str) -> None:
        await cur.execute(
            """
            UPDATE dashboard_case_summary AS summary SET
                state=source.state,case_version=source.version,
                severity=source.severity,owner=source.owner,
                active_session_count=(
                    SELECT count(*) FROM sessions
                    WHERE case_id=summary.case_id AND status='ACTIVE'
                ),
                evidence_verified_count=(
                    SELECT count(*) FROM evidence_objects
                    WHERE case_id=summary.case_id AND verification_status='VERIFIED'
                ),
                evidence_total_count=(
                    SELECT count(*) FROM evidence_objects WHERE case_id=summary.case_id
                ),
                unresolved_gap_count=(
                    SELECT count(*) FROM evidence_collection_gaps
                    WHERE case_id=summary.case_id AND required AND resolved_at IS NULL
                ),
                export_eligible=(
                    NOT EXISTS (
                        SELECT 1 FROM evidence_objects
                        WHERE case_id=summary.case_id AND required_for_export
                          AND verification_status <> 'VERIFIED'
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM evidence_collection_gaps
                        WHERE case_id=summary.case_id AND required AND resolved_at IS NULL
                    )
                ),
                projected_at=now()
            FROM cases AS source
            WHERE summary.case_id=source.case_id AND summary.case_id=%s
            """,
            (case_id,),
        )

    async def _upsert_timeline(self, cur: psycopg.AsyncCursor[Any], item: dict[str, Any]) -> None:
        await cur.execute(
            """
            INSERT INTO dashboard_timeline_items (
                item_id,case_id,session_id,item_type,classification,label,
                description,event_time,source_event_ids,source_references,
                evidence_references,confidence,output_tag,display_metadata,
                permissions,version,source_event_id
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
            )
            ON CONFLICT (item_id) DO UPDATE SET
                label=EXCLUDED.label,description=EXCLUDED.description,
                evidence_references=EXCLUDED.evidence_references,
                display_metadata=EXCLUDED.display_metadata,
                permissions=EXCLUDED.permissions,version=EXCLUDED.version
            """,
            (
                item["item_id"],
                item["case_id"],
                item["session_id"],
                item["item_type"],
                item["classification"],
                item["label"],
                item["description"],
                item["event_time"],
                Jsonb(item["source_event_ids"]),
                Jsonb(item["source_references"]),
                Jsonb(item["evidence_references"]),
                item["confidence"],
                item["output_tag"],
                Jsonb(item["display_metadata"]),
                Jsonb(item["permissions"]),
                item["version"],
                item["source_event_id"],
            ),
        )

    async def _upsert_node(self, cur: psycopg.AsyncCursor[Any], node: dict[str, Any]) -> None:
        if node["node_type"] not in NODE_TYPES:
            raise ValueError(f"unsupported graph node type: {node['node_type']}")
        await cur.execute(
            """
            INSERT INTO dashboard_graph_nodes (
                node_id,node_type,label,case_id,session_id,event_time,
                source_event_ids,source_references,evidence_references,
                classification,confidence,output_tag,display_metadata,
                permissions,version
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (node_id) DO UPDATE SET
                label=EXCLUDED.label,event_time=EXCLUDED.event_time,
                source_event_ids=EXCLUDED.source_event_ids,
                source_references=EXCLUDED.source_references,
                evidence_references=EXCLUDED.evidence_references,
                classification=EXCLUDED.classification,
                confidence=EXCLUDED.confidence,output_tag=EXCLUDED.output_tag,
                display_metadata=EXCLUDED.display_metadata,
                permissions=EXCLUDED.permissions,version=EXCLUDED.version
            """,
            (
                node["node_id"],
                node["node_type"],
                node["label"],
                node["case_id"],
                node["session_id"],
                node["event_time"],
                Jsonb(node["source_event_ids"]),
                Jsonb(node["source_references"]),
                Jsonb(node["evidence_references"]),
                node["classification"],
                node["confidence"],
                node["output_tag"],
                Jsonb(node["display_metadata"]),
                Jsonb(node["permissions"]),
                node["version"],
            ),
        )

    async def _upsert_edge(self, cur: psycopg.AsyncCursor[Any], edge: dict[str, Any]) -> None:
        if edge["edge_type"] not in EDGE_TYPES:
            raise ValueError(f"unsupported graph edge type: {edge['edge_type']}")
        await cur.execute(
            """
            INSERT INTO dashboard_graph_edges (
                edge_id,edge_type,label,source_node_id,target_node_id,case_id,
                session_id,event_time,source_event_ids,source_references,
                evidence_references,classification,confidence,output_tag,
                display_metadata,permissions,version
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (edge_id) DO UPDATE SET
                label=EXCLUDED.label,event_time=EXCLUDED.event_time,
                evidence_references=EXCLUDED.evidence_references,
                display_metadata=EXCLUDED.display_metadata,
                permissions=EXCLUDED.permissions,version=EXCLUDED.version
            """,
            (
                edge["edge_id"],
                edge["edge_type"],
                edge["label"],
                edge["source_node_id"],
                edge["target_node_id"],
                edge["case_id"],
                edge["session_id"],
                edge["event_time"],
                Jsonb(edge["source_event_ids"]),
                Jsonb(edge["source_references"]),
                Jsonb(edge["evidence_references"]),
                edge["classification"],
                edge["confidence"],
                edge["output_tag"],
                Jsonb(edge["display_metadata"]),
                Jsonb(edge["permissions"]),
                edge["version"],
            ),
        )

    async def _create_gap_notification(
        self,
        cur: psycopg.AsyncCursor[Any],
        *,
        case_id: str,
        event_id: str,
        gap_from: int,
        gap_to: int,
        projection_version: int,
    ) -> None:
        notification_id = generate_ulid()
        await cur.execute(
            """
            INSERT INTO dashboard_notifications (
                notification_id,case_id,severity,category,title,detail,source_reference
            ) VALUES (%s,%s,'HIGH','PROJECTION_GAP','Dashboard projection gap',
                      %s,%s)
            """,
            (
                notification_id,
                case_id,
                f"Missing source sequences {gap_from} through {gap_to}; replay requested.",
                Jsonb({"event_id": event_id, "gap_from": gap_from, "gap_to": gap_to}),
            ),
        )
        await self._publish_update(
            cur,
            update_type="NOTIFICATION_CREATED",
            case_id=case_id,
            projection_version=projection_version,
            event_time=datetime.now(UTC),
            payload={"notification_id": notification_id, "gap_from": gap_from, "gap_to": gap_to},
            correlation_id=event_id,
        )

    async def _publish_update(
        self,
        cur: psycopg.AsyncCursor[Any],
        *,
        update_type: str,
        case_id: str | None,
        projection_version: int,
        event_time: datetime,
        payload: dict[str, Any],
        correlation_id: str,
        minimum_role: str | None = None,
    ) -> None:
        await cur.execute(
            """
            INSERT INTO dashboard_realtime_updates (
                update_id,update_type,case_id,projection_version,event_time,
                payload,correlation_id,minimum_role
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                generate_ulid(),
                update_type,
                case_id,
                projection_version,
                event_time,
                Jsonb(payload),
                correlation_id,
                minimum_role,
            ),
        )


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise ValueError("event_time must be an RFC3339 string or datetime")


def _confidence(value: Any) -> float | None:
    if value is None:
        return None
    number = float(value)
    return max(0.0, min(1.0, number))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None][:100]


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=lambda item: item.isoformat()))
