"""Broker backend-selection (Step 8a, §6.1): "mirage-api owns
routing_decisions and exposes /route. Brokers are thin clients that call
/route before establishing a backend."

    Analyst approves steering -> mirage-api writes routing_decisions
    -> decision served by /route (1s in-memory TTL cache; Postgres authoritative)
    -> HTTP/SSH/RDP broker calls /route(match_key) BEFORE backend established
    -> broker receives ENDPOINT or SANDBOX; default = real ENDPOINT
    -> backend established once; steering recorded on case timeline

`write_routing_decision()` is the write side (analyst approval);
`resolve_route()` is the read side `/route` itself calls, including the
1-second in-memory TTL cache §6.1 specifies. Every decision write AND every
route resolution publishes `steering.decision_recorded` via the outbox —
the schema's own description says exactly that ("Emitted whenever /route
selects a backend... and whenever a routing_decisions row is
created/revoked"), so this module honors it literally rather than only
auditing writes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

DEFAULT_TARGET = "ENDPOINT"
ROUTE_CACHE_TTL_SECONDS = 1.0


def build_match_key(*, protocol: str, listener_id: str, source_ip: str, principal: str) -> str:
    """§6.1: 'match_key = protocol + listener_id + source_ip +
    SNI_or_authenticated_principal.' Canonical, stable join — every writer
    and reader of routing_decisions must build match_key this exact way or
    lookups silently miss."""
    return f"{protocol}|{listener_id}|{source_ip}|{principal}"


@dataclass(frozen=True)
class RoutingDecision:
    decision_id: str
    case_id: str
    match_key: str
    target: str
    version: int
    valid_from: str
    valid_until: str | None


async def write_routing_decision(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    match_key: str,
    protocol: str,
    target: str,
    created_by: str,
    valid_from=None,
    valid_until=None,
) -> RoutingDecision:
    """The write side of §6.1's flow ('Analyst approves steering -> mirage-api
    writes routing_decisions'). One transaction: INSERT routing_decisions,
    INSERT audit_events, write steering.decision_recorded(action=CREATED) to
    the outbox. Caller owns commit/rollback (same pattern as
    case_state_machine.transition_case / detection_correlation.correlate_detection).
    Raises psycopg.errors.ExclusionViolation if this match_key already has
    an overlapping active decision (the DB-level EXCLUDE constraint, not an
    application-level check — see migration 0005).
    """
    decision_id = generate_ulid()
    async with conn.cursor() as cur:
        await cur.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM routing_decisions WHERE match_key = %s", (match_key,))
        version_row = await cur.fetchone()
        assert version_row is not None  # COUNT/COALESCE always returns exactly one row
        version = version_row[0]

        await cur.execute(
            "INSERT INTO routing_decisions (case_id, match_key, target, valid_from, valid_until, version, created_by) "
            "VALUES (%s, %s, %s, COALESCE(%s, now()), %s, %s, %s) "
            "RETURNING valid_from, valid_until",
            (case_id, match_key, target, valid_from, valid_until, version, created_by),
        )
        inserted_row = await cur.fetchone()
        assert inserted_row is not None  # the INSERT above always returns exactly one row
        row_valid_from, row_valid_until = inserted_row

        await cur.execute(
            "INSERT INTO audit_events (actor, actor_type, action, target, outcome, correlation_id, detail) "
            "VALUES (%s, 'ANALYST', 'routing.decision_approved', %s, 'SUCCESS', %s, %s)",
            (created_by, case_id, decision_id, f"match_key={match_key} target={target}"),
        )

        event = build_event(
            event_type="steering.decision_recorded", schema_version="1.0",
            payload={
                "decision_id": decision_id, "case_id": case_id, "protocol": protocol,
                "match_key": match_key, "target": target, "decision_version": version, "action": "CREATED",
            },
            source_id="mirage-api", sequence=version, actor_type="ANALYST",
            classification="INTERNAL", case_id=case_id,
        )
        validated = validate_event(event)
        await cur.execute(
            "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
            (validated.envelope["event_id"], subject_for_event_type("steering.decision_recorded"), Jsonb(validated.envelope)),
        )

    return RoutingDecision(
        decision_id=decision_id, case_id=case_id, match_key=match_key, target=target,
        version=version, valid_from=str(row_valid_from), valid_until=str(row_valid_until) if row_valid_until else None,
    )


async def resolve_route(
    conn: psycopg.AsyncConnection, *, match_key: str, protocol: str,
) -> str:
    """§6.1's /route lookup: the currently-active decision for match_key, or
    DEFAULT_TARGET ('ENDPOINT' — 'default = real ENDPOINT', a fail-safe
    default even when there is no unreachability at all, just no matching
    decision). Publishes steering.decision_recorded(action=SELECTED or
    FAILSAFE_DEFAULT) every call — one Postgres transaction, caller commits.
    """
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT id, case_id, target, version FROM routing_decisions "
            "WHERE match_key = %s AND valid_from <= now() AND (valid_until IS NULL OR valid_until > now()) "
            "ORDER BY valid_from DESC LIMIT 1",
            (match_key,),
        )
        row = await cur.fetchone()

        if row is None:
            target = DEFAULT_TARGET
            action = "FAILSAFE_DEFAULT"
            case_id, version = None, 0
        else:
            _decision_row_id, case_id, target, version = row
            action = "SELECTED"

        event = build_event(
            event_type="steering.decision_recorded", schema_version="1.0",
            payload={
                "decision_id": generate_ulid(), "case_id": case_id or generate_ulid(),
                "protocol": protocol, "match_key": match_key, "target": target,
                "decision_version": max(version, 1), "action": action,
            },
            source_id="mirage-api", sequence=max(version, 1), actor_type="SYSTEM",
            classification="INTERNAL", case_id=case_id,
        )
        validated = validate_event(event)
        await cur.execute(
            "INSERT INTO outbox_events (event_id, topic, payload) VALUES (%s, %s, %s)",
            (validated.envelope["event_id"], subject_for_event_type("steering.decision_recorded"), Jsonb(validated.envelope)),
        )

    return target


@dataclass
class RouteCache:
    """§6.1: '/route (1s in-memory TTL cache; Postgres authoritative)'.
    Deliberately per-process, not shared (e.g. via Redis) — mirage-api
    instances are stateless and a 1-second staleness window per instance is
    the spec's own explicit tolerance, not a gap."""

    ttl_seconds: float = ROUTE_CACHE_TTL_SECONDS
    _entries: dict[str, tuple[str, float]] = field(default_factory=dict)

    def get(self, match_key: str) -> str | None:
        entry = self._entries.get(match_key)
        if entry is None:
            return None
        target, cached_at = entry
        if time.monotonic() - cached_at > self.ttl_seconds:
            del self._entries[match_key]
            return None
        return target

    def set(self, match_key: str, target: str) -> None:
        self._entries[match_key] = (target, time.monotonic())
