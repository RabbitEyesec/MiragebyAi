"""Stage 8 analyst directives and policy-gated direct messages."""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from mirage_common.subjects import subject_for_event_type
from mirage_contracts.envelope import build_event, validate_event
from mirage_contracts.ulid import generate_ulid

APPROVED_SURFACES = (
    "DECOY_WEB_CHAT",
    "DECOY_TERMINAL_BANNER",
    "CONTROLLED_DESKTOP_NOTIFICATION",
    "SCENARIO_SERVICE_RESPONSE",
)
DIRECTIVE_ROLES = frozenset({"investigator", "platform_admin"})
MESSAGE_ROLES = frozenset({"investigator", "platform_admin"})
UNSAFE_DIRECTIVE_PATTERNS = (
    r"(?i)(?:^|\s)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|bash|sh)\s+(?:/c|-c)\b",
    r"(?i)\b(?:run|execute)\s+(?:this\s+)?(?:shell\s+)?command\b",
    r"(?i)\b(?:reveal|show|print|send)\s+(?:the\s+)?(?:api[_ -]?key|secret|password|credential)",
    r"(?i)\boutside\s+(?:the\s+)?sandbox\b",
    r"(?i)\b(?:upload|exfiltrate)\b.*\bexternal",
)
SENSITIVE_PATTERNS = (
    r"(?i)\bpassword\b|\bcredential\b|\bapi[_ -]?key\b",
    r"(?i)\blegal\b|\blaw enforcement\b",
    r"(?i)\b(?:you are|we identified)\b",
    r"(?i)\b(?:disable|shutdown|terminate)\s+(?:service|session)\b",
    r"(?i)\b(?:session|investigation)\s+(?:is\s+)?concluded\b",
)


class AnalystChannelError(Exception):
    pass


def validate_objective(objective: str) -> str:
    objective = objective.strip()
    if not objective:
        raise AnalystChannelError("objective is required")
    if len(objective.encode("utf-8")) > 512:
        raise AnalystChannelError("objective exceeds 512 bytes")
    if any(re.search(pattern, objective) for pattern in UNSAFE_DIRECTIVE_PATTERNS):
        raise AnalystChannelError("objective contains a prohibited command, secret, or scope request")
    return objective


@dataclass(frozen=True)
class Directive:
    directive_id: str
    case_id: str
    session_id: str | None
    objective: str
    priority: str
    status: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None
    idempotency_key: str


async def submit_directive(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    session_id: str | None,
    objective: str,
    priority: str,
    created_by: str,
    expires_at: datetime | None,
    idempotency_key: str,
) -> Directive:
    objective = validate_objective(objective)
    if priority not in {"LOW", "NORMAL", "HIGH", "URGENT"}:
        raise AnalystChannelError("invalid priority")
    now = datetime.now(UTC)
    if expires_at is not None and expires_at <= now:
        raise AnalystChannelError("directive is already expired")
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT directive_id,session_id,objective,priority,status,created_by,created_at,expires_at
            FROM analyst_directives WHERE case_id=%s AND idempotency_key=%s
            """,
            (case_id, idempotency_key),
        )
        existing = await cur.fetchone()
        if existing:
            return Directive(
                existing[0],
                case_id,
                existing[1],
                existing[2],
                existing[3],
                existing[4],
                existing[5],
                existing[6],
                existing[7],
                idempotency_key,
            )
        await cur.execute("SELECT 1 FROM cases WHERE case_id=%s", (case_id,))
        if await cur.fetchone() is None:
            raise AnalystChannelError("unknown case")
        directive_id = generate_ulid()
        await cur.execute(
            """
            INSERT INTO analyst_directives (
                directive_id,case_id,session_id,objective,priority,status,
                created_by,created_at,expires_at,idempotency_key
            ) VALUES (%s,%s,%s,%s,%s,'SUBMITTED',%s,%s,%s,%s)
            """,
            (
                directive_id,
                case_id,
                session_id,
                objective,
                priority,
                created_by,
                now,
                expires_at,
                idempotency_key,
            ),
        )
        await cur.execute(
            """
            INSERT INTO audit_events
                (actor,actor_type,action,target,outcome,correlation_id,detail)
            VALUES (%s,'ANALYST','analyst.directive.submitted',%s,'SUCCESS',%s,%s)
            """,
            (created_by, directive_id, directive_id, objective),
        )
        event = build_event(
            event_type="analyst.directive",
            schema_version="1.0",
            payload={
                "directive_id": directive_id,
                "case_id": case_id,
                "objective": objective,
                "priority": priority,
                "status": "SUBMITTED",
                "created_by": created_by,
                "expires_at": expires_at.isoformat().replace("+00:00", "Z")
                if expires_at
                else None,
            },
            source_id="mirage-api.analyst",
            sequence=0,
            actor_type="ANALYST",
            classification="INTERNAL",
            case_id=case_id,
            session_id=session_id,
        )
        validated = validate_event(event)
        await cur.execute(
            "INSERT INTO outbox_events (event_id,topic,payload) VALUES (%s,%s,%s)",
            (event["event_id"], subject_for_event_type("analyst.directive"), Jsonb(validated.envelope)),
        )
    return Directive(
        directive_id,
        case_id,
        session_id,
        objective,
        priority,
        "SUBMITTED",
        created_by,
        now,
        expires_at,
        idempotency_key,
    )


async def cancel_directive(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    directive_id: str,
    actor: str,
) -> str:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE analyst_directives SET status='CANCELLED'
            WHERE case_id=%s AND directive_id=%s
              AND status IN ('SUBMITTED','ACKNOWLEDGED','QUEUED')
            RETURNING status
            """,
            (case_id, directive_id),
        )
        row = await cur.fetchone()
        if row is None:
            raise AnalystChannelError("directive cannot be cancelled")
        await cur.execute(
            """
            INSERT INTO audit_events
                (actor,actor_type,action,target,outcome,correlation_id,detail)
            VALUES (%s,'ANALYST','analyst.directive.cancelled',%s,'SUCCESS',%s,'cancelled')
            """,
            (actor, directive_id, directive_id),
        )
    return row[0]


def preview_hash(*, case_id: str, surface: str, content: str) -> str:
    return hashlib.sha256(
        f"{case_id}\0{surface}\0{content}".encode()
    ).hexdigest()


def confirmation_required(content: str) -> bool:
    return any(re.search(pattern, content) for pattern in SENSITIVE_PATTERNS)


@dataclass
class SlidingWindowRateLimiter:
    limits: dict[str, int]
    window: timedelta = timedelta(minutes=1)
    _events: dict[tuple[str, str], deque[datetime]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._events = defaultdict(deque)

    def consume(self, *, dimensions: dict[str, str], now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        for dimension, value in dimensions.items():
            key = (dimension, value)
            queue = self._events[key]
            while queue and now - queue[0] >= self.window:
                queue.popleft()
            if len(queue) >= self.limits[dimension]:
                return False
        for dimension, value in dimensions.items():
            self._events[(dimension, value)].append(now)
        return True


@dataclass(frozen=True)
class MessagePreview:
    case_id: str
    surface: str
    content: str
    preview_hash: str
    confirmation_required: bool
    output_tag: str = "ANALYST_MESSAGE"


def preview_message(*, case_id: str, surface: str, content: str) -> MessagePreview:
    if surface not in APPROVED_SURFACES:
        raise AnalystChannelError("surface is not approved")
    content = content.strip()
    if not content or len(content.encode("utf-8")) > 2048:
        raise AnalystChannelError("message must be 1..2048 bytes")
    if re.search(r"(?i)(?:cmd(?:\.exe)?|powershell|/bin/(?:sh|bash)|subprocess|os\.system)", content):
        raise AnalystChannelError("arbitrary command content is prohibited")
    return MessagePreview(
        case_id,
        surface,
        content,
        preview_hash(case_id=case_id, surface=surface, content=content),
        confirmation_required(content),
    )


async def channel_disabled(conn: psycopg.AsyncConnection, *, case_id: str) -> bool:
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT bool_or(disabled) FROM analyst_channel_controls
            WHERE (scope='PLATFORM' AND case_id IS NULL)
               OR (scope='CASE' AND case_id=%s)
            """,
            (case_id,),
        )
        row = await cur.fetchone()
    return bool(row and row[0])


async def set_channel_control(
    conn: psycopg.AsyncConnection,
    *,
    scope: str,
    case_id: str | None,
    disabled: bool,
    changed_by: str,
    reason: str,
) -> None:
    if scope not in {"PLATFORM", "CASE"}:
        raise AnalystChannelError("invalid emergency-control scope")
    if (scope == "PLATFORM") != (case_id is None):
        raise AnalystChannelError("platform scope must omit case_id; case scope must include it")
    async with conn.cursor() as cur:
        if case_id is not None:
            await cur.execute("SELECT 1 FROM cases WHERE case_id=%s", (case_id,))
            if await cur.fetchone() is None:
                raise AnalystChannelError("unknown case")
        await cur.execute(
            """
            UPDATE analyst_channel_controls
            SET disabled=%s,changed_by=%s,reason=%s,changed_at=now()
            WHERE scope=%s AND case_id IS NOT DISTINCT FROM %s
            """,
            (disabled, changed_by, reason, scope, case_id),
        )
        if cur.rowcount == 0:
            await cur.execute(
                """
                INSERT INTO analyst_channel_controls
                    (scope,case_id,disabled,changed_by,reason,changed_at)
                VALUES (%s,%s,%s,%s,%s,now())
                """,
                (scope, case_id, disabled, changed_by, reason),
            )
        await cur.execute(
            """
            INSERT INTO audit_events
                (actor,actor_type,action,target,outcome,correlation_id,detail)
            VALUES (%s,'ANALYST',%s,%s,'SUCCESS',%s,%s)
            """,
            (
                changed_by,
                "analyst.channel.disabled" if disabled else "analyst.channel.enabled",
                case_id or "PLATFORM",
                generate_ulid(),
                reason,
            ),
        )


async def create_message(
    conn: psycopg.AsyncConnection,
    *,
    case_id: str,
    session_id: str | None,
    author_id: str,
    content: str,
    surface: str,
    supplied_preview_hash: str,
    policy_decision_id: str,
    idempotency_key: str,
) -> dict[str, Any]:
    preview = preview_message(case_id=case_id, surface=surface, content=content)
    if not session_id:
        raise AnalystChannelError("an active session_id is required")
    if not hmac_compare(preview.preview_hash, supplied_preview_hash):
        raise AnalystChannelError("preview hash mismatch")
    if await channel_disabled(conn, case_id=case_id):
        raise AnalystChannelError("analyst direct-message channel is disabled")
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT c.state,s.status
            FROM cases c
            JOIN sessions s ON s.case_id=c.case_id
            WHERE c.case_id=%s AND s.session_id=%s
            """,
            (case_id, session_id),
        )
        case_session = await cur.fetchone()
        if case_session is None or case_session[1] != "ACTIVE":
            raise AnalystChannelError("message requires an active session belonging to the case")
        if case_session[0] in {"CONCLUDING", "EXPORTED", "DESTROYED"}:
            raise AnalystChannelError("case state does not permit direct messages")
        await cur.execute(
            """
            SELECT decision FROM policy_decisions
            WHERE decision_id=%s AND case_id=%s
            """,
            (policy_decision_id, case_id),
        )
        policy = await cur.fetchone()
        if policy is None or policy[0] not in {"ALLOW", "REQUIRE_ANALYST_APPROVAL"}:
            raise AnalystChannelError("message policy decision does not permit delivery")
        await cur.execute(
            """
            SELECT message_id,status,confirmation_required,preview_hash
            FROM analyst_messages WHERE case_id=%s AND idempotency_key=%s
            """,
            (case_id, idempotency_key),
        )
        existing = await cur.fetchone()
        if existing:
            return {
                "message_id": existing[0],
                "status": existing[1],
                "confirmation_required": existing[2],
                "preview_hash": existing[3],
                "output_tag": "ANALYST_MESSAGE",
            }
        message_id = generate_ulid()
        requires_confirmation = (
            preview.confirmation_required or policy[0] == "REQUIRE_ANALYST_APPROVAL"
        )
        status = "PENDING_CONFIRMATION" if requires_confirmation else "APPROVED"
        await cur.execute(
            """
            INSERT INTO analyst_messages (
                message_id,case_id,session_id,author_id,content,surface,output_tag,
                preview_hash,confirmation_required,policy_decision_id,status,idempotency_key
            ) VALUES (%s,%s,%s,%s,%s,%s,'ANALYST_MESSAGE',%s,%s,%s,%s,%s)
            """,
            (
                message_id,
                case_id,
                session_id,
                author_id,
                preview.content,
                surface,
                preview.preview_hash,
                requires_confirmation,
                policy_decision_id,
                status,
                idempotency_key,
            ),
        )
        await cur.execute(
            """
            INSERT INTO audit_events
                (actor,actor_type,action,target,outcome,correlation_id,detail)
            VALUES (%s,'ANALYST','analyst.message.created',%s,'SUCCESS',%s,%s)
            """,
            (author_id, message_id, message_id, status),
        )
    return {
        "message_id": message_id,
        "status": status,
        "confirmation_required": requires_confirmation,
        "preview_hash": preview.preview_hash,
        "output_tag": "ANALYST_MESSAGE",
    }


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)
