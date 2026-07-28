"""Encrypted local event queue + monotonic sequence store (Appendix G:
"Local state: Encrypted queue, sequence store"), shared by every Windows
agent (MirageEndpoint, MirageSpider — Step 4/Step 5) since the mechanics are
identical regardless of what the queued events contain. Backed by a single
SQLite file so both are crash-consistent with each other (one fsync'd commit
covers both an enqueued event and the sequence number it was assigned).

Event payload bytes are Fernet-encrypted before being written to disk; the
key comes from a KeyProvider (agent_keys.py) — DPAPI-protected on Windows, a
restrictive-permission file in development.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from cryptography.fernet import Fernet

from mirage_common.agent_keys import KeyProvider

# Queue row lifecycle (Priority 2's PENDING/IN_FLIGHT/ACKNOWLEDGED/RETRY/
# DEAD_LETTER state machine, adapted to this single-process local queue: a
# row is never "IN_FLIGHT" as durable state because only one flush loop ever
# drains this file at a time — a crash mid-send simply leaves it PENDING
# again, which is the correct and safe outcome for retry).
STATUS_PENDING = "PENDING"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_DEAD_LETTER = "DEAD_LETTER"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queue_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enqueued_at TEXT NOT NULL,
    encrypted_blob BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACKNOWLEDGED', 'DEAD_LETTER')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS queue_events_pending_idx ON queue_events (id) WHERE status = 'PENDING';

CREATE TABLE IF NOT EXISTS sequence_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO sequence_state (id, value) VALUES (1, 0);
"""

DEFAULT_MAX_QUEUE_SIZE = 100_000


class QueueCapacityExceeded(Exception):
    """Raised by enqueue() when the local queue is full of undelivered
    events — backpressure/disk-space protection, not a silent drop."""


class EncryptedEventQueue:
    """Not thread-safe across processes beyond SQLite's own locking; a single
    MirageEndpoint service instance owns one queue file at a time."""

    def __init__(
        self,
        db_path: Path,
        key_provider: KeyProvider,
        *,
        max_queue_size: int = DEFAULT_MAX_QUEUE_SIZE,
    ) -> None:
        self.db_path = db_path
        self.max_queue_size = max_queue_size
        self.recovered_from_corruption = False
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(key_provider.get_or_create_key())
        self._conn = self._open(db_path)

    def _open(self, db_path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            # A corrupt file can open() successfully but fail on first real
            # use — force a read now so corruption is caught here, not on
            # some later, harder-to-diagnose call.
            conn.execute("SELECT COUNT(*) FROM queue_events").fetchone()
        except sqlite3.DatabaseError:
            conn.close()
            quarantined = db_path.with_name(f"{db_path.name}.corrupt-{int(time.time())}")
            shutil.move(str(db_path), str(quarantined))
            for suffix in ("-wal", "-shm"):
                stray = db_path.with_name(db_path.name + suffix)
                if stray.exists():
                    stray.unlink()
            self.recovered_from_corruption = True
            conn = sqlite3.connect(str(db_path), isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
        return conn

    def close(self) -> None:
        self._conn.close()

    # --- Queue -------------------------------------------------------

    def enqueue(self, event: dict, *, enqueued_at: str) -> int:
        if self.pending_count() >= self.max_queue_size:
            raise QueueCapacityExceeded(
                f"local queue has reached its capacity of {self.max_queue_size} "
                "undelivered events; refusing to enqueue more until the "
                "backlog is delivered or dead-lettered"
            )
        blob = self._fernet.encrypt(json.dumps(event, separators=(",", ":")).encode("utf-8"))
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO queue_events (enqueued_at, encrypted_blob) VALUES (?, ?)",
                (enqueued_at, blob),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def peek_batch(self, limit: int = 100) -> list[tuple[int, dict]]:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT id, encrypted_blob FROM queue_events WHERE status = 'PENDING' ORDER BY id LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        return [(row_id, json.loads(self._fernet.decrypt(blob).decode("utf-8"))) for row_id, blob in rows]

    def ack(self, ids: list[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        self._conn.execute(  # noqa: S608 -- placeholders are '?' marks, not interpolated values
            f"UPDATE queue_events SET status = 'ACKNOWLEDGED' WHERE id IN ({placeholders})", ids
        )

    def record_attempt_failure(self, row_id: int, *, error: str) -> int:
        """Increments the attempt counter for a row that failed to send,
        without changing its status — it stays PENDING (i.e. RETRY-eligible)
        unless the caller separately calls dead_letter(). Returns the new
        attempt count so the caller can decide whether to give up."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "UPDATE queue_events SET attempts = attempts + 1, last_error = ? WHERE id = ? RETURNING attempts",
                (error, row_id),
            )
            return cur.fetchone()[0]

    def dead_letter(self, ids: list[int], *, error: str | None = None) -> None:
        """Moves rows out of the retry path permanently — for events the
        server has told us can never succeed (e.g. a structurally invalid
        event_type), not for transient/network failures. A dead-lettered
        event is never silently discarded: it remains on disk with its
        DEAD_LETTER status and last_error for operator inspection."""
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        if error is not None:
            self._conn.execute(  # noqa: S608
                f"UPDATE queue_events SET status = 'DEAD_LETTER', last_error = ? WHERE id IN ({placeholders})",
                [error, *ids],
            )
        else:
            self._conn.execute(  # noqa: S608
                f"UPDATE queue_events SET status = 'DEAD_LETTER' WHERE id IN ({placeholders})", ids
            )

    def dead_letter_count(self) -> int:
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT COUNT(*) FROM queue_events WHERE status = 'DEAD_LETTER'")
            return cur.fetchone()[0]

    def pending_count(self) -> int:
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT COUNT(*) FROM queue_events WHERE status = 'PENDING'")
            return cur.fetchone()[0]

    def vacuum_acked(self) -> None:
        """Reclaim space for already-acked rows. Called periodically, not on
        every ack, to avoid the I/O cost of VACUUM on the hot path. Dead
        letters are kept — they are not routine, self-cleaning state."""
        self._conn.execute("DELETE FROM queue_events WHERE status = 'ACKNOWLEDGED'")
        self._conn.execute("VACUUM")

    # --- Sequence ------------------------------------------------------

    def next_sequence(self) -> int:
        """Monotonic per certificate identity (Step 1 envelope contract),
        persisted so it survives a service restart without ever repeating or
        going backwards."""
        with closing(self._conn.cursor()) as cur:
            cur.execute("UPDATE sequence_state SET value = value + 1 WHERE id = 1 RETURNING value")
            return cur.fetchone()[0]

    def current_sequence(self) -> int:
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT value FROM sequence_state WHERE id = 1")
            return cur.fetchone()[0]
