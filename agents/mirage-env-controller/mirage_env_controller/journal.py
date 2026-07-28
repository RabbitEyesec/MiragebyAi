"""The Controller's local action journal (Appendix G: "Local state: Action
journal + rollback definitions"). A crash-consistent SQLite store, same
mechanics as `mirage_common.agent_queue.EncryptedEventQueue` (Step 4/5) but
keyed by action_id rather than an autoincrement queue position, and storing
a rollback DEFINITION per action rather than an outbound event — this is
what makes ROLLBACK_ACTION possible without a round trip back to the
gateway asking "what did you do."

Not encrypted: unlike Spider's telemetry queue (which holds observation
content worth protecting at rest), this journal holds only action
metadata + rollback instructions already derived from the command the
gateway sent in cleartext over the (TLS-protected) WSS channel — there is
no additional confidentiality requirement Appendix G calls out for it.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS journal_entries (
    action_id           TEXT PRIMARY KEY,
    action_type          TEXT NOT NULL,
    action_params          TEXT NOT NULL,
    rollback_definition     TEXT,
    status                   TEXT NOT NULL,
    recorded_at               TEXT NOT NULL
);
"""


class ActionJournal:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def record(
        self, *, action_id: str, action_type: str, action_params: dict, rollback_definition: dict | None,
        status: str, recorded_at: str,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO journal_entries "
            "(action_id, action_type, action_params, rollback_definition, status, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                action_id, action_type, json.dumps(action_params),
                json.dumps(rollback_definition) if rollback_definition is not None else None,
                status, recorded_at,
            ),
        )

    def get(self, action_id: str) -> dict | None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT action_id, action_type, action_params, rollback_definition, status, recorded_at "
                "FROM journal_entries WHERE action_id = ?",
                (action_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "action_id": row[0], "action_type": row[1], "action_params": json.loads(row[2]),
            "rollback_definition": json.loads(row[3]) if row[3] is not None else None,
            "status": row[4], "recorded_at": row[5],
        }

    def mark_status(self, action_id: str, status: str) -> None:
        self._conn.execute("UPDATE journal_entries SET status = ? WHERE action_id = ?", (status, action_id))
