-- Priority 2 remediation: idempotent replay for agent telemetry submission.
--
-- Without this table, mirage-agent-ingestion's only duplicate-detection
-- mechanism was `agents.last_sequence` — a plain "sequence must strictly
-- increase" check. That check has a real correctness gap: if an agent
-- durably persists an event server-side (commits, publishes, advances
-- last_sequence, returns 202) and then crashes before recording the
-- corresponding local ack, its next retry of that exact same event is
-- rejected with 409 forever (the sequence never becomes "next" again),
-- permanently wedging everything queued behind it. This table lets the
-- server recognize "I have already durably accepted this exact event" and
-- return the same successful acknowledgement instead of an error, which is
-- what makes retrying a locally-unacked-but-server-accepted event safe.

CREATE TABLE agent_telemetry_receipts (
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id),
    sequence    BIGINT NOT NULL,
    event_id    TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (agent_id, sequence)
);

-- An event_id must never be claimed by two different sequence numbers for
-- the same agent — that would mean the client reused an event_id, which
-- should never happen (build_event() generates a fresh ULID per event).
CREATE UNIQUE INDEX agent_telemetry_receipts_event_id_idx
    ON agent_telemetry_receipts (agent_id, event_id);
