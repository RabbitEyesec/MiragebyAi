-- Step 6: the full case state machine + transactional outbox (Appendices B,
-- §6.3). Extends migration 0002's minimal `cases` table (Step 4b bootstrap)
-- rather than replacing it — same pattern migration 0001 established for
-- `agents` in Step 3.

ALTER TABLE cases ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Appendix C: case_id in the event envelope is a canonical uppercase ULID
-- (or null). Migration 0002 (Step 4b bootstrap) left case_id as a bare TEXT
-- PRIMARY KEY with no format constraint, which a real bug caught in Step 6
-- testing: transition_case() builds a case.state_changed envelope carrying
-- this case_id, and envelope validation rejects anything that isn't a real
-- ULID. Enforced here at the DB level so it can never regress again.
ALTER TABLE cases ADD CONSTRAINT cases_case_id_is_ulid CHECK (case_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$');

-- case_state_transitions: immutable lifecycle history (Appendix B). Every
-- application-level transition (mirage_common.case_state_machine) inserts
-- exactly one row here, in the same transaction as the cases.state UPDATE.
CREATE TABLE case_state_transitions (
    id              BIGSERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases (case_id),
    from_state      TEXT NOT NULL,
    to_state        TEXT NOT NULL,
    actor           TEXT NOT NULL,
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('ANALYST', 'AI', 'SYSTEM')),
    reason          TEXT NOT NULL,
    new_version     INTEGER NOT NULL,
    correlation_id  TEXT NOT NULL,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX case_state_transitions_case_idx ON case_state_transitions (case_id, at);

-- outbox_events: transactional publication (Appendix B, §6.3). Written in
-- the SAME transaction as the business state change it announces;
-- mirage-outbox-relay is the only writer of published_at/attempts/next_attempt_at.
CREATE TABLE outbox_events (
    event_id        TEXT PRIMARY KEY,
    topic           TEXT NOT NULL,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The relay's hot-path query (§6.3): unpublished, due, oldest-first.
CREATE INDEX outbox_events_pending_idx ON outbox_events (next_attempt_at) WHERE published_at IS NULL;

-- "Poll 250ms, woken by NOTIFY" (§6.3) — every insert wakes any relay
-- currently blocked in LISTEN, so the common case doesn't wait out the poll
-- interval; the poll loop remains the correctness backstop (a relay that
-- misses a NOTIFY while busy still picks the row up on its next poll).
CREATE FUNCTION notify_outbox_events() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('outbox_events_channel', NEW.event_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER outbox_events_notify_trigger
    AFTER INSERT ON outbox_events
    FOR EACH ROW EXECUTE FUNCTION notify_outbox_events();

-- processed_events: idempotency state (Appendix B, §6.3). Each consumer
-- writes one row per event_id it has durably applied, in the same
-- transaction as the state change that event caused — this is what makes
-- "delivery is at-least-once, business effect is once" true regardless of
-- NATS redelivery.
CREATE TABLE processed_events (
    consumer_name   TEXT NOT NULL,
    event_id        TEXT NOT NULL,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_hash     TEXT,

    PRIMARY KEY (consumer_name, event_id)
);

-- audit_events: immutable audit trail (Appendix B). Every state-changing
-- transaction writes a row here in the same transaction as the change
-- itself (Step 6's own rule) — this table is the durable source of truth;
-- schemas/events/audit.recorded.v1 is its outbox-published counterpart.
CREATE TABLE audit_events (
    id              BIGSERIAL PRIMARY KEY,
    actor           TEXT NOT NULL,
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('ANALYST', 'AI', 'SYSTEM', 'AGENT')),
    action          TEXT NOT NULL,
    target          TEXT NOT NULL,
    outcome         TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED')),
    correlation_id  TEXT NOT NULL,
    detail          TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_correlation_idx ON audit_events (correlation_id);
CREATE INDEX audit_events_at_idx ON audit_events (at DESC);
