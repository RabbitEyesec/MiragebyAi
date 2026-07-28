-- Step 3: Trust, enrolment, rotation.
-- Certificate identity is stored in PostgreSQL (spec Step 3, item 9);
-- every event and acknowledgement is bound to certificate identity (item 10).
--
-- This is deliberately a MINIMAL early migration — the full Stage 2 / Step 6
-- schema (cases, sessions, routing_decisions, outbox_events, audit_events,
-- ...) lands in migration 0002+. agents/enrollment_tokens/certificate_history
-- exist now because Step 3 comes before Step 6 in the spec's build order and
-- needs its own durable identity store immediately.

CREATE TABLE enrollment_tokens (
    token_id            UUID PRIMARY KEY,           -- the minted JWT's `jti` claim
    role                TEXT NOT NULL CHECK (role IN ('ENDPOINT', 'SPIDER', 'ENV_CONTROLLER', 'BROKER_CLIENT', 'INTERNAL_CONTROL')),
    provisioner_name    TEXT NOT NULL,
    subject             TEXT NOT NULL,
    sans                TEXT[] NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    used_by_agent_id    TEXT,
    created_by          TEXT NOT NULL,

    CONSTRAINT enrollment_tokens_used_consistency
        CHECK ((used_at IS NULL AND used_by_agent_id IS NULL) OR (used_at IS NOT NULL AND used_by_agent_id IS NOT NULL))
);

-- The hot path for token consumption is exactly:
--   UPDATE enrollment_tokens SET used_at = now(), used_by_agent_id = $1
--   WHERE token_id = $2 AND used_at IS NULL AND expires_at > now();
-- A partial index on unused tokens keeps that fast as the table grows.
CREATE INDEX enrollment_tokens_unused_idx ON enrollment_tokens (token_id) WHERE used_at IS NULL;

CREATE TABLE agents (
    agent_id                TEXT PRIMARY KEY,
    role                    TEXT NOT NULL CHECK (role IN ('ENDPOINT', 'SPIDER', 'ENV_CONTROLLER', 'BROKER_CLIENT', 'INTERNAL_CONTROL')),
    certificate_profile     TEXT NOT NULL,
    certificate_serial      TEXT NOT NULL,
    certificate_not_after   TIMESTAMPTZ NOT NULL,
    build_hash              TEXT NOT NULL,
    host_fingerprint         TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
    enrolled_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at               TIMESTAMPTZ,
    revoked_reason           TEXT,
    last_seen_at              TIMESTAMPTZ,
    last_sequence             BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT agents_revoked_consistency
        CHECK ((status = 'ACTIVE' AND revoked_at IS NULL) OR (status = 'REVOKED' AND revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX agents_certificate_serial_idx ON agents (certificate_serial);
CREATE INDEX agents_status_idx ON agents (status);

CREATE TABLE certificate_history (
    id                     BIGSERIAL PRIMARY KEY,
    agent_id                TEXT NOT NULL REFERENCES agents (agent_id),
    certificate_serial      TEXT NOT NULL,
    action                 TEXT NOT NULL CHECK (action IN ('ISSUED', 'RENEWED', 'REVOKED')),
    at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail                  TEXT
);

CREATE INDEX certificate_history_agent_idx ON certificate_history (agent_id, at);

CREATE TABLE build_hash_allowlist (
    build_hash    TEXT PRIMARY KEY,
    role          TEXT NOT NULL CHECK (role IN ('ENDPOINT', 'SPIDER', 'ENV_CONTROLLER', 'BROKER_CLIENT', 'INTERNAL_CONTROL')),
    label         TEXT,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
