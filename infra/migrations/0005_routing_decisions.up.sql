-- Step 8a: the /route decision API's backing table (Appendix B, §6.1).
-- "A unique constraint forbids two active decisions sharing one match_key
-- during overlapping validity" — enforced here as a real Postgres EXCLUDE
-- constraint (not just an application-level check), the standard way to
-- forbid overlapping time ranges per key.

CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE routing_decisions (
    id          BIGSERIAL PRIMARY KEY,
    case_id     TEXT NOT NULL REFERENCES cases (case_id),
    match_key   TEXT NOT NULL,
    target      TEXT NOT NULL CHECK (target IN ('ENDPOINT', 'SANDBOX')),
    valid_from  TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until TIMESTAMPTZ,  -- NULL = open-ended / still active
    version     INTEGER NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT routing_decisions_validity_order CHECK (valid_until IS NULL OR valid_until > valid_from),

    -- match_key equality + overlapping [valid_from, valid_until) ranges is
    -- forbidden. 'infinity' stands in for an open-ended (NULL) valid_until
    -- so the range comparison still works for still-active decisions.
    EXCLUDE USING gist (
        match_key WITH =,
        tstzrange(valid_from, COALESCE(valid_until, 'infinity'::timestamptz), '[)') WITH &&
    )
);

CREATE INDEX routing_decisions_match_key_idx ON routing_decisions (match_key, valid_from);
CREATE INDEX routing_decisions_case_idx ON routing_decisions (case_id, created_at);
