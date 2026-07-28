-- Step 4b needs GET /api/v1/cases to query something real. This is
-- deliberately the MINIMAL "cases: Investigation aggregate" shape from
-- Appendix B (case_id, state, version, severity, owner, created_at) — Stage
-- 2 / Step 6 owns the FULL case lifecycle (case_state_transitions, the
-- allowed-transition table, optimistic-locking application logic, the
-- outbox, and the other dozen Stage 2 tables) and will ALTER this table
-- rather than replace it, exactly like migration 0001's `agents` table
-- pattern (Step 3 bootstrapped a minimal identity store; nothing since has
-- had to undo that decision).

CREATE TABLE cases (
    case_id     TEXT PRIMARY KEY,
    state       TEXT NOT NULL DEFAULT 'CREATED' CHECK (state IN (
        'CREATED', 'ARMED', 'MONITORING', 'STEERING_PENDING', 'SANDBOX_ACTIVE',
        'ENGAGING', 'CONCLUDING', 'EVIDENCE_VERIFYING', 'EXPORTED', 'DESTROYED'
    )),
    version     INTEGER NOT NULL DEFAULT 1,
    severity    TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    owner       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX cases_state_idx ON cases (state);
CREATE INDEX cases_created_at_idx ON cases (created_at DESC);
