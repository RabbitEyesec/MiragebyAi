-- Step 9b: MirageEnvironmentController's backing tables (Appendix B).
-- "sandbox_instances: Disposable runtime state — sandbox_id, image_id,
-- state_version, network_identity" and "sandbox_actions: Command lifecycle
-- — action_id, expected_state_version, status, rollback_action_id."
--
-- state_version is the optimistic-concurrency guard the command envelope's
-- own expected_state_version field checks against (Appendix C) — same
-- pattern as cases.version (migration 0002/0003), applied here to a
-- sandbox instance instead of a case.

CREATE TABLE sandbox_instances (
    sandbox_id       TEXT PRIMARY KEY,
    case_id          TEXT NOT NULL REFERENCES cases (case_id),
    image_id         TEXT NOT NULL,
    state_version    INTEGER NOT NULL DEFAULT 0,
    network_identity TEXT,
    status           TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DESTROYED')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    destroyed_at     TIMESTAMPTZ,

    CONSTRAINT sandbox_instances_destroyed_at_consistent CHECK (
        (status = 'DESTROYED') = (destroyed_at IS NOT NULL)
    )
);

-- The fixed action set (Appendix I) plus the five Stage-4/Prompt-1
-- framework+safe-testing actions already reserved in
-- schemas/commands/sandbox.command.v1.schema.json's action_type enum —
-- kept in sync by hand since Postgres CHECK constraints can't reference a
-- JSON Schema file; tests/unit/test_sandbox_actions_shared.py asserts the
-- two lists match.
CREATE TABLE sandbox_actions (
    action_id               TEXT PRIMARY KEY CHECK (action_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    command_id               TEXT NOT NULL CHECK (command_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    sandbox_id                TEXT NOT NULL REFERENCES sandbox_instances (sandbox_id),
    case_id                   TEXT NOT NULL REFERENCES cases (case_id),
    action_type                TEXT NOT NULL CHECK (action_type IN (
        'PLACE_ARTIFACT', 'MOVE_ARTIFACT', 'CREATE_DECOY_DIRECTORY',
        'CHANGE_VISIBLE_METADATA', 'DISPLAY_MESSAGE',
        'ENABLE_DECOY_SERVICE', 'DISABLE_DECOY_SERVICE',
        'REQUEST_SNAPSHOT', 'ROLLBACK_ACTION', 'CONCLUDE_SESSION',
        'TEST_FILE_PLACEMENT', 'TEST_METADATA_UPDATE', 'SOFT_RESET', 'FULL_REBUILD', 'CLEAN_SHUTDOWN'
    )),
    action_params               JSONB NOT NULL DEFAULT '{}'::jsonb,
    expected_state_version        INTEGER NOT NULL,
    issued_by                     TEXT NOT NULL CHECK (issued_by IN ('AI', 'ANALYST', 'SYSTEM')),
    policy_decision_id             TEXT NOT NULL CHECK (policy_decision_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    status                          TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'SUCCESS', 'FAILED', 'REJECTED', 'TIMEOUT', 'ROLLED_BACK'
    )),
    output_tag                       TEXT CHECK (output_tag IN (
        'REAL_OS_OUTPUT', 'DECOY_SERVICE_OUTPUT', 'AI_GENERATED_INTERACTION', 'ANALYST_MESSAGE'
    )),
    rollback_action_id                TEXT REFERENCES sandbox_actions (action_id),
    error_detail                       TEXT,
    created_at                          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at                        TIMESTAMPTZ,

    CONSTRAINT sandbox_actions_completed_consistent CHECK (
        (status = 'PENDING') = (completed_at IS NULL)
    )
);

CREATE INDEX sandbox_actions_sandbox_idx ON sandbox_actions (sandbox_id, created_at);
CREATE INDEX sandbox_actions_case_idx ON sandbox_actions (case_id, created_at);
CREATE UNIQUE INDEX sandbox_actions_command_id_idx ON sandbox_actions (command_id);
