-- Prompt 2, Stages 5-8. PostgreSQL remains the sole owner of workflow,
-- metadata, verification, policy, artifact, canary, and analyst-channel state.
-- Evidence/artifact bytes are referenced by immutable object-store coordinates
-- and are never stored in these tables.

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY CHECK (session_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    protocol TEXT NOT NULL,
    broker_id TEXT,
    sandbox_id TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ
);
CREATE INDEX sessions_case_idx ON sessions (case_id, created_at);

CREATE TABLE evidence_objects (
    evidence_id TEXT PRIMARY KEY CHECK (evidence_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT REFERENCES sessions (session_id),
    evidence_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_sequence BIGINT NOT NULL CHECK (source_sequence >= 0),
    source_certificate_serial TEXT,
    related_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(related_event_ids) = 'array'),
    acquisition_time TIMESTAMPTZ NOT NULL,
    stored_time TIMESTAMPTZ NOT NULL,
    original_filename TEXT,
    media_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    s3_bucket TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    s3_version_id TEXT NOT NULL,
    object_lock_mode TEXT CHECK (object_lock_mode IN ('GOVERNANCE', 'COMPLIANCE')),
    retention_until TIMESTAMPTZ,
    verification_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'VERIFIED', 'FAILED', 'MISSING', 'HASH_MISMATCH')),
    verified_at TIMESTAMPTZ,
    verification_error TEXT,
    collection_method TEXT NOT NULL,
    classification TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata_json) = 'object'),
    required_for_export BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_id, source_sequence),
    UNIQUE (s3_bucket, s3_key, s3_version_id)
);
CREATE INDEX evidence_objects_case_idx ON evidence_objects (case_id);
CREATE INDEX evidence_objects_session_idx ON evidence_objects (session_id);
CREATE INDEX evidence_objects_source_sequence_idx ON evidence_objects (source_id, source_sequence);
CREATE INDEX evidence_objects_sha256_idx ON evidence_objects (sha256);
CREATE INDEX evidence_objects_verification_idx ON evidence_objects (verification_status);
CREATE INDEX evidence_objects_created_idx ON evidence_objects (created_at DESC);
CREATE INDEX evidence_objects_s3_key_idx ON evidence_objects (s3_key);
CREATE INDEX evidence_objects_related_events_idx ON evidence_objects USING gin (related_event_ids);

CREATE TABLE evidence_verification_history (
    verification_id TEXT PRIMARY KEY CHECK (verification_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    evidence_id TEXT NOT NULL REFERENCES evidence_objects (evidence_id),
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('VERIFIED', 'FAILED', 'MISSING', 'HASH_MISMATCH')),
    expected_sha256 TEXT NOT NULL,
    calculated_sha256 TEXT,
    error TEXT,
    requested_by TEXT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_verification_history_evidence_idx
    ON evidence_verification_history (evidence_id, attempted_at DESC);

CREATE TABLE trusted_timestamps (
    timestamp_id TEXT PRIMARY KEY CHECK (timestamp_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    source_type TEXT NOT NULL CHECK (source_type IN ('RFC3161', 'AWS_SIGNED_TIME', 'LOCAL_DEVELOPMENT')),
    source_name TEXT NOT NULL,
    timestamp_time TIMESTAMPTZ NOT NULL,
    token BYTEA,
    record_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    independently_trusted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence_exports (
    export_id TEXT PRIMARY KEY CHECK (export_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    export_version INTEGER NOT NULL CHECK (export_version > 0),
    manifest_version TEXT NOT NULL,
    manifest_sha256 TEXT CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    kms_key_arn TEXT,
    kms_signature BYTEA,
    signing_algorithm TEXT CHECK (signing_algorithm IS NULL OR signing_algorithm = 'RSASSA_PSS_SHA_256'),
    signed_at TIMESTAMPTZ,
    trusted_timestamp_id TEXT REFERENCES trusted_timestamps (timestamp_id),
    verification_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'VERIFIED', 'FAILED')),
    verification_error TEXT,
    export_evidence_id TEXT REFERENCES evidence_objects (evidence_id),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (case_id, export_version)
);
CREATE INDEX evidence_exports_case_idx ON evidence_exports (case_id, created_at DESC);

CREATE TABLE evidence_export_items (
    export_id TEXT NOT NULL REFERENCES evidence_exports (export_id),
    evidence_id TEXT NOT NULL REFERENCES evidence_objects (evidence_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    sha256_at_export TEXT NOT NULL CHECK (sha256_at_export ~ '^[0-9a-f]{64}$'),
    verification_id TEXT REFERENCES evidence_verification_history (verification_id),
    included_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (export_id, evidence_id),
    UNIQUE (export_id, ordinal)
);

CREATE TABLE evidence_collection_gaps (
    gap_id TEXT PRIMARY KEY CHECK (gap_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT REFERENCES sessions (session_id),
    evidence_type TEXT NOT NULL,
    source_id TEXT,
    sequence_from BIGINT,
    sequence_to BIGINT,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    reason TEXT NOT NULL,
    documented_by TEXT NOT NULL,
    resolved_at TIMESTAMPTZ,
    resolution TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_collection_gaps_case_idx
    ON evidence_collection_gaps (case_id, required, resolved_at);

CREATE TABLE behaviour_observations (
    observation_id TEXT PRIMARY KEY CHECK (observation_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    category TEXT NOT NULL,
    behaviour_type TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    source_event_ids JSONB NOT NULL CHECK (jsonb_typeof(source_event_ids) = 'array'),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    evidence_strength DOUBLE PRECISION NOT NULL CHECK (evidence_strength BETWEEN 0 AND 1),
    summary TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX behaviour_observations_case_session_idx
    ON behaviour_observations (case_id, session_id, event_time);

CREATE TABLE behaviour_profiles (
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    summary TEXT NOT NULL CHECK (octet_length(summary) <= 2048),
    last_event_time TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, session_id)
);

CREATE TABLE skill_assessments (
    assessment_id TEXT PRIMARY KEY CHECK (assessment_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    band TEXT NOT NULL CHECK (band IN ('UNKNOWN', 'NOVICE', 'INTERMEDIATE', 'ADVANCED', 'EXPERT')),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    contradictory_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    uncertainties JSONB NOT NULL DEFAULT '[]'::jsonb,
    profile_version INTEGER NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX skill_assessments_case_session_idx
    ON skill_assessments (case_id, session_id, last_updated DESC);

CREATE TABLE skill_supporting_events (
    assessment_id TEXT NOT NULL REFERENCES skill_assessments (assessment_id),
    event_id TEXT NOT NULL,
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 0 AND 7),
    PRIMARY KEY (assessment_id, event_id),
    UNIQUE (assessment_id, ordinal)
);

CREATE TABLE behaviour_summary_history (
    history_id BIGSERIAL PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    profile_version INTEGER NOT NULL,
    summary TEXT NOT NULL CHECK (octet_length(summary) <= 2048),
    effective_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, session_id, profile_version)
);

CREATE TABLE ai_snapshots (
    snapshot_id TEXT PRIMARY KEY CHECK (snapshot_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    snapshot_hash TEXT NOT NULL CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
    snapshot_size_bytes INTEGER NOT NULL CHECK (snapshot_size_bytes <= 16384),
    estimated_tokens INTEGER NOT NULL CHECK (estimated_tokens <= 4000),
    trimmed BOOLEAN NOT NULL,
    trimmed_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_profile_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_proposals (
    proposal_id TEXT PRIMARY KEY CHECK (proposal_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    schema_version TEXT NOT NULL CHECK (schema_version = '1.0'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    snapshot_id TEXT NOT NULL REFERENCES ai_snapshots (snapshot_id),
    strategy_phase TEXT NOT NULL CHECK (strategy_phase IN ('OBSERVE','PROFILE','ENGAGE','DEEPEN','VERIFY','CONTAIN','CONCLUDE')),
    action_type TEXT NOT NULL,
    params JSONB NOT NULL,
    rationale TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    supporting_event_ids JSONB NOT NULL,
    expected_effect TEXT NOT NULL,
    rollback_required BOOLEAN NOT NULL,
    policy_reference TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_decisions (
    decision_id TEXT PRIMARY KEY CHECK (decision_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    proposal_id TEXT REFERENCES ai_proposals (proposal_id),
    policy_version TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY','REQUIRE_ANALYST_APPROVAL','DEFER','FALLBACK')),
    reason_codes JSONB NOT NULL,
    constraints JSONB NOT NULL DEFAULT '{}'::jsonb,
    analyst_approval BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX policy_decisions_case_idx ON policy_decisions (case_id, created_at DESC);

CREATE TABLE strategy_phase_history (
    phase_change_id TEXT PRIMARY KEY CHECK (phase_change_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    from_phase TEXT,
    to_phase TEXT NOT NULL,
    reason TEXT NOT NULL,
    approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_usage (
    request_id TEXT PRIMARY KEY CHECK (request_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    estimated_cost_gbp NUMERIC(12,6) NOT NULL CHECK (estimated_cost_gbp >= 0),
    request_latency_ms INTEGER NOT NULL CHECK (request_latency_ms >= 0),
    success BOOLEAN NOT NULL,
    failure_type TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    snapshot_id TEXT REFERENCES ai_snapshots (snapshot_id),
    proposal_id TEXT REFERENCES ai_proposals (proposal_id),
    fallback_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ai_usage_budget_idx ON ai_usage (created_at, estimated_cost_gbp);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY CHECK (artifact_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT REFERENCES cases (case_id),
    original_filename TEXT NOT NULL,
    sanitised_filename TEXT NOT NULL,
    media_type TEXT NOT NULL,
    detected_type TEXT,
    size_bytes BIGINT NOT NULL CHECK (size_bytes BETWEEN 0 AND 262144000),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    scan_status TEXT NOT NULL CHECK (scan_status IN ('UPLOADED','QUARANTINED','SCANNING','CLEAN','SUSPICIOUS','MALICIOUS','UNSUPPORTED','FAILED','APPROVED','REJECTED')),
    clamav_result JSONB,
    yara_matches JSONB NOT NULL DEFAULT '[]'::jsonb,
    oletools_result JSONB,
    archive_metadata JSONB,
    quarantine_location TEXT NOT NULL,
    approved_for_deployment BOOLEAN NOT NULL DEFAULT FALSE,
    artifact_classification TEXT NOT NULL DEFAULT 'UNCLASSIFIED'
        CHECK (artifact_classification IN ('UNCLASSIFIED','INERT','CONTROLLED','PROHIBITED')),
    approval_reason TEXT,
    approved_by TEXT,
    observation_levels JSONB NOT NULL DEFAULT '[]'::jsonb,
    observation_required_adapters JSONB NOT NULL DEFAULT '[]'::jsonb,
    observation_limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
    observation_evidence_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    scanned_at TIMESTAMPTZ,
    deployed_at TIMESTAMPTZ,
    deployment_status TEXT
);
CREATE INDEX artifacts_case_idx ON artifacts (case_id, created_at DESC);
CREATE INDEX artifacts_sha256_idx ON artifacts (sha256);
CREATE INDEX artifacts_scan_status_idx ON artifacts (scan_status);

CREATE TABLE artifact_deployments (
    deployment_id TEXT PRIMARY KEY CHECK (deployment_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts (artifact_id),
    destination TEXT NOT NULL,
    download_url_expires_at TIMESTAMPTZ NOT NULL,
    download_token_hash TEXT NOT NULL CHECK (download_token_hash ~ '^[0-9a-f]{64}$'),
    download_consumed_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    expected_sha256 TEXT NOT NULL,
    observed_sha256 TEXT,
    sandbox_action_id TEXT,
    rollback_action_id TEXT,
    idempotency_key TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE (case_id, idempotency_key)
);

CREATE TABLE canary_tokens (
    token_id TEXT PRIMARY KEY CHECK (token_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    public_token_hash TEXT NOT NULL UNIQUE CHECK (public_token_hash ~ '^[0-9a-f]{64}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts (artifact_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    expected_usage TEXT NOT NULL CHECK (expected_usage IN ('ONE_TIME','REUSABLE')),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','USED','EXPIRED','REVOKED')),
    signing_version TEXT NOT NULL,
    classification_status TEXT NOT NULL DEFAULT 'PENDING'
);

CREATE TABLE infrastructure_sources (
    source_id TEXT PRIMARY KEY,
    cidr CIDR NOT NULL,
    category TEXT NOT NULL,
    environment TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    last_refreshed TIMESTAMPTZ NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    owner TEXT NOT NULL,
    trusted_proxy BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX infrastructure_sources_validity_idx
    ON infrastructure_sources (valid_from, valid_until);

CREATE TABLE canary_callbacks (
    callback_id TEXT PRIMARY KEY CHECK (callback_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    token_id TEXT NOT NULL REFERENCES canary_tokens (token_id),
    callback_time TIMESTAMPTZ NOT NULL,
    source_ip INET NOT NULL,
    forwarded_source_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    user_agent TEXT,
    request_path TEXT NOT NULL,
    referrer TEXT,
    http_method TEXT NOT NULL,
    tls_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    collector_request_id TEXT NOT NULL,
    event_signature TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('IN_SANDBOX_CALLBACK','SECURITY_SCANNER_CALLBACK','EXTERNAL_CALLBACK','UNKNOWN_SOURCE_CALLBACK')),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    network_indicator TEXT,
    uncertainty TEXT,
    rule_version TEXT NOT NULL,
    analyst_review_required BOOLEAN NOT NULL,
    evidence_id TEXT REFERENCES evidence_objects (evidence_id),
    replayed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (collector_request_id)
);

CREATE TABLE analyst_directives (
    directive_id TEXT PRIMARY KEY CHECK (directive_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT REFERENCES sessions (session_id),
    objective TEXT NOT NULL CHECK (octet_length(objective) <= 512),
    priority TEXT NOT NULL CHECK (priority IN ('LOW','NORMAL','HIGH','URGENT')),
    status TEXT NOT NULL CHECK (status IN ('SUBMITTED','ACKNOWLEDGED','QUEUED','APPLIED','REJECTED','EXPIRED','CANCELLED')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,
    linked_proposal_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    linked_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    idempotency_key TEXT NOT NULL,
    UNIQUE (case_id, idempotency_key)
);
CREATE INDEX analyst_directives_case_idx ON analyst_directives (case_id, created_at DESC);

CREATE TABLE analyst_channel_controls (
    control_id BIGSERIAL PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('PLATFORM','CASE')),
    case_id TEXT,
    disabled BOOLEAN NOT NULL,
    changed_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((scope = 'PLATFORM' AND case_id IS NULL) OR (scope = 'CASE' AND case_id IS NOT NULL))
);
CREATE UNIQUE INDEX analyst_channel_controls_scope_idx
    ON analyst_channel_controls (scope, COALESCE(case_id, ''));

CREATE TABLE analyst_messages (
    message_id TEXT PRIMARY KEY CHECK (message_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    session_id TEXT REFERENCES sessions (session_id),
    author_id TEXT NOT NULL,
    content TEXT NOT NULL CHECK (octet_length(content) <= 2048),
    surface TEXT NOT NULL CHECK (surface IN ('DECOY_WEB_CHAT','DECOY_TERMINAL_BANNER','CONTROLLED_DESKTOP_NOTIFICATION','SCENARIO_SERVICE_RESPONSE')),
    output_tag TEXT NOT NULL CHECK (output_tag = 'ANALYST_MESSAGE'),
    preview_hash TEXT NOT NULL CHECK (preview_hash ~ '^[0-9a-f]{64}$'),
    confirmation_required BOOLEAN NOT NULL,
    confirmed_at TIMESTAMPTZ,
    policy_decision_id TEXT REFERENCES policy_decisions (decision_id),
    status TEXT NOT NULL CHECK (status IN ('DRAFT','PREVIEWED','PENDING_CONFIRMATION','APPROVED','SENT','DELIVERED','FAILED','CANCELLED','BLOCKED')),
    delivered_at TIMESTAMPTZ,
    response_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_id TEXT REFERENCES evidence_objects (evidence_id),
    idempotency_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, idempotency_key)
);
CREATE INDEX analyst_messages_case_idx ON analyst_messages (case_id, created_at DESC);

-- Immutability guard: evidence ledger rows may be updated only for verification
-- and retention metadata; application roles receive no DELETE path.
CREATE FUNCTION forbid_evidence_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'evidence records are immutable and cannot be deleted';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER evidence_objects_no_delete
    BEFORE DELETE ON evidence_objects FOR EACH ROW EXECUTE FUNCTION forbid_evidence_delete();
