CREATE TABLE case_reports (
    report_id TEXT PRIMARY KEY CHECK (report_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_id TEXT NOT NULL REFERENCES cases (case_id),
    export_id TEXT REFERENCES evidence_exports (export_id),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 256),
    export_mode TEXT NOT NULL
        CHECK (export_mode IN ('METADATA_ONLY','SELECTED_EVIDENCE','COMPLETE_CASE')),
    selected_evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    template_version TEXT NOT NULL,
    report_schema_version TEXT NOT NULL,
    generator_version TEXT NOT NULL,
    build_hash TEXT NOT NULL CHECK (build_hash ~ '^[0-9a-f]{40,64}$'),
    source_projection_version BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'QUEUED'
        CHECK (status IN (
            'QUEUED','WAITING_FOR_EXPORT','GENERATING','VERIFYING','COMPLETED',
            'CANCEL_REQUESTED','CANCELLED','FAILED'
        )),
    progress SMALLINT NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '15 minutes'),
    cancellation_requested_at TIMESTAMPTZ,
    retry_count SMALLINT NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 5),
    package_evidence_id TEXT REFERENCES evidence_objects (evidence_id),
    package_sha256 TEXT CHECK (package_sha256 IS NULL OR package_sha256 ~ '^[0-9a-f]{64}$'),
    verification_status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING','VERIFIED','FAILED')),
    verification_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    collection_gap_override JSONB,
    download_token_hash TEXT CHECK (
        download_token_hash IS NULL OR download_token_hash ~ '^[0-9a-f]{64}$'
    ),
    download_token_expires_at TIMESTAMPTZ,
    download_token_used_at TIMESTAMPTZ,
    error TEXT,
    UNIQUE (case_id, idempotency_key)
);
CREATE INDEX case_reports_case_created_idx
    ON case_reports (case_id, created_at DESC);
CREATE INDEX case_reports_worker_idx
    ON case_reports (status, created_at)
    WHERE status IN ('QUEUED','WAITING_FOR_EXPORT','CANCEL_REQUESTED');

CREATE TABLE report_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES case_reports (report_id),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
