-- Stage 9 dashboard projections. These tables are compact, rebuildable views
-- only; PostgreSQL domain tables and Elasticsearch telemetry remain authoritative.

CREATE TABLE dashboard_case_summary (
    case_id TEXT PRIMARY KEY REFERENCES cases (case_id) ON DELETE CASCADE,
    projection_version BIGINT NOT NULL DEFAULT 0 CHECK (projection_version >= 0),
    state TEXT NOT NULL,
    case_version INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence DOUBLE PRECISION CHECK (confidence BETWEEN 0 AND 1),
    owner TEXT,
    active_session_count INTEGER NOT NULL DEFAULT 0 CHECK (active_session_count >= 0),
    evidence_verified_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_verified_count >= 0),
    evidence_total_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_total_count >= 0),
    unresolved_gap_count INTEGER NOT NULL DEFAULT 0 CHECK (unresolved_gap_count >= 0),
    export_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    last_event_time TIMESTAMPTZ,
    source_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_event_ids) = 'array'),
    freshness_status TEXT NOT NULL DEFAULT 'CURRENT'
        CHECK (freshness_status IN ('CURRENT','STALE','GAP_DETECTED','REBUILDING')),
    projected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dashboard_timeline_items (
    item_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions (session_id) ON DELETE SET NULL,
    item_type TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (
        classification IN (
            'OBSERVED_FACT','DETERMINISTIC_CORRELATION','AI_INFERENCE',
            'ANALYST_ACTION','SYSTEM_ACTION'
        )
    ),
    label TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    event_time TIMESTAMPTZ NOT NULL,
    source_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_event_ids) = 'array'),
    source_references JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_references) = 'array'),
    evidence_references JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(evidence_references) = 'array'),
    confidence DOUBLE PRECISION CHECK (confidence BETWEEN 0 AND 1),
    output_tag TEXT,
    display_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(display_metadata) = 'object'),
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(permissions) = 'array'),
    version BIGINT NOT NULL CHECK (version > 0),
    source_event_id TEXT NOT NULL UNIQUE
);
CREATE INDEX dashboard_timeline_case_time_idx
    ON dashboard_timeline_items (case_id, event_time, item_id);

CREATE TABLE dashboard_graph_nodes (
    node_id TEXT PRIMARY KEY,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions (session_id) ON DELETE SET NULL,
    event_time TIMESTAMPTZ NOT NULL,
    source_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_event_ids) = 'array'),
    source_references JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_references) = 'array'),
    evidence_references JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(evidence_references) = 'array'),
    classification TEXT NOT NULL,
    confidence DOUBLE PRECISION CHECK (confidence BETWEEN 0 AND 1),
    output_tag TEXT,
    display_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(display_metadata) = 'object'),
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(permissions) = 'array'),
    version BIGINT NOT NULL CHECK (version > 0)
);
CREATE INDEX dashboard_graph_nodes_case_idx
    ON dashboard_graph_nodes (case_id, event_time, node_type);

CREATE TABLE dashboard_graph_edges (
    edge_id TEXT PRIMARY KEY,
    edge_type TEXT NOT NULL,
    label TEXT NOT NULL,
    source_node_id TEXT NOT NULL REFERENCES dashboard_graph_nodes (node_id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES dashboard_graph_nodes (node_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions (session_id) ON DELETE SET NULL,
    event_time TIMESTAMPTZ NOT NULL,
    source_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_event_ids) = 'array'),
    source_references JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(source_references) = 'array'),
    evidence_references JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(evidence_references) = 'array'),
    classification TEXT NOT NULL,
    confidence DOUBLE PRECISION CHECK (confidence BETWEEN 0 AND 1),
    output_tag TEXT,
    display_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(display_metadata) = 'object'),
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(permissions) = 'array'),
    version BIGINT NOT NULL CHECK (version > 0),
    CHECK (source_node_id <> target_node_id)
);
CREATE INDEX dashboard_graph_edges_case_idx
    ON dashboard_graph_edges (case_id, event_time, edge_type);

CREATE TABLE dashboard_projection_offsets (
    projector_name TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    projection_version BIGINT NOT NULL DEFAULT 0 CHECK (projection_version >= 0),
    last_source_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_source_sequence >= 0),
    last_event_id TEXT,
    last_event_time TIMESTAMPTZ,
    gap_detected BOOLEAN NOT NULL DEFAULT FALSE,
    gap_from BIGINT,
    gap_to BIGINT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (projector_name, case_id)
);

CREATE TABLE dashboard_projected_events (
    projector_name TEXT NOT NULL,
    event_id TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    source_sequence BIGINT NOT NULL,
    projection_version BIGINT NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (projector_name, event_id)
);

CREATE TABLE dashboard_notifications (
    notification_id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases (case_id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('INFO','WARNING','HIGH','CRITICAL')),
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    source_reference JSONB NOT NULL DEFAULT '{}'::jsonb,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX dashboard_notifications_case_time_idx
    ON dashboard_notifications (case_id, created_at DESC);

CREATE TABLE dashboard_saved_views (
    view_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    case_id TEXT REFERENCES cases (case_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    workspace TEXT NOT NULL,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    layout JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subject, name)
);

CREATE TABLE dashboard_user_preferences (
    subject TEXT PRIMARY KEY,
    preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dashboard_case_access (
    case_id TEXT NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('READ','OPERATE','EXPORT','ADMIN')),
    granted_by TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, subject, permission)
);

CREATE TABLE dashboard_realtime_updates (
    sequence_id BIGSERIAL PRIMARY KEY,
    update_id TEXT NOT NULL UNIQUE,
    update_type TEXT NOT NULL,
    case_id TEXT REFERENCES cases (case_id) ON DELETE CASCADE,
    projection_version BIGINT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    correlation_id TEXT NOT NULL,
    minimum_role TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX dashboard_realtime_updates_case_sequence_idx
    ON dashboard_realtime_updates (case_id, sequence_id);
