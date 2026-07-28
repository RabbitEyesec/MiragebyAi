-- Step 10: the live fingerprint gate's read side. MirageSpider submits a
-- spider.fingerprint_snapshot event via the existing telemetry endpoint
-- (mirage-agent-ingestion); the endpoint upserts the LATEST one per
-- sandbox_id here (a "latest observation cache," not a history log — the
-- gate only ever needs "what does the sandbox look like right now").
--
-- No foreign key to sandbox_instances (Step 9b) — Appendix G: "If the
-- Controller fails, observation continues... the two are never combined."
-- Coupling Spider's own reporting to the Controller's row existing would
-- violate that independence.

CREATE TABLE sandbox_fingerprint_snapshots (
    sandbox_id      TEXT PRIMARY KEY,
    checks          JSONB NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_agent_id TEXT NOT NULL
);
