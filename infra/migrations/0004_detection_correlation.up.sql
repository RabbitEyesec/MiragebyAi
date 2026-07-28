-- Step 7: detection-into-cases adapter. Adds the correlation key cases are
-- looked up by (Appendix C: case.created payload's `correlation_key`,
-- schemas/events/detection.raised.v1's `correlation_key`) — migration 0002's
-- minimal `cases` table (Step 4b bootstrap) had no such column since
-- nothing needed to correlate against it yet.

ALTER TABLE cases ADD COLUMN correlation_key TEXT;

-- UNIQUE, not NOT NULL: existing minimal-bootstrap cases (Step 4b) have no
-- correlation_key and never will; Postgres UNIQUE permits multiple NULLs,
-- so this coexists cleanly. Every case the Step 7 adapter creates always
-- sets one, and this index IS the "correlate into one case" lookup path
-- (`SELECT case_id FROM cases WHERE correlation_key = %s`).
CREATE UNIQUE INDEX cases_correlation_key_idx ON cases (correlation_key) WHERE correlation_key IS NOT NULL;
