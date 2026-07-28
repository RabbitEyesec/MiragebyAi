DROP INDEX IF EXISTS cases_correlation_key_idx;
ALTER TABLE cases DROP COLUMN IF EXISTS correlation_key;
