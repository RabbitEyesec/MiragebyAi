DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS processed_events;
DROP TRIGGER IF EXISTS outbox_events_notify_trigger ON outbox_events;
DROP FUNCTION IF EXISTS notify_outbox_events();
DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS case_state_transitions;
ALTER TABLE cases DROP CONSTRAINT IF EXISTS cases_case_id_is_ulid;
ALTER TABLE cases DROP COLUMN IF EXISTS updated_at;
