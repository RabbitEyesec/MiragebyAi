/* eslint-disable */
/** Generated from src/schemas/events/audit.recorded.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=audit.recorded, schema_version major=1. Mirrors audit_events (Appendix B). Every state-changing transaction writes an audit row in the same DB transaction (Step 6); this event is its outbox-published counterpart.
 */
export interface AuditRecordedPayload {
  actor: string;
  actor_type: "ANALYST" | "AI" | "SYSTEM" | "AGENT";
  action: string;
  target: string;
  outcome: "SUCCESS" | "FAILURE" | "DENIED";
  correlation_id: string;
  detail?: string | null;
}
