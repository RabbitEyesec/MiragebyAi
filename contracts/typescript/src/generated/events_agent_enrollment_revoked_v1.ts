/* eslint-disable */
/** Generated from src/schemas/events/agent.enrollment_revoked.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=agent.enrollment_revoked, schema_version major=1. Audit trail requirement: revocation. Emitted on sandbox destruction or manual revocation.
 */
export interface AgentEnrollmentRevokedPayload {
  agent_id: string;
  certificate_serial: string;
  reason: "SANDBOX_DESTROYED" | "MANUAL_REVOCATION" | "COMPROMISE_SUSPECTED" | "SUPERSEDED_BY_RENEWAL";
}
