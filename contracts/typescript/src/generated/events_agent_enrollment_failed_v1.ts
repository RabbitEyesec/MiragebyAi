/* eslint-disable */
/** Generated from src/schemas/events/agent.enrollment_failed.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=agent.enrollment_failed, schema_version major=1. Audit trail requirement: enrolment failure.
 */
export interface AgentEnrollmentFailedPayload {
  reason:
    | "TOKEN_EXPIRED"
    | "TOKEN_REUSED"
    | "TOKEN_UNKNOWN"
    | "BUILD_HASH_NOT_ALLOWLISTED"
    | "HOST_FINGERPRINT_INVALID"
    | "CSR_INVALID"
    | "CA_SIGNING_ERROR";
  enrollment_token_id: string | null;
  presented_build_hash?: string | null;
  presented_host_fingerprint?: string | null;
}
