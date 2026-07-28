/* eslint-disable */
/** Generated from src/schemas/events/case.state_changed.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export type CaseState =
  | "CREATED"
  | "ARMED"
  | "MONITORING"
  | "STEERING_PENDING"
  | "SANDBOX_ACTIVE"
  | "ENGAGING"
  | "CONCLUDING"
  | "EVIDENCE_VERIFYING"
  | "EXPORTED"
  | "DESTROYED";

/**
 * Payload for event_type=case.state_changed, schema_version major=1. Mirrors case_state_transitions (Appendix B). Every state-changing transaction writes this via the transactional outbox (Step 6, §6.3).
 */
export interface CaseStateChangedPayload {
  case_id: string;
  from_state: CaseState;
  to_state: CaseState;
  actor: string;
  actor_type: "ANALYST" | "AI" | "SYSTEM";
  reason: string;
  new_version: number;
  correlation_id: string;
}
