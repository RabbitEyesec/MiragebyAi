/* eslint-disable */
/** Generated from src/schemas/events/steering.decision_recorded.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=steering.decision_recorded, schema_version major=1. Emitted whenever /route selects a backend (Step 8a, §6.1) and whenever a routing_decisions row is created/revoked via POST /api/v1/cases/{id}/steer[/revoke].
 */
export interface SteeringDecisionRecordedPayload {
  decision_id: string;
  case_id: string;
  protocol: "HTTP" | "SSH" | "RDP";
  /**
   * protocol + listener_id + source_ip + SNI_or_authenticated_principal, canonically joined.
   */
  match_key: string;
  target: "ENDPOINT" | "SANDBOX";
  decision_version: number;
  action: "CREATED" | "SELECTED" | "REVOKED" | "EXPIRED" | "FAILSAFE_DEFAULT";
}
