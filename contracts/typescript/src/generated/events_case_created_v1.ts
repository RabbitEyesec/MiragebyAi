/* eslint-disable */
/** Generated from src/schemas/events/case.created.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=case.created, schema_version major=1. The immutable first lifecycle event for a case (Step 7 acceptance: exactly one case per correlated incident, first event immutable).
 */
export interface CaseCreatedPayload {
  case_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  correlation_key: string;
  /**
   * @minItems 1
   * @maxItems 50
   */
  source_detection_ids: [string, ...string[]];
  initial_state: "CREATED";
}
