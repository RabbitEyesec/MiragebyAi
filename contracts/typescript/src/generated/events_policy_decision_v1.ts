/* eslint-disable */
/** Generated from src/schemas/events/policy.decision.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface PolicyDecisionV1 {
  decision_id: string;
  case_id: string;
  proposal_id?: string | null;
  decision: "ALLOW" | "DENY" | "REQUIRE_ANALYST_APPROVAL" | "DEFER" | "FALLBACK";
  /**
   * @minItems 1
   */
  reason_codes: [string, ...string[]];
  policy_version: string;
}
