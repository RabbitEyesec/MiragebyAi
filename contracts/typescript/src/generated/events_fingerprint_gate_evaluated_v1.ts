/* eslint-disable */
/** Generated from src/schemas/events/fingerprint.gate_evaluated.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=fingerprint.gate_evaluated, schema_version major=1. Step 10's live, blocking §6.5 fingerprint gate — evaluated every time a case attempts SANDBOX_ACTIVE -> ENGAGING. Emitted on BOTH pass and block (§6.5: 'an inconsistent sandbox is worse than none' — the failure itself must be durably recorded, not silently swallowed). Carried in the shared envelope (Appendix C).
 */
export interface FingerprintGateEvaluatedPayload {
  case_id: string;
  sandbox_id: string;
  baseline_version: string;
  /**
   * §6.5 scoring rule result: MUST=100% AND SHOULD>=75%.
   */
  passed: boolean;
  all_must_passed: boolean;
  should_pass_ratio: number;
  /**
   * Names of every MUST-level check that failed (empty when all_must_passed is true) — the evidence a human reviewing why a case got stuck in SANDBOX_ACTIVE needs without re-running the comparator.
   */
  failed_must_checks: string[];
  /**
   * True when this evaluation prevented the SANDBOX_ACTIVE -> ENGAGING transition from happening at all.
   */
  blocked: boolean;
}
