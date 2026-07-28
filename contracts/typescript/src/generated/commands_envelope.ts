/* eslint-disable */
/** Generated from src/schemas/commands/envelope.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * The envelope wrapping every structured sandbox action (spec Appendix C). `params` is validated separately against the schema registered for `command_type`'s major schema_version. Model/AI output is NEVER a shell command — command_type is always one of a fixed, registered set (Appendix I; framework enforced here, concrete sandbox action types registered in Stage 4 / Step 9b).
 */
export interface MirageCommandEnvelope {
  command_id: string;
  /**
   * Dot-namespaced command type from the fixed registered action set, e.g. 'sandbox.place_artifact'.
   */
  command_type: string;
  schema_version: string;
  case_id: string;
  sandbox_id: string;
  /**
   * Optimistic-concurrency check against sandbox_instances.state_version; a mismatch rejects the command.
   */
  expected_state_version: number;
  issued_by: "AI" | "ANALYST" | "SYSTEM";
  policy_decision_id: string;
  /**
   * command_type-specific parameters, validated against the registered params schema for (command_type, schema_version major).
   */
  params: {};
  expires_at: string;
}
