/* eslint-disable */
/** Generated from src/schemas/events/sandbox.command_result.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=sandbox.command_result, schema_version major=1. Emitted by MirageEnvironmentController (Step 9b) for every executed command. output_tag is mandatory on every result carrying observable output.
 */
export interface SandboxCommandResultPayload {
  command_id: string;
  command_type: string;
  status: "SUCCESS" | "FAILED" | "REJECTED" | "TIMEOUT";
  output_tag: "REAL_OS_OUTPUT" | "DECOY_SERVICE_OUTPUT" | "AI_GENERATED_INTERACTION" | "ANALYST_MESSAGE";
  journal_entry_id: string;
  rollback_action_id?: string | null;
  error_detail?: string | null;
}
