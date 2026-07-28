/* eslint-disable */
/** Generated from src/schemas/commands/sandbox.command.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Base `params` shape for command_type=sandbox.* over the command envelope (Appendix F/I), schema_version major=1. This is the generic framework-level schema used by Stage 4 / Step 9b's command validation pipeline; concrete per-action-type param schemas (PLACE_ARTIFACT, MOVE_ARTIFACT, etc., Appendix I) are registered individually in mirage_env_controller.actions and validated by action_type before this base shape is used as a fallback/unknown-action rejection path.
 */
export interface SandboxCommandParams {
  /**
   * Fixed registered action set. The last five (TEST_*, SOFT_RESET, FULL_REBUILD, CLEAN_SHUTDOWN) are the Stage-4/Prompt-1 framework+safe-testing actions; the rest are the full Appendix I set whose concrete handlers are completed as later stages land.
   */
  action_type:
    | "PLACE_ARTIFACT"
    | "MOVE_ARTIFACT"
    | "CREATE_DECOY_DIRECTORY"
    | "CHANGE_VISIBLE_METADATA"
    | "DISPLAY_MESSAGE"
    | "ENABLE_DECOY_SERVICE"
    | "DISABLE_DECOY_SERVICE"
    | "REQUEST_SNAPSHOT"
    | "ROLLBACK_ACTION"
    | "CONCLUDE_SESSION"
    | "TEST_FILE_PLACEMENT"
    | "TEST_METADATA_UPDATE"
    | "SOFT_RESET"
    | "FULL_REBUILD"
    | "CLEAN_SHUTDOWN";
  /**
   * action_type-specific fields, validated by the registered handler for action_type.
   */
  action_params?: {};
}
