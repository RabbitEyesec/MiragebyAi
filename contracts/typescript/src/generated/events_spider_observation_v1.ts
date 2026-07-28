/* eslint-disable */
/** Generated from src/schemas/events/spider.observation.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=spider.observation, schema_version major=1. Read-only sandbox telemetry recorded by MirageSpider (Appendix G, Step 5). Priority 1 (revised): Sysmon/Windows Event Log ingestion is owned by Elastic Agent/Fleet, not MirageSpider (see docs/architecture/windows-telemetry.md) — Spider's own PROCESS_* /FILE_* /NETWORK_CONNECTION/REGISTRY_MODIFY types remain for the fingerprint-gate and dev-sandbox-target use cases that predate Elastic Agent's own Sysmon ingestion, and now carry optional host_id/process_guid/correlation_id so they can be correlated against (not duplicated with) Elastic Agent's own equivalent events for the same host/process. The Mirage-specific types (DECOY_INTERACTION, CONTROLLER_ACTION_OBSERVED, ANALYST_INTERACTION_OBSERVED, AI_INTERACTION_OBSERVED, USER_INTERACTION_INDICATOR) describe signals Elastic Agent has no way to observe at all. Carried in the shared envelope (Appendix C), which supplies case_id tagging, ordering (sequence), and actor identity — this schema only describes the observation itself.
 */
export interface SpiderObservationPayload {
  observation_type:
    | "PROCESS_START"
    | "PROCESS_STOP"
    | "FILE_CREATE"
    | "FILE_MODIFY"
    | "FILE_DELETE"
    | "NETWORK_CONNECTION"
    | "REGISTRY_MODIFY"
    | "ARTIFACT_INTERACTION"
    | "DECOY_INTERACTION"
    | "CONTROLLER_ACTION_OBSERVED"
    | "ANALYST_INTERACTION_OBSERVED"
    | "AI_INTERACTION_OBSERVED"
    | "USER_INTERACTION_INDICATOR";
  /**
   * What was observed — process image path, file path, registry key, or connection descriptor, depending on observation_type.
   */
  subject: string;
  /**
   * Optional structured detail, shape depends on observation_type. Deliberately permissive at this layer (Prompt 1 scope); Stage 7's artifact/canary work may tighten this per-type.
   */
  detail?: {
    pid?: number;
    parent_pid?: number;
    sha256?: string;
    remote_address?: string;
    remote_port?: number;
    registry_key?: string;
    artifact_id?: string;
    /**
     * Stable per-host identifier matching Elastic Agent's own host.id for this sandbox — the join key for correlating this observation against Elastic Agent's independently-collected Sysmon/Windows Event Log data for the same host, per docs/architecture/windows-telemetry.md. Never used to imply Spider collected the same event Elastic Agent already owns.
     */
    host_id?: string;
    /**
     * Sysmon-format ProcessGuid ({8-4-4-4-12 hex, braced}) for the same process this observation concerns, when known — the join key against Sysmon's own process-creation event for PROCESS_START/PROCESS_STOP observations specifically.
     */
    process_guid?: string;
    /**
     * Caller-supplied identifier grouping this observation with other events describing the same real-world action across sources (e.g. a controller action's action_id, or an analyst directive's id) — distinct from case_id/session_id, which only say WHICH engagement, not which specific cross-source action.
     */
    correlation_id?: string;
  };
  observed_at: string;
}
