/* eslint-disable */
/** Generated from src/schemas/events/agent.heartbeat.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=agent.heartbeat, schema_version major=1. Used for GET /api/v1/agents and health rollups (Step 4b). queue_depth was added in 1.1 as an additive, optional field — a 1.0 instance omitting it still validates.
 */
export interface AgentHeartbeatPayload {
  agent_id: string;
  role: "ENDPOINT" | "SPIDER" | "ENV_CONTROLLER";
  build_hash: string;
  version: string;
  certificate_serial: string;
  uptime_seconds: number;
  health_state: "HEALTHY" | "DEGRADED" | "UNHEALTHY";
  /**
   * Added in schema_version 1.1 (additive/optional). Local encrypted-queue depth.
   */
  queue_depth?: number;
}
