/* eslint-disable */
/** Generated from src/schemas/events/system.health.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=system.health, schema_version major=1. Emitted by each control-plane unit and consumed by GET /api/v1/health (Step 4b).
 */
export interface SystemHealthPayload {
  component:
    | "POSTGRES"
    | "NATS"
    | "ELASTICSEARCH"
    | "KEYCLOAK"
    | "STEP_CA"
    | "AGENT_INGESTION"
    | "SANDBOX_GATEWAY"
    | "OUTBOX_RELAY"
    | "WORKER"
    | "API";
  status: "HEALTHY" | "DEGRADED" | "UNHEALTHY" | "UNKNOWN";
  checked_at: string;
  detail?: string | null;
  latency_ms?: number | null;
}
