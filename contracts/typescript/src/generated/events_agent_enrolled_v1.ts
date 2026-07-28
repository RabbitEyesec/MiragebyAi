/* eslint-disable */
/** Generated from src/schemas/events/agent.enrolled.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=agent.enrolled, schema_version major=1. Emitted by mirage-agent-ingestion (Step 3) on successful one-time-token enrolment. Audit trail requirement: enrolment.
 */
export interface AgentEnrolledPayload {
  agent_id: string;
  role: "ENDPOINT" | "SPIDER" | "ENV_CONTROLLER" | "BROKER_CLIENT" | "INTERNAL_CONTROL";
  certificate_serial: string;
  certificate_profile:
    "MirageEndpoint" | "MirageSpider" | "MirageEnvironmentController" | "BrokerClient" | "InternalControl";
  build_hash: string;
  host_fingerprint: string;
  enrollment_token_id: string;
}
