/* eslint-disable */
/** Generated from src/schemas/events/agent.certificate_renewed.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=agent.certificate_renewed, schema_version major=1. Audit trail requirement: renewal. Identity (agent_id) is preserved across renewal — old_certificate_serial and new_certificate_serial share the same agent_id.
 */
export interface AgentCertificateRenewedPayload {
  agent_id: string;
  old_certificate_serial: string;
  new_certificate_serial: string;
  /**
   * Fraction of certificate lifetime remaining at renewal time; must be <= 0.20 per Step 3 auto-renew rule.
   */
  renewed_at_lifetime_fraction: number;
}
