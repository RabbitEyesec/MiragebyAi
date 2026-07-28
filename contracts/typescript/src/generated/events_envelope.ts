/* eslint-disable */
/** Generated from src/schemas/events/envelope.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * The envelope wrapping every telemetry, lifecycle, evidence, audit, and health event (spec Appendix C). `payload` is validated separately against the schema registered for `event_type`'s major schema_version — this schema only validates envelope-level structure. Artifact bytes are NEVER embedded here; payload is capped at 256 KB, enforced at the application layer (JSON Schema cannot bound serialized byte size).
 */
export interface MirageEventEnvelope {
  /**
   * Canonical uppercase ULID.
   */
  event_id: string;
  /**
   * Dot-namespaced event type, e.g. 'agent.heartbeat', 'case.created'.
   */
  event_type: string;
  /**
   * <major>.<minor> of the PAYLOAD schema registered for event_type. Unsupported major versions are rejected with a typed error before the event enters NATS or Elastic.
   */
  schema_version: string;
  /**
   * RFC3339 UTC with millisecond precision, canonical 'Z' suffix (not '+00:00').
   */
  event_time: string;
  /**
   * RFC3339 UTC with millisecond precision; stamped by mirage-agent-ingestion or mirage-api on receipt.
   */
  ingest_time: string;
  /**
   * ULID, or null when the event is not yet associated with a case.
   */
  case_id: string | null;
  /**
   * ULID, or null when the event has no session association.
   */
  session_id: string | null;
  /**
   * Certificate identity (Step 3) or service name that produced the event.
   */
  source_id: string;
  /**
   * Monotonic per certificate identity (source_id).
   */
  sequence: number;
  actor_type:
    | "ENDPOINT_AGENT"
    | "SPIDER_AGENT"
    | "ENV_CONTROLLER_AGENT"
    | "BROKER"
    | "CONTROL_SERVICE"
    | "AI"
    | "ANALYST"
    | "SYSTEM";
  integrity: {
    /**
     * SHA-256 of the canonical (sorted-key, no-whitespace) JSON encoding of `payload`.
     */
    sha256: string;
  };
  /**
   * Handling classification — see ARCHITECTURE_DECISIONS.md ADR-0011. UNTRUSTED_INTRUDER_OUTPUT content is analysed, never executed, and never logged verbatim (security boundary).
   */
  classification: "INTERNAL" | "EVIDENCE" | "UNTRUSTED_INTRUDER_OUTPUT" | "SYSTEM";
  /**
   * Event-type-specific payload, validated against the schema registered for (event_type, schema_version major). Maximum 256 KB serialized — enforced at the application layer.
   */
  payload: {};
}
