/* eslint-disable */
/** Generated from src/schemas/events/spider.tamper.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

/**
 * Payload for event_type=spider.tamper, schema_version major=1. High-priority signal (Step 5: 'Tamper + health high-priority') that something tried to interfere with MirageSpider's own observation — e.g. an attacker inside the sandbox attempting to stop or blind the agent. Routed to the immutable audit stream (subjects.py: audit.spider.tamper), not the short-retention telemetry stream, because tamper attempts are inherently security-relevant regardless of case outcome.
 */
export interface SpiderTamperPayload {
  tamper_type:
    | "SERVICE_STOP_ATTEMPT"
    | "PROCESS_KILL_ATTEMPT"
    | "CONFIG_MODIFIED"
    | "UNINSTALL_ATTEMPT"
    | "LOG_CLEARED"
    | "QUEUE_TAMPERED";
  detail: string;
  observed_at: string;
}
