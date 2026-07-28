/* eslint-disable */
/** Generated from src/schemas/events/canary.callback.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface CanaryCallbackV1 {
  callback_id: string;
  token_id: string;
  callback_time: string;
  source_ip: string;
  classification: "IN_SANDBOX_CALLBACK" | "SECURITY_SCANNER_CALLBACK" | "EXTERNAL_CALLBACK" | "UNKNOWN_SOURCE_CALLBACK";
  confidence: number;
  rule_version: string;
  signature: string;
}
