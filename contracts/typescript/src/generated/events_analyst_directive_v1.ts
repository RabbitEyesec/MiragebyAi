/* eslint-disable */
/** Generated from src/schemas/events/analyst.directive.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface AnalystDirectiveV1 {
  directive_id: string;
  case_id: string;
  objective: string;
  priority: "LOW" | "NORMAL" | "HIGH" | "URGENT";
  status: "SUBMITTED" | "ACKNOWLEDGED" | "QUEUED" | "APPLIED" | "REJECTED" | "EXPIRED" | "CANCELLED";
  created_by: string;
  expires_at: string | null;
}
