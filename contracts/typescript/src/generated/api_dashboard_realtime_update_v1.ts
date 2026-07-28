/* eslint-disable */
/** Generated from src/schemas/api/dashboard_realtime_update.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export interface DashboardRealtimeUpdateV1 {
  update_id: string;
  update_type:
    | "CASE_UPDATED"
    | "TIMELINE_APPENDED"
    | "GRAPH_NODE_UPSERTED"
    | "GRAPH_EDGE_UPSERTED"
    | "EVIDENCE_UPDATED"
    | "AI_STATE_UPDATED"
    | "SANDBOX_STATE_UPDATED"
    | "ARTIFACT_UPDATED"
    | "CANARY_UPDATED"
    | "DIRECTIVE_UPDATED"
    | "MESSAGE_UPDATED"
    | "EXPORT_UPDATED"
    | "HEALTH_UPDATED"
    | "NOTIFICATION_CREATED"
    | "FULL_REFRESH_REQUIRED"
    | "HEARTBEAT";
  case_id: string | null;
  projection_version: number;
  event_time: string;
  payload: {
    [k: string]: unknown;
  };
  correlation_id: string;
}
