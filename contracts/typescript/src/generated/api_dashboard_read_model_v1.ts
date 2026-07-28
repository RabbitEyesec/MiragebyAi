/* eslint-disable */
/** Generated from src/schemas/api/dashboard_read_model.v1.schema.json — DO NOT HAND-EDIT. Regenerate with `make generate-contracts`. */

export type Classification =
  "OBSERVED_FACT" | "DETERMINISTIC_CORRELATION" | "AI_INFERENCE" | "ANALYST_ACTION" | "SYSTEM_ACTION";
export type OutputTag =
  | "REAL_OS_OUTPUT"
  | "DECOY_SERVICE_OUTPUT"
  | "AI_GENERATED_INTERACTION"
  | "ANALYST_MESSAGE"
  | "UNTRUSTED_INTRUDER_OUTPUT"
  | null;

/**
 * Canonical Stage 9 read model shared by timelines, 2D/3D graphs, Evidence Board, and reports.
 */
export interface DashboardReadModelV1 {
  schema_version: "1.0";
  summary: CaseSummary;
  timeline: TimelineItem[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    sampled: boolean;
    total_nodes: number;
    total_edges: number;
  };
  freshness: Freshness;
}
export interface CaseSummary {
  case_id: string;
  state: string;
  version: number;
  severity: string;
  confidence?: number | null;
  owner?: string | null;
  active_session_count: number;
  evidence_verified_count: number;
  evidence_total_count: number;
  unresolved_gap_count: number;
  export_eligible: boolean;
  projection_version: number;
}
export interface TimelineItem {
  item_id: string;
  item_type: string;
  classification: Classification;
  label: string;
  description: string;
  case_id: string;
  session_id?: string | null;
  event_time: string;
  source_event_ids: string[];
  source_references: SourceReference[];
  evidence_references: string[];
  confidence?: number | null;
  output_tag?: OutputTag;
  display_metadata: {
    [k: string]: unknown;
  };
  permissions: string[];
  version: number;
}
export interface SourceReference {
  source_type: string;
  source_id: string;
  source_sequence?: number | null;
  event_id?: string | null;
}
export interface GraphNode {
  node_id: string;
  node_type:
    | "CASE"
    | "SESSION"
    | "HOST"
    | "USER"
    | "PROCESS"
    | "FILE"
    | "DIRECTORY"
    | "IP_ADDRESS"
    | "NETWORK_CONNECTION"
    | "ALERT"
    | "DETECTION"
    | "ARTIFACT"
    | "CANARY_TOKEN"
    | "CANARY_CALLBACK"
    | "AI_SNAPSHOT"
    | "AI_PROPOSAL"
    | "POLICY_DECISION"
    | "SANDBOX_ACTION"
    | "ANALYST_DIRECTIVE"
    | "ANALYST_MESSAGE"
    | "EVIDENCE_OBJECT"
    | "EXPORT"
    | "CERTIFICATE"
    | "AGENT";
  label: string;
  case_id: string;
  session_id?: string | null;
  event_time: string;
  source_event_ids: string[];
  source_references: SourceReference[];
  evidence_references: string[];
  classification: Classification;
  confidence?: number | null;
  output_tag?: OutputTag;
  display_metadata: {
    [k: string]: unknown;
  };
  permissions: string[];
  version: number;
}
export interface GraphEdge {
  edge_id: string;
  edge_type:
    | "OBSERVED_ON"
    | "SPAWNED"
    | "READ"
    | "WROTE"
    | "CREATED"
    | "MOVED"
    | "CONNECTED_TO"
    | "AUTHENTICATED_AS"
    | "TRIGGERED"
    | "CORRELATED_WITH"
    | "SUPPORTED_BY"
    | "PROPOSED"
    | "ALLOWED_BY"
    | "DENIED_BY"
    | "EXECUTED_AS"
    | "CAUSED"
    | "DEPLOYED_TO"
    | "CALLBACK_FOR"
    | "DIRECTED"
    | "MESSAGED"
    | "PRESERVED_AS"
    | "INCLUDED_IN"
    | "SIGNED_BY"
    | "BELONGS_TO";
  label: string;
  source_node_id: string;
  target_node_id: string;
  case_id: string;
  session_id?: string | null;
  event_time: string;
  source_event_ids: string[];
  source_references: SourceReference[];
  evidence_references: string[];
  classification: Classification;
  confidence?: number | null;
  output_tag?: OutputTag;
  display_metadata: {
    [k: string]: unknown;
  };
  permissions: string[];
  version: number;
}
export interface Freshness {
  status: "CURRENT" | "STALE" | "GAP_DETECTED" | "REBUILDING";
  projection_version: number;
  projected_at: string;
  last_event_time?: string | null;
  gap_detected: boolean;
  gap_from?: number | null;
  gap_to?: number | null;
}
