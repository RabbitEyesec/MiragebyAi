import type { DashboardReadModelV1, GraphEdge, GraphNode } from "@/models";

export const caseId = "01J00000000000000000000000";
export const evidenceId = "01J00000000000000000000001";
export const eventId = "01J00000000000000000000002";

export const caseNode: GraphNode = {
  node_id: `case:${caseId}`,
  node_type: "CASE",
  label: `Case ${caseId}`,
  case_id: caseId,
  session_id: null,
  event_time: "2026-07-26T10:00:00Z",
  source_event_ids: [eventId],
  source_references: [{ source_type: "DOMAIN_EVENT", source_id: "mirage-api", event_id: eventId }],
  evidence_references: [],
  classification: "SYSTEM_ACTION",
  confidence: null,
  output_tag: null,
  display_metadata: {},
  permissions: ["dashboard:read"],
  version: 1,
};

export const evidenceNode: GraphNode = {
  ...caseNode,
  node_id: `evidence_object:${evidenceId}`,
  node_type: "EVIDENCE_OBJECT",
  label: "<img src=x onerror=alert(1)> evidence",
  source_event_ids: [eventId],
  evidence_references: [evidenceId],
  classification: "OBSERVED_FACT",
  output_tag: "UNTRUSTED_INTRUDER_OUTPUT",
};

export const edge: GraphEdge = {
  edge_id: "edge:one",
  edge_type: "BELONGS_TO",
  label: "belongs to case",
  source_node_id: evidenceNode.node_id,
  target_node_id: caseNode.node_id,
  case_id: caseId,
  session_id: null,
  event_time: "2026-07-26T10:00:01Z",
  source_event_ids: [eventId],
  source_references: evidenceNode.source_references,
  evidence_references: [evidenceId],
  classification: "OBSERVED_FACT",
  confidence: 0.9,
  output_tag: "UNTRUSTED_INTRUDER_OUTPUT",
  display_metadata: {},
  permissions: ["dashboard:read"],
  version: 1,
};

export const model: DashboardReadModelV1 = {
  schema_version: "1.0",
  summary: {
    case_id: caseId,
    state: "ENGAGING",
    version: 7,
    severity: "HIGH",
    confidence: 0.91,
    owner: "investigator",
    active_session_count: 1,
    evidence_verified_count: 1,
    evidence_total_count: 1,
    unresolved_gap_count: 0,
    export_eligible: true,
    projection_version: 4,
  },
  timeline: [
    {
      item_id: "timeline:one",
      item_type: "spider.observation",
      classification: "OBSERVED_FACT",
      label: "<script>alert(1)</script> PowerShell observed",
      description: "Observed on the controlled sandbox.",
      case_id: caseId,
      session_id: null,
      event_time: "2026-07-26T10:00:01Z",
      source_event_ids: [eventId],
      source_references: evidenceNode.source_references,
      evidence_references: [evidenceId],
      confidence: 1,
      output_tag: "UNTRUSTED_INTRUDER_OUTPUT",
      display_metadata: {},
      permissions: ["dashboard:read"],
      version: 1,
    },
  ],
  graph: {
    nodes: [caseNode, evidenceNode],
    edges: [edge],
    sampled: false,
    total_nodes: 2,
    total_edges: 1,
  },
  freshness: {
    status: "CURRENT",
    projection_version: 4,
    projected_at: "2026-07-26T10:00:02Z",
    last_event_time: "2026-07-26T10:00:01Z",
    gap_detected: false,
    gap_from: null,
    gap_to: null,
  },
};
