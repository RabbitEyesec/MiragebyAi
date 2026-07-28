export type {
  CaseSummary,
  Classification,
  DashboardReadModelV1,
  DashboardRealtimeUpdateV1,
  Freshness,
  GraphEdge,
  GraphNode,
  OutputTag,
  SourceReference,
  TimelineItem,
} from "@mirage/contracts";

export interface UserSession {
  subject: string;
  username: string;
  roles: string[];
  expiresAt: number;
}

export interface SessionResponse {
  authenticated: true;
  user: UserSession;
  csrfToken: string;
}

export interface EvidenceCard {
  evidence_id: string;
  type: string;
  filename: string | null;
  media_type: string;
  size_bytes: number;
  sha256: string;
  source: string;
  sequence: number;
  certificate_serial: string | null;
  acquisition_time: string;
  s3_version_id: string;
  object_lock: { mode: string | null; retention_until: string | null };
  verification_status: string;
  classification: string;
  related_events: string[];
  related_graph_nodes: string[];
  export_inclusion: boolean;
}

export interface CaseListItem {
  case_id: string;
  state: string;
  version: number;
  severity: string;
  owner: string | null;
  created_at: string;
}
