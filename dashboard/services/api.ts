import type {
  CaseListItem,
  DashboardReadModelV1,
  EvidenceCard,
  SessionResponse,
} from "@/models";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(detail);
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  csrfToken?: string,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  if (csrfToken) headers.set("x-csrf-token", csrfToken);
  const response = await fetch(`/api/mirage/v1${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: unknown };
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      // A bounded generic response is safer than exposing upstream HTML.
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export const api = {
  session: () => fetch("/api/auth/session", { cache: "no-store" }).then(async (response) => {
    if (!response.ok) throw new ApiError(response.status, "Authentication required");
    return (await response.json()) as SessionResponse;
  }),
  cases: () => request<{ cases: CaseListItem[] }>("/dashboard/cases"),
  operations: () => request<Record<string, unknown>>("/dashboard/operations"),
  case: (caseId: string) =>
    request<DashboardReadModelV1>(`/dashboard/cases/${encodeURIComponent(caseId)}`),
  evidence: (caseId: string) =>
    request<{ evidence: EvidenceCard[] }>(
      `/dashboard/cases/${encodeURIComponent(caseId)}/evidence-board`,
    ),
  aiState: (caseId: string) =>
    request<Record<string, unknown>>(
      `/dashboard/cases/${encodeURIComponent(caseId)}/ai-state`,
    ),
  sandboxState: (caseId: string) =>
    request<Record<string, unknown>>(
      `/dashboard/cases/${encodeURIComponent(caseId)}/sandbox-state`,
    ),
  reports: (caseId: string) =>
    request<Record<string, unknown>>(`/cases/${encodeURIComponent(caseId)}/reports`),
  createReport: (caseId: string, csrfToken: string, exportMode = "METADATA_ONLY") =>
    request<Record<string, unknown>>(
      `/cases/${encodeURIComponent(caseId)}/reports`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({ export_mode: exportMode, selected_evidence_ids: [] }),
      },
      csrfToken,
    ),
  verifyReport: (caseId: string, reportId: string, csrfToken: string) =>
    request<Record<string, unknown>>(
      `/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}/verify`,
      { method: "POST" },
      csrfToken,
    ),
  cancelReport: (caseId: string, reportId: string, csrfToken: string) =>
    request<Record<string, unknown>>(
      `/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}/cancel`,
      { method: "POST" },
      csrfToken,
    ),
  reportDownload: (caseId: string, reportId: string) =>
    request<{ download_url: string; expires_at: string; single_use: boolean }>(
      `/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}/download`,
    ),
  submitDirective: (
    caseId: string,
    objective: string,
    priority: "LOW" | "NORMAL" | "HIGH" | "URGENT",
    csrfToken: string,
  ) =>
    request<{ directive_id: string; status: string; objective: string }>(
      `/cases/${encodeURIComponent(caseId)}/directive`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({ objective, priority }),
      },
      csrfToken,
    ),
  previewMessage: (
    caseId: string,
    surface: string,
    content: string,
    csrfToken: string,
  ) =>
    request<{
      preview_hash: string;
      confirmation_required: boolean;
      content: string;
      surface: string;
    }>(
      `/cases/${encodeURIComponent(caseId)}/messages/preview`,
      { method: "POST", body: JSON.stringify({ surface, content }) },
      csrfToken,
    ),
  createMessage: (
    caseId: string,
    body: {
      session_id: string;
      surface: string;
      content: string;
      preview_hash: string;
      policy_decision_id: string;
    },
    csrfToken: string,
  ) =>
    request<{
      message_id: string;
      status: string;
      preview_hash: string;
      confirmation_required: boolean;
    }>(
      `/cases/${encodeURIComponent(caseId)}/messages`,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify(body),
      },
      csrfToken,
    ),
  confirmMessage: (
    caseId: string,
    messageId: string,
    previewHash: string,
    csrfToken: string,
  ) =>
    request<{ message_id: string; status: string }>(
      `/cases/${encodeURIComponent(caseId)}/messages/${encodeURIComponent(messageId)}/confirm`,
      { method: "POST", body: JSON.stringify({ preview_hash: previewHash }) },
      csrfToken,
    ),
  rebuild: (caseId: string, csrfToken: string) =>
    request<Record<string, unknown>>(
      `/dashboard/cases/${encodeURIComponent(caseId)}/rebuild`,
      { method: "POST" },
      csrfToken,
    ),
};
