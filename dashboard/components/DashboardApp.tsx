"use client";

import { useEffect, useState } from "react";

import { AppShell } from "@/components/AppShell";
import { DegradedState, LoadingState, PermissionDenied } from "@/components/AsyncState";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AIView } from "@/features/ai/AIView";
import { EvidenceView } from "@/features/evidence/EvidenceView";
import { InvestigationView } from "@/features/investigation/InvestigationView";
import { OperationsView } from "@/features/operations/OperationsView";
import { ReportingView } from "@/features/reporting/ReportingView";
import { SandboxView } from "@/features/sandbox/SandboxView";
import { useRealtime } from "@/hooks/useRealtime";
import { canAccessWorkspace, type Workspace } from "@/lib/rbac";
import type { CaseListItem, EvidenceCard, UserSession } from "@/models";
import { api } from "@/services/api";

export function DashboardApp({ initialUser }: { initialUser: UserSession }) {
  const [user] = useState(initialUser);
  const [csrfToken, setCsrfToken] = useState("");
  const [cases, setCases] = useState<CaseListItem[]>([]);
  const [selectedCase, setSelectedCase] = useState<string | null>(null);
  const [workspace, setWorkspace] = useState<Workspace>("operations");
  const [operations, setOperations] = useState<Record<string, unknown> | null>(null);
  const [sandbox, setSandbox] = useState<Record<string, unknown> | null>(null);
  const [aiState, setAiState] = useState<Record<string, unknown> | null>(null);
  const [reports, setReports] = useState<Record<string, unknown> | null>(null);
  const [evidence, setEvidence] = useState<EvidenceCard[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [degraded, setDegraded] = useState<string | null>(null);
  const realtime = useRealtime(selectedCase);

  useEffect(() => {
    // The CSRF token must come from its own request, independent of the
    // cases/operations fetch below — bundling all three in one Promise.all
    // meant that a degraded (but still authenticated) backend left
    // csrfToken permanently empty, which silently broke the logout button
    // (every POST /api/auth/logout was rejected as a CSRF failure) even
    // though the session itself was perfectly valid.
    api.session().then((session) => setCsrfToken(session.csrfToken));
    Promise.all([api.cases(), api.operations()])
      .then(([caseResult, operationsResult]) => {
        setCases(caseResult.cases);
        setSelectedCase(caseResult.cases[0]?.case_id ?? null);
        setOperations(operationsResult);
      })
      .catch(() => setDegraded("The dashboard API or identity session is unavailable."))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedCase) return;
    setSandbox(null);
    setAiState(null);
    setReports(null);
    setEvidence(null);
    const load = async () => {
      try {
        if (workspace === "sandbox") setSandbox(await api.sandboxState(selectedCase));
        if (workspace === "ai") setAiState(await api.aiState(selectedCase));
        if (workspace === "evidence") setEvidence((await api.evidence(selectedCase)).evidence);
        if (workspace === "reporting") setReports(await api.reports(selectedCase));
      } catch {
        setDegraded(`The ${workspace} read model is temporarily unavailable.`);
      }
    };
    void load();
  }, [selectedCase, workspace]);

  async function logout() {
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      headers: { "x-csrf-token": csrfToken },
    });
    const result = (await response.json()) as { logoutUrl: string };
    window.location.assign(result.logoutUrl);
  }

  async function refreshReports() {
    if (selectedCase) setReports(await api.reports(selectedCase));
  }

  if (loading) return <LoadingState label="Loading analyst dashboard" />;
  const freshness = realtime.model?.freshness.status ?? "UNKNOWN";
  const alerts = ((operations?.recent_operational_alerts ?? []) as unknown[]).length;

  let content;
  if (!canAccessWorkspace(user.roles, workspace)) {
    content = <PermissionDenied workspace={workspace} />;
  } else if (degraded) {
    content = (
      <DegradedState title="Degraded service" detail={degraded}>
        <button type="button" onClick={() => setDegraded(null)}>Dismiss</button>
      </DegradedState>
    );
  } else {
    content = {
      operations: <OperationsView data={operations} />,
      investigation: (
        <InvestigationView
          model={realtime.model}
          roles={user.roles}
          caseId={selectedCase}
          csrfToken={csrfToken}
        />
      ),
      sandbox: <SandboxView data={sandbox} roles={user.roles} />,
      ai: (
        <AIView
          data={aiState}
          roles={user.roles}
          caseId={selectedCase}
          csrfToken={csrfToken}
        />
      ),
      evidence: <EvidenceView evidence={evidence} />,
      reporting: (
        <ReportingView
          data={reports}
          roles={user.roles}
          caseId={selectedCase}
          csrfToken={csrfToken}
          onRefresh={refreshReports}
        />
      ),
    }[workspace];
  }

  return (
    <AppShell
      user={user}
      cases={cases}
      selectedCase={selectedCase}
      onCaseChange={setSelectedCase}
      workspace={workspace}
      onWorkspaceChange={setWorkspace}
      connection={realtime.connection}
      freshness={freshness}
      notifications={alerts}
      onLogout={logout}
    >
      <ErrorBoundary>{content}</ErrorBoundary>
    </AppShell>
  );
}
