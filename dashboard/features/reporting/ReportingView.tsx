"use client";

import { useState } from "react";

import { EmptyState } from "@/components/AsyncState";
import { StatusBadge } from "@/components/StatusBadge";
import { canUseControl } from "@/lib/rbac";
import { api } from "@/services/api";

export function ReportingView({
  data,
  roles,
  caseId = null,
  csrfToken = "",
  onRefresh,
}: {
  data: Record<string, unknown> | null;
  roles: string[];
  caseId?: string | null;
  csrfToken?: string;
  onRefresh?: () => Promise<void>;
}) {
  const [pending, setPending] = useState<Record<string, unknown> | null>(null);
  const [action, setAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const reports = [...(pending ? [pending] : []), ...((data?.reports ?? []) as Array<Record<string, unknown>>)]
    .filter((report, index, values) =>
      values.findIndex((candidate) => candidate.report_id === report.report_id) === index,
    );
  const permitted = canUseControl(roles, "export");

  async function create() {
    if (!caseId || !csrfToken) return;
    setAction("create");
    setError(null);
    try {
      setPending(await api.createReport(caseId, csrfToken));
      await onRefresh?.();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Report request failed");
    } finally {
      setAction(null);
    }
  }

  async function verify(reportId: string) {
    if (!caseId || !csrfToken) return;
    setAction(`verify:${reportId}`);
    try {
      await api.verifyReport(caseId, reportId, csrfToken);
      await onRefresh?.();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Verification failed");
    } finally {
      setAction(null);
    }
  }

  async function cancel(reportId: string) {
    if (!caseId || !csrfToken) return;
    setAction(`cancel:${reportId}`);
    try {
      await api.cancelReport(caseId, reportId, csrfToken);
      await onRefresh?.();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Cancellation failed");
    } finally {
      setAction(null);
    }
  }

  async function prepareDownload(reportId: string) {
    if (!caseId) return;
    setAction(`download:${reportId}`);
    try {
      const result = await api.reportDownload(caseId, reportId);
      setDownloadUrl(
        result.download_url.replace(/^\/api\/v1\//, "/api/mirage/v1/"),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Download request failed");
    } finally {
      setAction(null);
    }
  }

  return (
    <div className="workspace-grid">
      <section className="hero-card">
        <p className="eyebrow">Evidence-ready output</p>
        <h2>Reports & export</h2>
        <p>PDF · DOCX · JSON · canonical manifest</p>
        {permitted ? (
          <button
            type="button"
            disabled={!caseId || !csrfToken || action === "create"}
            onClick={() => void create()}
          >
            {action === "create" ? "Queueing report…" : "Create report package"}
          </button>
        ) : <p>Explicit export permission is required.</p>}
        {error && <p role="alert">{error}</p>}
        {downloadUrl && (
          <p>
            <a href={downloadUrl}>Download single-use package</a>
            {" "}This short-lived link is consumed on first use.
          </p>
        )}
      </section>
      <section className="panel panel-wide">
        <h3>Report packages</h3>
        {!reports.length ? <EmptyState title="No reports generated" detail="Eligible reports will show progress, verification, and short-lived download controls here." /> : (
          <div className="table-scroll"><table><thead><tr><th>Report</th><th>Status</th><th>Progress</th><th>Formats</th><th>Package hash</th><th>Independent verification</th><th>Controls</th></tr></thead><tbody>{reports.map((report) => {
            const reportId = String(report.report_id);
            const status = String(report.status);
            return <tr key={reportId}><td className="mono">{reportId}</td><td><StatusBadge value={status} /></td><td>{String(report.progress ?? 0)}%</td><td>PDF · DOCX · JSON · manifest</td><td className="mono">{String(report.package_sha256 ?? "Pending")}</td><td>{String(report.verification_status ?? "Pending")}</td><td>{permitted && status === "COMPLETED" && <><button type="button" disabled={action === `verify:${reportId}`} onClick={() => void verify(reportId)}>Verify</button><button type="button" disabled={action === `download:${reportId}`} onClick={() => void prepareDownload(reportId)}>Create download link</button></>}{permitted && ["QUEUED", "WAITING_FOR_EXPORT", "GENERATING", "VERIFYING"].includes(status) && <button type="button" disabled={action === `cancel:${reportId}`} onClick={() => void cancel(reportId)}>Cancel</button>}</td></tr>;
          })}</tbody></table></div>
        )}
      </section>
      <section className="panel panel-wide">
        <h3>Independent verification</h3>
        <p>Every package includes the canonical manifest, signature, public verification material, verification reports, and offline instructions. Mirage describes output as evidence-ready, never court-admissible.</p>
      </section>
    </div>
  );
}
