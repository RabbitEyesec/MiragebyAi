"use client";

import { useState } from "react";

import { EmptyState } from "@/components/AsyncState";
import { GraphWorkbench } from "@/components/GraphWorkbench";
import { ClassificationBadge, OutputTagBadge, StatusBadge } from "@/components/StatusBadge";
import { formatUtc } from "@/lib/format";
import { canUseControl } from "@/lib/rbac";
import type { DashboardReadModelV1 } from "@/models";
import { api } from "@/services/api";

export function InvestigationView({
  model,
  roles = [],
  caseId = null,
  csrfToken = "",
}: {
  model: DashboardReadModelV1 | null;
  roles?: string[];
  caseId?: string | null;
  csrfToken?: string;
}) {
  const [objective, setObjective] = useState("");
  const [priority, setPriority] = useState<"LOW" | "NORMAL" | "HIGH" | "URGENT">(
    "NORMAL",
  );
  const [directiveStatus, setDirectiveStatus] = useState<string | null>(null);
  const [directiveError, setDirectiveError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  if (!model) return <EmptyState title="Select a case" detail="Choose an authorised case to open its canonical investigation model." />;
  const canDirect = canUseControl(roles, "directive");

  async function submitDirective() {
    if (!caseId || !csrfToken || !objective.trim()) return;
    setSubmitting(true);
    setDirectiveError(null);
    try {
      const result = await api.submitDirective(caseId, objective, priority, csrfToken);
      setDirectiveStatus(`${result.status}: ${result.directive_id}`);
      setObjective("");
    } catch (cause) {
      setDirectiveError(
        cause instanceof Error ? cause.message : "Directive submission failed",
      );
    } finally {
      setSubmitting(false);
    }
  }
  return (
    <div className="investigation-stack">
      <section className="case-hero">
        <div>
          <p className="eyebrow">Investigation</p>
          <h2>{model.summary.case_id}</h2>
          <div className="badge-row">
            <StatusBadge value={model.summary.state} />
            <StatusBadge value={model.summary.severity} tone="danger" />
            <span>Version {model.summary.version}</span>
            <span>Owner {model.summary.owner ?? "Unassigned"}</span>
          </div>
        </div>
        <dl className="summary-facts">
          <div><dt>Sessions</dt><dd>{model.summary.active_session_count}</dd></div>
          <div><dt>Evidence</dt><dd>{model.summary.evidence_verified_count}/{model.summary.evidence_total_count} verified</dd></div>
          <div><dt>Gaps</dt><dd>{model.summary.unresolved_gap_count}</dd></div>
          <div><dt>Export</dt><dd>{model.summary.export_eligible ? "Eligible" : "Blocked"}</dd></div>
        </dl>
      </section>
      <section className="panel">
        <div className="section-heading"><div><p className="eyebrow">Canonical timeline</p><h3>Facts, correlation, inference, and action</h3></div><span>{model.timeline.length} items</span></div>
        {!model.timeline.length ? (
          <EmptyState title="Timeline is empty" detail="The projection is current but no source items are available." />
        ) : (
          <ol className="timeline-list">
            {model.timeline.map((item) => (
              <li key={item.item_id} id={`event-${item.source_event_ids[0] ?? item.item_id}`}>
                <time dateTime={item.event_time}>{formatUtc(item.event_time)}</time>
                <div>
                  <div className="badge-row"><ClassificationBadge value={item.classification} /><OutputTagBadge value={item.output_tag} /></div>
                  <strong>{item.label}</strong>
                  <p>{item.description}</p>
                  <div className="pivot-list">
                    {item.evidence_references.map((id) => <a key={id} href={`#evidence-${encodeURIComponent(id)}`}>Evidence {id}</a>)}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>
      <section className="panel">
        <p className="eyebrow">Analyst control</p>
        <h3>Submit a bounded strategy directive</h3>
        {canDirect ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void submitDirective();
            }}
          >
            <label>
              Objective
              <textarea
                value={objective}
                maxLength={512}
                onChange={(event) => setObjective(event.target.value)}
                placeholder="Observe the next authentication attempt and preserve evidence"
                required
              />
            </label>
            <label>
              Priority
              <select
                value={priority}
                onChange={(event) =>
                  setPriority(
                    event.target.value as "LOW" | "NORMAL" | "HIGH" | "URGENT",
                  )
                }
              >
                <option>LOW</option>
                <option>NORMAL</option>
                <option>HIGH</option>
                <option>URGENT</option>
              </select>
            </label>
            <button
              type="submit"
              disabled={!caseId || !csrfToken || !objective.trim() || submitting}
            >
              {submitting ? "Submitting directive…" : "Submit directive"}
            </button>
          </form>
        ) : (
          <p>Investigator or platform administrator permission is required.</p>
        )}
        {directiveStatus && <p role="status">{directiveStatus}</p>}
        {directiveError && <p role="alert">{directiveError}</p>}
      </section>
      <GraphWorkbench graph={model.graph} />
    </div>
  );
}
