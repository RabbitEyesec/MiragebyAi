"use client";

import { useState } from "react";

import { EmptyState } from "@/components/AsyncState";
import { StatusBadge } from "@/components/StatusBadge";
import { formatGbp } from "@/lib/format";
import { canUseControl } from "@/lib/rbac";
import { api } from "@/services/api";

export function AIView({
  data,
  roles,
  caseId = null,
  csrfToken = "",
}: {
  data: Record<string, unknown> | null;
  roles: string[];
  caseId?: string | null;
  csrfToken?: string;
}) {
  const [sessionId, setSessionId] = useState("");
  const [policyDecisionId, setPolicyDecisionId] = useState("");
  const [content, setContent] = useState("");
  const [surface, setSurface] = useState("DECOY_WEB_CHAT");
  const [preview, setPreview] = useState<{
    preview_hash: string;
    confirmation_required: boolean;
    content: string;
    surface: string;
  } | null>(null);
  const [message, setMessage] = useState<{
    message_id: string;
    status: string;
    preview_hash: string;
  } | null>(null);
  const [controlError, setControlError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!data || data.status === "EMPTY") return <EmptyState title="No AI state" detail="No bounded snapshot or validated proposal exists for this case." />;
  const proposal = (data.proposal ?? {}) as Record<string, unknown>;
  const snapshot = (data.snapshot ?? {}) as Record<string, unknown>;
  const policy = (data.policy ?? {}) as Record<string, unknown>;
  const canMessage = canUseControl(roles, "direct_intervention");

  async function preparePreview() {
    if (!caseId || !csrfToken) return;
    setBusy(true);
    setControlError(null);
    setMessage(null);
    try {
      setPreview(await api.previewMessage(caseId, surface, content, csrfToken));
    } catch (cause) {
      setControlError(cause instanceof Error ? cause.message : "Preview failed");
    } finally {
      setBusy(false);
    }
  }

  async function createPreparedMessage() {
    if (!caseId || !csrfToken || !preview) return;
    setBusy(true);
    setControlError(null);
    try {
      setMessage(
        await api.createMessage(
          caseId,
          {
            session_id: sessionId,
            policy_decision_id: policyDecisionId,
            surface: preview.surface,
            content: preview.content,
            preview_hash: preview.preview_hash,
          },
          csrfToken,
        ),
      );
    } catch (cause) {
      setControlError(cause instanceof Error ? cause.message : "Message creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function confirmPreparedMessage() {
    if (!caseId || !csrfToken || !message) return;
    setBusy(true);
    setControlError(null);
    try {
      const result = await api.confirmMessage(
        caseId,
        message.message_id,
        message.preview_hash,
        csrfToken,
      );
      setMessage({ ...message, status: result.status });
    } catch (cause) {
      setControlError(cause instanceof Error ? cause.message : "Confirmation failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="workspace-grid">
      <section className="hero-card">
        <p className="eyebrow">AI interaction</p>
        <h2>{String(proposal.strategy_phase ?? "No active phase")}</h2>
        <StatusBadge value={String(policy.decision ?? "PENDING")} tone={policy.decision === "ALLOW" ? "good" : "warning"} />
        <p>{String(data.provider ?? "Provider not recorded")} · {String(data.model ?? "Model not recorded")}</p>
      </section>
      <section className="panel">
        <h3>Bounded snapshot</h3>
        <dl className="detail-list">
          <dt>Hash</dt><dd className="mono">{String(snapshot.snapshot_hash)}</dd>
          <dt>Size</dt><dd>{String(snapshot.size_bytes)} bytes</dd>
          <dt>Token estimate</dt><dd>{String(snapshot.estimated_tokens)}</dd>
          <dt>Trimmed fields</dt><dd>{JSON.stringify(snapshot.trimmed_fields ?? [])}</dd>
        </dl>
      </section>
      <section className="panel">
        <h3>Budget & fallback</h3>
        <dl className="detail-list">
          <dt>Cost</dt><dd>{formatGbp(String(data.cost_gbp ?? "0"))}</dd>
          <dt>Requests</dt><dd>{String(data.request_count ?? 0)}</dd>
          <dt>Fallback</dt><dd>{data.fallback_used ? "Used" : "Not used"}</dd>
        </dl>
      </section>
      <section className="panel panel-wide">
        <p className="eyebrow">AI inference — not observed fact</p>
        <h3>{String(proposal.action_type)}</h3>
        <p>{String(proposal.rationale)}</p>
        <div className="badge-row"><StatusBadge value={`Confidence ${String(proposal.confidence)}`} tone="ai" /><StatusBadge value={String(policy.decision)} /></div>
        <p>Supporting events: {JSON.stringify(proposal.supporting_event_ids ?? [])}</p>
        <p>Policy reasons: {JSON.stringify(policy.reason_codes ?? [])}</p>
      </section>
      <section className="panel panel-wide warning-panel">
        <h3>Sanitised untrusted content</h3>
        <p>Hostile input is hidden by default. Any excerpt is bounded, escaped, and labelled UNTRUSTED_INTRUDER_OUTPUT.</p>
      </section>
      <section className="panel panel-wide">
        <p className="eyebrow">Analyst action — never AI-to-shell</p>
        <h3>Preview and confirm a direct message</h3>
        {canMessage ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void preparePreview();
            }}
          >
            <label>Session ID<input value={sessionId} onChange={(event) => setSessionId(event.target.value)} required /></label>
            <label>ALLOW policy decision ID<input value={policyDecisionId} onChange={(event) => setPolicyDecisionId(event.target.value)} required /></label>
            <label>
              Approved surface
              <select value={surface} onChange={(event) => setSurface(event.target.value)}>
                <option>DECOY_WEB_CHAT</option>
                <option>DECOY_TERMINAL_BANNER</option>
                <option>CONTROLLED_DESKTOP_NOTIFICATION</option>
                <option>SCENARIO_SERVICE_RESPONSE</option>
              </select>
            </label>
            <label>Message<textarea value={content} maxLength={2048} onChange={(event) => setContent(event.target.value)} required /></label>
            <button type="submit" disabled={busy || !caseId || !csrfToken || !content.trim()}>Prepare direct message</button>
          </form>
        ) : <p>Direct-intervention permission is required.</p>}
        {preview && !message && (
          <div className="warning-panel">
            <p><strong>Exact preview:</strong> {preview.content}</p>
            <p>Surface: {preview.surface}. Confirmation required: {String(preview.confirmation_required)}.</p>
            <button type="button" disabled={busy || !sessionId || !policyDecisionId} onClick={() => void createPreparedMessage()}>Create pending message</button>
          </div>
        )}
        {message && (
          <div className="warning-panel">
            <p role="status">Message {message.message_id}: {message.status}</p>
            {message.status === "PENDING_CONFIRMATION" && (
              <button type="button" disabled={busy} onClick={() => void confirmPreparedMessage()}>Confirm exact preview</button>
            )}
          </div>
        )}
        {controlError && <p role="alert">{controlError}</p>}
      </section>
    </div>
  );
}
