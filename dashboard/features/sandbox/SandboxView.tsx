import { EmptyState } from "@/components/AsyncState";
import { OutputTagBadge, StatusBadge } from "@/components/StatusBadge";
import { canUseControl } from "@/lib/rbac";

export function SandboxView({
  data,
  roles,
}: {
  data: Record<string, unknown> | null;
  roles: string[];
}) {
  const sandbox = data?.sandbox as Record<string, unknown> | null | undefined;
  const journal = (data?.action_journal ?? []) as Array<Record<string, unknown>>;
  if (!sandbox) return <EmptyState title="No sandbox assigned" detail="This case has no active or historical sandbox instance." />;
  return (
    <div className="workspace-grid">
      <section className="hero-card">
        <p className="eyebrow">Sandbox</p>
        <h2>{String(sandbox.sandbox_id)}</h2>
        <StatusBadge value={String(sandbox.state)} tone={sandbox.state === "ACTIVE" ? "good" : "warning"} />
        <p>State version {String(sandbox.state_version)}</p>
      </section>
      <section className="panel">
        <h3>Identity & baseline</h3>
        <dl className="detail-list">
          <dt>Image</dt><dd className="mono">{String(sandbox.image_id)}</dd>
          <dt>Manifest hash</dt><dd className="mono">{String(sandbox.build_manifest_hash ?? "Not reported")}</dd>
          <dt>Network identity</dt><dd>{String(sandbox.network_identity ?? "Not reported")}</dd>
          <dt>Certificate</dt><dd>{String(sandbox.certificate_serial ?? "Not reported")}</dd>
        </dl>
      </section>
      <section className="panel">
        <h3>Services</h3>
        <dl className="detail-list">
          <dt>Spider</dt><dd>{String(sandbox.spider_status)}</dd>
          <dt>Controller</dt><dd>{String(sandbox.controller_status)}</dd>
          <dt>Agent</dt><dd>{String(sandbox.agent_status)}</dd>
        </dl>
      </section>
      <section className="panel panel-wide">
        <div className="section-heading"><h3>Protected controls</h3><span>Preview · confirm · policy · audit</span></div>
        {canUseControl(roles, "sandbox_mutation") ? (
          <div className="button-row">
            <button type="button" disabled>Preview snapshot</button>
            <button type="button" disabled>Preview soft reset</button>
            <button type="button" disabled>Preview rebuild</button>
            <span className="muted">Controls enable only when their policy-protected API advertises eligibility.</span>
          </div>
        ) : <p>Your role can inspect controls but cannot mutate the sandbox.</p>}
      </section>
      <section className="panel panel-wide">
        <h3>Action journal</h3>
        {!journal.length ? <EmptyState title="No actions" detail="No structured sandbox action has been recorded." /> : (
          <ol className="timeline-list">
            {journal.map((action) => <li key={String(action.action_id)}><StatusBadge value={String(action.status)} /><div><strong>{String(action.action_type)}</strong><OutputTagBadge value={action.output_tag as never} /><p className="mono">{String(action.action_id)}</p></div></li>)}
          </ol>
        )}
      </section>
    </div>
  );
}
