import { EmptyState } from "@/components/AsyncState";
import { StatusBadge } from "@/components/StatusBadge";

export function OperationsView({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState title="No operational read model" detail="The health projection has not produced a view yet." />;
  const states = (data.cases_by_state ?? {}) as Record<string, number>;
  const severity = (data.cases_by_severity ?? {}) as Record<string, number>;
  const alerts = (data.recent_operational_alerts ?? []) as Array<Record<string, unknown>>;
  return (
    <div className="workspace-grid">
      <section className="hero-card">
        <p className="eyebrow">Control plane</p>
        <h2>{String(data.platform_health ?? "UNKNOWN")}</h2>
        <StatusBadge
          value={String(data.platform_health ?? "UNKNOWN")}
          tone={data.platform_health === "HEALTHY" ? "good" : "warning"}
        />
        <p>{String(data.open_cases ?? 0)} open investigations</p>
      </section>
      <section className="panel">
        <h3>Cases by state</h3>
        <div className="metric-list">
          {Object.entries(states).map(([label, count]) => <div key={label}><span>{label.replaceAll("_", " ")}</span><strong>{count}</strong></div>)}
        </div>
      </section>
      <section className="panel">
        <h3>Cases by severity</h3>
        <div className="metric-list">
          {Object.entries(severity).map(([label, count]) => <div key={label}><span>{label}</span><strong>{count}</strong></div>)}
        </div>
      </section>
      <section className="panel">
        <h3>Operational signals</h3>
        <div className="metric-list">
          <div><span>Dead-letter events</span><strong>{String(data.dead_letter_count ?? 0)}</strong></div>
          <div><span>Evidence verification failures</span><strong>{String(data.evidence_verification_failures ?? 0)}</strong></div>
          <div><span>AI provider</span><strong>{String(data.ai_provider_status ?? "UNKNOWN")}</strong></div>
          <div><span>Artifact scanner</span><strong>{String(data.artifact_scanner_health ?? "UNKNOWN")}</strong></div>
          <div><span>Canary collector</span><strong>{String(data.canary_collector_health ?? "UNKNOWN")}</strong></div>
        </div>
      </section>
      <section className="panel panel-wide">
        <h3>Recent alerts</h3>
        {!alerts.length ? (
          <EmptyState title="No operational alerts" detail="Acknowledged alerts remain visible here." />
        ) : (
          <ol className="timeline-list">
            {alerts.map((alert) => (
              <li key={String(alert.notification_id)}>
                <StatusBadge value={String(alert.severity)} tone={alert.severity === "CRITICAL" ? "danger" : "warning"} />
                <div><strong>{String(alert.title)}</strong><p>{String(alert.detail)}</p></div>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}
