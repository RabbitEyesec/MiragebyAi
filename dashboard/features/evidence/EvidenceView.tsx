import { EmptyState } from "@/components/AsyncState";
import { StatusBadge } from "@/components/StatusBadge";
import { formatUtc } from "@/lib/format";
import type { EvidenceCard } from "@/models";

export function EvidenceView({ evidence }: { evidence: EvidenceCard[] | null }) {
  if (!evidence?.length) return <EmptyState title="Evidence Board is empty" detail="No authorised evidence metadata is linked to this case." />;
  return (
    <div className="evidence-grid">
      {evidence.map((item) => (
        <article className="evidence-card" id={`evidence-${item.evidence_id}`} key={item.evidence_id}>
          <div className="section-heading"><p className="eyebrow">{item.type}</p><StatusBadge value={item.verification_status} tone={item.verification_status === "VERIFIED" ? "good" : "warning"} /></div>
          <h3>{item.filename ?? "Unnamed evidence object"}</h3>
          <p>{item.media_type} · {item.size_bytes.toLocaleString("en-GB")} bytes</p>
          <dl className="detail-list">
            <dt>Evidence ID</dt><dd className="mono">{item.evidence_id}</dd>
            <dt>SHA-256</dt><dd className="mono wrap">{item.sha256}</dd>
            <dt>Source sequence</dt><dd>{item.source} / {item.sequence}</dd>
            <dt>Acquired</dt><dd>{formatUtc(item.acquisition_time)}</dd>
            <dt>S3 version</dt><dd className="mono">{item.s3_version_id}</dd>
            <dt>Object Lock</dt><dd>{item.object_lock.mode ?? "Not reported"} · {formatUtc(item.object_lock.retention_until)}</dd>
            <dt>Classification</dt><dd>{item.classification}</dd>
          </dl>
          <div className="button-row">
            <button type="button" disabled>Request verification</button>
            <button type="button" disabled>Authorised download</button>
            <a href={`#event-${encodeURIComponent(item.related_events[0] ?? "")}`}>Open source event</a>
          </div>
        </article>
      ))}
    </div>
  );
}
