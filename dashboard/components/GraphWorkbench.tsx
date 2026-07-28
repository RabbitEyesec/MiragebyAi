"use client";

import { useCallback, useMemo, useState } from "react";

import { Graph2D } from "@/components/Graph2D";
import { Graph3D } from "@/components/Graph3D";
import { ClassificationBadge, OutputTagBadge } from "@/components/StatusBadge";
import {
  filterGraph,
  sampleGraph,
  type CanonicalGraph,
  type GraphFilters,
} from "@/lib/graph";
import type { GraphNode } from "@/models";

export function GraphWorkbench({ graph }: { graph: CanonicalGraph }) {
  const [dimension, setDimension] = useState<"2D" | "3D">("2D");
  const [search, setSearch] = useState("");
  const [evidenceOnly, setEvidenceOnly] = useState(false);
  const [minimumConfidence, setMinimumConfidence] = useState(0);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [layout, setLayout] = useState<"circle" | "breadthfirst" | "grid">("circle");
  const [paused, setPaused] = useState(false);
  const [speed, setSpeed] = useState(1);
  const reducedMotion =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const filters: GraphFilters = { evidenceOnly, minimumConfidence };
  const filtered = useMemo(() => {
    const base = filterGraph(graph, filters);
    const searched = search
      ? {
          ...base,
          nodes: base.nodes.filter(
            (node) =>
              node.label.toLowerCase().includes(search.toLowerCase()) ||
              node.node_id.toLowerCase().includes(search.toLowerCase()),
          ),
        }
      : base;
    const ids = new Set(searched.nodes.map((node) => node.node_id));
    return sampleGraph(
      {
        ...searched,
        edges: searched.edges.filter(
          (edge) => ids.has(edge.source_node_id) && ids.has(edge.target_node_id),
        ),
      },
      5000,
    );
  }, [evidenceOnly, graph, minimumConfidence, search]);
  const select = useCallback((node: GraphNode) => setSelected(node), []);

  return (
    <div className="graph-workbench">
      <div className="filter-bar" aria-label="Graph filters">
        <label>
          Search
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Node label or ID" />
        </label>
        <label>
          Confidence ≥ {minimumConfidence.toFixed(1)}
          <input
            type="range"
            min="0"
            max="1"
            step="0.1"
            value={minimumConfidence}
            onChange={(event) => setMinimumConfidence(Number(event.target.value))}
          />
        </label>
        <label className="check-label">
          <input type="checkbox" checked={evidenceOnly} onChange={(event) => setEvidenceOnly(event.target.checked)} />
          Evidence only
        </label>
        <div className="segmented" role="group" aria-label="Graph dimension">
          {(["2D", "3D"] as const).map((value) => (
            <button key={value} className={dimension === value ? "active" : ""} onClick={() => setDimension(value)} type="button">
              {value}
            </button>
          ))}
        </div>
        {dimension === "2D" ? (
          <select aria-label="Graph layout" value={layout} onChange={(event) => setLayout(event.target.value as typeof layout)}>
            <option value="circle">Relationship</option>
            <option value="breadthfirst">Process tree</option>
            <option value="grid">Network grid</option>
          </select>
        ) : (
          <>
            <button type="button" onClick={() => setPaused((value) => !value)}>{paused ? "Play" : "Pause"}</button>
            <select aria-label="Playback speed" value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
              <option value={0.5}>0.5×</option>
              <option value={1}>1×</option>
              <option value={2}>2×</option>
              <option value={4}>4×</option>
            </select>
          </>
        )}
      </div>
      {filtered.sampled && (
        <div className="sampling-warning" role="status">
          Sampling active: rendering {filtered.nodes.length} of {filtered.total_nodes} nodes.
        </div>
      )}
      <div className="graph-layout">
        {dimension === "2D" ? (
          <Graph2D graph={filtered} onSelect={select} layout={layout} />
        ) : (
          <Graph3D graph={filtered} onSelect={select} paused={paused} reducedMotion={reducedMotion} speed={speed} />
        )}
        <aside className="detail-panel" aria-label="Graph item details" tabIndex={-1}>
          {selected ? (
            <>
              <p className="eyebrow">{selected.node_type.replaceAll("_", " ")}</p>
              <h3>{selected.label}</h3>
              <ClassificationBadge value={selected.classification} />
              <OutputTagBadge value={selected.output_tag} />
              <dl>
                <dt>Stable ID</dt><dd className="mono">{selected.node_id}</dd>
                <dt>Source events</dt><dd>{selected.source_event_ids.length || "None"}</dd>
                <dt>Evidence pivots</dt><dd>{selected.evidence_references.length || "None"}</dd>
              </dl>
              <div className="pivot-list">
                {selected.evidence_references.map((id) => <a key={id} href={`#evidence-${encodeURIComponent(id)}`}>Evidence {id}</a>)}
                {selected.source_event_ids.map((id) => <a key={id} href={`#event-${encodeURIComponent(id)}`}>Event {id}</a>)}
              </div>
            </>
          ) : (
            <p>Select a node to inspect the exact timeline, event, evidence, policy, and AI pivots.</p>
          )}
        </aside>
      </div>
    </div>
  );
}
