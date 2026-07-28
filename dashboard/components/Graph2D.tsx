"use client";

import cytoscape, { type Core } from "cytoscape";
import { useEffect, useRef } from "react";

import { toCytoscapeElements, type CanonicalGraph } from "@/lib/graph";
import type { GraphNode } from "@/models";

export function Graph2D({
  graph,
  onSelect,
  layout = "circle",
}: {
  graph: CanonicalGraph;
  onSelect: (node: GraphNode) => void;
  layout?: "circle" | "breadthfirst" | "grid";
}) {
  const container = useRef<HTMLDivElement>(null);
  const instance = useRef<Core | null>(null);

  useEffect(() => {
    if (!container.current) return;
    const cy = cytoscape({
      container: container.current,
      elements: toCytoscapeElements(graph),
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#dce8ef",
            "font-size": "9px",
            "text-wrap": "ellipsis",
            "text-max-width": "110px",
            "background-color": "#1fa8a5",
            "border-color": "#071217",
            "border-width": 2,
            width: 28,
            height: 28,
          },
        },
        {
          selector: 'node[classification = "AI_INFERENCE"]',
          style: { "background-color": "#b978ff", shape: "diamond" },
        },
        {
          selector: 'node[classification = "ANALYST_ACTION"]',
          style: { "background-color": "#ffb55e", shape: "round-rectangle" },
        },
        {
          selector: 'node[node_type = "EVIDENCE_OBJECT"]',
          style: { "background-color": "#63d78a", shape: "hexagon" },
        },
        {
          selector: 'node[node_type = "CASE"]',
          style: { "background-color": "#e8f4f6", width: 42, height: 42 },
        },
        {
          selector: "edge",
          style: {
            width: 1.4,
            "line-color": "#365461",
            "target-arrow-color": "#557784",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            opacity: 0.78,
          },
        },
        { selector: ":selected", style: { "border-color": "#ffda78", "border-width": 4 } },
      ],
      layout: { name: layout, animate: false, fit: true, padding: 30 },
    });
    cy.on("tap", "node", (event) => {
      const nodeId = event.target.id();
      const node = graph.nodes.find((candidate) => candidate.node_id === nodeId);
      if (node) onSelect(node);
    });
    instance.current = cy;
    return () => {
      instance.current = null;
      cy.destroy();
    };
  }, [graph, layout, onSelect]);

  function exportImage() {
    const uri = instance.current?.png({ full: true, scale: 2, bg: "#071217" });
    if (!uri) return;
    const link = document.createElement("a");
    link.download = "mirage-case-graph.png";
    link.href = uri;
    link.click();
  }

  return (
    <section className="graph-panel" aria-label="2D relationship graph">
      <div className="graph-toolbar">
        <span>Cytoscape 2D</span>
        <button type="button" onClick={() => instance.current?.fit(undefined, 30)}>
          Fit
        </button>
        <button type="button" onClick={() => instance.current?.reset()}>
          Reset
        </button>
        <button type="button" onClick={exportImage}>
          Export image
        </button>
      </div>
      <div ref={container} className="graph-canvas" role="img" aria-label={`${graph.nodes.length} nodes and ${graph.edges.length} edges`} />
    </section>
  );
}
