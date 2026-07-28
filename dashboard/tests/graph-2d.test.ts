import { describe, expect, it } from "vitest";

import { filterGraph, toCytoscapeElements } from "@/lib/graph";
import { caseNode, edge, evidenceNode } from "@/tests/fixtures";

const graph = {
  nodes: [caseNode, evidenceNode],
  edges: [edge],
  sampled: false,
  total_nodes: 2,
  total_edges: 1,
};

describe("Cytoscape conversion", () => {
  it("preserves stable IDs and evidence pivots", () => {
    const elements = toCytoscapeElements(graph);
    expect(elements).toHaveLength(3);
    expect(elements[1].data.id).toBe(evidenceNode.node_id);
    expect(elements[1].data.evidence_references).toEqual([evidenceNode.evidence_references[0]]);
    const edgeElement = elements.find((element) => element.group === "edges");
    expect(edgeElement?.data.source).toBe(evidenceNode.node_id);
  });

  it("applies evidence and confidence filters to the canonical model", () => {
    const filtered = filterGraph(graph, { evidenceOnly: true, minimumConfidence: 0.8 });
    expect(filtered.nodes.map((node) => node.node_id)).toEqual([evidenceNode.node_id]);
    expect(filtered.edges).toEqual([]);
  });
});
