import { describe, expect, it } from "vitest";

import { buildThreeSceneData, sampleGraph } from "@/lib/graph";
import { caseNode } from "@/tests/fixtures";

function largeGraph(size: number) {
  const nodes = Array.from({ length: size }, (_, index) => ({
    ...caseNode,
    node_id: `process:${String(index).padStart(6, "0")}`,
    node_type: "PROCESS" as const,
  }));
  return { nodes, edges: [], sampled: false, total_nodes: size, total_edges: 0 };
}

describe("Three.js scene input", () => {
  it.each([1000, 5000])("produces deterministic positions for %i nodes", (size) => {
    const graph = largeGraph(size);
    const first = buildThreeSceneData(graph);
    const second = buildThreeSceneData(graph);
    expect(first.positions.get(graph.nodes[999].node_id)).toEqual(
      second.positions.get(graph.nodes[999].node_id),
    );
    expect(first.positions.size).toBe(size);
  });

  it("samples explicitly at the configured maximum", () => {
    const graph = largeGraph(6000);
    const sampled = sampleGraph(graph, 5000);
    expect(sampled.sampled).toBe(true);
    expect(sampled.nodes).toHaveLength(5000);
    expect(sampled.total_nodes).toBe(6000);
  });
});
