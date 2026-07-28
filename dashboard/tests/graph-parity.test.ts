import { describe, expect, it } from "vitest";

import {
  buildThreeSceneData,
  filterGraph,
  graphIdentity,
  toCytoscapeElements,
} from "@/lib/graph";
import { model } from "@/tests/fixtures";

describe("2D/3D canonical parity", () => {
  it("uses the same node, edge, evidence, event, classification, and output-tag sets", () => {
    const filtered = filterGraph(model.graph, {});
    const twoDimensional = {
      ...filtered,
      nodes: toCytoscapeElements(filtered)
        .filter((item) => item.group === "nodes")
        .map((item) => filtered.nodes.find((node) => node.node_id === item.data.id)!),
      edges: filtered.edges,
    };
    const threeDimensional = buildThreeSceneData(filtered).graph;
    expect(graphIdentity(twoDimensional)).toEqual(graphIdentity(threeDimensional));
  });
});
