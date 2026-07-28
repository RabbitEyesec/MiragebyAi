import type { GraphEdge, GraphNode } from "@/models";

export interface CanonicalGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  sampled: boolean;
  total_nodes: number;
  total_edges: number;
}

export interface GraphFilters {
  sessionId?: string;
  nodeTypes?: ReadonlySet<string>;
  minimumConfidence?: number;
  evidenceOnly?: boolean;
  classifications?: ReadonlySet<string>;
  outputTags?: ReadonlySet<string>;
  from?: number;
  to?: number;
}

export function filterGraph(graph: CanonicalGraph, filters: GraphFilters): CanonicalGraph {
  const nodes = graph.nodes.filter((node) => {
    const time = Date.parse(node.event_time);
    return (
      (!filters.sessionId || !node.session_id || node.session_id === filters.sessionId) &&
      (!filters.nodeTypes?.size || filters.nodeTypes.has(node.node_type)) &&
      (filters.minimumConfidence === undefined ||
        (node.confidence ?? 1) >= filters.minimumConfidence) &&
      (!filters.evidenceOnly || node.evidence_references.length > 0) &&
      (!filters.classifications?.size || filters.classifications.has(node.classification)) &&
      (!filters.outputTags?.size ||
        (!!node.output_tag && filters.outputTags.has(node.output_tag))) &&
      (filters.from === undefined || time >= filters.from) &&
      (filters.to === undefined || time <= filters.to)
    );
  });
  const nodeIds = new Set(nodes.map((node) => node.node_id));
  const edges = graph.edges.filter(
    (edge) => nodeIds.has(edge.source_node_id) && nodeIds.has(edge.target_node_id),
  );
  return {
    nodes,
    edges,
    sampled: graph.sampled,
    total_nodes: graph.total_nodes,
    total_edges: graph.total_edges,
  };
}

export function sampleGraph(graph: CanonicalGraph, maximum: number): CanonicalGraph {
  if (graph.nodes.length <= maximum) return graph;
  const ordered = [...graph.nodes].sort((a, b) =>
    a.node_id.localeCompare(b.node_id),
  );
  const mandatory = ordered.filter((node) =>
    ["CASE", "EVIDENCE_OBJECT", "ALERT"].includes(node.node_type),
  );
  const mandatoryIds = new Set(mandatory.map((node) => node.node_id));
  const remainder = ordered.filter((node) => !mandatoryIds.has(node.node_id));
  const nodes = [...mandatory, ...remainder].slice(0, maximum);
  const nodeIds = new Set(nodes.map((node) => node.node_id));
  return {
    nodes,
    edges: graph.edges.filter(
      (edge) => nodeIds.has(edge.source_node_id) && nodeIds.has(edge.target_node_id),
    ),
    sampled: true,
    total_nodes: graph.total_nodes,
    total_edges: graph.total_edges,
  };
}

export function toCytoscapeElements(graph: CanonicalGraph) {
  return [
    ...graph.nodes.map((node) => ({
      group: "nodes" as const,
      data: { id: node.node_id, ...node },
    })),
    ...graph.edges.map((edge) => ({
      group: "edges" as const,
      data: {
        id: edge.edge_id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        ...edge,
      },
    })),
  ];
}

export function graphIdentity(graph: CanonicalGraph) {
  return {
    nodeIds: graph.nodes.map((node) => node.node_id).sort(),
    edgeIds: graph.edges.map((edge) => edge.edge_id).sort(),
    evidence: graph.nodes
      .map((node) => [node.node_id, [...node.evidence_references].sort()] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
    sourceEvents: graph.nodes
      .map((node) => [node.node_id, [...node.source_event_ids].sort()] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
    classifications: graph.nodes
      .map((node) => [node.node_id, node.classification] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
    outputTags: graph.nodes
      .map((node) => [node.node_id, node.output_tag ?? null] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
  };
}

export function buildThreeSceneData(graph: CanonicalGraph) {
  const ordered = [...graph.nodes].sort((a, b) =>
    a.node_id.localeCompare(b.node_id),
  );
  const positions = new Map(
    ordered.map((node, index) => {
      const angle = index * 2.399963229728653;
      const radius = 6 * Math.sqrt(index + 1);
      return [
        node.node_id,
        {
          x: Math.cos(angle) * radius,
          y: ((index % 7) - 3) * 2.4,
          z: Math.sin(angle) * radius,
        },
      ] as const;
    }),
  );
  return { graph, positions };
}
