"use client";

import * as THREE from "three";
import { useEffect, useRef } from "react";

import { buildThreeSceneData, type CanonicalGraph } from "@/lib/graph";
import type { GraphNode } from "@/models";

const colours: Record<string, number> = {
  AI_INFERENCE: 0xb978ff,
  ANALYST_ACTION: 0xffb55e,
  OBSERVED_FACT: 0x1fa8a5,
  DETERMINISTIC_CORRELATION: 0x6eb8ff,
  SYSTEM_ACTION: 0x91a7b1,
};

export function Graph3D({
  graph,
  paused,
  reducedMotion,
  speed,
  onSelect,
}: {
  graph: CanonicalGraph;
  paused: boolean;
  reducedMotion: boolean;
  speed: number;
  onSelect: (node: GraphNode) => void;
}) {
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!container.current || typeof WebGLRenderingContext === "undefined") return;
    const width = container.current.clientWidth || 800;
    const height = container.current.clientHeight || 520;
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    container.current.replaceChildren(renderer.domElement);
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x071217, 0.008);
    const camera = new THREE.PerspectiveCamera(55, width / height, 0.1, 2000);
    camera.position.set(0, 24, 80);
    scene.add(new THREE.AmbientLight(0xffffff, 1.4));
    const group = new THREE.Group();
    scene.add(group);
    const { positions } = buildThreeSceneData(graph);
    const meshes = new Map<string, THREE.Mesh>();
    for (const node of graph.nodes) {
      const geometry = new THREE.SphereGeometry(node.node_type === "CASE" ? 2.6 : 1.25, 16, 12);
      const material = new THREE.MeshStandardMaterial({
        color: colours[node.classification] ?? 0x91a7b1,
        roughness: 0.55,
        metalness: 0.15,
      });
      const mesh = new THREE.Mesh(geometry, material);
      const position = positions.get(node.node_id);
      if (position) mesh.position.set(position.x, position.y, position.z);
      mesh.userData.nodeId = node.node_id;
      meshes.set(node.node_id, mesh);
      group.add(mesh);
    }
    const lineMaterial = new THREE.LineBasicMaterial({ color: 0x365461, transparent: true, opacity: 0.7 });
    for (const edge of graph.edges) {
      const source = meshes.get(edge.source_node_id);
      const target = meshes.get(edge.target_node_id);
      if (!source || !target) continue;
      const geometry = new THREE.BufferGeometry().setFromPoints([
        source.position,
        target.position,
      ]);
      group.add(new THREE.Line(geometry, lineMaterial));
    }
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const pick = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects([...meshes.values()])[0];
      const node = graph.nodes.find((item) => item.node_id === hit?.object.userData.nodeId);
      if (node) onSelect(node);
    };
    renderer.domElement.addEventListener("pointerdown", pick);
    let frame = 0;
    const animate = () => {
      frame = requestAnimationFrame(animate);
      if (!paused && !reducedMotion) group.rotation.y += 0.0008 * speed;
      renderer.render(scene, camera);
    };
    animate();
    const resize = new ResizeObserver(([entry]) => {
      const nextWidth = entry.contentRect.width;
      const nextHeight = entry.contentRect.height;
      if (!nextWidth || !nextHeight) return;
      camera.aspect = nextWidth / nextHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(nextWidth, nextHeight);
    });
    resize.observe(container.current);
    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
      renderer.domElement.removeEventListener("pointerdown", pick);
      for (const mesh of meshes.values()) {
        mesh.geometry.dispose();
        (mesh.material as THREE.Material).dispose();
      }
      lineMaterial.dispose();
      renderer.dispose();
    };
  }, [graph, onSelect, paused, reducedMotion, speed]);

  return (
    <section className="graph-panel" aria-label="3D relationship graph">
      <div className="graph-toolbar">
        <span>Three.js 3D</span>
        <span>{reducedMotion ? "Reduced motion" : paused ? "Paused" : `${speed}× playback`}</span>
      </div>
      <div ref={container} className="graph-canvas graph-3d" role="img" aria-label={`${graph.nodes.length} canonical 3D nodes`} />
    </section>
  );
}
