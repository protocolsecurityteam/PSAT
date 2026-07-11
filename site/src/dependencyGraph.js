/**
 * Dependency graph visualization — builds, lays out, and renders dependency
 * graphs produced by the PSAT dependency pipeline.
 *
 * Reuses shortenAddress + wrapText from graph.js for its SVG rendering.
 */

import { shortenAddress, wrapText } from "./graph.js";

// ── Helpers ────────────────────────────────────────────────────────────────

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Human-readable label for a call operation type. */
function opLabel(op) {
  const labels = {
    CALL: "call",
    STATICCALL: "static call",
    DELEGATECALL: "delegate call",
    CALLCODE: "call code",
    CREATE: "create",
    CREATE2: "create2",
    STATIC_REF: "bytecode ref",
    DELEGATES_TO: "delegates to",
    BEACON: "beacon",
  };
  return labels[op] || op;
}

/** Slot offsets for distributing edge connection points along a node side. */
function slotPercents(count) {
  if (count <= 0) return [];
  if (count === 1) return [50];
  const start = 18;
  const end = 82;
  const step = (end - start) / (count - 1);
  return Array.from({ length: count }, (_, i) => start + i * step);
}

// ── Node visuals by contract classification ────────────────────────────────

const NODE_STYLES = {
  target: {
    shape: "rect",
    width: 320,
    height: 160,
    fill: "#ecfeff",
    stroke: "#0f766e",
    text: "#134e4a",
  },
  proxy: {
    shape: "rect",
    width: 260,
    height: 136,
    fill: "#fff7ed",
    stroke: "#d97706",
    text: "#7c2d12",
  },
  implementation: {
    shape: "rect",
    width: 260,
    height: 136,
    fill: "#dcfce7",
    stroke: "#16a34a",
    text: "#14532d",
  },
  beacon: {
    shape: "circle",
    width: 160,
    height: 160,
    fill: "#f5f3ff",
    stroke: "#7c3aed",
    text: "#3b0764",
  },
  factory: {
    shape: "rect",
    width: 260,
    height: 136,
    fill: "#fff1f2",
    stroke: "#e11d48",
    text: "#4c0519",
  },
  created: {
    shape: "rect",
    width: 240,
    height: 128,
    fill: "#fdf2f8",
    stroke: "#db2777",
    text: "#831843",
  },
  library: {
    shape: "rect",
    width: 260,
    height: 136,
    fill: "#eff6ff",
    stroke: "#2563eb",
    text: "#1e3a5f",
  },
  regular: {
    shape: "rect",
    width: 240,
    height: 128,
    fill: "#f1f5f9",
    stroke: "#64748b",
    text: "#1e293b",
  },
};

function nodeVisual(node) {
  if (node.is_proxy_context) return NODE_STYLES.proxy;
  if (node.is_target) return NODE_STYLES.target;
  return NODE_STYLES[node.type] || NODE_STYLES.regular;
}

/** Meta text shown on a node — summarizes type + discovery source. */
function nodeMeta(node) {
  if (node.is_proxy_context) return node.proxy_type ? `PROXY · ${node.proxy_type.toUpperCase()}` : "PROXY";
  if (node.is_target) return node.type === "implementation" ? "TARGET · IMPLEMENTATION" : "TARGET";
  const parts = [];
  const type = node.proxy_type || node.type || "regular";
  parts.push(type.toUpperCase());
  if (node.source?.length) {
    parts.push(node.source.join("+"));
  }
  return parts.join(" · ");
}

// ── Graph building ─────────────────────────────────────────────────────────

/**
 * Build a visual graph from the dependency_graph_viz.json data.
 *
 * @param {object} data - The output of build_dependency_visualization() from Python.
 * @returns {{ nodes: object[], edges: object[] } | null}
 */
export function buildDependencyGraph(data) {
  if (!data?.nodes?.length) return null;

  const nodes = data.nodes.map((n) => {
    const visual = nodeVisual(n);
    return {
      ...n,
      title: n.label || shortenAddress(n.address),
      subtitle: shortenAddress(n.address),
      meta: nodeMeta(n),
      kind: n.is_target ? "target" : n.type,
      ...visual,
    };
  });

  // Collapse multiple edges between the same pair into one with a combined label
  const edgeMap = new Map();
  for (const e of data.edges || []) {
    const key = `${e.from}|${e.to}`;
    const label = e.function_name
      ? `${opLabel(e.op)} ${e.function_name}()`
      : opLabel(e.op);
    if (edgeMap.has(key)) {
      edgeMap.get(key).labels.push(label);
    } else {
      edgeMap.set(key, { ...e, labels: [label] });
    }
  }
  const edges = Array.from(edgeMap.values()).map((e) => ({
    ...e,
    label: e.labels.join(" + "),
  }));

  return { nodes, edges };
}

// ── Layout ─────────────────────────────────────────────────────────────────

/**
 * Assign depth levels via BFS from the target node, then position nodes in
 * columns (left = target, right = deeper dependencies).
 */
export function layoutDependencyGraph(graph) {
  if (!graph) return null;

  // Build adjacency from edges (from → to)
  const outgoing = new Map();
  for (const edge of graph.edges) {
    const list = outgoing.get(edge.from) || [];
    list.push(edge.to);
    outgoing.set(edge.from, list);
  }

  // BFS to assign depth
  const depthMap = new Map();
  const targetNode = graph.nodes.find((n) => n.is_target);
  if (!targetNode) return null;

  const queue = [targetNode.id];
  depthMap.set(targetNode.id, 0);

  while (queue.length) {
    const current = queue.shift();
    const currentDepth = depthMap.get(current);
    for (const neighbor of outgoing.get(current) || []) {
      if (!depthMap.has(neighbor)) {
        depthMap.set(neighbor, currentDepth + 1);
        queue.push(neighbor);
      }
    }
  }

  // Proxy context nodes go to depth -1 (left of target)
  for (const node of graph.nodes) {
    if (node.is_proxy_context && !depthMap.has(node.id)) {
      depthMap.set(node.id, -1);
    }
  }

  // Assign orphan nodes (not reachable from target) to depth 1
  for (const node of graph.nodes) {
    if (!depthMap.has(node.id)) {
      depthMap.set(node.id, 1);
    }
  }

  // Shift all depths so minimum is 0
  const minDepth = Math.min(...depthMap.values(), 0);
  if (minDepth < 0) {
    for (const [id, d] of depthMap) depthMap.set(id, d - minDepth);
  }

  // Group by depth
  const maxDepth = Math.max(...depthMap.values(), 0);
  const columns = Array.from({ length: maxDepth + 1 }, () => []);
  for (const node of graph.nodes) {
    const depth = depthMap.get(node.id) || 0;
    columns[depth].push(node);
  }

  // Layout constants
  const marginX = 80;
  const colGap = 520;
  const nodeGapY = 96;

  // Calculate stage dimensions
  const stageWidth = marginX * 2 + (maxDepth + 1) * colGap;
  const tallestColumn = Math.max(
    ...columns.map((col) =>
      col.reduce((sum, n) => sum + n.height, 0) + Math.max(col.length - 1, 0) * nodeGapY
    ),
    400,
  );
  const stageHeight = tallestColumn + 200;

  // Build proxy → implementation Y-alignment map from DELEGATES_TO / BEACON edges.
  // Key = impl/beacon node id, Value = proxy node id whose Y it should match.
  const alignTo = new Map();
  for (const edge of graph.edges) {
    if (edge.op === "DELEGATES_TO" || edge.op === "BEACON") {
      alignTo.set(edge.to, edge.from);
    }
  }

  // Position each column (initial pass)
  const positioned = new Map();
  for (let depth = 0; depth <= maxDepth; depth++) {
    const col = columns[depth];
    const x = marginX + depth * colGap;
    const totalHeight =
      col.reduce((sum, n) => sum + n.height, 0) + Math.max(col.length - 1, 0) * nodeGapY;
    let y = Math.max(80, (stageHeight - totalHeight) / 2);

    for (const node of col) {
      positioned.set(node.id, { ...node, x, y, depth });
      y += node.height + nodeGapY;
    }
  }

  // Snap implementation/beacon nodes to the Y of their proxy so the
  // DELEGATES_TO / BEACON edges run straight across.
  for (const [implId, proxyId] of alignTo) {
    const impl = positioned.get(implId);
    const proxy = positioned.get(proxyId);
    if (impl && proxy) {
      // Align vertical centers
      const proxyCenterY = proxy.y + proxy.height / 2;
      impl.y = proxyCenterY - impl.height / 2;
    }
  }

  // After snapping, un-pinned nodes in the same column may overlap.
  // Re-spread each column: pinned nodes keep their Y, others fill gaps.
  for (let depth = 0; depth <= maxDepth; depth++) {
    const col = columns[depth].map((n) => positioned.get(n.id)).filter(Boolean);
    if (col.length < 2) continue;

    const pinned = new Set();
    for (const node of col) {
      if (alignTo.has(node.id)) pinned.add(node.id);
    }
    if (!pinned.size) continue; // nothing was snapped in this column

    // Sort by current Y so we process top-to-bottom
    col.sort((a, b) => a.y - b.y);

    // Push unpinned nodes so they don't overlap pinned ones
    for (let i = 1; i < col.length; i++) {
      const prev = col[i - 1];
      const curr = col[i];
      const minY = prev.y + prev.height + nodeGapY;
      if (curr.y < minY) {
        curr.y = minY;
      }
    }
  }

  // Resolve edge endpoints
  const positionedEdges = graph.edges
    .map((edge) => ({
      ...edge,
      from: positioned.get(edge.from),
      to: positioned.get(edge.to),
    }))
    .filter((e) => e.from && e.to);

  return {
    width: stageWidth,
    height: stageHeight,
    nodes: Array.from(positioned.values()),
    edges: positionedEdges,
  };
}

// ── Edge geometry (cubic Bézier curves) ────────────────────────────────────

/**
 * Compute SVG path data for each edge, distributing connection points across
 * node sides using slot offsets (same approach as the permission graph).
 */
export function computeEdgeGeometry(layout) {
  if (!layout) return [];

  const outgoingByNode = new Map();
  const incomingByNode = new Map();

  for (const edge of layout.edges) {
    const out = outgoingByNode.get(edge.from.id) || [];
    out.push(edge);
    outgoingByNode.set(edge.from.id, out);

    const inc = incomingByNode.get(edge.to.id) || [];
    inc.push(edge);
    incomingByNode.set(edge.to.id, inc);
  }

  return layout.edges.map((edge) => {
    const outList = outgoingByNode.get(edge.from.id) || [];
    const inList = incomingByNode.get(edge.to.id) || [];
    const sourceIdx = outList.indexOf(edge);
    const targetIdx = inList.indexOf(edge);
    const sourceSlots = slotPercents(outList.length);
    const targetSlots = slotPercents(inList.length);

    const startX = edge.from.x + edge.from.width;
    const startY = edge.from.y + (edge.from.height * (sourceSlots[sourceIdx] || 50)) / 100;
    const endX = edge.to.x;
    const endY = edge.to.y + (edge.to.height * (targetSlots[targetIdx] || 50)) / 100;
    const curve = Math.max(50, (endX - startX) / 2.2);

    return {
      ...edge,
      startX,
      startY,
      endX,
      endY,
      path: `M ${startX} ${startY} C ${startX + curve} ${startY}, ${endX - curve} ${endY}, ${endX} ${endY}`,
    };
  });
}

// ── SVG rendering helpers ──────────────────────────────────────────────────

/**
 * Generate static SVG markup for a positioned dependency node.
 */
export function svgDependencyNodeMarkup(node) {
  const isRect = node.shape === "rect";
  const maxChars = isRect ? 28 : 16;
  const titleLines = wrapText(node.title, maxChars, isRect ? 2 : 3);
  const subtitleLines = wrapText(node.subtitle, maxChars, 2);
  const metaLines = wrapText(node.meta, maxChars, 2);

  const centerX = node.width / 2;
  const centerY = node.height / 2;
  const titleStartY = isRect ? 30 : centerY - 26;
  const subtitleStartY = titleStartY + titleLines.length * 16 + 12;
  const metaStartY = subtitleStartY + subtitleLines.length * 16 + 16;

  function block(lines, className, startY) {
    return lines
      .map(
        (line, i) =>
          `<text class="${className}" x="0" y="${startY + i * 16}" text-anchor="middle">${escapeHtml(line)}</text>`,
      )
      .join("");
  }

  const body =
    node.shape === "circle"
      ? `<ellipse cx="${centerX}" cy="${centerY}" rx="${node.width / 2}" ry="${node.height / 2}" />`
      : `<rect x="0" y="0" width="${node.width}" height="${node.height}" rx="18" ry="18" />`;

  return `
    <g class="graph-svg-node dep-${escapeHtml(node.kind)}" transform="translate(${node.x}, ${node.y})" data-node-id="${escapeHtml(node.id)}">
      <g class="graph-svg-shape" fill="${node.fill}" stroke="${node.stroke}" stroke-width="3">
        ${body}
      </g>
      <g transform="translate(${centerX}, ${titleStartY})" fill="${node.text}">
        ${block(titleLines, "graph-svg-title", 0)}
        ${block(subtitleLines, "graph-svg-subtitle", subtitleLines.length ? subtitleStartY - titleStartY : 0)}
        ${block(metaLines, "graph-svg-meta", metaLines.length ? metaStartY - titleStartY : 0)}
      </g>
    </g>
  `;
}

// ── Full pipeline (data → layout → React Flow format) ──────────────────────

/**
 * One-shot: build, layout, and convert to React Flow compatible nodes/edges.
 * This is the main entry point for the DependencyGraphTab component.
 */
export function buildReactFlowDependencyGraph(data) {
  const graph = buildDependencyGraph(data);
  if (!graph) return null;

  const layout = layoutDependencyGraph(graph);
  if (!layout) return null;

  const geometry = computeEdgeGeometry(layout);

  const outgoingByNode = new Map();
  const incomingByNode = new Map();
  for (const edge of layout.edges) {
    const out = outgoingByNode.get(edge.from.id) || [];
    out.push(edge);
    outgoingByNode.set(edge.from.id, out);
    const inc = incomingByNode.get(edge.to.id) || [];
    inc.push(edge);
    incomingByNode.set(edge.to.id, inc);
  }

  const nodes = layout.nodes.map((node) => {
    const outgoing = outgoingByNode.get(node.id) || [];
    const incoming = incomingByNode.get(node.id) || [];
    return {
      id: node.id,
      type: "dependencyNode",
      position: { x: node.x, y: node.y },
      draggable: false,
      selectable: true,
      data: {
        title: node.title,
        subtitle: node.subtitle,
        meta: node.meta,
        kind: node.kind,
        contractType: node.type,
        proxyType: node.proxy_type,
        address: node.address,
        source: node.source,
        isTarget: node.is_target,
        sourceHandles: slotPercents(outgoing.length).map((top, i) => ({
          id: `source-${i}`,
          top,
        })),
        targetHandles: slotPercents(incoming.length).map((top, i) => ({
          id: `target-${i}`,
          top,
        })),
      },
      rawNode: node,
      style: { width: node.width, height: node.height },
    };
  });

  const edges = geometry.map((edge, index) => {
    const sourceIndex = (outgoingByNode.get(edge.from.id) || []).indexOf(
      layout.edges.find((e) => e === layout.edges[index]),
    );
    const targetIndex = (incomingByNode.get(edge.to.id) || []).indexOf(
      layout.edges.find((e) => e === layout.edges[index]),
    );
    return {
      id: `${edge.from.id}-${edge.to.id}-${index}`,
      source: edge.from.id,
      target: edge.to.id,
      sourceHandle: sourceIndex >= 0 ? `source-${sourceIndex}` : undefined,
      targetHandle: targetIndex >= 0 ? `target-${targetIndex}` : undefined,
      label: edge.label || "",
      animated: false,
      selectable: false,
      focusable: false,
      type: "smoothstep",
      className: "rf-edge",
      markerEnd: {
        type: "arrowclosed",
        width: 18,
        height: 18,
        color: "rgba(34, 29, 23, 0.24)",
      },
      data: edge,
    };
  });

  return { width: layout.width, height: layout.height, nodes, edges, geometry };
}
