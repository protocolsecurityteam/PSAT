
import ELK from "elkjs/lib/elk.bundled.js";

import { assignGroups, buildGroupControllers } from "./groupAssignment.js";
import { aggregateEdges, assignEdgeLanes } from "./edgeAggregation.js";
import {
  CHILD_H,
  CHILD_W,
  PRINCIPAL_H,
  PRINCIPAL_W,
  groupHeaderHeight,
  layoutGroupInterior,
} from "./nodeSizing.js";
import { attachObstacles } from "./edgeObstacles.js";

const elk = new ELK();

function hierarchicalLayout(machines, edgePairs) {
  const n = machines.length;
  if (n === 0) return [];
  if (n === 1) return [{ x: 0, y: 0 }];

  const addrToIdx = new Map();
  machines.forEach((m, i) => addrToIdx.set(m.address?.toLowerCase(), i));

  const children = new Map(); // idx → Set<idx> (who this node controls)
  const parents = new Map();  // idx → Set<idx> (who controls this node)
  for (let i = 0; i < n; i++) { children.set(i, new Set()); parents.set(i, new Set()); }

  for (const [from, to] of edgePairs) {
    const fi = addrToIdx.get(from);
    const ti = addrToIdx.get(to);
    if (fi !== undefined && ti !== undefined && fi !== ti) {
      children.get(fi).add(ti);
      parents.get(ti).add(fi);
    }
  }

  const tier = new Array(n).fill(-1);
  const roots = [];
  for (let i = 0; i < n; i++) {
    if (parents.get(i).size === 0) roots.push(i);
  }
  // No roots (cycles): start from the node with most children.
  if (roots.length === 0) {
    let best = 0;
    for (let i = 1; i < n; i++) {
      if (children.get(i).size > children.get(best).size) best = i;
    }
    roots.push(best);
  }

  const queue = [...roots];
  for (const r of roots) tier[r] = 0;

  const MAX_TIER = 20;
  while (queue.length > 0) {
    const curr = queue.shift();
    const nextTier = tier[curr] + 1;
    if (nextTier > MAX_TIER) continue;
    for (const child of children.get(curr)) {
      if (tier[child] < nextTier) {
        tier[child] = nextTier;
        queue.push(child);
      }
    }
  }

  const maxTier = Math.max(0, ...tier.filter((t) => t >= 0));
  for (let i = 0; i < n; i++) {
    if (tier[i] < 0) tier[i] = maxTier + 1;
  }

  const tiers = new Map();
  for (let i = 0; i < n; i++) {
    if (!tiers.has(tier[i])) tiers.set(tier[i], []);
    tiers.get(tier[i]).push(i);
  }

  const outCount = new Array(n).fill(0);
  const inCount = new Array(n).fill(0);
  const hasEdge = new Set();
  for (const [from, to] of edgePairs) {
    const fi = addrToIdx.get(from);
    const ti = addrToIdx.get(to);
    if (fi !== undefined) { outCount[fi]++; hasEdge.add(fi); }
    if (ti !== undefined) { inCount[ti]++; hasEdge.add(ti); }
  }

  const connected = [];
  const isolated = [];
  for (let i = 0; i < n; i++) {
    if (hasEdge.has(i)) connected.push(i);
    else isolated.push(i);
  }

  connected.sort((a, b) => {
    const sa = outCount[a] - inCount[a];
    const sb = outCount[b] - inCount[b];
    if (sb !== sa) return sb - sa;
    return outCount[b] - outCount[a];
  });

  const NODE_W = 250;
  const NODE_H = 160;
  const colCount = n <= 9 ? 3 : n <= 20 ? 4 : 5;
  const spread = NODE_W * 1.15;
  const positions = new Array(n);

  for (let rank = 0; rank < connected.length; rank++) {
    const idx = connected[rank];
    const col = rank % colCount;
    const row = Math.floor(rank / colCount);
    const rowSpread = spread * (1 + row * 0.08);
    let x, y;
    y = row * NODE_H;
    const colOffset = (col - (colCount - 1) / 2) * rowSpread;
    const jx = ((rank * 7 + 13) % 30 - 15);
    const jy = ((rank * 11 + 7) % 16 - 8);
    x = colOffset + jx;
    y += jy;
    positions[idx] = { x: Math.round(x), y: Math.round(y) };
  }

  if (isolated.length > 0) {
    const cxs = connected.map((i) => positions[i].x);
    const cys = connected.map((i) => positions[i].y);
    const cx = connected.length > 0 ? (Math.min(...cxs) + Math.max(...cxs)) / 2 : 0;
    const cy = connected.length > 0 ? (Math.min(...cys) + Math.max(...cys)) / 2 : 0;
    const rx = connected.length > 0 ? (Math.max(...cxs) - Math.min(...cxs)) / 2 + NODE_W * 1.5 : NODE_W * 2;
    const ry = connected.length > 0 ? (Math.max(...cys) - Math.min(...cys)) / 2 + NODE_H * 1.3 : NODE_H * 2;

    for (let i = 0; i < isolated.length; i++) {
      const angle = (2 * Math.PI * i) / isolated.length - Math.PI / 2;
      positions[isolated[i]] = {
        x: Math.round(cx + Math.cos(angle) * rx),
        y: Math.round(cy + Math.sin(angle) * ry),
      };
    }
  }

  return positions;
}

// `bandHeights` ({ groupId: px }) reserves each group's measured header band; a
// constant estimate until measured.
export function buildGraphLayout(machines, fundFlows, principals, bandHeights = {}, chain = "ethereum") {
  const sorted = [...machines].sort((a, b) => b.totalFunctions - a.totalFunctions);
  const principalList = principals || [];
  const principalByAddr = new Map();
  for (const p of principalList) {
    if (p.address) principalByAddr.set(p.address.toLowerCase(), p);
  }

  const { contractToGroup, groupChildren } = assignGroups(sorted, principalList);

  // Principals are positioned relative to what they control.
  const contractEntities = sorted.map((m) => ({ address: m.address?.toLowerCase(), kind: "contract" }));

  const edgePairs = [];
  const byName = new Map();
  for (const m of sorted) {
    if (!m.name) continue;
    if (!byName.has(m.name)) byName.set(m.name, []);
    byName.get(m.name).push(m);
  }
  for (const [, group] of byName) {
    if (group.length < 2) continue;
    const proxy = group.find((g) => g.is_proxy);
    const impl = group.find((g) => !g.is_proxy);
    if (proxy && impl) edgePairs.push([proxy.address?.toLowerCase(), impl.address?.toLowerCase()]);
  }
  const contractAddrs = new Set(contractEntities.map((e) => e.address));
  const allAddrs = new Set([...contractAddrs, ...principalList.map((p) => p.address?.toLowerCase())]);
  for (const flow of fundFlows || []) {
    const from = flow.from?.toLowerCase();
    const to = flow.to?.toLowerCase();
    if (from && to && contractAddrs.has(from) && contractAddrs.has(to)) {
      edgePairs.push([from, to]);
    }
  }

  // Only used if ELK fails.
  const fallbackPositions = hierarchicalLayout(contractEntities, edgePairs);
  const contractPositions = new Map();

  const groupTotalUsd = new Map();
  for (const [principalAddr, kids] of groupChildren) {
    let total = 0;
    for (const kid of kids) {
      const m = sorted.find((x) => x.address?.toLowerCase() === kid);
      if (m && m.total_usd) total += m.total_usd;
    }
    if (total > 0) groupTotalUsd.set(principalAddr, total);
  }

  const nameByAddr = new Map();
  for (const m of sorted) {
    if (m.address) nameByAddr.set(m.address.toLowerCase(), m.name || m.address);
  }

  // React Flow needs parents before children.
  const nodes = [];
  for (const [principalAddr, kids] of groupChildren) {
    const p = principalByAddr.get(principalAddr);
    if (!p) continue;
    const controllers = buildGroupControllers(p, kids, principalList, nameByAddr, chain);
    const measuredBand = bandHeights[p.address];
    const headerHeight = measuredBand != null ? measuredBand : groupHeaderHeight(controllers.length);
    nodes.push({
      id: p.address,
      type: "group",
      position: { x: 0, y: 0 },
      // Placeholder until the async layout resolves.
      style: { width: 400, height: 200 },
      data: {
        principal: p,
        childCount: kids.length,
        totalUsd: groupTotalUsd.get(principalAddr) || 0,
        controllers,
        headerHeight,
      },
    });
  }

  for (let i = 0; i < sorted.length; i++) {
    const m = sorted[i];
    const pos = fallbackPositions[i] || { x: 0, y: 0 };
    contractPositions.set(m.address?.toLowerCase(), pos);
    const groupAddr = contractToGroup.get(m.address?.toLowerCase());
    const node = {
      id: m.address,
      type: "contract",
      position: pos,
      data: { machine: m },
    };
    if (groupAddr) {
      // The group node's id is the original-cased address.
      const principalCanonical = principalByAddr.get(groupAddr)?.address || groupAddr;
      node.parentId = principalCanonical;
      node.extent = "parent";
    }
    nodes.push(node);
  }

  // Co-controllers render inside group accordions, not as rail nodes. The
  // permissionless long tail (other_callers) isn't rendered; per-function
  // caller buttons cover it.

  const edges = [];
  for (const [, group] of byName) {
    if (group.length < 2) continue;
    const proxy = group.find((g) => g.is_proxy);
    const impl = group.find((g) => !g.is_proxy);
    if (proxy && impl) {
      edges.push({
        id: `${proxy.address}-${impl.address}`,
        source: proxy.address,
        target: impl.address,
        sourceHandle: "ctrl-out",
        targetHandle: "ctrl-in",
        type: "smoothstep",
        style: { stroke: "#64748b", strokeWidth: 1 },
        animated: false,
      });
    }
  }

  // Principal-source edges are dropped: containment carries ownership, and the
  // fanout was the main source of spaghetti.
  const LANE_HANDLES = {
    control: { sourceHandle: "ctrl-out", targetHandle: "ctrl-in" },
    inflow:  { sourceHandle: "value-out", targetHandle: "value-in" },
    outflow: { sourceHandle: "value-out", targetHandle: "value-in" },
  };
  for (const flow of fundFlows || []) {
    const from = flow.from?.toLowerCase();
    const to = flow.to?.toLowerCase();
    if (!from || !to || !allAddrs.has(from) || !allAddrs.has(to)) continue;
    if (principalByAddr.has(from)) continue;
    const edgeId = `flow-${from}-${to}`;
    if (edges.some((e) => e.id === edgeId)) continue;
    const isValue = flow.type === "controls_value";
    const handles = LANE_HANDLES[flow.lane || "control"] || LANE_HANDLES.control;
    edges.push({
      id: edgeId,
      source: from,
      target: to,
      sourceHandle: handles.sourceHandle,
      targetHandle: handles.targetHandle,
      type: "smoothstep",
      style: { stroke: isValue ? "#7fc4b6" : "#94a3b8", strokeWidth: isValue ? 1.5 : 1 },
      animated: false,
      data: { capabilities: flow.capabilities || [], flowType: flow.type },
    });
  }

  // Kept out of aggregation: they give each box its caller→callee hierarchy.
  const intraGroupEdgesByGroup = new Map();
  const crossGroupEdges = [];
  for (const e of edges) {
    const fromLc = (e.source || "").toLowerCase();
    const toLc = (e.target || "").toLowerCase();
    const fromGroup = contractToGroup.get(fromLc);
    const toGroup = contractToGroup.get(toLc);
    if (fromGroup && toGroup && fromGroup === toGroup) {
      if (!intraGroupEdgesByGroup.has(fromGroup)) intraGroupEdgesByGroup.set(fromGroup, []);
      intraGroupEdgesByGroup.get(fromGroup).push(e);
    } else {
      crossGroupEdges.push(e);
    }
  }

  const aggregatedCrossEdges = aggregateEdges(crossGroupEdges, contractToGroup, principalList, sorted);

  // An empty group map keeps raw addresses, so child↔child pairs bundle instead
  // of collapsing to a self-loop. No cap filter: FP gating upstream already
  // removed the over-reach.
  const NO_GROUP_RESOLVE = new Map();
  const aggregatedIntraByGroup = new Map();
  const intraGroupRendered = [];
  for (const [groupAddr, list] of intraGroupEdgesByGroup) {
    const aggregated = aggregateEdges(list, NO_GROUP_RESOLVE, principalList, sorted);
    aggregatedIntraByGroup.set(groupAddr, aggregated);
    for (const e of aggregated) {
      intraGroupRendered.push({
        ...e,
        data: { ...(e.data || {}), intraGroup: true },
      });
    }
  }
  // Short stubs so grouped contracts with cross-group calls don't look
  // unconnected; the bundle carries the long haul.
  // - OUTBOUND: from the source contract down to its group's bottom, where the
  //     bundle leaves.
  // - INBOUND: from under the target group's header down to the contract; the
  //     header appears to hide the rest.
  const contractCanonicalByLc = new Map();
  for (const m of sorted) {
    if (m.address) contractCanonicalByLc.set(m.address.toLowerCase(), m.address);
  }
  const groupNodeByAddr = new Map();
  for (const n of nodes) {
    if (n.type === "group") groupNodeByAddr.set(n.id.toLowerCase(), n);
  }
  const stubEdges = [];
  const outStubbed = new Set();
  const inStubbed = new Set();
  for (const bundle of aggregatedCrossEdges) {
    const srcGroupLc = bundle.source?.toLowerCase();
    const tgtGroupLc = bundle.target?.toLowerCase();
    for (const s of bundle.data?.samples || []) {
      const fromLc = s.from?.toLowerCase();
      const toLc = s.to?.toLowerCase();
      // The membership check also guarantees the stub-bottom handle exists.
      if (fromLc && !outStubbed.has(fromLc) && contractToGroup.get(fromLc) === srcGroupLc) {
        const c = contractCanonicalByLc.get(fromLc);
        if (c) {
          outStubbed.add(fromLc);
          stubEdges.push({
            id: `stub-out-${fromLc}`,
            source: c,
            sourceHandle: "ctrl-out",
            target: bundle.source,
            targetHandle: "stub-bottom",
            type: "channeled",
            style: { stroke: bundle.style?.stroke || "#94a3b8", strokeWidth: 1 },
            animated: false,
            data: { stub: true },
          });
        }
      }
      // headerHeight tells ChanneledStepEdge where the visible drop starts.
      if (toLc && !inStubbed.has(toLc) && contractToGroup.get(toLc) === tgtGroupLc) {
        const c = contractCanonicalByLc.get(toLc);
        const g = groupNodeByAddr.get(tgtGroupLc);
        if (c && g) {
          inStubbed.add(toLc);
          stubEdges.push({
            id: `stub-in-${toLc}`,
            source: bundle.target,
            sourceHandle: "stub-top",
            target: c,
            targetHandle: "ctrl-in",
            type: "channeled",
            style: { stroke: bundle.style?.stroke || "#94a3b8", strokeWidth: 1 },
            animated: false,
            data: { stub: true, inbound: true, headerHeight: g.data?.headerHeight || 0 },
          });
        }
      }
    }
  }

  const finalEdges = [...intraGroupRendered, ...aggregatedCrossEdges, ...stubEdges];
  return {
    nodes,
    edges: finalEdges,
    groupChildren,
    contractToGroup,
    rawEdges: edges,
    intraGroupEdgesByGroup: aggregatedIntraByGroup,
  };
}

export async function elkLayout(machines, fundFlows, principals, bandHeights = {}, chain = "ethereum") {
  const { nodes: rawNodes, edges: rawEdges } = buildGraphLayout(machines, fundFlows, principals, bandHeights, chain);

  // ELK only packs top-level boxes; group interiors use semantic bands
  // (layoutGroupInterior), since ELK's layered layout ignored role and
  // scattered dense Safes.
  const childByParent = new Map();
  const topLevel = [];
  for (const n of rawNodes) {
    if (n.parentId) {
      if (!childByParent.has(n.parentId)) childByParent.set(n.parentId, []);
      childByParent.get(n.parentId).push(n);
    } else {
      topLevel.push(n);
    }
  }

  function dimsFor(n) {
    if (n.type === "principal") return { width: PRINCIPAL_W, height: PRINCIPAL_H };
    return { width: CHILD_W, height: CHILD_H };
  }

  // Before building elkChildren, so group sizes come from the band layout.
  const groupInteriors = new Map();
  for (const n of topLevel) {
    if (n.type !== "group") continue;
    const kids = childByParent.get(n.id) || [];
    groupInteriors.set(n.id, layoutGroupInterior(kids, machines, n.data?.headerHeight));
  }

  const elkChildren = topLevel.map((n) => {
    if (n.type === "group") {
      const interior = groupInteriors.get(n.id);
      return { id: n.id, width: interior.width, height: interior.height };
    }
    return { id: n.id, ...dimsFor(n) };
  });

  // No edges to ELK; ChanneledStepEdge routes them.
  const elkGraph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "rectpacking",
      "elk.spacing.nodeNode": "140",
      "elk.aspectRatio": "1.6",
    },
    children: elkChildren,
    edges: [],
  };

  try {
    const layout = await elk.layout(elkGraph);
    const topPos = new Map();
    for (const child of layout.children || []) {
      topPos.set(child.id, { x: child.x || 0, y: child.y || 0 });
    }

    const laidOutNodes = rawNodes.map((n) => {
      if (n.parentId) {
        // Relative to the parent group; React Flow adds the offset.
        const interior = groupInteriors.get(n.parentId);
        const pos = interior?.positions?.get(n.id) || n.position;
        return { ...n, position: pos };
      }
      const next = { ...n, position: topPos.get(n.id) || n.position };
      if (n.type === "group") {
        const interior = groupInteriors.get(n.id);
        if (interior) {
          next.style = {
            ...(n.style || {}),
            width: interior.width,
            height: interior.height,
          };
        }
      }
      return next;
    });
    const laneAdjusted = assignEdgeLanes(laidOutNodes, rawEdges);
    return { nodes: laidOutNodes, edges: attachObstacles(laneAdjusted, laidOutNodes) };
  } catch {
    // Fallback if ELK fails: groups keep interior dims; only inter-group
    // packing is lost.
    const laneAdjusted = assignEdgeLanes(rawNodes, rawEdges);
    return { nodes: rawNodes, edges: attachObstacles(laneAdjusted, rawNodes) };
  }
}
