// Graph layout for SurfaceCanvas. Pure helpers + an ELK instance that runs
// the async layered pass. No React — but `elkLayout` is async because ELK is.

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

  // Build directed adjacency: from → Set<to> (controller → target)
  const addrToIdx = new Map();
  machines.forEach((m, i) => addrToIdx.set(m.address?.toLowerCase(), i));

  const children = new Map(); // idx → Set<idx>  (who this node controls)
  const parents = new Map();  // idx → Set<idx>  (who controls this node)
  for (let i = 0; i < n; i++) { children.set(i, new Set()); parents.set(i, new Set()); }

  for (const [from, to] of edgePairs) {
    const fi = addrToIdx.get(from);
    const ti = addrToIdx.get(to);
    if (fi !== undefined && ti !== undefined && fi !== ti) {
      children.get(fi).add(ti);
      parents.get(ti).add(fi);
    }
  }

  // Assign tiers via BFS from roots (nodes with no parents)
  const tier = new Array(n).fill(-1);
  const roots = [];
  for (let i = 0; i < n; i++) {
    if (parents.get(i).size === 0) roots.push(i);
  }
  // If no roots (cycles), pick the node with most children
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

  // Unconnected nodes get their own tier at the bottom
  const maxTier = Math.max(0, ...tier.filter((t) => t >= 0));
  for (let i = 0; i < n; i++) {
    if (tier[i] < 0) tier[i] = maxTier + 1;
  }

  // Group nodes by tier
  const tiers = new Map();
  for (let i = 0; i < n; i++) {
    if (!tiers.has(tier[i])) tiers.set(tier[i], []);
    tiers.get(tier[i]).push(i);
  }

  // Score each node by influence
  const outCount = new Array(n).fill(0);
  const inCount = new Array(n).fill(0);
  const hasEdge = new Set();
  for (const [from, to] of edgePairs) {
    const fi = addrToIdx.get(from);
    const ti = addrToIdx.get(to);
    if (fi !== undefined) { outCount[fi]++; hasEdge.add(fi); }
    if (ti !== undefined) { inCount[ti]++; hasEdge.add(ti); }
  }

  // Split connected vs isolated
  const connected = [];
  const isolated = [];
  for (let i = 0; i < n; i++) {
    if (hasEdge.has(i)) connected.push(i);
    else isolated.push(i);
  }

  // Rank connected by influence (more outgoing = higher)
  connected.sort((a, b) => {
    const sa = outCount[a] - inCount[a];
    const sb = outCount[b] - inCount[b];
    if (sb !== sa) return sb - sa;
    return outCount[b] - outCount[a];
  });

  const NODE_W = 250;
  const NODE_H = 160;
  // Scale columns based on node count — more nodes = wider layout
  const colCount = n <= 9 ? 3 : n <= 20 ? 4 : 5;
  const spread = NODE_W * 1.15;
  const positions = new Array(n);

  // Connected nodes: multi-column stagger, spreading wider as we go down
  for (let rank = 0; rank < connected.length; rank++) {
    const idx = connected[rank];
    const col = rank % colCount;
    const row = Math.floor(rank / colCount);
    const rowSpread = spread * (1 + row * 0.08);
    let x, y;
    y = row * NODE_H;
    // Spread columns evenly around center
    const colOffset = (col - (colCount - 1) / 2) * rowSpread;
    // Deterministic jitter (subtle)
    const jx = ((rank * 7 + 13) % 30 - 15);
    const jy = ((rank * 11 + 7) % 16 - 8);
    x = colOffset + jx;
    y += jy;
    positions[idx] = { x: Math.round(x), y: Math.round(y) };
  }

  // Isolated nodes: ellipse ring around the connected core
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

// `bandHeights` ({ groupId: px }) reserves each group's real header-band
// height. GroupNode measures the rendered band (colored bar + Controllers
// accordion, including any capability summary that wraps to several lines) and
// reports it per group; we reserve that exact height so ELK packs the canvas
// to fit (rather than a wrapped row overflowing / overlapping cards). Until a
// group is measured we fall back to a constant estimate.
export function buildGraphLayout(machines, fundFlows, principals, bandHeights = {}, chain = "ethereum") {
  const sorted = [...machines].sort((a, b) => b.totalFunctions - a.totalFunctions);
  const principalList = principals || [];
  const principalByAddr = new Map();
  for (const p of principalList) {
    if (p.address) principalByAddr.set(p.address.toLowerCase(), p);
  }

  const { contractToGroup, groupChildren } = assignGroups(sorted, principalList);

  // Layout contracts only — principals get positioned relative to what they control
  const contractEntities = sorted.map((m) => ({ address: m.address?.toLowerCase(), kind: "contract" }));

  // Collect contract-to-contract edge pairs
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

  // Fallback positions (only used if ELK fails) — keep the old hierarchical
  // layout for that path; it doesn't understand groups but it never
  // renders unless ELK errors out.
  const fallbackPositions = hierarchicalLayout(contractEntities, edgePairs);
  const contractPositions = new Map();

  // Total USD per group, so the group header can show a single TVL number
  // instead of every child having to be inspected. Mirrors what the
  // `Has Funds` search mode and the bottom-of-card balance line use.
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
  const machineByAddr = new Map();
  for (const m of sorted) {
    if (m.address) {
      nameByAddr.set(m.address.toLowerCase(), m.name || m.address);
      machineByAddr.set(m.address.toLowerCase(), m);
    }
  }

  // Build group container nodes first — React Flow needs the parent
  // in the array before its children for stable rendering.
  const nodes = [];
  for (const [principalAddr, kids] of groupChildren) {
    const p = principalByAddr.get(principalAddr);
    if (!p) continue;
    // Controllers accordion model (primary first, then co-controllers) +
    // the header height it reserves, so layoutGroupInterior can start the
    // cards below it and GroupNode can pin the rendered band to the same
    // number. See buildGroupControllers / groupHeaderHeight.
    const controllers = buildGroupControllers(p, kids, principalList, nameByAddr, chain);
    // Reserve this group's measured band height so the cards — and everything
    // ELK packs below — start below it instead of being overlapped. Falls back
    // to a constant estimate until GroupNode reports the real height.
    const measuredBand = bandHeights[p.address];
    const headerHeight = measuredBand != null ? measuredBand : groupHeaderHeight(controllers.length);
    const directControls = new Set((p.controls || []).map((address) => address?.toLowerCase()).filter(Boolean));
    const directCount = kids.filter((address) => directControls.has(address)).length;
    nodes.push({
      id: p.address,
      type: "group",
      position: { x: 0, y: 0 },
      // ELK fills these in; the placeholder keeps React Flow happy on
      // the first render before the async layout resolves.
      style: { width: 400, height: 200 },
      data: {
        principal: p,
        childCount: kids.length,
        directCount,
        viaGovernanceCount: kids.length - directCount,
        heuristicCount: kids.filter((address) => machineByAddr.get(address)?.membershipKind === "heuristic").length,
        totalUsd: groupTotalUsd.get(principalAddr) || 0,
        controllers,
        headerHeight,
      },
    });
  }

  // Contract nodes
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
      // The principal's original-cased address is what we used as the
      // group node's id — find it so React Flow's parent lookup matches.
      const principalCanonical = principalByAddr.get(groupAddr)?.address || groupAddr;
      node.parentId = principalCanonical;
      node.extent = "parent";
    }
    nodes.push(node);
  }

  // Co-controllers — principals that hold real authority on contracts they
  // don't primary-own (principal.co_controls) — are no longer rendered as
  // standalone "guardian" rail nodes. They now live inside the owning group's
  // Controllers accordion (see buildGroupControllers / GroupNode), which lists
  // the exact functions each can call per contract instead of an illegible
  // dot in a rail. A co-controller spanning several groups appears in each.
  // The permissionless long tail (machine.other_callers) is not rendered at
  // all; the per-function caller buttons in the detail lanes cover it.

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

  // Fund flow / control edges with semantic handle routing. Any edge
  // whose source is a non-contract principal is silently dropped — the
  // ownership relationship now lives in the group containment, and the
  // cross-group principal fanout was the dominant source of canvas
  // spaghetti. Only contract→contract edges (proxy→impl, controls,
  // controller, contract-as-principal CGN edges) survive.
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

  // Split intra-group edges out of the aggregation pass — they're
  // what gives each box its caller→callee hierarchy when rendered
  // inside the group, and we don't want them bundled away.
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

  // Aggregate intra-group edges the same way we do cross-group ones.
  // aggregateEdges' endpoint() resolves a contract to its group when
  // given a populated contractToGroup — which would collapse every
  // child↔child pair into a same-group self-loop and drop the whole
  // batch. Handing it an empty map preserves the raw contract
  // addresses so each (childA, childB) pair collapses to one bundle,
  // mirroring the outside-the-groups view.
  //
  // No additional capability/flow-type filter is applied: upstream FP
  // gating on `type=principal` / `type=controller` flows already
  // removed the CGN/CV over-reach that was the dominant intra-group
  // spaghetti. Filtering further here on a cap whitelist would now
  // hide legitimate authorization edges whose caps happen to be
  // source-attribute tags (`upgradeable`, `pause`, `delegatecall`).
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
  // Always-visible cross-group connectors. A grouped contract whose
  // cross-group calls were aggregated into a box→box bundle would otherwise
  // look unconnected. We add a short stub at each contract that participates in
  // a bundle, so you can see which contracts reach outside the box while the
  // bundle still carries the long-haul (no per-contract cross-canvas fanout).
  // These are ordinary channeled edges that dim/brighten with selection.
  //   - OUTBOUND (the bundle's source contract): drops to its group's BOTTOM
  //     edge, the exact point the bundle leaves from. Routed around sibling
  //     cards (attachObstacles) and landed cleanly via ChanneledStepEdge.
  //   - INBOUND (the bundle's target contract): drops from just under its
  //     group's header to the contract's top. The bundle still arrives at the
  //     box top "as normal"; the stub only draws the part BELOW the header, so
  //     the header reads as hiding the segment between them (the "invisible
  //     line through the header" the connection appears to continue along).
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
      // Outbound: source contract → its group's bottom (where the bundle leaves).
      // The group-membership check also guarantees bundle.source is a group, so
      // the stub-bottom handle exists.
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
      // Inbound: from under the target group's header down to the target
      // contract's top. headerHeight tells ChanneledStepEdge where the header
      // ends so it can start the visible drop there.
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

  // Split nodes into top-level vs grouped-children. ELK only sees the
  // top level now: each group is handed to it as a single sized box.
  // The inside of every group is laid out by layoutGroupInterior
  // (semantic bands: control / value / interfaces) so position carries
  // meaning regardless of how the group's children relate to each other
  // in the call graph. ELK's `layered` algorithm minimised crossings
  // but ignored role — that's what made dense Safes read as scattered.
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

  // Pre-compute every group's interior layout. Doing this before
  // building elkChildren means the group's overall width/height — which
  // ELK uses to pack groups against each other — comes from the actual
  // role-band layout, not from ELK's own compound-layout heuristic.
  const groupInteriors = new Map();
  for (const n of topLevel) {
    if (n.type !== "group") continue;
    const kids = childByParent.get(n.id) || [];
    // headerHeight reserves the colored bar + collapsed Controllers
    // accordion, so the first card lands below it (see groupHeaderHeight).
    groupInteriors.set(n.id, layoutGroupInterior(kids, machines, n.data?.headerHeight));
  }

  const elkChildren = topLevel.map((n) => {
    if (n.type === "group") {
      const interior = groupInteriors.get(n.id);
      return { id: n.id, width: interior.width, height: interior.height };
    }
    return { id: n.id, ...dimsFor(n) };
  });

  // ELK only does the outer rectpacking pass over groups + standalone
  // contracts. No edges fed to ELK; intra-group routing is handled
  // entirely by ChanneledStepEdge's bundled router downstream.
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
        // Child positions come from the JS interior layout, relative
        // to the parent group's origin (React Flow adds the parent
        // offset automatically via extent="parent").
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
    // Fallback to manual positions if elk fails. Groups still get the
    // JS-computed interior dims; only the inter-group rectpacking is
    // lost (groups stack at their fallback positions).
    const laneAdjusted = assignEdgeLanes(rawNodes, rawEdges);
    return { nodes: rawNodes, edges: attachObstacles(laneAdjusted, rawNodes) };
  }
}
