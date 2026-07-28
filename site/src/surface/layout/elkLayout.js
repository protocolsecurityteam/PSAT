// Graph layout for SurfaceCanvas. Pure helpers + an ELK instance that runs
// the async layered pass. No React — but `elkLayout` is async because ELK is.

import ELK from "elkjs/lib/elk.bundled.js";

import { entityKey } from "../entityKey.js";
import { principalBadge } from "../format.js";

const elk = new ELK();

// Every principal (Safe / Timelock / EOA / proxy admin) that owns at
// least this many contracts becomes a group container. We default to 1
// — a Safe that touches a single contract still gets a labeled box,
// matching the visual the user wants for EOAs as well. Principals that
// the server didn't mark primary for any contract drop off the canvas
// entirely; they remain addressable via search and sidebar.
const MIN_GROUP_SIZE = 1;

export function hierarchicalLayout(machines, edgePairs) {
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

// Compute the contract→group assignment used by both buildGraphLayout
// (for node parentId + edge filtering) and elkLayout (for ELK compound
// children).
//
// The server's primary-controller assignment (services.governance.
// primary_controller, exposed as principal.primary_for) is the source
// of truth: a contract belongs to principal P's group iff P.primary_for
// includes it. That's the same decision monitoring enrollment uses, so
// the canvas and the Monitoring tab never disagree about who governs
// what. We previously derived this client-side from principal.controls
// + a local priority constant, which double-counted state-variable
// destinations (e.g. payoutAddress Safes) that have no call authority.
//
// Returns:
//   contractToGroup: Map<contractAddr_lc, principalAddr_lc>
//   groupChildren:   Map<principalAddr_lc, contractAddr_lc[]>
//   groupedPrincipals: Set<principalAddr_lc> (principals materialized as a group)
export function assignGroups(machines, principals) {
  const contractAddrs = new Set();
  for (const m of machines) {
    if (m.address) contractAddrs.add(m.address.toLowerCase());
  }

  const contractToGroup = new Map();
  const groupChildren = new Map();

  for (const p of principals || []) {
    const principalAddr = p?.address?.toLowerCase();
    if (!principalAddr) continue;
    const primary = Array.isArray(p.primary_for) ? p.primary_for : [];
    const owned = [];
    for (const c of primary) {
      const lc = c?.toLowerCase();
      if (!lc || lc === principalAddr) continue;
      if (!contractAddrs.has(lc)) continue;
      // A contract should only ever appear in one principal's primary_for
      // (server enforces this), but defensively skip duplicates.
      if (contractToGroup.has(lc)) continue;
      contractToGroup.set(lc, principalAddr);
      owned.push(lc);
    }
    if (owned.length >= MIN_GROUP_SIZE) {
      groupChildren.set(principalAddr, owned);
    }
  }

  return {
    contractToGroup,
    groupChildren,
    groupedPrincipals: new Set(groupChildren.keys()),
  };
}

// Build the Controllers-accordion model for one group: the primary owner
// first, then every co-controller that holds authority on a contract inside
// this group. Each row carries the contracts it governs WITHIN this group,
// with the concrete functions + capability tags it can call on each — all
// scoped to the group's own children, so a co-controller spanning several
// groups shows only the authority relevant to the box it's rendered in.
//
// Capability tags are taken verbatim from controls_detail[].capabilities
// (the shared _EFFECT_CAPABILITY vocabulary: pause / upgrade / fund-out / …)
// and unioned per row — never remapped, so a row reads the same word the
// per-contract chips do.
function buildGroupControllers(primary, kids, principalList, nameByAddr, chain = "ethereum") {
  const childOrder = kids; // group's child addresses (lc), in owned order
  const childSet = new Set(kids);

  const rowFor = (principal, isPrimary) => {
    // Keyed by (chain, address). A controls_detail row carries its own
    // chain, so a twin-governing principal's two same-address rows key to their
    // own chains — only the row on the page's active chain matches a visible kid
    // below; the other-chain row finds no child and is dropped. Legacy rows with
    // no chain fall back to the active chain, keying exactly as before.
    const detailByAddr = new Map();
    for (const d of principal.controls_detail || []) {
      if (d?.address) detailByAddr.set(entityKey(d.chain ?? chain, d.address), d);
    }
    const governs = [];
    const caps = new Set();
    const funcs = new Set();
    for (const childLc of childOrder) {
      const d = detailByAddr.get(entityKey(chain, childLc));
      if (!d) continue;
      const functions = Array.isArray(d.functions) ? d.functions : [];
      const capabilities = Array.isArray(d.capabilities) ? d.capabilities : [];
      if (functions.length === 0 && capabilities.length === 0) continue;
      governs.push({ address: childLc, name: nameByAddr.get(childLc) || childLc, capabilities, functions });
      for (const c of capabilities) caps.add(c);
      for (const f of functions) funcs.add(f);
    }
    governs.sort((a, b) => a.name.localeCompare(b.name));
    return {
      address: principal.address,
      type: principal.type,
      isPrimary,
      label: principalBadge(principal),
      capabilities: [...caps].sort(),
      // Unioned function names — the row summary falls back to these (like the
      // sidebar's "Can Call") for controllers whose functions map to no
      // high-level capability tag, so the summary is never blank.
      functions: [...funcs].sort(),
      governs,
    };
  };

  const primaryAddrLc = primary.address?.toLowerCase();
  const controllers = [rowFor(primary, true)];

  const coRows = [];
  for (const q of principalList) {
    const qLc = q.address?.toLowerCase();
    if (!qLc || qLc === primaryAddrLc) continue;
    const co = Array.isArray(q.co_controls) ? q.co_controls : [];
    if (!co.some((c) => childSet.has(c?.toLowerCase()))) continue;
    const row = rowFor(q, false);
    // co_controls says it has authority here; if we have no verified
    // function detail for any of this group's contracts there's nothing to
    // show, so skip the empty row rather than render "governs 0".
    if (row.governs.length === 0) continue;
    coRows.push(row);
  }
  // Most-capable co-controllers first; deterministic tie-breaks keep the
  // layout (and visual snapshots) stable across renders.
  coRows.sort(
    (a, b) =>
      b.governs.length - a.governs.length ||
      b.capabilities.length - a.capabilities.length ||
      a.address.localeCompare(b.address),
  );
  return controllers.concat(coRows);
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
  for (const m of sorted) {
    if (m.address) nameByAddr.set(m.address.toLowerCase(), m.name || m.address);
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

// Collapse the raw edge list into one bundle per (endpoint-group,
// endpoint-group) pair. The "endpoint" for an address is its
// containing group's id if it's a child of a group, otherwise the
// address itself. Intra-group edges (both endpoints resolve to the
// same group) and self-loops get dropped entirely — they're invisible
// at the macro view we're optimising for.
//
// The bundle preserves the underlying sample list under `data.samples`
// so selection-dimming in SurfaceCanvas can drill back into which
// specific contract→contract pair lit up. Width grows logarithmically
// with the bundled count so a 20-edge bundle reads heavier than a
// 2-edge bundle without dwarfing the canvas.
export function aggregateEdges(rawEdges, contractToGroup, principalList, machines) {
  const canonicalByLc = new Map();
  for (const m of machines || []) {
    if (m.address) canonicalByLc.set(m.address.toLowerCase(), m.address);
  }
  for (const p of principalList || []) {
    if (p.address) canonicalByLc.set(p.address.toLowerCase(), p.address);
  }

  // Set of addresses that render as a GroupNode. Those nodes only
  // carry ctrl-in (top) / ctrl-out (bottom) handles — if an
  // aggregated value-flow edge keeps its original value-in/value-out
  // handle on a group endpoint, React Flow can't resolve it and falls
  // back to the node centre, drawing the edge from somewhere inside
  // the container. Force ctrl handles for group endpoints to fix that.
  const groupAddrs = new Set();
  for (const g of contractToGroup.values()) {
    if (g) groupAddrs.add(String(g).toLowerCase());
  }

  function endpoint(lcAddr) {
    const g = contractToGroup.get(lcAddr);
    if (g) return canonicalByLc.get(g) || g;
    return canonicalByLc.get(lcAddr) || lcAddr;
  }

  const bundles = new Map();
  for (const e of rawEdges) {
    const fromLc = (e.source || "").toLowerCase();
    const toLc = (e.target || "").toLowerCase();
    const fromEnd = endpoint(fromLc);
    const toEnd = endpoint(toLc);
    if (fromEnd.toLowerCase() === toEnd.toLowerCase()) continue;

    const srcHandle = groupAddrs.has(fromEnd.toLowerCase()) ? "ctrl-out" : e.sourceHandle;
    const tgtHandle = groupAddrs.has(toEnd.toLowerCase()) ? "ctrl-in" : e.targetHandle;

    const key = `${fromEnd.toLowerCase()}->${toEnd.toLowerCase()}`;
    if (!bundles.has(key)) {
      bundles.set(key, {
        source: fromEnd,
        target: toEnd,
        samples: [],
        sourceHandle: srcHandle,
        targetHandle: tgtHandle,
        hasValue: false,
      });
    }
    const b = bundles.get(key);
    b.samples.push(e);
    if (e.data?.flowType === "controls_value") b.hasValue = true;
  }

  const out = [];
  for (const [, b] of bundles) {
    const count = b.samples.length;
    const isBundle = count > 1;
    const width = isBundle ? Math.min(4, 1 + Math.log2(count)) : 1;
    out.push({
      id: `agg-${b.source}-${b.target}`,
      source: b.source,
      target: b.target,
      sourceHandle: b.sourceHandle,
      targetHandle: b.targetHandle,
      type: "channeled",
      style: {
        stroke: b.hasValue ? "#7fc4b6" : "#94a3b8",
        strokeWidth: width,
      },
      animated: false,
      // The shared-trunk routing from routeOrthogonal carries the
      // "many connections" signal visually — every edge leaving a
      // handle overlaps on the same perpendicular stub before forking,
      // so the cable thickness at the bus column already reads as
      // weight. A numeric count label on top of that was redundant and
      // out of style with the rest of the page; selection chips
      // (added later) communicate the per-edge specifics on click.
      //
      // Per-sample capabilities + flowType are preserved so chips can
      // describe the SPECIFIC (from, to) flow rather than the bundle's
      // union — bundles can mix flow shapes (e.g. controller vs
      // principal, different cap sets per target) and a union'd chip
      // misleadingly suggests every child has the same relationship.
      data: {
        flowType: b.samples[0]?.data?.flowType,
        capabilities: Array.from(
          new Set(b.samples.flatMap((s) => s.data?.capabilities || [])),
        ),
        samples: b.samples.map((s) => ({
          from: s.source,
          to: s.target,
          capabilities: s.data?.capabilities || [],
          flowType: s.data?.flowType,
        })),
      },
    });
  }
  return out;
}

// Handle id → axis the side runs along. Used by assignEdgeLanes to
// know whether to compare endpoints by x or y when sorting members of
// a single side bucket. Keep this in sync with the Handle <Position>
// in ContractNode / GroupNode / PrincipalNode.
const HANDLE_AXIS = {
  "ctrl-in": "x",   // Position.Top
  "ctrl-out": "x",  // Position.Bottom
  "value-in": "y",  // Position.Left
  "value-out": "y", // Position.Right
};

// After ELK has positioned every node, group edges by the (node,
// handle) side they exit / enter and assign each one a lane index so
// that the custom ChanneledStepEdge can fan them out across the side
// rather than stacking on the handle centre. Lane 0 is centred, ±1 is
// one slot away, etc.
//
// All members of a single bucket live in the same coordinate space —
// either both top-level (cross-group bundles) or both children of the
// same group (intra-group bundles). So a raw position.x/y comparison
// is enough; we don't need to walk parent chains.
export function assignEdgeLanes(nodes, edges) {
  const nodeById = new Map();
  for (const n of nodes) nodeById.set(n.id, n);

  const buckets = new Map();
  function add(nodeId, handle, edgeId, role, otherId) {
    const key = `${nodeId}|${handle || ""}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push({ edgeId, role, otherId });
  }
  for (const e of edges) {
    add(e.source, e.sourceHandle, e.id, "source", e.target);
    add(e.target, e.targetHandle, e.id, "target", e.source);
  }

  const laneByEdge = new Map();
  for (const [key, members] of buckets) {
    const handle = key.split("|")[1];
    const axis = HANDLE_AXIS[handle] || "x";
    members.sort((m1, m2) => {
      const a = nodeById.get(m1.otherId);
      const b = nodeById.get(m2.otherId);
      return ((a?.position?.[axis]) || 0) - ((b?.position?.[axis]) || 0);
    });
    const n = members.length;
    members.forEach((m, i) => {
      const lane = n <= 1 ? 0 : i - (n - 1) / 2;
      const entry = laneByEdge.get(m.edgeId) || {};
      entry[m.role] = lane;
      laneByEdge.set(m.edgeId, entry);
    });
  }

  return edges.map((e) => {
    const lanes = laneByEdge.get(e.id);
    if (!lanes) return e;
    return {
      ...e,
      data: {
        ...(e.data || {}),
        sourceLane: lanes.source || 0,
        targetLane: lanes.target || 0,
      },
    };
  });
}

// Group container chrome sizing. The top reservation is dynamic now: it
// holds the colored primary bar PLUS the collapsed Controllers accordion
// (one fixed-height row per controller), so the contract cards always start
// below the accordion. The side/bottom padding give breathing room between
// the colored border and the children inside. Child dimensions are sized a
// touch larger than the .ps-node CSS naturally renders so rectpacking gives
// each card its own column of slack — without this, cards on neighbouring
// rows in dense groups visually butt up against each other.
//
// groupHeaderHeight() is only the INITIAL estimate of the collapsed band —
// GroupNode measures the real rendered height (rows can grow when a capability
// summary wraps) and reports it back, after which we reserve that exact value.
// The constants just need to roughly track layout.css so the first frame is
// close; the band is clipped (overflow:hidden) until the measured value lands,
// so an off estimate is never an overlap.
const GROUP_HEADER_BAR_H = 62; // colored primary bar (badge row + count)
const GROUP_ACC_LABEL_H = 26; // "Controllers" eyebrow strip
const GROUP_ACC_ROW_H = 32; // one collapsed single-line controller row (~.ps-ctrl-head + margin)
const GROUP_ACC_PAD_BOTTOM = 10; // breathing room below the last row
export function groupHeaderHeight(numControllers) {
  return GROUP_HEADER_BAR_H + GROUP_ACC_LABEL_H + numControllers * GROUP_ACC_ROW_H + GROUP_ACC_PAD_BOTTOM;
}

const GROUP_PADDING_TOP = groupHeaderHeight(1);
const GROUP_PADDING_SIDE = 24;
const GROUP_PADDING_BOTTOM = 24;
// Floor on a group's width so the Controllers accordion row reads without
// clipping. A row's fixed parts (caret + tag + badge + short address +
// "governs N") need ~350px; this leaves room for a capability tag or two
// beside them before the summary wraps. Narrow groups (1–2 small cards) would
// otherwise be ~306px and crop the row (the band is overflow:hidden). The
// cards stay centered in the widened interior.
const GROUP_MIN_WIDTH = 440;
// Gap between the header band's bottom and the first contract card. The band
// is `position:absolute; top:0` so it sits inside the group's 2px border,
// while React Flow positions child cards relative to the group's outer edge —
// without this the first card's top tucks ~2px under the band. The rest is
// breathing room below the accordion (~on par with GROUP_PADDING_BOTTOM).
const GROUP_HEADER_GAP = 28;
// Child cell sized for the widest contract card the .ps-node CSS
// actually renders (no max-width; long names like
// "EtherFiRedemptionManager" / "AuctionManager" stretch the card to
// ~250px). Telling the grid 200px and getting a 250px card back is
// what was making adjacent cells overlap. CHILD_H stays larger than
// the actual rendered height so vertical spacing has slack for the
// occasional double-line card.
const CHILD_W = 260;
const CHILD_H = 130;
const PRINCIPAL_W = 140;
const PRINCIPAL_H = 60;

// In-group band assignment. Three bands top-to-bottom:
//   0 = control surfaces — timelocks, role admins, governance contracts.
//   1 = value-bearing — value handlers, bridges, value-moving tokens.
//   2 = interfaces & plumbing — pure tokens, factories, utility.
// Position carries meaning: a glance tells you which contracts hold
// authority vs hold value vs are interface/plumbing, regardless of which
// protocol you're looking at.
//
// We can't rely on `role` alone. The backend classifier puts any
// contract with asset_pull / asset_send into `value_handler`, which
// captures TimelockController-style admins that also execute value
// moves during their queued operations. Has-timelock and
// control_model=governance are the more reliable "this contract issues
// commands" signals, so they win over `role` when both fire.
function bandFor(m) {
  if (!m) return 2;
  // `=== true`, not truthiness: `has_timelock` is three-state on the payload
  // (bool | null) and `null` means no summary row answered. Truthiness already
  // skipped a null, but it skipped it by treating it as the proven `false`; the
  // strict test says which state is being tested for, and the fall-through below
  // is where not-determined stops sharing an outcome with proven-false.
  if (m.has_timelock === true) return 0;
  if (m.control_model === "governance") return 0;
  if (m.role === "governance") return 0;
  // Name override: the backend role classifier does not surface every contract
  // that IS itself a control surface (TimelockController, BoringGovernance,
  // etc.) — when such a contract also has asset-move side effects it ends up
  // tagged value_handler and loses to the band-1 catchall. Pattern-match the
  // name so they float to the top. The check is also the only signal left when
  // `has_timelock` is null, which is why it is not redundant with the test
  // above: since summaries.py made the flag mean "THIS CONTRACT IS A TIMELOCK",
  // a proven timelock returns 0 at the first test and this one only ever adds
  // rows the flag did not prove.
  const nameLower = (m.name || "").toLowerCase();
  if (/timelock|governance|guardian/.test(nameLower)) return 0;
  // Band 2 is a positive claim — "interfaces & plumbing": holds no authority and
  // holds no value. A `role` the backend derived with no summary evidence at all
  // (`role_evidence === "not_determined"`, the `utility` fall-through reached
  // through nothing but nulls) is not evidence for it, so it takes the neutral
  // band-1 catchall instead. Only a role earned from a positive fact places a
  // node in the plumbing band.
  if (m.role_evidence === "not_determined") return 1;
  if (m.role === "token" || m.role === "factory" || m.role === "utility") return 2;
  return 1;
}

// Spacing between children inside a group. Roomier than the obvious
// minimum because:
//   - tight gaps make the bundled edge trunks visually merge with
//     adjacent cells; ~50px of horizontal slack keeps the cabling
//     readable as it forks across the band.
//   - selecting a contract reveals capability labels on its edges; a
//     larger V_GAP gives those labels somewhere to land without
//     overlapping cards in the next row.
const CHILD_H_GAP = 50;
const CHILD_V_GAP = 70;

// Within-group child layout: bucket by role band, sort each band by
// TVL desc, pack each band into a grid centred horizontally so the
// whole group reads as control-on-top / value-in-middle / interfaces-
// at-bottom regardless of which contracts happen to be in it.
//
// Returns: { positions: Map<address, {x,y}>, width, height }
// All coords are relative to the group container's origin; React Flow
// adds the parent offset.
export function layoutGroupInterior(kids, machines, headerHeight = GROUP_PADDING_TOP) {
  if (!kids || kids.length === 0) {
    return { positions: new Map(), width: Math.max(CHILD_W + 2 * GROUP_PADDING_SIDE, GROUP_MIN_WIDTH), height: headerHeight + GROUP_PADDING_BOTTOM };
  }

  const machineByAddr = new Map();
  for (const m of machines || []) {
    if (m.address) machineByAddr.set(m.address.toLowerCase(), m);
  }

  // Bucket into bands using the multi-signal classifier (role +
  // has_timelock + control_model). See bandFor for why role alone isn't
  // enough.
  const bands = [[], [], []];
  for (const kid of kids) {
    const m = machineByAddr.get(kid.id?.toLowerCase());
    bands[bandFor(m)].push({
      id: kid.id,
      tvl: m?.total_usd || 0,
      name: m?.name || kid.id || "",
    });
  }

  // Sort each band: TVL desc → name asc. TVL surfaces money-holding
  // contracts at the front of their row; name tie-break keeps the
  // layout stable across re-renders.
  for (const list of bands) {
    list.sort((a, b) => (b.tvl - a.tvl) || a.name.localeCompare(b.name));
  }

  // Pick a column count for each band that keeps the band's aspect
  // close to the 1.6 target the outer rectpacking uses. For small
  // bands (≤4 items) prefer a single row — squashing 3 contracts into
  // 2x2 feels arbitrary.
  function chooseCols(count) {
    if (count <= 4) return count;
    return Math.max(1, Math.floor(Math.sqrt(count * 1.6)));
  }

  const bandPlans = bands.map((list) => {
    if (list.length === 0) return null;
    const cols = chooseCols(list.length);
    const rows = Math.ceil(list.length / cols);
    return {
      list,
      cols,
      rows,
      width: cols * CHILD_W + (cols - 1) * CHILD_H_GAP,
      height: rows * CHILD_H + (rows - 1) * CHILD_V_GAP,
    };
  });

  // Group interior width = widest band's width, floored so the Controllers
  // accordion row fits (see GROUP_MIN_WIDTH). Each band is centred within that
  // width so the layout looks balanced regardless of role distribution — and a
  // narrow card band sits centered in the accordion-driven width.
  const bandW = Math.max(0, ...bandPlans.filter(Boolean).map((b) => b.width));
  const interiorW = Math.max(bandW, GROUP_MIN_WIDTH - 2 * GROUP_PADDING_SIDE);
  const totalWidth = interiorW + 2 * GROUP_PADDING_SIDE;

  const positions = new Map();
  let curY = headerHeight + GROUP_HEADER_GAP;
  for (const plan of bandPlans) {
    if (!plan) continue;
    const offsetX = GROUP_PADDING_SIDE + (interiorW - plan.width) / 2;
    for (let i = 0; i < plan.list.length; i++) {
      const col = i % plan.cols;
      const row = Math.floor(i / plan.cols);
      positions.set(plan.list[i].id, {
        x: offsetX + col * (CHILD_W + CHILD_H_GAP),
        y: curY + row * (CHILD_H + CHILD_V_GAP),
      });
    }
    curY += plan.height + CHILD_V_GAP;
  }
  const totalHeight = (curY - CHILD_V_GAP) + GROUP_PADDING_BOTTOM;

  return { positions, width: totalWidth, height: totalHeight };
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

// Top-level node bounding boxes. ChanneledStepEdge uses these to pick
// a centerY (or centerX) that doesn't drive the edge's middle segment
// through the interior of a group container.
function collectObstacles(nodes) {
  const out = [];
  for (const n of nodes) {
    if (n.parentId) continue;
    if (n.type !== "group" && n.type !== "contract") continue;
    // Groups carry ELK-computed dims on style; contracts use the same
    // CHILD_W/CHILD_H we hand ELK for top-level layout. The rendered
    // .ps-node may be a touch smaller, but a slightly oversized
    // obstacle is fine — we'd rather route around a card than clip it.
    const w = n.style?.width ?? CHILD_W;
    const h = n.style?.height ?? CHILD_H;
    out.push({
      id: n.id,
      x: n.position?.x || 0,
      y: n.position?.y || 0,
      w,
      h,
    });
  }
  return out;
}

// Attach the right obstacle list per edge:
//   - cross-group edges get top-level groups + standalone contracts so
//     they route around other group containers
//   - intra-group edges get the OTHER children of their parent group
//     (in absolute world coords) so they don't slice through siblings
// All edges sharing the same obstacle list reference the same array so
// React Flow's prop diff doesn't churn.
function attachObstacles(edges, nodes) {
  const topLevel = collectObstacles(nodes);
  const nodeById = new Map();
  for (const n of nodes) nodeById.set(n.id, n);

  // Children grouped by parent, with positions translated to absolute
  // world coords. ReactFlow gives edge components absolute sourceX /
  // targetX, so obstacles need to match that frame.
  const siblingsByParent = new Map();
  for (const n of nodes) {
    if (!n.parentId) continue;
    const parent = nodeById.get(n.parentId);
    if (!parent) continue;
    const absX = (parent.position?.x || 0) + (n.position?.x || 0);
    const absY = (parent.position?.y || 0) + (n.position?.y || 0);
    const w = n.style?.width ?? CHILD_W;
    const h = n.style?.height ?? CHILD_H;
    if (!siblingsByParent.has(n.parentId)) siblingsByParent.set(n.parentId, []);
    siblingsByParent.get(n.parentId).push({ id: n.id, x: absX, y: absY, w, h });
  }

  return edges.map((e) => {
    let obstacles = topLevel;
    // Stubs live inside their source group (contract → that group's bottom
    // edge), so they route around the same siblings the intra-group edges do.
    if (e.data?.intraGroup || e.data?.stub) {
      const src = nodeById.get(e.source);
      const parentId = src?.parentId;
      const siblings = parentId ? siblingsByParent.get(parentId) : null;
      if (siblings) obstacles = siblings;
    }
    return {
      ...e,
      data: { ...(e.data || {}), obstacles },
    };
  });
}
