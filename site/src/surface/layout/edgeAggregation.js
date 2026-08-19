// Edge bundling + lane assignment for the surface canvas. Split from
// elkLayout.js: aggregateEdges collapses raw contract→contract edges into one
// bundle per endpoint pair; assignEdgeLanes fans bundles out across each
// node side after positioning.

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
