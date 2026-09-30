// Edge bundling (aggregateEdges) and lane assignment (assignEdgeLanes) for the
// canvas.

// One bundle per (endpoint group, endpoint group) pair; intra-group edges and
// self-loops are dropped at this macro view. `data.samples` keeps the
// underlying pairs for selection; width grows logarithmically with count.
export function aggregateEdges(rawEdges, contractToGroup, principalList, machines) {
  const canonicalByLc = new Map();
  for (const m of machines || []) {
    if (m.address) canonicalByLc.set(m.address.toLowerCase(), m.address);
  }
  for (const p of principalList || []) {
    if (p.address) canonicalByLc.set(p.address.toLowerCase(), p.address);
  }

  // Groups only have ctrl-in/ctrl-out handles; a value handle on a group
  // endpoint makes React Flow draw from the centre.
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
      // No count label: the shared trunk shows weight. Per-sample caps/flowType
      // are kept so chips describe each specific pair.
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

// Keep in sync with the Handle positions in ContractNode / GroupNode.
const HANDLE_AXIS = {
  "ctrl-in": "x",   // Position.Top
  "ctrl-out": "x",  // Position.Bottom
  "value-in": "y",  // Position.Left
  "value-out": "y", // Position.Right
};

// After ELK positions nodes, assign each edge a lane per (node, handle) side so
// ChanneledStepEdge can fan them out. Bucket members share a coordinate space,
// so raw position comparison suffices.
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
