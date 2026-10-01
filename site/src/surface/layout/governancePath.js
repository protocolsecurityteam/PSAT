// Control-edge indexing and the witnessed-agency walk. Reach claims come from
// the server (serverReach.js); this serves the ReachPath block
// (buildControlEdgeIndex + shortestControlPath) and the indirect-caller
// derivation (the agency-gated closure).
//
// Transitivity isn't free: standing on a node confers its powers only if the
// walker can act AS it. With controls_detail witnessing the power, the walk
// continues only through agency-conferring ones (pausing doesn't confer
// authority). With no witness, the walk stays blind.

import { coalesceChain } from "../entityKey.js";

// `controls_value` is an ownership edge with a value marker (the backend emits
// it instead of `controls`); excluding it hid every owner → value-moving hop.
const CONTROL_EDGE_TYPES = new Set(["principal", "controller", "controls", "controls_value"]);

// Flows are intra-chain; legacy flows without a chain are kept.
// Shared by the canvas and the walk so they agree.
export function flowOnChain(flow, activeChain) {
  if (!activeChain || !flow || flow.to_chain == null) return true;
  return coalesceChain(flow.to_chain) === activeChain;
}

// Chain-scoped so a twin's edge can't enter this chain's walk.
export function buildControlAdjacency(fundFlows = [], activeChain = null) {
  const adjacency = new Map();
  for (const flow of fundFlows || []) {
    if (!flow || !CONTROL_EDGE_TYPES.has(flow.type)) continue;
    if (!flowOnChain(flow, activeChain)) continue;
    const from = String(flow.from || "").toLowerCase();
    const to = String(flow.to || "").toLowerCase();
    if (!from || !to || from === to) continue;
    if (!adjacency.has(from)) adjacency.set(from, new Set());
    adjacency.get(from).add(to);
  }
  return adjacency;
}

// The backend dedups fund_flows per (chain, from, to), so the first edge per
// pair wins.
export function buildControlEdgeIndex(fundFlows = [], activeChain = null) {
  const index = new Map();
  for (const flow of fundFlows || []) {
    if (!flow || !CONTROL_EDGE_TYPES.has(flow.type)) continue;
    if (!flowOnChain(flow, activeChain)) continue;
    const from = String(flow.from || "").toLowerCase();
    const to = String(flow.to || "").toLowerCase();
    if (!from || !to || from === to) continue;
    if (!index.has(from)) index.set(from, new Map());
    const row = index.get(from);
    if (!row.has(to)) row.set(to, flow);
  }
  return index;
}

// Scalar relation/label or `relations` (governance_view.py); [] when
// unwitnessed.
export function edgeClaims(flow) {
  if (!flow) return [];
  if (Array.isArray(flow.relations)) {
    return flow.relations.filter((c) => c && c.relation).map((c) => ({ relation: c.relation, label: c.label || null }));
  }
  if (flow.relation) return [{ relation: flow.relation, label: flow.label || null }];
  return [];
}

// Chips conferring agency over the contract (act as it). The chip projection of
// the scorer's TRANSITIVE_CAPABILITIES via CLAIM_CAPABILITY; coarser than
// claims, but never a family the scorer rules non-transitive (pause, fund
// flows, mint/burn).
const AGENCY_CAPABILITIES = new Set([
  "upgrade", // upgrade.implementation, proxy.admin_change
  "arbitrary-call", // exec.arbitrary
  "delegatecall", // delegatecall.execute
  "authority", // authority.replace, authorized_caller.rotate
  "ownership", // ownership.transfer (+renounce/accept at chip granularity)
  "roles", // roles.grant, roles.configure (+revoke at chip granularity)
]);

// controller → targets with a witnessed agency-conferring capability
// (controls_detail).
//
// Every principal with controls_detail gets an entry, possibly empty: a
// pause-only EOA gates closed, which differs from a never-emitted address (no
// entry, blind like the backend closure). Chain-scoped; chainless legacy
// entries kept.
export function buildAgencyIndex(principals = [], activeChain = null) {
  const index = new Map();
  for (const principal of principals || []) {
    const from = String(principal?.address || "").toLowerCase();
    const detail = principal?.controls_detail;
    if (!from || !Array.isArray(detail)) continue;
    const agency = index.get(from) || new Set();
    for (const entry of detail) {
      const to = String(entry?.address || "").toLowerCase();
      if (!to || to === from) continue;
      if (activeChain && entry?.chain != null && coalesceChain(entry.chain) !== activeChain) continue;
      if ((entry?.capabilities || []).some((c) => AGENCY_CAPABILITIES.has(c))) agency.add(to);
    }
    index.set(from, agency);
  }
  return index;
}

function walkContinues(agencyIndex, from, to) {
  const agency = agencyIndex ? agencyIndex.get(from) : undefined;
  return agency ? agency.has(to) : true;
}

// The agency-gated closure from `address`. Returns { distances, expandHops,
// expandParent }:
// - distances: shortest hop to every reached address (start excluded);
// - expandHops: hop at which the walk could first continue from an address
//    (start 0). Non-agency holdings are reached but absent here; they can be
//    re-entered later via an agency route;
// - expandParent: the node that licensed continuing; following it reconstructs
//    an agency route.
export function controlClosure(address, adjacency, agencyIndex = null) {
  const start = String(address || "").toLowerCase();
  const distances = new Map();
  const expandHops = new Map();
  const expandParent = new Map();
  if (!start || !adjacency) return { distances, expandHops, expandParent };
  expandHops.set(start, 0);
  const queue = [[start, 0]];
  for (let head = 0; head < queue.length; head += 1) {
    const [current, hop] = queue[head];
    for (const to of adjacency.get(current) || []) {
      if (to === start) continue;
      if (!distances.has(to)) distances.set(to, hop + 1);
      if (!expandHops.has(to) && walkContinues(agencyIndex, current, to)) {
        expandHops.set(to, hop + 1);
        expandParent.set(to, current);
        queue.push([to, hop + 1]);
      }
    }
  }
  return { distances, expandHops, expandParent };
}

// The agency-licensed route to `target` as [{ from, to, flow }], or null if
// never licensed. `flow` is null for pairs the index doesn't carry.
export function agencyRoute(target, closure, edgeIndex) {
  const goal = String(target || "").toLowerCase();
  if (!goal || !closure?.expandHops?.has(goal) || !closure?.expandParent) return null;
  const hops = [];
  let node = goal;
  while (closure.expandParent.has(node)) {
    const from = closure.expandParent.get(node);
    hops.push({ from, to: node, flow: edgeIndex?.get(from)?.get(node) || null });
    node = from;
  }
  hops.reverse();
  return hops;
}

// Shortest control route from any of `fromAddresses` to `toAddress`,
// deliberately not agency-gated: it illustrates a pair the server already
// witnessed.
//
// Returns { host, hops } or { host: null, hops: null } when uncarried, which
// must be said rather than drawn as nothing.
export function shortestControlPath(fromAddresses, toAddress, edgeIndex) {
  const target = String(toAddress || "").toLowerCase();
  const starts = (Array.isArray(fromAddresses) ? fromAddresses : [fromAddresses])
    .map((a) => String(a || "").toLowerCase())
    .filter(Boolean);
  const none = { host: null, hops: null };
  if (!target || !starts.length || !edgeIndex) return none;

  // `origin` remembers which host won.
  const prev = new Map();
  const origin = new Map();
  const seen = new Set();
  const queue = [];
  for (const start of starts) {
    if (start === target) return { host: start, hops: [] };
    if (seen.has(start)) continue;
    seen.add(start);
    origin.set(start, start);
    queue.push(start);
  }
  for (let head = 0; head < queue.length; head += 1) {
    const current = queue[head];
    for (const [to, flow] of edgeIndex.get(current) || []) {
      if (seen.has(to)) continue;
      seen.add(to);
      prev.set(to, { from: current, flow });
      origin.set(to, origin.get(current));
      if (to === target) {
        const hops = [];
        let node = to;
        while (prev.has(node)) {
          const step = prev.get(node);
          hops.push({ from: step.from, to: node, flow: step.flow });
          node = step.from;
        }
        hops.reverse();
        return { host: origin.get(to), hops };
      }
      queue.push(to);
    }
  }
  return none;
}

// Dedup by address; tag same-name proxy/impl families `proxy` / `impl`.
export function dedupeAndTagRows(rows = []) {
  const seen = new Set();
  const out = [];
  for (const row of rows) {
    const address = String(row.address || "").toLowerCase();
    if (!address || seen.has(address)) continue;
    seen.add(address);
    out.push({ ...row, address });
  }

  const byName = new Map();
  for (const row of out) {
    const key = String(row.name || "").toLowerCase();
    if (!key) continue;
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(row);
  }
  for (const group of byName.values()) {
    if (group.length < 2) continue;
    const hasProxy = group.some((r) => r.is_proxy);
    const hasImpl = group.some((r) => !r.is_proxy);
    if (hasProxy && hasImpl) {
      for (const row of group) row.tag = row.is_proxy ? "proxy" : "impl";
    }
  }
  return out;
}
