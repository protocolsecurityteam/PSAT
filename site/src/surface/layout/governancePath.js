// Control-graph reach derivation: the entity card's Governs tab and the
// canvas reach overlay. Pure — no React.
//
// The walk follows the payload's control-relation fund_flows edges, but
// transitivity is not free: standing on a node confers that node's own powers
// only when the walker can act AS the node. Where the payload witnesses what a
// controller can do to a target (principals[].controls_detail capabilities),
// the walk continues through the target only if that power is
// agency-conferring — pausing a contract reaches the contract, it never
// confers the contract's authority over anything else. Where no such witness
// exists (a plain contract standpoint, a machine-only authority like
// EtherFiTimelock), the walk stays blind, which is exactly how the backend
// closure treats contract nodes (services/scoring/planes.py
// load_control_closure + fold.py's seed-gated expansion).

import { coalesceChain } from "../entityKey.js";

// Control-relation edge types the walk follows. Value movement (controls_value)
// is deliberately excluded — that is the Inflows/Outflows dimension, not
// governance.
const CONTROL_EDGE_TYPES = new Set(["principal", "controller", "controls"]);

// Whether a fund_flows edge belongs to ``activeChain``. A flow is intra-chain
// (``from_chain`` === ``to_chain`` in the payload), so ``to_chain`` is
// representative. With no active chain the page is single-chain and every flow
// is kept; a legacy flow with no chain field is kept on any chain (inv. 13) —
// the single home for this predicate so the canvas fund-flow scope (the edges
// SurfaceCanvas draws) and the governance-adjacency walk agree.
export function flowOnChain(flow, activeChain) {
  if (!activeChain || !flow || flow.to_chain == null) return true;
  return coalesceChain(flow.to_chain) === activeChain;
}

// from-address (lc) → Set<to-address (lc)> over control-relation edges only.
//
// The Surface page is chain-scoped, so when ``activeChain`` is given only flows
// on that chain feed the adjacency: a same-address twin's edge on another chain
// must not enter this chain's walk (see flowOnChain).
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

// from-address (lc) → Map<to-address (lc), edge> over the same control-relation
// edges buildControlAdjacency walks, keeping the edge itself so a hop can name
// what it is. Parallel edges between one pair collapse to the first seen — the
// backend already dedups fund_flows per (chain, from, to), so a second entry
// here would be a payload the graph never emits.
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

// The witnessed claims on a control edge, normalized to one list. The payload
// publishes the single-claim case as scalar relation/label and the multi-claim
// case as `relations` (services/aggregations/company_overview.py); an edge the
// control graph never witnessed a relation for yields [] — the consumer shows
// the flow type alone rather than inventing a name for the hop.
export function edgeClaims(flow) {
  if (!flow) return [];
  if (Array.isArray(flow.relations)) {
    return flow.relations.filter((c) => c && c.relation).map((c) => ({ relation: c.relation, label: c.label || null }));
  }
  if (flow.relation) return [{ relation: flow.relation, label: flow.label || null }];
  return [];
}

// Capability chips that confer AGENCY over the contract they are held on:
// holding one lets the holder act as that contract (upgrade it, own it,
// replace its authority, grant themselves roles on it, make it execute
// arbitrary calls / delegatecalls) — so control witnessed one hop further
// genuinely transfers. This is the chip-vocabulary projection of the scorer's
// TRANSITIVE_CAPABILITIES (services/scoring/constants.py) through
// _CLAIM_CAPABILITY (services/aggregations/company_overview.py); the payload
// publishes chips, not claim ids, so the chip is the witness granularity
// available here. Chips are coarser than claims ("ownership" also covers
// renounce/accept, "roles" also covers revoke), so the gate can admit a seed
// the scorer's finer set would not — but never a capability family the scorer
// rules non-transitive: pause, fund flows, mint/burn never expand.
export const AGENCY_CAPABILITIES = new Set([
  "upgrade", // upgrade.implementation, proxy.admin_change
  "arbitrary-call", // exec.arbitrary
  "delegatecall", // delegatecall.execute
  "authority", // authority.replace, authorized_caller.rotate
  "ownership", // ownership.transfer (+renounce/accept at chip granularity)
  "roles", // roles.grant, roles.configure (+revoke at chip granularity)
]);

// controller address (lc) → Set<target address (lc)> of contracts the payload
// witnesses an agency-conferring capability on, read off controls_detail — the
// one per-(controller, contract) capability witness the payload carries.
//
// EVERY principal with a controls_detail gets an entry, possibly empty: an
// emitted principal whose witnessed powers are all non-agency (a pause-only
// EOA) must gate CLOSED, and that is a different state from an address the
// payload never emitted as a principal at all (no entry — the walk treats it
// as a plain contract node and stays blind, matching the backend closure).
// Detail entries are chain-scoped like the adjacency (inv. 13); an entry with
// no chain field is legacy and kept on any chain.
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

// Whether the walk may CONTINUE through `to` when standing on `from`: the
// witnessed-agency rule where a witness exists, blind where none does.
function walkContinues(agencyIndex, from, to) {
  const agency = agencyIndex ? agencyIndex.get(from) : undefined;
  return agency ? agency.has(to) : true;
}

// The reach closure from `address` over the control adjacency.
//
// Returns { distances, expandHops }, both Map<addrLc, hop> with the start
// excluded from distances:
//  - distances:  every reached address at the hop count of the SHORTEST route
//    to it — what the reach chips show;
//  - expandHops: the hop at which the walk could first CONTINUE from an
//    address (start at 0). An address held only by a non-agency power is
//    reached but absent here — it is where a claim ends, not a thoroughfare.
//    It can still be re-entered later through an agency route (its chip keeps
//    the shorter hop; expansion resumes at the longer one) — dropping that
//    re-entry would hide routes the control graph carries.
export function controlClosure(address, adjacency, agencyIndex = null) {
  const start = String(address || "").toLowerCase();
  const distances = new Map();
  const expandHops = new Map();
  if (!start || !adjacency) return { distances, expandHops };
  expandHops.set(start, 0);
  const queue = [[start, 0]];
  for (let head = 0; head < queue.length; head += 1) {
    const [current, hop] = queue[head];
    for (const to of adjacency.get(current) || []) {
      if (to === start) continue;
      if (!distances.has(to)) distances.set(to, hop + 1);
      if (!expandHops.has(to) && walkContinues(agencyIndex, current, to)) {
        expandHops.set(to, hop + 1);
        queue.push([to, hop + 1]);
      }
    }
  }
  return { distances, expandHops };
}

// Map<addrLc, hop distance ≥ 1> — every address reachable from `address`, at
// its shortest witnessed hop count. The start is excluded: it is where the
// walk begins, not something it reaches.
export function controlReach(address, adjacency, agencyIndex = null) {
  return controlClosure(address, adjacency, agencyIndex).distances;
}

// The walk-tree edges of a reach closure: every control edge `u → v` the walk
// actually traversed to give v its shortest hop count — u was a point the walk
// could continue from, and stepping off it reached v at its charged distance.
// Returned as a Set of "from>to" keys (both lowercased).
//
// Highlighting this set draws the routes the hop counts on the reach chips
// were derived from, and nothing else. A diamond (two continuing parents both
// reaching the same child at its shortest hop) contributes both edges: both
// are genuine shortest routes, and dropping either would claim a route the
// walk never ruled out. Edges leaving a terminal node (one the walk was not
// licensed to continue from), edges running backwards, and same-tier edges are
// all excluded — none of them carried a claim, so drawing them would overstate
// what the walk proved.
//
// `closure` is a controlClosure() result over the same adjacency.
export function controlPathEdges(address, adjacency, closure) {
  const start = String(address || "").toLowerCase();
  const out = new Set();
  if (!start || !adjacency || !closure?.distances || !closure?.expandHops) return out;
  for (const [from, hop] of closure.expandHops) {
    for (const to of adjacency.get(from) || []) {
      if (closure.distances.get(to) === hop + 1) out.add(`${from}>${to}`);
    }
  }
  return out;
}

// Shortest control-graph route from any of `fromAddresses` to `toAddress`.
//
// Deliberately NOT agency-gated: its callers illustrate a reach pair the
// SERVER already witnessed (a finding's host → reach entity), and the backend
// closure that witnessed it walks hops this client holds no capability detail
// for. Gating here would refuse to draw routes the score document vouches for;
// the route names control relations along the way, it does not claim the
// walker wields each hop.
//
// Returns { host, hops: [{ from, to, flow }] } for a route this graph carries,
// or { host: null, hops: null } when it carries none — an absent route is a
// distinct third state from a zero-length one, and the consumer must say the
// path is not carried rather than draw nothing and imply directness.
export function shortestControlPath(fromAddresses, toAddress, edgeIndex) {
  const target = String(toAddress || "").toLowerCase();
  const starts = (Array.isArray(fromAddresses) ? fromAddresses : [fromAddresses])
    .map((a) => String(a || "").toLowerCase())
    .filter(Boolean);
  const none = { host: null, hops: null };
  if (!target || !starts.length || !edgeIndex) return none;

  // Multi-source BFS: whichever host reaches the target in the fewest hops wins,
  // and `origin` remembers which one that was so the block can name it.
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

// The addresses reachable from `address` over the control adjacency, excluding
// the start itself — same witnessed-agency walk the reach overlay draws, so the
// Governs tab and the canvas never disagree about what an entity reaches.
// Order is discovery order; the card dedups + sorts downstream.
export function governancePathTargets(address, adjacency, agencyIndex = null) {
  return [...controlClosure(address, adjacency, agencyIndex).distances.keys()];
}

// Dedup a governed-contract row list by lowercased address, then disambiguate
// genuine same-name families that differ by address: when a name maps to both a
// proxy and a non-proxy address, tag each `proxy` / `impl`. Same-name rows that
// don't split proxy-vs-impl are left untagged (the short address disambiguates
// them). Rows are { address, name, is_proxy, ... }; returns fresh objects with a
// lowercased address and an optional `tag`.
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
