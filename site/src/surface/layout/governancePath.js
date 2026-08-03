// Governance-path derivation for the universal entity card's Governs tab.
// Pure — no React.
//
// The "Appears in governance path for" section lists the contracts an entity
// (transitively) governs. A principal entity reads it straight off
// principal.controls (server CGN reachability). A machine-only authority (an
// analyzed contract the server never emits as a principal, e.g. EtherFiTimelock)
// has no such list, so we reconstruct the same reachability client-side by
// walking the payload's control-relation fund_flows edges.

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

// Map<addrLc, hop distance ≥ 1> — every address reachable from `address` over
// the control adjacency, with the number of hops on the SHORTEST route to it
// (BFS, so the first arrival is the shortest). The start is excluded: it is
// where the walk begins, not something it reaches.
export function controlReach(address, adjacency) {
  const start = String(address || "").toLowerCase();
  const out = new Map();
  if (!start || !adjacency) return out;
  const seen = new Set([start]);
  let frontier = [start];
  let hop = 0;
  while (frontier.length) {
    hop += 1;
    const next = [];
    for (const current of frontier) {
      for (const to of adjacency.get(current) || []) {
        if (seen.has(to)) continue;
        seen.add(to);
        out.set(to, hop);
        next.push(to);
      }
    }
    frontier = next;
  }
  return out;
}

// Shortest control-graph route from any of `fromAddresses` to `toAddress`.
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

// Transitive set of addresses reachable from `address` over the control
// adjacency, excluding the start itself. Order is discovery order; the card
// dedups + sorts downstream.
export function governancePathTargets(address, adjacency) {
  const start = String(address || "").toLowerCase();
  if (!start || !adjacency) return [];
  const out = [];
  const seen = new Set([start]);
  const stack = [start];
  while (stack.length) {
    const current = stack.pop();
    for (const next of adjacency.get(current) || []) {
      if (seen.has(next)) continue;
      seen.add(next);
      out.push(next);
      stack.push(next);
    }
  }
  return out;
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
