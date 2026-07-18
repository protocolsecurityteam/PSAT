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
