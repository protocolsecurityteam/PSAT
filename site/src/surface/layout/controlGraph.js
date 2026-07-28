// Walks the per-contract control graphs to surface direct vs. indirect callers.
// Pure — no React, no I/O.

import { isRoleIdAddress } from "../format.js";

// buildMachines + guardSummary both call this once per function (~2× per fn).
// Cache by companyData identity so the index is built once per
// /api/company response; WeakMap entries die with the payload.
const indexCache = new WeakMap();

// Build a minimal nodeInfo + edge lookup over the per-contract control graphs
// so we can surface *indirect* upstream governance context without flattening
// function-level direct callers into it.
export function buildControlGraphIndex(companyData) {
  if (!companyData) return { controllerOf: new Map(), nodeInfo: new Map() };
  const cached = indexCache.get(companyData);
  if (cached) return cached;
  const controllerOf = new Map(); // from-address → [{to, relation}]
  const nodeInfo = new Map();
  for (const contract of companyData.contracts || []) {
    const cg = contract.control_graph;
    if (!cg) continue;
    for (const node of cg.nodes || []) {
      const addr = (node.address || "").toLowerCase();
      if (addr) nodeInfo.set(addr, node);
    }
    for (const edge of cg.edges || []) {
      // safe_owner edges are UI noise — owners are rendered nested under their Safe.
      if (edge.relation === "safe_owner") continue;
      // external_call_target says the from-node CALLS the to-node. Walking it
      // in collectIndirectPath would publish the callee's owner Safe as
      // "governance context" for a function that Safe cannot reach — the
      // frontend half of the gate/callee conflation.
      if (edge.relation === "external_call_target") continue;
      // controller_value_unattributed says the target's authority_provenance
      // was ABSENT — nothing proved it gates anyone. Walking it would publish
      // an unproven governance path (Leg A's tree widening enrolled pure
      // constants and non-authority mappings this way).
      if (edge.relation === "controller_value_unattributed") continue;
      const from = (edge.from || "").toLowerCase();
      const to = (edge.to || "").toLowerCase();
      if (!from || !to || from === to) continue;
      if (!controllerOf.has(from)) controllerOf.set(from, []);
      const existing = controllerOf.get(from);
      if (!existing.some((e) => e.to === to)) {
        existing.push({ to, relation: edge.relation });
      }
    }
  }
  const index = { controllerOf, nodeInfo };
  indexCache.set(companyData, index);
  return index;
}

// Direct callers = exactly what effective_permissions emits for the function:
// direct_owner, authority_roles[].principals, controllers[].principals. Contract
// principals stay as contracts — we do NOT replace them with "first reachable
// Safe/timelock/EOA" via the control graph, because that produces false claims
// like "Safe can pause" when the function is role-gated and the Safe doesn't
// hold that role. See ProtocolSurface note at ~line 236.
export function collectDirectCallers(fn) {
  const byAddress = new Map();

  function pushPrincipal(principal, origin) {
    const address = String(principal?.address || "").toLowerCase();
    if (!address.startsWith("0x")) return;
    if (isRoleIdAddress(address)) return;
    const existing = byAddress.get(address);
    if (existing) {
      if (!existing.origins.includes(origin)) existing.origins.push(origin);
      return;
    }
    byAddress.set(address, {
      address,
      resolvedType: String(principal.resolved_type || "unknown"),
      details: principal.details && typeof principal.details === "object" ? { ...principal.details } : {},
      label: principal.label || null,
      sourceContract: principal.source_contract || null,
      sourceControllerId: principal.source_controller_id || null,
      origins: [origin],
    });
  }

  if (fn.direct_owner) {
    pushPrincipal(fn.direct_owner, "direct owner");
  }
  for (const roleGrant of fn.authority_roles || []) {
    for (const principal of roleGrant.principals || []) {
      pushPrincipal(principal, `role ${roleGrant.role}`);
    }
  }
  for (const controller of fn.controllers || []) {
    const label = controller.label || controller.controller_id || "controller";
    for (const principal of controller.principals || []) {
      pushPrincipal(principal, label);
    }
  }

  return [...byAddress.values()].sort((a, b) => a.address.localeCompare(b.address));
}

// Indirect control path = walk outgoing edges from each direct-caller contract
// principal until we hit non-contract principals (safes, timelocks, EOAs).
// Reported separately so the UI can present it as "governance context" rather
// than claiming those principals can directly call the function.
export function collectIndirectPath(directCallers, graphIndex) {
  const { controllerOf, nodeInfo } = graphIndex;
  const out = new Map();
  const visited = new Set();

  function walk(addr, depth, trail) {
    if (!addr || visited.has(addr) || depth > 6) return;
    visited.add(addr);
    const edges = controllerOf.get(addr) || [];
    for (const edge of edges) {
      const to = edge.to;
      if (!to) continue;
      const node = nodeInfo.get(to);
      const isContract = node && node.type === "contract";
      if (!isContract && !isRoleIdAddress(to)) {
        // Keep the first path we discover to each principal — shorter paths
        // are more informative and dedupe visual clutter.
        if (!out.has(to)) {
          out.set(to, {
            address: to,
            resolvedType: String(node?.type || "unknown"),
            details: node?.details && typeof node.details === "object" ? { ...node.details } : {},
            label: node?.label || null,
            path: [...trail, { address: to, relation: edge.relation }],
          });
        }
      }
      if (isContract) {
        walk(to, depth + 1, [...trail, { address: to, relation: edge.relation }]);
      }
    }
  }

  for (const caller of directCallers) {
    if (caller.resolvedType !== "contract") continue;
    visited.clear();
    walk(caller.address, 0, [{ address: caller.address, relation: "direct" }]);
  }

  return [...out.values()].sort((a, b) => a.address.localeCompare(b.address));
}

export function collectPrincipals(fn, companyData) {
  const direct = collectDirectCallers(fn);
  const graphIndex = buildControlGraphIndex(companyData);
  const indirect = collectIndirectPath(direct, graphIndex);
  return { direct, indirect };
}
