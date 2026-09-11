// Direct callers per function, and the indirect callers above them.
// Pure — no React, no I/O.
//
// Indirect callers are derived from the SAME witnessed-agency reach walk the
// canvas overlay and the Governs tab use (governancePath.js): a principal is
// an indirect caller of a function only when the closure from that principal
// was licensed to STAND ON one of the function's contract-typed direct
// callers — every hop down to it witnessed as agency-conferring. A principal
// that merely reaches a direct caller through a terminal power (pause-only,
// say) holds no route to the function and is not published as one.

import { isRoleIdAddress } from "../format.js";
import { principalOnChain } from "../entityKey.js";
import {
  agencyRoute,
  buildAgencyIndex,
  buildControlAdjacency,
  buildControlEdgeIndex,
  controlClosure,
  edgeClaims,
} from "./governancePath.js";

// Node identity (type/label/details) over every contract's control_graph —
// buildMachines flags passthrough timelocks off it. Built once per
// /api/company response; WeakMap entries die with the payload.
const nodeIndexCache = new WeakMap();

export function buildControlNodeIndex(companyData) {
  if (!companyData) return new Map();
  const cached = nodeIndexCache.get(companyData);
  if (cached) return cached;
  const nodeInfo = new Map();
  for (const contract of companyData.contracts || []) {
    for (const node of contract.control_graph?.nodes || []) {
      const addr = (node.address || "").toLowerCase();
      if (addr) nodeInfo.set(addr, node);
    }
  }
  nodeIndexCache.set(companyData, nodeInfo);
  return nodeInfo;
}

// Direct callers = exactly what permission_index emits for the function:
// direct_owner, authority_roles[].principals, controllers[].principals. Contract
// principals stay as contracts — we do NOT replace them with "first reachable
// Safe/timelock/EOA" via the control graph, because that produces false claims
// like "Safe can pause" when the function is role-gated and the Safe doesn't
// hold that role.
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

// Shared context for the indirect-caller derivation: the payload's principals
// (chain-scoped, inv. 13) plus the same adjacency / agency / edge indexes the
// reach overlay walks, and a per-principal closure cache — one BFS per
// principal per payload, not one per function. Keyed by payload identity and
// chain token so a chain switch gets its own scoped indexes.
const indirectCtxCache = new WeakMap();

export function buildIndirectCallerContext(companyData, activeChain = null) {
  const chainTok = activeChain || "";
  let byChain = indirectCtxCache.get(companyData);
  if (!byChain) {
    byChain = new Map();
    indirectCtxCache.set(companyData, byChain);
  }
  if (byChain.has(chainTok)) return byChain.get(chainTok);
  const flows = companyData?.fund_flows || [];
  const principals = (companyData?.principals || []).filter(
    (p) => p?.address && !isRoleIdAddress(p.address) && principalOnChain(p, activeChain)
  );
  const ctx = {
    principals,
    adjacency: buildControlAdjacency(flows, activeChain),
    agencyIndex: buildAgencyIndex(companyData?.principals || [], activeChain),
    edgeIndex: buildControlEdgeIndex(flows, activeChain),
    closures: new Map(),
  };
  byChain.set(chainTok, ctx);
  return ctx;
}

function closureFor(ctx, address) {
  let closure = ctx.closures.get(address);
  if (!closure) {
    closure = controlClosure(address, ctx.adjacency, ctx.agencyIndex);
    ctx.closures.set(address, closure);
  }
  return closure;
}

// The witnessed relation naming a hop, for the path trail: the edge's control
// claims where the graph carries them, the flow type otherwise, null when the
// pair has no carried edge at all — never an invented name.
function hopRelation(flow) {
  const claims = edgeClaims(flow);
  if (claims.length) return claims.map((c) => c.relation).join(" · ");
  return flow?.type || null;
}

// Indirect callers = the payload principals whose agency-licensed reach walk
// can stand on one of the function's contract-typed direct callers. Reported
// separately so the UI presents governance standing above the caller, not a
// direct call right. Each entry carries the agency route as `path`, ordered
// direct-caller-first to principal-last (the shape the inspector's "via" line
// reads); a principal licensed onto several direct callers keeps the shortest
// route.
export function collectIndirectCallers(directCallers, ctx) {
  const directAddrs = new Set(directCallers.map((c) => c.address));
  const contractCallers = directCallers.filter((c) => c.resolvedType === "contract");
  if (!contractCallers.length) return [];

  const out = [];
  for (const principal of ctx.principals) {
    const address = principal.address.toLowerCase();
    if (directAddrs.has(address)) continue;
    const closure = closureFor(ctx, address);
    let best = null;
    for (const caller of contractCallers) {
      const route = agencyRoute(caller.address, closure, ctx.edgeIndex);
      if (route && route.length && (!best || route.length < best.length)) best = route;
    }
    if (!best) continue;
    // agencyRoute runs principal → caller; the trail renders caller-upward.
    const path = [{ address: best[best.length - 1].to, relation: "direct" }];
    for (let i = best.length - 1; i >= 0; i -= 1) {
      path.push({ address: best[i].from, relation: hopRelation(best[i].flow) });
    }
    out.push({
      address,
      resolvedType: String(principal.type || "unknown"),
      details: principal.details && typeof principal.details === "object" ? { ...principal.details } : {},
      label: principal.label || null,
      path,
    });
  }
  return out.sort((a, b) => a.address.localeCompare(b.address));
}
