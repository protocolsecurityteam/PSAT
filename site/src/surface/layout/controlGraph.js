// Direct callers per function, and indirect callers above them. Indirect
// callers come from the same agency walk as the reach overlay
// (governancePath.js): only when every hop down to a contract-typed direct
// caller confers agency. Reaching a caller through a terminal power
// (pause-only) is not a route.

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

// WeakMap entries die with the payload.
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

// Exactly what effective_permissions emits. Contract principals are not
// replaced by the first reachable Safe/EOA: that produced false claims like
// "Safe can pause" on role-gated functions.
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

// One closure per principal per payload, keyed by payload and chain.
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

// Never an invented name.
function hopRelation(flow) {
  const claims = edgeClaims(flow);
  if (claims.length) return claims.map((c) => c.relation).join(" · ");
  return flow?.type || null;
}

// Reported separately: governance standing, not a call right. `path` runs
// direct caller first; the shortest route wins.
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
