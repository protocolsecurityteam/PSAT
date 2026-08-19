// Per-function guard summary (label, sublabel, accent, principals).
// Pure — no React.

import { TYPE_META } from "../meta.js";
import { formatDelay, shortAddr } from "../format.js";
import { collectDirectCallers } from "./controlGraph.js";
import { oneShotState } from "./oneShot.js";

// Address → on-canvas contract name (the cards collapse a proxy onto its
// implementation name). Also maps a contract's implementation / secondary-impl
// addresses to that name, so a caller referenced by an implementation address
// resolves to the same collapsed name the canvas shows. Cached per payload.
const _nameMapCache = new WeakMap();
function contractDisplayNames(companyData) {
  if (!companyData) return new Map();
  const cached = _nameMapCache.get(companyData);
  if (cached) return cached;
  const m = new Map();
  for (const c of companyData.contracts || []) {
    if (c.address && c.name) m.set(c.address.toLowerCase(), c.name);
  }
  for (const c of companyData.contracts || []) {
    if (!c.name) continue;
    if (c.implementation && !m.has(c.implementation.toLowerCase())) {
      m.set(c.implementation.toLowerCase(), c.name);
    }
    for (const s of c.secondary_implementations || []) {
      if (s && !m.has(s.toLowerCase())) m.set(s.toLowerCase(), c.name);
    }
  }
  _nameMapCache.set(companyData, m);
  return m;
}

// Per-caller display descriptor (type glyph kind + name + sub), generalising the
// single-principal label logic so each direct caller can render as its own button.
function describeCaller(principal, companyData) {
  const kind = principal.resolvedType === "unknown" ? "address" : (principal.resolvedType || "address");
  const meta = TYPE_META[kind] || TYPE_META.unknown;
  const owners = Array.isArray(principal.details?.owners) ? principal.details.owners.length : 0;
  const threshold = Number(principal.details?.threshold);
  const delay = formatDelay(principal.details?.delay);
  let name;
  let sub = null;
  if (kind === "safe") {
    name = "Safe";
    sub = owners
      ? (Number.isFinite(threshold) && threshold > 0 ? `${threshold}/${owners}` : `${owners} sig`)
      : shortAddr(principal.address);
  } else if (kind === "timelock") {
    name = "Timelock";
    sub = delay || shortAddr(principal.address);
  } else if (kind === "contract") {
    // Resolve to the same name the canvas renders — a proxy caller collapses to
    // its implementation name — keyed by the caller's address or impl address.
    name = contractDisplayNames(companyData).get(principal.address?.toLowerCase())
      || principal.label
      || "Contract";
  } else if (kind === "eoa") {
    name = principal.label || "EOA";
    sub = shortAddr(principal.address);
  } else if (kind === "proxy_admin") {
    name = principal.label || "Proxy admin";
    sub = shortAddr(principal.address);
  } else {
    name = principal.label || shortAddr(principal.address);
  }
  return { kind, name, sub, accent: meta.accent };
}

function isExactEmptyCapability(cap) {
  if (!cap || typeof cap !== "object") return false;
  if (cap.kind === "finite_set") {
    return cap.membership_quality === "exact" && Array.isArray(cap.members) && cap.members.length === 0;
  }
  const children = Array.isArray(cap.children) ? cap.children : [];
  if (cap.kind === "AND") return children.some(isExactEmptyCapability);
  if (cap.kind === "OR") return children.length > 0 && children.every(isExactEmptyCapability);
  return false;
}

function isResolvedEmptyFunction(fn) {
  return fn?.status === "resolved_empty" || isExactEmptyCapability(fn?.capability_expr);
}

// Flavors of an "open" path. The function is callable by anyone in every case,
// so they share the `open` badge kind — the `shape`/sublabel says under what
// shape, read off the typed side-conditions the backend projects.
const OPEN_SUBLABEL = {
  one_shot_unread: "one-shot",
  denylist: "denylist",
  permit: "signature",
  self_service: "self-service",
  public: "public",
};

function openShape(fn) {
  const kinds = new Set((Array.isArray(fn?.conditions) ? fn.conditions : []).map((c) => c?.kind));
  if (kinds.has("denylist")) return "denylist";
  if (kinds.has("permit_sig")) return "permit";
  if (kinds.has("self_service")) return "self_service";
  return "public";
}

export function guardSummary(fn, companyData) {
  // `principals` is the direct-callers list — every consumer that reads
  // `fnView.guard.principals` only cares about who can actually call the
  // function *now*; the governance chain above that is buildMachines'
  // `indirectPrincipals`, derived from the reach walk.
  const direct = collectDirectCallers(fn);
  const principals = direct.map((p) => ({ ...p, display: describeCaller(p, companyData) }));

  if (!direct.length) {
    // One-shot initializers split the "open" badge by their on-chain latch: a
    // consumed one-shot is inert (renders like resolved_empty — nobody can call
    // it again); a live one is a critical opening (its own high-severity badge).
    const latch = oneShotState(fn);
    if (fn.authority_public && latch === "consumed") {
      const meta = TYPE_META.resolved_empty;
      return { kind: "resolved_empty", shape: "one_shot_consumed", label: meta.label,
        sublabel: "one-shot · consumed", accent: meta.accent, principals };
    }
    if (fn.authority_public && latch === "live") {
      const meta = TYPE_META.one_shot_live;
      return { kind: "one_shot_live", shape: "one_shot_live", label: meta.label,
        sublabel: "one-shot · LIVE", accent: meta.accent, principals };
    }
    const kind = fn.authority_public ? "open" : isResolvedEmptyFunction(fn) ? "resolved_empty" : "unknown";
    const meta = TYPE_META[kind];
    const shape = fn.authority_public
      ? latch
        ? "one_shot_unread"
        : openShape(fn)
      : kind === "resolved_empty"
        ? "resolved_empty"
        : "unknown";
    return {
      kind,
      shape,
      label: meta.label,
      sublabel: fn.authority_public
        ? OPEN_SUBLABEL[shape]
        : kind === "resolved_empty"
          ? "no active principal"
          : "unresolved",
      accent: meta.accent,
      principals,
    };
  }

  if (direct.length > 1) {
    return {
      kind: "many",
      label: `${direct.length}P`,
      sublabel: "mixed",
      accent: TYPE_META.many.accent,
      principals,
    };
  }

  const principal = direct[0];
  const principalKind = principal.resolvedType === "unknown" ? "address" : principal.resolvedType;
  const type = TYPE_META[principalKind] || TYPE_META.unknown;
  const safeOwners = Array.isArray(principal.details?.owners) ? principal.details.owners.length : 0;
  const threshold = Number(principal.details?.threshold);
  const delay = formatDelay(principal.details?.delay);

  let sublabel = shortAddr(principal.address);
  if (principal.resolvedType === "safe" && safeOwners) {
    sublabel = Number.isFinite(threshold) && threshold > 0 ? `${threshold}/${safeOwners}` : `${safeOwners} sig`;
  } else if (principal.resolvedType === "timelock" && delay) {
    sublabel = delay;
  } else if (principal.resolvedType === "contract") {
    // Prefer the contract's own name from the protocol inventory over the
    // generic word "contract" — fetchNextKeyIndex resolving to "AuctionManager"
    // tells the user something; "contract" doesn't.
    const targetAddr = principal.address?.toLowerCase();
    const named = (companyData?.contracts || []).find(
      (c) => c.address?.toLowerCase() === targetAddr,
    );
    sublabel = principal.label || named?.name || "contract";
  }

  return {
    kind: principalKind,
    label: type.label,
    sublabel,
    accent: type.accent,
    principals,
  };
}
