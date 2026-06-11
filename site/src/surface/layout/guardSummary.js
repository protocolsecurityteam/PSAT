// Per-function guard summary (label, sublabel, accent, principals).
// Pure — no React.

import { TYPE_META } from "../meta.js";
import { formatDelay, shortAddr } from "../format.js";
import { collectPrincipals } from "./controlGraph.js";
import { oneShotState } from "../../oneShot.js";

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
  const { direct, indirect } = collectPrincipals(fn, companyData);
  // `principals` stays as the direct list for backward compatibility — every
  // consumer that reads `fnView.guard.principals` only cares about who can
  // actually call the function *now*, not the governance chain above that.
  const principals = direct;

  if (!direct.length) {
    // One-shot initializers split the "open" badge by their on-chain latch: a
    // consumed one-shot is inert (renders like resolved_empty — nobody can call
    // it again); a live one is a critical opening (its own high-severity badge).
    const latch = oneShotState(fn);
    if (fn.authority_public && latch === "consumed") {
      const meta = TYPE_META.resolved_empty;
      return { kind: "resolved_empty", shape: "one_shot_consumed", label: meta.label,
        sublabel: "one-shot · consumed", accent: meta.accent, principals, indirect };
    }
    if (fn.authority_public && latch === "live") {
      const meta = TYPE_META.one_shot_live;
      return { kind: "one_shot_live", shape: "one_shot_live", label: meta.label,
        sublabel: "one-shot · LIVE", accent: meta.accent, principals, indirect };
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
      indirect,
    };
  }

  if (direct.length > 1) {
    return {
      kind: "many",
      label: `${direct.length}P`,
      sublabel: "mixed",
      accent: TYPE_META.many.accent,
      principals,
      indirect,
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
    indirect,
  };
}
