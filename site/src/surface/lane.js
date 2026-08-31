// Lane classification + ops grouping. Pure helpers — no React.
// Decides which "lane" (control / inflow / outflow / ops) a function lives
// in, what tone its port wears, and how the ops lane is sub-grouped.

import {
  LANE_META,
  OPS_CATEGORIES,
} from "./meta.js";
import {
  laneForClaims,
  priorityForClaims,
  sentenceForClaims,
  toneForClaims,
} from "../vocab/claimProjection.js";
import { qualifierForClaims } from "../vocab/claimQualifiers.js";

export function laneForFunction(fn) {
  return laneForClaims(fn) || "ops";
}

export function toneForFunction(fn, lane) {
  const claimTone = toneForClaims(fn);
  if (claimTone) return claimTone;
  return LANE_META[lane].tone;
}

export function compactActionSummary(fn) {
  // The witness qualifier (destination/expiry/backing) is appended when present and
  // at the bar — absent/indeterminate leaves the plain phrase (§7 honesty rule).
  const claimSentence = sentenceForClaims(fn);
  if (claimSentence) {
    const qualifier = qualifierForClaims(fn);
    return qualifier ? `${claimSentence} ${qualifier}` : claimSentence;
  }

  return "";
}

export function lanePriority(fn) {
  const claimPriority = priorityForClaims(fn);
  if (claimPriority !== null) return claimPriority;

  return 9;
}

export function categorizeOps(items) {
  const groups = OPS_CATEGORIES.map((cat) => ({ ...cat, items: [] }));
  const assigned = new Set();
  for (const cat of groups) {
    for (const item of items) {
      if (!assigned.has(item.key) && cat.match(item.name)) {
        cat.items.push(item);
        assigned.add(item.key);
      }
    }
  }
  return groups.filter((g) => g.items.length > 0);
}

export function machineFunctions(machine) {
  if (!machine?.lanes) return [];
  return [
    ...(machine.lanes.top || []),
    ...(machine.lanes.ops || []),
    ...(machine.lanes.left || []),
    ...(machine.lanes.right || []),
  ];
}

export function tabForLane(lane) {
  if (lane === "left") return "inflows";
  if (lane === "right") return "outflows";
  return "control";
}

function normalizeFunctionTarget(target = {}) {
  return {
    signature: String(target.functionSignature || target.fn || "").toLowerCase(),
    selector: String(target.selector || "").toLowerCase(),
  };
}

function matchesExactly(fnView, signature, selector) {
  const fnKey = String(fnView.key || "").toLowerCase();
  if (selector && fnKey.endsWith(`:${selector}`)) return true;
  return Boolean(signature) && String(fnView.signature || "").toLowerCase() === signature;
}

// A bare name ("pause") is only a name — it carries no argument list, so it
// identifies a call site only where nothing else answers to it.
function isBareName(signature) {
  return Boolean(signature) && !signature.includes("(");
}

function matchesByName(fnView, signature) {
  return String(fnView.name || "").toLowerCase() === signature;
}

// One deployed function's identity on its card. A split proxy materializes the
// same selector once per implementation, so a card can carry two rows for one
// function — same identity, and never an overload.
function fnIdentity(fnView) {
  return String(fnView.signature || fnView.key || "").toLowerCase();
}

export function findFunctionView(machine, target = {}) {
  const { signature, selector } = normalizeFunctionTarget(target);
  if (!signature && !selector) return null;
  const fns = machineFunctions(machine);
  const exact = fns.find((fnView) => matchesExactly(fnView, signature, selector));
  if (exact) return exact;
  // The scorer names example functions by bare name ("pause"), never by
  // signature. A bare name resolves only when it names exactly one function on
  // the machine: with overloads present, picking one would point the user at a
  // call site the caller never named. Distinct identities, not distinct rows —
  // duplicate rows of one function must not read as overloads.
  if (!isBareName(signature)) return null;
  const byName = fns.filter((fnView) => matchesByName(fnView, signature));
  const identities = new Set(byName.map(fnIdentity));
  return identities.size === 1 ? byName[0] : null;
}

// The caller chip a score row's controller names on an already-resolved
// function — or null. Only the function's OWN witnessed caller list can answer:
// a row's controller that this function does not list is not this function's
// caller, and marking a chip for it (or marking the chips of whoever IS listed)
// would publish a pair the graph never witnessed.
export function findCaller(fnView, address) {
  const wanted = String(address || "").toLowerCase();
  if (!fnView || !wanted) return null;
  const hit = (fnView.guard?.principals || []).find(
    (principal) => String(principal.address || "").toLowerCase() === wanted,
  );
  return hit ? String(hit.address).toLowerCase() : null;
}

// Every function on the whole graph the target names, as {machine, fnView}.
//
// The score document names an example function by bare name and never publishes
// the contract it was witnessed on — `reach_entities` is the closure the
// capability reaches, priced or not, not the host. So the graph is the only witness to where
// that name lives, and it witnesses a host only when the name lands in exactly
// one place: a name carried by two contracts resolves to neither. Exact matches
// (full signature / selector) shadow bare-name matches, so a caller that does
// know the signature is never dragged into an ambiguity it had already
// resolved.
export function findFunctionMatches(machines, target = {}) {
  const { signature, selector } = normalizeFunctionTarget(target);
  if (!signature && !selector) return [];
  const exact = [];
  const named = [];
  // Deduped on (host, identity): a duplicate row of one deployed function must
  // not turn a unique name into an "ambiguous" refusal. The key's address
  // prefix scopes the identity, so a shared name on two hosts stays two.
  const seen = new Set();
  for (const machine of machines || []) {
    for (const fnView of machineFunctions(machine)) {
      const id = `${String(fnView.key || "").split(":")[0].toLowerCase()}|${fnIdentity(fnView)}`;
      if (seen.has(id)) continue;
      if (matchesExactly(fnView, signature, selector)) {
        seen.add(id);
        exact.push({ machine, fnView });
      } else if (isBareName(signature) && matchesByName(fnView, signature)) {
        seen.add(id);
        named.push({ machine, fnView });
      }
    }
  }
  return exact.length ? exact : named;
}
