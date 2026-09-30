// Lane classification (control / inflow / outflow / ops) and ops grouping.

import {
  CONTROL_EFFECTS,
  CONTROL_HINTS,
  INPUT_EFFECTS,
  INPUT_HINTS,
  LANE_META,
  OPS_CATEGORIES,
  OUTPUT_EFFECTS,
  OUTPUT_HINTS,
} from "./meta.js";
import { functionName, hasHint } from "./format.js";
import {
  hasClaims,
  laneForClaims,
  priorityForClaims,
  sentenceForClaims,
  toneForClaims,
} from "../vocab/claimProjection.js";
import { qualifierForClaims } from "../vocab/claimQualifiers.js";

export function laneForFunction(fn) {
  // Claims decide when present; name hints only apply to claim-less functions.
  const claimLane = laneForClaims(fn);
  if (claimLane) return claimLane;

  const effects = new Set(fn.effect_labels || []);
  const loweredName = functionName(fn.function).toLowerCase();

  if ([...CONTROL_EFFECTS].some((label) => effects.has(label))) return "top";
  if ([...INPUT_EFFECTS].some((label) => effects.has(label)) && ![...OUTPUT_EFFECTS].some((label) => effects.has(label))) return "left";
  if ([...OUTPUT_EFFECTS].some((label) => effects.has(label))) return "right";
  if (hasHint(loweredName, CONTROL_HINTS)) return "top";
  if (hasHint(loweredName, INPUT_HINTS) && !hasHint(loweredName, OUTPUT_HINTS)) return "left";
  if (hasHint(loweredName, OUTPUT_HINTS)) return "right";
  return "ops";
}

export function toneForFunction(fn, lane) {
  const claimTone = toneForClaims(fn);
  if (claimTone) return claimTone;
  // Never a legacy effect-label tone for a claim-bearing function.
  if (hasClaims(fn)) return LANE_META[lane].tone;

  const effects = new Set(fn.effect_labels || []);
  if (effects.has("implementation_update") || effects.has("delegatecall_execution")) return "#9b8a9e";
  if (effects.has("ownership_transfer")) return "#9e8a8d";
  if (effects.has("role_management") || effects.has("authority_update") || effects.has("hook_update")) return "#7a8098";
  if (effects.has("pause_toggle")) return "#998a6a";
  if (effects.has("timelock_operation")) return "#8a7e6a";
  if (effects.has("asset_pull") || effects.has("mint")) return "#6a9e94";
  if (effects.has("asset_send") || effects.has("burn")) return "#9a8a6e";
  return LANE_META[lane].tone;
}

export function compactActionSummary(fn) {
  // Claim-bearing functions always resolve here. The witness qualifier is
  // appended only when present and at the bar.
  const claimSentence = sentenceForClaims(fn);
  if (claimSentence) {
    const qualifier = qualifierForClaims(fn);
    return qualifier ? `${claimSentence} ${qualifier}` : claimSentence;
  }

  const effects = new Set(fn.effect_labels || []);
  if (effects.has("implementation_update")) return "changes logic";
  if (effects.has("delegatecall_execution")) return "delegatecall path";
  if (effects.has("ownership_transfer")) return "changes owner";
  if (effects.has("authority_update")) return "changes authority";
  if (effects.has("hook_update")) return "changes hook";
  if (effects.has("pause_toggle")) return "pause control";

  if (effects.has("asset_pull") || effects.has("mint")) return "moves value in";
  if (effects.has("asset_send") || effects.has("burn")) return "moves value out";
  return "";
}

export function lanePriority(fn) {
  const claimPriority = priorityForClaims(fn);
  if (claimPriority !== null) return claimPriority;

  const effects = new Set(fn.effect_labels || []);
  if (effects.has("implementation_update") || effects.has("delegatecall_execution")) return 0;
  if (effects.has("ownership_transfer")) return 1;
  if (effects.has("role_management") || effects.has("authority_update") || effects.has("hook_update")) return 2;
  if (effects.has("pause_toggle")) return 3;
  if (effects.has("timelock_operation")) return 4;
  if (effects.has("asset_pull") || effects.has("mint")) return 5;
  if (effects.has("asset_send") || effects.has("burn")) return 6;
  if (effects.has("arbitrary_external_call") || effects.has("external_contract_call")) return 7;
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

function isBareName(signature) {
  return Boolean(signature) && !signature.includes("(");
}

function matchesByName(fnView, signature) {
  return String(fnView.name || "").toLowerCase() === signature;
}

// A split proxy materializes one selector per implementation: same identity,
// not an overload.
function fnIdentity(fnView) {
  return String(fnView.signature || fnView.key || "").toLowerCase();
}

export function findFunctionView(machine, target = {}) {
  const { signature, selector } = normalizeFunctionTarget(target);
  if (!signature && !selector) return null;
  const fns = machineFunctions(machine);
  const exact = fns.find((fnView) => matchesExactly(fnView, signature, selector));
  if (exact) return exact;
  // The scorer names functions by bare name; resolve only when exactly one
  // identity matches, never pick among overloads.
  if (!isBareName(signature)) return null;
  const byName = fns.filter((fnView) => matchesByName(fnView, signature));
  const identities = new Set(byName.map(fnIdentity));
  return identities.size === 1 ? byName[0] : null;
}

// Only the function's own witnessed caller list can answer; anything else would
// publish an unwitnessed pair.
export function findCaller(fnView, address) {
  const wanted = String(address || "").toLowerCase();
  if (!fnView || !wanted) return null;
  const hit = (fnView.guard?.principals || []).find(
    (principal) => String(principal.address || "").toLowerCase() === wanted,
  );
  return hit ? String(hit.address).toLowerCase() : null;
}

// Every function on the graph the target names, as {machine, fnView}.
//
// The score document never names a function's host (`reach_entities` is the
// reach closure), so a bare name resolves only when it lands in exactly one
// place. Exact signature/selector matches shadow bare-name matches.
export function findFunctionMatches(machines, target = {}) {
  const { signature, selector } = normalizeFunctionTarget(target);
  if (!signature && !selector) return [];
  const exact = [];
  const named = [];
  // Dedupe per (host, identity) so duplicate rows don't turn a unique name
  // ambiguous.
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
