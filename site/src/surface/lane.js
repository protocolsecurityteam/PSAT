// Lane classification + ops grouping. Pure helpers — no React.
// Decides which "lane" (control / inflow / outflow / ops) a function lives
// in, what tone its port wears, and how the ops lane is sub-grouped.

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
  qualifierForClaims,
  sentenceForClaims,
  toneForClaims,
} from "../claimsVocab.js";

export function laneForFunction(fn) {
  // Claims (Plane 1) decide the lane when present; name-hints stay layout-only
  // and only fire for claim-less functions.
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
  // A claim-bearing function with no tone of its own (e.g. approve/delegate)
  // wears its lane tone — never a legacy effect-label tone.
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
  // Every vocab entry carries a sentence, so a claim-bearing function always
  // resolves here and never falls through to the legacy phrases below. The
  // witness qualifier (destination/expiry/backing) is appended when present and
  // at the bar — absent/indeterminate leaves the plain phrase (§7 honesty rule).
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

export function findFunctionView(machine, target = {}) {
  const signature = String(target.functionSignature || target.fn || "").toLowerCase();
  const selector = String(target.selector || "").toLowerCase();
  if (!signature && !selector) return null;
  const fns = machineFunctions(machine);
  const exact = fns.find((fnView) => {
    const fnSig = String(fnView.signature || "").toLowerCase();
    const fnKey = String(fnView.key || "").toLowerCase();
    if (selector && fnKey.endsWith(`:${selector}`)) return true;
    return signature && fnSig === signature;
  });
  if (exact) return exact;
  // The scorer names example functions by bare name ("pause"), never by
  // signature. A bare name resolves only when it names exactly one function on
  // the machine: with overloads present, picking one would point the user at a
  // call site the caller never named.
  if (!signature || signature.includes("(")) return null;
  const byName = fns.filter((fnView) => String(fnView.name || "").toLowerCase() === signature);
  return byName.length === 1 ? byName[0] : null;
}
