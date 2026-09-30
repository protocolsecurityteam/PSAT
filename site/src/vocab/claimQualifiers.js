import { OBSERVED_TIER } from "./claimVocab.data.js";
import { claimsOf, primaryClaim, routedOutFlows } from "./claimProjection.js";

// Witness qualifiers. A qualifier renders only when its witness is present and
// at the bar; unknown/absent falls through to the plain phrase, never a guessed
// or reassuring one. All witness parsing lives here.

// "fixed" is a proven negative. storage_setter is not fixed (an admin can
// repoint it). self / indeterminate / absent block "fixed" and render nothing.
const OUT_TARGET_FIXED = new Set([
  "immutable",
  "constant",
  "storage_no_setter",
]);
// All caller-directed and theft-shaped. caller_controlled is tx.origin, but
// ranks with param/msg_sender.
const OUT_TARGET_CALLER = new Set(["param", "msg_sender", "caller_controlled"]);

// Every out-flow entry across flow.out claims (the behavioral claim has no
// flows).
//
// "indeterminate" stays hedged: its alternatives aren't a closed set. "several"
// members are all resolved and may all execute, so each counts, and one
// caller-chosen member makes the whole caller-chosen. An empty member list
// counts as "other" rather than vanishing.
function memberKinds(kinds) {
  const out = Array.isArray(kinds)
    ? kinds
        .map((k) => (k && typeof k.kind === "string" ? k.kind : null))
        .filter(Boolean)
    : [];
  return out.length ? out : [null];
}

// A "param" destination proves the caller names it; `target_constraint` says
// whether freely.
//
// `unconstrained_proven` and `constrained` with `pins: false` (a denylist) stay
// caller-chosen. Only `constrained` with `pins: true` may soften to "gated".
// `pins` absent is undetermined (all four local cases are blacklists) and keeps
// the hazard reading. `not_determined` or no verdict (82/82 persisted params;
// every fold member) also keeps it: less knowledge must never read safer.
// msg_sender / caller_controlled are unconditional.
//
// Returns the three-state pinning answer. Without `pins`, a `denylist` guard is
// still proven non-pinning by classification; any other guard is undetermined.
export function constraintPins(verdict) {
  if (!verdict) return null;
  if (verdict.pins === true || verdict.pins === false) return verdict.pins;
  if (verdict.guard === "denylist") return false;
  return null;
}

function paramDestinationIsFreelyChosen(flow) {
  const c = flow && flow.target_constraint;
  return !!(c && c.state === "unconstrained_proven");
}

export function flowOutTargetSummary(claims) {
  let sawCaller = false;
  let sawSetter = false;
  let sawFixed = false;
  let sawGuardedParam = false; // param + guard proven to pin
  let sawUnprovenPin = false; // param + guard, pinning not proven
  let sawUnknownParam = false; // param + constraint not determined
  let sawOther = false; // indeterminate / self / unclassified: blocks "fixed"
  let total = 0;
  for (const c of claims) {
    const w = c.witness;
    // Routed outflows ask the same destination question (inbound routes
    // excluded by ``routedOutFlows``).
    let entries = null;
    if (c.claim_id === "flow.out") {
      entries =
        w && w.direction === "out" && Array.isArray(w.flows) ? w.flows : null;
    } else if (c.claim_id === "value_router") {
      entries = routedOutFlows(w);
      if (!entries.length) entries = null;
    }
    if (!entries) continue;
    for (const f of entries) {
      total += 1;
      const kind =
        f && f.target_kind && typeof f.target_kind.kind === "string"
          ? f.target_kind.kind
          : null;
      for (const k of kind === "several" ? memberKinds(f.target_kinds) : [kind]) {
        if (k === "param") {
          // A fold's one verdict is keyed to a single resolved param; applying
          // it per member would attribute one member's proof to another.
          if (paramDestinationIsFreelyChosen(f)) sawCaller = true;
          else if (f.target_constraint && f.target_constraint.state === "constrained") {
            // Only a guard proven to pin softens; denylists are caller-chosen;
            // undetermined pinning keeps the hazard wording.
            const pins = constraintPins(f.target_constraint);
            if (pins === true) sawGuardedParam = true;
            else if (pins === false) sawCaller = true;
            else sawUnprovenPin = true;
          } else sawUnknownParam = true;
        } else if (OUT_TARGET_CALLER.has(k)) sawCaller = true;
        else if (k === "storage_setter") sawSetter = true;
        else if (OUT_TARGET_FIXED.has(k)) sawFixed = true;
        else sawOther = true;
      }
    }
  }
  // A non-free param blocks "fixed" like an indeterminate one.
  if (sawGuardedParam || sawUnprovenPin || sawUnknownParam) sawOther = true;
  return {
    sawCaller,
    sawSetter,
    sawFixed,
    sawGuardedParam,
    sawUnprovenPin,
    sawUnknownParam,
    sawOther,
    total,
  };
}

// Worst case: one caller-chosen path dominates; "fixed" only when every
// out-flow is fixed.
function flowOutQualifier(claims) {
  const s = flowOutTargetSummary(claims);
  if (!s.total) {
    // No static flow lattice (approve-then-pull): the fork's proof that the
    // caller picks is the finding.
    for (const c of claims) {
      const observed = c.witness && c.witness.observed;
      if (!observed) continue;
      if (observed.destination_shape === "caller_arbitrary" && observed.shape_proved_by === "simulation") {
        return "(caller-chosen destination)";
      }
    }
    return null;
  }
  if (s.sawCaller) return "(caller-chosen destination)";
  // Directly under the proven-free case: less knowledge must never read safer.
  if (s.sawUnknownParam) return "(caller-chosen destination; gate not analysed)";
  // Hazard end, worded to claim only what's proven.
  if (s.sawUnprovenPin) return "(destination checked; pinning not proven)";
  if (s.sawSetter) return "(admin-settable destination)";
  // The only softening state; needs a present constrained verdict with a proven
  // pin.
  if (s.sawGuardedParam) return "(destination gated by a guard)";
  if (s.sawFixed && !s.sawOther) return "(fixed destination)";
  return null;
}

// `storage_setter` is a real capability; `indeterminate` must not read as
// settable or fixed.
const DELEGATECALL_DESTINATION_WORD = {
  storage_setter: "target is admin-settable storage",
  storage_no_setter: "target is storage with no writer",
  immutable: "target is immutable",
  constant: "target is a compile-time constant",
  param: "target is caller-supplied",
  indeterminate: "target not determined",
};

function delegatecallDestination(claims) {
  for (const c of claims) {
    if (c.claim_id !== "delegatecall.execute") continue;
    const d = c.witness && c.witness.destination;
    const word = d && DELEGATECALL_DESTINATION_WORD[d.target_kind];
    if (word) return `(${word})`;
  }
  return null;
}

// Worst constraint state across exec.arbitrary claims, or null. Qualifies the
// "arbitrary external call" sentence where a mandatory gate pins the target.
function execTargetConstraint(claims) {
  let guarded = null;
  let unprovenPin = false;
  let unknown = false;
  for (const c of claims) {
    if (c.claim_id !== "exec.arbitrary") continue;
    const k = c.witness && c.witness.destination_constraint;
    if (!k || typeof k.state !== "string") {
      // Unanswered: an older payload, or no parameter determines the
      // destination.
      unknown = true;
      continue;
    }
    if (k.state === "unconstrained_proven") return null;
    if (k.state === "constrained") {
      // Only a proven pin softens "arbitrary"; a denylist leaves it standing;
      // undetermined gets its own wording.
      const pins = constraintPins(k);
      if (pins === true) guarded = k;
      else if (pins !== false) unprovenPin = true;
    } else unknown = true;
  }
  if (guarded) return `(target gated by ${guarded.guard || "a guard"})`;
  if (unprovenPin) return "(target checked; pinning not proven)";
  return unknown ? "(target constraint not determined)" : null;
}

export function pauseObserved(claims) {
  for (const c of claims) {
    if (
      c.claim_id === "pause.set" &&
      c.tier === OBSERVED_TIER &&
      c.witness &&
      c.witness.observed
    ) {
      return c.witness.observed;
    }
  }
  return null;
}

export function formatDuration(seconds) {
  const days = seconds / 86400;
  if (days >= 1) return `${Math.round(days)}d`;
  const hours = seconds / 3600;
  if (hours >= 1) return `${Math.round(hours)}h`;
  return `${Math.max(1, Math.round(seconds / 60))}m`;
}

// `duration_bound_seconds === null` is two facts; `duration_bound_source`
// separates them.
//
// "no_time_reference" is a proven indefinite latch: no leaf anywhere in the
// latch's guard tree reads a clock or an unread operand (unexpanded expression
// or unentered callee). Leaf-local reading got `||` siblings and `_clock()`
// helpers wrong.
//
// "not_determined" or absent means the window wasn't established; the
// production cases are `pauseUntil`, which does expire.
export const PAUSE_BOUND_PROVEN_INDEFINITE = "no_time_reference";

function pauseQualifier(claims) {
  const o = pauseObserved(claims);
  if (!o) return null;
  // A reducer only when the fork affirmed expiry and a positive bound was read.
  if (
    o.auto_expiry === true &&
    typeof o.duration_bound_seconds === "number" &&
    o.duration_bound_seconds > 0
  ) {
    return `(auto-expires ~${formatDuration(o.duration_bound_seconds)})`;
  }
  // Indefinite only when proven (both null and no clock read); absent keys
  // never reach here.
  if (
    o.auto_expiry === null &&
    o.duration_bound_seconds === null &&
    o.duration_bound_source === PAUSE_BOUND_PROVEN_INDEFINITE
  ) {
    return "(indefinite)";
  }
  return null;
}

// Synthesis qualifiers. Both flags weaken the verdict
// (services/effects/recipes.py value_out; claims_bridge.py):
// * `input_seeded` — the principal was given the asset; the effect is observed,
//     but not that they hold it today.
// * `contract_balance_seeded` — the contract's ETH was overridden, so it's a
//     code capability, not a live outflow. Dominates.
// Only `=== true` produces a clause; absent means seeding wasn't needed.
const SEED_CLAUSE_INPUT = "with seeded inputs";
const SEED_CLAUSE_CONTRACT_BALANCE = "only if the contract were funded";

// Older supply verdicts carry the flags only inside `backing`.
function seedClauseOfObserved(observed) {
  if (!observed || typeof observed !== "object") return null;
  const backing = observed.backing;
  if (
    observed.contract_balance_seeded === true ||
    (backing && backing.contract_balance_seeded === true)
  )
    return SEED_CLAUSE_CONTRACT_BALANCE;
  if (
    observed.input_seeded === true ||
    (backing && backing.input_seeded === true)
  )
    return SEED_CLAUSE_INPUT;
  return null;
}

export const isOutflowClaim = (c) =>
  c.claim_id === "flow.out" || c.claim_id === "value_router";
export const isMintClaim = (c) => c.claim_id === "supply.mint";

// The contract-balance clause dominates.
export function seedClauseForClaims(claims, accept) {
  let clause = null;
  for (const c of claims) {
    if (!accept(c)) continue;
    const found = seedClauseOfObserved(c.witness && c.witness.observed);
    if (found === SEED_CLAUSE_CONTRACT_BALANCE) return found;
    if (found) clause = found;
  }
  return clause;
}

// Folded into the existing parenthetical; null returns it byte for byte.
function withSeedClause(qualifier, clause) {
  if (!clause) return qualifier;
  if (!qualifier) return `(${clause})`;
  return qualifier.endsWith(")")
    ? `${qualifier.slice(0, -1)}; ${clause})`
    : `${qualifier} (${clause})`;
}

// One separator so rows with dashes or parentheticals don't grow a second.
export function withSeedNote(value, clause) {
  return clause ? `${value}; ${clause}` : value;
}

export function mintBacking(claims) {
  for (const c of claims) {
    if (
      c.claim_id === "supply.mint" &&
      c.tier === OBSERVED_TIER &&
      c.witness &&
      c.witness.observed &&
      c.witness.observed.backing
    ) {
      return c.witness.observed.backing;
    }
  }
  return null;
}

function mintQualifier(claims) {
  const b = mintBacking(claims);
  if (!b) return null;
  // false is witnessed dilution; absent is unknown, never "backed".
  if (b.inflow_observed === true) return "(backed)";
  if (b.inflow_observed === false) return "(unbacked)";
  return null;
}

// Parenthetical for the primary claim, or null, from every claim of the
// primary's kind.
//
// Wraps carry flow.in and supply.mint at the same priority and flow.in wins the
// tie, so the mint's backing qualifier is promoted onto the chip ("moves value
// in (backed)") rather than lost. The seeding clause comes from the same claims
// as each branch's qualifier.
export function qualifierForClaims(fn) {
  const primary = primaryClaim(fn);
  if (!primary) return null;
  const claims = claimsOf(fn);
  const primarySeed = seedClauseOfObserved(
    primary.witness && primary.witness.observed,
  );
  switch (primary.claim_id) {
    case "flow.out":
    case "value_router":
      return withSeedClause(
        flowOutQualifier(claims),
        seedClauseForClaims(claims, isOutflowClaim),
      );
    case "exec.arbitrary":
      return withSeedClause(execTargetConstraint(claims), primarySeed);
    case "delegatecall.execute":
      return withSeedClause(delegatecallDestination(claims), primarySeed);
    case "pause.set":
      return withSeedClause(pauseQualifier(claims), primarySeed);
    case "supply.mint":
      return withSeedClause(
        mintQualifier(claims),
        seedClauseForClaims(claims, isMintClaim),
      );
    case "flow.in":
      // Only an at-bar backing witness qualifies; the seed clause comes from
      // the same mint claim.
      return withSeedClause(
        mintQualifier(claims),
        seedClauseForClaims(claims, isMintClaim),
      );
    default:
      return withSeedClause(null, primarySeed);
  }
}
