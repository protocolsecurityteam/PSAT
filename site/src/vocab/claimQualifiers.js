import { OBSERVED_TIER } from "./claimVocab.data.js";
import { claimsOf, primaryClaim, routedOutFlows } from "./claimProjection.js";

// ── Witness qualifiers ───────────────────────────────────────────────────────
//
// The honesty rule (mirror of the backend witness bar) — a confidence gap is
// reported as a gap, never rounded into a favourable answer:
// a qualifier renders ONLY when its witness field is present and at the bar.
// unknown / absent / indeterminate always falls through to the plain phrase —
// never a guessed qualifier, never a reassurance laundered from absence. That is
// the whole point: "moves value out" with no destination witness must NOT read
// "(fixed destination)".
//
// All witness parsing lives here (the single-vocabulary-module invariant): chip
// (lane.compactActionSummary), summary line (claimSummaryLine) and the inspector
// (claimWitnessFacts / terminalControllerNote / signerOverlapNote) all read these.

// Out-flow destination kinds. "fixed" is a PROVEN NEGATIVE — the destination
// provably cannot be redirected. storage_setter is deliberately NOT fixed: an
// admin can repoint it, so it earns its own honest phrasing rather than a
// reassurance. self / indeterminate / absent are neither proven-fixed nor
// caller-chosen → they block a "fixed" claim and render nothing.
const OUT_TARGET_FIXED = new Set([
  "immutable",
  "constant",
  "storage_no_setter",
]);
// param / msg_sender / caller_controlled (tx.origin) are all caller-directed
// destinations — the same theft-shaped class. caller_controlled is a distinct
// address fact (the origin EOA, not msg.sender) but must never read as fixed and
// dominates the worst-case precedence exactly like param/msg_sender.
const OUT_TARGET_CALLER = new Set(["param", "msg_sender", "caller_controlled"]);

// Scan every out-flow entry across all flow.out claims (the static claim carries
// witness.flows[]; the behavioral one has no direction/flows and is skipped).
//
// Reads the FOLDED target_kind, with one exception the fold itself licenses.
// "indeterminate" stays one hedged word: some site was not resolved, so the
// alternatives are not a closed set and promoting one of them would turn "we
// cannot say" into a verdict the fold never reached.
//
// "several" is different in kind. Every member IS resolved and together they are
// the complete set of what the function does, so each member is counted — and
// because the qualifier below takes the worst case, a set containing one
// caller-chosen destination reads as caller-chosen. That is not promoting a
// guess: the caller provably names the destination on that path, and the members
// are not even alternatives — they may all execute in one call. Ignoring them
// here would suppress the theft signal on precisely the functions that pay a
// caller-named address alongside a fixed one.
// The member kinds behind a "several" fold. An empty/absent list falls back to a
// single null, which the caller counts as "other" — a "several" without its
// members is an artifact we cannot read, and it must not silently vanish from
// the tally.
function memberKinds(kinds) {
  const out = Array.isArray(kinds)
    ? kinds
        .map((k) => (k && typeof k.kind === "string" ? k.kind : null))
        .filter(Boolean)
    : [];
  return out.length ? out : [null];
}

// A "param" destination proves the caller NAMES the destination. Whether they
// can name it FREELY is a separate, three-state question the producer answers in
// `target_constraint` — a mandatory revert gate that pins the parameter (a
// storage equality, an allowlist, a hash commitment) means the caller chooses
// from a set an authority wrote, which is not the theft-shaped fact this
// vocabulary's "caller-chosen" wording asserts.
//
// Two verdicts license that wording: `unconstrained_proven`, and `constrained`
// whose guard PROVABLY does not pin (`pins: false` — a denylist excludes a set
// and leaves the rest of the address space freely chosen; the producer's own
// docstring says the consumer must keep treating it as caller-chosen).
// `constrained` with `pins: true` is the only state that may SOFTEN the
// reading into "gated"; `pins` null/absent is a real guard whose set semantics
// are not determined (another contract's revert surface can be a blacklist as
// easily as an allowlist — on the local artifacts all four such rows ARE
// blacklists), so it keeps the hazard reading with its own wording.
// `not_determined` and an ABSENT field KEEP the caller-chosen hazard reading
// (same tone as the unconstrained case), with wording that notes the gate was
// not analysed. The `param` destination is the PROVEN fact here — the caller
// names the address — and the missing verdict is only the answer to a
// secondary question; reading strictly-less-knowledge as strictly-safer would
// demote every payload minted before the producer answered (82/82 persisted
// param flow destinations carry no verdict) and every fold member, for which
// the producer never mints a verdict at all. Only a PRESENT `constrained`
// verdict may soften. Nothing here launders a constraint into reassurance, and
// no absence of proof ever suppresses the theft-shaped signal.
//
// msg_sender / caller_controlled carry no such question: the destination IS the
// caller, provably, so they stay unconditional.
// The three-state pinning answer of a `constrained` verdict. `pins` is the
// producer's field; on a payload minted before it existed the guard NAME still
// carries one proof: `denylist` is BY CLASSIFICATION a falsy membership — a
// guard that excludes a set and pins nothing — so it reads as proven
// non-pinning even without the field. Every other guard without `pins` is
// undetermined: absence of the proof is never the proof.
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
  let sawGuardedParam = false; // param + mandatory gate PROVEN to pin (pins: true)
  let sawUnprovenPin = false; // param + real guard, pinning not proven (pins null/absent)
  let sawUnknownParam = false; // param + constraint not determined
  let sawOther = false; // indeterminate / self / unclassified → blocks a "fixed" claim
  let total = 0;
  for (const c of claims) {
    const w = c.witness;
    // A routed outflow counts here too: the funds leave a contract this entry
    // calls, and the destination question ("can the caller name it") is the same
    // one. Inbound routes are excluded by ``routedOutFlows``.
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
          // A "several" fold carries ONE constraint verdict for the flow, and
          // the verdict is keyed to the resolved target_param_index — which a
          // fold only has when one site supplied it. Reading it per member
          // would attribute one member's proof to another, so a param member
          // inside a fold is only ever freely-chosen when the flow-level
          // verdict says so.
          if (paramDestinationIsFreelyChosen(f)) sawCaller = true;
          else if (f.target_constraint && f.target_constraint.state === "constrained") {
            // Only a guard PROVEN to pin may soften the reading. A proven
            // non-pinning guard (denylist) IS the caller-chosen fact; a guard
            // whose pinning is not determined keeps the hazard reading under
            // its own wording — three states, none conflated.
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
  // A param destination without a proven-free verdict still blocks the "fixed"
  // reading exactly like an indeterminate one — otherwise a function with one
  // guarded (or unanalysed) param and one immutable path would read
  // "(fixed destination)".
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

// Worst-case across a multi-flow function: a single caller-chosen path is the
// theft signal (proven positive) and dominates; "fixed" is asserted only when
// EVERY classified out-flow is fixed and none is indeterminate/self/unclassified.
function flowOutQualifier(claims) {
  const s = flowOutTargetSummary(claims);
  if (!s.total) {
    // No static flow lattice at all (the approve-then-pull shape). If the fork
    // PROVED the caller picks the destination, that is the finding — the chip stayed
    // unqualified only because the static side had nothing to say.
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
  // An UNANALYSED param ranks directly under the proven-free case and ABOVE
  // every softer reading: the caller provably names the destination, and with
  // no verdict at all — legacy payload, `several`-fold member, producer not yet
  // run — nothing is known that the unconstrained case doesn't also satisfy.
  // Knowing strictly less must never read strictly safer; the
  // wording keeps the caller-chosen claim and notes the unanswered question.
  if (s.sawUnknownParam) return "(caller-chosen destination; gate not analysed)";
  // A real guard whose pinning is NOT proven sits at the hazard end with the
  // caller-chosen case (it may well be a blacklist — all four local rows are),
  // but under wording that claims exactly what was proven and no more.
  if (s.sawUnprovenPin) return "(destination checked; pinning not proven)";
  if (s.sawSetter) return "(admin-settable destination)";
  // Below admin-settable in the worst case and above "fixed": a gate an
  // authority wrote is weaker evidence than an unwritable address. This is the
  // ONLY param state that softens — it takes a PRESENT constrained verdict
  // with a proven pin to get here.
  if (s.sawGuardedParam) return "(destination gated by a guard)";
  if (s.sawFixed && !s.sawOther) return "(fixed destination)";
  return null;
}

// Where the foreign code a delegatecall runs comes from. The claim itself says
// only that it happens; who can change the code is the severity question, and
// the three states are kept distinct — `storage_setter` names a real capability,
// `indeterminate` is an unanswered question that must not read as either
// "settable" or "fixed".
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

// Worst destination-constraint state across a function's exec.arbitrary claims,
// or null when none carries the field. The claim's own sentence ("arbitrary
// external call") asserts an unconstrained target; where a mandatory gate pins
// it — an allowlist, the timelock's hash commitment — the sentence overstates,
// and this is the qualifier that says so beside it.
function execTargetConstraint(claims) {
  let guarded = null;
  let unprovenPin = false;
  let unknown = false;
  for (const c of claims) {
    if (c.claim_id !== "exec.arbitrary") continue;
    const k = c.witness && c.witness.destination_constraint;
    if (!k || typeof k.state !== "string") {
      // No verdict on the claim at all: the question was not answered for this
      // row (an older payload, or a destination no parameter determines).
      unknown = true;
      continue;
    }
    if (k.state === "unconstrained_proven") return null;
    if (k.state === "constrained") {
      // Only a guard PROVEN to pin softens the claim's own "arbitrary"
      // sentence. A proven non-pinning guard (pins: false, a denylist) leaves
      // the sentence standing unqualified — that is the honest reading, not a
      // gap. Pinning not determined gets its own wording; it never reads as
      // "gated".
      const pins = constraintPins(k);
      if (pins === true) guarded = k;
      else if (pins !== false) unprovenPin = true;
    } else unknown = true;
  }
  if (guarded) return `(target gated by ${guarded.guard || "a guard"})`;
  if (unprovenPin) return "(target checked; pinning not proven)";
  return unknown ? "(target constraint not determined)" : null;
}

// The fork-observed pause summary (only the behavioral tier carries it).
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

// `duration_bound_seconds === null` is TWO facts, and duration_bound_source is
// the only thing that separates them. "no_time_reference" is a PROVEN indefinite
// latch: no leaf ANYWHERE in the guard tree that reads the latch touches a clock,
// and nothing anywhere in that tree is an operand whose contents were never read
// (an undecomposed expression, or a NAMED CALLEE the recorder does not enter).
// Both conditions are part of the proof, not hygiene, and both are asked of the
// whole tree — a leaf-local reading called `!frozen || block.timestamp > unpauseAt`
// proven-most-severe (Solidity lowers `||` into sibling leaves), read a
// pre-widening `block.timestamp - pausedUntil < 2592000` the same way, and read
// `!frozen || _clock() > unpauseAt` — the Uniswap-V3 / OZ-Governor idiom of
// reading time through a helper — the same way again.
// "not_determined" — and an ABSENT source, which is every verdict written before
// the source field existed — means the window was not established; the four rows
// in production that carry it are all `pauseUntil`, a latch that DOES expire, so
// rendering them "(indefinite)" asserted the most severe reading from an
// extraction failure.
export const PAUSE_BOUND_PROVEN_INDEFINITE = "no_time_reference";

function pauseQualifier(claims) {
  const o = pauseObserved(claims);
  if (!o) return null;
  // A bounded auto-expiry is a severity REDUCER only when the fork affirmed it
  // (auto_expiry === true) AND a positive duration bound was read. auto_expiry
  // false means the fork contradicted the static bound → not a mitigation → plain.
  if (
    o.auto_expiry === true &&
    typeof o.duration_bound_seconds === "number" &&
    o.duration_bound_seconds > 0
  ) {
    return `(auto-expires ~${formatDuration(o.duration_bound_seconds)})`;
  }
  // Indefinite latch = most severe, and it is now a PROVEN state rather than the
  // absence of a bound: both fields present AND null AND static proved the latch
  // reads no clock. Absent keys (unknown) never reach here — undefined !== null.
  if (
    o.auto_expiry === null &&
    o.duration_bound_seconds === null &&
    o.duration_bound_source === PAUSE_BOUND_PROVEN_INDEFINITE
  ) {
    return "(indefinite)";
  }
  return null;
}

// ── Synthesis qualifiers ─────────────────────────────────────────────────────
//
// `input_seeded` / `contract_balance_seeded` ride on the behavioral witness and
// both WEAKEN the verdict they travel with (services/effects/recipes.py, the
// `value_out` docstring; services/effects/claims_bridge.py's consumer contract).
// The producer forwards them precisely so a consumer cannot read the claim as
// stronger than the observation, so the renderer states them beside the fact
// they qualify rather than dropping them:
//   * `input_seeded` — the acting principal was GIVEN the asset the function
//     pulls. The effect is still fully observed; what is not claimed is that this
//     principal holds the asset today.
//   * `contract_balance_seeded` — the TARGET CONTRACT's own ETH balance was
//     overridden before the payout ran, so the verdict is a capability of the
//     code ("would move value if the contract were funded"), NOT a live outflow
//     of present treasury. It is the stronger weakener and therefore dominates.
// Three states, kept apart: true → the clause; false → nothing; ABSENT → nothing,
// because absence contractually means no seeding was NEEDED, never "seeded but
// undisclosed". Only `=== true` may produce a clause.
const SEED_CLAUSE_INPUT = "with seeded inputs";
const SEED_CLAUSE_CONTRACT_BALANCE = "only if the contract were funded";

// A supply verdict written before the producer mirrored these onto `details`
// carries them ONLY inside `backing`, so both places are read; a `backing` whose
// flags are explicitly false is an unseeded observation and stays silent.
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

// Worst case across the claims a rendered fact is built from: the contract-balance
// clause dominates because it is the strictly weaker verdict.
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

// Fold the clause into an existing parenthetical rather than opening a second
// one — same shape as "(caller-chosen destination; gate not analysed)". A null
// clause returns the qualifier untouched, byte for byte.
function withSeedClause(qualifier, clause) {
  if (!clause) return qualifier;
  if (!qualifier) return `(${clause})`;
  return qualifier.endsWith(")")
    ? `${qualifier.slice(0, -1)}; ${clause})`
    : `${qualifier} (${clause})`;
}

// Same clause, appended to a verbose inspector row. Kept to one separator so a
// row that already contains an em-dash or a parenthetical does not grow a second.
export function withSeedNote(value, clause) {
  return clause ? `${value}; ${clause}` : value;
}

// The fork-observed mint-backing object (behavioral tier only).
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
  // inflow_observed === false is a witnessed dilution signal (supply rose with
  // no matching inflow); absence of the field is unknown, never "backed".
  if (b.inflow_observed === true) return "(backed)";
  if (b.inflow_observed === false) return "(unbacked)";
  return null;
}

// The glanceable parenthetical for the primary claim, or null. Reads the witness
// of every claim of the primary's kind (so a static destination + a behavioral
// reach on the same flow.out both feed the answer).
//
// Wrap-shape backing visibility (register #10): a wrap carries BOTH flow.in and
// supply.mint at priority 6; primaryClaim tie-breaks to flow.in ("f" < "s"), so
// the backing witness would only ever surface in the inspector. flow.in has no
// destination-theft concept of its own, so when it is primary we promote the
// co-occurring mint's backing qualifier onto the chip — "moves value in (backed)"
// — instead of dropping it. Pure-mint (supply.mint primary, no flow.in) is
// unchanged and still handled by the supply.mint case below.
//
// The synthesis clause rides along on every branch, read from the SAME claims the
// branch's own qualifier is built from, so it is never attributed to a sibling
// claim that was not seeded. The `default` branch reads the primary's own witness:
// only `value_out` and `supply` recipes stamp these flags today, and a branch
// that returned a bare null would silently drop the qualifier the day another
// effect class starts carrying one.
export function qualifierForClaims(fn) {
  const primary = primaryClaim(fn);
  if (!primary) return null;
  const claims = claimsOf(fn);
  const primarySeed = seedClauseOfObserved(
    primary.witness && primary.witness.observed,
  );
  switch (primary.claim_id) {
    case "flow.out":
    // A routed outflow answers the same destination question, so it takes the
    // same qualifier; flowOutTargetSummary already admits only outbound routes.
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
      // Only a co-occurring, at-bar mint-backing witness qualifies a value-in
      // chip; a plain inflow (no mint, or mint without backing) stays unqualified.
      // The seeding clause comes from the same mint claim — a "(backed)" read off
      // a seeded execution must not present as a backing observed in live state.
      return withSeedClause(
        mintQualifier(claims),
        seedClauseForClaims(claims, isMintClaim),
      );
    default:
      return withSeedClause(null, primarySeed);
  }
}
