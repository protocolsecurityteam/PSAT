import { claimsOf, routedOutFlows } from "./claimProjection.js";
import {
  PAUSE_BOUND_PROVEN_INDEFINITE,
  constraintPins,
  formatDuration,
  isMintClaim,
  isOutflowClaim,
  mintBacking,
  pauseObserved,
  seedClauseForClaims,
  withSeedNote,
} from "./claimQualifiers.js";


const TARGET_KIND_WORD = {
  immutable: "immutable address",
  constant: "compile-time constant",
  storage_no_setter: "storage (no setter — fixed)",
  storage_setter: "storage (admin-settable)",
  param: "caller-supplied argument",
  msg_sender: "msg.sender (the caller)",
  caller_controlled: "caller (tx.origin)",
  self: "the contract itself",
  token_owner: "the token's current owner",
  several: "several destinations (each resolved)",
  indeterminate: "indeterminate",
};

const AMOUNT_KIND_WORD = {
  msg_value: "msg.value (attached ETH)",
  param: "caller-supplied argument",
  whole_balance: "the whole balance",
  bounded_by_storage: "bounded by a storage value",
  fixed_constant: "a fixed constant",
  balance_delta: "a balance delta",
  // A real ceiling: min of the contract's balance and something else.
  capped_by_balance: "capped at the contract's own balance",
  // Provenance, not a ceiling: the external rate is unseen state.
  param_derived: "an external conversion of a caller-supplied argument",
  // ABI argument or msg.value, so no single ABI slot.
  caller_supplied: "a caller-supplied amount",
  // Not a quantity: which NFT moves.
  token_identity: "a token id (one NFT)",
  several: "several amounts (each resolved)",
  indeterminate: "indeterminate",
};

const TIER_WORD = {
  dispositive_ast: "dispositive AST",
  static_trace: "static trace",
};

function kindTierText(kt, wordMap) {
  if (!kt || typeof kt.kind !== "string") return null;
  const word = wordMap[kt.kind] || kt.kind;
  const tier = TIER_WORD[kt.tier];
  return tier ? `${word} · ${tier}` : word;
}

// A fold of disagreeing sites reads "indeterminate" even when every site
// resolved; target_kinds/amount_kinds recover them. At most 4 spelled out; the
// count states the true total.
const SITE_RENDER_CAP = 4;

function kindTierRowText(folded, sites, wordMap) {
  if (Array.isArray(sites) && sites.length > 1) {
    const texts = sites.map((s) => kindTierText(s, wordMap)).filter(Boolean);
    if (texts.length > 1) {
      const shown = texts.slice(0, SITE_RENDER_CAP).join(" / ");
      const more =
        texts.length > SITE_RENDER_CAP
          ? ` +${texts.length - SITE_RENDER_CAP} more`
          : "";
      return `${texts.length} sites: ${shown}${more}`;
    }
  }
  return kindTierText(folded, wordMap);
}

function formatUsdUpperBound(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0)
    return null;
  const abs = Math.abs(value);
  let text;
  if (abs >= 1e9) text = `$${(value / 1e9).toFixed(1)}B`;
  else if (abs >= 1e6) text = `$${(value / 1e6).toFixed(1)}M`;
  else if (abs >= 1e3) text = `$${(value / 1e3).toFixed(1)}K`;
  else text = `$${Math.round(value)}`;
  return `up to ~${text}`;
}

// Current payloads count per (holder, asset); pre-fix payloads only have the
// asset set.
function unvaluedText(count, keyed) {
  return keyed ? `${count} holder/asset pair(s) of unknown value` : `${count} asset(s) of unknown value`;
}

// The same three-state verdict from `target_constraint` (flows) and
// `destination_constraint` (exec). Only a present verdict produces a row.
const GUARD_WORD = {
  mapping_allowlist: "a storage allowlist the caller did not write",
  hash_commitment: "a hash commitment in storage",
  equality_vs_storage: "equality against a storage address",
  equality_vs_caller: "equality against the caller",
  numeric_bound: "a numeric bound",
  merkle_inclusion: "a merkle inclusion proof",
  signature_witness: "a signature check",
  denylist: "a denylist",
  external_call_revert: "another contract's revert surface",
};

function constraintText(verdict) {
  if (!verdict || typeof verdict.state !== "string") return null;
  if (verdict.state === "unconstrained_proven")
    return "no mandatory gate references it (freely chosen)";
  if (verdict.state === "not_determined") return "not determined";
  const word = GUARD_WORD[verdict.guard] || verdict.guard || "a guard";
  const via =
    verdict.binding === "derived_from"
      ? " (bound through a computation's argument provenance)"
      : "";
  // "gated by" only for a proven pin; non-pinning and undetermined guards both
  // read "checked by" with their own caveat. Absent `pins` is undetermined.
  const pins = constraintPins(verdict);
  if (pins === true) return `gated by ${word}${via}`;
  if (pins === false)
    return `checked by ${word}${via} — excludes a set; does NOT pin the destination`;
  return `checked by ${word}${via} — whether it pins the destination is not proven`;
}

function destinationConstraintText(claims) {
  const seen = [];
  for (const c of claims) {
    let verdict = null;
    if (c.claim_id === "exec.arbitrary") {
      verdict = c.witness && c.witness.destination_constraint;
    } else if (c.claim_id === "flow.out" || c.claim_id === "value_router") {
      const rows =
        c.claim_id === "value_router"
          ? routedOutFlows(c.witness)
          : c.witness && c.witness.direction === "out" && Array.isArray(c.witness.flows)
            ? c.witness.flows
            : [];
      for (const f of rows) {
        const t = constraintText(f && f.target_constraint);
        if (t && !seen.includes(t)) seen.push(t);
      }
      continue;
    }
    const t = constraintText(verdict);
    if (t && !seen.includes(t)) seen.push(t);
  }
  return seen.length ? seen.join(", ") : null;
}

// Fork-observed destination answer for an outflow (`destination_shape` +
// `shape_proved_by`), or null. Proven `caller_arbitrary` on 35 rows before the
// bridge forwarded it.
const OBSERVED_SHAPE_WORD = {
  caller_arbitrary: "caller-chosen (a sentinel address received the outflow)",
  immutable_fixed: "fixed — an immutable address static proved",
  storage_determined: "storage-determined (no setter reached it)",
};

function observedDestinationShape(claims) {
  for (const c of claims) {
    if (c.claim_id !== "flow.out" && c.claim_id !== "value_router") continue;
    const observed = c.witness && c.witness.observed;
    if (!observed) continue;
    const shape = observed.destination_shape;
    const provedBy = observed.shape_proved_by;
    if (typeof shape !== "string") continue;
    if (shape === "unknown" || provedBy === "none") {
      // Nothing established and nothing hidden; silence beside a large reach
      // reads as fine.
      return "not determined (no static classification, no sentinel landed)";
    }
    return OBSERVED_SHAPE_WORD[shape] || `${shape} (observed)`;
  }
  return null;
}

export function claimWitnessFacts(fn) {
  const claims = claimsOf(fn);
  const facts = [];

  const destKinds = [];
  const amtKinds = [];
  let reachValue = null;
  let reachDetermined = null;
  let reachIndeterminate = false;
  let reachFloor = null;
  let reachUnvalued = 0;
  let reachUnvaluedKeyed = false;
  let reachPricedHolders = 0;
  let reachPriced = null;
  let reachRejected = false;
  for (const c of claims) {
    if (c.claim_id !== "flow.out" && c.claim_id !== "value_router") continue;
    const w = c.witness;
    if (!w) continue;
    const rows =
      c.claim_id === "value_router"
        ? routedOutFlows(w)
        : w.direction === "out" && Array.isArray(w.flows)
          ? w.flows
          : [];
    if (rows.length) {
      for (const f of rows) {
        const dt = kindTierRowText(
          f && f.target_kind,
          f && f.target_kinds,
          TARGET_KIND_WORD,
        );
        if (dt && !destKinds.includes(dt)) destKinds.push(dt);
        const at = kindTierRowText(
          f && f.amount_kind,
          f && f.amount_kinds,
          AMOUNT_KIND_WORD,
        );
        if (at && !amtKinds.includes(at)) amtKinds.push(at);
      }
    }
    const observed = w.observed;
    if (observed) {
      if (typeof observed.observed_reach_value_usd === "number")
        reachValue = observed.observed_reach_value_usd;
      // The one key separating a measured reach from a never-attempted one; a
      // measured $0 is otherwise silent (`formatUsdUpperBound(0)` is falsy).
      // Absent on older payloads.
      if (typeof observed.reach_determined === "boolean")
        reachDetermined = observed.reach_determined;
      if (observed.reach_indeterminate === true) reachIndeterminate = true;
      // The acting deployment's balance is a floor, never the reach: published
      // as the reach, it showed "$0" for functions that move millions.
      if (typeof observed.observed_reach_floor_usd === "number")
        reachFloor = observed.observed_reach_floor_usd;
      // Moved value in an asset unpriced for that holder, counted per (holder,
      // asset). Reading the old asset-keyed field showed "1 asset of unknown
      // value" beside $8.47M from an unnamed holder.
      if (Array.isArray(observed.observed_reach_unvalued_pairs)) {
        reachUnvalued = observed.observed_reach_unvalued_pairs.length;
        reachUnvaluedKeyed = true;
      } else if (Array.isArray(observed.observed_reach_unvalued_assets)) {
        // Pre-fix: asset-keyed, so a priced part can't be attributed.
        reachUnvalued = observed.observed_reach_unvalued_assets.length;
      }
      if (Array.isArray(observed.observed_reach_priced_holders))
        reachPricedHolders = observed.observed_reach_priced_holders.length;
      if (typeof observed.observed_reach_priced_usd === "number")
        reachPriced = observed.observed_reach_priced_usd;
      // Exceeded the protocol's own TVL; shown as a contradiction, never the
      // number.
      if (observed.reach_tvl_check === "exceeds_protocol_tvl") reachRejected = true;
    }
  }
  if (destKinds.length)
    facts.push({ label: "Destination", value: destKinds.join(", ") });
  else {
    // Approve-then-pull outflows have no static destination, so a huge reach
    // showed no destination statement at all; the fork's answer fills it.
    const observedShape = observedDestinationShape(claims);
    if (observedShape) facts.push({ label: "Destination", value: observedShape });
  }
  const destConstraint = destinationConstraintText(claims);
  if (destConstraint)
    facts.push({ label: "Destination constraint", value: destConstraint });
  if (amtKinds.length)
    facts.push({ label: "Amount", value: amtKinds.join(", ") });
  // A seeded reach isn't about live state; unseeded rows are byte-identical.
  const reachSeedClause = seedClauseForClaims(claims, isOutflowClaim);
  let reachFact = null;
  if (reachRejected) {
    // The refusal must not swallow the independent partial-floor disclosure;
    // compose both.
    reachFact = {
      label: "Reach",
      value:
        reachUnvalued > 0
          ? `not determined — ${unvaluedText(reachUnvalued, reachUnvaluedKeyed)}, and the priced floor exceeded protocol TVL and was refused`
          : "not determined (measured figure exceeded protocol TVL and was refused)",
    };
  } else if (reachUnvalued > 0) {
    // The priced part is shown only with its subjects, beside the unpriced
    // pairs.
    const priced = formatUsdUpperBound(reachPriced);
    const unvalued = unvaluedText(reachUnvalued, reachUnvaluedKeyed);
    let pricedClause = "";
    if (priced && reachUnvaluedKeyed)
      pricedClause = reachPricedHolders
        ? `, priced part ${priced} across ${reachPricedHolders} holder(s)`
        : `, priced part ${priced}`;
    // Pre-fix: no holder recorded, so shown unattributed.
    else if (priced) pricedClause = `, priced part ${priced} (holder attribution not recorded)`;
    reachFact = {
      label: "Reach",
      value: `value not determined — ${unvalued}${pricedClause}`,
    };
  } else if (reachIndeterminate) {
    // Not measured: the floor is a lower bound, and zero says nothing.
    const floor = formatUsdUpperBound(reachFloor);
    reachFact = {
      label: "Reach",
      value: floor
        ? `not determined (own balance floor ${floor})`
        : "not determined (no downstream holder observed)",
    };
  } else if (reachDetermined === true) {
    // Measured: zero is a measurement and used to render as silence.
    const reach = formatUsdUpperBound(reachValue);
    reachFact = reach
      ? { label: "Reach (upper bound)", value: reach }
      : { label: "Reach", value: "$0 — measured, no priced value reachable" };
  } else {
    // `reach_determined` absent: an old 0 may be the own-balance floor, so stay
    // as before rather than claim a measured zero.
    const reach = formatUsdUpperBound(reachValue);
    if (reach) reachFact = { label: "Reach (upper bound)", value: reach };
  }
  if (reachFact)
    facts.push({
      label: reachFact.label,
      value: withSeedNote(reachFact.value, reachSeedClause),
    });

  // pause.set: freeze blast radius, expiry and duration (fork-observed).
  const observed = pauseObserved(claims);
  if (observed) {
    const radius = observed.observed_blast_radius;
    if (Array.isArray(radius) && radius.length) {
      const shown = radius.slice(0, 4).join(", ");
      const more = radius.length > 4 ? ` +${radius.length - 4} more` : "";
      facts.push({
        label: "Freeze scope",
        value: `${radius.length} entry point(s): ${shown}${more}`,
      });
    }
    if (
      observed.auto_expiry === true &&
      typeof observed.duration_bound_seconds === "number"
    ) {
      facts.push({
        label: "Auto-expiry",
        value: `self-recovers after ~${formatDuration(observed.duration_bound_seconds)}`,
      });
    } else if (observed.auto_expiry === false) {
      facts.push({ label: "Auto-expiry", value: "does not self-recover" });
    } else if (
      observed.auto_expiry === null &&
      observed.duration_bound_seconds === null &&
      observed.duration_bound_source === PAUSE_BOUND_PROVEN_INDEFINITE
    ) {
      facts.push({
        label: "Auto-expiry",
        value: "indefinite latch (no self-recovery bound)",
      });
    } else if (
      observed.auto_expiry === null &&
      observed.duration_bound_seconds === null
    ) {
      // Window not established: neither the most-severe indefinite sentence nor
      // a mitigation.
      facts.push({
        label: "Auto-expiry",
        value: "window not determined",
      });
    }
  }

  // supply.mint: backing inflow (fork-observed).
  const backing = mintBacking(claims);
  if (backing) {
    // Same seeded execution, so "backed" isn't a live-state claim either.
    const mintSeedClause = seedClauseForClaims(claims, isMintClaim);
    if (backing.inflow_observed === true) {
      facts.push({
        label: "Backing",
        value: withSeedNote(
          "matching asset inflow observed (backed)",
          mintSeedClause,
        ),
      });
    } else if (backing.inflow_observed === false) {
      facts.push({
        label: "Backing",
        value: withSeedNote(
          "no matching inflow — supply rose alone (dilution)",
          mintSeedClause,
        ),
      });
    }
  }

  return facts;
}
