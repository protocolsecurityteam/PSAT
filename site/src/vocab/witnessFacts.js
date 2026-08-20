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

// ── Inspector verbose facts ──────────────────────────────────────────────────

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
  // A real ceiling, so it reads as one: the amount is the minimum of the
  // contract's own balance and some other value.
  capped_by_balance: "capped at the contract's own balance",
  // Deliberately phrased as provenance, never as a ceiling: the external
  // contract's rate is unseen state, so this is not a bound and not proof the
  // caller sets the magnitude.
  param_derived: "an external conversion of a caller-supplied argument",
  // Every branch of the amount is the caller's number — an ABI argument or the
  // ETH attached to the call — so it carries no single ABI slot.
  caller_supplied: "a caller-supplied amount",
  // Not a quantity at all: the slot names WHICH non-fungible token moves.
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

// A flow whose contributing IR sites disagreed folds to "indeterminate", which
// reads as "we don't know" even when every site WAS resolved (a payout to the
// token's owner plus a sweep to a fixed address, say). The fact layer publishes
// those sites as target_kinds/amount_kinds exactly when the fold lost that
// information, so prefer them here and say how many there are — the count is
// what makes "two destinations" legible rather than one hedged word.
//
// Rendering cap: at most 4 sites are spelled out, the rest counted. The backend
// list is already deduplicated by meaning (bounded by the lattice, not the site
// count), so the cap only ever drops distinct-but-rarer classifications from a
// pathological function — and the leading count still states the true total.
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

// Conservative UPPER-BOUND USD phrasing — never render as exact.
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

// How the unvalued half of a partial reach floor is counted. A current payload
// keys it per (holder, asset) — the key the USD arithmetic uses — and the phrase
// says so; a pre-fix payload only has the asset-level set and cannot claim more
// than "some holder could not value this asset".
function unvaluedText(count, keyed) {
  return keyed ? `${count} holder/asset pair(s) of unknown value` : `${count} asset(s) of unknown value`;
}

// What a mandatory revert gate proved about a caller-named destination. Reads
// the flow claims' `target_constraint` and the exec claim's
// `destination_constraint` — the same three-state verdict on two witnesses.
// Only a PRESENT verdict produces a row: an absent one is the question being
// unanswered, and the inspector says nothing rather than implying either proof.
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
  // `pins` is three-state and the wording tracks it exactly: "gated by" is
  // reserved for a guard PROVEN to pin; a proven non-pinning guard and a guard
  // of undetermined set semantics both read "checked by", each with its own
  // caveat. An absent `pins` (older payload) is the undetermined case — never
  // the proof.
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

// Verbose witness rows for the function inspector: [{label, value}]. Every row is
// derived from a present, at-the-bar field — absent facts produce no row (the
// same honesty rule as the chip; an unwitnessed destination shows nothing rather
// than a reassuring default).
// The fork-observed destination answer for an outflow claim, as prose, or null.
// Reads `destination_shape` + `shape_proved_by` off the behavioral witness: the
// fork proved `caller_arbitrary` on 35 rows and no consumer had ever seen it,
// because the bridge did not forward either key.
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
      // The honest sentence for these rows: nothing was established, and no attempt
      // is hidden. NOT silence — silence beside a large reach figure reads as "fine".
      return "not determined (no static classification, no sentinel landed)";
    }
    return OBSERVED_SHAPE_WORD[shape] || `${shape} (observed)`;
  }
  return null;
}

export function claimWitnessFacts(fn) {
  const claims = claimsOf(fn);
  const facts = [];

  // flow.out — destination kind, amount kind (static lattice) + reach (fork).
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
      // The measured-reach discriminator, read HERE and not only in the branches
      // below: it is the one key that separates a MEASURED reach from a
      // never-attempted one, and a measured reach of exactly $0 is otherwise
      // indistinguishable from silence (`formatUsdUpperBound(0)` is falsy).
      // Absent on an older payload, which is
      // its own third value — see the render branch.
      if (typeof observed.reach_determined === "boolean")
        reachDetermined = observed.reach_determined;
      if (observed.reach_indeterminate === true) reachIndeterminate = true;
      // On a not-measured row the acting deployment's own balance is a FLOOR
      // and now arrives under its own key. Rendered as a floor, never as the reach:
      // the producer used to publish it AS observed_reach_value_usd, so a
      // zero-balance router read "$0 reach" for a function that can move millions.
      if (typeof observed.observed_reach_floor_usd === "number")
        reachFloor = observed.observed_reach_floor_usd;
      // Value WAS observed leaving a holder, in an asset whose USD we do not
      // have for THAT holder (unpriced, or no balance row for the pair at all). Its
      // own state: neither a reach figure nor a floor on the acting contract. Counted
      // per (holder, asset) pair, which is how it is measured — the same asset can be
      // priced for one holder and unknown for another, and reading the old
      // asset-keyed key as if it covered every holder is what let this renderer show
      // "1 asset of unknown value" beside a priced figure of $8.47M drawn from a
      // holder it never named.
      if (Array.isArray(observed.observed_reach_unvalued_pairs)) {
        reachUnvalued = observed.observed_reach_unvalued_pairs.length;
        reachUnvaluedKeyed = true;
      } else if (Array.isArray(observed.observed_reach_unvalued_assets)) {
        // Pre-fix payload: asset-keyed, so a priced part on it cannot be attributed
        // to any holder and must not be shown as though it could.
        reachUnvalued = observed.observed_reach_unvalued_assets.length;
      }
      if (Array.isArray(observed.observed_reach_priced_holders))
        reachPricedHolders = observed.observed_reach_priced_holders.length;
      if (typeof observed.observed_reach_priced_usd === "number")
        reachPriced = observed.observed_reach_priced_usd;
      // The corroborating ceiling refused this figure: it exceeded the protocol's own
      // measured TVL. Shown as the contradiction it is, never as the number.
      if (observed.reach_tvl_check === "exceeds_protocol_tvl") reachRejected = true;
    }
  }
  if (destKinds.length)
    facts.push({ label: "Destination", value: destKinds.join(", ") });
  else {
    // The static flows matcher produces nothing for an approve-then-pull outflow
    // (the transfer sink lives in the callee), so the inspector used to show a
    // half-billion-dollar reach with NO statement about the destination at all —
    // indistinguishable from a destination examined and found unclassifiable. The
    // fork's own three-valued answer is now forwarded and rendered.
    const observedShape = observedDestinationShape(claims);
    if (observedShape) facts.push({ label: "Destination", value: observedShape });
  }
  const destConstraint = destinationConstraintText(claims);
  if (destConstraint)
    facts.push({ label: "Destination constraint", value: destConstraint });
  if (amtKinds.length)
    facts.push({ label: "Amount", value: amtKinds.join(", ") });
  // Every reach branch below states what an exercise of this function can touch,
  // and a seeded verdict is exactly the case where that figure is not a statement
  // about live state. The branch builds its row, the clause is appended once, and
  // an unseeded row is pushed byte-identical to before.
  const reachSeedClause = seedClauseForClaims(claims, isOutflowClaim);
  let reachFact = null;
  if (reachRejected) {
    // The corroborating ceiling refused this row's USD. When the row is ALSO the
    // partial-floor shape (assets moved whose value is unknown), that is an
    // independent fact and the refusal must not swallow it — one early-returning
    // sentence hiding a second disclosure is the same defect the balance table
    // had. Compose both.
    reachFact = {
      label: "Reach",
      value:
        reachUnvalued > 0
          ? `not determined — ${unvaluedText(reachUnvalued, reachUnvaluedKeyed)}, and the priced floor exceeded protocol TVL and was refused`
          : "not determined (measured figure exceeded protocol TVL and was refused)",
    };
  } else if (reachUnvalued > 0) {
    // Witnessed, not valued. Naming the count keeps this apart from both the
    // measured row (a number) and the not-witnessed row (a floor on own balance).
    // The priced part is only ever shown WITH its subjects: it is a sum over the
    // (holder, asset) pairs that were priced, and the pairs that were not are the
    // clause beside it — the two must not read as statements about the same thing.
    const priced = formatUsdUpperBound(reachPriced);
    const unvalued = unvaluedText(reachUnvalued, reachUnvaluedKeyed);
    let pricedClause = "";
    if (priced && reachUnvaluedKeyed)
      pricedClause = reachPricedHolders
        ? `, priced part ${priced} across ${reachPricedHolders} holder(s)`
        : `, priced part ${priced}`;
    // Pre-fix payload: the unvalued set is asset-keyed and nothing records which
    // holder the figure came from, so the figure is shown as unattributed rather
    // than as the priced part of the assets just named.
    else if (priced) pricedClause = `, priced part ${priced} (holder attribution not recorded)`;
    reachFact = {
      label: "Reach",
      value: `value not determined — ${unvalued}${pricedClause}`,
    };
  } else if (reachIndeterminate) {
    // NOT measured. Name the floor for what it is and never as the reach: the
    // acting contract's own balance is a lower bound on what an exercise of this
    // function can touch, and a zero floor says nothing about the money it moves.
    const floor = formatUsdUpperBound(reachFloor);
    reachFact = {
      label: "Reach",
      value: floor
        ? `not determined (own balance floor ${floor})`
        : "not determined (no downstream holder observed)",
    };
  } else if (reachDetermined === true) {
    // MEASURED. A zero here is a measurement — every asset that moved had a priced
    // holding and the total came out at nothing — and it used to render as silence,
    // which is what "nothing was attempted" renders as. The backend payload
    // is already pinned correct by
    // `test_zero_reach_without_the_flag_is_a_measured_zero_not_a_floor`; only this
    // renderer was blind.
    const reach = formatUsdUpperBound(reachValue);
    reachFact = reach
      ? { label: "Reach (upper bound)", value: reach }
      : { label: "Reach", value: "$0 — measured, no priced value reachable" };
  } else {
    // `reach_determined` absent: an older payload, where a 0 may be the acting
    // deployment's own (zero) balance published as the reach rather than a
    // measurement. Left exactly as it was — asserting a measured zero here would
    // re-mint the "$0 reach for a function that may move millions" sentence the
    // floor key removed. A never-attempted reach stays silent, as before.
    const reach = formatUsdUpperBound(reachValue);
    if (reach) reachFact = { label: "Reach (upper bound)", value: reach };
  }
  if (reachFact)
    facts.push({
      label: reachFact.label,
      value: withSeedNote(reachFact.value, reachSeedClause),
    });

  // pause.set — freeze blast radius, auto-expiry + duration (fork-observed).
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
      // not_determined, or an absent source on an older verdict. The freeze window
      // was NOT established — say so, rather than borrowing the proven-indefinite
      // sentence (which is the most severe statement this inspector makes).
      // Symmetrically it may not read as a MITIGATION: an unread window is not a
      // short one, so this sentence carries no duration and no expiry either way.
      facts.push({
        label: "Auto-expiry",
        value: "window not determined",
      });
    }
  }

  // supply.mint — backing inflow (fork-observed).
  const backing = mintBacking(claims);
  if (backing) {
    // The backing answer is read off the SAME seeded execution, so "backed" here
    // is not a statement that the mint is backed in live state either.
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
