// Projection layer: the claims carried on a function payload projected onto
// the presentation facts consumers need — lane, tone, chip sentence, ordering
// priority and the joined summary line. (Split from claimsVocab.js; the design
// statement lives at the top of claimVocab.data.js.)

import { CLAIM_VOCAB, OBSERVED_TIER, TIER_RANK, tierLabelFor } from "./claimVocab.data.js";
// This module and claimQualifiers.js are mutually recursive by design: the
// summary line and tone carry the witness qualifier, while the qualifiers read
// the projected claims. Every binding crossing the cycle is a hoisted function
// declaration, so evaluation order cannot observe an uninitialized import.
import {
  flowOutTargetSummary,
  mintBacking,
  qualifierForClaims,
  seedClauseForClaims,
} from "./claimQualifiers.js";

// Registered claims carried on a function payload, in registry-entry order.
// Unknown ids are dropped (fail-closed): a claim the vocab can't render is
// treated as absent rather than crashing a consumer.
export function claimsOf(fn) {
  const raw = Array.isArray(fn?.claims) ? fn.claims : [];
  return raw.filter(
    (c) => c && typeof c.claim_id === "string" && CLAIM_VOCAB[c.claim_id],
  );
}

export function hasClaims(fn) {
  return claimsOf(fn).length > 0;
}

// The claim that drives tone / chip / ordering: lowest priority number wins,
// ties resolved by claim_id for determinism.
export function primaryClaim(fn) {
  const claims = claimsOf(fn);
  if (!claims.length) return null;
  return claims.reduce((best, c) => {
    const a = CLAIM_VOCAB[c.claim_id].priority;
    const b = CLAIM_VOCAB[best.claim_id].priority;
    if (a !== b) return a < b ? c : best;
    return c.claim_id < best.claim_id ? c : best;
  });
}

// A routed move takes its lane from the direction of the value, not from the
// claim id: the same ``value_router`` claim covers a router forwarding funds
// INTO a vault (an inflow) and one sending that vault's funds onward (an
// outflow). ``from_is_self`` is the fact layer's own discriminator for which.
export function routedOutFlows(witness) {
  if (!witness || !Array.isArray(witness.flows)) return [];
  return witness.flows.filter((f) => f && f.from_is_self === true);
}

function laneOfClaim(c) {
  if (c.claim_id === "value_router") {
    return routedOutFlows(c.witness).length ? "right" : "left";
  }
  return CLAIM_VOCAB[c.claim_id].lane;
}

// Lane from claim families, reproducing laneForFunction's original ordering:
// any control/exec claim → top; otherwise an outflow beats an inflow; then ops.
export function laneForClaims(fn) {
  const lanes = claimsOf(fn).map((c) => laneOfClaim(c));
  if (!lanes.length) return null;
  if (lanes.includes("top")) return "top";
  const hasLeft = lanes.includes("left");
  const hasRight = lanes.includes("right");
  if (hasLeft && !hasRight) return "left";
  if (hasRight) return "right";
  if (hasLeft) return "left";
  if (lanes.includes("ops")) return "ops";
  return null;
}

// Hazard / calm tone tints. Colour obeys the same honesty rule as the chip
// text: a PROVEN-POSITIVE theft-shaped witness (caller-chosen destination,
// witnessed dilution) reads more hazardous than the neutral base; a PROVEN-NEGATIVE
// witness (immutable destination) reads calmer. Absent / indeterminate / unknown
// keeps the neutral base tone — no reassurance and no alarm laundered from absence.
// Values stay inside the existing desaturated vocabulary.
const TONE_FLOW_OUT_CALLER = "#a8746a"; // caller-chosen destination — theft-shaped, warmer/redder
const TONE_FLOW_OUT_FIXED = "#8f947a"; // proven-immutable destination — cooler, reads calmer
const TONE_MINT_UNBACKED = "#9e8a6a"; // witnessed dilution — drifts to the hazard/outflow warm

export function toneForClaims(fn) {
  const primary = primaryClaim(fn);
  if (!primary) return null;
  const base = CLAIM_VOCAB[primary.claim_id].tone;
  const claims = claimsOf(fn);
  if (primary.claim_id === "flow.out" || primary.claim_id === "value_router") {
    const s = flowOutTargetSummary(claims);
    // The hazard tint covers the proven caller-chosen case, the guard whose
    // pinning is not proven, AND the param whose constraint was never analysed
    // (absent field / not_determined): dropping the tint on any of them would
    // read absence of a proof as the proof itself: all four real "constrained"
    // rows are blacklists and had lost the tint, and every legacy payload and
    // every `several`-fold param member has NO verdict, and had lost it too.
    if (s.sawCaller || s.sawUnprovenPin || s.sawUnknownParam) return TONE_FLOW_OUT_CALLER;
    // Calm-tint only a purely-fixed out-flow (mirrors flowOutQualifier's "fixed"
    // gate): any admin-settable, indeterminate, self or unclassified path blocks it.
    if (s.sawFixed && !s.sawOther && !s.sawSetter) return TONE_FLOW_OUT_FIXED;
    return base;
  }
  // supply.mint primary, or flow.in primary on a wrap carrying a mint backing.
  if (primary.claim_id === "supply.mint" || primary.claim_id === "flow.in") {
    const b = mintBacking(claims);
    if (b && b.inflow_observed === false) return TONE_MINT_UNBACKED;
    // Backed / unknown keep the neutral inflow green (already reads safe).
    return base;
  }
  return base;
}

export function priorityForClaims(fn) {
  const primary = primaryClaim(fn);
  return primary ? CLAIM_VOCAB[primary.claim_id].priority : null;
}

// Glanceable chip text for the primary claim — the concise registry phrase.
export function sentenceForClaims(fn) {
  const primary = primaryClaim(fn);
  return primary ? CLAIM_VOCAB[primary.claim_id].sentence : null;
}

// Joined chip line for the wider surfaces (graph meta, permissions chip): every
// claim's sentence in priority order plus its provenance.
//
// `tier` is the STRONGEST tier present, which is the right headline. On its own it
// hid the weakest: a function carrying both a `standard_exact` claim and a
// `policy_derived` one (a cross-contract inference with no single-contract
// evidence) labelled as "standard" and the policy provenance disappeared from
// every surface that reads this line. `weakestTier` is published beside it, and
// the label names it whenever the two differ — the reader needs the weakest link,
// not only the strongest.
export function claimSummaryLine(fn) {
  const claims = claimsOf(fn);
  if (!claims.length) return null;
  const ordered = [...claims].sort(
    (a, b) =>
      CLAIM_VOCAB[a.claim_id].priority - CLAIM_VOCAB[b.claim_id].priority,
  );
  const seen = new Set();
  const phrases = [];
  let bestTier = null;
  let worstTier = null;
  for (const c of ordered) {
    const phrase = CLAIM_VOCAB[c.claim_id].sentence;
    if (!seen.has(phrase)) {
      seen.add(phrase);
      phrases.push(phrase);
    }
    if (
      bestTier === null ||
      (TIER_RANK[c.tier] || 0) > (TIER_RANK[bestTier] || 0)
    ) {
      bestTier = c.tier;
    }
    if (
      worstTier === null ||
      (TIER_RANK[c.tier] || 0) < (TIER_RANK[worstTier] || 0)
    ) {
      worstTier = c.tier;
    }
  }
  // Append the primary claim's witness qualifier to the PRIMARY claim's phrase,
  // so the wider surfaces (graph meta, permissions chip) carry the same honest
  // signal. Not phrases[0]: on a priority tie (e.g. supply.burn + flow.out, both
  // priority 7) the stable sort keeps the array-first claim at index 0 while
  // primaryClaim tie-breaks by claim_id — the qualifier must land on the claim
  // it was computed for, never a tied sibling's phrase.
  const qualifier = qualifierForClaims(fn);
  if (qualifier && phrases.length) {
    const primary = primaryClaim(fn);
    const primaryPhrase = primary
      ? CLAIM_VOCAB[primary.claim_id].sentence
      : phrases[0];
    const at = Math.max(0, phrases.indexOf(primaryPhrase));
    phrases[at] = `${phrases[at]} ${qualifier}`;
  }
  // "observed" on its own asserts a live-state observation. When the observed
  // claim's verdict was synthesised — the caller funded, the contract's balance
  // overridden — the tier is qualified in place, so the provenance word can never
  // read stronger than the witness behind it. Only the observed tier can carry
  // this; the static tiers have no such synthesis.
  const seeded = Boolean(
    seedClauseForClaims(claims, (c) => c.tier === OBSERVED_TIER),
  );
  const tierLabel = tierLabelFor(bestTier, seeded);
  const weakLabel = tierLabelFor(worstTier, seeded);
  const text = phrases.join(" · ");
  // Both tiers named when they differ, so the weakest provenance on the line is
  // never hidden behind the strongest.
  const provenance =
    tierLabel && weakLabel && worstTier !== bestTier
      ? `${tierLabel} + ${weakLabel}`
      : tierLabel;
  return {
    text,
    tier: bestTier,
    weakestTier: worstTier,
    label: provenance ? `${text} · ${provenance}` : text,
  };
}
