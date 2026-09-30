// Claims projected onto lane, tone, chip sentence, priority and summary line.
// Design notes are at the top of claimVocab.data.js.

import { CLAIM_VOCAB, OBSERVED_TIER, TIER_RANK, tierLabelFor } from "./claimVocab.data.js";
// Mutually recursive with claimQualifiers.js; every binding across the cycle is
// a hoisted function declaration, so evaluation order can't observe an
// uninitialized import.
import {
  flowOutTargetSummary,
  mintBacking,
  qualifierForClaims,
  seedClauseForClaims,
} from "./claimQualifiers.js";

// Unknown ids are dropped (fail closed).
export function claimsOf(fn) {
  const raw = Array.isArray(fn?.claims) ? fn.claims : [];
  return raw.filter(
    (c) => c && typeof c.claim_id === "string" && CLAIM_VOCAB[c.claim_id],
  );
}

export function hasClaims(fn) {
  return claimsOf(fn).length > 0;
}

// Lowest priority wins; ties by claim_id.
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

// The lane follows the value's direction: one ``value_router`` claim covers
// both inflow and outflow routers. ``from_is_self`` discriminates.
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

// Same ordering as laneForFunction: control/exec top; outflow beats inflow;
// then ops.
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

// Colour follows the text's honesty rule: proven theft-shaped witnesses read
// hazardous, proven-immutable destinations calmer, and absent/unknown stays
// neutral.
const TONE_FLOW_OUT_CALLER = "#a8746a"; // caller-chosen destination — theft-shaped
const TONE_FLOW_OUT_FIXED = "#8f947a"; // proven-immutable destination
const TONE_MINT_UNBACKED = "#9e8a6a"; // witnessed dilution

export function toneForClaims(fn) {
  const primary = primaryClaim(fn);
  if (!primary) return null;
  const base = CLAIM_VOCAB[primary.claim_id].tone;
  const claims = claimsOf(fn);
  if (primary.claim_id === "flow.out" || primary.claim_id === "value_router") {
    const s = flowOutTargetSummary(claims);
    // Unproven pinning and unanalysed params keep the hazard tint: dropping it
    // read absence of proof as proof (legacy payloads and `several` members
    // carry no verdict).
    if (s.sawCaller || s.sawUnprovenPin || s.sawUnknownParam) return TONE_FLOW_OUT_CALLER;
    // Mirrors flowOutQualifier's "fixed" gate.
    if (s.sawFixed && !s.sawOther && !s.sawSetter) return TONE_FLOW_OUT_FIXED;
    return base;
  }
  if (primary.claim_id === "supply.mint" || primary.claim_id === "flow.in") {
    const b = mintBacking(claims);
    if (b && b.inflow_observed === false) return TONE_MINT_UNBACKED;
    return base;
  }
  return base;
}

export function priorityForClaims(fn) {
  const primary = primaryClaim(fn);
  return primary ? CLAIM_VOCAB[primary.claim_id].priority : null;
}

export function sentenceForClaims(fn) {
  const primary = primaryClaim(fn);
  return primary ? CLAIM_VOCAB[primary.claim_id].sentence : null;
}

// Every claim's sentence in priority order plus provenance. `tier` is the
// strongest; `weakestTier` is named too when they differ, so policy-derived
// provenance can't hide behind a standard claim.
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
  // On the primary claim's phrase, not phrases[0]: on a priority tie the sort
  // and primaryClaim can pick different claims.
  const qualifier = qualifierForClaims(fn);
  if (qualifier && phrases.length) {
    const primary = primaryClaim(fn);
    const primaryPhrase = primary
      ? CLAIM_VOCAB[primary.claim_id].sentence
      : phrases[0];
    const at = Math.max(0, phrases.indexOf(primaryPhrase));
    phrases[at] = `${phrases[at]} ${qualifier}`;
  }
  // A synthesized observation (caller funded, balance overridden) qualifies
  // "observed" so the word can't read stronger than the witness.
  const seeded = Boolean(
    seedClauseForClaims(claims, (c) => c.tier === OBSERVED_TIER),
  );
  const tierLabel = tierLabelFor(bestTier, seeded);
  const weakLabel = tierLabelFor(worstTier, seeded);
  const text = phrases.join(" · ");
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
