// Single shared claims vocabulary (Plane 1) for every frontend consumer.
//
// A function payload may carry `claims: [{claim_id, tier, witness}]` minted by
// the backend registry (services/static/claims). This module is the one place
// that maps a claim_id onto the presentation facts consumers need — family,
// lane, tone, chip sentence, ordering priority, legacy projection, and the
// protocol-score kind/severity. Keeping it in one map is the frontend half of
// spec §6.6 ("single vocabulary module per side"): lane.js, protocolScore.js,
// graph.js and PermissionsTab all read from here so the five sites cannot drift.
//
// Precedence rule for a function with several claims: the *primary* claim is the
// one with the lowest `priority` number (ties broken by claim_id). Lane, tone,
// chip sentence and ordering derive from it. Lane additionally honours the
// legacy in/out merge (a control claim always wins the top lane; when only flow
// claims exist, an outflow beats an inflow — matching laneForFunction's original
// ordering). Score takes the strongest severity across all claims.
//
// Families → lanes: control_plane and exec render in the top (Control) lane;
// flow renders in the inflow/outflow lanes by direction; user_plane is NEVER
// control — user operations sit in a flow lane or ops, never top.

// Concise display phrases ("changes owner") deliberately survive as the chip
// text — spec §7 keeps the familiar legacy words, now backed by a checkable
// claim rather than a name heuristic. The full registry sentence lives on the
// backend; here we render the glanceable form.
const CLAIM_VOCAB = {
  // ── upgrade / proxy admin (top lane) ──────────────────────────────────────
  "upgrade.implementation": {
    family: "control_plane", lane: "top", tone: "#9b8a9e", sentence: "changes logic",
    priority: 0, legacy: "implementation_update", score: { kind: "upgrade", severity: 1 },
  },
  "proxy.admin_change": {
    family: "control_plane", lane: "top", tone: "#9b8a9e", sentence: "changes proxy admin",
    priority: 0, legacy: null, score: { kind: "admin", severity: 0.88 },
  },

  // ── arbitrary execution / deployment (exec family, top lane) ──────────────
  "exec.arbitrary": {
    family: "exec", lane: "top", tone: "#7a8098", sentence: "arbitrary external call",
    priority: 1, legacy: "arbitrary_external_call", score: { kind: "execution", severity: 0.95 },
  },
  contract_deployment: {
    family: "exec", lane: "top", tone: "#7a8098", sentence: "deploys a contract",
    priority: 1, legacy: "contract_deployment", score: null,
  },

  // ── ownership (top lane) ──────────────────────────────────────────────────
  "ownership.transfer": {
    family: "control_plane", lane: "top", tone: "#9e8a8d", sentence: "changes owner",
    priority: 2, legacy: "ownership_transfer", score: { kind: "admin", severity: 0.88 },
  },
  "ownership.renounce": {
    family: "control_plane", lane: "top", tone: "#9e8a8d", sentence: "renounces ownership",
    priority: 2, legacy: "ownership_transfer", score: { kind: "admin", severity: 0.88 },
  },
  "ownership.accept": {
    family: "control_plane", lane: "top", tone: "#9e8a8d", sentence: "accepts ownership",
    priority: 2, legacy: "ownership_transfer", score: { kind: "admin", severity: 0.88 },
  },

  // ── role / authority / pointer admin (top lane) ───────────────────────────
  "roles.grant": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "grants role",
    priority: 3, legacy: "role_management", score: { kind: "admin", severity: 0.88 },
  },
  "roles.revoke": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "revokes role",
    priority: 3, legacy: "role_management", score: { kind: "admin", severity: 0.88 },
  },
  "roles.configure": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "configures roles",
    priority: 3, legacy: "role_management", score: { kind: "admin", severity: 0.88 },
  },
  "authority.replace": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "changes authority",
    priority: 3, legacy: "authority_update", score: { kind: "admin", severity: 0.88 },
  },
  "authorized_caller.rotate": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "rotates caller authority",
    priority: 3, legacy: null, score: { kind: "admin", severity: 0.88 },
  },
  // Minted only by the effects claims bridge (behavioral_observed): a simulated
  // call opened a permission gate to previously-rejected callers. Scoreable like
  // the other control-plane authority claims, but the observed tier is
  // neutralised in protocolScore.js until SCORING_INVARIANTS.md designs consumption.
  "authority.grant": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "opens a gate",
    priority: 3, legacy: "authority_update", score: { kind: "admin", severity: 0.88 },
  },
  "callee_pointer.rotate": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "changes hook",
    priority: 3, legacy: "hook_update", score: { kind: "config", severity: 0.78 },
  },
  "safe.signer_mgmt": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "changes signers",
    priority: 3, legacy: null, score: { kind: "admin", severity: 0.88 },
  },
  "safe.module_mgmt": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "changes modules",
    priority: 3, legacy: null, score: { kind: "admin", severity: 0.88 },
  },
  "safe.set_guard": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "sets guard",
    priority: 3, legacy: null, score: { kind: "admin", severity: 0.88 },
  },
  "lz_oapp.set_peer": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "sets peer",
    priority: 3, legacy: null, score: { kind: "config", severity: 0.78 },
  },
  "lz_oapp.set_delegate": {
    family: "control_plane", lane: "top", tone: "#7a8098", sentence: "sets delegate",
    priority: 3, legacy: null, score: { kind: "config", severity: 0.78 },
  },

  // ── pause (top lane, split set/unset) ─────────────────────────────────────
  "pause.set": {
    family: "control_plane", lane: "top", tone: "#998a6a", sentence: "pauses",
    priority: 4, legacy: "pause_toggle", score: { kind: "pause", severity: 0.25 },
  },
  "pause.unset": {
    family: "control_plane", lane: "top", tone: "#998a6a", sentence: "unpauses",
    priority: 4, legacy: "pause_toggle", score: { kind: "unpause", severity: 0.68 },
  },

  // ── timelock ops (top lane) ───────────────────────────────────────────────
  "timelock.schedule": {
    family: "control_plane", lane: "top", tone: "#8a7e6a", sentence: "schedules op",
    priority: 5, legacy: "timelock_operation", score: { kind: "timelock", severity: 0.62 },
  },
  "timelock.execute": {
    family: "control_plane", lane: "top", tone: "#8a7e6a", sentence: "executes op",
    priority: 5, legacy: "timelock_operation", score: { kind: "timelock", severity: 0.62 },
  },
  "timelock.cancel": {
    family: "control_plane", lane: "top", tone: "#8a7e6a", sentence: "cancels op",
    priority: 5, legacy: "timelock_operation", score: { kind: "timelock", severity: 0.62 },
  },
  "timelock.set_delay": {
    family: "control_plane", lane: "top", tone: "#8a7e6a", sentence: "changes delay",
    priority: 5, legacy: "timelock_operation", score: { kind: "timelock", severity: 0.62 },
  },

  // ── flow / supply (inflow / outflow lanes) ────────────────────────────────
  "flow.in": {
    family: "flow", lane: "left", tone: "#6a9e94", sentence: "moves value in",
    priority: 6, legacy: "asset_pull", score: { kind: "asset_in", severity: 0.5 },
  },
  "supply.mint": {
    family: "flow", lane: "left", tone: "#6a9e94", sentence: "mints supply",
    priority: 6, legacy: "mint", score: { kind: "asset_in", severity: 0.5 },
  },
  "flow.out": {
    family: "flow", lane: "right", tone: "#9a8a6e", sentence: "moves value out",
    priority: 7, legacy: "asset_send", score: { kind: "asset_out", severity: 0.78 },
  },
  "supply.burn": {
    family: "flow", lane: "right", tone: "#9a8a6e", sentence: "burns supply",
    priority: 7, legacy: "burn", score: { kind: "asset_out", severity: 0.78 },
  },

  // ── user-plane operations (never the control lane) ────────────────────────
  "weth.deposit": {
    family: "user_plane", lane: "left", tone: "#6a9e94", sentence: "wraps ETH",
    priority: 8, legacy: null, score: null,
  },
  "weth.withdraw": {
    family: "user_plane", lane: "right", tone: "#9a8a6e", sentence: "unwraps ETH",
    priority: 9, legacy: null, score: null,
  },
  "erc20.transfer": {
    family: "user_plane", lane: "right", tone: "#9a8a6e", sentence: "transfers tokens",
    priority: 9, legacy: null, score: null,
  },
  "erc20.transfer_from": {
    family: "user_plane", lane: "right", tone: "#9a8a6e", sentence: "transfers tokens",
    priority: 9, legacy: null, score: null,
  },
  "erc20.approve": {
    family: "user_plane", lane: "ops", tone: null, sentence: "approves allowance",
    priority: 10, legacy: null, score: null,
  },
  "gov.delegate": {
    family: "user_plane", lane: "ops", tone: null, sentence: "delegates votes",
    priority: 10, legacy: null, score: null,
  },
};

const TIER_LABEL = {
  behavioral_observed: "observed",
  standard_exact: "standard",
  idiom_structural: "idiom",
  policy_derived: "policy",
};

// behavioral_observed (effects plane) outranks every static tier: a witnessed
// state transition on real forked state is the strongest provenance a claim can
// carry (EFFECTS_RESOLUTION_SPEC §5.2). Mirrors services/static/claims/types.py.
const TIER_RANK = { behavioral_observed: 4, standard_exact: 3, idiom_structural: 2, policy_derived: 1 };

// Registered claims carried on a function payload, in registry-entry order.
// Unknown ids are dropped (fail-closed): a claim the vocab can't render is
// treated as absent rather than crashing a consumer.
export function claimsOf(fn) {
  const raw = Array.isArray(fn?.claims) ? fn.claims : [];
  return raw.filter((c) => c && typeof c.claim_id === "string" && CLAIM_VOCAB[c.claim_id]);
}

export function hasClaims(fn) {
  return claimsOf(fn).length > 0;
}

export const OBSERVED_TIER = "behavioral_observed";

// Score-facing view of a function: the effects bridge mints observable labels at
// the `behavioral_observed` tier, but the score must NOT consume verdicts yet
// (EFFECTS_RESOLUTION_SPEC §5.2 / §3a amendment — deferred to
// SCORING_INVARIANTS.md). This strips the observed claims and the legacy
// effect_labels they alone projected, so a function scores exactly as it did
// before the bridge labeled it (byte-identical). Display consumers keep the full
// claim set; only the score path uses this view.
export function scoreClaimsView(fn) {
  const claims = Array.isArray(fn?.claims) ? fn.claims : [];
  const observed = claims.filter((c) => c && c.tier === OBSERVED_TIER);
  if (!observed.length) return fn;
  const scoreable = claims.filter((c) => !(c && c.tier === OBSERVED_TIER));
  const scoreableLabels = new Set(scoreable.map((c) => CLAIM_VOCAB[c?.claim_id]?.legacy).filter(Boolean));
  // Only labels contributed SOLELY by an observed claim are removed; a label a
  // scoreable claim also projects stays (and is ignored anyway when claims exist).
  const observedOnly = new Set(
    observed.map((c) => CLAIM_VOCAB[c?.claim_id]?.legacy).filter((l) => l && !scoreableLabels.has(l)),
  );
  const labels = (Array.isArray(fn?.effect_labels) ? fn.effect_labels : []).filter((l) => !observedOnly.has(l));
  return { ...fn, claims: scoreable, effect_labels: labels };
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

// Lane from claim families, reproducing laneForFunction's original ordering:
// any control/exec claim → top; otherwise an outflow beats an inflow; then ops.
export function laneForClaims(fn) {
  const lanes = claimsOf(fn).map((c) => CLAIM_VOCAB[c.claim_id].lane);
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

export function toneForClaims(fn) {
  const primary = primaryClaim(fn);
  return primary ? CLAIM_VOCAB[primary.claim_id].tone : null;
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

// Joined chip line for the wider surfaces (graph meta, permissions chip):
// every claim's sentence in priority order plus the strongest provenance tier.
export function claimSummaryLine(fn) {
  const claims = claimsOf(fn);
  if (!claims.length) return null;
  const ordered = [...claims].sort(
    (a, b) => CLAIM_VOCAB[a.claim_id].priority - CLAIM_VOCAB[b.claim_id].priority,
  );
  const seen = new Set();
  const phrases = [];
  let bestTier = null;
  for (const c of ordered) {
    const phrase = CLAIM_VOCAB[c.claim_id].sentence;
    if (!seen.has(phrase)) {
      seen.add(phrase);
      phrases.push(phrase);
    }
    if (bestTier === null || (TIER_RANK[c.tier] || 0) > (TIER_RANK[bestTier] || 0)) {
      bestTier = c.tier;
    }
  }
  const tierLabel = TIER_LABEL[bestTier];
  const text = phrases.join(" · ");
  return { text, tier: bestTier, label: tierLabel ? `${text} · ${tierLabel}` : text };
}

// {kind, severity} for protocolScore — the strongest-severity scoreable claim.
// Returns null when a function carries only non-scoreable claims (user_plane,
// contract_deployment), so the caller can decide how to treat it.
export function scoreForClaims(fn) {
  let best = null;
  for (const c of claimsOf(fn)) {
    const score = CLAIM_VOCAB[c.claim_id].score;
    if (!score) continue;
    if (best === null || score.severity > best.severity) best = score;
  }
  return best;
}

export { CLAIM_VOCAB };
