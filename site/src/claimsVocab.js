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
    family: "control_plane",
    lane: "top",
    tone: "#9b8a9e",
    sentence: "changes logic",
    priority: 0,
    legacy: "implementation_update",
    score: { kind: "upgrade", severity: 1 },
  },
  "proxy.admin_change": {
    family: "control_plane",
    lane: "top",
    tone: "#9b8a9e",
    sentence: "changes proxy admin",
    priority: 0,
    legacy: null,
    score: { kind: "admin", severity: 0.88 },
  },

  // ── arbitrary execution / deployment (exec family, top lane) ──────────────
  "exec.arbitrary": {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "arbitrary external call",
    priority: 1,
    legacy: "arbitrary_external_call",
    score: { kind: "execution", severity: 0.95 },
  },
  // Foreign code running in THIS contract's storage. Kept out of
  // upgrade.implementation on purpose: that claim carries the EIP-1967/UUPS
  // population and its statistics, and a non-standard split proxy admitted into
  // it would corrupt them to say the same severity-relevant thing. A consumer
  // that wants "logic can be replaced" reads the union of the two.
  "delegatecall.execute": {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "runs foreign code in its own storage",
    priority: 1,
    legacy: "delegatecall_execution",
    score: { kind: "execution", severity: 0.95 },
  },
  contract_deployment: {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "deploys a contract",
    priority: 1,
    legacy: "contract_deployment",
    score: null,
  },

  // ── ownership (top lane) ──────────────────────────────────────────────────
  "ownership.transfer": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "changes owner",
    priority: 2,
    legacy: "ownership_transfer",
    score: { kind: "admin", severity: 0.88 },
  },
  "ownership.renounce": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "renounces ownership",
    priority: 2,
    legacy: "ownership_transfer",
    score: { kind: "admin", severity: 0.88 },
  },
  "ownership.accept": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "accepts ownership",
    priority: 2,
    legacy: "ownership_transfer",
    score: { kind: "admin", severity: 0.88 },
  },

  // ── role / authority / pointer admin (top lane) ───────────────────────────
  "roles.grant": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "grants role",
    priority: 3,
    legacy: "role_management",
    score: { kind: "admin", severity: 0.88 },
  },
  "roles.revoke": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "revokes role",
    priority: 3,
    legacy: "role_management",
    score: { kind: "admin", severity: 0.88 },
  },
  "roles.configure": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "configures roles",
    priority: 3,
    legacy: "role_management",
    score: { kind: "admin", severity: 0.88 },
  },
  "authority.replace": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes authority",
    priority: 3,
    legacy: "authority_update",
    score: { kind: "admin", severity: 0.88 },
  },
  "authorized_caller.rotate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "rotates caller authority",
    priority: 3,
    legacy: null,
    score: { kind: "admin", severity: 0.88 },
  },
  // Minted only by the effects claims bridge (behavioral_observed): a simulated
  // call opened a permission gate to previously-rejected callers. Scoreable like
  // the other control-plane authority claims, but the observed tier is
  // neutralised in protocolScore.js until SCORING_INVARIANTS.md designs consumption.
  "authority.grant": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "opens a gate",
    priority: 3,
    legacy: "authority_update",
    score: { kind: "admin", severity: 0.88 },
  },
  "callee_pointer.rotate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes hook",
    priority: 3,
    legacy: "hook_update",
    score: { kind: "config", severity: 0.78 },
  },
  "safe.signer_mgmt": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes signers",
    priority: 3,
    legacy: null,
    score: { kind: "admin", severity: 0.88 },
  },
  "safe.module_mgmt": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes modules",
    priority: 3,
    legacy: null,
    score: { kind: "admin", severity: 0.88 },
  },
  "safe.set_guard": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets guard",
    priority: 3,
    legacy: null,
    score: { kind: "admin", severity: 0.88 },
  },
  "lz_oapp.set_peer": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets peer",
    priority: 3,
    legacy: null,
    score: { kind: "config", severity: 0.78 },
  },
  "lz_oapp.set_delegate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets delegate",
    priority: 3,
    legacy: null,
    score: { kind: "config", severity: 0.78 },
  },

  // ── pause (top lane, split set/unset) ─────────────────────────────────────
  "pause.set": {
    family: "control_plane",
    lane: "top",
    tone: "#998a6a",
    sentence: "pauses",
    priority: 4,
    legacy: "pause_toggle",
    score: { kind: "pause", severity: 0.25 },
  },
  "pause.unset": {
    family: "control_plane",
    lane: "top",
    tone: "#998a6a",
    sentence: "unpauses",
    priority: 4,
    legacy: "pause_toggle",
    score: { kind: "unpause", severity: 0.68 },
  },

  // ── timelock ops (top lane) ───────────────────────────────────────────────
  "timelock.schedule": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "schedules op",
    priority: 5,
    legacy: "timelock_operation",
    score: { kind: "timelock", severity: 0.62 },
  },
  "timelock.execute": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "executes op",
    priority: 5,
    legacy: "timelock_operation",
    score: { kind: "timelock", severity: 0.62 },
  },
  "timelock.cancel": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "cancels op",
    priority: 5,
    legacy: "timelock_operation",
    score: { kind: "timelock", severity: 0.62 },
  },
  "timelock.set_delay": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "changes delay",
    priority: 5,
    legacy: "timelock_operation",
    score: { kind: "timelock", severity: 0.62 },
  },

  // ── flow / supply (inflow / outflow lanes) ────────────────────────────────
  "flow.in": {
    family: "flow",
    lane: "left",
    tone: "#6a9e94",
    sentence: "moves value in",
    priority: 6,
    legacy: "asset_pull",
    score: { kind: "asset_in", severity: 0.5 },
  },
  "supply.mint": {
    family: "flow",
    lane: "left",
    tone: "#6a9e94",
    sentence: "mints supply",
    priority: 6,
    legacy: "mint",
    score: { kind: "asset_in", severity: 0.5 },
  },
  "flow.out": {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "moves value out",
    priority: 7,
    legacy: "asset_send",
    score: { kind: "asset_out", severity: 0.78 },
  },
  // The entry neither holds nor sends the value — it calls a contract that does.
  // Same risk class as a direct out-flow when the routed value LEAVES that
  // contract (the caller can still name where it lands), so it shares
  // flow.out's severity. ``lane`` here is the outbound default; laneForClaims
  // overrides it per-witness, because a router that forwards value INTO a vault
  // is an inflow and must not read as an outflow.
  value_router: {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "routes value through a contract it calls",
    priority: 7,
    legacy: null,
    score: { kind: "asset_out", severity: 0.78 },
  },
  "supply.burn": {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "burns supply",
    priority: 7,
    legacy: "burn",
    score: { kind: "asset_out", severity: 0.78 },
  },

  // ── user-plane operations (never the control lane) ────────────────────────
  "weth.deposit": {
    family: "user_plane",
    lane: "left",
    tone: "#6a9e94",
    sentence: "wraps ETH",
    priority: 8,
    legacy: null,
    score: null,
  },
  "weth.withdraw": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "unwraps ETH",
    priority: 9,
    legacy: null,
    score: null,
  },
  "erc20.transfer": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "transfers tokens",
    priority: 9,
    legacy: null,
    score: null,
  },
  "erc20.transfer_from": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "transfers tokens",
    priority: 9,
    legacy: null,
    score: null,
  },
  "erc20.approve": {
    family: "user_plane",
    lane: "ops",
    tone: null,
    sentence: "approves allowance",
    priority: 10,
    legacy: null,
    score: null,
  },
  "gov.delegate": {
    family: "user_plane",
    lane: "ops",
    tone: null,
    sentence: "delegates votes",
    priority: 10,
    legacy: null,
    score: null,
  },

  // ── facts (present for provenance; contribute nothing to severity) ────────
  // A bucket rate limiter bounds throughput per window, not total loss — over N
  // windows the extractable total is unbounded — so it is recorded and scored at
  // zero rather than credited as a ceiling. It sits in ops, never a flow lane,
  // so it can never displace the claim that describes the actual value move.
  // The severity meaning INVERTS on configuration (a zero refill rate is a
  // one-shot total cap; a zero capacity is a freeze), and both numbers are chain
  // state the static witness marks not-determined — so no consumer may derive a
  // grade from this claim as it stands.
  "rate_limit.consume": {
    family: "fact",
    lane: "ops",
    tone: null,
    sentence: "passes through a rate limiter",
    priority: 11,
    legacy: null,
    score: null,
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
const TIER_RANK = {
  behavioral_observed: 4,
  standard_exact: 3,
  idiom_structural: 2,
  policy_derived: 1,
};

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
  const scoreableLabels = new Set(
    scoreable.map((c) => CLAIM_VOCAB[c?.claim_id]?.legacy).filter(Boolean),
  );
  // Only labels contributed SOLELY by an observed claim are removed; a label a
  // scoreable claim also projects stays (and is ignored anyway when claims exist).
  const observedOnly = new Set(
    observed
      .map((c) => CLAIM_VOCAB[c?.claim_id]?.legacy)
      .filter((l) => l && !scoreableLabels.has(l)),
  );
  const labels = (
    Array.isArray(fn?.effect_labels) ? fn.effect_labels : []
  ).filter((l) => !observedOnly.has(l));
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

// A routed move takes its lane from the direction of the value, not from the
// claim id: the same ``value_router`` claim covers a router forwarding funds
// INTO a vault (an inflow) and one sending that vault's funds onward (an
// outflow). ``from_is_self`` is the fact layer's own discriminator for which.
function routedOutFlows(witness) {
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

// Hazard / calm tone tints (§7.4). Colour obeys the same honesty rule as the chip
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
    // The hazard tint covers the proven caller-chosen case AND the guard whose
    // pinning is not proven: dropping the tint there would read absence of a
    // pinning proof as the proof itself (round-2 R3 — all four real
    // "constrained" rows are blacklists and had lost the tint).
    if (s.sawCaller || s.sawUnprovenPin) return TONE_FLOW_OUT_CALLER;
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

// Joined chip line for the wider surfaces (graph meta, permissions chip):
// every claim's sentence in priority order plus the strongest provenance tier.
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
  const tierLabel = TIER_LABEL[bestTier];
  const text = phrases.join(" · ");
  return {
    text,
    tier: bestTier,
    label: tierLabel ? `${text} · ${tierLabel}` : text,
  };
}

// ── Witness qualifiers (SCORING plan §7) ─────────────────────────────────────
//
// The honesty rule (mirror of the backend witness bar, SCORING_INVARIANTS inv-2):
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
// `not_determined` and an ABSENT field stay their own bucket — a payload
// minted before the producer answered the question is not evidence that no
// gate exists. Nothing here launders a constraint into reassurance, and no
// absence of proof-of-pinning ever suppresses the theft-shaped signal.
//
// msg_sender / caller_controlled carry no such question: the destination IS the
// caller, provably, so they stay unconditional.
// The three-state pinning answer of a `constrained` verdict. `pins` is the
// producer's field; on a payload minted before it existed the guard NAME still
// carries one proof: `denylist` is BY CLASSIFICATION a falsy membership — a
// guard that excludes a set and pins nothing — so it reads as proven
// non-pinning even without the field. Every other guard without `pins` is
// undetermined: absence of the proof is never the proof.
function constraintPins(verdict) {
  if (!verdict) return null;
  if (verdict.pins === true || verdict.pins === false) return verdict.pins;
  if (verdict.guard === "denylist") return false;
  return null;
}

function paramDestinationIsFreelyChosen(flow) {
  const c = flow && flow.target_constraint;
  return !!(c && c.state === "unconstrained_proven");
}

function flowOutTargetSummary(claims) {
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
            // its own wording — three states, none conflated (R3, round 2).
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
  // A param destination that is not proven-free is neither fixed nor caller
  // chosen, so it must block the "fixed" reading exactly like an indeterminate
  // one — otherwise a function with one guarded param and one immutable path
  // would read "(fixed destination)".
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
  if (!s.total) return null;
  if (s.sawCaller) return "(caller-chosen destination)";
  // A real guard whose pinning is NOT proven sits at the hazard end with the
  // caller-chosen case (it may well be a blacklist — all four local rows are),
  // but under wording that claims exactly what was proven and no more.
  if (s.sawUnprovenPin) return "(destination checked; pinning not proven)";
  if (s.sawSetter) return "(admin-settable destination)";
  // Both of these sit BELOW admin-settable in the worst case and above "fixed":
  // a gate an authority wrote is weaker evidence than an unwritable address, and
  // an unanswered question is weaker still. Neither is reassurance — the wording
  // states what was proven and nothing more.
  if (s.sawGuardedParam) return "(destination gated by a guard)";
  if (s.sawUnknownParam) return "(destination constraint not determined)";
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
      // "gated" (round-2 R3).
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
function pauseObserved(claims) {
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

function formatDuration(seconds) {
  const days = seconds / 86400;
  if (days >= 1) return `${Math.round(days)}d`;
  const hours = seconds / 3600;
  if (hours >= 1) return `${Math.round(hours)}h`;
  return `${Math.max(1, Math.round(seconds / 60))}m`;
}

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
  // Indefinite latch = most severe: both fields present AND null. Absent keys
  // (unknown) never reach here — undefined !== null.
  if (o.auto_expiry === null && o.duration_bound_seconds === null) {
    return "(indefinite)";
  }
  return null;
}

// The fork-observed mint-backing object (behavioral tier only).
function mintBacking(claims) {
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
export function qualifierForClaims(fn) {
  const primary = primaryClaim(fn);
  if (!primary) return null;
  const claims = claimsOf(fn);
  switch (primary.claim_id) {
    case "flow.out":
    // A routed outflow answers the same destination question, so it takes the
    // same qualifier; flowOutTargetSummary already admits only outbound routes.
    case "value_router":
      return flowOutQualifier(claims);
    case "exec.arbitrary":
      return execTargetConstraint(claims);
    case "delegatecall.execute":
      return delegatecallDestination(claims);
    case "pause.set":
      return pauseQualifier(claims);
    case "supply.mint":
      return mintQualifier(claims);
    case "flow.in":
      // Only a co-occurring, at-bar mint-backing witness qualifies a value-in
      // chip; a plain inflow (no mint, or mint without backing) stays unqualified.
      return mintQualifier(claims);
    default:
      return null;
  }
}

// ── Inspector verbose facts (SCORING plan §7.3) ──────────────────────────────

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

// Conservative UPPER-BOUND USD phrasing — never render as exact (inv. 5/7).
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
export function claimWitnessFacts(fn) {
  const claims = claimsOf(fn);
  const facts = [];

  // flow.out — destination kind, amount kind (static lattice) + reach (fork).
  const destKinds = [];
  const amtKinds = [];
  let reachValue = null;
  let reachIndeterminate = false;
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
      if (observed.reach_indeterminate === true) reachIndeterminate = true;
    }
  }
  if (destKinds.length)
    facts.push({ label: "Destination", value: destKinds.join(", ") });
  const destConstraint = destinationConstraintText(claims);
  if (destConstraint)
    facts.push({ label: "Destination constraint", value: destConstraint });
  if (amtKinds.length)
    facts.push({ label: "Amount", value: amtKinds.join(", ") });
  if (reachIndeterminate) {
    facts.push({
      label: "Reach",
      value: "floored to own balance (reach indeterminate)",
    });
  } else {
    const reach = formatUsdUpperBound(reachValue);
    if (reach) facts.push({ label: "Reach (upper bound)", value: reach });
  }

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
      observed.duration_bound_seconds === null
    ) {
      facts.push({
        label: "Auto-expiry",
        value: "indefinite latch (no self-recovery bound)",
      });
    }
  }

  // supply.mint — backing inflow (fork-observed).
  const backing = mintBacking(claims);
  if (backing) {
    if (backing.inflow_observed === true) {
      facts.push({
        label: "Backing",
        value: "matching asset inflow observed (backed)",
      });
    } else if (backing.inflow_observed === false) {
      facts.push({
        label: "Backing",
        value: "no matching inflow — supply rose alone (dilution)",
      });
    }
  }

  return facts;
}

// A resolved-principal's terminal-controller note (SCORING plan §4 / §7.3). Reads
// the non-terminal marking + terminal walk so the inspector NEVER implies a
// settled key where the control chain didn't terminate. Returns null for a
// principal that is itself terminal (a settled Safe/EOA/timelock), or when there
// is nothing to say. Shape: {kind: "terminated"|"ambiguous"|"unresolved", ...}.
export function terminalControllerNote(principal) {
  const details = (principal && principal.details) || {};
  const resolvedType =
    (principal && (principal.resolvedType || principal.resolved_type)) ||
    "unknown";
  // A settled key (terminal === true) needs no way-point note.
  if (details.terminal === true) return null;

  const tp = details.terminal_principal;
  if (tp && typeof tp === "object") {
    if (tp.terminal === true && tp.address) {
      return {
        kind: "terminated",
        address: tp.address,
        resolvedType: String(tp.resolved_type || "unknown"),
      };
    }
    // Multiple parallel control planes (Solmate/Solady Auth owner + authority).
    // `multi_plane` at the top level carries `tp.planes` — each plane walked to
    // its OWN terminal — so the verbose inspector can show every plane's controller
    // and outcome (a reviewer needs to see the weakest plane). The header still says
    // "no single settled key"; we never collapse to one key.
    if (
      tp.status === "multi_plane" &&
      Array.isArray(tp.planes) &&
      tp.planes.length
    ) {
      const planes = tp.planes.map((p) => {
        const rec = (p && p.terminal_record) || {};
        const outcome =
          rec.terminal === true && rec.address
            ? {
                resolved: true,
                address: rec.address,
                resolvedType: String(rec.resolved_type || "unknown"),
              }
            : { resolved: false, status: String(rec.status || "unknown") };
        return { controller: (p && p.controller) || null, outcome };
      });
      return { kind: "multi_plane", planes };
    }
    // `ambiguous_controllers` (a nested plane that itself forked) has no per-plane
    // walk to show — render the flat controller count as "no single settled key".
    // A `multi_plane` status without a usable `planes` array degrades here too.
    if (tp.status === "multi_plane" || tp.status === "ambiguous_controllers") {
      const planes = Array.isArray(tp.controllers) ? tp.controllers : [];
      return { kind: "ambiguous", planes };
    }
    // cycle | depth_exceeded | unknown_unfetched → honestly unresolved.
    return { kind: "unresolved", status: tp.status || "unknown" };
  }

  // resolved_type=contract way-point with no terminal walk: still non-terminal.
  if (resolvedType === "contract" || details.terminal === false) {
    return { kind: "unresolved", status: "unknown_unfetched" };
  }
  return null;
}

// Signer-overlap attribution CONTEXT for a Safe principal (SCORING plan §2 / C1).
// Tier 1 (on-chain owner reads). NB the honesty boundary baked into the copy this
// feeds: shared signers is attribution context, NOT proof of shared org identity.
// Returns {selfOwnerCount, strongest: {address, sharedCount, otherOwnerCount,
// subset, superset, equal, jaccard}} or null.
export function signerOverlapNote(principal) {
  const so = principal && principal.details && principal.details.signer_overlap;
  if (!so || !Array.isArray(so.overlaps) || !so.overlaps.length) return null;
  const withShared = so.overlaps.filter(
    (o) => o && typeof o.shared_count === "number" && o.shared_count > 0,
  );
  if (!withShared.length)
    return { selfOwnerCount: so.self_owner_count, strongest: null };
  const strongest = withShared.reduce((best, o) =>
    o.jaccard > best.jaccard ? o : best,
  );
  return {
    selfOwnerCount: so.self_owner_count,
    strongest: {
      address: strongest.address,
      sharedCount: strongest.shared_count,
      otherOwnerCount: strongest.other_owner_count,
      subset: Boolean(strongest.subset),
      superset: Boolean(strongest.superset),
      equal: Boolean(strongest.equal),
      jaccard: strongest.jaccard,
    },
  };
}

// Shared-deployer attribution HINT for a principal (SCORING plan §2 sub-part B).
// A Tier-1 on-chain read (`provenance:"deployer_read"`) but a HEURISTIC for
// attribution — factories, shared deployer EOAs and vanity-deployer services all
// defeat "same deployer ⇒ same org". The fact is honest; the conclusion is not.
// INSPECTOR-ONLY (never a chip qualifier), and the copy this feeds MUST carry the
// hedge whenever `heuristic` is true — never phrased as org identity or control.
// Returns {deployer, otherCount, heuristic} or null (absent fact → nothing).
export function sharedDeployerNote(principal) {
  const sd =
    principal && principal.details && principal.details.shared_deployer;
  if (!sd || typeof sd.deployer !== "string") return null;
  const addresses = Array.isArray(sd.addresses) ? sd.addresses : [];
  const self = String((principal && principal.address) || "").toLowerCase();
  // `addresses` is the full deployer group INCLUDING this principal; count the
  // OTHERS. Fall back to the raw length only if self isn't in the list.
  const others = addresses.filter((a) => String(a).toLowerCase() !== self);
  const otherCount = others.length || Math.max(0, addresses.length - 1);
  if (otherCount <= 0) return null;
  return {
    deployer: sd.deployer,
    otherCount,
    heuristic: sd.heuristic !== false,
  };
}

// An inbound route scored as an outflow. The vocab entry's severity is the
// outbound default (the caller can name where the routed funds land), but the
// same claim also covers a move INTO a vault and a pull between two third
// parties — neither sends this unit's assets anywhere. laneForClaims already
// splits the two on ``from_is_self``; the score has to use the same
// discriminator or an inbound route is filed as a high-risk asset_out.
const ROUTED_IN_SCORE = { kind: "asset_in", severity: 0.5 };

function scoreOfClaim(c) {
  const score = CLAIM_VOCAB[c.claim_id].score;
  if (!score || c.claim_id !== "value_router") return score;
  return routedOutFlows(c.witness).length ? score : ROUTED_IN_SCORE;
}

// {kind, severity} for protocolScore — the strongest-severity scoreable claim.
// Returns null when a function carries only non-scoreable claims (user_plane,
// contract_deployment), so the caller can decide how to treat it.
export function scoreForClaims(fn) {
  let best = null;
  for (const c of claimsOf(fn)) {
    const score = scoreOfClaim(c);
    if (!score) continue;
    if (best === null || score.severity > best.severity) best = score;
  }
  return best;
}

export { CLAIM_VOCAB };
