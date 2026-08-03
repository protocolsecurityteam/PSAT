// Single shared claims vocabulary (Plane 1) for every frontend consumer.
//
// A function payload may carry `claims: [{claim_id, tier, witness}]` minted by
// the backend registry (services/static/claims). This module is the one place
// that maps a claim_id onto the presentation facts consumers need — family,
// lane, tone, chip sentence, ordering priority, and legacy projection. Keeping
// it in one map is the frontend half of the rule "one vocabulary module per
// side": lane.js, graph.js and PermissionsTab all read from here so the sites
// cannot drift.
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
// text — the familiar legacy words are kept, now backed by a checkable
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
  },
  "proxy.admin_change": {
    family: "control_plane",
    lane: "top",
    tone: "#9b8a9e",
    sentence: "changes proxy admin",
    priority: 0,
    legacy: null,
  },

  // ── arbitrary execution / deployment (exec family, top lane) ──────────────
  "exec.arbitrary": {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "arbitrary external call",
    priority: 1,
    legacy: "arbitrary_external_call",
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
  },
  contract_deployment: {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "deploys a contract",
    priority: 1,
    legacy: "contract_deployment",
  },

  // ── ownership (top lane) ──────────────────────────────────────────────────
  "ownership.transfer": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "changes owner",
    priority: 2,
    legacy: "ownership_transfer",
  },
  "ownership.renounce": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "renounces ownership",
    priority: 2,
    legacy: "ownership_transfer",
  },
  "ownership.accept": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "accepts ownership",
    priority: 2,
    legacy: "ownership_transfer",
  },

  // ── role / authority / pointer admin (top lane) ───────────────────────────
  "roles.grant": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "grants role",
    priority: 3,
    legacy: "role_management",
  },
  "roles.revoke": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "revokes role",
    priority: 3,
    legacy: "role_management",
  },
  "roles.configure": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "configures roles",
    priority: 3,
    legacy: "role_management",
  },
  "authority.replace": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes authority",
    priority: 3,
    legacy: "authority_update",
  },
  "authorized_caller.rotate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "rotates caller authority",
    priority: 3,
    legacy: null,
  },
  // Minted only by the effects claims bridge (behavioral_observed): a simulated
  // call opened a permission gate to previously-rejected callers. Displayed like
  // the other control-plane authority claims.
  "authority.grant": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "opens a gate",
    priority: 3,
    legacy: "authority_update",
  },
  "callee_pointer.rotate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes hook",
    priority: 3,
    legacy: "hook_update",
  },
  "safe.signer_mgmt": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes signers",
    priority: 3,
    legacy: null,
  },
  "safe.module_mgmt": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes modules",
    priority: 3,
    legacy: null,
  },
  "safe.set_guard": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets guard",
    priority: 3,
    legacy: null,
  },
  "lz_oapp.set_peer": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets peer",
    priority: 3,
    legacy: null,
  },
  "lz_oapp.set_delegate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets delegate",
    priority: 3,
    legacy: null,
  },

  // ── pause (top lane, split set/unset) ─────────────────────────────────────
  "pause.set": {
    family: "control_plane",
    lane: "top",
    tone: "#998a6a",
    sentence: "pauses",
    priority: 4,
    legacy: "pause_toggle",
  },
  "pause.unset": {
    family: "control_plane",
    lane: "top",
    tone: "#998a6a",
    sentence: "unpauses",
    priority: 4,
    legacy: "pause_toggle",
  },

  // ── timelock ops (top lane) ───────────────────────────────────────────────
  "timelock.schedule": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "schedules op",
    priority: 5,
    legacy: "timelock_operation",
  },
  "timelock.execute": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "executes op",
    priority: 5,
    legacy: "timelock_operation",
  },
  "timelock.cancel": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "cancels op",
    priority: 5,
    legacy: "timelock_operation",
  },
  "timelock.set_delay": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "changes delay",
    priority: 5,
    legacy: "timelock_operation",
  },

  // ── flow / supply (inflow / outflow lanes) ────────────────────────────────
  "flow.in": {
    family: "flow",
    lane: "left",
    tone: "#6a9e94",
    sentence: "moves value in",
    priority: 6,
    legacy: "asset_pull",
  },
  "supply.mint": {
    family: "flow",
    lane: "left",
    tone: "#6a9e94",
    sentence: "mints supply",
    priority: 6,
    legacy: "mint",
  },
  "flow.out": {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "moves value out",
    priority: 7,
    legacy: "asset_send",
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
  },
  "supply.burn": {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "burns supply",
    priority: 7,
    legacy: "burn",
  },

  // ── user-plane operations (never the control lane) ────────────────────────
  "weth.deposit": {
    family: "user_plane",
    lane: "left",
    tone: "#6a9e94",
    sentence: "wraps ETH",
    priority: 8,
    legacy: null,
  },
  "weth.withdraw": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "unwraps ETH",
    priority: 9,
    legacy: null,
  },
  "erc20.transfer": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "transfers tokens",
    priority: 9,
    legacy: null,
  },
  "erc20.transfer_from": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "transfers tokens",
    priority: 9,
    legacy: null,
  },
  "erc20.approve": {
    family: "user_plane",
    lane: "ops",
    tone: null,
    sentence: "approves allowance",
    priority: 10,
    legacy: null,
  },
  "gov.delegate": {
    family: "user_plane",
    lane: "ops",
    tone: null,
    sentence: "delegates votes",
    priority: 10,
    legacy: null,
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
  },
};

const TIER_LABEL = {
  behavioral_observed: "observed",
  standard_exact: "standard",
  idiom_structural: "idiom",
  policy_derived: "policy",
};

// The provenance word, qualified when the observation it names was synthesised
// (see the synthesis-qualifier block below). `seeded` only ever reaches the
// observed tier — a static tier is not an observation and cannot be seeded.
function tierLabelFor(tier, seeded) {
  const label = TIER_LABEL[tier];
  if (!label) return label;
  return seeded && tier === OBSERVED_TIER ? `${label} (seeded)` : label;
}

// behavioral_observed (effects plane) outranks every static tier: a witnessed
// state transition on real forked state is the strongest provenance a claim can
// carry. Mirrors services/static/claims/types.py.
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
const PAUSE_BOUND_PROVEN_INDEFINITE = "no_time_reference";

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

const isOutflowClaim = (c) =>
  c.claim_id === "flow.out" || c.claim_id === "value_router";
const isMintClaim = (c) => c.claim_id === "supply.mint";

// Worst case across the claims a rendered fact is built from: the contract-balance
// clause dominates because it is the strictly weaker verdict.
function seedClauseForClaims(claims, accept) {
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
function withSeedNote(value, clause) {
  return clause ? `${value}; ${clause}` : value;
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

// A resolved-principal's terminal-controller note. Reads
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
    // cycle | depth_exceeded | unknown_unfetched | controllers_not_determined
    // (canonical getters silent — NOT proof of no controller; the record
    // carries probes_silent/undetermined_at as the basis) | legacy
    // no_controller rows persisted before the proven-absence claim was
    // retired → all honestly unresolved, with the true status carried through.
    return { kind: "unresolved", status: tp.status || "unknown" };
  }

  // resolved_type=contract way-point with no terminal walk: still non-terminal.
  if (resolvedType === "contract" || details.terminal === false) {
    return { kind: "unresolved", status: "unknown_unfetched" };
  }
  return null;
}

// Signer-overlap attribution CONTEXT for a Safe principal.
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

// Shared-deployer attribution HINT for a principal.
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

// Reading of a capability id in a sentence, for the score page's callouts and
// its fix-first line ("two EOA authority holes"). Singular/plural, because the
// callouts count the rows they name. An id with no phrase renders as the id
// itself — an unmapped capability must not be silently absorbed into a
// neighbouring phrase.
const CAPABILITY_PHRASE = {
  "authority.replace": ["authority hole", "authority holes"],
  "authorized_caller.rotate": ["caller rotation", "caller rotations"],
  "delegatecall.execute": ["delegatecall hole", "delegatecall holes"],
  "exec.arbitrary": ["arbitrary-call hole", "arbitrary-call holes"],
  "flow.out": ["outflow path", "outflow paths"],
  "lz_oapp.set_delegate": ["bridge-delegate control", "bridge-delegate controls"],
  "lz_oapp.set_peer": ["bridge-peer control", "bridge-peer controls"],
  "ownership.transfer": ["ownership handle", "ownership handles"],
  "pause.set": ["freeze switch", "freeze switches"],
  "roles.configure": ["role configuration", "role configurations"],
  "roles.grant": ["role grant", "role grants"],
  "roles.revoke": ["role revocation", "role revocations"],
  "timelock.set_delay": ["delay control", "delay controls"],
  "transfer_policy.configure": ["transfer-policy control", "transfer-policy controls"],
  "upgrade.implementation": ["upgrade path", "upgrade paths"],
};

export function capabilityPhrase(capability, count) {
  const entry = CAPABILITY_PHRASE[capability];
  if (!entry) return String(capability || "");
  return count === 1 ? entry[0] : entry[1];
}

// The ids the phrase table covers — the frontend's copy of the scorer's fixed
// capability vocabulary, exported so parallel maps (the glossary) can assert
// they cover the same set instead of drifting apart silently.
export const CAPABILITY_PHRASE_IDS = Object.freeze(Object.keys(CAPABILITY_PHRASE));

export { CLAIM_VOCAB };
