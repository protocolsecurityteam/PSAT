// Single shared claims vocabulary (Plane 1) for every frontend consumer.
// (One package, src/vocab/: data table here; projection, qualifiers, witness
// facts, principal notes and capability phrases in sibling modules.)
//
// A function payload may carry `claims: [{claim_id, tier, witness}]` minted by
// the backend registry (services/static/claims). This package is the one place
// that maps a claim_id onto the presentation facts consumers need — family,
// lane, tone, chip sentence, ordering priority, and legacy projection. Keeping
// it in one map is the frontend half of the rule "one vocabulary module per
// side": lane.js, the inspector and the score page all read from here so the
// sites cannot drift.
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
export const CLAIM_VOCAB = {
  // ── upgrade / proxy admin (top lane) ──────────────────────────────────────
  "upgrade.implementation": {
    family: "control_plane",
    lane: "top",
    tone: "#9b8a9e",
    sentence: "changes logic",
    priority: 0,
  },
  "proxy.admin_change": {
    family: "control_plane",
    lane: "top",
    tone: "#9b8a9e",
    sentence: "changes proxy admin",
    priority: 0,
  },

  // ── arbitrary execution / deployment (exec family, top lane) ──────────────
  "exec.arbitrary": {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "arbitrary external call",
    priority: 1,
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
  },
  contract_deployment: {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "deploys a contract",
    priority: 1,
  },

  // ── ownership (top lane) ──────────────────────────────────────────────────
  "ownership.transfer": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "changes owner",
    priority: 2,
  },
  "ownership.renounce": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "renounces ownership",
    priority: 2,
  },
  "ownership.accept": {
    family: "control_plane",
    lane: "top",
    tone: "#9e8a8d",
    sentence: "accepts ownership",
    priority: 2,
  },

  // ── role / authority / pointer admin (top lane) ───────────────────────────
  "roles.grant": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "grants role",
    priority: 3,
  },
  "roles.revoke": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "revokes role",
    priority: 3,
  },
  "roles.configure": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "configures roles",
    priority: 3,
  },
  "authority.replace": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes authority",
    priority: 3,
  },
  "authorized_caller.rotate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "rotates caller authority",
    priority: 3,
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
  },
  "callee_pointer.rotate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes hook",
    priority: 3,
  },
  "safe.signer_mgmt": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes signers",
    priority: 3,
  },
  "safe.module_mgmt": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "changes modules",
    priority: 3,
  },
  "safe.set_guard": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets guard",
    priority: 3,
  },
  "lz_oapp.set_peer": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets peer",
    priority: 3,
  },
  "lz_oapp.set_delegate": {
    family: "control_plane",
    lane: "top",
    tone: "#7a8098",
    sentence: "sets delegate",
    priority: 3,
  },

  // ── pause (top lane, split set/unset) ─────────────────────────────────────
  "pause.set": {
    family: "control_plane",
    lane: "top",
    tone: "#998a6a",
    sentence: "pauses",
    priority: 4,
  },
  "pause.unset": {
    family: "control_plane",
    lane: "top",
    tone: "#998a6a",
    sentence: "unpauses",
    priority: 4,
  },

  // ── timelock ops (top lane) ───────────────────────────────────────────────
  "timelock.schedule": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "schedules op",
    priority: 5,
  },
  "timelock.execute": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "executes op",
    priority: 5,
  },
  "timelock.cancel": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "cancels op",
    priority: 5,
  },
  "timelock.set_delay": {
    family: "control_plane",
    lane: "top",
    tone: "#8a7e6a",
    sentence: "changes delay",
    priority: 5,
  },

  // ── flow / supply (inflow / outflow lanes) ────────────────────────────────
  "flow.in": {
    family: "flow",
    lane: "left",
    tone: "#6a9e94",
    sentence: "moves value in",
    priority: 6,
  },
  "supply.mint": {
    family: "flow",
    lane: "left",
    tone: "#6a9e94",
    sentence: "mints supply",
    priority: 6,
  },
  "flow.out": {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "moves value out",
    priority: 7,
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
  },
  "supply.burn": {
    family: "flow",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "burns supply",
    priority: 7,
  },

  // ── user-plane operations (never the control lane) ────────────────────────
  "weth.deposit": {
    family: "user_plane",
    lane: "left",
    tone: "#6a9e94",
    sentence: "wraps ETH",
    priority: 8,
  },
  "weth.withdraw": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "unwraps ETH",
    priority: 9,
  },
  "erc20.transfer": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "transfers tokens",
    priority: 9,
  },
  "erc20.transfer_from": {
    family: "user_plane",
    lane: "right",
    tone: "#9a8a6e",
    sentence: "transfers tokens",
    priority: 9,
  },
  "erc20.approve": {
    family: "user_plane",
    lane: "ops",
    tone: null,
    sentence: "approves allowance",
    priority: 10,
  },
  "gov.delegate": {
    family: "user_plane",
    lane: "ops",
    tone: null,
    sentence: "delegates votes",
    priority: 10,
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
export function tierLabelFor(tier, seeded) {
  const label = TIER_LABEL[tier];
  if (!label) return label;
  return seeded && tier === OBSERVED_TIER ? `${label} (seeded)` : label;
}

// behavioral_observed (effects plane) outranks every static tier: a witnessed
// state transition on real forked state is the strongest provenance a claim can
// carry. Mirrors services/static/claims/types.py.
export const TIER_RANK = {
  behavioral_observed: 4,
  standard_exact: 3,
  idiom_structural: 2,
  policy_derived: 1,
};

// The tier token for a fork-observed (effects-plane) claim; the only tier a
// seed qualifier can ever attach to.
export const OBSERVED_TIER = "behavioral_observed";
