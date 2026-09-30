// The frontend's single claims vocabulary (Plane 1): claim_id → family, lane,
// tone, chip sentence, priority. Claims are minted by services/static/claims.
//
// The primary claim has the lowest `priority` (ties by claim_id) and drives
// lane, tone, sentence and ordering; a control claim always wins the top lane,
// otherwise outflow beats inflow. Score takes the strongest severity across
// claims.
//
// control_plane and exec → Control lane; flow → inflow/outflow by direction;
// user_plane is never Control.

// Chip text keeps the familiar short phrases, now backed by a checkable claim.
export const CLAIM_VOCAB = {
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

  "exec.arbitrary": {
    family: "exec",
    lane: "top",
    tone: "#7a8098",
    sentence: "arbitrary external call",
    priority: 1,
    legacy: "arbitrary_external_call",
  },
  // Kept out of upgrade.implementation so non-standard split proxies don't
  // corrupt its EIP-1967/UUPS statistics; "logic can be replaced" is the union
  // of both.
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
  // Minted only by the effects bridge: a simulated call opened a gate to
  // previously-rejected callers.
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
  // Calls a contract that moves the value; shares flow.out's severity. ``lane``
  // is the outbound default; laneForClaims overrides for inbound routers.
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

  // Facts: provenance only, no severity. A rate limiter bounds per-window
  // throughput, not total loss, so it scores zero and sits in ops. Its meaning
  // inverts with configuration (zero refill = one-shot cap, zero capacity =
  // freeze), which is unread chain state.
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

// Only the observed tier can be seeded.
export function tierLabelFor(tier, seeded) {
  const label = TIER_LABEL[tier];
  if (!label) return label;
  return seeded && tier === OBSERVED_TIER ? `${label} (seeded)` : label;
}

// Fork-observed outranks every static tier. Mirrors
// services/static/claims/types.py.
export const TIER_RANK = {
  behavioral_observed: 4,
  standard_exact: 3,
  idiom_structural: 2,
  policy_derived: 1,
};

export const OBSERVED_TIER = "behavioral_observed";
