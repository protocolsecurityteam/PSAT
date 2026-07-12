// Constants used across ProtocolSurface and its sub-components.
// Pure data — no React, no helpers. Behavioral helpers that close over these
// constants live in lane.js / layout/ alongside the data they classify.

export const CONTROL_EFFECTS = new Set([
  "implementation_update",
  "delegatecall_execution",
  "ownership_transfer",
  "role_management",
  "authority_update",
  "hook_update",
  "pause_toggle",
  "timelock_operation",
  "contract_deployment",
  "selfdestruct_capability",
]);

export const INPUT_EFFECTS = new Set(["asset_pull", "mint"]);
export const OUTPUT_EFFECTS = new Set(["asset_send", "burn"]);

export const INPUT_HINTS = ["deposit", "mint", "stake", "supply", "repay", "transferin", "bridgein", "join", "wrap"];
export const OUTPUT_HINTS = ["withdraw", "redeem", "transfer", "send", "sweep", "claim", "borrow", "unstake", "burn"];
export const CONTROL_HINTS = ["upgrade", "owner", "admin", "pause", "role", "authority", "hook", "timelock", "config"];

export const LANE_META = {
  top: { label: "Control", tone: "#8b92a8", chip: "CTRL" },
  ops: { label: "Operations", tone: "#6b7590", chip: "OPS" },
  left: { label: "Inflows", tone: "#6a9e94", chip: "IN" },
  right: { label: "Outflows", tone: "#9a8a6e", chip: "OUT" },
};

export const TYPE_META = {
  safe: { label: "SAFE", accent: "#6a9e94" },
  timelock: { label: "TL", accent: "#9a8a6e" },
  eoa: { label: "EOA", accent: "#a09870" },
  contract: { label: "CON", accent: "#7a8098" },
  proxy_admin: { label: "ADM", accent: "#8880a0" },
  address: { label: "ADDR", accent: "#94a3b8" },
  unknown: { label: "UNK", accent: "#94a3b8" },
  resolved_empty: { label: "NONE", accent: "#64748b" },
  open: { label: "OPEN", accent: "#64748b" },
  // A live, unconsumed one-shot initializer — anyone can call it once. Red:
  // it is the highest-severity principal-less state, not a benign open.
  one_shot_live: { label: "1-SHOT!", accent: "#ef4444" },
  many: { label: "MULTI", accent: "#8a80a0" },
};

export const MONITOR_FLAGS = [
  { key: "watch_upgrades", label: "Upgrades" },
  { key: "watch_ownership", label: "Ownership" },
  { key: "watch_pause", label: "Pause" },
  { key: "watch_roles", label: "Roles" },
  // Read both `watch_safe_signers` (auto-enrolled rows + new editor
  // saves) and `watch_signers` (legacy alias) so the chip lights up
  // either way. ``aliases`` is consumed by ``monitoringChips``.
  { key: "watch_safe_signers", aliases: ["watch_signers"], label: "Safe activity" },
  { key: "watch_timelock", label: "Timelock" },
  { key: "watch_state", label: "State" },
];

export const MONITOR_ALERT_GROUPS = [
  {
    key: "upgrades",
    label: "Upgrades",
    flags: ["watch_upgrades"],
    eventTypes: ["upgraded", "admin_changed", "beacon_upgraded"],
  },
  {
    key: "ownership",
    label: "Ownership",
    flags: ["watch_ownership"],
    eventTypes: ["ownership_transferred"],
  },
  {
    key: "pause",
    label: "Pause",
    flags: ["watch_pause"],
    eventTypes: ["paused", "unpaused"],
  },
  {
    key: "roles",
    label: "Roles",
    flags: ["watch_roles"],
    eventTypes: ["role_granted", "role_revoked"],
  },
  {
    key: "signers",
    label: "Safe activity",
    // Backend's _should_watch maps both signer changes AND Safe-tx
    // executions onto `watch_safe_signers` — the historical UI-only
    // alias `watch_signers` stays for backward compat with old alerts.
    flags: ["watch_safe_signers", "watch_signers"],
    eventTypes: [
      "signer_added",
      "signer_removed",
      "threshold_changed",
      "safe_tx_executed",
      "safe_tx_failed",
      "safe_module_executed",
      "safe_module_failed",
    ],
  },
  {
    key: "timelock",
    label: "Timelock",
    flags: ["watch_timelock"],
    eventTypes: ["timelock_scheduled", "timelock_executed", "delay_changed"],
  },
  {
    key: "state",
    label: "State polling",
    flags: ["watch_state"],
    eventTypes: ["state_changed_poll"],
    needsPolling: true,
  },
];

export const OPS_CATEGORIES = [
  { key: "setters", label: "Setters", match: (n) => /^(set|unset|reset)/i.test(n) },
  { key: "updates", label: "Updates", match: (n) => /^update/i.test(n) },
  { key: "add-remove", label: "Add / Remove", match: (n) => /^(add|remove)/i.test(n) },
  { key: "proposals", label: "Proposals", match: (n) => /^(propose|confirm|cancel)/i.test(n) },
  { key: "lifecycle", label: "Lifecycle", match: (n) => /^(initialize|create|delete|destroy|finalize|migrate)/i.test(n) },
  { key: "recovery", label: "Recovery", match: (n) => /^recover/i.test(n) },
  { key: "reports", label: "Reports", match: (n) => /^report/i.test(n) },
  { key: "other", label: "Other", match: () => true },
];

export const MACHINE_TABS = [
  { key: "control", label: "Control" },
  { key: "inflows", label: "Inflows" },
  { key: "outflows", label: "Outflows" },
  { key: "balances", label: "Balances" },
];

export const ROLE_META = {
  value_handler: { label: "Value Handlers", color: "#6a9e94", defaultOn: true },
  token:         { label: "Tokens",         color: "#6a8a9e", defaultOn: true },
  governance:    { label: "Governance",     color: "#8a6a9e", defaultOn: true },
  bridge:        { label: "Bridges",        color: "#9e8a6a", defaultOn: true },
  factory:       { label: "Factories",      color: "#6a9e8a", defaultOn: true },
  utility:       { label: "Utilities",      color: "#7a7a7a", defaultOn: true },
};
export const ALL_ROLES = Object.keys(ROLE_META);

export const PRINCIPAL_COLORS = {
  safe: "#6a9e94",
  eoa: "#a09870",
  timelock: "#9a8a6e",
  proxy_admin: "#8880a0",
};

export const SEARCH_MODES = [
  { key: "all", icon: "⊕", label: "All", accent: "#94a3b8" },
  { key: "safe", icon: "🔒", label: "Safes", accent: "#6a9e94" },
  { key: "eoa", icon: "👤", label: "EOAs", accent: "#a09870" },
  { key: "timelock", icon: "⏳", label: "Timelocks", accent: "#9a8a6e" },
  { key: "funds", icon: "💰", label: "Has Funds", accent: "#f59e0b" },
];

export const SORT_OPTIONS = [
  { key: "value", label: "Value ↓" },
  { key: "signers", label: "Signers ↓" },
  { key: "functions", label: "Functions ↓" },
  { key: "name", label: "Name A-Z" },
];
