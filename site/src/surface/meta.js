
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
  // Highest-severity principal-less state, not a benign open.
  one_shot_live: { label: "1-SHOT!", accent: "#ef4444" },
  many: { label: "MULTI", accent: "#8a80a0" },
};

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
    label: "Safe signers",
    // The backend maps signer changes and Safe executions onto
    // `watch_safe_signers`; `watch_signers` is a legacy alias.
    flags: ["watch_safe_signers", "watch_signers"],
    eventTypes: ["signer_added", "signer_removed", "threshold_changed"],
  },
  {
    // Split from `signers`: same enrollment flag, but owner changes are config
    // events and executions are routine traffic. Until a per-group selector
    // exists, notifier._FILTER_GROUP_EXPANSIONS keeps old subscriptions whole.
    key: "safe_exec",
    label: "Safe executions",
    flags: ["watch_safe_signers", "watch_signers"],
    eventTypes: [
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
    // `watch_state` is a phantom flag: nothing writes or reads it. Kept so a
    // config carrying it is honoured; `planKeys` actually offers the group.
    flags: ["watch_state"],
    // Written at enrollment by `build_polling_plan`; produces every event in
    // this group.
    planKeys: ["polling_plan"],
    // `value_changed:<controller_id>` also belongs here but can't be
    // enumerated; notifier._READ_WITNESSED_WILDCARD_SEEDS lets this checkbox
    // deliver them.
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
  value_handler: { singular: "Value Handler", color: "#6a9e94" },
  token:         { singular: "Token",         color: "#6a8a9e" },
  governance:    { singular: "Governance",    color: "#8a6a9e" },
  bridge:        { singular: "Bridge",        color: "#9e8a6a" },
  factory:       { singular: "Factory",       color: "#6a9e8a" },
  utility:       { singular: "Utility",       color: "#7a7a7a" },
};

export const PRINCIPAL_COLORS = {
  safe: "#6a9e94",
  eoa: "#a09870",
  timelock: "#9a8a6e",
  proxy_admin: "#8880a0",
};

export const SEARCH_MODES = [
  // Contracts only, not a superset of the other modes.
  { key: "contracts", label: "Contracts", accent: "#94a3b8" },
  { key: "safe", label: "Safes", accent: "#6a9e94" },
  { key: "eoa", label: "EOAs", accent: "#a09870" },
  { key: "timelock", label: "Timelocks", accent: "#9a8a6e" },
  { key: "funds", label: "Has Funds", accent: "#f59e0b" },
];

export const SORT_OPTIONS = [
  { key: "value", label: "Value ↓" },
  { key: "signers", label: "Signers ↓" },
  { key: "functions", label: "Functions ↓" },
  { key: "name", label: "Name A-Z" },
];
