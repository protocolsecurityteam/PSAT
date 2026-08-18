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
    // Backend's _should_watch maps both signer changes AND Safe-tx
    // executions onto `watch_safe_signers` — the historical UI-only
    // alias `watch_signers` stays for backward compat with old alerts.
    flags: ["watch_safe_signers", "watch_signers"],
    eventTypes: ["signer_added", "signer_removed", "threshold_changed"],
  },
  {
    // Split out of `signers`. Both are gated on the same enrollment flag (the
    // backend gates `_safe_op`/`_safe_module_op` on `watch_safe_signers` just
    // like `owners`/`threshold`), so a Safe offers both groups and nothing a
    // Safe is watched for today is withdrawn — but they are not the same fact.
    // An owner-set change is a config-plane event; an execution is the fleet's
    // routine traffic (11 of the dev corpus's 12 events), and one group made
    // "tell me when this Safe's owners change" mean "tell me about every
    // transaction it runs". Separating the vocabulary is what will let a
    // subscription say which one it wants — the Alerts control still offers the
    // whole set, so nothing can ask for one alone until a per-group selector
    // exists; see notifier._FILTER_GROUP_EXPANSIONS for what keeps the
    // pre-split subscriptions whole meanwhile.
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
    // `watch_state` is a phantom flag: no enrollment path writes it
    // (`enrollment._build_monitoring_config` never emits the key — 0 of 183
    // monitored contracts carry it) and no backend gate reads it
    // (`unified_watcher._WRITE_TARGET_TO_CONFIG_KEYS` has no entry, so
    // `_should_watch` never consults it). Gating the group on it made the group
    // unofferable, and with it the one subscription path to
    // `state_changed_poll` — and, via notifier._READ_WITNESSED_WILDCARD_SEEDS,
    // to every `value_changed:*`. It stays listed so a config that does carry
    // it is still honoured; `planKeys` is what actually offers the group.
    flags: ["watch_state"],
    // The witness that a contract is polled at all. `polling_plan` is written
    // by `polling_plan.build_polling_plan` at enrollment and is the thing that
    // produces every event in this group — 160 of the 183 monitored contracts
    // carry a non-empty one.
    planKeys: ["polling_plan"],
    // `value_changed:<controller_id>` belongs to this group too — a scan-pass
    // verification read is the same read-witnessed field diff the poller
    // produces. It is not listed because the controller_id is per-contract and
    // cannot be enumerated into a static set. The backend treats
    // `state_changed_poll` as a seed admitting any `value_changed:` type
    // (notifier._READ_WITNESSED_WILDCARD_SEEDS), so a subscription saved from
    // this checkbox still delivers them.
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

// `singular` names one entity (canvas node + card badges, search labels).
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
  // Contracts-only — NOT a superset of the Safes/EOAs/Timelocks modes.
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
