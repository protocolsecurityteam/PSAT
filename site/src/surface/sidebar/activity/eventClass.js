// Event classification + salience for the Activity tab: event_type/effect-tag
// → kind, and the backend-owned salience vocabulary. No rendering here —
// prose/detail lines live in format.js, which reads this module's tag and
// slot parsers.

// Mirror of services.monitoring.event_topics._HANDROLLED_EVENT_TYPE_TO_TAGS.
// Hand-maintained in sync with the Python source — both sides need the
// same synthesis fallback so a MonitoredEvent persisted before
// effect_tags landed on data still classifies correctly.
//
// Convention: real state-variable names ("owner", "admin", …) match
// what the static analyzer emits. Underscore-prefixed names are
// synthetic markers for activity events that don't mutate a single
// named slot (_roles, _safe_op, _safe_module_op, _timelock_op).
const HANDROLLED_EVENT_TYPE_TO_TAGS = {
  // Proxy / upgrade events
  upgraded: { writes: ["implementation"], delegates: true },
  admin_changed: { writes: ["admin"] },
  beacon_upgraded: { writes: ["beacon"], delegates: true },
  changed_master_copy: { writes: ["implementation"], delegates: true },
  new_implementation: { writes: ["implementation"], delegates: true },
  new_pending_implementation: { writes: ["pendingImplementation"] },
  target_updated: { writes: ["implementation"], delegates: true },
  upgraded_revision: { writes: ["implementation"], delegates: true },
  diamond_cut: { writes: ["facets"], delegates: true },
  // Governance events
  ownership_transferred: { writes: ["owner"] },
  paused: { writes: ["paused"] },
  unpaused: { writes: ["paused"] },
  role_granted: { writes: ["_roles"] },
  role_revoked: { writes: ["_roles"] },
  signer_added: { writes: ["owners"] },
  signer_removed: { writes: ["owners"] },
  threshold_changed: { writes: ["threshold"] },
  timelock_scheduled: { writes: ["_timelock_op"] },
  timelock_executed: { writes: ["_timelock_op"] },
  delay_changed: { writes: ["min_delay"] },
  safe_tx_executed: { writes: ["_safe_op"] },
  safe_tx_failed: { writes: ["_safe_op"] },
  safe_module_executed: { writes: ["_safe_module_op"] },
  safe_module_failed: { writes: ["_safe_module_op"] },
  // Per-contract canonical types from parse_tracked_log
  ownership_transfer_started: { writes: ["pendingOwner"] },
  authority_updated: { writes: ["authority"] },
  initialized: { writes: ["_initialized"], is_initializer: true },
  signer_updated: { writes: ["owners"] },
};

export function tagsForEvent(evt) {
  const fromData = evt?.data?.effect_tags;
  if (fromData && typeof fromData === "object") return fromData;
  const type = evt?.event_type;
  return (type && HANDROLLED_EVENT_TYPE_TO_TAGS[type]) || {};
}

// Map a write target → high-level event kind. Drives the kind chip and
// the filter checkboxes. ``state`` is event_type-keyed because
// state_changed_poll is a synthetic poll event without tags.
const WRITE_TARGET_TO_KIND = {
  owner: "owner",
  pendingOwner: "owner",
  authority: "owner",
  implementation: "upgrade",
  pendingImplementation: "upgrade",
  beacon: "upgrade",
  facets: "upgrade",
  admin: "upgrade",
  _initialized: "upgrade",
  paused: "pause",
  _roles: "role",
  owners: "signer",
  threshold: "signer",
  _safe_op: "safe",
  _safe_module_op: "safe",
  _timelock_op: "timelock",
  min_delay: "timelock",
};

// Pull the state-variable name out of a witnessed type's payload:
// `value_changed:state_variable:owner` → "owner",
// `member_changed:fromDenyList` → "fromDenyList".
export function witnessedSlot(type) {
  const match = /^(value|member)_changed:(.+)$/.exec(String(type || ""));
  if (!match) return null;
  return { stem: match[1], slot: match[2].split(":").pop() };
}

export function eventKind(evt) {
  // Back-compat: callers historically passed just the event_type string.
  const event = typeof evt === "string" ? { event_type: evt } : evt;
  const type = String(event?.event_type || "");
  if (type === "state_changed_poll") return "state";
  // Witnessed types name the slot that was PROVEN to move, so the kind comes
  // from that slot rather than from the emitter's donated write set (which is
  // exactly the evidence the taxonomy stopped trusting).
  const witnessed = witnessedSlot(type);
  if (witnessed) {
    return WRITE_TARGET_TO_KIND[witnessed.slot] || "state";
  }
  const tags = tagsForEvent(event);
  const writes = tags.writes || [];
  for (const wt of writes) {
    if (WRITE_TARGET_TO_KIND[wt]) return WRITE_TARGET_TO_KIND[wt];
  }
  // Producer's neutral terminal fallback (`state_changed:<controller_id>`):
  // a tracked slot was written and nothing classified it. "State change" is
  // what that says; it stays out of every control/authority kind.
  if (type.startsWith("state_changed")) return "state";
  return "other";
}

const KIND_LABEL = {
  upgrade: "Upgrade",
  owner: "Ownership",
  pause: "Pause",
  role: "Role",
  signer: "Signer",
  safe: "Safe tx",
  timelock: "Timelock",
  state: "State change",
  other: "Event",
};

export function eventKindLabel(evt) {
  return KIND_LABEL[eventKind(evt)] || "Event";
}

// Severity is used for the colored ticks / chip backgrounds.
//   critical → owner, pause, upgrade — change anyone should react to
//   major    → role grant/revoke, threshold/delay changes
//   routine  → safe tx, module exec, state polls
//
// Kept as the FALLBACK only: it is derived from the event kind, which is a
// statement about what moved, not about whether an operator needs to see it.
// Where the backend published a salience, that wins (see eventSeverity).
const SEVERITY = {
  upgrade: "critical",
  owner: "critical",
  pause: "critical",
  role: "major",
  signer: "major",
  timelock: "major",
  safe: "routine",
  state: "routine",
  other: "routine",
};

// ---------------------------------------------------------------------------
// Salience — the vocabulary mirror of record
// ---------------------------------------------------------------------------
//
// Mirrors services/monitoring/salience.py. Four values, and the fourth is the
// point: `not_determined` is an event the backend's rules did not rate, and it
// renders at `notable` prominence. Nothing here may default to `routine` —
// that would be silent suppression minted from ignorance, client-side.
const SALIENCE_ALERT = "alert";
const SALIENCE_NOTABLE = "notable";
export const SALIENCE_ROUTINE = "routine";
export const SALIENCE_NOT_DETERMINED = "not_determined";

const SALIENCE_VALUES = [
  SALIENCE_ALERT,
  SALIENCE_NOTABLE,
  SALIENCE_ROUTINE,
  SALIENCE_NOT_DETERMINED,
];

// `not_determined` sorts WITH `notable` (services/monitoring/notifier.py's
// _SALIENCE_ORDER), so a threshold never drops an event it never rated.
const SALIENCE_ORDER = {
  [SALIENCE_ROUTINE]: 0,
  [SALIENCE_NOT_DETERMINED]: 1,
  [SALIENCE_NOTABLE]: 1,
  [SALIENCE_ALERT]: 2,
};

// The backend owns this classification. There is deliberately NO client-side
// re-derivation from event_type: a mirrored ruleset would drift, and a drifted
// mirror that hides rows is a silent-suppression bug. An absent or unknown
// value reads as `not_determined`, which renders.
export function eventSalience(evt) {
  const value = evt?.data?.salience;
  return SALIENCE_VALUES.includes(value) ? value : SALIENCE_NOT_DETERMINED;
}

function salienceRank(level) {
  const rank = SALIENCE_ORDER[level];
  return rank === undefined ? SALIENCE_ORDER[SALIENCE_NOT_DETERMINED] : rank;
}

// Does `level` clear a `minimum` threshold? An unrecognized minimum admits
// everything rather than filtering on a bar we cannot read.
export function salienceAllows(level, minimum) {
  if (!SALIENCE_VALUES.includes(minimum)) return true;
  return salienceRank(level) >= salienceRank(minimum);
}

// Salience → tick colour. `not_determined` maps to `major`, the same
// prominence as `notable`: unrated is visible.
const SEVERITY_BY_SALIENCE = {
  [SALIENCE_ALERT]: "critical",
  [SALIENCE_NOTABLE]: "major",
  [SALIENCE_ROUTINE]: "routine",
  [SALIENCE_NOT_DETERMINED]: "major",
};

// Rebased on salience when the row carries one — which removes the old
// hardcoding of every `safe` and `state` event to `routine`. Rows written
// before salience landed keep the kind-derived table.
export function eventSeverity(evt) {
  const level = evt?.data?.salience;
  if (SALIENCE_VALUES.includes(level)) return SEVERITY_BY_SALIENCE[level];
  return SEVERITY[eventKind(evt)] || "routine";
}
