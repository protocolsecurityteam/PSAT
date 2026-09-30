// Event kind and backend-owned salience. Prose lives in format.js.

// Mirrors services.monitoring.event_topics._HANDROLLED_EVENT_TYPE_TO_TAGS, kept
// in sync by hand so pre-effect_tags events still classify. Underscore names
// are synthetic markers for events that don't write one named slot.
const HANDROLLED_EVENT_TYPE_TO_TAGS = {
  upgraded: { writes: ["implementation"], delegates: true },
  admin_changed: { writes: ["admin"] },
  beacon_upgraded: { writes: ["beacon"], delegates: true },
  changed_master_copy: { writes: ["implementation"], delegates: true },
  new_implementation: { writes: ["implementation"], delegates: true },
  new_pending_implementation: { writes: ["pendingImplementation"] },
  target_updated: { writes: ["implementation"], delegates: true },
  upgraded_revision: { writes: ["implementation"], delegates: true },
  diamond_cut: { writes: ["facets"], delegates: true },
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

// ``state`` is keyed by event_type: state_changed_poll carries no tags.
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

// `value_changed:state_variable:owner` → "owner", `member_changed:fromDenyList`
// → "fromDenyList".
export function witnessedSlot(type) {
  const match = /^(value|member)_changed:(.+)$/.exec(String(type || ""));
  if (!match) return null;
  return { stem: match[1], slot: match[2].split(":").pop() };
}

export function eventKind(evt) {
  const event = typeof evt === "string" ? { event_type: evt } : evt;
  const type = String(event?.event_type || "");
  if (type === "state_changed_poll") return "state";
  // Witnessed types name the slot proven to move; the emitter's donated write
  // set isn't trusted.
  const witnessed = witnessedSlot(type);
  if (witnessed) {
    return WRITE_TARGET_TO_KIND[witnessed.slot] || "state";
  }
  const tags = tagsForEvent(event);
  const writes = tags.writes || [];
  for (const wt of writes) {
    if (WRITE_TARGET_TO_KIND[wt]) return WRITE_TARGET_TO_KIND[wt];
  }
  // Neutral fallback: a slot was written and nothing classified it.
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

// Kind-derived fallback only; a published salience wins (eventSeverity).
// critical → owner, pause, upgrade
// major → role grant/revoke, threshold/delay changes
// routine → safe tx, module exec, state polls
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

// Mirrors services/monitoring/salience.py. `not_determined` is unrated and
// renders at `notable`; nothing may default to `routine`.
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

// As in notifier._SALIENCE_ORDER, so a threshold never drops an unrated event.
const SALIENCE_ORDER = {
  [SALIENCE_ROUTINE]: 0,
  [SALIENCE_NOT_DETERMINED]: 1,
  [SALIENCE_NOTABLE]: 1,
  [SALIENCE_ALERT]: 2,
};

// Deliberately no client-side re-derivation: a drifted mirror that hides rows
// is a silent-suppression bug. Unknown reads as `not_determined`.
export function eventSalience(evt) {
  const value = evt?.data?.salience;
  return SALIENCE_VALUES.includes(value) ? value : SALIENCE_NOT_DETERMINED;
}

function salienceRank(level) {
  const rank = SALIENCE_ORDER[level];
  return rank === undefined ? SALIENCE_ORDER[SALIENCE_NOT_DETERMINED] : rank;
}

// An unrecognized minimum admits everything.
export function salienceAllows(level, minimum) {
  if (!SALIENCE_VALUES.includes(minimum)) return true;
  return salienceRank(level) >= salienceRank(minimum);
}

const SEVERITY_BY_SALIENCE = {
  [SALIENCE_ALERT]: "critical",
  [SALIENCE_NOTABLE]: "major",
  [SALIENCE_ROUTINE]: "routine",
  [SALIENCE_NOT_DETERMINED]: "major",
};

// Rows written before salience keep the kind-derived table.
export function eventSeverity(evt) {
  const level = evt?.data?.salience;
  if (SALIENCE_VALUES.includes(level)) return SEVERITY_BY_SALIENCE[level];
  return SEVERITY[eventKind(evt)] || "routine";
}
