import { shortenAddress } from "../graph.js";

export function relativeTime(iso, now = Date.now()) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.round(d / 30);
  return `${mo}mo ago`;
}

function shortHash(h) {
  if (!h || typeof h !== "string") return "—";
  if (h.length <= 14) return h;
  return `${h.slice(0, 8)}…${h.slice(-4)}`;
}

function fmtSeconds(sec) {
  if (sec == null) return null;
  const n = Number(sec);
  if (!Number.isFinite(n)) return null;
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${Math.round(n / 60)}m`;
  if (n < 86400) return `${Math.round(n / 3600)}h`;
  return `${Math.round(n / 86400)}d`;
}

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

function tagsForEvent(evt) {
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
function witnessedSlot(type) {
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
export const SALIENCE_ALERT = "alert";
export const SALIENCE_NOTABLE = "notable";
export const SALIENCE_ROUTINE = "routine";
export const SALIENCE_NOT_DETERMINED = "not_determined";

export const SALIENCE_VALUES = [
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

export function salienceRank(level) {
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

function arrowSub(from, to) {
  return from && to ? `${shortenAddress(from)} → ${shortenAddress(to)}` : null;
}

// Addresses and hashes shorten; numbers, booleans and names render whole —
// truncating a uint would state a different value.
function shortenIfHex(value) {
  const s = String(value);
  return /^0x[0-9a-f]{40}$/i.test(s) ? shortenAddress(s) : s;
}

// Unbounded numeric scalars (uint256 supplies/balances) are unreadable raw,
// but the producer doesn't know the token's decimals, so no unit may be
// assumed. Big integers render in scientific notation; the relative delta is
// derivable from the pair alone and carries the meaning a unit would.
const DECIMAL_INT = /^-?\d+$/;
const COMPACT_OVER_DIGITS = 12;

function isLongInt(s) {
  return DECIMAL_INT.test(s) && s.replace("-", "").length > COMPACT_OVER_DIGITS;
}

function fmtScalar(value) {
  const s = String(value);
  if (!isLongInt(s)) return shortenIfHex(s);
  const neg = s.startsWith("-");
  const digits = neg ? s.slice(1) : s;
  return `${neg ? "-" : ""}${digits[0]}.${digits.slice(1, 5)}e${digits.length - 1}`;
}

function pctDelta(before, after) {
  const b = String(before);
  const a = String(after);
  if (!DECIMAL_INT.test(b) || !DECIMAL_INT.test(a)) return null;
  const bi = BigInt(b);
  const ai = BigInt(a);
  if (bi === 0n) return null; // no base to be relative to
  const base = bi < 0n ? -bi : bi;
  const milliPct = ((ai - bi) * 100000n) / base;
  const sign = ai >= bi ? "+" : "-";
  if (milliPct === 0n) return ai === bi ? null : `${sign}<0.001%`;
  const abs = milliPct < 0n ? -milliPct : milliPct;
  return `${sign}${abs / 1000n}.${(abs % 1000n).toString().padStart(3, "0")}%`;
}

// old→new detail line shared by the read-witnessed renderers. Small values
// stay verbatim; wei-scale integers compact, with the relative delta appended
// since compaction is what hid it.
function diffSub(before, after) {
  if (before == null || after == null) return null;
  const b = String(before);
  const a = String(after);
  const compacted = isLongInt(b) || isLongInt(a);
  const delta = compacted ? pctDelta(b, a) : null;
  return `${fmtScalar(b)} → ${fmtScalar(a)}${delta ? ` (${delta})` : ""}`;
}

// Per-write-target renderers. Each renderer is ``(data, event_type) → {
// title, sub }``. The event_type is passed so paired events (paused vs
// unpaused, granted vs revoked, scheduled vs executed, success vs
// failure) can swap verbs without exploding into separate write-target
// entries.
//
// Underscore-prefixed targets render activity events (no addressable
// slot); the renderer surfaces the meaningful tx args.

// Why a Safe execution carries no decoded call. Mirrors the backend's
// ``safe_exec.status`` values (``services/monitoring/enrichment.py``); an
// unknown status renders verbatim rather than as silence.
const SAFE_EXEC_STATUS_SUB = {
  not_top_level_call: "not a direct execTransaction on this Safe — inner call not witnessed",
  over_budget: "not decoded this pass (transaction budget)",
  args_undecodable: "execTransaction arguments did not decode",
  ambiguous_attribution:
    "this Safe executed more than once in this transaction — which call these arguments describe is not witnessed",
};

// Which layer of a batch failed to expand. Mirrors ``batch_status_reason``.
const SAFE_EXEC_BATCH_REASON = {
  malformed_payload: "payload did not decode",
  nested_payload_undecodable: "a nested payload did not decode",
  nested_depth_exceeded: "nested deeper than the decoder expands",
};

// A signature's display form: the function name alone. The parameter-type
// list is a fact about the ABI, not about what happened — it goes in the
// tooltip (`titleDetail`), never in the row. A selector stays raw: it is a
// real fact and no name is invented to replace it.
function fnDisplay(signature) {
  const s = String(signature || "");
  const paren = s.indexOf("(");
  return paren > 0 ? `${s.slice(0, paren)}()` : s || null;
}

// Display-only address naming. `nameFor` is the caller's map of the
// protocol's own contracts (surface machines / principals) — a rendering
// convenience, never a witness: it changes what a row SAYS an address is
// called, never what was claimed or how salient it is.
function addrDisplay(addr, opts) {
  if (!addr) return null;
  const name = opts?.nameFor ? opts.nameFor(addr) : null;
  return name || shortenAddress(addr);
}

const RENDER_BY_WRITE_TARGET = {
  owner: (d) => {
    const renounced = d.new_owner && /^0x0+$/i.test(d.new_owner);
    return {
      title: renounced ? "Ownership renounced" : "Ownership transferred",
      sub: arrowSub(d.old_owner, d.new_owner),
    };
  },
  pendingOwner: (d) => ({
    title: "Ownership transfer initiated",
    sub: arrowSub(d.old_owner, d.new_owner),
  }),
  authority: (d) => ({
    title: "Authority updated",
    sub: arrowSub(d.old_authority, d.new_authority),
  }),
  implementation: (d) => ({
    title: "Implementation upgraded",
    sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
  }),
  pendingImplementation: (d) => ({
    title: "Pending implementation queued",
    sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
  }),
  beacon: (d) => ({
    title: "Beacon upgraded",
    sub: d.beacon ? `beacon ${shortenAddress(d.beacon)}` : null,
  }),
  facets: () => ({ title: "Diamond cut (facets changed)", sub: null }),
  admin: (d) => ({
    title: "Proxy admin changed",
    sub: d.new_admin ? `new admin ${shortenAddress(d.new_admin)}` : null,
  }),
  paused: (d, type) => ({
    title: type === "paused" ? "Contract paused" : "Contract unpaused",
    sub: d.account
      ? `${type === "paused" ? "paused" : "unpaused"} by ${shortenAddress(d.account)}`
      : null,
  }),
  _roles: (d, type) => {
    const granted = type === "role_granted";
    return {
      title: granted ? "Role granted" : "Role revoked",
      sub: d.account
        ? `${granted ? "to" : "from"} ${shortenAddress(d.account)}${d.sender ? ` by ${shortenAddress(d.sender)}` : ""}`
        : null,
    };
  },
  owners: (d, type) => ({
    title: type === "signer_added" ? "Safe signer added" : "Safe signer removed",
    sub: d.owner ? shortenAddress(d.owner) : null,
  }),
  threshold: (d) => ({
    title: "Safe threshold changed",
    sub: d.threshold != null ? `new threshold ${d.threshold}` : null,
  }),
  min_delay: (d) => {
    const oldD = fmtSeconds(d.old_delay);
    const newD = fmtSeconds(d.new_delay);
    return {
      title: "Timelock delay changed",
      sub: oldD && newD ? `${oldD} → ${newD}` : null,
    };
  },
  _safe_op: (d, type, opts) => {
    const executed = type === "safe_tx_executed";
    // Pre-enrichment shape, and the shape a row keeps when the transaction was
    // never fetched: the Safe-internal hash is all that was witnessed.
    const unenriched = {
      title: executed ? "Safe transaction executed" : "Safe transaction reverted",
      sub: d.safe_tx_hash
        ? `safeTxHash ${shortHash(d.safe_tx_hash)}${d.payment ? ` · payment ${d.payment} wei` : ""}`
        : null,
    };
    const se = d.safe_exec;
    if (!se || typeof se !== "object") return unenriched;

    // A stated decode gap renders AS one. Falling back to the bare hash here
    // would make "we could not examine this" look like the whole story.
    if (se.status !== "decoded") {
      return { ...unenriched, sub: SAFE_EXEC_STATUS_SUB[se.status] || `not decoded (${se.status})` };
    }

    if (se.batch_status === "undecodable") {
      const why = SAFE_EXEC_BATCH_REASON[se.batch_status_reason];
      const parts = [`delegatecall → ${addrDisplay(se.to, opts)}`];
      if (why) parts.push(why);
      return {
        title: `${executed ? "MultiSend batch" : "Reverted MultiSend batch"} — did not decode`,
        sub: parts.join(" · "),
      };
    }

    const batch = Array.isArray(se.batch) ? se.batch : null;
    const head = batch && batch.length ? batch[0] : null;
    const call = head || se;
    // A resolved signature when one exists, the raw selector otherwise — a
    // selector is a real fact, and a name is never invented to replace it.
    // The row shows the function NAME; the full signature rides in
    // `titleDetail` for the tooltip.
    const signature = head ? head.signature : se.target_function?.signature;
    const name = fnDisplay(signature) || call.selector || null;
    const title = executed
      ? name
        ? `Executed ${name}`
        : "Safe transaction executed"
      : `Reverted: ${name || "Safe transaction"}`;

    const parts = [];
    if (call.to) parts.push(`on ${addrDisplay(call.to, opts)}`);
    // `call` is the default operation — only a delegatecall is worth ink,
    // and an unrecognized one says so out loud (it is what the alert is).
    if (call.operation === 1 || call.operation_label === "delegatecall") {
      parts.push(
        se.multisend_recognized === false && !batch
          ? "delegatecall — not a pinned MultiSend"
          : "delegatecall",
      );
    }
    if (se.value && se.value !== "0") parts.push(`value ${se.value} wei`);
    if (batch && batch.length > 1) parts.push(`+${batch.length - 1} more in batch`);
    return {
      title,
      titleDetail: signature || null,
      sub: parts.length ? parts.join(" · ") : null,
    };
  },
  _safe_module_op: (d, type, opts) => ({
    title: type === "safe_module_executed" ? "Safe module executed" : "Safe module reverted",
    sub: d.module ? `module ${addrDisplay(d.module, opts)}` : null,
  }),
  _timelock_op: (d, type, opts) => {
    const scheduled = type === "timelock_scheduled";
    // The backend's fleet-internal resolution when it found one; the raw
    // selector otherwise. Never a name this side invented.
    const signature = d.target_function?.signature || null;
    const name = fnDisplay(signature) || (d.selector ? `sel ${d.selector}` : null);
    const delay = fmtSeconds(d.delay);
    const subParts = [];
    if (d.target) subParts.push(`on ${addrDisplay(d.target, opts)}`);
    if (scheduled && delay) subParts.push(`delay ${delay}`);
    return {
      title: `Timelock ${scheduled ? "scheduled" : "executed"}${name ? ` ${name}` : " operation"}`,
      titleDetail: signature,
      sub: subParts.length ? subParts.join(" · ") : null,
    };
  },
};

// Per-event_type title overrides. Used for the one case where the same
// write target produces a distinct title — GnosisSafe's
// ``changed_master_copy`` writes ``implementation`` (same as a proxy
// upgrade) but the user-facing label is "Safe singleton swapped"
// because the contract isn't a generic proxy. Kept as a small map
// rather than baking into the write-target renderer so the renderer
// table stays generic.
const TITLE_OVERRIDES = {
  changed_master_copy: "Safe singleton (mastercopy) swapped",
};

// Turn an event row into a human sentence for the right pane. Returns
// { title, sub } — title is the short prose summary, sub is the supporting
// detail line (hash, target, etc.). Falls back to a generic shape rather
// than throwing on unknown types so future event_types still render.
// `opts.nameFor(address) → name|null` is an optional display-only resolver
// (the surface's own contract/principal names). It never affects which
// renderer runs or what is claimed — only how an address reads.
export function decodeEvent(evt, opts = undefined) {
  const d = evt?.data || {};
  const type = evt?.event_type || "unknown";

  // Synthetic poll event — no decoder, no tags, render directly. The poller
  // writes `old_value`/`new_value`; the shorter keys are read too because the
  // read-verified path below and older rows use them.
  if (type === "state_changed_poll") {
    const field = d.field || "state";
    const rawBefore = d.old != null ? d.old : d.old_value;
    const rawAfter = d.new != null ? d.new : d.new_value;
    return {
      title: `${field} changed (polled)`,
      sub: diffSub(rawBefore, rawAfter),
    };
  }

  // Witnessed types. `value_changed:<controller_id>` carries a read-verified
  // old→new diff; `member_changed:<mapping_var>` carries a qualified entry
  // change with the key/value/direction in data. Both are handled ahead of
  // the tag-driven table on purpose: the proven payload is the claim, and the
  // emitter's donated write set must not re-title it as something else.
  const witnessed = witnessedSlot(type);
  if (witnessed?.stem === "value") {
    return {
      title: `${witnessed.slot} changed (verified)`,
      sub: diffSub(d.old, d.new),
    };
  }
  if (witnessed?.stem === "member") {
    const key = d.key != null ? shortenIfHex(d.key) : null;
    // `direction` is the event's own statement about what happened to the
    // entry; without one the honest rendering names no verb.
    const verb = { add: "added", remove: "removed", set: "set" }[d.direction] || "changed";
    const parts = [];
    if (key) parts.push(key);
    if (d.value != null) parts.push(`= ${shortenIfHex(d.value)}`);
    return {
      title: `${witnessed.slot} entry ${verb}`,
      sub: parts.length ? parts.join(" ") : null,
    };
  }

  // Tag-driven: walk effect_tags.writes (with synthesis fallback for
  // legacy events). First matching write target's renderer wins —
  // priority comes from the order tags emit writes (commit-phase
  // owner before intent-phase pendingOwner, etc.).
  const tags = tagsForEvent(evt);
  const writes = tags.writes || [];
  for (const wt of writes) {
    const renderer = RENDER_BY_WRITE_TARGET[wt];
    if (renderer) {
      const result = renderer(d, type, opts);
      if (TITLE_OVERRIDES[type]) {
        result.title = TITLE_OVERRIDES[type];
      }
      return result;
    }
  }

  // Unknown event type / unrecognized write target — surface raw
  // key-value pairs so the user sees something useful instead of an
  // opaque event name.
  const entries = Object.entries(d)
    .filter(([k]) => !["contract_address", "contract_type", "chain", "effect_tags"].includes(k))
    .slice(0, 3);
  const sub = entries.length
    ? entries
        .map(
          ([k, v]) =>
            `${k}: ${typeof v === "string" && v.startsWith("0x") ? shortenAddress(v) : v}`,
        )
        .join(" · ")
    : null;

  // The producer's terminal fallback (services/monitoring/event_topics.py
  // `_resolve_event_type`) carries the tracked controller_id after the stem.
  // The stem is the claim and must survive verbatim into the prose: only
  // `controller_changed:` says an authority binding moved;
  // `state_changed:` says a tracked slot was written and nothing more.
  // Mangling the whole type string (`replace(/_/g, " ")`) turned the second
  // into the first's wording, so match the stem explicitly.
  const terminal = /^(controller|state)_changed:(.+)$/.exec(type);
  if (terminal) {
    const slot = terminal[2].split(":").pop();
    return {
      title: terminal[1] === "controller" ? `Controller changed: ${slot}` : `State changed: ${slot}`,
      sub,
    };
  }

  return { title: type.replace(/_/g, " "), sub };
}

// Convert a MonitoredContract's last_known_state + monitoring_config into
// rows for the left-rail card. Returns [{ k, v, tone }] where tone is one
// of "ok" | "warn" | "muted" | null.
export function stateRows(contract) {
  const s = contract?.last_known_state || {};
  const cfg = contract?.monitoring_config || {};
  const rows = [];

  if (contract?.contract_type === "safe") {
    if (s.threshold != null) {
      rows.push({ k: "Threshold", v: String(s.threshold), tone: null });
    }
  }
  if ("owner" in s) {
    const renounced = /^0x0+$/i.test(s.owner || "");
    rows.push({
      k: "Owner",
      v: renounced ? "renounced" : shortenAddress(s.owner),
      tone: renounced ? "ok" : null,
    });
  }
  if ("paused" in s) {
    rows.push({
      k: "Paused",
      v: s.paused ? "yes" : "no",
      tone: s.paused ? "warn" : "ok",
    });
  }
  if ("implementation" in s) {
    rows.push({ k: "Impl", v: shortenAddress(s.implementation), tone: null });
  }
  if ("admin" in s) {
    rows.push({ k: "Admin", v: shortenAddress(s.admin), tone: null });
  }
  if ("min_delay" in s) {
    const f = fmtSeconds(s.min_delay) || `${s.min_delay}s`;
    rows.push({ k: "Min delay", v: f, tone: null });
  }

  // Always show what we're watching, even if last_known_state is empty —
  // tells the user this row isn't broken, just hasn't seen state yet.
  const watching = [];
  if (cfg.watch_upgrades) watching.push("upgrades");
  if (cfg.watch_ownership) watching.push("owner");
  if (cfg.watch_pause) watching.push("pause");
  if (cfg.watch_roles) watching.push("roles");
  if (cfg.watch_safe_signers || cfg.watch_signers) watching.push("safe");
  if (cfg.watch_timelock) watching.push("timelock");
  // Same phantom flag as the `state` alert group: nothing writes `watch_state`,
  // so a polled contract used to render as not watched for state at all. The
  // polling plan is the witness that it is.
  if (cfg.watch_state || (Array.isArray(cfg.polling_plan) && cfg.polling_plan.length > 0)) watching.push("state");
  if (watching.length === 0) watching.push("nothing");
  rows.push({ k: "Watching", v: watching.join(" · "), tone: "muted" });

  return rows;
}

// Pick the freshness state for the global status bar. Returns
//   { tone: "ok"|"warn"|"err", label }
// based on the youngest updated_at across contracts (scanner bumps
// updated_at every scan, so a recent timestamp means it's alive).
export function scannerHealth(contracts, now = Date.now()) {
  if (!contracts || contracts.length === 0) {
    return { tone: "muted", label: "no contracts" };
  }
  const stamps = contracts
    .map((c) => c.updated_at)
    .filter(Boolean)
    .map((s) => new Date(s).getTime())
    .filter(Number.isFinite);
  if (stamps.length === 0) return { tone: "muted", label: "no scan yet" };
  const youngest = Math.max(...stamps);
  const ageS = Math.round((now - youngest) / 1000);
  // PROTOCOL_SCAN_INTERVAL default is 600s. Treat 2× as "lagging", 5× as "stalled".
  let tone = "ok";
  if (ageS > 600 * 2) tone = "warn";
  if (ageS > 600 * 5) tone = "err";
  return { tone, label: `scanned ${relativeTime(new Date(youngest).toISOString(), now)}` };
}
