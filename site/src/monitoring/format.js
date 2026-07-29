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

export function eventKind(evt) {
  // Back-compat: callers historically passed just the event_type string.
  const event = typeof evt === "string" ? { event_type: evt } : evt;
  if (event?.event_type === "state_changed_poll") return "state";
  const tags = tagsForEvent(event);
  const writes = tags.writes || [];
  for (const wt of writes) {
    if (WRITE_TARGET_TO_KIND[wt]) return WRITE_TARGET_TO_KIND[wt];
  }
  // Producer's neutral terminal fallback (`state_changed:<controller_id>`):
  // a tracked slot was written and nothing classified it. "State change" is
  // what that says; it stays out of every control/authority kind.
  if (String(event?.event_type || "").startsWith("state_changed")) return "state";
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

export function eventSeverity(evt) {
  return SEVERITY[eventKind(evt)] || "routine";
}

function arrowSub(from, to) {
  return from && to ? `${shortenAddress(from)} → ${shortenAddress(to)}` : null;
}

// Per-write-target renderers. Each renderer is ``(data, event_type) → {
// title, sub }``. The event_type is passed so paired events (paused vs
// unpaused, granted vs revoked, scheduled vs executed, success vs
// failure) can swap verbs without exploding into separate write-target
// entries.
//
// Underscore-prefixed targets render activity events (no addressable
// slot); the renderer surfaces the meaningful tx args.
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
  _safe_op: (d, type) => ({
    title: type === "safe_tx_executed" ? "Safe transaction executed" : "Safe transaction reverted",
    sub: d.safe_tx_hash
      ? `safeTxHash ${shortHash(d.safe_tx_hash)}${d.payment ? ` · payment ${d.payment} wei` : ""}`
      : null,
  }),
  _safe_module_op: (d, type) => ({
    title: type === "safe_module_executed" ? "Safe module executed" : "Safe module reverted",
    sub: d.module ? `module ${shortenAddress(d.module)}` : null,
  }),
  _timelock_op: (d, type) => {
    const scheduled = type === "timelock_scheduled";
    const target = d.target ? shortenAddress(d.target) : null;
    const sel = d.selector;
    const delay = fmtSeconds(d.delay);
    const subParts = [];
    if (target) subParts.push(`target ${target}`);
    if (sel) subParts.push(`sel ${sel}`);
    if (scheduled && delay) subParts.push(`delay ${delay}`);
    return {
      title: `Timelock operation ${scheduled ? "scheduled" : "executed"}`,
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
export function decodeEvent(evt) {
  const d = evt?.data || {};
  const type = evt?.event_type || "unknown";

  // Synthetic poll event — no decoder, no tags, render directly.
  if (type === "state_changed_poll") {
    const field = d.field || "state";
    const before = d.old != null ? String(d.old) : null;
    const after = d.new != null ? String(d.new) : null;
    return {
      title: `${field} changed (polled)`,
      sub: before && after ? `${before} → ${after}` : null,
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
      const result = renderer(d, type);
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
  if (cfg.watch_state) watching.push("state");
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
