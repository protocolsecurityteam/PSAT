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

const KIND = {
  upgraded: "upgrade",
  admin_changed: "upgrade",
  beacon_upgraded: "upgrade",
  new_implementation: "upgrade",
  new_pending_implementation: "upgrade",
  changed_master_copy: "upgrade",
  target_updated: "upgrade",
  upgraded_revision: "upgrade",
  diamond_cut: "upgrade",
  ownership_transferred: "owner",
  paused: "pause",
  unpaused: "pause",
  role_granted: "role",
  role_revoked: "role",
  signer_added: "signer",
  signer_removed: "signer",
  threshold_changed: "signer",
  safe_tx_executed: "safe",
  safe_tx_failed: "safe",
  safe_module_executed: "safe",
  safe_module_failed: "safe",
  timelock_scheduled: "timelock",
  timelock_executed: "timelock",
  delay_changed: "timelock",
  state_changed_poll: "state",
};

export function eventKind(type) {
  return KIND[type] || "other";
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

export function eventKindLabel(type) {
  return KIND_LABEL[eventKind(type)] || "Event";
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

export function eventSeverity(type) {
  return SEVERITY[eventKind(type)] || "routine";
}

// Turn an event row into a human sentence for the right pane. Returns
// { title, sub } — title is the short prose summary, sub is the supporting
// detail line (hash, target, etc.). Falls back to a generic shape rather
// than throwing on unknown types so future event_types still render.
export function decodeEvent(evt) {
  const d = evt?.data || {};
  const type = evt?.event_type || "unknown";

  switch (type) {
    case "ownership_transferred": {
      const from = d.old_owner;
      const to = d.new_owner;
      const renounced = to && /^0x0+$/i.test(to);
      const title = renounced
        ? "Ownership renounced"
        : "Ownership transferred";
      const sub = from && to ? `${shortenAddress(from)} → ${shortenAddress(to)}` : null;
      return { title, sub };
    }
    case "paused":
      return {
        title: "Contract paused",
        sub: d.account ? `paused by ${shortenAddress(d.account)}` : null,
      };
    case "unpaused":
      return {
        title: "Contract unpaused",
        sub: d.account ? `unpaused by ${shortenAddress(d.account)}` : null,
      };

    case "upgraded":
    case "new_implementation":
    case "target_updated":
    case "upgraded_revision":
      return {
        title: "Implementation upgraded",
        sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
      };
    case "new_pending_implementation":
      return {
        title: "Pending implementation queued",
        sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
      };
    case "changed_master_copy":
      return {
        title: "Safe singleton (mastercopy) swapped",
        sub: d.implementation ? `→ ${shortenAddress(d.implementation)}` : null,
      };
    case "admin_changed":
      return {
        title: "Proxy admin changed",
        sub: d.new_admin ? `new admin ${shortenAddress(d.new_admin)}` : null,
      };
    case "beacon_upgraded":
      return {
        title: "Beacon upgraded",
        sub: d.beacon ? `beacon ${shortenAddress(d.beacon)}` : null,
      };
    case "diamond_cut":
      return { title: "Diamond cut (facets changed)", sub: null };

    case "role_granted":
      return {
        title: "Role granted",
        sub: d.account
          ? `to ${shortenAddress(d.account)}${d.sender ? ` by ${shortenAddress(d.sender)}` : ""}`
          : null,
      };
    case "role_revoked":
      return {
        title: "Role revoked",
        sub: d.account
          ? `from ${shortenAddress(d.account)}${d.sender ? ` by ${shortenAddress(d.sender)}` : ""}`
          : null,
      };

    case "signer_added":
      return {
        title: "Safe signer added",
        sub: d.owner ? shortenAddress(d.owner) : null,
      };
    case "signer_removed":
      return {
        title: "Safe signer removed",
        sub: d.owner ? shortenAddress(d.owner) : null,
      };
    case "threshold_changed":
      return {
        title: "Safe threshold changed",
        sub: d.threshold != null ? `new threshold ${d.threshold}` : null,
      };

    case "safe_tx_executed":
      return {
        title: "Safe transaction executed",
        sub: d.safe_tx_hash
          ? `safeTxHash ${shortHash(d.safe_tx_hash)}${d.payment ? ` · payment ${d.payment} wei` : ""}`
          : null,
      };
    case "safe_tx_failed":
      return {
        title: "Safe transaction reverted",
        sub: d.safe_tx_hash ? `safeTxHash ${shortHash(d.safe_tx_hash)}` : null,
      };
    case "safe_module_executed":
      return {
        title: "Safe module executed",
        sub: d.module ? `module ${shortenAddress(d.module)}` : null,
      };
    case "safe_module_failed":
      return {
        title: "Safe module reverted",
        sub: d.module ? `module ${shortenAddress(d.module)}` : null,
      };

    case "timelock_scheduled": {
      const delay = fmtSeconds(d.delay);
      const target = d.target ? shortenAddress(d.target) : null;
      const sel = d.selector;
      const subParts = [];
      if (target) subParts.push(`target ${target}`);
      if (sel) subParts.push(`sel ${sel}`);
      if (delay) subParts.push(`delay ${delay}`);
      return {
        title: "Timelock operation scheduled",
        sub: subParts.length ? subParts.join(" · ") : null,
      };
    }
    case "timelock_executed": {
      const target = d.target ? shortenAddress(d.target) : null;
      const sel = d.selector;
      const subParts = [];
      if (target) subParts.push(`target ${target}`);
      if (sel) subParts.push(`sel ${sel}`);
      return {
        title: "Timelock operation executed",
        sub: subParts.length ? subParts.join(" · ") : null,
      };
    }
    case "delay_changed": {
      const oldD = fmtSeconds(d.old_delay);
      const newD = fmtSeconds(d.new_delay);
      return {
        title: "Timelock delay changed",
        sub: oldD && newD ? `${oldD} → ${newD}` : null,
      };
    }

    case "state_changed_poll": {
      const field = d.field || "state";
      const before = d.old != null ? String(d.old) : null;
      const after = d.new != null ? String(d.new) : null;
      return {
        title: `${field} changed (polled)`,
        sub: before && after ? `${before} → ${after}` : null,
      };
    }

    default: {
      const entries = Object.entries(d)
        .filter(([k]) => !["contract_address", "contract_type", "chain"].includes(k))
        .slice(0, 3);
      const sub = entries.length
        ? entries.map(([k, v]) => `${k}: ${typeof v === "string" && v.startsWith("0x") ? shortenAddress(v) : v}`).join(" · ")
        : null;
      return { title: type.replace(/_/g, " "), sub };
    }
  }
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

// Build a map of contract.id → most recent event timestamp.
export function lastEventByContract(events) {
  const out = {};
  for (const e of events || []) {
    const id = e.monitored_contract_id;
    const t = e.detected_at;
    if (!id || !t) continue;
    if (!out[id] || new Date(t).getTime() > new Date(out[id]).getTime()) {
      out[id] = t;
    }
  }
  return out;
}
