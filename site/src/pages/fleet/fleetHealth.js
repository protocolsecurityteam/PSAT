// Fleet pill labels, staleness, the progress triad (backlog · oldest-age ·
// rate), tones and unhealthy counting.

import { formatBlockNumber } from "../jobStages.js";

// Interval isn't in the response; mirrored from PROCESS_META.
export const PROCESS_PILL_LABEL = {
  coverage_verify: "Coverage verify",
  audit_text_extraction: "Audit text",
  audit_scope_extraction: "Audit scope",
  event_log_indexer: "Event indexer",
  enrollment_reconciler: "Reconciler",
};
export const PROCESS_INTERVAL_S = {
  coverage_verify: 30,
  audit_text_extraction: 30,
  audit_scope_extraction: 30,
  event_log_indexer: 90,
  enrollment_reconciler: 660,
};
export const KIND_DESC = { drainer: "row-draining daemon", indexer: "row-draining daemon", daemon: "background daemon" };
export const TONE_DOT = { ok: "#22c55e", idle: "#7dd3fc", warn: "#f59e0b", err: "#f87171", mute: "#64748b" };

// Watchers have no heartbeat; liveness comes from row freshness.
export const WATCHER_STALE_S = 6 * 3600;

export function staleWindowS(process) {
  const iv = PROCESS_INTERVAL_S[process] || 40;
  return Math.max(3 * iv, 120);
}

export function humanAge(s) {
  if (s == null) return "—";
  const n = Number(s);
  if (!Number.isFinite(n)) return "—";
  if (n < 60) return `${Math.round(n)}s`;
  if (n < 3600) return `${Math.round(n / 60)}m`;
  if (n < 86400) return `${(n / 3600).toFixed(1)}h`;
  return `${(n / 86400).toFixed(1)}d`;
}

export function utcTime(iso) {
  if (!iso) return "—";
  try {
    return `${new Date(iso).toISOString().slice(11, 19)}Z`;
  } catch {
    return iso;
  }
}

function auditHasFailures(d) {
  return (
    (d.process === "audit_text_extraction" || d.process === "audit_scope_extraction") &&
    (d.work?.failed || 0) > 0
  );
}

// A new cursor backfills from its contract's creation block, and resolution
// against it fails closed until caught up; max_indexed_block alone hides that.
export function indexerLagging(d) {
  return d.process === "event_log_indexer" && (d.work?.lagging_cursors || 0) > 0;
}


// Above the drainers' poll/lease cadence so a momentary empty claim doesn't
// trip it.
const STUCK_AGE_S = 300;
const FALLING_BEHIND_PER_MIN = 2;
// A stopped worker's last rate shouldn't linger.
const RATE_DECAY_MS = 5 * 60 * 1000;

// undefined when the worker hasn't reported one.
function throughputCount(d) {
  const det = d.detail || {};
  switch (d.process) {
    case "coverage_verify":
      return det.verified_last_pass;
    case "audit_text_extraction":
    case "audit_scope_extraction":
      return det.claimed_last_pass;
    case "event_log_indexer":
      return det.inserted_last_pass;
    case "enrollment_reconciler":
      return det.protocols_reconciled_last_pass;
    default:
      return undefined;
  }
}

// Backlog, an aged oldest item, and zero throughput last pass; either alone is
// ambiguous. Needs an oldest-age, so audit workers only.
export function daemonStuck(d) {
  const w = d.work || {};
  return (
    (w.backlog || 0) > 0 &&
    w.oldest_pending_age_s != null &&
    w.oldest_pending_age_s >= STUCK_AGE_S &&
    throughputCount(d) === 0
  );
}

// A soft warn, not counted as unhealthy: bursts legitimately grow the queue.
export function daemonFallingBehind(rate) {
  return rate?.backlogPerMin != null && rate.backlogPerMin >= FALLING_BEHIND_PER_MIN;
}

function parseIsoMs(iso) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : null;
}

// Anchored at the last value change, not the last poll, so slow-tick workers
// (the indexer, ~90s) report a stable rate rather than a 0/spike sawtooth.
// Decays to null after RATE_DECAY_MS. Mutates ``anchors``.
function trackRate(anchors, key, value, nowMs) {
  const v = Number(value);
  if (value == null || !Number.isFinite(v)) return null;
  const a = anchors[key];
  if (!a) {
    anchors[key] = { value: v, t: nowMs, rate: null };
    return null;
  }
  if (v !== a.value) {
    const dtMin = (nowMs - a.t) / 60000;
    const rate = dtMin > 0 ? (v - a.value) / dtMin : null;
    anchors[key] = { value: v, t: nowMs, rate };
    return rate;
  }
  if (a.rate != null && nowMs - a.t > RATE_DECAY_MS) a.rate = null;
  return a.rate;
}

// Δt uses the server's ``now`` so client clock skew can't distort it.
export function computeFleetRates(anchors, fleet) {
  if (!fleet) return {};
  const t = parseIsoMs(fleet.now) ?? Date.now();
  const rates = {};
  for (const d of fleet.daemons || []) {
    const a = anchors[d.process] || (anchors[d.process] = {});
    const w = d.work || {};
    const r = {};
    if (w.backlog != null) r.backlogPerMin = trackRate(a, "backlog", w.backlog, t);
    if (w.max_indexed_block != null) r.blocksPerMin = trackRate(a, "block", w.max_indexed_block, t);
    rates[d.process] = r;
  }
  const wch = fleet.watchers;
  if (wch) {
    const a = anchors.watchers || (anchors.watchers = {});
    rates.watchers = wch.max_scanned_block != null
      ? { blocksPerMin: trackRate(a, "block", wch.max_scanned_block, t) }
      : {};
  }
  return rates;
}

// Null near zero so a flat queue doesn't clutter.
export function fmtBacklogRate(perMin) {
  if (perMin == null || !Number.isFinite(perMin)) return null;
  const r = Math.round(perMin);
  if (r === 0) return null;
  return `${r > 0 ? "+" : "−"}${Math.abs(r)}/min`;
}

// Negative means a reorg rewind.
export function fmtBlockRate(perMin) {
  if (perMin == null || !Number.isFinite(perMin)) return null;
  const r = Math.round(perMin);
  if (r === 0) return null;
  return `${r > 0 ? "+" : "−"}${formatBlockNumber(Math.abs(r))} blocks/min`;
}

// err/mute set the pill class; idle/ok tint the dot. warn covers failed work
// items, a lagging indexer, stuck or falling-behind queues, and stale non-error
// daemons.
export function daemonTone(d, rate) {
  if (d.status === "error") return "err";
  if (d.status === "sleeping") return "idle";
  if (!d.last_beat_at || d.status === "unknown") return "mute";
  if (d.stale) return "warn";
  if (indexerLagging(d)) return "warn";
  if (daemonStuck(d)) return "warn";
  if (daemonFallingBehind(rate)) return "warn";
  if (auditHasFailures(d)) return "warn";
  if (d.status === "idle") return "idle";
  return "ok";
}

export function daemonPulse(d) {
  return !!d.alive && (d.status === "running" || d.status === "idle");
}

export function pillSub(d, tone, rate) {
  if (d.status === "sleeping") return "sleeping";
  if (daemonStuck(d)) return "stuck";
  if (daemonFallingBehind(rate)) return fmtBacklogRate(rate.backlogPerMin);
  switch (d.process) {
    case "coverage_verify":
      return `${d.work?.total ?? 0} rows`;
    case "audit_text_extraction":
    case "audit_scope_extraction": {
      const f = d.work?.failed ?? 0;
      return f > 0 ? `${f} failed` : "clear";
    }
    case "event_log_indexer":
      if (tone === "err") return "error";
      if (d.stale) return "stale";
      if ((d.work?.lagging_cursors || 0) > 0) return `${d.work.lagging_cursors} behind`;
      return `${d.work?.cursors ?? 0} cursors`;
    case "enrollment_reconciler":
      return d.last_beat_at ? (d.stale ? "stale" : "ok") : "no beat";
    default:
      return tone === "err" ? "error" : tone === "mute" ? "no beat" : "";
  }
}

export function watcherStale(w) {
  if (!w) return true;
  const age = w.last_update_age_s;
  return age == null || age > WATCHER_STALE_S;
}

export function watcherSub(w) {
  if (!w) return "no data";
  if (watcherStale(w)) return w.last_update_age_s == null ? "no data" : `${humanAge(w.last_update_age_s)} stale`;
  return `${w.monitored_contracts ?? 0} watched`;
}

// Stuck is stable, so it counts; falling-behind is transient and doesn't.
export function countUnhealthy(fleet) {
  const daemons = fleet?.daemons || [];
  let n = daemons.filter(
    (d) => d.status !== "sleeping" && (d.status === "error" || d.stale || indexerLagging(d) || daemonStuck(d)),
  ).length;
  if (fleet?.watchers && watcherStale(fleet.watchers)) n += 1;
  return n;
}
