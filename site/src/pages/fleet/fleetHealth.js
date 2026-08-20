// Pure rate/health layer for the fleet strip + daemon detail: pill labels,
// staleness windows, the Option B progress/throughput triad (backlog ·
// oldest-age · rate), tones and unhealthy counting. No React.

import { formatBlockNumber } from "../jobStages.js";

// Short pill labels (the long form lives on fleet.daemons[].label, shown in
// the dock header). Interval is loop cadence — not in the response, mirrored
// here from PROCESS_META so the meta line can show it.
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

// Watchers have no heartbeat; liveness is derived from row freshness. 6h with
// no state-row update reads as stale (the live box was ~3.6d when the indexer
// stopped feeding it).
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

// Indexer cursors far behind the leader (≈ head). A freshly-enrolled cursor
// seeds at its contract's creation block and backfills forward; until it
// catches up, resolution against that authority fails closed (deferred, then
// re-enqueued automatically). max_indexed_block alone hides this, so we treat
// it as a degraded (warn) state even while the daemon beats normally.
export function indexerLagging(d) {
  return d.process === "event_log_indexer" && (d.work?.lagging_cursors || 0) > 0;
}

// ── Option B: uniform progress/throughput triad (backlog · oldest-age · rate) ──

// "oldest item this old AND nothing moved last pass" → stuck. Tuned above the
// drainers' poll/lease cadence so a momentary empty claim doesn't trip it.
const STUCK_AGE_S = 300;
// Backlog growth (items/min) past which a daemon reads as "falling behind".
const FALLING_BEHIND_PER_MIN = 2;
// Hold a computed rate this long with no further change before decaying it to
// null — a stopped worker's last rate shouldn't linger as if still current.
const RATE_DECAY_MS = 5 * 60 * 1000;

// The per-pass throughput count each worker reports into its heartbeat detail.
// Returns undefined when the worker hasn't reported one (pre-deploy / no beat).
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

// Stuck = work waiting (backlog > 0), the oldest item aged past the window, and
// the last pass moved nothing (throughput exactly 0). Either signal alone is
// ambiguous — an idle drainer does 0/pass but has 0 backlog, which is fine — so
// both must hold. Requires an oldest-age, so it only fires for the audit
// workers (coverage has no clean enqueue timestamp to age from).
export function daemonStuck(d) {
  const w = d.work || {};
  return (
    (w.backlog || 0) > 0 &&
    w.oldest_pending_age_s != null &&
    w.oldest_pending_age_s >= STUCK_AGE_S &&
    throughputCount(d) === 0
  );
}

// Falling behind = the backlog grew over the last rate window. A soft warn (it
// tints the pill but isn't counted toward "N unhealthy") since a burst of new
// work legitimately grows the queue before the drainer catches up.
export function daemonFallingBehind(rate) {
  return rate?.backlogPerMin != null && rate.backlogPerMin >= FALLING_BEHIND_PER_MIN;
}

function parseIsoMs(iso) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : null;
}

// Rate of change (per minute) for one tracked counter, anchored at the last
// value CHANGE rather than the previous poll. Between changes we hold the last
// computed rate, so a slow-tick worker (the indexer advances cursors only every
// ~90s) reports a stable per-minute figure instead of the 0/spike sawtooth that
// diffing 2.5s polls would produce. Decays to null after RATE_DECAY_MS of no
// movement. Mutates ``anchors`` (page-owned useRef payload) so it persists.
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

// Update per-process rate anchors from a fresh /api/fleet snapshot and return
// the rate map keyed by process (+ "watchers"). Diff time comes from the
// server's own ``now`` so client-clock skew can't distort it; first poll (no
// anchor) and missed polls (wider Δt) both fall out naturally.
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

// "+N/min" backlog growth / "−N/min" drain. Null at ~0 so a flat queue doesn't
// clutter the UI.
export function fmtBacklogRate(perMin) {
  if (perMin == null || !Number.isFinite(perMin)) return null;
  const r = Math.round(perMin);
  if (r === 0) return null;
  return `${r > 0 ? "+" : "−"}${Math.abs(r)}/min`;
}

// "+12.3K blocks/min" progress (negative = a reorg rewind).
export function fmtBlockRate(perMin) {
  if (perMin == null || !Number.isFinite(perMin)) return null;
  const r = Math.round(perMin);
  if (r === 0) return null;
  return `${r > 0 ? "+" : "−"}${formatBlockNumber(Math.abs(r))} blocks/min`;
}

// Resolve a daemon's fine-grained tone. err/mute set the pill class; idle/ok
// keep the default pill but tint the dot. warn (amber) covers a healthy daemon
// with a failed work item, a backfill-lagging indexer, a stuck or
// falling-behind queue, or a stale-but-not-error daemon.
export function daemonTone(d, rate) {
  if (d.status === "error") return "err";
  if (!d.last_beat_at || d.status === "unknown") return "mute";
  if (d.stale) return "warn";
  if (indexerLagging(d)) return "warn";
  if (daemonStuck(d)) return "warn";
  if (daemonFallingBehind(rate)) return "warn";
  if (auditHasFailures(d)) return "warn";
  if (d.status === "idle") return "idle";
  return "ok";
}

// Pulse only while genuinely live — err/mute/never-beat dots are static.
export function daemonPulse(d) {
  return !!d.alive && (d.status === "running" || d.status === "idle");
}

export function pillSub(d, tone, rate) {
  // The two Option B health signals win the (tiny) pill sub when they fire.
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

// "⚠ N unhealthy" = err + stale daemons (stale already covers never-beat) +
// a backfill-lagging indexer + a stuck drainer + stale watchers. Stuck is a
// stable, non-flapping signal (old age + 0 throughput), so it belongs in the
// count; falling-behind is a transient trend and is intentionally left out.
export function countUnhealthy(fleet) {
  const daemons = fleet?.daemons || [];
  let n = daemons.filter(
    (d) => d.status === "error" || d.stale || indexerLagging(d) || daemonStuck(d),
  ).length;
  if (fleet?.watchers && watcherStale(fleet.watchers)) n += 1;
  return n;
}
