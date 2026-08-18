import React from "react";

import { formatBlockNumber } from "./jobStages.js";

// Fleet system-health strip + the docked daemon/watcher detail. Drives the
// "all background processes" view of the monitor page from /api/fleet:
// heartbeat-backed daemons (coverage-verify, audit text/scope extraction,
// event-log indexer, enrollment reconciler) plus the derived-liveness
// runtime watchers. Health states (running/idle/error/unknown/stale) all
// render; selecting a pill fills the dock with that process's detail.

// Short pill labels (the long form lives on fleet.daemons[].label, shown in
// the dock header). Interval is loop cadence — not in the response, mirrored
// here from PROCESS_META so the meta line can show it.
const PROCESS_PILL_LABEL = {
  coverage_verify: "Coverage verify",
  audit_text_extraction: "Audit text",
  audit_scope_extraction: "Audit scope",
  event_log_indexer: "Event indexer",
  enrollment_reconciler: "Reconciler",
};
const PROCESS_INTERVAL_S = {
  coverage_verify: 30,
  audit_text_extraction: 30,
  audit_scope_extraction: 30,
  event_log_indexer: 90,
  enrollment_reconciler: 660,
};
const KIND_DESC = { drainer: "row-draining daemon", indexer: "row-draining daemon", daemon: "background daemon" };
const TONE_DOT = { ok: "#22c55e", idle: "#7dd3fc", warn: "#f59e0b", err: "#f87171", mute: "#64748b" };

// Watchers have no heartbeat; liveness is derived from row freshness. 6h with
// no state-row update reads as stale (the live box was ~3.6d when the indexer
// stopped feeding it).
const WATCHER_STALE_S = 6 * 3600;

function staleWindowS(process) {
  const iv = PROCESS_INTERVAL_S[process] || 40;
  return Math.max(3 * iv, 120);
}

function humanAge(s) {
  if (s == null) return "—";
  const n = Number(s);
  if (!Number.isFinite(n)) return "—";
  if (n < 60) return `${Math.round(n)}s`;
  if (n < 3600) return `${Math.round(n / 60)}m`;
  if (n < 86400) return `${(n / 3600).toFixed(1)}h`;
  return `${(n / 86400).toFixed(1)}d`;
}

function utcTime(iso) {
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
function indexerLagging(d) {
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
function daemonStuck(d) {
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
function daemonFallingBehind(rate) {
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
function fmtBacklogRate(perMin) {
  if (perMin == null || !Number.isFinite(perMin)) return null;
  const r = Math.round(perMin);
  if (r === 0) return null;
  return `${r > 0 ? "+" : "−"}${Math.abs(r)}/min`;
}

// "+12.3K blocks/min" progress (negative = a reorg rewind).
function fmtBlockRate(perMin) {
  if (perMin == null || !Number.isFinite(perMin)) return null;
  const r = Math.round(perMin);
  if (r === 0) return null;
  return `${r > 0 ? "+" : "−"}${formatBlockNumber(Math.abs(r))} blocks/min`;
}

// Rate annotation next to a metric. ``good`` paints it green (healthy
// direction) vs amber (concerning).
function RateNote({ text, good }) {
  if (!text) return null;
  return (
    <span className="dmn-rate" style={{ color: good ? "#34d399" : "#fbbf24" }}>
      {text}
    </span>
  );
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
function daemonPulse(d) {
  return !!d.alive && (d.status === "running" || d.status === "idle");
}

function pillSub(d, tone, rate) {
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

function watcherStale(w) {
  if (!w) return true;
  const age = w.last_update_age_s;
  return age == null || age > WATCHER_STALE_S;
}

function watcherSub(w) {
  if (!w) return "no data";
  if (watcherStale(w)) return w.last_update_age_s == null ? "no data" : `${humanAge(w.last_update_age_s)} stale`;
  return `${w.monitored_contracts ?? 0} watched`;
}

// "⚠ N unhealthy" = err + stale daemons (stale already covers never-beat) +
// a backfill-lagging indexer + a stuck drainer + stale watchers. Stuck is a
// stable, non-flapping signal (old age + 0 throughput), so it belongs in the
// count; falling-behind is a transient trend and is intentionally left out.
function countUnhealthy(fleet) {
  const daemons = fleet?.daemons || [];
  let n = daemons.filter(
    (d) => d.status === "error" || d.stale || indexerLagging(d) || daemonStuck(d),
  ).length;
  if (fleet?.watchers && watcherStale(fleet.watchers)) n += 1;
  return n;
}

export function FleetStrip({ fleet, selected, onSelectProcess, rates }) {
  const daemons = fleet?.daemons || [];
  const watchers = fleet?.watchers || null;
  const selKey = selected?.type === "process" ? selected.key : null;

  const pills = daemons.map((d) => {
    const rate = rates?.[d.process];
    const tone = daemonTone(d, rate);
    return {
      key: d.process,
      label: PROCESS_PILL_LABEL[d.process] || d.label,
      tone,
      sub: pillSub(d, tone, rate),
      pulse: daemonPulse(d),
    };
  });
  if (watchers) {
    const wTone = watcherStale(watchers) ? "warn" : "ok";
    pills.push({ key: "watchers", label: "Watchers", tone: wTone, sub: watcherSub(watchers), pulse: false });
  }

  const unhealthy = countUnhealthy(fleet);

  return (
    <div className="sys-strip">
      <span className="sys-label">Fleet</span>
      {pills.map((p) => {
        const pillCls = p.tone === "err" ? "err" : p.tone === "warn" ? "warn" : "";
        return (
          <button
            key={p.key}
            type="button"
            className={`sys-pill ${pillCls}${selKey === p.key ? " sel" : ""}`.replace(/\s+/g, " ").trim()}
            onClick={() => onSelectProcess(p.key)}
            aria-pressed={selKey === p.key}
          >
            <span className={`d${p.pulse ? " pulse" : ""}`} style={{ background: TONE_DOT[p.tone] }} />
            {p.label}
            <span className="sub">{p.sub}</span>
          </button>
        );
      })}
      {pills.length > 0 && (
        unhealthy > 0 ? (
          <span className="sys-summary" style={{ color: "#f87171" }}>⚠ {unhealthy} unhealthy</span>
        ) : (
          <span className="sys-summary" style={{ color: "#22c55e" }}>✓ all healthy</span>
        )
      )}
    </div>
  );
}

function alertContent(d, rate) {
  if (d.status === "error") {
    if (d.process === "event_log_indexer") {
      return {
        head: `Erroring — ${humanAge(d.work?.stalest_run_age_s)} since last successful run`,
        body: "No new blocks indexed; the runtime watchers downstream are starving for events.",
      };
    }
    return { head: `${d.label} is erroring`, body: "The process reported an error on its last pass." };
  }
  if (!d.last_beat_at) {
    return { head: "No heartbeat recorded", body: "Process may be down — it has never reported a beat." };
  }
  if (d.stale) {
    return {
      head: `Stale — last beat ${humanAge(d.beat_age_s)} ago`,
      body: `Expected a heartbeat within the ${staleWindowS(d.process)}s window.`,
    };
  }
  if (indexerLagging(d)) {
    const w = d.work || {};
    return {
      head: `${w.lagging_cursors} cursor${w.lagging_cursors === 1 ? "" : "s"} far behind head`,
      body: `Worst same-chain gap ~${formatBlockNumber(w.block_spread)} blocks between a chain's slowest and leading cursor. These cursors are still backfilling from their contract's creation block; resolution against them fails closed and is deferred until backfill completes, then re-enqueued automatically.`,
    };
  }
  if (daemonStuck(d)) {
    const w = d.work || {};
    return {
      head: `Stuck — oldest item waiting ${humanAge(w.oldest_pending_age_s)}`,
      body: `${w.backlog} item${w.backlog === 1 ? "" : "s"} queued but the last pass processed none. The drainer is alive but not advancing — check for un-claimable rows or a stalled dependency.`,
    };
  }
  // Remaining trigger: a growing backlog (falling behind).
  const w = d.work || {};
  return {
    head: `Backlog growing — ${fmtBacklogRate(rate?.backlogPerMin) || "rising"}`,
    body: `${w.backlog ?? 0} item${(w.backlog ?? 0) === 1 ? "" : "s"} queued and rising — throughput isn't keeping up with incoming work.`,
  };
}

const EQ_LABELS = { hash_mismatch: "mismatch", commit_not_found: "commit not found", proven: "proven" };
const EQ_COLORS = { hash_mismatch: "#ef4444", commit_not_found: "#f59e0b", proven: "#22c55e" };

function eqSegments(byStatus) {
  const keys = Object.keys(byStatus || {});
  const others = keys.filter((k) => !["hash_mismatch", "commit_not_found", "proven"].includes(k));
  const ordered = ["hash_mismatch", "commit_not_found", ...others, "proven"].filter((k) => byStatus[k]);
  const total = ordered.reduce((a, k) => a + byStatus[k], 0) || 1;
  return ordered.map((k) => ({
    key: k,
    label: EQ_LABELS[k] || k.replaceAll("_", " "),
    count: byStatus[k],
    pct: (byStatus[k] / total) * 100,
    color: EQ_COLORS[k] || "#64748b",
  }));
}

function WorkSection({ d, rate }) {
  if (d.process === "coverage_verify") {
    const w = d.work || {};
    const byStatus = w.by_equivalence_status || {};
    const segs = eqSegments(byStatus);
    const backlogRate = fmtBacklogRate(rate?.backlogPerMin);
    return (
      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Work</h3>
        {segs.length > 0 && (
          <>
            <div className="fleet-bar">
              {segs.map((s) => (
                <i key={s.key} style={{ background: s.color, width: `${s.pct}%` }} />
              ))}
            </div>
            <div className="fleet-legend">
              {segs.map((s) => (
                <span key={s.key}>
                  <i style={{ background: s.color }} />
                  {s.label} {s.count}
                </span>
              ))}
            </div>
          </>
        )}
        <dl className="job-panel-ops">
          <dt>backlog</dt>
          <dd>
            {w.backlog ?? 0}
            <RateNote text={backlogRate} good={(rate?.backlogPerMin ?? 0) <= 0} />
          </dd>
          <dt>queued rows</dt>
          <dd>{w.total ?? 0}</dd>
          {segs.map((s) => (
            <React.Fragment key={s.key}>
              <dt>{s.label}</dt>
              <dd>{s.count}</dd>
            </React.Fragment>
          ))}
        </dl>
      </section>
    );
  }

  if (d.process === "audit_text_extraction" || d.process === "audit_scope_extraction") {
    const w = d.work || {};
    const backlogRate = fmtBacklogRate(rate?.backlogPerMin);
    return (
      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Work</h3>
        <dl className="job-panel-ops">
          <dt>processing</dt>
          <dd>{w.processing ?? 0}</dd>
          <dt>backlog</dt>
          <dd>
            {w.backlog ?? 0}
            <RateNote text={backlogRate} good={(rate?.backlogPerMin ?? 0) <= 0} />
          </dd>
          <dt>oldest waiting</dt>
          <dd>{humanAge(w.oldest_pending_age_s)}</dd>
          <dt>failed</dt>
          <dd>{w.failed ?? 0}</dd>
        </dl>
      </section>
    );
  }

  if (d.process === "event_log_indexer") {
    const w = d.work || {};
    const spread = w.block_spread;
    const blockRate = fmtBlockRate(rate?.blocksPerMin);
    return (
      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Work</h3>
        <dl className="job-panel-ops">
          <dt>cursors</dt>
          <dd>{w.cursors ?? 0}</dd>
          <dt>indexed block</dt>
          <dd>
            {w.min_indexed_block != null
              ? `${formatBlockNumber(w.min_indexed_block)} → ${formatBlockNumber(w.max_indexed_block)}`
              : w.max_indexed_block != null
              ? formatBlockNumber(w.max_indexed_block)
              : "—"}
          </dd>
          {blockRate && (
            <>
              <dt>indexing rate</dt>
              <dd>
                <RateNote text={blockRate} good={(rate?.blocksPerMin ?? 0) >= 0} />
              </dd>
            </>
          )}
          {spread != null && spread > 0 && (
            <>
              <dt>blocks behind</dt>
              <dd>{formatBlockNumber(spread)}</dd>
            </>
          )}
          {(w.lagging_cursors || 0) > 0 && (
            <>
              <dt>lagging cursors</dt>
              <dd>{w.lagging_cursors}</dd>
            </>
          )}
          <dt>stalest run age</dt>
          <dd>{humanAge(w.stalest_run_age_s)}</dd>
        </dl>
      </section>
    );
  }

  // enrollment_reconciler (work=null): liveness only.
  return (
    <section className="job-panel-section">
      <h3 className="job-panel-section-title">Work</h3>
      <p className="job-panel-empty">No work table — liveness only.</p>
    </section>
  );
}

function detailSummary(detail) {
  return Object.entries(detail)
    .map(([k, v]) => `${k.replaceAll("_", " ")} ${v}`)
    .join(" · ");
}

function WatcherDetail({ watchers, rate, onClose }) {
  const w = watchers || {};
  const stale = watcherStale(w);
  const tone = stale ? "warn" : "ok";
  const scanRate = fmtBlockRate(rate?.blocksPerMin);
  return (
    <>
      <header className="job-panel-header">
        <div className="job-panel-title">
          <span className="job-panel-name">Watchers</span>
          <span className="dmn-kind">runtime monitors · derived liveness</span>
        </div>
        <button type="button" className="job-panel-close" onClick={onClose} aria-label="Close panel">×</button>
      </header>
      <div className="job-panel-meta">
        <span className="job-panel-tag" style={{ color: TONE_DOT[tone], borderColor: `${TONE_DOT[tone]}66` }}>
          {stale ? "stale" : "active"}
        </span>
        <span className="job-panel-tag job-panel-next">state {humanAge(w.last_update_age_s)} ago</span>
        <span className="job-panel-tag job-panel-next">tvl {humanAge(w.tvl_last_snapshot_age_s)} ago</span>
      </div>
      {stale && (
        <section className="job-panel-section">
          <h3 className="job-panel-section-title">Status</h3>
          <div className="dmn-alert warn">
            <b>Watchers stale</b>
            <span>No row updates in {humanAge(w.last_update_age_s)} — downstream monitoring may be lagging.</span>
          </div>
        </section>
      )}
      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Work</h3>
        <dl className="job-panel-ops">
          <dt>monitored</dt>
          <dd>{w.monitored_contracts ?? 0}</dd>
          <dt>active</dt>
          <dd>{w.active ?? 0}</dd>
          {w.min_scanned_block != null && (
            <>
              <dt>scanned block</dt>
              <dd>{formatBlockNumber(w.min_scanned_block)} → {formatBlockNumber(w.max_scanned_block)}</dd>
            </>
          )}
          {scanRate && (
            <>
              <dt>scan rate</dt>
              <dd>
                <RateNote text={scanRate} good={(rate?.blocksPerMin ?? 0) >= 0} />
              </dd>
            </>
          )}
          {w.scan_block_spread != null && w.scan_block_spread > 0 && (
            <>
              <dt>blocks behind</dt>
              <dd>{formatBlockNumber(w.scan_block_spread)}</dd>
            </>
          )}
          <dt>state updated</dt>
          <dd>{w.last_update_at ? `${utcTime(w.last_update_at)} · ${humanAge(w.last_update_age_s)} ago` : "—"}</dd>
          <dt>tvl snapshot</dt>
          <dd>{w.tvl_last_snapshot_at ? `${utcTime(w.tvl_last_snapshot_at)} · ${humanAge(w.tvl_last_snapshot_age_s)} ago` : "—"}</dd>
        </dl>
      </section>
    </>
  );
}

// The docked detail for a fleet process. `daemonKey` is a daemon `process`
// value or the synthetic "watchers". Reads the latest /api/fleet snapshot —
// no extra fetch (the page polls fleet for everyone).
export function DaemonDetail({ daemonKey, fleet, onClose, rates }) {
  if (daemonKey === "watchers") {
    return <WatcherDetail watchers={fleet?.watchers} rate={rates?.watchers} onClose={onClose} />;
  }
  const d = (fleet?.daemons || []).find((x) => x.process === daemonKey);
  if (!d) {
    return (
      <div className="dock-empty">
        <div className="de-icon">⊘</div>
        <b>Process unavailable</b>
        <span>No fleet data for this process in the latest poll.</span>
      </div>
    );
  }

  const rate = rates?.[d.process];
  const tone = daemonTone(d, rate);
  const interval = PROCESS_INTERVAL_S[d.process];
  const window = staleWindowS(d.process);
  const showAlert = d.status === "error" || d.stale || indexerLagging(d) || daemonStuck(d) || daemonFallingBehind(rate);
  const alert = showAlert ? alertContent(d, rate) : null;
  const alertCls = d.status === "error" ? "err" : "warn";

  return (
    <>
      <header className="job-panel-header">
        <div className="job-panel-title">
          <span className="job-panel-name">{d.label}</span>
          <span className="dmn-kind">{d.kind} · {KIND_DESC[d.kind] || "daemon"}</span>
        </div>
        <button type="button" className="job-panel-close" onClick={onClose} aria-label="Close panel">×</button>
      </header>

      <div className="job-panel-meta">
        <span className="job-panel-tag" style={{ color: TONE_DOT[tone], borderColor: `${TONE_DOT[tone]}66` }}>
          {d.status}
        </span>
        <span className="job-panel-tag job-panel-next">
          last beat {d.last_beat_at ? `${humanAge(d.beat_age_s)} ago` : "never"}
        </span>
        {interval && <span className="job-panel-tag job-panel-next">interval {interval}s</span>}
      </div>

      {alert && (
        <section className="job-panel-section">
          <h3 className="job-panel-section-title">Status</h3>
          <div className={`dmn-alert ${alertCls}`}>
            <b>{alert.head}</b>
            <span>{alert.body}</span>
          </div>
        </section>
      )}

      <WorkSection d={d} rate={rate} />

      {d.detail && Object.keys(d.detail).length > 0 && (
        <section className="job-panel-section">
          <h3 className="job-panel-section-title">Last pass</h3>
          <p className={`jp-detail ${tone === "err" || tone === "warn" ? "run" : "info"}`}>
            <span className="lbl">detail</span>
            {detailSummary(d.detail)}
          </p>
        </section>
      )}

      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Operational</h3>
        <dl className="job-panel-ops">
          <dt>process</dt>
          <dd>{d.process}</dd>
          <dt>last beat at</dt>
          <dd>{d.last_beat_at ? utcTime(d.last_beat_at) : "never"}</dd>
          <dt>stale</dt>
          <dd>
            {String(d.stale)}
            {d.last_beat_at ? ` (${humanAge(d.beat_age_s)} ${d.stale ? "≥" : "<"} ${window}s window)` : ""}
          </dd>
        </dl>
      </section>
    </>
  );
}
