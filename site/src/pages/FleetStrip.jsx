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

// Indexer cursors far behind the leader (≈ head). The signature of one seeded
// at block 0 backfilling the whole chain while the rest track head — invisible
// in max_indexed_block alone, so we treat it as a degraded (warn) state even
// while the daemon beats normally.
function indexerLagging(d) {
  return d.process === "event_log_indexer" && (d.work?.lagging_cursors || 0) > 0;
}

// Resolve a daemon's fine-grained tone. err/mute set the pill class; idle/ok
// keep the default pill but tint the dot. warn (amber) covers a healthy daemon
// with a failed work item, a backfill-lagging indexer, or a stale-but-not-error
// daemon.
export function daemonTone(d) {
  if (d.status === "error") return "err";
  if (!d.last_beat_at || d.status === "unknown") return "mute";
  if (d.stale) return "warn";
  if (indexerLagging(d)) return "warn";
  if (auditHasFailures(d)) return "warn";
  if (d.status === "idle") return "idle";
  return "ok";
}

// Pulse only while genuinely live — err/mute/never-beat dots are static.
function daemonPulse(d) {
  return !!d.alive && (d.status === "running" || d.status === "idle");
}

function pillSub(d, tone) {
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
// a backfill-lagging indexer + stale watchers.
export function countUnhealthy(fleet) {
  const daemons = fleet?.daemons || [];
  let n = daemons.filter((d) => d.status === "error" || d.stale || indexerLagging(d)).length;
  if (fleet?.watchers && watcherStale(fleet.watchers)) n += 1;
  return n;
}

export function FleetStrip({ fleet, selected, onSelectProcess }) {
  const daemons = fleet?.daemons || [];
  const watchers = fleet?.watchers || null;
  const selKey = selected?.type === "process" ? selected.key : null;

  const pills = daemons.map((d) => {
    const tone = daemonTone(d);
    return {
      key: d.process,
      label: PROCESS_PILL_LABEL[d.process] || d.label,
      tone,
      sub: pillSub(d, tone),
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

function alertContent(d) {
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
  // Beating fine, not stale → the remaining alert trigger is indexer backfill lag.
  const w = d.work || {};
  return {
    head: `${w.lagging_cursors} cursor${w.lagging_cursors === 1 ? "" : "s"} far behind head`,
    body: `Earliest cursor at block ${formatBlockNumber(w.min_indexed_block)} vs ${formatBlockNumber(w.max_indexed_block)} (~${formatBlockNumber(w.block_spread)} behind). New cursors backfill from block 0, so a contract's first resolution can run before its authority events are indexed.`,
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

function WorkSection({ d }) {
  if (d.process === "coverage_verify") {
    const byStatus = d.work?.by_equivalence_status || {};
    const segs = eqSegments(byStatus);
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
          <dt>queued rows</dt>
          <dd>{d.work?.total ?? 0}</dd>
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
    return (
      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Work</h3>
        <dl className="job-panel-ops">
          <dt>processing</dt>
          <dd>{w.processing ?? 0}</dd>
          <dt>pending</dt>
          <dd>{w.pending ?? 0}</dd>
          <dt>failed</dt>
          <dd>{w.failed ?? 0}</dd>
        </dl>
      </section>
    );
  }

  if (d.process === "event_log_indexer") {
    const w = d.work || {};
    const spread = w.block_spread;
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

function WatcherDetail({ watchers, onClose }) {
  const w = watchers || {};
  const stale = watcherStale(w);
  const tone = stale ? "warn" : "ok";
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
export function DaemonDetail({ daemonKey, fleet, onClose }) {
  if (daemonKey === "watchers") {
    return <WatcherDetail watchers={fleet?.watchers} onClose={onClose} />;
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

  const tone = daemonTone(d);
  const interval = PROCESS_INTERVAL_S[d.process];
  const window = staleWindowS(d.process);
  const showAlert = d.status === "error" || d.stale || indexerLagging(d);
  const alert = showAlert ? alertContent(d) : null;
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

      <WorkSection d={d} />

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
