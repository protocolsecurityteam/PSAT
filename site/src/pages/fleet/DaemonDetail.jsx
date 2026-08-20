import React from "react";

import { formatBlockNumber } from "../jobStages.js";
import { WatcherDetail } from "./WatcherDetail.jsx";
import { WorkSection } from "./WorkSection.jsx";
import {
  KIND_DESC,
  PROCESS_INTERVAL_S,
  TONE_DOT,
  daemonFallingBehind,
  daemonStuck,
  daemonTone,
  fmtBacklogRate,
  humanAge,
  indexerLagging,
  staleWindowS,
  utcTime,
} from "./fleetHealth.js";

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

function detailSummary(detail) {
  return Object.entries(detail)
    .map(([k, v]) => `${k.replaceAll("_", " ")} ${v}`)
    .join(" · ");
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
