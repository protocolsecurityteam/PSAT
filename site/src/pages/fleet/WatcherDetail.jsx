import React from "react";

import { formatBlockNumber } from "../jobStages.js";
import { RateNote } from "./RateNote.jsx";
import { TONE_DOT, fmtBlockRate, humanAge, utcTime, watcherStale } from "./fleetHealth.js";

export function WatcherDetail({ watchers, rate, onClose }) {
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
