import React from "react";

import { formatBlockNumber } from "../jobStages.js";
import { RateNote } from "./RateNote.jsx";
import { fmtBacklogRate, fmtBlockRate, humanAge } from "./fleetHealth.js";

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

export function WorkSection({ d, rate }) {
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
