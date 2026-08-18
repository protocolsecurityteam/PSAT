import React, { useEffect, useMemo, useState } from "react";

import { api } from "../api/client.js";
import { shortenAddress } from "../graph.js";
import {
  CORE_STAGES,
  JOB_STAGE_ORDER,
  STAGE_COLORS,
  STATUS_COLORS,
  coreIndexForStage,
  formatStageLabel,
  formatMetricValue,
  humanizeMetricLabel,
  orderedMetricEntries,
} from "./jobStages.js";

// Grafana Cloud instance. The worker fleet writes structured JSON logs that
// include `"trace_id":"<hex>"` inside the log line — trace_id is *not* a
// stream label, so the deeplink filters via `|=` on the line and scopes the
// stream via fly_app_name (prod = "psat", preview = "psat-pr-<N>"). Without
// the env scope Loki would scan every PR preview's logs for every lookup.
const GRAFANA_LOGS_BASE = "https://protocolsectool.grafana.net";

// Grafana Cloud free-tier Loki retention. Probed 2026-05-21: data present
// at day-13, gone by day-16. Clamping the deeplink range to this floor
// avoids scanning a window where nothing can ever exist.
const LOKI_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;
// 1h padding around the job span so a log line written a few minutes before
// the job row was created (e.g. submission queueing) or after it landed in a
// terminal state still falls inside the window.
const LOKI_RANGE_BUFFER_MS = 60 * 60 * 1000;

// Map a browser hostname back to the Fly app that produced the page.
//   psat.fly.dev         → "psat"          (prod)
//   psat-pr-90.fly.dev   → "psat-pr-90"    (preview)
//   anything else        → null            (fall back to wildcard query)
export function inferFlyApp(hostname) {
  if (!hostname) return null;
  const m = hostname.match(/^(psat(?:-pr-\d+)?)\.fly\.dev$/);
  return m ? m[1] : null;
}

function parseIsoMs(value) {
  if (!value) return null;
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? t : null;
}

export function buildLogsDeeplink(traceId, opts = {}) {
  if (!traceId) return null;
  const hostname = opts.hostname ?? (typeof window !== "undefined" ? window.location.hostname : null);
  const flyApp = inferFlyApp(hostname);
  // Tight selector when we know the env; broad wildcard otherwise. Both
  // resolve to the same trace because trace_id is a substring filter on
  // the line, but the scoped variant is dramatically cheaper for Loki.
  const selector = flyApp ? `{fly_app_name="${flyApp}"}` : `{service_name=~".+"}`;

  // Derive the time range from the job span when caller provides it, so
  // an old terminal failure still produces a useful Explore link (the
  // hardcoded now-24h missed anything older than a day even though Loki
  // holds ~14 days). Clamp to the retention floor either way.
  const now = opts.now ?? Date.now();
  const createdMs = parseIsoMs(opts.createdAt);
  const updatedMs = parseIsoMs(opts.updatedAt);
  const retentionFloor = now - LOKI_RETENTION_MS;
  let fromMs = createdMs != null ? Math.max(createdMs - LOKI_RANGE_BUFFER_MS, retentionFloor) : retentionFloor;
  let toMs = updatedMs != null ? Math.min(updatedMs + LOKI_RANGE_BUFFER_MS, now) : now;
  // Defensive: clock skew / bad timestamps could invert the range.
  if (fromMs >= toMs) {
    fromMs = retentionFloor;
    toMs = now;
  }

  const left = {
    datasource: "grafanacloud-logs",
    queries: [{ refId: "A", expr: `${selector} |= "${traceId}"` }],
    range: { from: String(fromMs), to: String(toMs) },
  };
  return `${GRAFANA_LOGS_BASE}/explore?left=${encodeURIComponent(JSON.stringify(left))}`;
}

function formatSeconds(s) {
  if (s == null) return "—";
  const n = Number(s);
  if (!Number.isFinite(n)) return "—";
  if (n < 60) return `${n.toFixed(n < 10 ? 2 : 1)}s`;
  const m = Math.floor(n / 60);
  const r = Math.round(n % 60);
  if (m < 60) return `${m}m ${r}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

// A stage's duration in seconds: the recorded elapsed_s, else derived from the
// started_at→ended_at span (so a bar still renders from real timestamps if
// elapsed_s is ever absent). null when there's no timing to draw from.
function stageElapsed(blob) {
  if (!blob) return null;
  const e = Number(blob.elapsed_s);
  if (Number.isFinite(e)) return e;
  const start = parseIsoMs(blob.started_at);
  const end = parseIsoMs(blob.ended_at);
  if (start != null && end != null && end >= start) return (end - start) / 1000;
  return null;
}

function formatTime(iso) {
  if (!iso) return "—";
  try {
    // UTC HH:MM:SS — the worker fleet logs in UTC and the Logs↗ deeplink is
    // UTC, so the panel's timestamps line up with what you'll see in Grafana
    // (and it's deterministic across operator timezones).
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return iso;
  }
}

// Split a live `detail` message ("Slither running · 14 deps · 3 discovered")
// into chip-sized segments for the in-progress stage. Heuristic by nature —
// the authoritative live message is the Live-progress block above.
function liveChips(detail) {
  if (!detail) return [];
  return detail
    .split(/\s*[·;]\s*/)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => s.length <= 28)
    .slice(0, 5);
}

// One stage row in the timeline. `kind` is the resolved presentation state;
// `blob` is the server timing artifact (null for synthesized running/pending
// rows). Widths are proportional to elapsed_s / max across recorded stages.
function StageRow({ stage, kind, blob, maxElapsed, job }) {
  const color = STAGE_COLORS[stage] || "#cbd5e1";

  if (kind === "pending" || kind === "notreached") {
    return (
      <div className="jp-stage pending">
        <div className="jp-stage-head">
          <span className="jp-stage-name" style={{ color }}>{formatStageLabel(stage)}</span>
          <span className="jp-badge pend">{kind === "notreached" ? "NOT REACHED" : "PENDING"}</span>
          <span className="jp-time pend">—</span>
        </div>
      </div>
    );
  }

  const elapsed = stageElapsed(blob);
  const hasElapsed = Number.isFinite(elapsed);
  const badge =
    kind === "running" ? { cls: "run", text: "● RUNNING" }
    : kind === "failed" ? { cls: "fail", text: "● FAILED" }
    : { cls: "ok", text: "SUCCESS" };
  const timeCls = kind === "running" ? "run" : kind === "failed" ? "fail" : "";
  const timeText = kind === "running"
    ? formatSeconds((Date.now() - parseIsoMs(job.created_at)) / 1000 || 0)
    : formatSeconds(elapsed); // "—" when there's no recorded timing

  // Bar: proportional for a recorded stage, striped for the live one. A stage
  // we know ran but have no artifact for (synthesized) gets no bar — faking a
  // width would misrepresent a duration we don't have.
  let bar = null;
  if (kind === "running") {
    bar = <div className="jp-barwrap"><i className="run" style={{ width: "64%" }} /></div>;
  } else if (hasElapsed) {
    const pct = maxElapsed > 0 ? Math.max(2, (elapsed / maxElapsed) * 100) : 2;
    bar = <div className="jp-barwrap"><i style={{ width: `${pct}%`, background: kind === "failed" ? "#ef4444" : color }} /></div>;
  }

  // Provenance sub-line. With an artifact: worker + the time span. Synthesized
  // from job state (no artifact): say so, so a missing duration doesn't read
  // as instantaneous.
  let sub;
  if (kind === "running") {
    sub = `${job.worker_id || "worker —"} · live`;
  } else if (blob) {
    const worker = blob.worker_id || "—";
    sub = kind === "failed"
      ? `${worker} · ${formatTime(blob.started_at)} · failed`
      : `${worker} · ${formatTime(blob.started_at)} → ${formatTime(blob.ended_at)}`;
  } else {
    sub = kind === "failed" ? "failed · no timing recorded" : "no timing recorded";
  }

  return (
    <div className="jp-stage">
      <div className="jp-stage-head">
        <span className="jp-stage-name" style={{ color }}>{formatStageLabel(stage)}</span>
        <span className={`jp-badge ${badge.cls}`}>{badge.text}</span>
        <span className={`jp-time ${timeCls}`.trim()}>{timeText}</span>
      </div>
      {bar}
      {kind === "running" && liveChips(job.detail).length > 0 && (
        <div className="jp-metrics">
          {liveChips(job.detail).map((seg, i) => (
            <span key={i} className="jp-metric live">{seg}</span>
          ))}
        </div>
      )}
      {kind === "success" && blob && orderedMetricEntries(blob.metrics).length > 0 && (
        <div className="jp-metrics">
          {orderedMetricEntries(blob.metrics).map(([k, v]) => (
            <span key={k} className="jp-metric">
              {humanizeMetricLabel(k)} <b>{formatMetricValue(k, v)}</b>
            </span>
          ))}
        </div>
      )}
      <div className="jp-sub">{sub}</div>
    </div>
  );
}

// The docked drill-in for a job. Renders the panel *content* (header → meta →
// sections → retry footer) directly into the page's `.dock` container; the
// dock + responsive backdrop are owned by the page so the same component
// serves both the wide docked layout and the <900px overlay drawer.
export function JobDetail({ job, onClose, refreshTick, now = Date.now() }) {
  const jobId = job?.job_id || null;
  const [errors, setErrors] = useState(null);
  const [stageTimings, setStageTimings] = useState(null);
  // Track an unrecoverable failure (e.g. 401 with no admin key) so we stop
  // refetching that endpoint on every refreshTick. The panel still shows
  // everything else; the affected section degrades to a message.
  const [stageTimingsErrored, setStageTimingsErrored] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [retryError, setRetryError] = useState(null);
  const [expandedIdx, setExpandedIdx] = useState(null);
  const [copyOk, setCopyOk] = useState(false);

  // Reset internal state when the selected job changes — otherwise the panel
  // would flash the previous job's data before the new fetch resolves.
  useEffect(() => {
    setErrors(null);
    setStageTimings(null);
    setStageTimingsErrored(false);
    setRetrying(false);
    setRetryError(null);
    setExpandedIdx(null);
  }, [jobId]);

  // Lazy load + refresh on each parent tick while open. The /errors endpoint
  // is public; /stage_timings is admin-protected and uses silent:true so a
  // missing key doesn't spam the prompt on every poll.
  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    api(`/api/jobs/${encodeURIComponent(jobId)}/errors`)
      .then((data) => { if (!cancelled) setErrors(data); })
      .catch(() => { if (!cancelled) setErrors({ errors: [] }); });
    if (!stageTimingsErrored) {
      api(`/api/jobs/${encodeURIComponent(jobId)}/stage_timings`, { silent: true })
        .then((data) => { if (!cancelled) setStageTimings(data); })
        .catch(() => { if (!cancelled) setStageTimingsErrored(true); });
    }
    return () => { cancelled = true; };
  }, [jobId, refreshTick, stageTimingsErrored]);

  // Build the stage timeline in pipeline order. A recorded timing renders from
  // its artifact. For everything else we synthesize from the job's position in
  // the pipeline: a CORE stage the job advanced *past* (or any CORE stage of a
  // completed job) is shown as a completed row even with no artifact — so a
  // job that failed at `static`, or one that predates the stage-metrics
  // feature, still shows the full path (discovery/selection done → static
  // failed → rest not reached) instead of collapsing to a single row.
  const timelineRows = useMemo(() => {
    const timings = stageTimings?.stage_timings || {};
    const curIdx = coreIndexForStage(job?.stage);
    const isRunning = job?.status === "processing" || job?.status === "queued";
    const isFailed = job?.status === "failed" || job?.status === "failed_terminal";
    const isCompleted = job?.status === "completed";
    const rows = [];
    for (const stage of JOB_STAGE_ORDER) {
      if (stage === "done") continue;
      const blob = timings[stage] || null;
      const coreIdx = CORE_STAGES.indexOf(stage);
      // `effects` is a flag-gated optional CORE stage: render it presence-based
      // (a server timing, or the job sitting on it right now) so a flag-off or
      // historical job that never entered the stage doesn't synthesize an
      // eternal NOT-REACHED / completed row. Same spirit as the company-child
      // `coreIdx === -1` skip below, but for an optional (not off-path) stage.
      if (stage === "effects" && !blob && stage !== job.stage) continue;
      let kind;
      if (blob) {
        const st = String(blob.status || "success").toLowerCase();
        kind = st === "failed" || st === "error" ? "failed" : "success";
      } else if (coreIdx === -1) {
        // dapp_crawl / defillama_scan are company-discovery children off the
        // per-contract CORE path — only show them when they have a timing.
        continue;
      } else if (stage === job.stage) {
        kind = isFailed ? "failed" : isRunning ? "running" : "success";
      } else if (isCompleted || coreIdx < curIdx) {
        kind = "success";
      } else if (isFailed) {
        kind = "notreached";
      } else {
        kind = "pending";
      }
      rows.push({ stage, kind, blob });
    }
    return rows;
  }, [stageTimings, job?.stage, job?.status]);

  const maxElapsed = useMemo(() => {
    const vals = timelineRows
      .map((r) => stageElapsed(r.blob))
      .filter((n) => Number.isFinite(n) && n > 0);
    return vals.length ? Math.max(...vals) : 1;
  }, [timelineRows]);

  const totalElapsed = useMemo(() => {
    return timelineRows.reduce((sum, r) => {
      const n = stageElapsed(r.blob);
      return Number.isFinite(n) ? sum + n : sum;
    }, 0);
  }, [timelineRows]);

  const recordedCount = useMemo(
    () => timelineRows.filter((r) => r.blob).length,
    [timelineRows],
  );

  // The list-row worker_id is null once a job completes; the live source of
  // truth is the most recent stage's worker.
  const opWorker = useMemo(() => {
    for (let i = timelineRows.length - 1; i >= 0; i--) {
      if (timelineRows[i].blob?.worker_id) return timelineRows[i].blob.worker_id;
    }
    return job?.worker_id || null;
  }, [timelineRows, job?.worker_id]);

  if (!job) return null;

  const label = job.name || job.company || (job.address ? shortenAddress(job.address) : job.job_id);
  const statusKey = job.status;
  const isTerminal = statusKey === "failed_terminal";
  const isFailed = statusKey === "failed";
  const isProcessing = statusKey === "processing";
  const isCompleted = statusKey === "completed";
  const statusLabel = isTerminal ? "FAILED (TERMINAL)" : isFailed ? "FAILED" : statusKey;

  const stageColor = STAGE_COLORS[job.stage] || "#94a3b8";
  const statusColor = STATUS_COLORS[statusKey] || "#94a3b8";

  const traceId = job.trace_id || errors?.trace_id || null;
  const logsHref = buildLogsDeeplink(traceId, { createdAt: job.created_at, updatedAt: job.updated_at });
  const showLiveDetail = !!job.detail && !isFailed && !isTerminal;

  async function handleRetry() {
    setRetrying(true);
    setRetryError(null);
    try {
      await api(`/api/jobs/${encodeURIComponent(jobId)}/retry`, { method: "POST" });
      // The parent's next poll tick will pick up the queued status and the
      // panel re-renders automatically once allJobs updates.
    } catch (err) {
      setRetryError(err?.message || String(err));
    } finally {
      setRetrying(false);
    }
  }

  async function copyTrace() {
    if (!traceId) return;
    try {
      await navigator.clipboard.writeText(traceId);
      setCopyOk(true);
      setTimeout(() => setCopyOk(false), 1200);
    } catch {
      // Clipboard API unavailable (insecure context, denied permission). The
      // trace_id is still visible in the panel; admins can select it manually.
    }
  }

  return (
    <>
      <header className="job-panel-header">
        <div className="job-panel-title">
          <span className="job-panel-name">{label}</span>
          {job.address && (
            <span className="job-panel-address" title={job.address}>{shortenAddress(job.address)}</span>
          )}
        </div>
        <button type="button" className="job-panel-close" onClick={onClose} aria-label="Close panel">×</button>
      </header>

      <div className="job-panel-meta">
        <span className="job-panel-tag" style={{ color: stageColor, borderColor: `${stageColor}55` }}>
          {formatStageLabel(job.stage)}
        </span>
        <span
          className={`job-panel-tag job-panel-status${isTerminal ? " terminal" : ""}`}
          style={{ color: isTerminal ? "#fca5a5" : statusColor, borderColor: isTerminal ? "#b91c1c88" : `${statusColor}66` }}
        >
          {statusLabel}
        </span>
        {isCompleted && (
          <span className="job-panel-tag job-panel-next">
            {recordedCount > 0
              ? `total ${totalElapsed.toFixed(1)}s · ${recordedCount} stage${recordedCount === 1 ? "" : "s"}`
              : `${timelineRows.length} stages`}
          </span>
        )}
        {isProcessing && (
          <span className="job-panel-tag job-panel-next">
            running {formatSeconds((now - parseIsoMs(job.created_at)) / 1000 || 0)}
          </span>
        )}
        {(job.retry_count || 0) > 0 && (
          <span className="job-panel-tag job-panel-retry">
            ↻ {job.retry_count}× retried{job.last_failure_kind ? ` · ${job.last_failure_kind}` : ""}
          </span>
        )}
        {job.next_attempt_at && isFailed && (
          <span className="job-panel-tag job-panel-next">next attempt {formatTime(job.next_attempt_at)}</span>
        )}
      </div>

      {showLiveDetail && (
        <section className="job-panel-section">
          <h3 className="job-panel-section-title">Live progress</h3>
          <p className={`jp-detail ${isProcessing ? "run" : "info"}`}>
            <span className="lbl">{isProcessing ? "detail · now" : "detail"}</span>
            {job.detail}
          </p>
        </section>
      )}

      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Stage timeline</h3>
        {stageTimingsErrored ? (
          <p className="job-panel-empty">Stage timings require an admin key.</p>
        ) : stageTimings === null && timelineRows.length === 0 ? (
          <p className="job-panel-empty">Loading…</p>
        ) : timelineRows.length === 0 ? (
          <p className="job-panel-empty">No stage timings recorded yet.</p>
        ) : (
          <div>
            {timelineRows.map((row) => (
              <StageRow
                key={row.stage}
                stage={row.stage}
                kind={row.kind}
                blob={row.blob}
                maxElapsed={maxElapsed}
                job={job}
              />
            ))}
          </div>
        )}
      </section>

      <section className="job-panel-section">
        <h3 className="job-panel-section-title">
          Errors{errors?.errors?.length ? ` (${errors.errors.length})` : ""}
        </h3>
        {errors === null ? (
          <p className="job-panel-empty">Loading…</p>
        ) : !errors.errors || errors.errors.length === 0 ? (
          <p className="job-panel-empty">
            {job.error
              ? <>No structured error log. Raw error:<br /><code>{job.error.split("\n")[0]}</code></>
              : "No errors recorded."}
          </p>
        ) : (
          <ul className="job-panel-error-list">
            {errors.errors.map((e, i) => {
              const isExpanded = expandedIdx === i;
              const hasDetail = !!(e.traceback || (e.context && Object.keys(e.context).length > 0));
              const sev = e.severity || "error";
              return (
                <li key={i} className={`job-panel-error job-panel-error-${sev}`}>
                  <div className="job-panel-error-head">
                    <span className={`job-panel-error-badge job-panel-error-badge-${sev}`}>{sev.toUpperCase()}</span>
                    <span className="job-panel-error-stage" style={{ color: STAGE_COLORS[e.stage] || "#cbd5e1" }}>
                      {formatStageLabel(e.stage)}
                    </span>
                    <span className="job-panel-error-exc">{e.exc_type}</span>
                    {(e.retry_count || 0) > 0 && (
                      <span className="job-panel-error-attempt">attempt {e.retry_count + 1}</span>
                    )}
                    <span className="job-panel-error-time">{formatTime(e.failed_at)}</span>
                  </div>
                  {e.message && <div className="job-panel-error-msg">{e.message}</div>}
                  {hasDetail && (
                    <button
                      type="button"
                      className="job-panel-error-toggle"
                      onClick={() => setExpandedIdx(isExpanded ? null : i)}
                    >
                      {isExpanded ? "Hide" : "Show"} {e.traceback ? "traceback" : "context"}
                    </button>
                  )}
                  {isExpanded && e.traceback && <pre className="job-panel-error-detail">{e.traceback}</pre>}
                  {isExpanded && e.context && Object.keys(e.context).length > 0 && (
                    <pre className="job-panel-error-detail">{JSON.stringify(e.context, null, 2)}</pre>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="job-panel-section">
        <h3 className="job-panel-section-title">Operational</h3>
        <dl className="job-panel-ops">
          <dt>worker</dt>
          <dd>{opWorker || "—"}</dd>
          <dt>trace_id</dt>
          <dd className="job-panel-trace">
            {traceId ? (
              <>
                <code>{traceId}</code>
                <button type="button" className="job-panel-link" onClick={copyTrace}>
                  {copyOk ? "Copied" : "Copy"}
                </button>
                {logsHref && (
                  <a className="job-panel-link" href={logsHref} target="_blank" rel="noreferrer">Logs ↗</a>
                )}
              </>
            ) : "—"}
          </dd>
          <dt>created</dt>
          <dd>{formatTime(job.created_at)}</dd>
          <dt>updated</dt>
          <dd>{formatTime(job.updated_at)}</dd>
          {job.next_attempt_at && (
            <>
              <dt>next attempt</dt>
              <dd>{formatTime(job.next_attempt_at)}</dd>
            </>
          )}
        </dl>
      </section>

      {isTerminal && (
        <footer className="job-panel-actions">
          <button type="button" className="job-panel-retry-btn" onClick={handleRetry} disabled={retrying}>
            {retrying ? "Retrying…" : "Retry job"}
          </button>
          {retryError && <p className="job-panel-retry-error">{retryError}</p>}
        </footer>
      )}
    </>
  );
}
