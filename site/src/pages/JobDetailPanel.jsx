import React, { useEffect, useMemo, useState } from "react";

import { api } from "../api/client.js";
import { shortenAddress } from "../shared/format.js";
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

// trace_id is inside the log line, not a stream label, so the link filters with
// `|=` and scopes by fly_app_name; unscoped, Loki scans every preview.
const GRAFANA_LOGS_BASE = "https://protocolsectool.grafana.net";

// Free-tier retention (probed 2026-05-21): data at day 13, gone by day 16.
const LOKI_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;
// Catches lines logged just before the job row existed or after it finished.
const LOKI_RANGE_BUFFER_MS = 60 * 60 * 1000;

// psat.fly.dev → "psat" (prod)
// <preview>.flycast → "<preview>" (private preview)
// anything else → null (wildcard query)
export function inferFlyApp(hostname) {
  if (!hostname) return null;
  const m = hostname.match(/^(psat(?:-pr-\d+)?)\.fly\.dev$|^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?-pr-\d+)\.flycast$/);
  return m ? (m[1] || m[2]) : null;
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
  // Same trace either way; the scoped selector is much cheaper.
  const selector = flyApp ? `{fly_app_name="${flyApp}"}` : `{service_name=~".+"}`;

  // From the job span, so old failures still link (a fixed now-24h missed
  // them). Clamped to retention.
  const now = opts.now ?? Date.now();
  const createdMs = parseIsoMs(opts.createdAt);
  const updatedMs = parseIsoMs(opts.updatedAt);
  const retentionFloor = now - LOKI_RETENTION_MS;
  let fromMs = createdMs != null ? Math.max(createdMs - LOKI_RANGE_BUFFER_MS, retentionFloor) : retentionFloor;
  let toMs = updatedMs != null ? Math.min(updatedMs + LOKI_RANGE_BUFFER_MS, now) : now;
  // Clock skew can invert the range.
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

// null when there's no timing to draw.
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
    // UTC to match the fleet logs and Grafana.
    return new Date(iso).toISOString().slice(11, 19);
  } catch {
    return iso;
  }
}

// Heuristic; the Live-progress block is authoritative.
function liveChips(detail) {
  if (!detail) return [];
  return detail
    .split(/\s*[·;]\s*/)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => s.length <= 28)
    .slice(0, 5);
}

// `blob` is null for synthesized rows.
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
    : formatSeconds(elapsed);

  // No artifact means no bar: faking a width would invent a duration.
  let bar = null;
  if (kind === "running") {
    bar = <div className="jp-barwrap"><i className="run" style={{ width: "64%" }} /></div>;
  } else if (hasElapsed) {
    const pct = maxElapsed > 0 ? Math.max(2, (elapsed / maxElapsed) * 100) : 2;
    bar = <div className="jp-barwrap"><i style={{ width: `${pct}%`, background: kind === "failed" ? "#ef4444" : color }} /></div>;
  }

  // Synthesized rows say so, so a missing duration doesn't read as instant.
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

// Panel content only; the page owns the dock and <900px drawer.
export function JobDetail({ job, onClose, refreshTick, now = Date.now() }) {
  const jobId = job?.job_id || null;
  const [errors, setErrors] = useState(null);
  const [stageTimings, setStageTimings] = useState(null);
  // Stop refetching after an unrecoverable failure (e.g. 401 without a key).
  const [stageTimingsErrored, setStageTimingsErrored] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [retryError, setRetryError] = useState(null);
  const [expandedIdx, setExpandedIdx] = useState(null);
  const [copyOk, setCopyOk] = useState(false);

  // Otherwise the previous job's data flashes.
  useEffect(() => {
    setErrors(null);
    setStageTimings(null);
    setStageTimingsErrored(false);
    setRetrying(false);
    setRetryError(null);
    setExpandedIdx(null);
  }, [jobId]);

  // /stage_timings is admin-only; silent so polls don't prompt.
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

  // Pipeline order. Stages the job advanced past (or all, if completed) render
  // as completed even without an artifact, so a failure at `static` or a
  // pre-metrics job still shows its full path.
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
      // `effects` is flag-gated: presence-based, so a job that never entered it
      // gets no eternal row.
      if (stage === "effects" && !blob && stage !== job.stage) continue;
      let kind;
      if (blob) {
        const st = String(blob.status || "success").toLowerCase();
        kind = st === "failed" || st === "error" ? "failed" : "success";
      } else if (coreIdx === -1) {
        // Company-discovery children: only with a timing.
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

  // worker_id is null once a job completes; use the latest stage's.
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
      // The next poll picks up the queued status.
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
      // Clipboard unavailable (insecure context); the trace_id is still
      // selectable.
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
        <span className="tag tag-md tag-pill job-panel-tag" style={{ color: stageColor, borderColor: `${stageColor}55` }}>
          {formatStageLabel(job.stage)}
        </span>
        <span
          className={`tag tag-md tag-pill job-panel-tag job-panel-status${isTerminal ? " terminal" : ""}`}
          style={{ color: isTerminal ? "#fca5a5" : statusColor, borderColor: isTerminal ? "#b91c1c88" : `${statusColor}66` }}
        >
          {statusLabel}
        </span>
        {isCompleted && (
          <span className="tag tag-md tag-pill tag-plain job-panel-tag job-panel-next">
            {recordedCount > 0
              ? `total ${totalElapsed.toFixed(1)}s · ${recordedCount} stage${recordedCount === 1 ? "" : "s"}`
              : `${timelineRows.length} stages`}
          </span>
        )}
        {isProcessing && (
          <span className="tag tag-md tag-pill tag-plain job-panel-tag job-panel-next">
            running {formatSeconds((now - parseIsoMs(job.created_at)) / 1000 || 0)}
          </span>
        )}
        {(job.retry_count || 0) > 0 && (
          <span className="tag tag-md tag-pill job-panel-tag job-panel-retry">
            ↻ {job.retry_count}× retried{job.last_failure_kind ? ` · ${job.last_failure_kind}` : ""}
          </span>
        )}
        {job.next_attempt_at && isFailed && (
          <span className="tag tag-md tag-pill tag-plain job-panel-tag job-panel-next">next attempt {formatTime(job.next_attempt_at)}</span>
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
          <p className="job-panel-empty">Stage timings require admin access.</p>
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
                    <span className={`tag job-panel-error-badge job-panel-error-badge-${sev}`}>{sev.toUpperCase()}</span>
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
