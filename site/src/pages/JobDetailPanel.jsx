import React, { useEffect, useMemo, useState } from "react";

import { api } from "../api/client.js";
import { shortenAddress } from "../graph.js";

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

function formatStageLabel(stage) {
  return String(stage || "").replaceAll("_", " ").toUpperCase();
}

function formatTime(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return iso;
  }
}

export default function JobDetailPanel({ job, stageColors, statusColors, onClose, refreshTick }) {
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
  // would flash the previous job's errors before the new fetch resolves.
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

  // ESC closes the panel.
  useEffect(() => {
    function onKey(ev) { if (ev.key === "Escape") onClose(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const stageRows = useMemo(() => {
    const map = stageTimings?.stage_timings || {};
    return Object.entries(map)
      .map(([stage, blob]) => ({
        stage,
        // Workers write the canonical key; older artifacts used elapsed_seconds.
        elapsed: blob?.worker_elapsed_seconds ?? blob?.elapsed_seconds ?? null,
      }))
      .sort((a, b) => a.stage.localeCompare(b.stage));
  }, [stageTimings]);

  if (!job) return null;

  const label = job.name || job.company || (job.address ? shortenAddress(job.address) : job.job_id);
  const statusKey = job.status;
  const isTerminal = statusKey === "failed_terminal";
  const isFailed = statusKey === "failed";
  const statusLabel = isTerminal
    ? "Failed (terminal)"
    : isFailed
    ? "Failed (will retry)"
    : statusKey;

  const stageColor = stageColors?.[job.stage] || "#94a3b8";
  const statusColor = statusColors?.[statusKey] || "#94a3b8";

  const traceId = job.trace_id || errors?.trace_id || null;
  const logsHref = buildLogsDeeplink(traceId, {
    createdAt: job.created_at,
    updatedAt: job.updated_at,
  });

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
      <div className="job-panel-backdrop" onClick={onClose} aria-hidden="true" />
      <aside className="job-panel" role="dialog" aria-label={`Job ${label} details`}>
        <header className="job-panel-header">
          <div className="job-panel-title">
            <span className="job-panel-name">{label}</span>
            {job.address && (
              <span className="job-panel-address" title={job.address}>
                {shortenAddress(job.address)}
              </span>
            )}
          </div>
          <button
            type="button"
            className="job-panel-close"
            onClick={onClose}
            aria-label="Close panel"
          >
            ×
          </button>
        </header>

        <div className="job-panel-meta">
          <span className="job-panel-tag" style={{ color: stageColor, borderColor: `${stageColor}55` }}>
            {formatStageLabel(job.stage)}
          </span>
          <span
            className={`job-panel-tag job-panel-status${isTerminal ? " terminal" : ""}`}
            style={{ color: statusColor, borderColor: `${statusColor}66` }}
          >
            {statusLabel}
          </span>
          {(job.retry_count || 0) > 0 && (
            <span className="job-panel-tag job-panel-retry">
              ↻ {job.retry_count}× retried
              {job.last_failure_kind ? ` · ${job.last_failure_kind}` : ""}
            </span>
          )}
          {job.next_attempt_at && (
            <span className="job-panel-tag job-panel-next">
              next attempt {formatTime(job.next_attempt_at)}
            </span>
          )}
        </div>

        <section className="job-panel-section">
          <h3 className="job-panel-section-title">Stage timeline</h3>
          {stageTimingsErrored ? (
            <p className="job-panel-empty">
              Stage timings require an admin key.
            </p>
          ) : stageTimings === null ? (
            <p className="job-panel-empty">Loading…</p>
          ) : stageRows.length === 0 ? (
            <p className="job-panel-empty">No stage timings recorded yet.</p>
          ) : (
            <ul className="job-panel-stage-list">
              {stageRows.map(({ stage, elapsed }) => (
                <li key={stage} className="job-panel-stage-row">
                  <span
                    className="job-panel-stage-name"
                    style={{ color: stageColors?.[stage] || "#cbd5e1" }}
                  >
                    {formatStageLabel(stage)}
                  </span>
                  <span className="job-panel-stage-time">{formatSeconds(elapsed)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="job-panel-section">
          <h3 className="job-panel-section-title">
            Errors
            {errors?.errors?.length ? ` (${errors.errors.length})` : ""}
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
                return (
                  <li key={i} className={`job-panel-error job-panel-error-${e.severity || "error"}`}>
                    <div className="job-panel-error-head">
                      <span className={`job-panel-error-badge job-panel-error-badge-${e.severity || "error"}`}>
                        {(e.severity || "error").toUpperCase()}
                      </span>
                      <span
                        className="job-panel-error-stage"
                        style={{ color: stageColors?.[e.stage] || "#cbd5e1" }}
                      >
                        {formatStageLabel(e.stage)}
                      </span>
                      <span className="job-panel-error-exc">{e.exc_type}</span>
                      {(e.retry_count || 0) > 0 && (
                        <span className="job-panel-error-attempt">
                          attempt {e.retry_count + 1}
                        </span>
                      )}
                      <span className="job-panel-error-time">{formatTime(e.failed_at)}</span>
                    </div>
                    {e.message && (
                      <div className="job-panel-error-msg">{e.message}</div>
                    )}
                    {hasDetail && (
                      <button
                        type="button"
                        className="job-panel-error-toggle"
                        onClick={() => setExpandedIdx(isExpanded ? null : i)}
                      >
                        {isExpanded ? "Hide" : "Show"} {e.traceback ? "traceback" : "context"}
                      </button>
                    )}
                    {isExpanded && e.traceback && (
                      <pre className="job-panel-error-detail">{e.traceback}</pre>
                    )}
                    {isExpanded && e.context && Object.keys(e.context).length > 0 && (
                      <pre className="job-panel-error-detail">
                        {JSON.stringify(e.context, null, 2)}
                      </pre>
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
            <dd>{job.worker_id || "—"}</dd>
            <dt>trace_id</dt>
            <dd className="job-panel-trace">
              {traceId ? (
                <>
                  <code>{traceId}</code>
                  <button type="button" className="job-panel-link" onClick={copyTrace}>
                    {copyOk ? "Copied" : "Copy"}
                  </button>
                  {logsHref && (
                    <a className="job-panel-link" href={logsHref} target="_blank" rel="noreferrer">
                      Logs ↗
                    </a>
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

        {job.request && Object.keys(job.request).length > 0 && (
          <section className="job-panel-section">
            <h3 className="job-panel-section-title">Request</h3>
            <details className="job-panel-request">
              <summary>
                {Object.keys(job.request).length} field{Object.keys(job.request).length === 1 ? "" : "s"}
                {job.request.dapp_urls ? " · from dapp_crawl" : ""}
                {job.request.defillama_protocol ? " · from defillama_scan" : ""}
                {job.request.proxy_address ? " · spawned for proxy impl" : ""}
              </summary>
              <pre className="job-panel-request-body">{JSON.stringify(job.request, null, 2)}</pre>
            </details>
          </section>
        )}

        {isTerminal && (
          <footer className="job-panel-actions">
            <button
              type="button"
              className="job-panel-retry-btn"
              onClick={handleRetry}
              disabled={retrying}
            >
              {retrying ? "Retrying…" : "Retry job"}
            </button>
            {retryError && (
              <p className="job-panel-retry-error">{retryError}</p>
            )}
          </footer>
        )}
      </aside>
    </>
  );
}
