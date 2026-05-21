import React, { useEffect, useMemo, useState } from "react";

import { api } from "../api/client.js";
import { getPipeline as getAuditPipeline } from "../api/audits.js";
import { shortenAddress } from "../graph.js";
import JobDetailPanel from "./JobDetailPanel.jsx";

export const PIPELINE_STAGES = ["discovery", "dapp_crawl", "defillama_scan", "selection", "static", "resolution", "policy", "coverage"];
export const ALL_STAGES = [...PIPELINE_STAGES, "done"];

function shortFailReason(error) {
  if (!error) return "Unknown";
  if (error.includes("No verified source")) return "Not Verified";
  if (error.includes("No such file or directory")) return "Crawler Missing";
  if (error.includes("Read timed out")) return "RPC Timeout";
  if (error.includes("name resolution") || error.includes("NameResolutionError")) return "DNS Failure";
  if (error.includes("Max retries exceeded")) return "RPC Unreachable";
  if (error.includes("value too long")) return "DB Column Overflow";
  if (error.includes("StringDataRightTruncation")) return "DB Column Overflow";
  if (error.includes("execution reverted")) return "Contract Reverted";
  if (error.includes("rate limit") || error.includes("429")) return "Rate Limited";
  if (error.includes("PendingRollbackError")) return "DB Session Error";
  const last = error.split("\n").filter(Boolean).pop() || "";
  const match = last.match(/^\w+Error:\s*(.{0,40})/);
  return match ? match[1] : last.slice(0, 40) || "Unknown";
}

function formatElapsed(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return `${m}m ${rem}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function formatStageLabel(stage) {
  return String(stage || "").replaceAll("_", " ").toUpperCase();
}

function sortByUpdatedAtDesc(a, b) {
  return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
}

function monitorJobLabel(job) {
  return job.name || job.company || (job.address ? shortenAddress(job.address) : "Job");
}


export default function PipelineDashboard() {
  const [allJobs, setAllJobs] = useState([]);
  const [stats, setStats] = useState(null);
  const [auditPipeline, setAuditPipeline] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [expandedError, setExpandedError] = useState(null);
  const [selectedJobId, setSelectedJobId] = useState(null);
  // Bumped each top-level poll tick so the open detail panel knows to
  // re-fetch its /errors + /stage_timings — keeps the panel live without
  // making it run its own interval.
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      try {
        const [jobs, s, audits] = await Promise.all([
          api("/api/jobs"),
          api("/api/stats"),
          getAuditPipeline().catch(() => null),
        ]);
        if (!cancelled) {
          setAllJobs(jobs);
          setStats(s);
          setAuditPipeline(audits);
          setLoaded(true);
          setRefreshTick((n) => n + 1);
        }
      } catch {}
    }
    fetchAll();
    const timer = setInterval(fetchAll, 2500);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  // Tick every second so elapsed timers update live
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // Filter to only show meaningful analysis jobs:
  // - Skip proxy jobs once their impl child job exists (the impl does the real work)
  // - Skip company/discovery-only jobs once child contract jobs exist
  const hasChildJobs = useMemo(() =>
    allJobs.some((j) => !j.company && j.address),
  [allJobs]);
  const implProxyAddresses = useMemo(() =>
    new Set(allJobs.map((j) => (j.request?.proxy_address || "").toLowerCase()).filter(Boolean)),
  [allJobs]);
  const visiblePipelineJobs = useMemo(() =>
    allJobs.filter((j) => {
      // Always show jobs that are still actively running
      const isActive = j.status === "queued" || j.status === "processing";
      if (j.is_proxy && !isActive) return false;
      if (!j.is_proxy && j.address && implProxyAddresses.has(j.address.toLowerCase()) && !isActive) return false;
      if (j.company && hasChildJobs && j.status === "completed") return false;
      return true;
    }),
  [allJobs, hasChildJobs, implProxyAddresses]);

  const buckets = useMemo(() => {
    const b = {};
    // failed_terminal is a distinct bucket from failed — terminal jobs
    // need operator intervention, transient failures keep retrying. Until
    // this branch they fell through to the implicit `else` and were silently
    // dropped from the SVG entirely.
    for (const s of ALL_STAGES) b[s] = { queued: [], processing: [], completed: [], failed: [], failed_terminal: [] };
    for (const j of visiblePipelineJobs) {
      const stage = j.stage || "discovery";
      const status = j.status || "queued";
      if (b[stage] && b[stage][status]) b[stage][status].push(j);
    }
    return b;
  }, [visiblePipelineJobs]);

  const totals = useMemo(() => {
    const t = { queued: 0, processing: 0, completed: 0, failed: 0, failed_terminal: 0, total: 0 };
    for (const j of visiblePipelineJobs) {
      t[j.status] = (t[j.status] || 0) + 1; t.total++;
    }
    return t;
  }, [visiblePipelineJobs]);

  const activeStageGroups = useMemo(() =>
    ALL_STAGES
      .map((stage) => ({
        stage,
        jobs: visiblePipelineJobs
          .filter((job) => job.stage === stage && job.status === "processing")
          .sort(sortByUpdatedAtDesc),
      }))
      .filter((entry) => entry.jobs.length > 0),
  [visiblePipelineJobs]);

  // Protocol-centric grouping: one card per protocol, collapsing the old
  // "Live Stage Activity" (stage-grouped) and "Audit Extraction" (separate
  // panel) into a single unified view. Audits are a parallel sidecar —
  // they aren't a stage in the job pipeline, they run alongside it.
  const protocolGroups = useMemo(() => {
    const byCompany = new Map();
    function ensure(company) {
      const key = company || "__standalone__";
      if (!byCompany.has(key)) {
        byCompany.set(key, {
          key,
          company: company || null,
          jobs: [],
          audits: { text: { processing: [], pending: [], failed: [] }, scope: { processing: [], pending: [], failed: [] } },
        });
      }
      return byCompany.get(key);
    }
    for (const j of visiblePipelineJobs) {
      ensure(j.company).jobs.push(j);
    }
    if (auditPipeline) {
      for (const [apiStage, localStage] of [["text_extraction", "text"], ["scope_extraction", "scope"]]) {
        const bucket = auditPipeline[apiStage] || {};
        for (const status of ["processing", "pending", "failed"]) {
          for (const item of bucket[status] || []) {
            ensure(item.company).audits[localStage][status].push(item);
          }
        }
      }
    }
    // Keep only protocols with *active* work (running/queued jobs or any audit
    // activity). Completed-only protocols drop out — their completion shows
    // in the "Recently Completed" section below.
    const groups = [...byCompany.values()].filter((g) => {
      const anyActiveJob = g.jobs.some((j) => j.status === "processing" || j.status === "queued");
      const anyAudit = ["text", "scope"].some((s) =>
        g.audits[s].processing.length + g.audits[s].pending.length + g.audits[s].failed.length > 0,
      );
      return anyActiveJob || anyAudit;
    });
    // Sort: protocols with running jobs first (by most-recent update), then
    // audit-only, then standalone.
    groups.sort((a, b) => {
      const rankA = a.jobs.some((j) => j.status === "processing") ? 0 : 1;
      const rankB = b.jobs.some((j) => j.status === "processing") ? 0 : 1;
      if (rankA !== rankB) return rankA - rankB;
      const lastA = a.jobs.length ? Math.max(...a.jobs.map((j) => new Date(j.updated_at || j.created_at).getTime())) : 0;
      const lastB = b.jobs.length ? Math.max(...b.jobs.map((j) => new Date(j.updated_at || j.created_at).getTime())) : 0;
      return lastB - lastA;
    });
    return groups;
  }, [visiblePipelineJobs, auditPipeline]);

  // Completed-in-the-last-hour feed — replaces the old "Recent Activity"
  // table, which duplicated the processing/queued information shown above.
  const RECENT_WINDOW_MS = 60 * 60 * 1000;
  const recentlyCompleted = useMemo(() => {
    const cutoff = now - RECENT_WINDOW_MS;
    return allJobs
      .filter((j) => (j.status === "completed" || j.status === "failed") && j.updated_at && new Date(j.updated_at).getTime() >= cutoff)
      .sort(sortByUpdatedAtDesc)
      .slice(0, 20);
  }, [allJobs, now]);

  if (!loaded) {
    return <div className="page"><section className="panel"><p style={{ textAlign: "center", padding: "2rem 0", color: "#64748b" }}>Loading pipeline status...</p></section></div>;
  }
  if (!allJobs.length) {
    return <div className="page"><section className="panel empty-state"><p className="empty">No jobs yet. Submit an analysis to get started.</p></section></div>;
  }

  const stageColors = { discovery: "#0f766e", dapp_crawl: "#0e7490", defillama_scan: "#0891b2", selection: "#6366f1", static: "#d97706", resolution: "#2563eb", policy: "#7c3aed", coverage: "#059669", done: "#16a34a" };
  const statusColors = { queued: "#94a3b8", processing: "#f59e0b", completed: "#22c55e", failed: "#ef4444", failed_terminal: "#b91c1c" };
  const colW = 160, gapW = 80, headerH = 64, dotR = 6;
  const totalW = ALL_STAGES.length * colW + (ALL_STAGES.length - 1) * gapW;
  const dotsPerRow = Math.floor((colW - 20) / (dotR * 2 + 4));
  const maxDots = Math.max(1, ...ALL_STAGES.map((s) => { const b = buckets[s]; return (b.processing?.length || 0) + (b.queued?.length || 0) + (b.completed?.length || 0) + (b.failed?.length || 0); }));
  const dotsAreaH = Math.max(60, Math.ceil(maxDots / dotsPerRow) * (dotR * 2 + 4) + 20);
  const totalH = headerH + dotsAreaH + 40;

  function renderDots(jobs, startX, startY) {
    return jobs.map((j, i) => {
      const cx = startX + 10 + (i % dotsPerRow) * (dotR * 2 + 4) + dotR;
      const cy = startY + Math.floor(i / dotsPerRow) * (dotR * 2 + 4) + dotR;
      const fill = statusColors[j.status] || "#94a3b8";
      const hasRetries = (j.retry_count || 0) > 0;
      const isTerminal = j.status === "failed_terminal";
      // Terminal failures get a thicker pale-red ring so they read as
      // "needs operator action" even though the fill is the same red family
      // as the transient `failed` state. Retry stroke is amber and narrower.
      const stroke = isTerminal ? "#fca5a5" : hasRetries ? "#fbbf24" : null;
      const strokeWidth = isTerminal ? 2 : hasRetries ? 1.5 : 0;
      const titleLines = [
        j.name || j.company || j.address || j.job_id,
        `${j.status} / ${j.stage}`,
      ];
      if (hasRetries) {
        titleLines.push(
          `Retried ${j.retry_count}×${j.last_failure_kind ? ` (${j.last_failure_kind})` : ""}`,
        );
      }
      if (j.error) {
        titleLines.push(`Last error: ${shortFailReason(j.error)}`);
      }
      titleLines.push("Click for details");
      const isSelected = selectedJobId === j.job_id;
      return (
        <g
          key={j.job_id}
          style={{ cursor: "pointer" }}
          onClick={() => setSelectedJobId(j.job_id)}
        >
          <title>{titleLines.join("\n")}</title>
          {isSelected && (
            <circle cx={cx} cy={cy} r={dotR + 3} fill="none" stroke="#e2e8f0" strokeWidth="1.5" opacity="0.7" />
          )}
          <circle
            cx={cx} cy={cy} r={dotR}
            fill={fill}
            stroke={stroke || "none"}
            strokeWidth={strokeWidth}
            opacity={j.status === "processing" ? 1 : 0.85}
          >
            {j.status === "processing" && <animate attributeName="opacity" values="1;0.4;1" dur="1.5s" repeatCount="indefinite" />}
          </circle>
        </g>
      );
    });
  }

  return (
    <div className="page">
      <section className="panel">
        <div className="panel-header">
          <div><p className="eyebrow">Pipeline Status</p><h2>{totals.total} Jobs</h2></div>
          <div className="chips">
            {stats && <span className="chip" style={{ background: "#e0e7ff", color: "#3730a3" }}>{stats.unique_addresses} addresses</span>}
            <span className="chip" style={{ background: "#dcfce7", color: "#166534" }}>{totals.completed} done</span>
            {totals.processing > 0 && <span className="chip" style={{ background: "#fef3c7", color: "#92400e" }}>{totals.processing} running</span>}
            {totals.queued > 0 && <span className="chip" style={{ background: "#f1f5f9", color: "#475569" }}>{totals.queued} queued</span>}
            {totals.failed > 0 && <span className="chip" style={{ background: "#fee2e2", color: "#991b1b" }}>{totals.failed} failed</span>}
            {totals.failed_terminal > 0 && <span className="chip chip-terminal" style={{ background: "#fef2f2", color: "#7f1d1d", border: "1px solid #fecaca" }}>{totals.failed_terminal} terminal</span>}
          </div>
        </div>
        <svg viewBox={`0 0 ${totalW + 40} ${totalH}`} style={{ width: "100%", height: "auto", marginTop: 16 }}>
          {ALL_STAGES.map((stage, i) => {
            const x = 20 + i * (colW + gapW);
            const b = buckets[stage];
            const all = [...(b.processing || []), ...(b.queued || []), ...(b.failed || []), ...(b.failed_terminal || []), ...(b.completed || [])];
            // Aggregate badges: jobs in this stage that are mid-retry (any
            // status with retry_count > 0) and jobs that hit failed_terminal
            // here. Surfaced on the column header so admins don't have to
            // hover individual dots to spot trouble.
            const retryCount = all.reduce((n, j) => n + ((j.retry_count || 0) > 0 ? 1 : 0), 0);
            const terminalCount = (b.failed_terminal || []).length;
            return (
              <g key={stage}>
                <rect x={x} y={0} width={colW} height={totalH} rx="12" fill={stageColors[stage]} opacity="0.06" />
                <rect x={x} y={0} width={colW} height={headerH} rx="12" fill={stageColors[stage]} opacity="0.12" />
                <rect x={x} y={headerH - 12} width={colW} height={12} fill={stageColors[stage]} opacity="0.12" />
                <text x={x + colW / 2} y={24} textAnchor="middle" fontSize="12" fontWeight="700" fill={stageColors[stage]}>{formatStageLabel(stage)}</text>
                <text x={x + colW / 2} y={40} textAnchor="middle" fontSize="11" fill={stageColors[stage]} opacity="0.7">{all.length}</text>
                {b.processing.length > 0 && (
                  <>
                    <circle cx={x + colW / 2 - 28} cy={54} r="4" fill={statusColors.processing}>
                      <animate attributeName="opacity" values="1;0.35;1" dur="1.4s" repeatCount="indefinite" />
                    </circle>
                    <text x={x + colW / 2} y={58} textAnchor="middle" fontSize="10" fontWeight="700" fill={statusColors.processing}>
                      {`${b.processing.length} active`}
                    </text>
                  </>
                )}
                {(retryCount > 0 || terminalCount > 0) && (
                  <text x={x + colW - 8} y={18} textAnchor="end" fontSize="9" fontWeight="700" fontFamily="JetBrains Mono, monospace">
                    {retryCount > 0 && <tspan fill="#fbbf24">↻{retryCount} </tspan>}
                    {terminalCount > 0 && <tspan fill="#fca5a5">✕{terminalCount}</tspan>}
                  </text>
                )}
                {renderDots(all, x, headerH + 10)}
                {i < ALL_STAGES.length - 1 && <line x1={x + colW + 8} y1={totalH / 2} x2={x + colW + gapW - 8} y2={totalH / 2} stroke="#cbd5e1" strokeWidth="2" markerEnd="url(#pipeline-arrow)" />}
              </g>
            );
          })}
          <defs><marker id="pipeline-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M 0 0 L 8 4 L 0 8 z" fill="#cbd5e1" /></marker></defs>
        </svg>
        <div className="chips" style={{ marginTop: 12, justifyContent: "center" }}>
          <span className="chip" style={{ background: "#fef3c7", color: "#92400e", fontSize: 10 }}>Processing</span>
          <span className="chip" style={{ background: "#f1f5f9", color: "#475569", fontSize: 10 }}>Queued</span>
          <span className="chip" style={{ background: "#dcfce7", color: "#166534", fontSize: 10 }}>Completed</span>
          <span className="chip" style={{ background: "#fee2e2", color: "#991b1b", fontSize: 10 }}>Failed (retrying)</span>
          <span className="chip" style={{ background: "#fef2f2", color: "#7f1d1d", border: "1px solid #fecaca", fontSize: 10 }}>Terminal</span>
          <span className="chip" style={{ background: "rgba(251,191,36,0.12)", color: "#92400e", fontSize: 10 }}>↻ Has retries</span>
        </div>
      </section>

      {protocolGroups.length > 0 && (
        <section className="panel" style={{ marginTop: 16 }}>
          <div className="panel-header">
            <div>
              <p className="eyebrow">Running Protocols</p>
              <h2>{protocolGroups.length} active</h2>
            </div>
          </div>
          <div className="protocol-card-grid">
            {protocolGroups.map((group) => (
              <ProtocolCard
                key={group.key}
                group={group}
                now={now}
                stageColors={stageColors}
                statusColors={statusColors}
                expandedError={expandedError}
                setExpandedError={setExpandedError}
              />
            ))}
          </div>
        </section>
      )}

      {selectedJobId && (
        <JobDetailPanel
          job={allJobs.find((j) => j.job_id === selectedJobId) || null}
          stageColors={stageColors}
          statusColors={statusColors}
          onClose={() => setSelectedJobId(null)}
          refreshTick={refreshTick}
        />
      )}

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <div>
            <p className="eyebrow">Recently Completed</p>
            <h2>Last hour</h2>
          </div>
          <div className="chips">
            <span className="chip" style={{ background: "rgba(34,197,94,0.12)", color: "#4ade80" }}>
              {recentlyCompleted.filter((j) => j.status === "completed").length} done
            </span>
            {recentlyCompleted.some((j) => j.status === "failed") && (
              <span className="chip" style={{ background: "rgba(239,68,68,0.12)", color: "#fca5a5" }}>
                {recentlyCompleted.filter((j) => j.status === "failed").length} failed
              </span>
            )}
          </div>
        </div>
        {recentlyCompleted.length === 0 ? (
          <p className="empty" style={{ textAlign: "center", padding: "16px 0" }}>
            No jobs have completed in the last hour.
          </p>
        ) : (
          <div className="completion-tape">
            {recentlyCompleted.map((j) => {
              const done = new Date(j.updated_at).getTime();
              const ago = now - done;
              const label = j.name || j.company || (j.address ? shortenAddress(j.address) : "Job");
              const isFailed = j.status === "failed";
              return (
                <React.Fragment key={j.job_id}>
                  <div
                    className={`completion-row ${isFailed ? "failed" : ""}`}
                    onClick={() => isFailed && setExpandedError(expandedError === j.job_id ? null : j.job_id)}
                    style={{ cursor: isFailed ? "pointer" : "default" }}
                  >
                    <span className={`completion-dot ${isFailed ? "failed" : ""}`} />
                    <span className="completion-name">{label}</span>
                    <span className="completion-stage" style={{ color: stageColors[j.stage] || "#94a3b8" }}>
                      {formatStageLabel(j.stage)}
                    </span>
                    <span className="completion-detail">
                      {isFailed
                        ? <span style={{ color: "#fca5a5" }}>{shortFailReason(j.error)}</span>
                        : (j.detail || "")}
                    </span>
                    <span className="completion-time">{formatElapsed(ago)} ago</span>
                  </div>
                  {isFailed && expandedError === j.job_id && (
                    <pre
                      style={{
                        margin: "2px 0 8px",
                        padding: "10px 14px",
                        background: "rgba(239,68,68,0.06)",
                        color: "#fca5a5",
                        fontSize: 11,
                        fontFamily: "monospace",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                        maxHeight: 260,
                        overflow: "auto",
                        borderRadius: 8,
                        border: "1px solid rgba(239,68,68,0.18)",
                      }}
                    >
                      {j.error || "No error details available"}
                    </pre>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

// ── Protocol card: shows all running work for a single protocol in one place,
// including per-stage counts for its jobs and the audit extraction sidecar
// that runs in parallel with the main pipeline.
function ProtocolCard({ group, now, stageColors, statusColors, expandedError, setExpandedError }) {
  const { company, jobs, audits } = group;
  const running = jobs.filter((j) => j.status === "processing");
  const queued = jobs.filter((j) => j.status === "queued");
  const failed = jobs.filter((j) => j.status === "failed");
  const completedChildren = jobs.filter((j) => j.status === "completed").length;

  // Stage pills — every stage the protocol has jobs in, with running/queued counts.
  const stagesInPlay = ALL_STAGES
    .map((stage) => {
      const stageJobs = jobs.filter((j) => j.stage === stage);
      return { stage, stageJobs };
    })
    .filter((s) => s.stageJobs.length > 0);

  const auditTotals = {
    text: audits.text.processing.length + audits.text.pending.length,
    scope: audits.scope.processing.length + audits.scope.pending.length,
    textRunning: audits.text.processing.length,
    scopeRunning: audits.scope.processing.length,
    failed: audits.text.failed.length + audits.scope.failed.length,
  };
  const hasAuditActivity = auditTotals.text + auditTotals.scope + auditTotals.failed > 0;

  return (
    <article className="protocol-card">
      <div className="protocol-card-header">
        <div className="protocol-card-title">
          <span className="protocol-card-name">{company || "Standalone contracts"}</span>
          <span className="protocol-card-sub">
            {jobs.length} job{jobs.length === 1 ? "" : "s"}
            {completedChildren > 0 ? ` · ${completedChildren} done` : ""}
          </span>
        </div>
        <div className="protocol-card-chips">
          {running.length > 0 && (
            <span className="chip" style={{ background: "rgba(245,158,11,0.12)", color: "#fbbf24" }}>
              {running.length} running
            </span>
          )}
          {queued.length > 0 && (
            <span className="chip" style={{ background: "rgba(148,163,184,0.12)", color: "#cbd5e1" }}>
              {queued.length} queued
            </span>
          )}
          {failed.length > 0 && (
            <span className="chip" style={{ background: "rgba(239,68,68,0.12)", color: "#fca5a5" }}>
              {failed.length} failed
            </span>
          )}
        </div>
      </div>

      {/* Main pipeline lane: stage pills for stages the protocol currently has jobs in */}
      <div className="protocol-lane">
        <span className="protocol-lane-label">pipeline</span>
        <div className="protocol-stage-pills">
          {stagesInPlay.length === 0 ? (
            <span className="protocol-stage-empty">—</span>
          ) : (
            stagesInPlay.map(({ stage, stageJobs }) => {
              const stageRunning = stageJobs.filter((j) => j.status === "processing").length;
              const stageQueued = stageJobs.filter((j) => j.status === "queued").length;
              const stageFailed = stageJobs.filter((j) => j.status === "failed").length;
              const color = stageColors[stage] || "#94a3b8";
              return (
                <span
                  key={stage}
                  className="protocol-stage-pill"
                  style={{ borderColor: `${color}55`, color }}
                >
                  <span className="protocol-stage-pill-name">{formatStageLabel(stage)}</span>
                  <span className="protocol-stage-pill-counts">
                    {stageRunning > 0 && <span style={{ color: statusColors.processing }}>{stageRunning}</span>}
                    {stageQueued > 0 && <span style={{ color: statusColors.queued }}>{stageQueued}</span>}
                    {stageFailed > 0 && <span style={{ color: statusColors.failed }}>{stageFailed}</span>}
                  </span>
                </span>
              );
            })
          )}
        </div>
      </div>

      {/* Audit sidecar — parallel to the pipeline, not a stage in it */}
      {hasAuditActivity && (
        <div className="protocol-lane protocol-lane-audit">
          <span className="protocol-lane-label">audits</span>
          <div className="protocol-stage-pills">
            <span className="protocol-stage-pill" style={{ borderColor: "#0891b255", color: "#22d3ee" }}>
              <span className="protocol-stage-pill-name">Text</span>
              <span className="protocol-stage-pill-counts">
                {auditTotals.textRunning > 0 && <span style={{ color: statusColors.processing }}>{auditTotals.textRunning}</span>}
                {audits.text.pending.length > 0 && <span style={{ color: statusColors.queued }}>{audits.text.pending.length}</span>}
                {audits.text.failed.length > 0 && <span style={{ color: statusColors.failed }}>{audits.text.failed.length}</span>}
              </span>
            </span>
            <span className="protocol-stage-pill" style={{ borderColor: "#7c3aed55", color: "#a78bfa" }}>
              <span className="protocol-stage-pill-name">Scope</span>
              <span className="protocol-stage-pill-counts">
                {auditTotals.scopeRunning > 0 && <span style={{ color: statusColors.processing }}>{auditTotals.scopeRunning}</span>}
                {audits.scope.pending.length > 0 && <span style={{ color: statusColors.queued }}>{audits.scope.pending.length}</span>}
                {audits.scope.failed.length > 0 && <span style={{ color: statusColors.failed }}>{audits.scope.failed.length}</span>}
              </span>
            </span>
          </div>
        </div>
      )}

      {/* Inline children: up to 3 running jobs with their detail */}
      {(running.length > 0 || failed.length > 0) && (
        <div className="protocol-children">
          {running.slice(0, 3).map((job) => {
            const created = new Date(job.created_at).getTime();
            return (
              <div className="protocol-child" key={job.job_id}>
                <span className="protocol-child-dot processing" />
                <span className="protocol-child-name">{monitorJobLabel(job)}</span>
                <span className="protocol-child-stage" style={{ color: stageColors[job.stage] }}>
                  {formatStageLabel(job.stage)}
                </span>
                <span className="protocol-child-detail">{job.detail || "Working…"}</span>
                <span className="protocol-child-time">{formatElapsed(now - created)}</span>
              </div>
            );
          })}
          {running.length > 3 && (
            <div className="protocol-child-more">+{running.length - 3} more running</div>
          )}
          {failed.slice(0, 2).map((job) => (
            <React.Fragment key={job.job_id}>
              <div
                className="protocol-child failed"
                onClick={() => setExpandedError(expandedError === job.job_id ? null : job.job_id)}
              >
                <span className="protocol-child-dot failed" />
                <span className="protocol-child-name">{monitorJobLabel(job)}</span>
                <span className="protocol-child-stage" style={{ color: stageColors[job.stage] }}>
                  {formatStageLabel(job.stage)}
                </span>
                <span className="protocol-child-detail" style={{ color: "#fca5a5" }}>
                  {shortFailReason(job.error)}
                </span>
              </div>
              {expandedError === job.job_id && (
                <pre className="protocol-child-error">{job.error || "No error details available"}</pre>
              )}
            </React.Fragment>
          ))}
        </div>
      )}
    </article>
  );
}
