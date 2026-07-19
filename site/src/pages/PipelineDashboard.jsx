import React, { useEffect, useMemo, useRef, useState } from "react";

import { api } from "../api/client.js";
import { entityKey } from "../surface/entityKey.js";
import { shortenAddress } from "../graph.js";
import { JobDetail } from "./JobDetailPanel.jsx";
import { FleetStrip, DaemonDetail, computeFleetRates } from "./FleetStrip.jsx";
import { CORE_STAGES, STAGE_COLORS, STATUS_COLORS, coreIndexForStage, formatStageLabel } from "./jobStages.js";

// Time-window selector universe. Only truly live work (queued/processing) is
// exempt from the window filter — those represent the current state of the
// worker fleet and have no useful "stale" interpretation. failed and
// failed_terminal flow through the window like completed jobs. "all" means no
// upper bound; the cutoff is just 0.
const TIME_WINDOWS = [
  { id: "1h", label: "1h", ms: 60 * 60 * 1000 },
  { id: "24h", label: "24h", ms: 24 * 60 * 60 * 1000 },
  { id: "7d", label: "7d", ms: 7 * 24 * 60 * 60 * 1000 },
  { id: "all", label: "All", ms: Infinity },
];
const ACTIVE_STATUSES = new Set(["queued", "processing"]);
const HISTORY_STATUSES = new Set(["completed", "failed", "failed_terminal"]);

function windowCutoff(windowId, now) {
  if (windowId === "all") return 0;
  const w = TIME_WINDOWS.find((x) => x.id === windowId);
  return w ? now - w.ms : 0;
}

function windowLabel(windowId) {
  if (windowId === "all") return "All time";
  const w = TIME_WINDOWS.find((x) => x.id === windowId);
  return w ? `Last ${w.label}` : "Last 1h";
}

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

function parseMs(iso) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : null;
}

function sortByUpdatedAtDesc(a, b) {
  return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
}

function monitorJobLabel(job) {
  const base = job.name || job.company || (job.address ? shortenAddress(job.address) : "Job");
  // Impl jobs (spawned for a proxy) keep the proxy address in request — flag
  // them so the (impl) row isn't confused with its proxy shell.
  return job.request?.proxy_address ? `${base} (impl)` : base;
}

function onActivate(fn) {
  return (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      fn();
    }
  };
}

// ── Shared 6-segment CORE-stage progress bar (Active + History rows) ──────
function StageProgress({ job }) {
  const status = job.status;
  const done = status === "completed" || job.stage === "done";
  const curIdx = coreIndexForStage(job.stage);
  const cur = done
    ? null
    : status === "processing"
    ? { bg: "#f59e0b", op: 1 }
    : status === "failed"
    ? { bg: "#ef4444", op: 1 }
    : status === "failed_terminal"
    ? { bg: "#b91c1c", op: 1 }
    : { bg: "#94a3b8", op: 0.5 }; // queued

  const segs = CORE_STAGES.map((_, i) => {
    if (done) return { bg: "#22c55e", op: 0.85 };
    if (i < curIdx) return { bg: "#22c55e", op: 0.7 };
    if (i === curIdx) return cur;
    return null;
  });

  let labText;
  let labColor;
  if (done) {
    labText = "DONE";
    labColor = "#22c55e";
  } else if (status === "failed" || status === "failed_terminal") {
    labText = formatStageLabel(job.stage);
    labColor = "#fca5a5";
  } else if (status === "queued") {
    labText = "QUEUED";
    labColor = STAGE_COLORS[job.stage] || "#64748b";
  } else {
    labText = formatStageLabel(job.stage);
    labColor = STAGE_COLORS[job.stage] || "#64748b";
  }

  return (
    <span className="prog">
      {segs.map((s, i) => (
        <i key={i} style={s ? { background: s.bg, opacity: s.op } : undefined} />
      ))}
      <span className="lab" style={{ color: labColor }}>{labText}</span>
    </span>
  );
}

function ActiveRow({ job, now, selected, onSelect }) {
  const isSel = selected?.type === "job" && selected.id === job.job_id;
  const dotColor = STATUS_COLORS[job.status] || "#94a3b8";
  const pulse = job.status === "processing";
  const created = parseMs(job.created_at);
  const elapsed = job.status === "processing" && created ? formatElapsed(now - created) : "—";
  return (
    <div
      className={`run-row${isSel ? " sel" : ""}`}
      onClick={() => onSelect(job.job_id)}
      onKeyDown={onActivate(() => onSelect(job.job_id))}
      role="button"
      tabIndex={0}
    >
      <span className={`rdot${pulse ? " pulse-dot" : ""}`} style={{ background: dotColor }} />
      <span className="rname">
        <b>{monitorJobLabel(job)}</b>
        <small>{job.company || "—"}</small>
      </span>
      <StageProgress job={job} />
      <span className="adetail">{job.detail || (job.status === "queued" ? "waiting…" : "")}</span>
      <span className="rcell mut">{elapsed}</span>
    </div>
  );
}

function HistoryRow({ job, now, selected, onSelect }) {
  const isSel = selected?.type === "job" && selected.id === job.job_id;
  const isFailed = job.status === "failed" || job.status === "failed_terminal";
  const dotColor = STATUS_COLORS[job.status] || "#22c55e";
  const created = parseMs(job.created_at);
  const updated = parseMs(job.updated_at);
  const duration = created && updated ? formatElapsed(Math.max(0, updated - created)) : "—";
  const ago = updated ? `${formatElapsed(now - updated)} ago` : "—";
  return (
    <div
      className={`run-row${isFailed ? " fail" : ""}${isSel ? " sel" : ""}`}
      onClick={() => onSelect(job.job_id)}
      onKeyDown={onActivate(() => onSelect(job.job_id))}
      role="button"
      tabIndex={0}
    >
      <span className="rdot" style={{ background: dotColor }} />
      <span className="rname">
        <b>{monitorJobLabel(job)}</b>
        <small>{job.company || "—"}</small>
      </span>
      <StageProgress job={job} />
      {isFailed ? (
        <span className="rcell red">
          {shortFailReason(job.error)}
          {(job.retry_count || 0) > 0 && <span className="rretry"> ↻{job.retry_count}</span>}
        </span>
      ) : (
        <span className="rcell">{duration}</span>
      )}
      <span className="rcell mut">{ago}</span>
    </div>
  );
}

function FiltersBar({ filter, onFilter, search, onSearch, counts }) {
  const chips = [
    ["all", "All", counts.all],
    ["completed", "Done", counts.completed],
    ["failed", "Failed", counts.failed],
    ["failed_terminal", "Terminal", counts.terminal],
  ];
  return (
    <div className="runs-toolbar">
      {chips.map(([id, lbl, n]) => (
        <button
          key={id}
          type="button"
          className={`rfilter${filter === id ? " on" : ""}`}
          onClick={() => onFilter(id)}
          aria-pressed={filter === id}
        >
          {lbl}
          <span className="n">{n}</span>
        </button>
      ))}
      <input
        className="rsearch"
        placeholder="Search name, address, worker, trace_id…"
        value={search}
        onChange={(e) => onSearch(e.target.value)}
        aria-label="Search history"
      />
    </div>
  );
}

function EmptyDock() {
  return (
    <div className="dock-empty">
      <div className="de-icon">⊘</div>
      <b>Select a job or process</b>
      <span>Click any row in Active or History — or a process in the Fleet strip — to inspect it here.</span>
    </div>
  );
}

function EmptyRow({ children }) {
  return (
    <div style={{ padding: "12px 14px", color: "#64748b", font: "12px 'JetBrains Mono', monospace" }}>
      {children}
    </div>
  );
}

export default function PipelineDashboard() {
  const [allJobs, setAllJobs] = useState([]);
  const [stats, setStats] = useState(null);
  const [fleet, setFleet] = useState(null);
  // Per-process progress rates, diffed across successive /api/fleet polls.
  // Anchors (last-changed value + time per counter) persist in a ref so the
  // rate survives re-renders; the derived map is state so it triggers one.
  const fleetRatesAnchors = useRef({});
  const [fleetRates, setFleetRates] = useState({});
  const [now, setNow] = useState(Date.now());
  // One selection drives the dock: null | {type:'job', id} | {type:'process', key}
  const [selected, setSelected] = useState(null);
  const [timeWindow, setTimeWindow] = useState("24h");
  const [historyFilter, setHistoryFilter] = useState("all");
  const [search, setSearch] = useState("");
  // Bumped each poll tick so the open job detail re-fetches its
  // /errors + /stage_timings without running its own interval.
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      try {
        const [jobs, s, f] = await Promise.all([
          api("/api/jobs"),
          api("/api/stats").catch(() => null),
          api("/api/fleet").catch(() => null),
        ]);
        if (!cancelled) {
          setAllJobs(Array.isArray(jobs) ? jobs : []);
          setStats(s);
          setFleet(f);
          // Only re-derive rates from a real snapshot — a failed fleet poll
          // (f null) keeps the last rates rather than wiping them to zero.
          if (f) setFleetRates(computeFleetRates(fleetRatesAnchors.current, f));
          setRefreshTick((n) => n + 1);
        }
      } catch {
        // Jobs fetch failed (backend down) — keep the last good state and
        // retry on the next tick.
      }
    }
    fetchAll();
    const timer = setInterval(fetchAll, 2500);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Tick every second so elapsed / "X ago" stay live.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // ESC clears any selection (job or process), collapsing the dock.
  useEffect(() => {
    function onKey(ev) {
      if (ev.key === "Escape") setSelected(null);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // ── Dedup: hide proxy + company shells once their real work has spawned.
  const hasChildJobs = useMemo(() => allJobs.some((j) => !j.company && j.address), [allJobs]);
  // /api/jobs is all-chains; an impl job's request.proxy_address is same-chain
  // as the job. Key the impl-hide set on the composite (chain, proxy_address)
  // so a proxy address on one chain never hides a standalone twin on another.
  const implProxyKeys = useMemo(
    () =>
      new Set(
        allJobs
          .map((j) => {
            const p = (j.request?.proxy_address || "").toLowerCase();
            return p ? entityKey(j.request?.chain, p) : null;
          })
          .filter(Boolean),
      ),
    [allJobs],
  );
  const visiblePipelineJobs = useMemo(() => {
    const cutoff = windowCutoff(timeWindow, now);
    return allJobs.filter((j) => {
      const isActive = ACTIVE_STATUSES.has(j.status);
      const isRunning = j.status === "queued" || j.status === "processing";
      if (j.is_proxy && !isRunning) return false;
      if (!j.is_proxy && j.address && implProxyKeys.has(entityKey(j.request?.chain, j.address.toLowerCase())) && !isRunning) return false;
      // Hide the completed company-discovery *shell* (company set, no address)
      // once its child contract jobs exist — but keep completed contract jobs
      // (they have an address) so they show in History.
      if (j.company && !j.address && hasChildJobs && j.status === "completed") return false;
      // Live work is always visible; everything else is window-scoped so old
      // red dots don't persist forever.
      if (!isActive) {
        const t = new Date(j.updated_at || j.created_at).getTime();
        if (t < cutoff) return false;
      }
      return true;
    });
  }, [allJobs, hasChildJobs, implProxyKeys, timeWindow, now]);

  const activeJobs = useMemo(
    () =>
      visiblePipelineJobs
        .filter((j) => ACTIVE_STATUSES.has(j.status))
        .sort((a, b) => {
          const ra = a.status === "processing" ? 0 : 1;
          const rb = b.status === "processing" ? 0 : 1;
          if (ra !== rb) return ra - rb;
          return sortByUpdatedAtDesc(a, b);
        }),
    [visiblePipelineJobs],
  );

  const historyAll = useMemo(
    () => visiblePipelineJobs.filter((j) => HISTORY_STATUSES.has(j.status)).sort(sortByUpdatedAtDesc),
    [visiblePipelineJobs],
  );

  const historyCounts = useMemo(
    () => ({
      all: historyAll.length,
      completed: historyAll.filter((j) => j.status === "completed").length,
      failed: historyAll.filter((j) => j.status === "failed").length,
      terminal: historyAll.filter((j) => j.status === "failed_terminal").length,
    }),
    [historyAll],
  );

  const historyJobs = useMemo(() => {
    let list = historyAll;
    if (historyFilter === "completed") list = list.filter((j) => j.status === "completed");
    else if (historyFilter === "failed") list = list.filter((j) => j.status === "failed");
    else if (historyFilter === "failed_terminal") list = list.filter((j) => j.status === "failed_terminal");
    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter((j) =>
        [j.name, j.address, j.company, j.worker_id, j.trace_id].some(
          (v) => v && String(v).toLowerCase().includes(q),
        ),
      );
    }
    return list.slice(0, 100);
  }, [historyAll, historyFilter, search]);

  // One source per number: header total ← /api/stats (all-time); active count
  // + running/queued chips ← /api/fleet.jobs (live), falling back to the
  // derived counts when fleet hasn't loaded.
  const fleetJobs = fleet?.jobs;
  const liveProcessing = fleetJobs?.processing ?? activeJobs.filter((j) => j.status === "processing").length;
  const liveQueued = fleetJobs?.queued ?? activeJobs.filter((j) => j.status === "queued").length;
  const liveActive = liveProcessing + liveQueued;
  const totalJobs = stats?.total_jobs ?? allJobs.length;

  const selectJob = (id) => setSelected({ type: "job", id });
  const selectProcess = (key) => setSelected((prev) => (prev?.type === "process" && prev.key === key ? null : { type: "process", key }));
  const clearSelection = () => setSelected(null);
  const selectedJob = selected?.type === "job" ? allJobs.find((j) => j.job_id === selected.id) || null : null;

  return (
    <div className="page">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Jobs</p>
          <h2>{totalJobs} total · {liveActive} active</h2>
        </div>
      </div>

      <FleetStrip fleet={fleet} selected={selected} onSelectProcess={selectProcess} rates={fleetRates} />

      <div className="split">
        <div>
          <section className="zone zone-active-wrap">
            <div className="zone-head">
              <div>
                <p className="eyebrow" style={{ color: "#fbbf24" }}>Active · queued + processing</p>
                <h2>{liveActive} in flight</h2>
              </div>
              <div className="chips">
                <span className="chip" style={{ background: "rgba(245,158,11,.12)", color: "#fbbf24" }}>{liveProcessing} running</span>
                <span className="chip" style={{ background: "rgba(148,163,184,.12)", color: "#cbd5e1" }}>{liveQueued} queued</span>
              </div>
            </div>
            <div className="runs zone-active">
              <div className="runs-head">
                <span />
                <span>Job</span>
                <span>Stage</span>
                <span>Live progress</span>
                <span>Elapsed</span>
              </div>
              {activeJobs.length === 0 ? (
                <EmptyRow>No active jobs.</EmptyRow>
              ) : (
                activeJobs.map((j) => (
                  <ActiveRow key={j.job_id} job={j} now={now} selected={selected} onSelect={selectJob} />
                ))
              )}
            </div>
          </section>

          <section className="zone zone-hist-wrap">
            <div className="zone-head">
              <div>
                <p className="eyebrow">History · completed + failed</p>
                <h2>{windowLabel(timeWindow)}</h2>
              </div>
              <div className="chips">
                <div className="window-selector" role="group" aria-label="Time window">
                  <span className="window-selector-label">window</span>
                  {TIME_WINDOWS.map((w) => (
                    <button
                      key={w.id}
                      type="button"
                      className={`window-chip${timeWindow === w.id ? " active" : ""}`}
                      onClick={() => setTimeWindow(w.id)}
                      aria-pressed={timeWindow === w.id}
                    >
                      {w.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <FiltersBar
              filter={historyFilter}
              onFilter={setHistoryFilter}
              search={search}
              onSearch={setSearch}
              counts={historyCounts}
            />
            <div className="runs zone-hist">
              <div className="runs-head">
                <span />
                <span>Job</span>
                <span>Stage progress</span>
                <span>Duration</span>
                <span>Started</span>
              </div>
              {historyJobs.length === 0 ? (
                <EmptyRow>No jobs in this window.</EmptyRow>
              ) : (
                historyJobs.map((j) => (
                  <HistoryRow key={j.job_id} job={j} now={now} selected={selected} onSelect={selectJob} />
                ))
              )}
            </div>
          </section>
        </div>

        {selected && <div className="dock-backdrop" onClick={clearSelection} aria-hidden="true" />}
        <div className={`dock${selected ? " open" : ""}`}>
          {selected?.type === "job" && selectedJob ? (
            <JobDetail
              job={selectedJob}
              onClose={clearSelection}
              refreshTick={refreshTick}
              now={now}
            />
          ) : selected?.type === "process" ? (
            <DaemonDetail daemonKey={selected.key} fleet={fleet} onClose={clearSelection} rates={fleetRates} />
          ) : (
            <EmptyDock />
          )}
        </div>
      </div>
    </div>
  );
}
