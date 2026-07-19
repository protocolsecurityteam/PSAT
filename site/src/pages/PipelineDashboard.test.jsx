// Job monitor (/monitor) behavior tests for the runs-table master-detail
// rebuild. Covers:
//   - Active/History split by status; StageProgress 6-segment bar
//   - Fleet strip tone states + "N unhealthy" summary
//   - Select a job → docked JobDetail: stage timeline reads elapsed_s (the
//     regression — old panel read elapsed_seconds and showed "—"), renders
//     metric chips, in PIPELINE ORDER, with the per-stage worker
//   - Select a fleet pill → DaemonDetail in the same dock
//   - Empty dock placeholder; History filter + search; terminal → Retry POST
//   - buildLogsDeeplink / inferFlyApp helper shapes (unchanged)

import React from "react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor, within, act } from "@testing-library/react";

import PipelineDashboard from "./PipelineDashboard.jsx";
import { computeFleetRates, daemonTone } from "./FleetStrip.jsx";
import { buildLogsDeeplink, inferFlyApp } from "./JobDetailPanel.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const NOW = Date.now();
const isoAgo = (ms) => new Date(NOW - ms).toISOString();

function makeJob(overrides = {}) {
  return {
    job_id: "job-base",
    address: "0x1111111111111111111111111111111111111111",
    company: "etherfi",
    name: null,
    status: "processing",
    stage: "static",
    detail: null,
    request: null,
    error: null,
    worker_id: "w-01",
    trace_id: "trace-base",
    is_proxy: false,
    retry_count: 0,
    next_attempt_at: null,
    last_failure_kind: null,
    created_at: isoAgo(130_000),
    updated_at: isoAgo(2_000),
    ...overrides,
  };
}

const RUNNING = makeJob({ job_id: "run-1", name: "weETH", status: "processing", stage: "static", detail: "Slither running · 14 deps · 3 discovered" });
const QUEUED = makeJob({ job_id: "q-1", name: "lido", company: "lido", status: "queued", stage: "discovery", created_at: isoAgo(1_000), updated_at: isoAgo(1_000) });
const DONE = makeJob({ job_id: "done-1", name: "LRTSquaredCore", status: "completed", stage: "done", updated_at: isoAgo(12 * 60_000), created_at: isoAgo(17 * 60_000) });
const FAILED = makeJob({ job_id: "fail-1", name: "stETH", company: "lido", status: "failed", stage: "static", error: "TimeoutError: Read timed out after 30s", retry_count: 1, updated_at: isoAgo(20_000) });
const TERMINAL = makeJob({
  job_id: "term-1",
  name: "AvsOperator",
  status: "failed_terminal",
  stage: "static",
  retry_count: 2,
  last_failure_kind: "transient",
  trace_id: "abc123def456",
  error: "RuntimeError: No source files found in DB",
  updated_at: isoAgo(60 * 60_000),
  created_at: isoAgo(61 * 60_000),
});

const FLEET = {
  now: new Date(NOW).toISOString(),
  jobs: { queued: 5, processing: 3, completed: 126, failed: 1, failed_terminal: 7, by_stage: {} },
  daemons: [
    { process: "coverage_verify", kind: "drainer", label: "Coverage / source-equivalence", status: "idle", last_beat_at: isoAgo(2_000), beat_age_s: 2, alive: true, stale: false, detail: null, work: { by_equivalence_status: { hash_mismatch: 653, commit_not_found: 216, proven: 65 }, total: 934 } },
    { process: "audit_text_extraction", kind: "drainer", label: "Audit text extraction", status: "running", last_beat_at: isoAgo(3_000), beat_age_s: 3, alive: true, stale: false, detail: null, work: { processing: 1, pending: 0, failed: 0 } },
    { process: "audit_scope_extraction", kind: "drainer", label: "Audit scope extraction", status: "running", last_beat_at: isoAgo(3_000), beat_age_s: 3, alive: true, stale: false, detail: null, work: { processing: 0, pending: 0, failed: 1 } },
    { process: "event_log_indexer", kind: "indexer", label: "Event-log indexer", status: "error", last_beat_at: isoAgo(33_000), beat_age_s: 33, alive: true, stale: false, detail: { enrolled_last_pass: 0, inserted_last_pass: 0 }, work: { cursors: 2, stalest_run_age_s: 337_000, max_indexed_block: 0 } },
    { process: "enrollment_reconciler", kind: "daemon", label: "Enrollment reconciler", status: "unknown", last_beat_at: null, beat_age_s: null, alive: false, stale: true, detail: null, work: null },
  ],
  watchers: { monitored_contracts: 12, active: 9, last_update_at: isoAgo(311_040_000), last_update_age_s: 311_040, tvl_last_snapshot_at: isoAgo(311_040_000), tvl_last_snapshot_age_s: 311_040 },
};

const STAGE_TIMINGS = {
  job_id: "done-1",
  stage_timings: {
    // Deliberately NOT in pipeline order — proves the panel re-sorts.
    resolution: { schema_version: "2", stage: "resolution", started_at: "2026-05-28T22:03:54Z", ended_at: "2026-05-28T22:04:47Z", elapsed_s: 52.2, worker_id: "ResolutionWorker-441", status: "success", metrics: { controllers_resolved: 18, block_number: 19_230_000, graph_nodes: 22, graph_edges: 31 } },
    discovery: { schema_version: "2", stage: "discovery", started_at: "2026-05-28T22:01:03Z", ended_at: "2026-05-28T22:01:39Z", elapsed_s: 36.4, worker_id: "DiscoveryWorker-441", status: "success", metrics: { contracts_discovered: 35, audit_reports: 4, source_files: 35 } },
    static: { schema_version: "2", stage: "static", started_at: "2026-05-28T22:01:46Z", ended_at: "2026-05-28T22:03:54Z", elapsed_s: 128, worker_id: "StaticWorker-441", status: "success", metrics: { is_proxy: true, static_dependencies: 12, dependencies: 14 } },
  },
};

let retryCalls = [];

function installMocks(jobs, { fleet = FLEET, stageTimings = STAGE_TIMINGS } = {}) {
  retryCalls = [];
  setFetchHandler(/^\/api\/jobs$/, () => jobs);
  setFetchHandler(/^\/api\/stats$/, () => ({ unique_addresses: jobs.length, total_jobs: 133, completed_jobs: 126, failed_jobs: 8 }));
  setFetchHandler(/^\/api\/fleet$/, () => fleet);
  setFetchHandler(
    (url, init) => /^\/api\/jobs\/[^/]+\/retry$/.test(url.pathname) && (init?.method || "GET") === "POST",
    (url) => {
      retryCalls.push(url.pathname);
      const id = url.pathname.split("/")[3];
      return makeJob({ job_id: id, status: "queued", stage: "static" });
    },
  );
  setFetchHandler(
    (url) => /^\/api\/jobs\/[^/]+\/errors$/.test(url.pathname),
    (url) => {
      const id = url.pathname.split("/")[3];
      const isTerm = id === "term-1";
      return {
        job_id: id,
        trace_id: isTerm ? "abc123def456" : null,
        status: isTerm ? "failed_terminal" : "completed",
        stage: "static",
        errors: isTerm
          ? [{ stage: "static", severity: "error", exc_type: "builtins.RuntimeError", message: "No source files found in DB", phase: null, trace_id: "abc123def456", job_id: id, worker_id: "StaticWorker-637", failed_at: NOW, retry_count: 2, context: null, traceback: "Traceback...\nRuntimeError: No source files found in DB" }]
          : [],
      };
    },
  );
  setFetchHandler(
    (url) => /^\/api\/jobs\/[^/]+\/stage_timings$/.test(url.pathname),
    (url) => ({ ...stageTimings, job_id: url.pathname.split("/")[3] }),
  );
}

describe("PipelineDashboard — zones", () => {
  beforeEach(() => {
    installMocks([RUNNING, QUEUED, DONE, FAILED, TERMINAL]);
  });

  it("splits jobs into Active (queued/processing) and History (completed/failed) zones", async () => {
    const { container } = render(<PipelineDashboard />);
    const active = await waitFor(() => {
      const el = container.querySelector(".zone-active");
      expect(within(el).getByText("weETH")).toBeInTheDocument();
      return el;
    });
    // queued + processing in Active (weETH processing, lido queued).
    expect(active.querySelectorAll(".run-row")).toHaveLength(2);
    expect(within(active).getByText("weETH")).toBeInTheDocument();
    // completed + failed in History, not Active.
    expect(within(active).queryByText("LRTSquaredCore")).not.toBeInTheDocument();
    const hist = container.querySelector(".zone-hist");
    expect(within(hist).getByText("LRTSquaredCore")).toBeInTheDocument();
    expect(within(hist).getByText("stETH")).toBeInTheDocument();
    expect(within(hist).getByText("AvsOperator")).toBeInTheDocument();
  });

  it("renders a 6-segment StageProgress bar: all filled when done, partial mid-flight", async () => {
    const { container } = render(<PipelineDashboard />);
    const doneRow = await waitFor(() => {
      const b = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((r) =>
        r.textContent.includes("LRTSquaredCore"),
      );
      expect(b).toBeTruthy();
      return b;
    });
    const filled = (row) =>
      Array.from(row.querySelectorAll(".prog i")).filter((s) => (s.getAttribute("style") || "").includes("background"));
    // Completed → all six segments carry a fill.
    expect(doneRow.querySelectorAll(".prog i")).toHaveLength(6);
    expect(filled(doneRow)).toHaveLength(6);
    expect(within(doneRow).getByText("DONE")).toBeInTheDocument();
    // Processing at `static` (CORE idx 2) → 3 filled (2 done + current), 3 empty.
    const runRow = Array.from(container.querySelectorAll(".zone-active .run-row")).find((r) =>
      r.textContent.includes("weETH"),
    );
    expect(filled(runRow)).toHaveLength(3);
    expect(within(runRow).getByText("STATIC")).toBeInTheDocument();
  });

  it("shows the failure reason + retry indicator on a failed History row", async () => {
    const { container } = render(<PipelineDashboard />);
    const failRow = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((x) =>
        x.textContent.includes("stETH"),
      );
      expect(r).toBeTruthy();
      return r;
    });
    expect(within(failRow).getByText(/RPC Timeout/)).toBeInTheDocument();
    expect(within(failRow).getByText(/↻1/)).toBeInTheDocument();
  });
});

describe("PipelineDashboard — fleet strip", () => {
  beforeEach(() => {
    installMocks([RUNNING]);
  });

  it("renders a pill per daemon with health-derived tone + an unhealthy summary", async () => {
    const { container } = render(<PipelineDashboard />);
    // Wait for the pills themselves — .sys-strip renders immediately (just the
    // "Fleet" label) before /api/fleet resolves, so waiting on it races the
    // fetch and finds zero pills.
    const errPill = await waitFor(() => {
      const p = Array.from(container.querySelectorAll(".sys-strip .sys-pill")).find((x) =>
        x.textContent.includes("Event indexer"),
      );
      expect(p).toBeTruthy();
      return p;
    });
    const strip = container.querySelector(".sys-strip");
    // error daemon → .err pill; failed-audit daemon → .warn; watchers stale → .warn.
    expect(errPill.className).toContain("err");
    const scopePill = Array.from(strip.querySelectorAll(".sys-pill")).find((p) => p.textContent.includes("Audit scope"));
    expect(scopePill.className).toContain("warn");
    // event-indexer (error) + reconciler (never beat → stale) + watchers (stale) = 3
    expect(within(strip).getByText(/3 unhealthy/)).toBeInTheDocument();
  });

  it("selecting a fleet pill fills the dock with DaemonDetail", async () => {
    const { container } = render(<PipelineDashboard />);
    const covPill = await waitFor(() => {
      const p = Array.from(container.querySelectorAll(".sys-pill")).find((x) => x.textContent.includes("Coverage verify"));
      expect(p).toBeTruthy();
      return p;
    });
    fireEvent.click(covPill);
    const dock = container.querySelector(".dock");
    expect(await within(dock).findByText("Coverage / source-equivalence")).toBeInTheDocument();
    // Equivalence breakdown bar + work counts.
    expect(within(dock).getByText(/mismatch 653/)).toBeInTheDocument();
    expect(within(dock).getByText("coverage_verify")).toBeInTheDocument();
  });

  it("flags a backfill-lagging indexer (cursor still backfilling from creation) as warn with a blocks-behind alert", async () => {
    // A beating, non-error indexer whose leading cursor is at head but one
    // cursor is still backfilling from its contract's creation block —
    // invisible in max_indexed_block alone.
    const laggingFleet = {
      now: new Date(NOW).toISOString(),
      jobs: { queued: 0, processing: 0, by_stage: {} },
      daemons: [
        { process: "event_log_indexer", kind: "indexer", label: "Event-log indexer", status: "idle", last_beat_at: isoAgo(2_000), beat_age_s: 2, alive: true, stale: false, detail: null, work: { cursors: 2, stalest_run_age_s: 5, max_indexed_block: 19_000_000, min_indexed_block: 12_700_000, block_spread: 6_300_000, lagging_cursors: 1 } },
      ],
      watchers: { monitored_contracts: 0, active: 0, last_update_at: new Date(NOW).toISOString(), last_update_age_s: 5, tvl_last_snapshot_at: null, tvl_last_snapshot_age_s: null },
    };
    installMocks([RUNNING], { fleet: laggingFleet });
    const { container } = render(<PipelineDashboard />);
    const pill = await waitFor(() => {
      const p = Array.from(container.querySelectorAll(".sys-pill")).find((x) => x.textContent.includes("Event indexer"));
      expect(p).toBeTruthy();
      return p;
    });
    // Lagging-but-beating → warn pill + "N behind" sub.
    expect(pill.className).toContain("warn");
    expect(within(pill).getByText(/1 behind/)).toBeInTheDocument();
    fireEvent.click(pill);
    const dock = container.querySelector(".dock");
    expect(await within(dock).findByText(/1 cursor far behind head/)).toBeInTheDocument();
    expect(within(dock).getByText("blocks behind")).toBeInTheDocument();
  });
});

describe("PipelineDashboard — fleet triad (Option B)", () => {
  const baseWatchers = {
    monitored_contracts: 0,
    active: 0,
    last_update_at: new Date(NOW).toISOString(),
    last_update_age_s: 5,
    tvl_last_snapshot_at: null,
    tvl_last_snapshot_age_s: null,
  };

  it("renders backlog, oldest-waiting age, and the per-pass throughput count in the daemon detail", async () => {
    const fleet = {
      now: new Date(NOW).toISOString(),
      jobs: { queued: 0, processing: 0, by_stage: {} },
      daemons: [
        {
          process: "audit_text_extraction", kind: "drainer", label: "Audit text extraction", status: "running",
          last_beat_at: isoAgo(2_000), beat_age_s: 2, alive: true, stale: false,
          detail: { claimed_last_pass: 7 },
          work: { processing: 2, pending: 12, failed: 0, backlog: 12, oldest_pending_age_s: 240 },
        },
      ],
      watchers: baseWatchers,
    };
    installMocks([RUNNING], { fleet });
    const { container } = render(<PipelineDashboard />);
    const pill = await waitFor(() => {
      const p = Array.from(container.querySelectorAll(".sys-pill")).find((x) => x.textContent.includes("Audit text"));
      expect(p).toBeTruthy();
      return p;
    });
    fireEvent.click(pill);
    const dock = container.querySelector(".dock");
    // Triad rows.
    expect(await within(dock).findByText("backlog")).toBeInTheDocument();
    expect(within(dock).getByText("oldest waiting")).toBeInTheDocument();
    expect(within(dock).getByText("4m")).toBeInTheDocument(); // humanAge(240)
    // Per-pass throughput surfaces from the heartbeat detail ("Last pass" block).
    expect(within(dock).getByText(/claimed last pass 7/)).toBeInTheDocument();
  });

  it("flags a stuck drainer (old age + zero throughput) as warn and counts it unhealthy", async () => {
    const fleet = {
      now: new Date(NOW).toISOString(),
      jobs: { queued: 0, processing: 0, by_stage: {} },
      daemons: [
        {
          process: "audit_scope_extraction", kind: "drainer", label: "Audit scope extraction", status: "idle",
          last_beat_at: isoAgo(3_000), beat_age_s: 3, alive: true, stale: false,
          detail: { claimed_last_pass: 0 },
          work: { processing: 0, pending: 5, failed: 0, backlog: 5, oldest_pending_age_s: 1800 },
        },
      ],
      watchers: baseWatchers,
    };
    installMocks([RUNNING], { fleet });
    const { container } = render(<PipelineDashboard />);
    const pill = await waitFor(() => {
      const p = Array.from(container.querySelectorAll(".sys-pill")).find((x) => x.textContent.includes("Audit scope"));
      expect(p).toBeTruthy();
      return p;
    });
    // Stuck → warn pill, "stuck" sub, and counted in the unhealthy summary.
    expect(pill.className).toContain("warn");
    expect(within(pill).getByText("stuck")).toBeInTheDocument();
    const strip = container.querySelector(".sys-strip");
    expect(within(strip).getByText(/1 unhealthy/)).toBeInTheDocument();
    fireEvent.click(pill);
    const dock = container.querySelector(".dock");
    expect(await within(dock).findByText(/Stuck — oldest item waiting/)).toBeInTheDocument();
  });

  it("computeFleetRates diffs two snapshots into per-process progress/backlog rates", () => {
    const anchors = {};
    const snap = (now, block, backlog) => ({
      now,
      daemons: [
        { process: "event_log_indexer", work: { max_indexed_block: block } },
        { process: "audit_text_extraction", work: { backlog } },
      ],
      watchers: { max_scanned_block: block },
    });
    // First snapshot seeds anchors — no rate yet.
    const first = computeFleetRates(anchors, snap("2026-05-28T12:00:00.000Z", 19_000_000, 30));
    expect(first.event_log_indexer.blocksPerMin).toBeNull();
    expect(first.audit_text_extraction.backlogPerMin).toBeNull();
    // 60s later: +2400 blocks indexed, backlog drained by 10.
    const second = computeFleetRates(anchors, snap("2026-05-28T12:01:00.000Z", 19_002_400, 20));
    expect(second.event_log_indexer.blocksPerMin).toBe(2400);
    expect(second.audit_text_extraction.backlogPerMin).toBe(-10);
    expect(second.watchers.blocksPerMin).toBe(2400);
  });

  it("reads a growing backlog as warn (falling behind) and a draining one as healthy", () => {
    const d = {
      process: "audit_text_extraction", status: "running", last_beat_at: new Date(NOW).toISOString(),
      stale: false, detail: { claimed_last_pass: 3 }, work: { backlog: 50, oldest_pending_age_s: 30, failed: 0 },
    };
    expect(daemonTone(d, { backlogPerMin: 5 })).toBe("warn"); // backlog rising → falling behind
    expect(daemonTone(d, { backlogPerMin: -5 })).toBe("ok"); // backlog draining → healthy
    expect(daemonTone(d, {})).toBe("ok"); // no rate yet (first poll) → healthy
  });

  it("shows a frontend-computed progress rate in the dock after two differing polls", async () => {
    vi.useFakeTimers();
    try {
      installMocks([RUNNING]);
      const idx = (nowMs, block) => ({
        process: "event_log_indexer", kind: "indexer", label: "Event-log indexer",
        status: "idle", last_beat_at: new Date(nowMs).toISOString(), beat_age_s: 1, alive: true, stale: false,
        detail: { enrolled_last_pass: 0, inserted_last_pass: 4, windows_scanned: 5, caught_up_cursors: 2, total_cursors: 2 },
        work: { cursors: 2, stalest_run_age_s: 5, max_indexed_block: block, min_indexed_block: block, block_spread: 0, lagging_cursors: 0 },
      });
      const poll = (nowMs, block) => ({
        now: new Date(nowMs).toISOString(),
        jobs: { queued: 0, processing: 0, by_stage: {} },
        daemons: [idx(nowMs, block)],
        watchers: { monitored_contracts: 0, active: 0, last_update_at: new Date(nowMs).toISOString(), last_update_age_s: 1 },
      });
      let n = 0;
      setFetchHandler(/^\/api\/fleet$/, () => (n++ === 0 ? poll(NOW, 19_000_000) : poll(NOW + 60_000, 19_002_400)));

      const { container } = render(<PipelineDashboard />);
      // Poll #1 seeds the anchor; the 2.5s interval fires poll #2 (+2400 blocks
      // over 60s of server time) which the page diffs into a rate.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(2600);
      });

      const pill = Array.from(container.querySelectorAll(".sys-pill")).find((x) => x.textContent.includes("Event indexer"));
      fireEvent.click(pill);
      const dock = container.querySelector(".dock");
      expect(within(dock).getByText("indexing rate")).toBeInTheDocument();
      expect(within(dock).getByText(/\+2\.4K blocks\/min/)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("PipelineDashboard — job drill-in", () => {
  beforeEach(() => {
    installMocks([RUNNING, QUEUED, DONE, FAILED, TERMINAL]);
  });

  it("renders the stage timeline reading elapsed_s, with metric chips, in pipeline order, with per-stage worker", async () => {
    const { container } = render(<PipelineDashboard />);
    const doneRow = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((x) =>
        x.textContent.includes("LRTSquaredCore"),
      );
      expect(r).toBeTruthy();
      return r;
    });
    fireEvent.click(doneRow);
    const dock = container.querySelector(".dock");

    // elapsed_s rendered (regression: old panel read elapsed_seconds → "—").
    expect(await within(dock).findByText("36.4s")).toBeInTheDocument();
    expect(within(dock).getByText("52.2s")).toBeInTheDocument();

    // Metric chips humanized (contracts 35, block 19.23M).
    expect(within(dock).getByText("contracts")).toBeInTheDocument();
    expect(within(dock).getByText("19.23M")).toBeInTheDocument();

    // Pipeline order, not the resolution-first object order. A completed job
    // shows the full CORE path; selection/policy/coverage have no artifact in
    // this mock and render as synthesized "no timing recorded" rows.
    const names = Array.from(dock.querySelectorAll(".jp-stage-name")).map((n) => n.textContent);
    expect(names).toEqual(["DISCOVERY", "SELECTION", "STATIC", "RESOLUTION", "POLICY", "COVERAGE"]);
    expect(within(dock).getAllByText("no timing recorded").length).toBeGreaterThan(0);

    // Per-stage worker (sub-line), not the null list-row worker.
    expect(within(dock).getByText(/DiscoveryWorker-441/)).toBeInTheDocument();
  });

  it("shows stages a failed job already ran even with no timing artifacts (old DB)", async () => {
    // A job that failed at `static` with zero recorded timings (predates the
    // stage-metrics feature) must still show discovery/selection as completed,
    // the failed stage, and the unreached tail — not collapse to one row.
    installMocks([FAILED], { stageTimings: { job_id: "fail-1", stage_timings: {} } });
    const { container } = render(<PipelineDashboard />);
    const row = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((x) => x.textContent.includes("stETH"));
      expect(r).toBeTruthy();
      return r;
    });
    fireEvent.click(row);
    const dock = container.querySelector(".dock");
    await within(dock).findByText("Stage timeline");
    const names = Array.from(dock.querySelectorAll(".jp-stage-name")).map((n) => n.textContent);
    expect(names).toEqual(["DISCOVERY", "SELECTION", "STATIC", "RESOLUTION", "POLICY", "COVERAGE"]);
    expect(within(dock).getAllByText("SUCCESS")).toHaveLength(2); // discovery + selection
    expect(within(dock).getByText("● FAILED")).toBeInTheDocument(); // static
    expect(within(dock).getAllByText("NOT REACHED")).toHaveLength(3); // resolution/policy/coverage
  });

  it("derives a stage's duration from started_at→ended_at when elapsed_s is absent", async () => {
    installMocks([DONE], {
      stageTimings: {
        job_id: "done-1",
        stage_timings: {
          // No elapsed_s — only the timestamp span (22:01:03 → 22:01:39 = 36s).
          discovery: { stage: "discovery", worker_id: "DiscoveryWorker-9", status: "success", started_at: "2026-05-28T22:01:03Z", ended_at: "2026-05-28T22:01:39Z", metrics: {} },
        },
      },
    });
    const { container } = render(<PipelineDashboard />);
    const row = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((x) => x.textContent.includes("LRTSquaredCore"));
      expect(r).toBeTruthy();
      return r;
    });
    fireEvent.click(row);
    const dock = container.querySelector(".dock");
    expect(await within(dock).findByText("36.0s")).toBeInTheDocument();
  });

  it("synthesizes RUNNING + PENDING rows for an in-flight job", async () => {
    installMocks([RUNNING], { stageTimings: { job_id: "run-1", stage_timings: { discovery: { stage: "discovery", elapsed_s: 30, worker_id: "DiscoveryWorker-1", status: "success", metrics: {} }, selection: { stage: "selection", elapsed_s: 6, worker_id: "SelectionWorker-1", status: "success", metrics: {} } } } });
    const { container } = render(<PipelineDashboard />);
    const row = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-active .run-row")).find((x) => x.textContent.includes("weETH"));
      expect(r).toBeTruthy();
      return r;
    });
    fireEvent.click(row);
    const dock = container.querySelector(".dock");
    expect(await within(dock).findByText("● RUNNING")).toBeInTheDocument();
    // Future CORE stages synthesized as PENDING.
    expect(within(dock).getAllByText("PENDING").length).toBeGreaterThan(0);
    // Live detail surfaces (Live-progress block + the running stage's live chip).
    expect(within(dock).getAllByText(/Slither running/).length).toBeGreaterThan(0);
  });

  it("offers Retry on a terminal job and POSTs to the retry endpoint", async () => {
    const { container } = render(<PipelineDashboard />);
    const termRow = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((x) => x.textContent.includes("AvsOperator"));
      expect(r).toBeTruthy();
      return r;
    });
    fireEvent.click(termRow);
    const dock = container.querySelector(".dock");
    expect(await within(dock).findByText(/FAILED \(TERMINAL\)/)).toBeInTheDocument();
    expect(await within(dock).findByText("builtins.RuntimeError")).toBeInTheDocument();
    const retryBtn = within(dock).getByRole("button", { name: /Retry job/i });
    fireEvent.click(retryBtn);
    await waitFor(() => expect(retryCalls).toContain("/api/jobs/term-1/retry"));
  });

  it("ESC clears the selection back to the empty dock", async () => {
    const { container } = render(<PipelineDashboard />);
    const doneRow = await waitFor(() => {
      const r = Array.from(container.querySelectorAll(".zone-hist .run-row")).find((x) => x.textContent.includes("LRTSquaredCore"));
      expect(r).toBeTruthy();
      return r;
    });
    fireEvent.click(doneRow);
    const dock = container.querySelector(".dock");
    await within(dock).findByText("Stage timeline");
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(within(dock).getByText("Select a job or process")).toBeInTheDocument());
  });
});

describe("PipelineDashboard — history filter + search", () => {
  beforeEach(() => {
    installMocks([RUNNING, DONE, FAILED, TERMINAL]);
  });

  it("filters History to Failed and searches by substring", async () => {
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      const hist = container.querySelector(".zone-hist");
      expect(within(hist).getByText("LRTSquaredCore")).toBeInTheDocument();
    });
    // Failed filter → only failed (not completed).
    fireEvent.click(screen.getByRole("button", { name: /^Failed/ }));
    await waitFor(() => {
      const hist = container.querySelector(".zone-hist");
      expect(within(hist).queryByText("LRTSquaredCore")).not.toBeInTheDocument();
      expect(within(hist).getByText("stETH")).toBeInTheDocument();
    });
    // Search narrows further (Active zone is untouched).
    fireEvent.change(screen.getByLabelText("Search history"), { target: { value: "nomatch-zzz" } });
    await waitFor(() => {
      const hist = container.querySelector(".zone-hist");
      expect(within(hist).queryByText("stETH")).not.toBeInTheDocument();
    });
    // Active zone still shows its running job regardless of the History filter.
    expect(within(container.querySelector(".zone-active")).getByText("weETH")).toBeInTheDocument();
  });
});

describe("PipelineDashboard — empty dock", () => {
  it("shows the placeholder when nothing is selected", async () => {
    installMocks([RUNNING]);
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => expect(container.querySelector(".dock")).toBeTruthy());
    expect(within(container.querySelector(".dock")).getByText("Select a job or process")).toBeInTheDocument();
  });
});

describe("PipelineDashboard — dedup", () => {
  it("hides a completed proxy shell but shows its impl child", async () => {
    const proxy = makeJob({ job_id: "px", name: "FiatTokenProxy", address: "0xproxy", status: "completed", stage: "done", is_proxy: true, updated_at: isoAgo(60_000) });
    const impl = makeJob({ job_id: "im", name: "FiatTokenV2_2", address: "0ximpl", status: "completed", stage: "done", request: { proxy_address: "0xproxy" }, updated_at: isoAgo(60_000) });
    installMocks([proxy, impl]);
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      const hist = container.querySelector(".zone-hist");
      expect(within(hist).getByText(/FiatTokenV2_2/)).toBeInTheDocument();
    });
    const hist = container.querySelector(".zone-hist");
    expect(within(hist).queryByText("FiatTokenProxy")).not.toBeInTheDocument();
    // Impl row is flagged (impl).
    expect(within(hist).getByText(/\(impl\)/)).toBeInTheDocument();
  });

  it("keeps a cross-chain standalone job whose address matches another chain's proxy_address", async () => {
    // /api/jobs is all-chains. An ethereum impl job references an ethereum
    // proxy at 0xshared; a base-chain standalone job lives at the SAME address.
    // The impl-hide predicate keys on (chain, proxy_address) so it hides only
    // the same-chain impl — the base twin stays visible.
    const ethImpl = makeJob({
      job_id: "eth-impl", name: "VaultImpl", address: "0xshared", status: "completed", stage: "done",
      request: { proxy_address: "0xshared", chain: "ethereum" }, updated_at: isoAgo(60_000),
    });
    const baseStandalone = makeJob({
      job_id: "base-standalone", name: "BaseVault", company: "protocol-base", address: "0xshared",
      status: "completed", stage: "done", is_proxy: false, request: { chain: "base" }, updated_at: isoAgo(60_000),
    });
    installMocks([ethImpl, baseStandalone]);
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      const hist = container.querySelector(".zone-hist");
      expect(within(hist).getByText("BaseVault")).toBeInTheDocument();
    });
    const hist = container.querySelector(".zone-hist");
    // Base standalone visible; the same-chain impl still hidden.
    expect(within(hist).getByText("BaseVault")).toBeInTheDocument();
    expect(within(hist).queryByText("VaultImpl")).not.toBeInTheDocument();
  });

  it("hides a completed company SHELL but keeps completed company CONTRACT jobs", async () => {
    // A childless+addressed job flips hasChildJobs true. The completed company
    // *shell* (company, no address) drops out; the completed company *contract*
    // (company + address) must stay — it's a real result, not a shell.
    const shell = makeJob({ job_id: "sh", name: "etherfi", company: "etherfi", address: null, status: "completed", stage: "done", updated_at: isoAgo(60_000) });
    const contract = makeJob({ job_id: "ct", name: "LRTSquaredCore", company: "etherfi", address: "0xabc", status: "completed", stage: "done", updated_at: isoAgo(60_000) });
    const standalone = makeJob({ job_id: "st", name: "WETH9", company: null, address: "0xdef", status: "completed", stage: "done", updated_at: isoAgo(60_000) });
    installMocks([shell, contract, standalone]);
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      const hist = container.querySelector(".zone-hist");
      expect(within(hist).getByText("LRTSquaredCore")).toBeInTheDocument();
    });
    const hist = container.querySelector(".zone-hist");
    expect(within(hist).getByText("WETH9")).toBeInTheDocument();
    // The company shell (no address) collapses out → only contract + standalone.
    expect(hist.querySelectorAll(".run-row")).toHaveLength(2);
  });
});

describe("buildLogsDeeplink", () => {
  it("returns null when no trace_id is provided", () => {
    expect(buildLogsDeeplink(null)).toBeNull();
    expect(buildLogsDeeplink("")).toBeNull();
  });

  it("builds a Grafana explore URL that filters on the trace_id", () => {
    const href = buildLogsDeeplink("abc123def456");
    expect(href).toMatch(/^https:\/\/protocolsectool\.grafana\.net\/explore\?left=/);
    const left = JSON.parse(decodeURIComponent(href.split("left=")[1]));
    expect(left.datasource).toBe("grafanacloud-logs");
    expect(left.queries[0].expr).toContain("abc123def456");
    expect(left.queries[0].expr).toContain("|=");
  });

  it("scopes the Loki stream to fly_app_name when hostname matches prod or a preview", () => {
    const prod = buildLogsDeeplink("abc123", { hostname: "psat.fly.dev" });
    const prodLeft = JSON.parse(decodeURIComponent(prod.split("left=")[1]));
    expect(prodLeft.queries[0].expr).toBe('{fly_app_name="psat"} |= "abc123"');

    const preview = buildLogsDeeplink("xyz789", { hostname: "psat-pr-90.fly.dev" });
    const previewLeft = JSON.parse(decodeURIComponent(preview.split("left=")[1]));
    expect(previewLeft.queries[0].expr).toBe('{fly_app_name="psat-pr-90"} |= "xyz789"');
  });

  it("falls back to a wildcard selector when the hostname is unrecognized", () => {
    const href = buildLogsDeeplink("abc123", { hostname: "example.com" });
    const left = JSON.parse(decodeURIComponent(href.split("left=")[1]));
    expect(left.queries[0].expr).toContain("service_name=~");
    expect(left.queries[0].expr).not.toContain("fly_app_name");
  });

  it("derives the time range from the job span when timestamps are provided", () => {
    const now = new Date("2026-05-21T12:00:00Z").getTime();
    const createdAt = new Date("2026-05-18T12:00:00Z").toISOString();
    const updatedAt = new Date("2026-05-18T12:05:00Z").toISOString();
    const href = buildLogsDeeplink("abc123", { now, createdAt, updatedAt });
    const left = JSON.parse(decodeURIComponent(href.split("left=")[1]));
    expect(Number(left.range.from)).toBe(new Date("2026-05-18T11:00:00Z").getTime());
    expect(Number(left.range.to)).toBe(new Date("2026-05-18T13:05:00Z").getTime());
  });

  it("clamps `from` to the 14-day Loki retention floor", () => {
    const now = new Date("2026-05-21T00:00:00Z").getTime();
    const createdAt = new Date("2026-04-21T00:00:00Z").toISOString();
    const updatedAt = new Date("2026-04-21T00:10:00Z").toISOString();
    const href = buildLogsDeeplink("abc123", { now, createdAt, updatedAt });
    const left = JSON.parse(decodeURIComponent(href.split("left=")[1]));
    expect(Number(left.range.from)).toBe(now - 14 * 24 * 60 * 60 * 1000);
    expect(Number(left.range.to)).toBe(now);
  });

  it("falls back to a 14-day window when no timestamps are provided", () => {
    const now = new Date("2026-05-21T00:00:00Z").getTime();
    const href = buildLogsDeeplink("abc123", { now });
    const left = JSON.parse(decodeURIComponent(href.split("left=")[1]));
    expect(Number(left.range.from)).toBe(now - 14 * 24 * 60 * 60 * 1000);
    expect(Number(left.range.to)).toBe(now);
  });
});

describe("inferFlyApp", () => {
  it("recognizes prod and PR preview hostnames; returns null otherwise", () => {
    expect(inferFlyApp("psat.fly.dev")).toBe("psat");
    expect(inferFlyApp("psat-pr-1.fly.dev")).toBe("psat-pr-1");
    expect(inferFlyApp("psat-pr-123.fly.dev")).toBe("psat-pr-123");
    expect(inferFlyApp("localhost")).toBeNull();
    expect(inferFlyApp("example.com")).toBeNull();
    expect(inferFlyApp("evil-psat.fly.dev.attacker.com")).toBeNull();
    expect(inferFlyApp("")).toBeNull();
    expect(inferFlyApp(null)).toBeNull();
  });
});
