// Pipeline dashboard regression + behavior tests. Covers:
//   - failed_terminal jobs render (regression: the old bucket initializer
//     dropped them on the floor, leaving terminal failures invisible)
//   - retry indicator and terminal ring appear on the right dots
//   - clicking a dot opens the side panel, /errors + /stage_timings populate
//   - ESC closes the panel
//   - logs deeplink builder shape
//   - completed jobs no longer render as dots (collapse into DONE counter
//     and the completion tape)
//   - time window selector filters historical jobs visible in the tape
//   - completion tape rows and protocol-card rows route through the same
//     drill-in panel as the SVG dots

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";

import PipelineDashboard from "./PipelineDashboard.jsx";
import { buildLogsDeeplink, inferFlyApp } from "./JobDetailPanel.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const NOW_ISO = new Date().toISOString();

function makeJob(overrides = {}) {
  return {
    job_id: "job-base",
    address: "0x1111111111111111111111111111111111111111",
    company: "TestCo",
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
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    ...overrides,
  };
}

const RUNNING_JOB = makeJob({ job_id: "running-1", name: "Running Job", status: "processing", stage: "static" });
const TERMINAL_JOB = makeJob({
  job_id: "terminal-1",
  name: "Terminal Job",
  status: "failed_terminal",
  stage: "resolution",
  retry_count: 3,
  last_failure_kind: "transient",
  trace_id: "abc123def456",
  error: "TimeoutError: Read timed out after 30s",
});
const RETRY_JOB = makeJob({
  job_id: "retry-1",
  name: "Retry Job",
  status: "processing",
  stage: "discovery",
  retry_count: 1,
  last_failure_kind: "transient",
});

function installJobMocks(jobs) {
  setFetchHandler(/^\/api\/jobs$/, () => jobs);
  setFetchHandler(/^\/api\/stats$/, () => ({ unique_addresses: jobs.length }));
  setFetchHandler(/^\/api\/audits\/pipeline$/, () => ({ text_extraction: {}, scope_extraction: {} }));
  setFetchHandler(
    (url) => /^\/api\/jobs\/[^/]+\/errors$/.test(url.pathname),
    (url) => {
      const id = url.pathname.split("/")[3];
      return {
        job_id: id,
        trace_id: id === "terminal-1" ? "abc123def456" : null,
        status: id === "terminal-1" ? "failed_terminal" : "processing",
        stage: "resolution",
        errors: id === "terminal-1"
          ? [
              {
                stage: "resolution",
                severity: "error",
                exc_type: "TimeoutError",
                message: "Read timed out after 30s",
                phase: null,
                trace_id: "abc123def456",
                job_id: id,
                worker_id: "w-01",
                failed_at: NOW_ISO,
                retry_count: 2,
                context: null,
                traceback: null,
              },
            ]
          : [],
      };
    },
  );
  setFetchHandler(
    (url) => /^\/api\/jobs\/[^/]+\/stage_timings$/.test(url.pathname),
    (url) => {
      const id = url.pathname.split("/")[3];
      return {
        job_id: id,
        stage_timings: { resolution: { worker_elapsed_seconds: 512.3 } },
      };
    },
  );
}

describe("PipelineDashboard", () => {
  beforeEach(() => {
    installJobMocks([RUNNING_JOB, TERMINAL_JOB, RETRY_JOB]);
  });

  it("renders failed_terminal jobs in the legend and chip row", async () => {
    render(<PipelineDashboard />);
    // The header chip for terminal failures didn't exist before this rework,
    // and the old buckets dropped failed_terminal jobs entirely.
    await waitFor(() => {
      expect(screen.getByText(/1 terminal/i)).toBeInTheDocument();
    });
    expect(screen.getByText("Terminal")).toBeInTheDocument();
  });

  it("opens the detail panel when a dot is clicked", async () => {
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      expect(container.querySelectorAll("circle").length).toBeGreaterThan(0);
    });
    // Find the SVG <g> that has the terminal job's title and click it.
    const titleEl = await waitFor(() => {
      const found = Array.from(container.querySelectorAll("title")).find((t) =>
        (t.textContent || "").includes("Terminal Job"),
      );
      expect(found).toBeTruthy();
      return found;
    });
    const group = titleEl.parentNode;
    fireEvent.click(group);
    // Panel header shows the job name; the error log section populates from
    // the /errors mock above.
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toBeInTheDocument();
    expect(await within(dialog).findByText("TimeoutError")).toBeInTheDocument();
    expect(await within(dialog).findByText(/Failed \(terminal\)/i)).toBeInTheDocument();
    // Retry button only shown for failed_terminal status. Scope to the
    // dialog because protocol-card rows now also have role="button" and one
    // of them is the "Retry Job" fixture, which collides with the regex.
    expect(within(dialog).getByRole("button", { name: /Retry job/i })).toBeInTheDocument();
  });

  it("closes the detail panel on ESC", async () => {
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      expect(container.querySelectorAll("circle").length).toBeGreaterThan(0);
    });
    const titleEl = await waitFor(() => {
      const found = Array.from(container.querySelectorAll("title")).find((t) =>
        (t.textContent || "").includes("Terminal Job"),
      );
      expect(found).toBeTruthy();
      return found;
    });
    fireEvent.click(titleEl.parentNode);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });

  it("shows the retry stroke on dots with retry_count > 0", async () => {
    const { container } = render(<PipelineDashboard />);
    const retryDot = await waitFor(() => {
      const found = Array.from(container.querySelectorAll("title")).find((t) =>
        (t.textContent || "").includes("Retry Job"),
      );
      expect(found).toBeTruthy();
      // The <circle> sibling carries the stroke — terminal jobs get a thicker
      // red stroke, retry-but-still-running jobs get amber.
      return found.parentNode.querySelector("circle");
    });
    expect(retryDot.getAttribute("stroke")).toBe("#fbbf24");
  });

  it("does not render completed jobs as dots in the SVG", async () => {
    const completed = makeJob({
      job_id: "done-1",
      name: "Done Job",
      status: "completed",
      stage: "done",
      updated_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    });
    installJobMocks([RUNNING_JOB, completed]);
    const { container } = render(<PipelineDashboard />);
    await waitFor(() => {
      expect(container.querySelectorAll("circle").length).toBeGreaterThan(0);
    });
    // Completed jobs collapse into the DONE-column counter; no green dot
    // should be drawn. statusColors.completed is #22c55e.
    const completedDots = Array.from(container.querySelectorAll("circle")).filter(
      (c) => c.getAttribute("fill") === "#22c55e",
    );
    expect(completedDots).toHaveLength(0);
    // The DONE column instead carries the count text and a "completed" label.
    expect(screen.getByText(/COMPLETED · LAST 1H/i)).toBeInTheDocument();
  });
});

describe("PipelineDashboard — time window", () => {
  it("filters old failed_terminal jobs out of the dot view", async () => {
    // 5h-old terminal failure: outside 1h, inside 7d. Live jobs (queued/
    // processing) would still show regardless; failed_terminal should not.
    const oldTerminal = makeJob({
      job_id: "old-terminal",
      name: "Old Terminal",
      status: "failed_terminal",
      stage: "policy",
      retry_count: 3,
      last_failure_kind: "terminal",
      updated_at: new Date(Date.now() - 5 * 60 * 60_000).toISOString(),
    });
    installJobMocks([oldTerminal]);
    render(<PipelineDashboard />);
    // Default 1h: terminal chip should be absent because the only terminal
    // job is outside the window.
    await waitFor(() => {
      expect(screen.getByText(/Pipeline Status/i)).toBeInTheDocument();
    });
    expect(screen.queryByText(/1 terminal/i)).not.toBeInTheDocument();
    // Switch to 7d → the terminal job is back in scope and the chip appears.
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    await waitFor(() => {
      expect(screen.getByText(/1 terminal/i)).toBeInTheDocument();
    });
  });

  it("switching the window updates the completion tape", async () => {
    const recent = makeJob({
      job_id: "recent", name: "Recent Done", status: "completed", stage: "done",
      updated_at: new Date(Date.now() - 30 * 60_000).toISOString(),
    });
    const older = makeJob({
      job_id: "older", name: "Older Done", status: "completed", stage: "done",
      updated_at: new Date(Date.now() - 5 * 60 * 60_000).toISOString(),
    });
    installJobMocks([recent, older]);
    render(<PipelineDashboard />);
    // Default 1h: only the 30-min-old one shows.
    await waitFor(() => {
      expect(screen.getByText("Recent Done")).toBeInTheDocument();
    });
    expect(screen.queryByText("Older Done")).not.toBeInTheDocument();
    // Switch to 7d → both jobs appear.
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    await waitFor(() => {
      expect(screen.getByText("Older Done")).toBeInTheDocument();
    });
    expect(screen.getByText("Recent Done")).toBeInTheDocument();
  });
});

describe("PipelineDashboard — drill-in parity", () => {
  it("clicking a completion tape row opens the same detail panel as a dot", async () => {
    const recent = makeJob({
      job_id: "recent",
      name: "Recent Done",
      status: "completed",
      stage: "done",
      updated_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    });
    installJobMocks([recent]);
    render(<PipelineDashboard />);
    const nameNode = await screen.findByText("Recent Done");
    const row = nameNode.closest(".completion-row");
    expect(row).toBeTruthy();
    fireEvent.click(row);
    // Same dialog landmark as the dot-click path.
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("clicking a running protocol-card row opens the detail panel", async () => {
    // ProtocolCard renders inline children for running/failed jobs grouped
    // by company. A row click should route through onOpenJob = setSelectedJobId.
    const job = makeJob({
      job_id: "proc-1",
      name: "Active Proc",
      company: "AcmeCo",
      status: "processing",
      stage: "static",
      detail: "Building",
    });
    installJobMocks([job]);
    render(<PipelineDashboard />);
    const nameNode = await screen.findByText("Active Proc");
    const row = nameNode.closest(".protocol-child");
    expect(row).toBeTruthy();
    fireEvent.click(row);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });
});

describe("buildLogsDeeplink", () => {
  it("returns null when no trace_id is provided", () => {
    expect(buildLogsDeeplink(null)).toBeNull();
    expect(buildLogsDeeplink("")).toBeNull();
  });

  it("builds a Grafana explore URL that filters on the trace_id", () => {
    // jsdom hostname is "localhost" so the default call falls back to the
    // wildcard selector — both behaviors are covered separately below.
    const href = buildLogsDeeplink("abc123def456");
    expect(href).toMatch(/^https:\/\/protocolsectool\.grafana\.net\/explore\?left=/);
    const left = JSON.parse(decodeURIComponent(href.split("left=")[1]));
    expect(left.datasource).toBe("grafanacloud-logs");
    expect(left.queries[0].expr).toContain("abc123def456");
    expect(left.queries[0].expr).toContain('|=');
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
    expect(left.queries[0].expr).toContain('service_name=~');
    expect(left.queries[0].expr).not.toContain("fly_app_name");
  });
});

describe("inferFlyApp", () => {
  it("recognizes prod and PR preview hostnames; returns null otherwise", () => {
    expect(inferFlyApp("psat.fly.dev")).toBe("psat");
    expect(inferFlyApp("psat-pr-1.fly.dev")).toBe("psat-pr-1");
    expect(inferFlyApp("psat-pr-123.fly.dev")).toBe("psat-pr-123");
    expect(inferFlyApp("psat-pr-90.fly.dev")).toBe("psat-pr-90");
    expect(inferFlyApp("localhost")).toBeNull();
    expect(inferFlyApp("example.com")).toBeNull();
    expect(inferFlyApp("evil-psat.fly.dev.attacker.com")).toBeNull();
    expect(inferFlyApp("")).toBeNull();
    expect(inferFlyApp(null)).toBeNull();
  });
});
