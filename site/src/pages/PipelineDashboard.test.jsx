// Pipeline dashboard regression + behavior tests. Covers:
//   - failed_terminal jobs render (regression: the old bucket initializer
//     dropped them on the floor, leaving terminal failures invisible)
//   - retry indicator and terminal ring appear on the right dots
//   - clicking a dot opens the side panel, /errors + /stage_timings populate
//   - ESC closes the panel
//   - logs deeplink builder shape

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

import PipelineDashboard from "./PipelineDashboard.jsx";
import { buildLogsDeeplink } from "./JobDetailPanel.jsx";
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
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(await screen.findByText("TimeoutError")).toBeInTheDocument();
    expect(await screen.findByText(/Failed \(terminal\)/i)).toBeInTheDocument();
    // Retry button only shown for failed_terminal status.
    expect(screen.getByRole("button", { name: /Retry job/i })).toBeInTheDocument();
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
    expect(left.queries[0].expr).toContain('|=');
  });
});
