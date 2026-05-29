import { test, expect } from "@playwright/test";

// E2E for the rebuilt /monitor job dashboard: the fleet system-health strip,
// the Active/History runs tables, and the docked master-detail drill-in for
// both a job and a fleet process. Route-mocks the five endpoints the page
// polls so it runs offline.
test.describe("job monitor", () => {
  test.beforeEach(async ({ page }) => {
    const now = Date.now();
    const iso = (msAgo) => new Date(now - msAgo).toISOString();

    // Catch-all first so the specific routes registered after it win.
    await page.route(
      (url) => url.pathname.startsWith("/api/"),
      (route) => route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
    );

    await page.route(/\/api\/jobs(\?|$)/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { job_id: "j1", company: "etherfi", address: null, name: "weETH", status: "processing", stage: "static", detail: "Slither running · 14 deps · 3 discovered", request: {}, error: null, is_proxy: false, retry_count: 0, worker_id: "StaticWorker-441", trace_id: "t1", created_at: iso(130_000), updated_at: iso(2_000) },
          { job_id: "j2", company: "lido", address: null, name: "lido", status: "queued", stage: "discovery", detail: "waiting for discovery worker", request: {}, error: null, is_proxy: false, retry_count: 0, created_at: iso(2_000), updated_at: iso(2_000) },
          { job_id: "j3", company: "etherfi", address: "0x2222222222222222222222222222222222222222", name: "LRTSquaredCore", status: "completed", stage: "done", detail: "Analysis complete", request: {}, error: null, is_proxy: false, retry_count: 0, created_at: iso(17 * 60_000), updated_at: iso(12 * 60_000) },
          { job_id: "j4", company: "etherfi", address: "0x3333333333333333333333333333333333333333", name: "AvsOperator", status: "failed_terminal", stage: "static", detail: null, request: { proxy_address: "0x9999999999999999999999999999999999999999" }, error: "RuntimeError: No source files found in DB", is_proxy: false, retry_count: 2, last_failure_kind: "transient", trace_id: "t4", created_at: iso(61 * 60_000), updated_at: iso(60 * 60_000) },
        ]),
      }),
    );

    await page.route(/\/api\/stats/, (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ unique_addresses: 3, total_jobs: 133, completed_jobs: 126, failed_jobs: 8 }) }),
    );

    await page.route(/\/api\/fleet$/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          now: new Date(now).toISOString(),
          jobs: { queued: 5, processing: 3, completed: 126, failed: 1, failed_terminal: 7, by_stage: {} },
          daemons: [
            { process: "coverage_verify", kind: "drainer", label: "Coverage / source-equivalence", status: "idle", last_beat_at: iso(2_000), beat_age_s: 2, alive: true, stale: false, detail: null, work: { by_equivalence_status: { hash_mismatch: 653, commit_not_found: 216, proven: 65 }, total: 934 } },
            { process: "audit_text_extraction", kind: "drainer", label: "Audit text extraction", status: "running", last_beat_at: iso(3_000), beat_age_s: 3, alive: true, stale: false, detail: null, work: { processing: 1, pending: 0, failed: 0 } },
            { process: "audit_scope_extraction", kind: "drainer", label: "Audit scope extraction", status: "running", last_beat_at: iso(3_000), beat_age_s: 3, alive: true, stale: false, detail: null, work: { processing: 0, pending: 0, failed: 1 } },
            { process: "event_log_indexer", kind: "indexer", label: "Event-log indexer", status: "error", last_beat_at: iso(33_000), beat_age_s: 33, alive: true, stale: false, detail: { enrolled_last_pass: 0, inserted_last_pass: 0 }, work: { cursors: 2, stalest_run_age_s: 337_000, max_indexed_block: 0 } },
            { process: "enrollment_reconciler", kind: "daemon", label: "Enrollment reconciler", status: "unknown", last_beat_at: null, beat_age_s: null, alive: false, stale: true, detail: null, work: null },
          ],
          watchers: { monitored_contracts: 12, active: 9, last_update_at: iso(311_040_000), last_update_age_s: 311_040, tvl_last_snapshot_at: iso(311_040_000), tvl_last_snapshot_age_s: 311_040 },
        }),
      }),
    );

    await page.route(/\/api\/audits\/pipeline/, (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ text_extraction: {}, scope_extraction: {} }) }),
    );

    await page.route(/\/api\/jobs\/[^/]+\/stage_timings/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          job_id: "j3",
          stage_timings: {
            resolution: { stage: "resolution", elapsed_s: 52.2, worker_id: "ResolutionWorker-441", status: "success", started_at: "2026-05-28T22:03:54Z", ended_at: "2026-05-28T22:04:47Z", metrics: { controllers_resolved: 18, block_number: 19_230_000 } },
            discovery: { stage: "discovery", elapsed_s: 36.4, worker_id: "DiscoveryWorker-441", status: "success", started_at: "2026-05-28T22:01:03Z", ended_at: "2026-05-28T22:01:39Z", metrics: { contracts_discovered: 35, audit_reports: 4 } },
          },
        }),
      }),
    );

    await page.route(/\/api\/jobs\/[^/]+\/errors/, (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ job_id: "j", trace_id: null, status: "completed", stage: "done", errors: [] }) }),
    );
  });

  test("renders the fleet strip, both zones, and drills into a job and a process", async ({ page }) => {
    const errors = [];
    page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(`console.error: ${m.text()}`);
    });

    await page.goto("/monitor");

    // Header counts: total from /api/stats, active from /api/fleet.jobs.
    await expect(page.getByText("133 total · 8 active")).toBeVisible();

    // Fleet strip: one pill per daemon + a watchers pill, with an unhealthy summary.
    const strip = page.locator(".sys-strip");
    await expect(strip.locator(".sys-pill")).toHaveCount(6);
    await expect(strip.locator(".sys-pill.err", { hasText: "Event indexer" })).toBeVisible();
    await expect(strip.getByText(/unhealthy/)).toBeVisible();

    // Two zones split by status.
    await expect(page.locator(".zone-active .run-row", { hasText: "weETH" })).toBeVisible();
    await expect(page.locator(".zone-hist .run-row", { hasText: "LRTSquaredCore" })).toBeVisible();
    // Impl flag on the terminal job (request.proxy_address set).
    await expect(page.locator(".zone-hist .run-row", { hasText: "AvsOperator (impl)" })).toBeVisible();

    // Default dock is the empty placeholder.
    await expect(page.locator(".dock .dock-empty")).toBeVisible();

    // Drill into a completed job → docked timeline reads elapsed_s.
    await page.locator(".zone-hist .run-row", { hasText: "LRTSquaredCore" }).click();
    const dock = page.locator(".dock");
    await expect(dock.getByText("Stage timeline")).toBeVisible();
    await expect(dock.getByText("36.4s")).toBeVisible();
    // Pipeline order, not the resolution-first payload order.
    await expect(dock.locator(".jp-stage-name").first()).toHaveText("DISCOVERY");
    // Per-stage worker (sub-line), not the null list-row one.
    await expect(dock.getByText(/DiscoveryWorker-441/)).toBeVisible();

    // Drill into a terminal job → Retry offered.
    await page.locator(".zone-hist .run-row", { hasText: "AvsOperator" }).click();
    await expect(dock.getByRole("button", { name: /Retry job/i })).toBeVisible();

    // Drill into a fleet process → DaemonDetail fills the same dock.
    await page.locator(".sys-pill", { hasText: "Coverage verify" }).click();
    await expect(dock.getByText("Coverage / source-equivalence")).toBeVisible();
    await expect(dock.getByText(/mismatch 653/)).toBeVisible();

    expect(errors, errors.join("\n")).toEqual([]);
  });
});
