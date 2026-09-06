import { test, expect } from "@playwright/test";

test("Monitor submits the selected compute target and defaults to Cloud", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("psat_admin_key", "offline-admin"));
  await page.route(url => url.pathname.startsWith("/api/"), route => route.fulfill({ json: {} }));
  await page.route("**/api/analyses", route => route.fulfill({ json: [] }));
  await page.route(/\/api\/jobs(\?|$)/, route => route.fulfill({ json: [] }));
  await page.route("**/api/compute-capabilities", route => route.fulfill({ json: { local_enabled: true } }));
  let submitted;
  await page.route("**/api/analyze", route => {
    submitted = route.request().postDataJSON();
    return route.fulfill({ json: { job_id: "offline-job" } });
  });
  await page.goto("/monitor");
  await page.getByRole("button", { name: "+ New Analysis" }).click();
  await expect(page.getByLabel("Compute")).toHaveValue("cloud");
  await page.getByLabel("Compute").selectOption("local");
  await page.getByLabel("Address or company").fill("0x" + "a".repeat(40));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect.poll(() => submitted?.compute_target).toBe("local");
});

test("Monitor hides the local option until the runtime is ready", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("psat_admin_key", "offline-admin"));
  await page.route(url => url.pathname.startsWith("/api/"), route => route.fulfill({ json: {} }));
  await page.route("**/api/analyses", route => route.fulfill({ json: [] }));
  await page.route(/\/api\/jobs(\?|$)/, route => route.fulfill({ json: [] }));
  await page.goto("/monitor");
  await page.getByRole("button", { name: "+ New Analysis" }).click();
  await expect(page.getByLabel("Compute")).toHaveValue("cloud");
  await expect(page.getByLabel("Compute").locator("option")).toHaveCount(1);
});
