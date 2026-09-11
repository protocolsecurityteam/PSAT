import { test, expect } from "@playwright/test";

test("a gateway failure shows a short error and Retry recovers the company page", async ({ page }) => {
  let overviewRequests = 0;
  let unavailable = true;
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route((url) => !["127.0.0.1", "localhost"].includes(url.hostname), (route) => route.abort());
  await page.route((url) => url.pathname.startsWith("/api/"), (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/company/recovery") {
      overviewRequests += 1;
      if (unavailable) return route.fulfill({
        status: 502,
        contentType: "text/html",
        body: "<!DOCTYPE html><html>Cloudflare 502: Bad gateway, Ray ID: example</html>",
      });
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          company: "recovery", contracts: [], principals: [], ownership_hierarchy: [], fund_flows: [],
        }),
      });
    }
    if (path === "/api/analyses") return route.fulfill({ contentType: "application/json", body: "[]" });
    return route.fulfill({ contentType: "application/json", body: "{}" });
  });
  await page.goto("/company/recovery");
  await expect(page.getByRole("alert")).toContainText("temporarily unavailable");
  await expect(page.getByRole("alert")).not.toContainText("DOCTYPE");
  await expect(page.getByRole("alert")).not.toContainText("Ray ID");
  const beforeRetry = overviewRequests;
  unavailable = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByRole("heading", { name: "recovery", exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  expect(overviewRequests).toBe(beforeRetry + 1);
  expect(errors).toEqual([]);
});
