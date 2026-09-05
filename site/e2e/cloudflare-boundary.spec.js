import { test, expect } from "@playwright/test";

// This suite has its own loopback server; never run against a deployed URL.
test("anonymous browsing, origin denial, and both operator credentials", async ({ page, request }) => {
  await page.route((url) => !["127.0.0.1", "localhost"].includes(url.hostname), (route) => route.abort());
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Menu", exact: true })).toBeVisible();
  const company = await request.get("/api/company/Example");
  expect(company.status()).toBe(200);
  expect(company.headers()["cache-control"]).toContain("s-maxage=60");
  expect((await company.json()).company).toBe("Example");

  await page.getByRole("button", { name: "Menu", exact: true }).click();
  await expect(page.getByRole("link", { name: "Operator sign in" })).toHaveCount(0);
  const keyOnly = await request.get("/api/jobs", { headers: { "X-PSAT-Admin-Key": "test-admin-key" } });
  expect(keyOnly.status()).toBe(403);
  expect(keyOnly.headers()["cache-control"]).toBe("private, no-store");
  expect((await request.get("/monitor")).status()).toBe(403);
  expect((await request.post("/api/analyze", { data: {}, headers: { "X-PSAT-Admin-Key": "test-admin-key" } })).status()).toBe(403);
  expect((await request.get("/__direct/api/version", { headers: {
    Host: "snif.sh", "CF-Connecting-IP": "192.0.2.8", "CF-Access-Jwt-Assertion": "fake",
  } })).status()).toBe(403);

  page.once("dialog", (dialog) => dialog.accept("test-admin-key"));
  await page.goto("/__test_login");
  await expect(page).toHaveURL(/\/operator\/\?admin=1$/);
  expect(await page.evaluate(() => localStorage.getItem("psat_admin_key"))).toBe("test-admin-key");
  // page.request shares the browser's signed, HTTP-only test Access cookie.
  expect((await page.request.get("/api/jobs")).status()).toBe(401);
  for (const path of ["/api/jobs", "/operator/api/jobs"]) {
    const authorized = await page.request.get(path, { headers: { "X-PSAT-Admin-Key": "test-admin-key" } });
    expect(authorized.status()).toBe(200);
    expect(await authorized.json()).toEqual([]);
    expect(authorized.headers()["cache-control"]).toBe("private, no-store");
  }
});
