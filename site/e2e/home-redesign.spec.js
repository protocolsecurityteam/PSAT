import { test, expect } from "@playwright/test";

test.describe("home redesign", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(
      (url) => url.pathname.startsWith("/api/"),
      (route) => route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
    );

    // Fake CoinGecko: one 1×1 PNG for any coin lookup, empty results for search.
    const png1x1 = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
      "base64",
    );
    await page.route(/api\.coingecko\.com\/api\/v3\/coins\//, (route) => {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          image: { large: "https://stub.test/large.png", small: "https://stub.test/small.png" },
        }),
      });
    });
    await page.route(/api\.coingecko\.com\/api\/v3\/search/, (route) => {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ coins: [{ large: "https://stub.test/search.png" }] }),
      });
    });
    await page.route(/stub\.test\/.+\.png/, (route) =>
      route.fulfill({ status: 200, contentType: "image/png", body: png1x1 }),
    );
    // Also fulfill the /logos/<slug>.svg requests so the local-first path falls through quickly
    await page.route(/\/logos\/.+\.svg$/, (route) => route.fulfill({ status: 404, body: "" }));

    await page.route(/\/api\/(analyses|company|jobs)\b/, (route) => {
      const url = route.request().url();
      if (url.includes("/api/analyses")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify([
            { job_id: "a", company: "etherfi", address: "0x1111111111111111111111111111111111111111", contract_name: "Weeth", is_proxy: true, upgrade_count: 2 },
            { job_id: "b", company: "etherfi", address: "0x2222222222222222222222222222222222222222", contract_name: "LiquidityPool", upgrade_count: 0 },
            { job_id: "c", company: "lido", address: "0x3333333333333333333333333333333333333333", contract_name: "stETH" },
          ]),
        });
      }
      if (url.includes("/api/company/etherfi/audit_coverage")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            audit_count: 3,
            coverage: [
              { address: "0x1111111111111111111111111111111111111111", audit_count: 2, audits: [], last_audit: { auditor: "ABC", date: "2024-06" } },
              { address: "0x2222222222222222222222222222222222222222", audit_count: 0, audits: [] },
            ],
          }),
        });
      }
      if (url.includes("/api/company/etherfi")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            contracts: [
              { address: "0x1111111111111111111111111111111111111111", name: "Weeth", is_proxy: true, proxy_type: "ERC1967", upgrade_count: 2, control_model: "timelock", controllers: { owner: "0xMultiSig" } },
              { address: "0x2222222222222222222222222222222222222222", name: "LiquidityPool", upgrade_count: 0, controllers: {} },
            ],
            ownership_hierarchy: [
              { owner: "0x9999999999999999999999999999999999999999", owner_name: "Treasury", owner_is_contract: true, contracts: [
                { address: "0x1111111111111111111111111111111111111111", name: "Weeth" },
                { address: "0x2222222222222222222222222222222222222222", name: "LiquidityPool" },
              ]},
            ],
            all_addresses: [],
          }),
        });
      }
      if (url.includes("/api/jobs")) {
        return route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
    });
  });

  test("home page and protocol page render without errors", async ({ page }) => {
    const errors = [];
    page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}\n${e.stack || ""}`));
    page.on("console", (m) => {
      if (m.type() !== "error") return;
      const sourceUrl = m.location()?.url || "";
      // Missing local /logos/<slug>.svg 404s are the expected trigger for the
      // CoinGecko fallback path — not an error.
      if (/\/logos\/.+\.svg/.test(sourceUrl)) return;
      errors.push(`console.error: ${m.text()} (from ${sourceUrl})`);
    });

    await page.goto("/");
    await page.waitForTimeout(1500);

    if (errors.length) {
      console.log("EARLY ERRORS:\n" + errors.join("\n---\n"));
      const html = await page.content();
      console.log("BODY (first 2000):\n" + html.slice(0, 2000));
    }

    // Wait for React to mount — look for brand in top-nav
    await expect(page.locator(".top-nav-brand")).toBeVisible();

    // Splash hero — minesweeper background, cycling-word title
    await expect(page.locator(".ph-meta-dot")).toBeVisible();
    await expect(page.locator(".ph-title")).toContainText(/Detect every/i);
    await expect(page.locator(".ph-title")).toContainText(/before they do/i);

    // Protocol list
    await expect(page.locator(".home-protocol-row")).toHaveCount(2);

    // Click etherfi row
    await page.locator(".home-protocol-row").first().click();
    await expect(page).toHaveURL(/\/company\/etherfi/);

    // Company hero
    await expect(page.locator(".company-hero-title")).toBeVisible();
    await expect(page.locator(".protocol-radar")).toBeVisible();
    // Stage B replaced the static SurfacePreview with an inline ProtocolSurface
    // that has its own "Open fullscreen" pill in the band header.
    await expect(page.locator(".company-surface-band-header")).toBeVisible();

    if (errors.length) console.log("ERRORS:\n" + errors.join("\n---\n"));
    expect(errors).toEqual([]);
  });

  test("protocol logos fall back to CoinGecko when no local SVG exists", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".home-protocol-row")).toHaveCount(2);

    const etherfiLogo = page.locator(".home-protocol-row", { hasText: "etherfi" }).locator(".protocol-logo img");
    await expect(etherfiLogo).toHaveAttribute("src", /stub\.test/, { timeout: 5000 });
  });
});
