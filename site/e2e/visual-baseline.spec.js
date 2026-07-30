// Visual regression baselines for the major page states.
//
// Why these exist: the upcoming styles.css split (~9k lines into many
// per-feature files) can silently break specificity / cascade order.
// Vitest + jsdom doesn't render CSS, so render tests can't catch it. A
// few stable screenshots can.
//
// What's covered: every URL the App router resolves to, with mocked API
// responses identical to home-redesign.spec.js so backend changes don't
// shift the baseline.
//
// Updating baselines after intentional CSS work:
//   npx playwright test e2e/visual-baseline.spec.js --update-snapshots
// then commit the new files under e2e/visual-baseline.spec.js-snapshots/.
//
// Platform note: snapshots are platform-sensitive. CI runs ubuntu-latest;
// local dev should also run on Linux (WSL is fine) for the diffs to match.
// macOS will produce different baselines.

import { test, expect } from "@playwright/test";

const ETHERFI_ADDR = "0x1111111111111111111111111111111111111111";
const POOL_ADDR = "0x2222222222222222222222222222222222222222";

const ANALYSES = [
  {
    job_id: "a",
    company: "etherfi",
    address: ETHERFI_ADDR,
    contract_name: "Weeth",
    is_proxy: true,
    upgrade_count: 2,
  },
  {
    job_id: "b",
    company: "etherfi",
    address: POOL_ADDR,
    contract_name: "LiquidityPool",
    upgrade_count: 0,
  },
];

const COMPANY_ETHERFI = {
  contracts: [
    {
      address: ETHERFI_ADDR,
      name: "Weeth",
      is_proxy: true,
      proxy_type: "ERC1967",
      upgrade_count: 2,
      control_model: "timelock",
      controllers: { owner: "0xMultiSig" },
      functions: [],
    },
    {
      address: POOL_ADDR,
      name: "LiquidityPool",
      upgrade_count: 0,
      controllers: {},
      functions: [],
    },
  ],
  ownership_hierarchy: [],
  all_addresses: [],
};

const COVERAGE = {
  audit_count: 0,
  coverage: [
    { address: ETHERFI_ADDR, audit_count: 0, audits: [] },
    { address: POOL_ADDR, audit_count: 0, audits: [] },
  ],
};

// Mocked API + animation-killer style. Animations and transitions are
// disabled so snapshots don't flake on hover/focus mid-render.
async function setupPage(page) {
  // Operator controls (monitor dashboard, surface Agent/Monitor tabs, the
  // admin modals) are admin-gated; seed an admin key so the baselines keep
  // capturing the full control surface.
  await page.addInitScript(() => {
    try { window.localStorage.setItem("psat_admin_key", "e2e-admin-key"); } catch {}
  });
  await page.addInitScript(() => {
    const style = document.createElement("style");
    style.textContent = `*, *::before, *::after {
      animation-duration: 0s !important;
      animation-delay: 0s !important;
      transition-duration: 0s !important;
      transition-delay: 0s !important;
      caret-color: transparent !important;
    }`;
    if (document.head) document.head.appendChild(style);
    else document.addEventListener("DOMContentLoaded", () => document.head.appendChild(style));
  });

  // Match only paths whose pathname starts with /api/ — using a regex
  // like /\/api\// would also match Vite's /src/api/client.js module
  // requests and break the page bootstrap.
  function matchApi(pattern) {
    if (pattern instanceof RegExp) {
      return (url) => pattern.test(url.pathname);
    }
    return (url) => url.pathname === pattern;
  }

  // Catch-all first so specific routes registered later take precedence.
  await page.route(
    (url) => url.pathname.startsWith("/api/"),
    (route) => route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
  );
  await page.route(matchApi("/api/analyses"), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(ANALYSES) }),
  );
  await page.route(matchApi(/^\/api\/company\/[^/]+\/audit_coverage$/), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(COVERAGE) }),
  );
  await page.route(matchApi(/^\/api\/company\/[^/]+$/), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(COMPANY_ETHERFI) }),
  );
  await page.route(matchApi("/api/jobs"), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  );
  await page.route(matchApi("/api/stats"), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
  );
  await page.route(matchApi("/api/audits/pipeline"), (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ groups: [], recent_completed: [] }),
    }),
  );
  await page.route(matchApi("/api/monitored-contracts"), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  );
  await page.route(matchApi("/api/address_labels"), (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ labels: {} }) }),
  );
  // Local logo SVGs 404 → CoinGecko fallback path. Stub coingecko too.
  await page.route(/\/logos\/.+\.svg$/, (route) => route.fulfill({ status: 404, body: "" }));
  await page.route(/api\.coingecko\.com\/.+/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
  );

  await page.setViewportSize({ width: 1440, height: 900 });
}

// `toHaveScreenshot` defaults to a strict pixel-level diff. The
// `maxDiffPixelRatio` knob lets minor anti-aliasing differences pass
// without obscuring real cascade regressions. 0.01 = 1% — tight enough
// to catch a missing rule, loose enough to avoid font-render flake.
const SCREENSHOT_OPTS = { maxDiffPixelRatio: 0.01, fullPage: false };

test.describe("visual baselines", () => {
  test.beforeEach(async ({ page }) => {
    await setupPage(page);
  });

  test("home page", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.locator(".ph-title").waitFor({ state: "visible" });
    await expect(page).toHaveScreenshot("home.png", SCREENSHOT_OPTS);
  });

  test("company overview", async ({ page }) => {
    await page.goto("/company/etherfi", { waitUntil: "domcontentloaded" });
    await page.locator(".company-hero-title").waitFor({ state: "visible" });
    // Wait for radar SVG to settle.
    await page.waitForTimeout(400);
    await expect(page).toHaveScreenshot("company-overview.png", SCREENSHOT_OPTS);
  });

  test("company surface (ProtocolSurface fullscreen)", async ({ page }) => {
    await page.goto("/company/etherfi/surface", { waitUntil: "domcontentloaded" });
    await page.locator(".ps-surface").waitFor({ state: "visible" });
    // ELK + React Flow first layout takes ~500ms.
    await page.waitForTimeout(800);
    await expect(page).toHaveScreenshot("company-surface.png", SCREENSHOT_OPTS);
  });

  test("pipeline dashboard", async ({ page }) => {
    await page.goto("/monitor", { waitUntil: "domcontentloaded" });
    await page.locator(".top-nav").waitFor({ state: "visible" });
    await page.waitForTimeout(400);
    await expect(page).toHaveScreenshot("pipeline-dashboard.png", SCREENSHOT_OPTS);
  });
});
