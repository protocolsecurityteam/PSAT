// Component-level visual baselines: the sidebar tabs, cards, chips, rows and
// modals that the page-level baselines (visual-baseline.spec.js) never open.
// They guard refactors that share components and styles across features: a
// shared primitive has to reproduce every one of these states pixel for pixel.
//
// Updating after an intentional visual change:
//   npx playwright test e2e/visual-components.spec.js --update-snapshots

import fs from "node:fs";
import { test, expect } from "@playwright/test";
import { ETHERFI_COMPANY_RICH, RICH_ADDRESSES, RICH_COVERAGE } from "../src/test/fixtures.js";

const SCORE = JSON.parse(fs.readFileSync(new URL("../src/test/fixtures/score_etherfi.json", import.meta.url), "utf8"));
const { VAULT, POOL, SAFE, TIMELOCK, EOA } = RICH_ADDRESSES;
const NOW = new Date("2026-07-14T12:00:00Z");
const iso = (msAgo) => new Date(NOW.getTime() - msAgo).toISOString();
const IMPL_OLD = "0x5555555555555555555555555555555555555555";
const IMPL_CUR = "0x6666666666666666666666666666666666666666";
const LIDO = "0x7777777777777777777777777777777777777777";

const COMPANY = {
  ...ETHERFI_COMPANY_RICH,
  contracts: ETHERFI_COMPANY_RICH.contracts.map((c) =>
    c.address === VAULT
      ? {
          ...c,
          total_usd: 1234567.89,
          balances: [
            { token_symbol: "WETH", token_name: "Wrapped Ether", token_address: "0x8888888888888888888888888888888888888888", balance: "1200.5", usd_value: 4200000, usd_value_state: "measured" },
            { token_symbol: "DUST", token_name: "Dust Token", token_address: "0x9999999999999999999999999999999999999999", balance: "3", usd_value: null, usd_value_state: "not_determined" },
          ],
          holdings_coverage: { state: "not_determined" },
        }
      : c,
  ),
};

const DEP_GRAPH = {
  nodes: [
    { id: "t", address: VAULT, label: "Vault", type: "implementation", is_target: true, source: [] },
    { id: "pool", address: POOL, label: "LiquidityPool", type: "implementation", source: ["dynamic"] },
    { id: "lido", address: LIDO, label: "Lido", type: "implementation", source: ["classification"] },
  ],
  edges: [
    { from: "t", to: "pool", op: "CALL", function_name: "rebalance" },
    { from: "t", to: "pool", op: "STATICCALL", function_name: "totalAssets" },
    { from: "t", to: "lido", op: "STATICCALL", function_name: "balanceOf" },
  ],
};

const MONITORED = [
  { id: "c-vault", address: VAULT, chain: "ethereum", contract_type: "proxy", monitoring_config: { watch_upgrades: true, watch_ownership: true }, last_known_state: { implementation: IMPL_CUR, paused: false }, last_scanned_block: 400, enrollment_block: 250, is_active: true, created_at: "2025-12-01T00:00:00Z", updated_at: iso(3_600_000) },
  { id: "c-safe", address: SAFE, chain: "ethereum", contract_type: "safe", monitoring_config: { watch_safe_signers: true }, last_known_state: { threshold: 2 }, last_scanned_block: 400, enrollment_block: 250, is_active: true, created_at: "2025-12-01T00:00:00Z", updated_at: iso(3_600_000) },
];

const EVENTS = [
  { id: "e1", monitored_contract_id: "c-vault", event_type: "upgraded", block_number: 300, tx_hash: `0x${"ab".repeat(32)}`, data: { implementation: IMPL_CUR }, detected_at: iso(86_400_000), salience: "alert" },
  { id: "e2", monitored_contract_id: "c-vault", event_type: "paused", block_number: 320, tx_hash: `0x${"cd".repeat(32)}`, data: {}, detected_at: iso(7_200_000), salience: "alert" },
];

const HISTORY = {
  proxies: {
    [VAULT.toLowerCase()]: {
      proxy_type: "ERC1967",
      current_implementation: IMPL_CUR,
      upgrade_count: 2,
      implementations: [
        { address: IMPL_OLD, block_introduced: 100, block_replaced: 300, timestamp_introduced: 1700000000 },
        { address: IMPL_CUR, block_introduced: 300, timestamp_introduced: 1720000000 },
      ],
    },
  },
};

const ADDRESSES = {
  all_addresses: [
    { address: VAULT, chain: "ethereum", name: "Vault", is_proxy: true, implementation_name: "VaultImpl", analyzed: true, rank_score: 0.91, membership_state: "member" },
    { address: POOL, chain: "ethereum", name: "LiquidityPool", analyzed: true, rank_score: 0.72, membership_state: "member" },
    { address: EOA, chain: "ethereum", name: null, analyzed: false, rank_score: 0.1, membership_state: "candidate", candidate_reason: { kind: "no_probe_attempt" } },
  ],
};

const AUDITS_LIST = [
  { id: 1, auditor: "Trail of Bits", date: "2024-03-15", title: "V2 Audit", url: "https://example.com/a.pdf", pdf_url: "https://example.com/a.pdf", text_extraction_status: "success", scope_extraction_status: "success", scope_contract_count: 4, reviewed_commits: ["abc1234"] },
  { id: 2, auditor: "Spearbit", date: "2023-11-02", title: "V1 Review", url: "https://example.com/b.pdf", pdf_url: null, text_extraction_status: "failed", scope_extraction_status: null, scope_contract_count: 0, reviewed_commits: [] },
];
const AUDITS = { audit_count: AUDITS_LIST.length, audits: AUDITS_LIST };
const AUDIT_DETAIL = {
  id: 1, auditor: "Trail of Bits", title: "V2 Audit", date: "2024-03-15", url: null, pdf_url: null,
  classified_commits: [
    { sha: "abc1234def5678", label: "reviewed", context: "audited commit" },
    { sha: "fed4321cba9876", label: "fix", context: "fix review" },
  ],
  reviewed_commits: ["abc1234def5678"],
};

const json = (body, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function setup(page) {
  await page.clock.setFixedTime(NOW);
  await page.addInitScript(() => {
    try { window.localStorage.setItem("psat_admin_key", "e2e-admin-key"); } catch {}
    const style = document.createElement("style");
    style.textContent = `*, *::before, *::after {
      animation-duration: 0s !important; animation-delay: 0s !important;
      transition-duration: 0s !important; transition-delay: 0s !important;
      caret-color: transparent !important;
    }`;
    if (document.head) document.head.appendChild(style);
    else document.addEventListener("DOMContentLoaded", () => document.head.appendChild(style));
  });
  const api = (re, body, status) => page.route((url) => re.test(url.pathname), (route) => route.fulfill(json(body, status)));
  await api(/^\/api\//, {});
  await api(/^\/api\/company\/etherfi$/, COMPANY);
  await api(/^\/api\/company\/etherfi\/summary$/, {});
  await api(/^\/api\/company\/etherfi\/audit_coverage$/, RICH_COVERAGE);
  await api(/^\/api\/company\/etherfi\/score$/, SCORE);
  await api(/^\/api\/company\/etherfi\/addresses$/, ADDRESSES);
  await api(/^\/api\/company\/etherfi\/audits$/, AUDITS);
  await api(/^\/api\/address_labels$/, { labels: {} });
  await api(/^\/api\/audits\/1$/, AUDIT_DETAIL);
  await api(/^\/api\/audits\/1\/scope$/, { contracts: ["Vault", "LiquidityPool"] });
  await page.route((url) => /^\/api\/audits\/1\/text$/.test(url.pathname), (route) =>
    route.fulfill({ status: 200, contentType: "text/plain", body: "1. Scope\n\nVault.sol\nLiquidityPool.sol\n\n2. Findings\n\nNo critical issues." }));
  await api(/^\/api\/protocols\/\d+\/monitoring$/, MONITORED);
  await api(/^\/api\/protocols\/\d+\/subscriptions$/, []);
  await api(/^\/api\/protocols\/\d+\/events$/, EVENTS);
  await api(/^\/api\/monitored-events$/, EVENTS);
  await api(/\/artifact\/upgrade_history$/, HISTORY);
  await api(/\/artifact\/dependency_graph_viz$/, DEP_GRAPH);
  await page.route(/\/logos\/.+\.svg$/, (route) => route.fulfill({ status: 404, body: "" }));
  await page.route(/api\.coingecko\.com\/.+/, (route) => route.fulfill(json({})));
  await page.setViewportSize({ width: 1440, height: 900 });
}

const SHOT = { maxDiffPixelRatio: 0.01 };

async function openSurface(page) {
  await page.goto("/company/etherfi/surface");
  await page.waitForSelector(".react-flow__node", { timeout: 15000 });
  await page.waitForTimeout(800);
}

async function selectContract(page, name) {
  await page.locator(".ps-node", { hasText: name }).first().click();
  await page.waitForTimeout(300);
}

async function sidebarTab(page, name) {
  await page.locator(".ps-sidebar-tabs button", { hasText: name }).first().click();
  await page.waitForTimeout(300);
}

async function cardTab(page, name) {
  await page.locator(".ps-machine-tab", { hasText: name }).first().click();
  await page.waitForTimeout(300);
}

const sidebar = (page) => page.locator(".ps-sidebar");

test.describe("component visual baselines", () => {
  test.beforeEach(async ({ page }) => {
    await setup(page);
  });

  test("detail: empty state", async ({ page }) => {
    await openSurface(page);
    await sidebarTab(page, "Detail");
    await expect(sidebar(page)).toHaveScreenshot("detail-empty.png", SHOT);
  });

  test("contract card: control, balances, governs, depends", async ({ page }) => {
    await openSurface(page);
    await selectContract(page, "Vault");
    await sidebarTab(page, "Detail");
    await expect(sidebar(page)).toHaveScreenshot("card-control.png", SHOT);
    await cardTab(page, "Balances");
    await expect(sidebar(page)).toHaveScreenshot("card-balances.png", SHOT);
    await cardTab(page, "Depends");
    await page.waitForTimeout(300);
    await page.locator(".ref-toggle").first().click();
    await expect(sidebar(page)).toHaveScreenshot("card-depends.png", SHOT);
  });

  test("principal card: governs with expanded row", async ({ page }) => {
    await openSurface(page);
    await page.locator(".ps-group-header").first().click();
    await page.waitForTimeout(300);
    await sidebarTab(page, "Detail");
    const expand = page.locator(".ref-toggle").first();
    if (await expand.count()) await expand.click();
    await expect(sidebar(page)).toHaveScreenshot("card-governs.png", SHOT);
  });

  test("function inspector", async ({ page }) => {
    await openSurface(page);
    await selectContract(page, "Vault");
    await sidebarTab(page, "Detail");
    await page.locator(".ps-port-copy", { hasText: "pause" }).first().click();
    await page.waitForTimeout(300);
    await expect(sidebar(page)).toHaveScreenshot("inspector.png", SHOT);
  });

  test("activity: protocol feed and contract timeline", async ({ page }) => {
    await openSurface(page);
    await sidebarTab(page, "Activity");
    await page.waitForTimeout(300);
    await expect(sidebar(page)).toHaveScreenshot("activity-protocol.png", SHOT);
    await selectContract(page, "Vault");
    await sidebarTab(page, "Activity");
    await page.waitForTimeout(300);
    await expect(sidebar(page)).toHaveScreenshot("activity-contract-alerts.png", SHOT);
    await page.locator(".ps-activity-salience button", { hasText: "All" }).first().click();
    await page.waitForTimeout(300);
    await expect(sidebar(page)).toHaveScreenshot("activity-contract-all.png", SHOT);
  });

  test("audits: panel, expanded audit, read modal", async ({ page }) => {
    await openSurface(page);
    await sidebarTab(page, "Audits");
    await expect(sidebar(page)).toHaveScreenshot("audits-panel.png", SHOT);
    await page.locator(".ps-audits-arow").first().click();
    await page.waitForTimeout(200);
    await expect(sidebar(page)).toHaveScreenshot("audits-expanded.png", SHOT);
    const read = page.getByRole("button", { name: /read/i }).first();
    if (await read.count()) {
      await read.click();
      await page.waitForTimeout(300);
      await expect(page).toHaveScreenshot("audit-read-modal.png", SHOT);
    }
  });

  test("filter panel expanded", async ({ page }) => {
    await openSurface(page);
    await page.locator('.ps-filter-pill[aria-expanded="false"]').click();
    await page.waitForTimeout(200);
    await expect(page.locator(".ps-filter-overlay")).toHaveScreenshot("filter-panel.png", SHOT);
  });

  test("overview: score breakdown and modals", async ({ page }) => {
    await page.goto("/company/etherfi");
    await page.locator(".company-hero-title").waitFor({ state: "visible" });
    await page.waitForTimeout(500);
    await page.locator(".sc-expand-btn").first().click();
    await page.waitForTimeout(300);
    await expect(page.locator(".score-band").first()).toHaveScreenshot("score-band.png", SHOT);
    await expect(page.locator(".score-breakdown").first()).toHaveScreenshot("score-breakdown.png", SHOT);
    await page.getByTitle("Browse all addresses").click();
    await page.locator(".ps-addresses-modal").waitFor({ state: "visible" });
    await page.waitForTimeout(300);
    await expect(page).toHaveScreenshot("addresses-modal.png", SHOT);
    await page.keyboard.press("Escape");
    await page.getByTitle("Manage audits (admin)").click();
    await page.waitForTimeout(400);
    await expect(page).toHaveScreenshot("audits-admin-modal.png", SHOT);
  });
});
