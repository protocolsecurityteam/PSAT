/**
 * Full-flow selection regression (SELECTION_FILTERING_DIAGNOSIS.md).
 *
 * Mirrors the original diagnosis reproduction: search-commit a safe, then walk
 * Detail / Agent / Audits / Upgrades / Monitor asserting the safe — never one
 * of its controlled contracts — is what each tab reflects. Plus:
 *   - Flow A (search-commit) === Flow B (canvas-side principal select).
 *   - a node-less co-controller safe highlights its touch set on the canvas.
 *   - the search preview never duplicates the type as the label ("safe safe").
 *
 * Assertions are structural (shapes, not pinned prod values) so the spec is
 * robust to fixture edits.
 */
import { test, expect } from "@playwright/test";

const VAULT = "0x1111111111111111111111111111111111111111";
const POOL = "0x2222222222222222222222222222222222222222";
const GOV_SAFE = "0x3333333333333333333333333333333333333333"; // primary owner of VAULT → group node
const CO_SAFE = "0x4444444444444444444444444444444444444444"; // node-less co-controller of POOL

const FIXTURE = {
  protocol_id: 1,
  contracts: [
    {
      address: VAULT,
      name: "Vault",
      display_name: "Vault",
      role: "governance",
      is_proxy: true,
      proxy_type: "ERC1967",
      upgrade_count: 2,
      job_id: "vault-job",
      functions: [
        {
          function: "pauseContract()",
          selector: "0x11111111",
          effect_labels: ["pause_toggle"],
          direct_owner: {
            address: GOV_SAFE,
            resolved_type: "safe",
            details: { threshold: 4, owners: ["0x0a", "0x0b", "0x0c", "0x0d", "0x0e", "0x0f", "0x10"] },
          },
          authority_roles: [],
          controllers: [],
        },
      ],
    },
    {
      address: POOL,
      name: "LiquidityPool",
      display_name: "LiquidityPool",
      role: "value_handler",
      is_proxy: false,
      upgrade_count: 0,
      job_id: "pool-job",
      functions: [
        {
          function: "setOracle()",
          selector: "0x22222222",
          effect_labels: ["config"],
          direct_owner: {
            address: CO_SAFE,
            resolved_type: "safe",
            details: { threshold: 2, owners: ["0x21", "0x22", "0x23"] },
          },
          authority_roles: [],
          controllers: [],
        },
      ],
    },
  ],
  principals: [
    {
      address: GOV_SAFE,
      type: "safe",
      label: "GovSafe",
      details: { threshold: 4, owners: ["0x0a", "0x0b", "0x0c", "0x0d", "0x0e", "0x0f", "0x10"] },
      controls: [VAULT, POOL],
      primary_for: [VAULT],
      co_controls: [POOL],
      controls_detail: [
        { address: VAULT, functions: ["pauseContract"], capabilities: ["pause"] },
        { address: POOL, functions: ["setOracle"], capabilities: ["config"] },
      ],
    },
    {
      // A co-controller of POOL that is the primary owner of nothing → it has
      // no group box / canvas node; selecting it must highlight its touch set
      // rather than no-op. Its label is the bare type token to exercise the
      // "safe safe" label fix.
      address: CO_SAFE,
      type: "safe",
      label: "safe",
      details: { threshold: 2, owners: ["0x21", "0x22", "0x23"] },
      controls: [POOL],
      primary_for: [],
      co_controls: [POOL],
      controls_detail: [{ address: POOL, functions: ["setOracle"], capabilities: ["config"] }],
    },
  ],
  fund_flows: [],
};

/** The safe's controlled contract names — the entities that must NOT leak. */
const CONTROLLED_NAMES = ["Vault", "LiquidityPool"];

async function goToSurface(page, { admin = false } = {}) {
  if (admin) {
    // The Agent/Monitor tabs gate on the presence of an admin key only.
    await page.addInitScript(() => window.localStorage.setItem("psat_admin_key", "e2e"));
  }
  await page.route("**/api/company/seltest", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(FIXTURE) })
  );
  // Silence best-effort side calls the panels make so tabs render their state.
  await page.route(/\/api\/(address_labels|monitored-events|agent\/).*/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({}) })
  );
  await page.route(/\/api\/protocols\/.*/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) })
  );
  await page.route(/\/api\/company\/[^/]+\/audit_coverage$/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ audit_count: 0, coverage: [] }) })
  );
  await page.goto("/company/seltest/surface");
  await page.waitForSelector(".ps-surface", { timeout: 10000 });
  await page.waitForSelector(".react-flow__node", { timeout: 15000 });
}

/** Pick a search mode pill in the top-left modes bar. */
async function pickMode(page, label) {
  const bar = page.locator(".ps-search-modes");
  await bar.getByRole("button", { name: new RegExp(label, "i") }).click();
}

/** Commit the current search preview (index 0) via Enter. */
async function commitSearch(page) {
  const input = page.locator(".ps-search-input");
  await input.click();
  await input.press("Enter");
}

/** Open a sidebar tab by label, scoped to the tab bar. */
async function openTab(page, label) {
  await page.locator(".ps-sidebar-tabs").getByRole("button", { name: new RegExp(`^${label}`, "i") }).click();
}

test.describe("Surface selection — full flow", () => {
  test("search-committing a safe reflects the safe (not a controlled contract) across every tab", async ({ page }) => {
    await goToSurface(page, { admin: true });

    await pickMode(page, "Safes");
    await commitSearch(page); // highest-value safe = GovSafe (controls Vault + Pool)

    // Detail: the safe's PrincipalDetail card, with signers + threshold.
    await openTab(page, "Detail");
    await expect(page.locator(".ps-machine-address")).toContainText(GOV_SAFE.slice(0, 6));
    await expect(page.getByText(/4\/7 threshold/i)).toBeVisible();

    // Agent: context is the SAFE (type word + its own short address as meta),
    // never a controlled contract name.
    await openTab(page, "Agent");
    const ctx = page.locator(".agent-context-value");
    await expect(ctx).toBeVisible();
    await expect(page.locator(".agent-context-meta")).toBeVisible();
    for (const name of CONTROLLED_NAMES) {
      await expect(ctx).not.toContainText(name);
    }

    // Audits: no selected-contract coverage card.
    await openTab(page, "Audits");
    await expect(page.locator(".ps-audits-contract-card")).toHaveCount(0);

    // Upgrades: explicit "pick a contract" hint, not a leaked timeline.
    await openTab(page, "Upgrades");
    await expect(page.getByText(/choose a contract to see its upgrade timeline/i)).toBeVisible();

    // Monitor: explicit "pick a contract" hint.
    await openTab(page, "Monitor");
    await expect(page.getByText(/choose a contract to see its alerts/i)).toBeVisible();

    // The URL persists the principal selection (shareable/restorable).
    await expect(page).toHaveURL(new RegExp(`sel=${GOV_SAFE}`));
    await expect(page).toHaveURL(/view=principal/);
  });

  test("canvas-side selection of the same safe matches the search selection (Flow A === Flow B)", async ({ page }) => {
    // Flow A: search-commit → capture the Detail address + URL selection.
    await goToSurface(page);
    await pickMode(page, "Safes");
    await commitSearch(page);
    await openTab(page, "Detail");
    const flowAAddr = await page.locator(".ps-machine-address").innerText();
    await expect(page).toHaveURL(new RegExp(`sel=${GOV_SAFE}`));

    // Flow B: fresh load, select the SAME safe from the canvas via its primary
    // controller row (a canvas-side principal selection).
    await goToSurface(page);
    await page.locator(".ps-ctrl-row--primary .ps-ctrl-head").click();
    const flowBAddr = await page.locator(".ps-machine-address").innerText();

    expect(flowBAddr).toBe(flowAAddr);
    expect(flowBAddr.toLowerCase()).toContain(GOV_SAFE.slice(2, 6));
  });

  test("selecting a node-less co-controller safe highlights its touch set (no silent no-op)", async ({ page }) => {
    await goToSurface(page);

    // Browse to the co-controller safe (CO_SAFE, lower value than GovSafe) and
    // commit it. It owns no group node, so pre-fix the canvas did nothing.
    await pickMode(page, "Safes");
    const input = page.locator(".ps-search-input");
    await input.click();
    const viewport = page.locator(".react-flow__viewport");
    const transformBefore = await viewport.evaluate((n) => n.style.transform);
    await input.press("ArrowDown"); // move from GovSafe to CO_SAFE
    await input.press("Enter");

    // The camera pans to the safe's touch set even though it has no node of
    // its own (FocusOnNode falls back to the touched nodes' bounding box).
    await expect
      .poll(async () => viewport.evaluate((n) => n.style.transform))
      .not.toBe(transformBefore);

    // Its touch set is POOL — POOL stays bright, VAULT (untouched) dims.
    const pool = page.locator(`.react-flow__node[data-id="${POOL}"]`);
    const vault = page.locator(`.react-flow__node[data-id="${VAULT}"]`);
    await expect(pool).toBeVisible();
    await expect
      .poll(async () => Number(await vault.evaluate((n) => Number(n.style.opacity) || 1)))
      .toBeLessThan(1);
    await expect
      .poll(async () => Number(await pool.evaluate((n) => Number(n.style.opacity) || 1)))
      .toBe(1);
  });

  test("browsing a safe marks its entity — group box + controller row — not its contracts", async ({ page }) => {
    await goToSurface(page);

    // Browse (never commit) back around to GovSafe: two ArrowDowns wrap
    // 0 → 1 (CO_SAFE) → 0 (GovSafe), and only a move() fires a preview.
    await pickMode(page, "Safes");
    const input = page.locator(".ps-search-input");
    await input.click();
    await input.press("ArrowDown");
    await input.press("ArrowDown");

    // The browsed principal's own footprint gets the gold browse marker: its
    // group box and its row in the Controllers accordion.
    await expect(page.locator(".ps-group-focused")).toHaveCount(1);
    await expect(page.locator(".ps-ctrl-row--focused")).toHaveCount(1);
    // Its CONTRACTS are untouched — no gold rings, no dim (that treatment is
    // reserved for an actual commit), no selected ring, no URL write.
    await expect(page.locator(".ps-node-focused")).toHaveCount(0);
    const pool = page.locator(`.react-flow__node[data-id="${POOL}"]`);
    await expect
      .poll(async () => Number(await pool.evaluate((n) => Number(n.style.opacity) || 1)))
      .toBe(1);
    await expect(page.locator(".ps-node-selected")).toHaveCount(0);
    expect(page.url()).not.toContain("sel=");
  });

  test("browsing a footprint-less principal falls back to dotting its touch set", async ({ page }) => {
    await goToSurface(page);

    // CO_SAFE has no node and no accordion row (its co-controlled POOL sits
    // in no group), so the browse marker falls back to its touched contracts.
    await pickMode(page, "Safes");
    const input = page.locator(".ps-search-input");
    await input.click();
    await input.press("ArrowDown"); // preview CO_SAFE — never committed

    const pool = page.locator(`.react-flow__node[data-id="${POOL}"]`);
    await expect(pool.locator(".ps-node")).toHaveClass(/ps-node-focused/);
    // The gold chip explains the marker: who the off-graph principal is and
    // what it can call on this contract.
    const chip = pool.locator(".ps-node-chip--browse");
    await expect(chip).toContainText("not on graph");
    await expect(chip).toContainText("setOracle");
    // Still a preview, not a selection: no dim, no selected ring, no URL.
    await expect
      .poll(async () => Number(await pool.evaluate((n) => Number(n.style.opacity) || 1)))
      .toBe(1);
    await expect(page.locator(".ps-node-selected")).toHaveCount(0);
    expect(page.url()).not.toContain("sel=");
  });

  test("the search preview never duplicates the type as the label ('safe safe')", async ({ page }) => {
    await goToSurface(page);

    await pickMode(page, "Safes");
    const input = page.locator(".ps-search-input");
    await input.click();
    await input.press("ArrowDown"); // preview CO_SAFE, whose label is the bare "safe"

    const preview = page.locator(".ps-search-preview");
    await expect(preview).toBeVisible();
    // The name slot shows the short address, not a second "safe".
    await expect(preview.locator(".ps-search-preview-name")).toHaveText(/^0x[0-9a-fA-F]{4}\.\./);
    await expect(preview).not.toContainText("safe safe");
  });
});
