// @ts-check
import { test, expect } from "@playwright/test";

/**
 * Minimal API fixture for /api/company/testco.
 *
 * Contains one contract ("Vault") with four functions, each guarded by
 * a different direct-caller configuration:
 *   - setSafe:        single safe caller
 *   - setTimelock:    single timelock caller
 *   - setOwner:       single contract caller
 *   - setMixed:       two callers (safe + timelock) → one button each
 */
const SAFE_ADDR = "0xaaaa000000000000000000000000000000000001";
const TL_ADDR = "0xbbbb000000000000000000000000000000000002";
const CON_ADDR = "0xcccc000000000000000000000000000000000003";
const VAULT_ADDR = "0xdddd000000000000000000000000000000000004";

const COMPANY_FIXTURE = {
  contracts: [
    {
      address: VAULT_ADDR,
      name: "Vault",
      display_name: "Vault",
      role: "governance",
      functions: [
        {
          function: "setSafe()",
          selector: "0x11111111",
          effect_labels: ["ownership_transfer"],
          direct_owner: {
            address: SAFE_ADDR,
            resolved_type: "safe",
            details: { threshold: 2, owners: ["0x0001", "0x0002", "0x0003"] },
          },
          authority_roles: [],
          controllers: [],
        },
        {
          function: "setTimelock()",
          selector: "0x22222222",
          effect_labels: ["pause_toggle"],
          direct_owner: {
            address: TL_ADDR,
            resolved_type: "timelock",
            details: { delay: 86400 },
          },
          authority_roles: [],
          controllers: [],
        },
        {
          function: "setOwner()",
          selector: "0x33333333",
          effect_labels: ["ownership_transfer"],
          direct_owner: {
            address: CON_ADDR,
            resolved_type: "contract",
            details: {},
          },
          authority_roles: [],
          controllers: [],
        },
        {
          function: "setMixed()",
          selector: "0x44444444",
          effect_labels: ["authority_update"],
          direct_owner: {
            address: SAFE_ADDR,
            resolved_type: "safe",
            details: { threshold: 2, owners: ["0x0001", "0x0002", "0x0003"] },
          },
          authority_roles: [],
          controllers: [
            {
              controller_id: "extra",
              label: "secondary",
              principals: [
                {
                  address: TL_ADDR,
                  resolved_type: "timelock",
                  details: { delay: 86400 },
                },
              ],
            },
          ],
        },
      ],
    },
  ],
  principals: [
    {
      address: SAFE_ADDR,
      type: "safe",
      label: "TestSafe",
      details: { threshold: 2, owners: ["0x0001", "0x0002", "0x0003"] },
      controls: [VAULT_ADDR],
    },
    {
      address: TL_ADDR,
      type: "timelock",
      label: "TestTimelock",
      details: { delay: 86400 },
      controls: [VAULT_ADDR],
    },
  ],
  fund_flows: [],
};

/** Intercept the company API and return our fixture. */
async function mockApi(page) {
  await page.route("**/api/company/testco", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(COMPANY_FIXTURE),
    })
  );
}

/** Navigate to the company surface page. */
async function goToSurface(page) {
  await mockApi(page);
  await page.goto("/company/testco/surface");
  // Wait for surface header to render
  await page.waitForSelector(".ps-surface", { timeout: 10000 });
  // Wait for ReactFlow canvas + ELK layout to produce nodes
  await page.waitForSelector(".react-flow__node", { timeout: 15000 });
}

/** Open the Vault contract's detail panel (the function lanes). */
async function openVaultDetail(page) {
  await page.locator(".ps-node").first().click();
  await page.waitForSelector(".ps-machine", { timeout: 5000 });
}

/** The .ps-port lane card for a given function name. */
function portFor(page, fnName) {
  return page.locator(".ps-port", {
    has: page.locator(".ps-port-name", { hasText: fnName }),
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Caller button navigation", () => {
  test("single safe caller button navigates to the safe principal detail", async ({ page }) => {
    await goToSurface(page);
    await openVaultDetail(page);

    const safePort = portFor(page, "setSafe");
    const safeBtn = safePort.locator(".ps-caller-btn");
    await expect(safeBtn).toHaveCount(1);
    await expect(safeBtn).toContainText("Safe");
    // A single caller renders no "callable by" header.
    await expect(safePort.locator(".ps-callers-label")).toHaveCount(0);

    // The button body previews; the arrow commits the navigation.
    await safeBtn.locator(".ps-goto-arrow").click();

    // Sidebar swaps to the principal detail.
    await expect(page.locator(".ps-machine-name")).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".ps-machine-address")).toContainText(SAFE_ADDR.slice(0, 6));
    // Selection follows the navigation target — the safe persists as ?sel=
    // (address only; the card is chosen from the entity's facets, no view axis).
    await expect(page).toHaveURL(new RegExp(`sel=${SAFE_ADDR}`));
    await expect(page).not.toHaveURL(/view=/);
  });

  test("single timelock caller button navigates to the timelock principal detail", async ({ page }) => {
    await goToSurface(page);
    await openVaultDetail(page);

    const tlBtn = portFor(page, "setTimelock").locator(".ps-caller-btn");
    await expect(tlBtn).toHaveCount(1);
    await expect(tlBtn).toContainText("Timelock");
    await tlBtn.locator(".ps-goto-arrow").click();

    await expect(page.locator(".ps-machine-name")).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".ps-machine-address")).toContainText(TL_ADDR.slice(0, 6));
  });

  test("single contract caller renders its own button", async ({ page }) => {
    await goToSurface(page);
    await openVaultDetail(page);

    const conBtn = portFor(page, "setOwner").locator(".ps-caller-btn");
    await expect(conBtn).toHaveCount(1);
    await expect(conBtn).toContainText("Contract");
    // The arrow navigates to the contract target; the entity index spans all
    // machines so it no longer silently no-ops. It must not throw — a selection
    // param is written (?sel=).
    await conBtn.locator(".ps-goto-arrow").click();
    await expect(page).toHaveURL(/sel=/);
  });

  test("a multi-caller function renders one button per caller, each navigating directly", async ({ page }) => {
    await goToSurface(page);
    await openVaultDetail(page);

    const mixedPort = portFor(page, "setMixed");
    // Two distinct callers → "callable by" header + two buttons (no tour).
    await expect(mixedPort.locator(".ps-callers-label")).toBeVisible();
    const mixedBtns = mixedPort.locator(".ps-caller-btn");
    await expect(mixedBtns).toHaveCount(2);
    await expect(mixedBtns.filter({ hasText: "Safe" })).toHaveCount(1);
    await expect(mixedBtns.filter({ hasText: "Timelock" })).toHaveCount(1);

    // The timelock button's arrow navigates straight to the timelock — no
    // intermediate "first principal + tour" hop.
    await mixedPort.locator(".ps-caller-btn", { hasText: "Timelock" }).locator(".ps-goto-arrow").click();
    await expect(page).toHaveURL(new RegExp(`sel=${TL_ADDR}`));
  });

  test("clicking the function name opens the guard inspector (not navigation)", async ({ page }) => {
    await goToSurface(page);
    await openVaultDetail(page);

    // Click the function name text, not a caller button.
    const fnName = page.locator(".ps-port-name", { hasText: "setSafe" }).first();
    await expect(fnName).toBeVisible();
    await fnName.click();

    const inspector = page.locator(".ps-inspector");
    await expect(inspector).toBeVisible({ timeout: 5000 });
    await expect(inspector.locator("h3")).toContainText("setSafe");
  });
});

test.describe("URL focus parameter", () => {
  test("legacy focus param in URL restores a committed selection", async ({ page }) => {
    await mockApi(page);
    await page.goto(`/company/testco/surface?focus=${VAULT_ADDR}`);
    await page.waitForSelector(".ps-node", { timeout: 10000 });

    // Wait for the restore to apply
    await page.waitForTimeout(500);

    // A legacy ?focus link resolves to a full selection: the node gets the
    // selected ring (the gold dotted ring is reserved for search browsing,
    // which never applies to the committed node) and the URL normalizes to
    // the ?sel form.
    const selectedNode = page.locator(".ps-node-selected");
    await expect(selectedNode).toBeVisible({ timeout: 5000 });
    await expect(selectedNode.locator(".ps-node-name")).toHaveText("Vault");
    await expect(page).toHaveURL(new RegExp(`sel=${VAULT_ADDR}`));
    await expect(page.locator(".ps-node-focused")).toHaveCount(0);
  });

  test("navigating updates focus param to new target", async ({ page }) => {
    await goToSurface(page);
    await openVaultDetail(page);

    // URL should select the vault contract
    await expect(page).toHaveURL(new RegExp(`sel=${VAULT_ADDR}`));

    // Click the safe caller button's arrow to navigate to the safe principal
    await portFor(page, "setSafe").locator(".ps-caller-btn .ps-goto-arrow").click();

    // URL selection should now point to the safe address, not the vault
    await expect(page).toHaveURL(new RegExp(`sel=${SAFE_ADDR}`));
  });
});
