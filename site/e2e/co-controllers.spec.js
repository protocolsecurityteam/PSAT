/**
 * Co-controllers on the Surface canvas.
 *
 * A co-controller is a principal that holds real authority on a contract it
 * isn't the primary owner of (e.g. EtherFi's pause/fund-recovery guardian
 * Safe, which the bigger governance Safe out-ranks for primary). The canvas
 * renders these as their own nodes in a guardians rail above the groups —
 * always visible at fit-view, unlike an on-card label. Their edges to the
 * contracts they control appear only on select, so the rail stays a clean
 * band rather than permanent cross-group fanout.
 */
import { test, expect } from "@playwright/test";

const VAULT = "0x1111111111111111111111111111111111111111";
const GOV_SAFE = "0x2222222222222222222222222222222222222222"; // primary owner of VAULT
const GUARDIAN = "0x3333333333333333333333333333333333333333"; // pause-only co-controller

const FIXTURE = {
  contracts: [
    {
      address: VAULT,
      name: "Vault",
      display_name: "Vault",
      role: "governance",
      functions: [
        {
          function: "pauseContract()",
          selector: "0x11111111",
          effect_labels: ["pause_toggle"],
          direct_owner: {
            address: GUARDIAN,
            resolved_type: "safe",
            details: { threshold: 4, owners: ["0x0a", "0x0b", "0x0c", "0x0d"] },
          },
          authority_roles: [],
          controllers: [],
        },
      ],
      // Permissionless / lower-privilege callers (server-computed): neither the
      // primary owner nor a guardian. Rendered in aggregate as "+N callers",
      // each carrying the functions / capabilities it can actually call.
      other_callers: [
        { address: "0x" + "41".repeat(20), type: "eoa", label: "bot-a", functions: ["createBid"], capabilities: [] },
        { address: "0x" + "42".repeat(20), type: "safe", label: "bidder-x", functions: ["createBid"], capabilities: [] },
        { address: "0x" + "43".repeat(20), type: "eoa", label: "bot-b", functions: ["createBid"], capabilities: [] },
      ],
    },
  ],
  principals: [
    // Primary owner → renders as the group container around VAULT.
    {
      address: GOV_SAFE,
      type: "safe",
      label: "GovSafe",
      details: { threshold: 6, owners: ["0x01", "0x02"] },
      controls: [VAULT],
      primary_for: [VAULT],
      co_controls: [],
    },
    // Co-controller → no group of its own; surfaces as a chip on VAULT.
    {
      address: GUARDIAN,
      type: "safe",
      label: "Guardian",
      details: { threshold: 4, owners: ["0x0a", "0x0b", "0x0c", "0x0d"] },
      controls: [VAULT],
      primary_for: [],
      co_controls: [VAULT],
      // Verified per-contract call rights — drives the on-select capability
      // chips and the sidebar "Can Call" list (vs a generic "controlled").
      controls_detail: [{ address: VAULT, functions: ["pauseContract"], capabilities: ["pause"] }],
    },
  ],
  fund_flows: [],
};

async function goToSurface(page) {
  await page.route("**/api/company/cctest", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(FIXTURE) })
  );
  await page.goto("/company/cctest/surface");
  await page.waitForSelector(".ps-surface", { timeout: 10000 });
  await page.waitForSelector(".react-flow__node", { timeout: 15000 });
}

test.describe("Surface co-controllers", () => {
  test("renders a co-controller as a guardian node, visible by default", async ({ page }) => {
    await goToSurface(page);

    // The guardian is its own node in the rail (always visible at fit-view),
    // tagged "co-controller" to distinguish it from a primary group owner.
    const guardian = page.locator(".ps-principal-node--guardian");
    await expect(guardian).toBeVisible();
    await expect(guardian).toContainText("co-controller");
    // No co-control edges are drawn until it's selected.
    expect(await page.locator(".react-flow__edge").count()).toBe(0);
  });

  test("selecting a guardian draws its edges to the contracts it controls", async ({ page }) => {
    await goToSurface(page);

    await page.locator(".ps-principal-node--guardian").click();

    // Edges from the guardian to its governed contract appear on select...
    await expect(page.locator(".react-flow__edge").first()).toBeVisible({ timeout: 5000 });
    // ...the on-card chip says what it can DO (its capability), not "controlled"...
    await expect(page.locator(".ps-node-chip--out", { hasText: "pause" }).first()).toBeVisible();
    // ...the sidebar lists the verified call rights per contract...
    await expect(page.locator(".ps-principal-cancall-caps", { hasText: "pause" }).first()).toBeVisible();
    // ...and selecting it focuses it (URL focus param), like any principal.
    await expect(page).toHaveURL(/focus=/);
  });

  test("aggregates permissionless callers into a '+N callers' affordance + sidebar list", async ({ page }) => {
    await goToSurface(page);

    // The long tail is a single per-contract affordance, not a node each.
    const callers = page.locator(".ps-node-callers");
    await expect(callers).toBeVisible();
    await expect(callers).toContainText("+3 callers");

    // Clicking it opens the contract detail and lists every caller with the
    // function each can actually call (not a generic "controlled").
    await callers.click();
    await expect(page.locator(".ps-machine-caller").first()).toBeVisible({ timeout: 5000 });
    expect(await page.locator(".ps-machine-caller").count()).toBe(3);
    await expect(page.locator(".ps-machine-caller-caps", { hasText: "createBid" }).first()).toBeVisible();
  });
});
