/**
 * Co-controllers on the Surface canvas.
 *
 * A co-controller is a principal that holds real authority on a contract it
 * isn't the primary owner of (e.g. EtherFi's pause/fund-recovery guardian
 * Safe, which the bigger governance Safe out-ranks for primary). They used to
 * render as illegible dots in a left "guardian rail"; now they live inside the
 * owning group's Controllers accordion — one row per controller (the primary
 * owner plus every co-controller), each expanding to the exact functions it
 * can call per contract.
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
      // primary owner nor a co-controller. Rendered in aggregate as "+N
      // callers", each carrying the functions / capabilities it can call.
      other_callers: [
        { address: "0x" + "41".repeat(20), type: "eoa", label: "bot-a", functions: ["createBid"], capabilities: [] },
        { address: "0x" + "42".repeat(20), type: "safe", label: "bidder-x", functions: ["createBid"], capabilities: [] },
        { address: "0x" + "43".repeat(20), type: "eoa", label: "bot-b", functions: ["createBid"], capabilities: [] },
      ],
    },
  ],
  principals: [
    // Primary owner → renders as the group container around VAULT, and the
    // PRIMARY row of its Controllers accordion.
    {
      address: GOV_SAFE,
      type: "safe",
      label: "GovSafe",
      details: { threshold: 6, owners: ["0x01", "0x02"] },
      controls: [VAULT],
      primary_for: [VAULT],
      co_controls: [],
      // A rich capability set (6 tags) so the row summary proves it shows ALL
      // of them, comma-separated, never truncated to "+N".
      controls_detail: [
        {
          address: VAULT,
          functions: ["upgradeTo", "transferOwnership"],
          capabilities: ["ownership", "upgrade", "pause", "fund-out", "roles", "authority"],
        },
      ],
    },
    // Co-controller → no group of its own; surfaces as a CO row in GOV_SAFE's
    // accordion, expanding to the functions it can call on VAULT.
    {
      address: GUARDIAN,
      type: "safe",
      label: "Guardian",
      details: { threshold: 4, owners: ["0x0a", "0x0b", "0x0c", "0x0d"] },
      controls: [VAULT],
      primary_for: [],
      co_controls: [VAULT],
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
  test("lists the primary and every co-controller in the group's accordion", async ({ page }) => {
    await goToSurface(page);

    // The old guardian rail is gone — no standalone co-controller node.
    expect(await page.locator(".ps-principal-node--guardian").count()).toBe(0);

    // The primary owner is the first accordion row, tagged PRIMARY, with its
    // capability summary showing EVERY tag (verbatim, comma-separated) — not
    // truncated to "+N".
    const primary = page.locator(".ps-ctrl-row--primary");
    await expect(primary).toBeVisible();
    await expect(primary).toContainText("primary");
    const capsText = await primary.locator(".ps-ctrl-caps").innerText();
    for (const tag of ["authority", "fund-out", "ownership", "pause", "roles", "upgrade"]) {
      expect(capsText).toContain(tag);
    }
    expect(capsText).not.toContain("+"); // no "+N" truncation
    expect(capsText).toContain(","); // comma-separated like the rest of the app

    // The co-controller is a CO row in the same box, scoped to VAULT.
    const co = page.locator(".ps-ctrl-row--co");
    await expect(co).toBeVisible();
    await expect(co).toContainText("co");
    await expect(co.locator(".ps-ctrl-caps")).toContainText("pause");
    await expect(co.locator(".ps-ctrl-governs")).toContainText("governs 1");

    // Collapsed by default — no function detail until a row is expanded.
    expect(await page.locator(".ps-ctrl-detail").count()).toBe(0);
  });

  test("clicking a controller highlights the contracts it governs without zooming the camera", async ({ page }) => {
    await goToSurface(page);

    // Click the co-controller row → it reads as selected, and VAULT (the
    // contract it governs) gets an on-card capability chip, mirroring a click
    // on the group header.
    await page.locator(".ps-ctrl-row--co .ps-ctrl-head").click();
    await expect(page.locator(".ps-ctrl-row--co.ps-ctrl-row--selected")).toBeVisible();
    await expect(page.locator(".ps-node-chip--out", { hasText: "pause" }).first()).toBeVisible();

    // The primary controller IS a group node, so selecting it used to pan/zoom
    // the camera to it. Clicking its row highlights (selects) without moving
    // the camera — no focus param is written to the URL.
    await page.locator(".ps-ctrl-row--primary .ps-ctrl-head").click();
    await expect(page.locator(".ps-ctrl-row--primary.ps-ctrl-row--selected")).toBeVisible();
    await expect(page).not.toHaveURL(/focus=/);
  });

  test("expanding a controller row reveals the exact functions it can call", async ({ page }) => {
    await goToSurface(page);

    await page.locator(".ps-ctrl-row--co .ps-ctrl-head").click();

    // The detail overlay lists VAULT and the function the co-controller can
    // actually invoke on it.
    const detail = page.locator(".ps-ctrl-row--co .ps-ctrl-detail");
    await expect(detail).toBeVisible();
    await expect(detail).toContainText("Vault");
    await expect(detail.locator(".ps-ctrl-fnchip", { hasText: "pauseContract" })).toBeVisible();

    // Exclusive expansion: opening the primary closes the co row.
    await page.locator(".ps-ctrl-row--primary .ps-ctrl-head").click();
    await expect(page.locator(".ps-ctrl-row--co .ps-ctrl-detail")).toHaveCount(0);
    await expect(page.locator(".ps-ctrl-row--primary .ps-ctrl-detail")).toBeVisible();
    await expect(
      page.locator(".ps-ctrl-row--primary .ps-ctrl-fnchip", { hasText: "transferOwnership" }),
    ).toBeVisible();
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
