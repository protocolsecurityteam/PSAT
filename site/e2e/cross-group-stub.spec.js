/**
 * Cross-group contract connections on the Surface canvas.
 *
 * A contract's cross-group relationships are aggregated into a single
 * group→group bundle (anchored box-to-box, not on the contract) to avoid
 * per-contract fanout. So a grouped contract that calls into another group
 * would otherwise look unconnected. To keep each such contract legible we draw
 * permanent stubs that highlight like any other edge:
 *   - the SOURCE contract gets an outbound stub down to its group's bottom edge
 *     (where the bundle leaves);
 *   - the TARGET contract gets an inbound stub dropping from just under its
 *     group's header to its top (the bundle arrives at the box top as normal;
 *     the header hides the segment between, so it reads as continuing through).
 */
import { test, expect } from "@playwright/test";

const SAFE_A = "0x" + "a1".repeat(20);
const SAFE_B = "0x" + "b2".repeat(20);
const SAFE_C = "0x" + "c3".repeat(20);
const SAFE_D = "0x" + "d4".repeat(20);
const ALPHA = "0x" + "11".repeat(20); // owned by SAFE_A, calls into SAFE_B's group
const BETA = "0x" + "22".repeat(20); // owned by SAFE_B
// A second, unrelated cross-group pair (Gamma → Delta) so we can assert that
// selecting Alpha/Beta dims stubs that aren't part of their path.
const GAMMA = "0x" + "33".repeat(20); // owned by SAFE_C, calls into SAFE_D's group
const DELTA = "0x" + "44".repeat(20); // owned by SAFE_D

function contract(address, name, ownerSafe, ownerThreshold) {
  return {
    address,
    name,
    display_name: name,
    role: "value_handler",
    functions: [
      {
        function: "poke()",
        selector: "0x12345678",
        claims: [{ claim_id: "pause.set", tier: "standard_exact", witness: {} }],
        direct_owner: { address: ownerSafe, resolved_type: "safe", details: { threshold: ownerThreshold, owners: ["0x01", "0x02", "0x03"] } },
        authority_roles: [],
        controllers: [],
      },
    ],
  };
}

function safe(address, label, threshold, owned) {
  return {
    address,
    type: "safe",
    label,
    details: { threshold, owners: ["0x01", "0x02", "0x03"] },
    controls: [owned],
    primary_for: [owned],
    co_controls: [],
    controls_detail: [{ address: owned, functions: ["poke"], capabilities: ["pause"] }],
  };
}

const FIXTURE = {
  contracts: [
    contract(ALPHA, "Alpha", SAFE_A, 2),
    contract(BETA, "Beta", SAFE_B, 3),
    contract(GAMMA, "Gamma", SAFE_C, 2),
    contract(DELTA, "Delta", SAFE_D, 2),
  ],
  principals: [
    safe(SAFE_A, "SafeA", 2, ALPHA),
    safe(SAFE_B, "SafeB", 3, BETA),
    safe(SAFE_C, "SafeC", 2, GAMMA),
    safe(SAFE_D, "SafeD", 2, DELTA),
  ],
  // Two independent cross-group links: Alpha → Beta and Gamma → Delta. Each
  // aggregates into its own box→box bundle; the pairs don't touch each other.
  fund_flows: [
    { from: ALPHA, to: BETA, type: "controls_value", lane: "control", capabilities: ["fund-out"] },
    { from: GAMMA, to: DELTA, type: "controls_value", lane: "control", capabilities: ["fund-out"] },
  ],
};

const FUNCTIONS_FIXTURE = {
  functions: Object.fromEntries(
    FIXTURE.contracts.map((entry) => [
      `ethereum::${entry.address.toLowerCase()}`,
      entry.functions || [],
    ]),
  ),
};

async function goToSurface(page) {
  await page.route("**/api/company/xgtest/functions", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(FUNCTIONS_FIXTURE) })
  );
  await page.route("**/api/company/xgtest", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(FIXTURE) })
  );
  await page.goto("/company/xgtest/surface");
  await page.waitForSelector(".ps-surface", { timeout: 10000 });
  await page.waitForSelector(".react-flow__node-group", { timeout: 15000 });
  // This 4-group fixture packs into the top-left, where the floating filter
  // panel legitimately sits. This spec tests stub geometry/highlighting, not the
  // panel, so make the panel click-transparent rather than pan around it (a real
  // large graph wouldn't fully hide a node under the panel).
  await page.addStyleTag({ content: ".ps-filter-overlay { pointer-events: none; }" });
}

const OUT_STUB = `.react-flow__edge[data-id="stub-out-${ALPHA}"]`; // Alpha is the source
const IN_STUB = `.react-flow__edge[data-id="stub-in-${BETA}"]`; // Beta is the target
const FAR_OUT_STUB = `.react-flow__edge[data-id="stub-out-${GAMMA}"]`; // unrelated pair
const FAR_IN_STUB = `.react-flow__edge[data-id="stub-in-${DELTA}"]`; // unrelated pair

const edgeOpacity = (page, sel) =>
  page.locator(`${sel} .react-flow__edge-path`).first().evaluate((p) => parseFloat(getComputedStyle(p).opacity));

test.describe("Surface cross-group contract connections", () => {
  test("cross-group contracts show permanent outbound + inbound stubs that highlight like any other edge", async ({ page }) => {
    await goToSurface(page);
    await expect(page.locator(".react-flow__node-group")).toHaveCount(4);

    // Stubs are part of the layout, not a selection artifact: Alpha (source)
    // gets an outbound stub, Beta (target) gets an inbound stub, both at rest.
    await expect(page.locator(OUT_STUB)).toHaveCount(1);
    await expect(page.locator(IN_STUB)).toHaveCount(1);

    // They're ordinary edges — no elevation above the cards, no glow — so they
    // read as part of the graph rather than a special selection overlay.
    const cardZ = await page
      .locator(".react-flow__node-contract")
      .first()
      .evaluate((n) => parseInt(getComputedStyle(n).zIndex, 10) || 0);
    for (const sel of [OUT_STUB, IN_STUB]) {
      const s = await page.locator(sel).first().evaluate((g) => {
        const p = g.querySelector(".react-flow__edge-path");
        return {
          z: parseInt(getComputedStyle(g.closest("svg")).zIndex, 10) || 0,
          opacity: parseFloat(getComputedStyle(p).opacity),
          filter: getComputedStyle(p).filter,
        };
      });
      expect(s.opacity).toBeGreaterThan(0.9); // visible at rest
      expect(s.z).toBeLessThanOrEqual(cardZ + 1); // not lifted above the cards
      expect(s.filter).toBe("none"); // no glow
    }

    // The inbound stub is a downward drop that starts at/below its group's
    // header band — it never starts up at the box top (which would paint across
    // the header). We assert it begins in the header's lower half or below, so
    // the header reads as hiding the segment above it.
    const inbound = await page.locator(IN_STUB).first().evaluate((g) => {
      const path = g.querySelector(".react-flow__edge-path");
      const ys = [...path.getAttribute("d").matchAll(/[ML] [\d.]+ ([\d.]+)/g)].map((m) => parseFloat(m[1]));
      const r = path.getBoundingClientRect();
      // Beta's group = the box containing the stub's bottom point.
      const group = [...document.querySelectorAll(".react-flow__node-group")].find((gr) => {
        const b = gr.getBoundingClientRect();
        return r.left >= b.left - 5 && r.left <= b.right + 5 && r.bottom >= b.top && r.bottom <= b.bottom + 5;
      });
      const head = group?.querySelector(".ps-group-head").getBoundingClientRect();
      return { monotonicDown: ys[ys.length - 1] >= ys[0], stubTop: r.top, headerTop: head?.top ?? 0, headerBottom: head?.bottom ?? 0 };
    });
    expect(inbound.monotonicDown).toBe(true);
    expect(inbound.stubTop).toBeGreaterThan((inbound.headerTop + inbound.headerBottom) / 2);

    // The WHOLE path lights when you select either end of a link: selecting
    // Alpha brings up BOTH its outbound stub and Beta's inbound stub (the bug
    // was the connected contract's stub staying dim). The unrelated Gamma→Delta
    // stubs dim, so the highlight stays scoped to the selection's connections.
    // Beta also gets an on-card chip.
    await page.locator(".react-flow__node-contract", { hasText: "Alpha" }).first().click();
    await expect.poll(() => edgeOpacity(page, OUT_STUB)).toBeGreaterThan(0.9);
    await expect.poll(() => edgeOpacity(page, IN_STUB)).toBeGreaterThan(0.9);
    await expect.poll(() => edgeOpacity(page, FAR_OUT_STUB)).toBeLessThan(0.5);
    await expect.poll(() => edgeOpacity(page, FAR_IN_STUB)).toBeLessThan(0.5);
    await expect(page.locator(".ps-node-chip--out").first()).toBeVisible();

    // Symmetric from the other end: selecting Beta lights the same path and
    // still leaves the unrelated pair dim.
    await page.locator(".react-flow__node-contract", { hasText: "Beta" }).first().click();
    await expect.poll(() => edgeOpacity(page, IN_STUB)).toBeGreaterThan(0.9);
    await expect.poll(() => edgeOpacity(page, OUT_STUB)).toBeGreaterThan(0.9);
    await expect.poll(() => edgeOpacity(page, FAR_OUT_STUB)).toBeLessThan(0.5);
  });
});
