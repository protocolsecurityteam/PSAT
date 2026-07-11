import { describe, it, expect } from "vitest";

import {
  buildEntityIndex,
  nodelessPrincipalHighlight,
  principalTouchSet,
} from "./entities.js";

const PRIMARY = "0x1111111111111111111111111111111111111111"; // group owner
const COCO = "0x2222222222222222222222222222222222222222"; // node-less co-controller
const VAULT = "0x3333333333333333333333333333333333333333";
const POOL = "0x4444444444444444444444444444444444444444";

describe("principalTouchSet", () => {
  it("collects the principal itself plus controls, co_controls and controls_detail", () => {
    const set = principalTouchSet({
      address: COCO,
      controls: [VAULT],
      co_controls: [POOL],
      controls_detail: [{ address: "0x5555555555555555555555555555555555555555" }],
    });
    expect(set.has(COCO)).toBe(true);
    expect(set.has(VAULT)).toBe(true);
    expect(set.has(POOL)).toBe(true);
    expect(set.has("0x5555555555555555555555555555555555555555")).toBe(true);
    expect(set.size).toBe(4);
  });

  it("lowercases every address and tolerates missing fields", () => {
    const set = principalTouchSet({ address: VAULT.toUpperCase(), controls: [POOL.toUpperCase()] });
    expect(set.has(VAULT)).toBe(true);
    expect(set.has(POOL)).toBe(true);
    expect(principalTouchSet(null).size).toBe(0);
  });
});

describe("nodelessPrincipalHighlight", () => {
  const canvasNodeAddrs = new Set([VAULT, POOL, PRIMARY]);

  it("returns the reach (not the principal itself) for a node-less co-controller", () => {
    const hi = nodelessPrincipalHighlight(
      { address: COCO, co_controls: [VAULT] },
      canvasNodeAddrs,
    );
    expect(hi).not.toBeNull();
    expect(hi.has(VAULT)).toBe(true);
    // The principal owns no node, so it isn't part of the highlight set.
    expect(hi.has(COCO)).toBe(false);
  });

  it("returns null for a group-backed principal (keeps its own ring/focus)", () => {
    // PRIMARY owns a canvas node, so its selection must not be overridden by a
    // highlight overlay.
    expect(
      nodelessPrincipalHighlight({ address: PRIMARY, controls: [VAULT] }, canvasNodeAddrs),
    ).toBeNull();
  });

  it("returns null when the principal reaches nothing beyond itself", () => {
    expect(
      nodelessPrincipalHighlight({ address: COCO, controls: [], co_controls: [] }, canvasNodeAddrs),
    ).toBeNull();
  });

  it("returns null when none of the reach is on the canvas (avoids blanking it)", () => {
    // Controls only an off-canvas address → nothing to ring, so no overlay.
    expect(
      nodelessPrincipalHighlight(
        { address: COCO, controls: ["0x9999999999999999999999999999999999999999"] },
        canvasNodeAddrs,
      ),
    ).toBeNull();
  });

  it("returns null for no principal", () => {
    expect(nodelessPrincipalHighlight(null, canvasNodeAddrs)).toBeNull();
  });
});

describe("buildEntityIndex", () => {
  it("carries both facets for a timelock that is machine and principal", () => {
    const idx = buildEntityIndex(
      [{ address: VAULT }, { address: PRIMARY }],
      [{ address: PRIMARY, type: "timelock" }],
    );
    expect(idx.get(VAULT).machine).toBeTruthy();
    expect(idx.get(VAULT).principal).toBeNull();
    expect(idx.get(PRIMARY).machine).toBeTruthy();
    expect(idx.get(PRIMARY).principal).toBeTruthy();
  });
});
