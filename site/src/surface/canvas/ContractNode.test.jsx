import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render } from "@testing-library/react";

// ContractNode renders ReactFlow <Handle>s, which need the ReactFlow store
// context. Stub them so we can unit-test the card's own render logic — the
// proxy marker — without standing up a full canvas.
vi.mock("@xyflow/react", () => ({
  Handle: () => null,
  Position: { Top: "top", Bottom: "bottom", Left: "left", Right: "right" },
}));

import { ContractNode } from "./ContractNode.jsx";

function renderNode(machine) {
  const { container } = render(
    <ContractNode data={{ machine, onSelect: () => {} }} />,
  );
  return container;
}

describe("ContractNode — proxy indicator", () => {
  it("shows a PROXY line + glyph + upgrade count for an upgradeable proxy", () => {
    const c = renderNode({
      address: "0x308861a430be4cce5502d0a12724771fc6daf216",
      name: "LiquidityPool",
      role: "value_handler",
      is_proxy: true,
      proxy_type: "eip1967",
      upgrade_count: 16,
    });
    const el = c.querySelector(".ps-node-proxy");
    expect(el).toBeTruthy();
    expect(el.querySelector("svg")).toBeTruthy();
    expect(el.textContent).toMatch(/PROXY/);
    expect(el.textContent).toMatch(/16 upgrades/);
  });

  it("singularizes a single upgrade", () => {
    const c = renderNode({ address: "0x2", name: "X", role: "utility", is_proxy: true, proxy_type: "eip1967", upgrade_count: 1 });
    const text = c.querySelector(".ps-node-proxy").textContent;
    expect(text).toContain("1 upgrade");
    expect(text).not.toMatch(/upgrades/);
  });

  it("omits the count when upgrade_count is null or zero", () => {
    const cNull = renderNode({ address: "0x3", name: "Beacon", role: "utility", is_proxy: true, proxy_type: "eip1967", upgrade_count: null });
    const elNull = cNull.querySelector(".ps-node-proxy");
    expect(elNull.textContent).toMatch(/PROXY/);
    expect(elNull.textContent).not.toMatch(/upgrade/i);

    const cZero = renderNode({ address: "0x4", name: "Beacon0", role: "utility", is_proxy: true, proxy_type: "eip1967", upgrade_count: 0 });
    expect(cZero.querySelector(".ps-node-proxy").textContent).not.toMatch(/upgrade/i);
  });

  it("labels a gnosis_safe proxy as SAFE PROXY", () => {
    const c = renderNode({ address: "0x5", name: "SafeProxy", role: "utility", is_proxy: true, proxy_type: "gnosis_safe", upgrade_count: 0 });
    expect(c.querySelector(".ps-node-proxy").textContent).toMatch(/SAFE PROXY/);
  });

  it("renders no proxy line for a regular contract", () => {
    const c = renderNode({ address: "0x6", name: "RolesAuthority", role: "utility", is_proxy: false });
    expect(c.querySelector(".ps-node-proxy")).toBeNull();
  });
});

describe("ContractNode — timelock marker", () => {
  it("shows a TIMELOCK line and flips the role label for a timelock contract", () => {
    const c = renderNode({ address: "0x9f26", name: "EtherFiTimelock", role: "value_handler", isTimelock: true, timelockDelay: 172800 });
    const el = c.querySelector(".ps-node-timelock");
    expect(el).toBeTruthy();
    expect(el.querySelector("svg")).toBeTruthy();
    expect(el.textContent).toMatch(/TIMELOCK/);
    // role label is replaced (not the classifier's "Value Handler")
    expect(c.querySelector(".ps-node-role").textContent).toBe("Timelock");
  });

  it("shows the delay when known and omits it otherwise", () => {
    const c1 = renderNode({ address: "0x1", name: "TL", role: "utility", isTimelock: true, timelockDelay: 172800 });
    expect(c1.querySelector(".ps-node-timelock").textContent).toMatch(/2d delay/);
    const c2 = renderNode({ address: "0x2", name: "TL2", role: "utility", isTimelock: true, timelockDelay: null });
    const t2 = c2.querySelector(".ps-node-timelock").textContent;
    expect(t2).toMatch(/TIMELOCK/);
    expect(t2).not.toMatch(/delay/);
  });

  it("leaves a non-timelock contract untouched", () => {
    const c = renderNode({ address: "0x3", name: "WeETH", role: "value_handler", isTimelock: false });
    expect(c.querySelector(".ps-node-timelock")).toBeNull();
    expect(c.querySelector(".ps-node-role").textContent).toBe("Value Handler");
  });
});
