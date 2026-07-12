// Render + interaction tests for the Governs tab and the dual-facet principal
// strip added to the contract card.

import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, within } from "@testing-library/react";

import { ContractMachine } from "./ContractMachine.jsx";

const POOL = "0x3333333333333333333333333333333333333333";
const TIMELOCK = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761";

function machine(overrides = {}) {
  return {
    address: TIMELOCK,
    name: "EtherFiTimelock",
    role: "governance",
    totalFunctions: 0,
    balances: [],
    lanes: { top: [], left: [], right: [], ops: [] },
    ...overrides,
  };
}

function governsWith(rows) {
  return new Map([[TIMELOCK, rows]]);
}

describe("ContractMachine Governs tab", () => {
  it("hides the Governs tab when the entity governs nothing", () => {
    const { queryByText } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} />,
    );
    expect(queryByText("Governs")).toBeNull();
  });

  it("shows the Governs tab with a count and one row per governed contract", () => {
    const idx = governsWith([
      { contractAddress: POOL, contractName: "LiquidityPool", functions: ["upgradeTo", "pause"] },
    ]);
    const { getByText, container } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={idx} />,
    );
    const tab = getByText("Governs").closest("button");
    expect(within(tab).getByText("1")).toBeInTheDocument();
    fireEvent.click(tab);
    expect(getByText("LiquidityPool")).toBeInTheDocument();
    expect(container.querySelectorAll(".ps-ctrl-fnchip")).toHaveLength(2);
  });

  it("navigates to the governed contract (type:contract) when its name is clicked", () => {
    const onNavigate = vi.fn();
    const idx = governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["pause"] }]);
    const { getByText } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={onNavigate} governsIndex={idx} />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    fireEvent.click(getByText("LiquidityPool"));
    expect(onNavigate).toHaveBeenCalledWith({ type: "contract", address: POOL });
  });

  it("shows capability tags for a governed contract when a principal facet is present", () => {
    const idx = governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["upgradeTo"] }]);
    const principal = {
      address: TIMELOCK,
      type: "timelock",
      details: { delay: 864000 },
      controls_detail: [{ address: POOL, functions: ["upgradeTo"], capabilities: ["upgrade"] }],
    };
    const { getByText, container } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={idx} principal={principal} />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(container.querySelector(".ps-governs-cap")).toHaveTextContent("upgrade");
  });
});

describe("ContractMachine principal strip", () => {
  it("renders no strip when the contract has no principal facet", () => {
    const { container } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} />,
    );
    expect(container.querySelector(".ps-machine-principal-strip")).toBeNull();
  });

  it("renders the badge + delay for a dual-facet timelock", () => {
    const principal = { address: TIMELOCK, type: "timelock", details: { delay: 864000 } };
    const { container, getByText } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} principal={principal} />,
    );
    const strip = container.querySelector(".ps-machine-principal-strip");
    expect(strip).toBeInTheDocument();
    expect(within(strip).getByText("TL · 10d")).toBeInTheDocument();
    expect(getByText("10d delay")).toBeInTheDocument();
  });

  it("renders threshold/signers for a dual-facet safe", () => {
    const principal = {
      address: TIMELOCK,
      type: "safe",
      details: { threshold: 4, owners: ["0xa", "0xb", "0xc", "0xd", "0xe", "0xf"] },
    };
    const { container, getByText } = render(
      <ContractMachine machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} principal={principal} />,
    );
    const strip = container.querySelector(".ps-machine-principal-strip");
    expect(within(strip).getByText("4/6 SAFE")).toBeInTheDocument();
    expect(getByText("4/6 signers")).toBeInTheDocument();
  });
});
