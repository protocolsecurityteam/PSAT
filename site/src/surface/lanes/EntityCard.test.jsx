// Render + interaction tests for the universal entity card: the always-present
// Governs tab (Can Call + governance path), the collapsible Can Call rows,
// dual-facet identity badges, and the principal-only card shape.

import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, within } from "@testing-library/react";

import { EntityCard } from "./EntityCard.jsx";

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

describe("EntityCard Governs tab", () => {
  it("keeps the Governs tab present with an empty state when the entity governs nothing", () => {
    const { getByText } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(getByText("Governs nothing")).toBeInTheDocument();
  });

  it("shows the Governs tab count and one collapsible row per governed contract", () => {
    const idx = governsWith([
      { contractAddress: POOL, contractName: "LiquidityPool", functions: ["upgradeTo", "pause"] },
    ]);
    const { getByText, container } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={idx} />,
    );
    const tab = getByText("Governs").closest("button");
    expect(within(tab).getByText("1")).toBeInTheDocument();
    fireEvent.click(tab);
    // Row is present but collapsed by default — no function chips yet.
    expect(getByText("LiquidityPool")).toBeInTheDocument();
    expect(container.querySelectorAll(".ps-ctrl-fnchip")).toHaveLength(0);
    // Expanding the row reveals every function.
    fireEvent.click(getByText("LiquidityPool").closest("button"));
    expect(container.querySelectorAll(".ps-ctrl-fnchip")).toHaveLength(2);
  });

  it("navigates to the governed contract via the view (→) link", () => {
    const onNavigate = vi.fn();
    const idx = governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["pause"] }]);
    const { getByText, container } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onNavigate={onNavigate} governsIndex={idx} />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    fireEvent.click(container.querySelector(".ps-governs-goto"));
    expect(onNavigate).toHaveBeenCalledWith({ type: "contract", address: POOL });
  });

  it("shows the capability summary for a governed contract when a principal facet is present", () => {
    const idx = governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["upgradeTo"] }]);
    const principal = {
      address: TIMELOCK,
      type: "timelock",
      details: { delay: 864000 },
      controls_detail: [{ address: POOL, functions: ["upgradeTo"], capabilities: ["upgrade"] }],
    };
    const { getByText, container } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={idx} principal={principal} />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(container.querySelector(".ps-governs-summary")).toHaveTextContent("upgrade");
  });
});

describe("EntityCard identity badges (dual facet)", () => {
  it("renders the type + delay badges for a dual-facet timelock", () => {
    const principal = { address: TIMELOCK, type: "timelock", details: { delay: 864000 } };
    const { container, getByText } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} principal={principal} />,
    );
    const badges = container.querySelector(".ps-machine-badges");
    expect(within(badges).getByText("TL")).toBeInTheDocument();
    expect(getByText("10d delay")).toBeInTheDocument();
  });

  it("renders the timelock + delay badges from the machine facet when no principal entry exists", () => {
    // The EtherFiTimelock case: an analyzed timelock absent from principals —
    // its identity lives on machine.isTimelock/timelockDelay (same fields the
    // canvas node's TIMELOCK marker uses).
    const { container, getByText } = render(
      <EntityCard
        machine={machine({ isTimelock: true, timelockDelay: 864000 })}
        onSelectGuard={vi.fn()}
        onNavigate={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    const badges = container.querySelector(".ps-machine-badges");
    expect(within(badges).getByText("Timelock")).toBeInTheDocument();
    expect(getByText("10d delay")).toBeInTheDocument();
  });

  it("does not double-badge a dual-facet timelock (principal badge wins)", () => {
    const principal = { address: TIMELOCK, type: "timelock", details: { delay: 864000 } };
    const { container } = render(
      <EntityCard
        machine={machine({ isTimelock: true, timelockDelay: 864000 })}
        onSelectGuard={vi.fn()}
        onNavigate={vi.fn()}
        governsIndex={new Map()}
        principal={principal}
      />,
    );
    const badges = container.querySelector(".ps-machine-badges");
    expect(within(badges).getAllByText(/delay/)).toHaveLength(1);
  });

  it("renders the type + threshold badges for a dual-facet safe", () => {
    const principal = {
      address: TIMELOCK,
      type: "safe",
      details: { threshold: 4, owners: ["0xa", "0xb", "0xc", "0xd", "0xe", "0xf"] },
    };
    const { container, getByText } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onNavigate={vi.fn()} governsIndex={new Map()} principal={principal} />,
    );
    const badges = container.querySelector(".ps-machine-badges");
    expect(within(badges).getByText("SAFE")).toBeInTheDocument();
    expect(getByText("4/6 threshold")).toBeInTheDocument();
  });
});

describe("EntityCard principal-only", () => {
  it("collapses to the Governs tab alone (auto-open) with a signers list", () => {
    const principal = {
      address: TIMELOCK,
      type: "safe",
      label: "GovSafe",
      details: { threshold: 2, owners: ["0xa", "0xb", "0xc"] },
      controls: [],
    };
    const { container, getByText, queryByText } = render(
      <EntityCard principal={principal} onNavigate={vi.fn()} governsIndex={new Map()} machines={[]} />,
    );
    // No machine facet → no Control/Inflows/Outflows/Balances tabs.
    expect(queryByText("Control")).toBeNull();
    expect(queryByText("Inflows")).toBeNull();
    // Governs is the only tab and is auto-opened → its empty state renders.
    expect(getByText("Governs")).toBeInTheDocument();
    expect(getByText("Governs nothing")).toBeInTheDocument();
    // Signers list from the safe.
    expect(getByText("Signers (3)")).toBeInTheDocument();
    expect(container.querySelectorAll(".ps-principal-signer")).toHaveLength(3);
  });
});
