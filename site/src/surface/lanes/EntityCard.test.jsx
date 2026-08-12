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

  it("shows the Governs tab count and an expand button revealing every function", () => {
    const idx = governsWith([
      { contractAddress: POOL, contractName: "LiquidityPool", functions: ["upgradeTo", "pause"] },
    ]);
    const { getByText, container } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onPreview={vi.fn()} governsIndex={idx} />,
    );
    const tab = getByText("Governs").closest("button");
    expect(within(tab).getByText("1")).toBeInTheDocument();
    fireEvent.click(tab);
    // Row is present but collapsed by default — name/value only, no chips.
    expect(getByText("LiquidityPool")).toBeInTheDocument();
    expect(container.querySelectorAll(".ps-ctrl-fnchip")).toHaveLength(0);
    // The expand button carries the function count; clicking it reveals them.
    const expand = container.querySelector(".ps-governs-expand");
    expect(expand).toHaveTextContent("2 fns");
    fireEvent.click(expand);
    expect(container.querySelectorAll(".ps-ctrl-fnchip")).toHaveLength(2);
  });

  it("previews the governed contract on a row-body click and commits only via the arrow", () => {
    const onPreview = vi.fn();
    const onNavigate = vi.fn();
    const idx = governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["pause"] }]);
    const { getByText, container } = render(
      <EntityCard
        machine={machine()}
        onSelectGuard={vi.fn()}
        onNavigate={onNavigate}
        onPreview={onPreview}
        governsIndex={idx}
      />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    // Body click = peek only.
    fireEvent.click(getByText("LiquidityPool").closest(".ps-governs-head"));
    expect(onPreview).toHaveBeenCalledWith(POOL);
    expect(onNavigate).not.toHaveBeenCalled();
    // The trailing arrow is the commit affordance.
    fireEvent.click(container.querySelector(".ps-goto-arrow"));
    expect(onNavigate).toHaveBeenCalledWith(expect.objectContaining({ address: POOL, type: "contract" }));
  });

  it("shows no capability summary — the collapsed row is name/value only, functions behind the expand button", () => {
    const idx = governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["upgradeTo"] }]);
    const principal = {
      address: TIMELOCK,
      type: "timelock",
      details: { delay: 864000 },
      controls_detail: [{ address: POOL, functions: ["upgradeTo"], capabilities: ["upgrade"] }],
    };
    const { getByText, container } = render(
      <EntityCard machine={machine()} onSelectGuard={vi.fn()} onPreview={vi.fn()} governsIndex={idx} principal={principal} />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    // No capability-word summary is rendered anywhere on the row.
    expect(container.querySelector(".ps-governs-summary")).toBeNull();
    const expand = container.querySelector(".ps-governs-expand");
    expect(expand).toHaveTextContent("1 fns");
    expect(container.querySelectorAll(".ps-ctrl-fnchip")).toHaveLength(0);
    fireEvent.click(expand);
    expect(getByText("upgradeTo")).toBeInTheDocument();
  });

  it("gives governance-path rows no expand button (reachability only, no function data)", () => {
    const onPreview = vi.fn();
    const principal = { address: TIMELOCK, type: "timelock", details: { delay: 864000 } };
    const machines = [{ address: POOL, name: "LiquidityPool" }];
    const { getByText, container } = render(
      <EntityCard
        machine={machine()}
        onSelectGuard={vi.fn()}
        onPreview={onPreview}
        governsIndex={new Map()}
        principal={principal}
        machines={machines}
        reachDistances={new Map([[POOL, 1]])}
      />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(getByText("Appears In Governance Path For (1)")).toBeInTheDocument();
    expect(getByText("LiquidityPool")).toBeInTheDocument();
    // Path rows carry no function list → no expand button, but still focus on click.
    expect(container.querySelector(".ps-governs-expand")).toBeNull();
    fireEvent.click(getByText("LiquidityPool").closest(".ps-governs-head"));
    expect(onPreview).toHaveBeenCalledWith(POOL);
  });

  it("shows no governance-path rows without a server reach record — fail closed", () => {
    // principal.controls is NOT a path source any more: the rows come from the
    // server's reached set alone, and its absence renders nothing.
    const principal = { address: TIMELOCK, type: "timelock", details: { delay: 864000 }, controls: [POOL] };
    const machines = [{ address: POOL, name: "LiquidityPool" }];
    const { getByText, queryByText } = render(
      <EntityCard
        machine={machine()}
        onSelectGuard={vi.fn()}
        onPreview={vi.fn()}
        governsIndex={new Map()}
        principal={principal}
        machines={machines}
      />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(queryByText(/Appears In Governance Path For/)).toBeNull();
  });

  it("renders the frontier as a count line only — never rows in the reached list", () => {
    const machines = [{ address: POOL, name: "LiquidityPool" }];
    const { getByText, container } = render(
      <EntityCard
        machine={machine()}
        onSelectGuard={vi.fn()}
        onPreview={vi.fn()}
        governsIndex={new Map()}
        machines={machines}
        reachDistances={new Map([[POOL, 1]])}
        reachFrontierCount={2}
      />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(getByText("Appears In Governance Path For (1)")).toBeInTheDocument();
    const ndLine = container.querySelector(".ps-governs-ndcount");
    expect(ndLine).toHaveTextContent("reach unconfirmed · 2 destinations");
    // The reached list itself stays at one row.
    expect(container.querySelectorAll(".ps-governs-row")).toHaveLength(1);
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

describe("EntityCard balances tab count", () => {
  const bal = (over) => ({
    token_symbol: "T",
    token_address: "0x1",
    raw_balance: "1",
    decimals: 18,
    usd_value: null,
    usd_value_state: "not_determined",
    ...over,
  });

  it("counts the holdings the BACKEND presents, not the ones the page re-judges", () => {
    // The regression this pins: the count split on delivery_shape alone, so a
    // mass-distributed token the protocol's own discovery names — HEX, WETH,
    // base USDC on the reference corpus — was dropped from the count while the
    // score spared it. The withholding rule is a conjunction; the backend
    // publishes its verdict so a consumer never carries half of it.
    const card = render(
      <EntityCard
        machine={machine({
          balances: [
            bal({ token_symbol: "HEX", delivery_shape: "fan_out_all", disposition_state: "presented" }),
            bal({ token_symbol: "REAL", delivery_shape: "has_direct_delivery", disposition_state: "presented" }),
            bal({ token_symbol: "JUNK", delivery_shape: "fan_out_all", disposition_state: "disposed" }),
          ],
        })}
        onSelectGuard={vi.fn()}
        onNavigate={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    const tab = card.getByText("Balances").closest("button");
    expect(within(tab).getByText("2")).toBeInTheDocument();
  });

  it("counts a row carrying no verdict — an unjudged holding is still a holding", () => {
    const card = render(
      <EntityCard
        machine={machine({ balances: [bal({ token_symbol: "NOVERDICT", delivery_shape: "fan_out_all" })] })}
        onSelectGuard={vi.fn()}
        onNavigate={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    const tab = card.getByText("Balances").closest("button");
    expect(within(tab).getByText("1")).toBeInTheDocument();
  });
});
