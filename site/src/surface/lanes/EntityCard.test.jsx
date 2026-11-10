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
    const expand = container.querySelector(".ref-toggle");
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
    fireEvent.click(getByText("LiquidityPool").closest(".ref-link"));
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
    const expand = container.querySelector(".ref-toggle");
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
    expect(container.querySelector(".ref-toggle")).toBeNull();
    fireEvent.click(getByText("LiquidityPool").closest(".ref-link"));
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
    expect(container.querySelectorAll(".ref-row")).toHaveLength(1);
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

  it("counts all recorded holdings, including legacy disposed rows", () => {
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
    expect(within(tab).getByText("3")).toBeInTheDocument();
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

describe("EntityCard controller enumeration", () => {
  it("badges a contract whose member replay never completed, naming the status", () => {
    const { getByText } = render(
      <EntityCard
        machine={machine({ controller_enumeration: { state: "not_determined", status: "error" } })}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    const badge = getByText("Controllers not determined");
    expect(badge).toHaveAttribute("title", "enumeration errored");
  });

  it("badges a principal-only timelock the same way", () => {
    const { getByText } = render(
      <EntityCard
        principal={{
          address: TIMELOCK,
          type: "timelock",
          details: {},
          controller_enumeration: { state: "not_determined", status: "incomplete_timeout" },
        }}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    expect(getByText("Controllers not determined")).toHaveAttribute("title", "enumeration timed out");
  });

  it("badges an entry whose controller values were never read for this deployment", () => {
    const { getByText } = render(
      <EntityCard machine={machine({ controller_values_state: "not_determined" })} onSelectGuard={vi.fn()} governsIndex={new Map()} />,
    );
    expect(getByText("Controllers not determined")).toHaveAttribute(
      "title",
      "controller values not determined for this deployment",
    );
  });

  it("names both routes in one badge when the replay and the values are both unread", () => {
    const { getAllByText } = render(
      <EntityCard
        machine={machine({
          controller_values_state: "not_determined",
          controller_enumeration: { state: "not_determined", status: "error" },
        })}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    const badges = getAllByText("Controllers not determined");
    expect(badges).toHaveLength(1);
    expect(badges[0]).toHaveAttribute("title", "enumeration errored; controller values not determined for this deployment");
  });

  it("renders an unknown controller_values_state token raw", () => {
    const { getByText, queryByText } = render(
      <EntityCard machine={machine({ controller_values_state: "partial" })} onSelectGuard={vi.fn()} governsIndex={new Map()} />,
    );
    expect(getByText("partial")).toBeInTheDocument();
    expect(queryByText("Controllers not determined")).toBeNull();
  });

  it("shows nothing extra for a complete member set", () => {
    const { queryByText } = render(
      <EntityCard
        machine={machine({ controller_enumeration: { state: "complete" } })}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    expect(queryByText("Controllers not determined")).toBeNull();
  });
});

describe("EntityCard upgrade count", () => {
  const card = (over) =>
    render(<EntityCard machine={machine({ is_proxy: true, ...over })} onSelectGuard={vi.fn()} governsIndex={new Map()} />);
  const basis = (relation) => ({ history_fetch_status: "complete", recorded_count_relation: relation });

  it("badges the count with its relation to the recorded upgrades", () => {
    expect(card({ upgrade_count: 2, upgrade_count_basis: basis("exact") }).getByText("2 recorded upgrades")).toBeInTheDocument();
    expect(card({ upgrade_count: 5, upgrade_count_basis: basis("upper_bound") }).getByText("up to 5 upgrades")).toBeInTheDocument();
    expect(
      card({ upgrade_count: 5, upgrade_count_basis: basis("not_determined") }).getByText("5 upgrades · bound not determined"),
    ).toBeInTheDocument();
  });

  it("keeps a published basis with no count visible as not determined", () => {
    const { getByText, queryByText } = card({ upgrade_count: null, upgrade_count_basis: basis("not_determined") });
    expect(getByText("upgrades not determined")).toBeInTheDocument();
    expect(queryByText(/0 upgrades/)).toBeNull();
  });

  it("shows no badge when the entry makes no upgrade claim", () => {
    const { container } = card({ upgrade_count: null, upgrade_count_basis: null });
    expect(container.querySelector(".ps-machine-badges").textContent).not.toMatch(/upgrade/i);
  });
});

describe("EntityCard analysis provenance", () => {
  const job = (over = {}) => ({
    job_id: "abcdef12-0000-0000-0000-000000000000",
    state: "current_analyzer",
    static_analyzer_version: 12,
    static_reused_from_job_id: null,
    started_at: "2026-11-03T13:00:00+00:00",
    last_pipeline_pass_at: "2026-11-03T14:02:00+00:00",
    ...over,
  });

  it("shows one provenance line with the implementation job for a proxy", () => {
    const { container } = render(
      <EntityCard
        machine={machine({
          is_proxy: true,
          analysis_provenance: { job: job(), impl_job: job({ job_id: "impl", state: "older_analyzer", static_analyzer_version: 11 }) },
        })}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    const lines = container.querySelectorAll(".ps-machine-title-wrap .ps-machine-address");
    expect(lines).toHaveLength(2);
    expect(lines[1].textContent).toMatch(/^analyzer v12 · last pipeline pass .+ · impl older analyzer v11, /);
    expect(lines[1].getAttribute("title")).toContain("implementation job impl");
  });

  it("keeps not determined provenance visible", () => {
    const nd = "not_determined";
    const { getByText } = render(
      <EntityCard
        machine={machine({
          analysis_provenance: {
            job: job({ state: nd, static_analyzer_version: nd, static_reused_from_job_id: nd, started_at: nd, last_pipeline_pass_at: nd }),
            impl_job: null,
          },
        })}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    expect(getByText("analysis provenance not determined")).toBeInTheDocument();
  });
});

describe("EntityCard USD lower bound", () => {
  it("badges a total over unvalued holdings as a lower bound", () => {
    const { getByText } = render(
      <EntityCard
        machine={machine({ total_usd: 5_000_000, holdings_coverage: { unvalued_rows: 2 } })}
        onSelectGuard={vi.fn()}
        governsIndex={new Map()}
      />,
    );
    expect(getByText("≥ $5.0M")).toBeInTheDocument();
  });

  it("carries the bound onto Governs rows", () => {
    const pool = { address: POOL, name: "LiquidityPool", total_usd: 2_000_000, holdings_coverage: { unvalued_rows: 1 } };
    const { getByText } = render(
      <EntityCard
        machine={machine()}
        machines={[pool]}
        onSelectGuard={vi.fn()}
        onPreview={vi.fn()}
        governsIndex={governsWith([{ contractAddress: POOL, contractName: "LiquidityPool", functions: ["pause"] }])}
      />,
    );
    fireEvent.click(getByText("Governs").closest("button"));
    expect(getByText("≥ $2.0M")).toBeInTheDocument();
  });
});
