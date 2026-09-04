// Direct tests for the pure helpers extracted from ProtocolSurface.jsx.
// Previously exercised only through the rendered surface — these run the
// builders against the rich fixture so a regression in any of them shows
// up before we hit a render assertion.

import { describe, it, expect } from "vitest";

import {
  ETHERFI_COMPANY_RICH,
  RICH_ADDRESSES,
} from "../../test/fixtures.js";
import { buildMachines, membershipKind } from "./buildMachines.js";
import {
  buildIndirectCallerContext,
  collectDirectCallers,
  collectIndirectCallers,
} from "./controlGraph.js";
import { guardSummary } from "./guardSummary.js";
import { buildSearchResults } from "./search.js";
import { buildGraphLayout } from "./elkLayout.js";
import { assignGroups } from "./groupAssignment.js";
import { aggregateEdges } from "./edgeAggregation.js";
import { groupHeaderHeight, layoutGroupInterior } from "./nodeSizing.js";
import { buildControlAdjacency, flowOnChain } from "./governancePath.js";
import { entityKey } from "../entityKey.js";

// buildMachines reads functions by the composite (chain, address) token; the
// fixture is single-chain (no chain field → "ethereum"), so key it the same way.
const functionData = Object.fromEntries(
  ETHERFI_COMPANY_RICH.contracts.map((c) => [entityKey(c.chain, c.address), c.functions || []]),
);

describe("buildMachines", () => {
  it("keeps heuristic membership explicit on the machine", () => {
    expect(membershipKind({
      membership_state: "member",
      membership_witnesses: [
        { rule: "w4h_deployer_affinity", heuristic: true },
      ],
    })).toBe("heuristic");
    expect(membershipKind({
      membership_state: "member",
      membership_witnesses: [
        { rule: "w4h_deployer_affinity", heuristic: true },
        { rule: "w3_control", heuristic: false },
      ],
    })).toBe("supported");
  });

  it("groups each fixture function into a lane and skips role constants", () => {
    const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);
    expect(machines).toHaveLength(2);
    const vault = machines.find((m) => m.address === RICH_ADDRESSES.VAULT);
    const pool = machines.find((m) => m.address === RICH_ADDRESSES.POOL);
    expect(vault.totalFunctions).toBe(6);
    expect(pool.totalFunctions).toBe(3);
    // Vault: upgrade/pause/unpause/setFee → control, deposit → inflow,
    // withdraw → outflow.
    expect(vault.lanes.top.map((f) => f.name)).toEqual(
      expect.arrayContaining(["upgrade", "pause", "unpause"]),
    );
    expect(vault.lanes.left.map((f) => f.name)).toContain("deposit");
    expect(vault.lanes.right.map((f) => f.name)).toContain("withdraw");
  });

  it("sorts machines by totalFunctions desc", () => {
    const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);
    expect(machines[0].totalFunctions).toBeGreaterThanOrEqual(machines[1].totalFunctions);
  });

  it("distinguishes direct control from contracts reached through governance", async () => {
    const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);
    const addresses = machines.map((machine) => machine.address);
    const principal = {
      address: "0x" + "ab".repeat(20),
      type: "safe",
      primary_for: addresses,
      controls: [addresses[0]],
      controls_detail: [],
    };
    const { nodes } = await buildGraphLayout(machines, [], [principal]);
    const group = nodes.find((node) => node.type === "group");

    expect(group.data.directCount).toBe(1);
    expect(group.data.viaGovernanceCount).toBe(addresses.length - 1);
  });

  it("does not turn missing or unknown claims into blank ops rows", () => {
    const contract = { address: RICH_ADDRESSES.VAULT, name: "Vault", is_proxy: false };
    const data = { contracts: [contract], principals: [], fund_flows: [] };
    const functions = {
      [entityKey("ethereum", contract.address)]: [
        { function: "missing()", claims: [] },
        { function: "unknown()", claims: [{ claim_id: "not.registered", tier: "policy_derived", witness: {} }] },
      ],
    };
    expect(buildMachines(data, functions)).toEqual([]);
  });

  it("renders transfer-policy configuration as a control claim", () => {
    const contract = { address: RICH_ADDRESSES.VAULT, name: "Vault", is_proxy: false };
    const data = { contracts: [contract], principals: [], fund_flows: [] };
    const functions = {
      [entityKey("ethereum", contract.address)]: [
        {
          function: "setAllowed(address,bool)",
          claims: [{ claim_id: "transfer_policy.configure", tier: "policy_derived", witness: {} }],
        },
      ],
    };
    const machine = buildMachines(data, functions)[0];
    expect(machine.lanes.top[0].action).toBe("configures transfer policy");
  });
});

describe("collectDirectCallers", () => {
  it("returns a direct caller for a guarded fixture function", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "pause");
    const direct = collectDirectCallers(fn);
    expect(direct).toHaveLength(1);
    expect(direct[0].resolvedType).toBe("safe");
  });

  it("returns no direct caller for a public-authority function", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "deposit");
    const direct = collectDirectCallers(fn);
    expect(direct).toHaveLength(0);
  });
});

describe("guardSummary", () => {
  it("classifies a Safe-guarded function with a threshold sublabel", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "pause");
    const guard = guardSummary(fn, ETHERFI_COMPANY_RICH);
    expect(guard.kind).toBe("safe");
    expect(guard.sublabel).toBe("2/3");
  });

  it("classifies a Timelock-guarded function with a delay sublabel", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "upgrade");
    const guard = guardSummary(fn, ETHERFI_COMPANY_RICH);
    expect(guard.kind).toBe("timelock");
    expect(guard.sublabel).toBe("1d");
  });

  it("classifies a public function as kind=open", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "deposit");
    const guard = guardSummary(fn, ETHERFI_COMPANY_RICH);
    expect(guard.kind).toBe("open");
  });

  it("classifies a no-principal non-public function as kind=unknown", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[1].functions.find((f) => f.function === "setOracle");
    const guard = guardSummary(fn, ETHERFI_COMPANY_RICH);
    expect(guard.kind).toBe("unknown");
  });
});

describe("buildSearchResults", () => {
  const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);
  const principals = ETHERFI_COMPANY_RICH.resolved_principals.map((p) => ({
    address: p.address,
    type: p.resolved_type,
    label: p.display_name,
    details: p.details,
    controls: machines.map((m) => m.address),
    primary_for: machines.map((m) => m.address),
  }));

  it("filters to safes when mode=safe", () => {
    const results = buildSearchResults(machines, principals, "safe", "name", "");
    expect(results.every((r) => r.kind === "principal" && r.type === "safe")).toBe(true);
  });

  it("returns contracts when mode=contracts", () => {
    const results = buildSearchResults(machines, principals, "contracts", "name", "");
    expect(results.every((r) => r.kind === "contract")).toBe(true);
    expect(results.length).toBe(machines.length);
  });

  it("filters by query against name/address/type", () => {
    const results = buildSearchResults(machines, principals, "contracts", "name", "Vault");
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("Vault");
  });

  it("supports `value > 1m` style numeric filters", () => {
    const machinesWithValue = machines.map((m) => ({ ...m, total_usd: m.address === RICH_ADDRESSES.VAULT ? 5_000_000 : 100 }));
    const results = buildSearchResults(machinesWithValue, principals, "contracts", "value", "value > 1m");
    expect(results.every((r) => r.value >= 1_000_000)).toBe(true);
  });
});

describe("buildGraphLayout", () => {
  const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);

  it("emits a group per principal that uniquely controls at least one contract", () => {
    // Server marks only the Safe as primary for machines[0]; the
    // Timelock has no primary_for entries and drops off the canvas
    // entirely (still visible in search and sidebar via
    // companyData.principals).
    const principals = ETHERFI_COMPANY_RICH.resolved_principals.map((p) => ({
      address: p.address,
      type: p.resolved_type,
      label: p.display_name,
      details: p.details,
      controls: [machines[0].address],
      primary_for: p.resolved_type === "safe" ? [machines[0].address] : [],
    }));
    const { nodes, edges } = buildGraphLayout(machines, ETHERFI_COMPANY_RICH.fund_flows, principals);
    const contractNodes = nodes.filter((n) => n.type === "contract");
    const principalNodes = nodes.filter((n) => n.type === "principal");
    const groupNodes = nodes.filter((n) => n.type === "group");
    expect(contractNodes.length).toBe(machines.length);
    // No standalone principal rendering anymore.
    expect(principalNodes.length).toBe(0);
    expect(groupNodes).toHaveLength(1);
    expect(groupNodes[0].id.toLowerCase()).toBe(RICH_ADDRESSES.SAFE.toLowerCase());
    // Vault → Pool fund flow (contract→contract) survives the
    // principal-source filter and becomes an aggregated cross-group
    // edge from the Safe group to the ungrouped Pool.
    expect(edges.some((e) => e.id.startsWith("agg-"))).toBe(true);
  });

  it("collapses every principal→child edge into containment", () => {
    // Same fixture, but the Safe is now the server-marked primary for
    // both contracts — exactly the fanout the grouping is meant to
    // collapse. The Timelock has no primary_for entries.
    const principals = ETHERFI_COMPANY_RICH.resolved_principals.map((p) => ({
      address: p.address,
      type: p.resolved_type,
      label: p.display_name,
      details: p.details,
      controls: p.resolved_type === "safe" ? machines.map((m) => m.address) : [machines[0].address],
      primary_for: p.resolved_type === "safe" ? machines.map((m) => m.address) : [],
    }));
    const { nodes, edges, groupChildren, contractToGroup } = buildGraphLayout(
      machines,
      ETHERFI_COMPANY_RICH.fund_flows,
      principals,
    );
    const groupNodes = nodes.filter((n) => n.type === "group");
    expect(groupNodes).toHaveLength(1);
    expect(groupNodes[0].id.toLowerCase()).toBe(RICH_ADDRESSES.SAFE.toLowerCase());
    const childContracts = nodes.filter((n) => n.type === "contract" && n.parentId);
    expect(childContracts).toHaveLength(2);
    for (const c of childContracts) {
      expect(c.parentId.toLowerCase()).toBe(RICH_ADDRESSES.SAFE.toLowerCase());
      expect(c.extent).toBe("parent");
    }
    // The Timelock loses every candidate child to the Safe and
    // disappears from the canvas entirely.
    expect(nodes.filter((n) => n.type === "principal").length).toBe(0);
    expect(groupChildren.size).toBe(1);
    expect(contractToGroup.size).toBe(2);
    // No edge in the final list originates from any non-contract
    // principal — that's the spiderweb fix.
    const principalAddrs = new Set(
      principals.map((p) => p.address?.toLowerCase()),
    );
    const principalEdges = edges.filter((e) => principalAddrs.has(e.source?.toLowerCase()));
    expect(principalEdges).toHaveLength(0);
  });

  it("respects the server's primary_for assignment for group membership", () => {
    // Same fixture: server has already picked the Safe as primary for
    // both contracts. The Timelock is in the principal list (so it
    // remains searchable) but has an empty primary_for, so it doesn't
    // get a group.
    const principals = ETHERFI_COMPANY_RICH.resolved_principals.map((p) => ({
      address: p.address,
      type: p.resolved_type,
      label: p.display_name,
      details: p.details,
      controls: machines.map((m) => m.address),
      primary_for: p.resolved_type === "safe" ? machines.map((m) => m.address) : [],
    }));
    const { groupChildren, contractToGroup } = assignGroups(machines, principals);
    expect(groupChildren.size).toBe(1);
    expect([...groupChildren.keys()][0]).toBe(RICH_ADDRESSES.SAFE.toLowerCase());
    for (const m of machines) {
      expect(contractToGroup.get(m.address.toLowerCase())).toBe(
        RICH_ADDRESSES.SAFE.toLowerCase(),
      );
    }
  });

  it("honors grouped_with: a mediator renders with its operand group, not its driver's", () => {
    // The etherfi 2d-operating-timelock shape: the ops Safe primary-owns the
    // timelock (true authority, kept in primary_for), but the server marked it
    // grouped_with the gov Safe whose box holds the contracts it operates on.
    const gov = "0x" + "a1".repeat(20);
    const ops = "0x" + "b2".repeat(20);
    const tl = "0x" + "c3".repeat(20);
    const mediatorMachines = [
      { address: "0x" + "d4".repeat(20), totalFunctions: 3 },
      { address: "0x" + "d5".repeat(20), totalFunctions: 2 },
      { address: tl, totalFunctions: 1, grouped_with: gov },
      { address: "0x" + "d6".repeat(20), totalFunctions: 1 },
      { address: "0x" + "d7".repeat(20), totalFunctions: 1 },
    ];
    const mediatorPrincipals = [
      { address: gov, type: "safe", primary_for: ["0x" + "d4".repeat(20), "0x" + "d5".repeat(20)] },
      { address: ops, type: "safe", primary_for: [tl, "0x" + "d6".repeat(20), "0x" + "d7".repeat(20)] },
    ];
    const { groupChildren, contractToGroup } = assignGroups(mediatorMachines, mediatorPrincipals);
    expect(contractToGroup.get(tl)).toBe(gov);
    expect(groupChildren.get(gov)).toContain(tl);
    expect(groupChildren.get(ops) || []).not.toContain(tl);
  });

  it("ignores grouped_with pointing at an unknown principal", () => {
    const gov = "0x" + "a1".repeat(20);
    const tl = "0x" + "c3".repeat(20);
    const mediatorMachines = [
      { address: tl, totalFunctions: 1, grouped_with: "0x" + "99".repeat(20) },
      { address: "0x" + "d6".repeat(20), totalFunctions: 1 },
    ];
    const mediatorPrincipals = [
      { address: gov, type: "safe", primary_for: [tl, "0x" + "d6".repeat(20)] },
    ];
    const { contractToGroup } = assignGroups(mediatorMachines, mediatorPrincipals);
    // Falls back to the primary_for placement.
    expect(contractToGroup.get(tl)).toBe(gov);
  });

  it("attaches a Controllers list to each group: primary first, then co-controllers scoped to the group", () => {
    // The Safe primary-owns both contracts (→ one group container). The
    // Timelock and an operator EOA each co-control machines[0] (VAULT) without
    // being primary. Co-controllers no longer render as standalone guardian
    // nodes — they live in the owning group's Controllers accordion
    // (group.data.controllers), with the functions/caps they can call scoped
    // to that group's contracts. EOAs are included on Surface even though
    // monitoring drops them.
    const eoaAddr = "0x" + "ee".repeat(20);
    const principals = ETHERFI_COMPANY_RICH.resolved_principals.map((p) => ({
      address: p.address,
      type: p.resolved_type,
      label: p.display_name,
      details: p.details,
      controls: machines.map((m) => m.address),
      primary_for: p.resolved_type === "safe" ? machines.map((m) => m.address) : [],
      co_controls: p.resolved_type === "timelock" ? [machines[0].address] : [],
      controls_detail:
        p.resolved_type === "safe"
          ? [
              { address: machines[0].address, functions: ["upgradeTo", "transferOwnership"], capabilities: ["ownership", "upgrade"] },
              { address: machines[1].address, functions: ["upgradeTo"], capabilities: ["upgrade"] },
            ]
          : p.resolved_type === "timelock"
          ? [{ address: machines[0].address, functions: ["pauseContract"], capabilities: ["pause"] }]
          : [],
    }));
    principals.push({
      address: eoaAddr,
      type: "eoa",
      label: "ops-bot",
      details: {},
      controls: [machines[0].address],
      primary_for: [],
      co_controls: [machines[0].address],
      controls_detail: [{ address: machines[0].address, functions: ["sweepFunds"], capabilities: ["fund-out"] }],
    });

    const { nodes } = buildGraphLayout(machines, ETHERFI_COMPANY_RICH.fund_flows, principals);
    const safe = principals.find((p) => p.type === "safe");

    // No standalone principal/guardian nodes anymore.
    expect(nodes.filter((n) => n.type === "principal")).toHaveLength(0);

    const group = nodes.find((n) => n.type === "group" && n.id === safe.address);
    expect(group).toBeTruthy();
    const controllers = group.data.controllers;

    // Primary first.
    expect(controllers[0].isPrimary).toBe(true);
    expect(controllers[0].address).toBe(safe.address);
    // Capability summary is the verbatim union of the real tags, sorted.
    expect(controllers[0].capabilities).toEqual(["ownership", "upgrade"]);
    // Primary governs both contracts in the group.
    expect(controllers[0].governs).toHaveLength(2);

    // Both co-controllers appear, tagged non-primary, scoped to VAULT only.
    const cos = controllers.filter((c) => !c.isPrimary);
    expect(cos).toHaveLength(2);
    const tl = cos.find((c) => c.address.toLowerCase() === RICH_ADDRESSES.TIMELOCK.toLowerCase());
    const eoa = cos.find((c) => c.address.toLowerCase() === eoaAddr);
    expect(tl.capabilities).toEqual(["pause"]);
    expect(tl.governs).toHaveLength(1);
    expect(tl.governs[0].functions).toEqual(["pauseContract"]);
    expect(eoa.capabilities).toEqual(["fund-out"]);
    // The header height grows with the number of controller rows.
    expect(group.data.headerHeight).toBe(groupHeaderHeight(controllers.length));
  });

  it("lists a relocated member's true controller as a controller row in the operand box", () => {
    // The grouped_with shape: ops Safe primary-owns ONLY the timelock, which
    // renders inside gov's box via grouped_with. The accordion of gov's box
    // must name the ops Safe (its only canvas footprint), scoped to the
    // timelock, even though the timelock is in nobody-in-this-box's
    // co_controls.
    const gov = "0x" + "a1".repeat(20);
    const ops = "0x" + "b2".repeat(20);
    const tl = "0x" + "c3".repeat(20);
    const core = "0x" + "d4".repeat(20);
    const relMachines = [
      { address: core, name: "Core", totalFunctions: 2 },
      { address: tl, name: "OpsTimelock", totalFunctions: 1, grouped_with: gov },
    ];
    const relPrincipals = [
      {
        address: gov,
        type: "safe",
        primary_for: [core],
        co_controls: [],
        controls_detail: [{ address: core, functions: ["upgradeTo"], capabilities: ["upgrade"] }],
      },
      {
        address: ops,
        type: "safe",
        primary_for: [tl],
        co_controls: [],
        controls_detail: [{ address: tl, functions: ["schedule", "execute"], capabilities: ["timelock"] }],
      },
    ];
    const { nodes } = buildGraphLayout(relMachines, [], relPrincipals);
    const group = nodes.find((n) => n.type === "group" && n.id === gov);
    expect(group).toBeTruthy();
    const opsRow = group.data.controllers.find((c) => c.address.toLowerCase() === ops);
    expect(opsRow).toBeTruthy();
    expect(opsRow.isPrimary).toBe(false);
    expect(opsRow.governs).toHaveLength(1);
    expect(opsRow.governs[0].address).toBe(tl);
    expect(opsRow.governs[0].functions).toEqual(["schedule", "execute"]);
  });

  it("reserves each group's measured band height verbatim so cards start below it", () => {
    const principals = ETHERFI_COMPANY_RICH.resolved_principals.map((p) => ({
      address: p.address,
      type: p.resolved_type,
      label: p.display_name,
      details: p.details,
      controls: machines.map((m) => m.address),
      primary_for: p.resolved_type === "safe" ? machines.map((m) => m.address) : [],
      co_controls: [],
      controls_detail:
        p.resolved_type === "safe"
          ? machines.map((m) => ({ address: m.address, functions: ["upgradeTo"], capabilities: ["upgrade"] }))
          : [],
    }));
    const safe = principals.find((p) => p.type === "safe");
    const nControllers = 1; // primary only (no co-controllers here)
    const collapsed = groupHeaderHeight(nControllers);

    // No measurement yet → the constant estimate is reserved.
    const base = buildGraphLayout(machines, ETHERFI_COMPANY_RICH.fund_flows, principals);
    expect(base.nodes.find((n) => n.id === safe.address).data.headerHeight).toBe(collapsed);

    // Once GroupNode reports the measured band height for the group (e.g. a
    // capability summary wrapped to several lines), it's reserved verbatim,
    // keyed by the group id, and layoutGroupInterior starts the first card
    // below the reserved band.
    const grownHeader = 540;
    const measured = buildGraphLayout(machines, ETHERFI_COMPANY_RICH.fund_flows, principals, {
      [safe.address]: grownHeader,
    });
    expect(measured.nodes.find((n) => n.id === safe.address).data.headerHeight).toBe(grownHeader);
    const kids = measured.groupChildren.get(safe.address.toLowerCase());
    const interior = layoutGroupInterior(
      kids.map((id) => ({ id })),
      machines,
      grownHeader,
    );
    // Cards start at or below the reserved band (a small gap clears the
    // group's border so the first card never tucks under the accordion).
    const firstCardY = Math.min(...[...interior.positions.values()].map((pt) => pt.y));
    expect(firstCardY).toBeGreaterThanOrEqual(grownHeader);
  });
});

describe("aggregateEdges", () => {
  const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);
  const safeAddr = RICH_ADDRESSES.SAFE.toLowerCase();

  it("collapses multiple cross-group edges into one bundle, keeping samples but no count label", () => {
    const rawEdges = [
      { id: "e1", source: machines[0].address, target: "0xexternal1", data: {} },
      { id: "e2", source: machines[1].address, target: "0xexternal1", data: {} },
      { id: "e3", source: machines[0].address, target: "0xexternal1", data: {} },
    ];
    // Both fixture contracts share the Safe as their group.
    const contractToGroup = new Map([
      [machines[0].address.toLowerCase(), safeAddr],
      [machines[1].address.toLowerCase(), safeAddr],
    ]);
    const principals = [{ address: RICH_ADDRESSES.SAFE, type: "safe", controls: [] }];
    const aggregated = aggregateEdges(rawEdges, contractToGroup, principals, machines);
    expect(aggregated).toHaveLength(1);
    expect(aggregated[0].source.toLowerCase()).toBe(safeAddr);
    expect(aggregated[0].target).toBe("0xexternal1");
    expect(aggregated[0].label).toBeUndefined();
    expect(aggregated[0].data.samples).toHaveLength(3);
  });

  it("drops intra-group edges (both endpoints resolve to the same group)", () => {
    const rawEdges = [
      { id: "e1", source: machines[0].address, target: machines[1].address, data: {} },
    ];
    const contractToGroup = new Map([
      [machines[0].address.toLowerCase(), safeAddr],
      [machines[1].address.toLowerCase(), safeAddr],
    ]);
    const principals = [{ address: RICH_ADDRESSES.SAFE, type: "safe", controls: [] }];
    const aggregated = aggregateEdges(rawEdges, contractToGroup, principals, machines);
    expect(aggregated).toHaveLength(0);
  });

  it("leaves a single cross-group edge unlabeled", () => {
    const rawEdges = [
      { id: "e1", source: machines[0].address, target: "0xexternal", data: {} },
    ];
    const contractToGroup = new Map([
      [machines[0].address.toLowerCase(), safeAddr],
    ]);
    const principals = [{ address: RICH_ADDRESSES.SAFE, type: "safe", controls: [] }];
    const aggregated = aggregateEdges(rawEdges, contractToGroup, principals, machines);
    expect(aggregated).toHaveLength(1);
    expect(aggregated[0].label).toBeUndefined();
    expect(aggregated[0].data.samples).toHaveLength(1);
  });
});

describe("buildControlAdjacency — chain scope", () => {
  const CTRL = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const TWIN = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  // Same control edge (CTRL -> TWIN) exists on both chains — the classic CREATE2
  // twin. Scoped to ethereum, only ethereum's edge may enter the walk.
  const FLOWS = [
    { from: CTRL, to: TWIN, type: "controller", from_chain: "ethereum", to_chain: "ethereum" },
    { from: CTRL, to: TWIN, type: "controller", from_chain: "base", to_chain: "base" },
  ];

  it("keeps only the active chain's flow edges", () => {
    const eth = buildControlAdjacency(FLOWS, "ethereum");
    expect(eth.get(CTRL) && [...eth.get(CTRL)]).toEqual([TWIN]);

    // A base-only control edge must NOT enter the ethereum adjacency.
    const baseOnly = buildControlAdjacency(
      [{ from: CTRL, to: TWIN, type: "controller", from_chain: "base", to_chain: "base" }],
      "ethereum",
    );
    expect(baseOnly.has(CTRL)).toBe(false);
  });

  it("keeps legacy chain-less flows regardless of active chain", () => {
    const adj = buildControlAdjacency([{ from: CTRL, to: TWIN, type: "controller" }], "ethereum");
    expect(adj.get(CTRL) && [...adj.get(CTRL)]).toEqual([TWIN]);
  });

  it("is identical to the unscoped build when no active chain is given", () => {
    const adj = buildControlAdjacency(FLOWS);
    expect([...adj.get(CTRL)]).toEqual([TWIN]);
  });
});

describe("flowOnChain — canvas fund-flow scope", () => {
  const A = "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
  const B = "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

  it("keeps only the active chain's flow", () => {
    expect(flowOnChain({ from: A, to: B, type: "controller", to_chain: "ethereum" }, "ethereum")).toBe(true);
    expect(flowOnChain({ from: A, to: B, type: "controller", to_chain: "base" }, "ethereum")).toBe(false);
  });

  it("keeps chain-less legacy flows on any active chain", () => {
    expect(flowOnChain({ from: A, to: B, type: "controller" }, "ethereum")).toBe(true);
  });

  it("keeps every flow when no active chain is given", () => {
    expect(flowOnChain({ from: A, to: B, type: "controller", to_chain: "base" }, null)).toBe(true);
  });

  // The canvas keys contract→contract edges by bare address, so a base twin flow
  // between two addresses that ALSO exist as visible ethereum machines misdraws
  // onto the ethereum nodes. ProtocolSurface scopes the flows with flowOnChain
  // before they reach the layout; this proves the layer that scoping protects.
  it("a base twin flow does not reach the canvas layout when scoped to ethereum", () => {
    const machines = [
      { address: A, name: "GovA", is_proxy: false, totalFunctions: 2, total_usd: 0 },
      { address: B, name: "GovB", is_proxy: false, totalFunctions: 1, total_usd: 0 },
    ];
    const baseFlow = { from: A, to: B, type: "controller", from_chain: "base", to_chain: "base" };
    const drawn = (edges) =>
      edges.some((e) => (e.source || "").toLowerCase() === A && (e.target || "").toLowerCase() === B);

    // Unscoped: the base relationship misdraws as an ethereum edge.
    expect(drawn(buildGraphLayout(machines, [baseFlow], [], {}, "ethereum").edges)).toBe(true);
    // Scoped the way ProtocolSurface scopes it: the base edge is gone.
    const scoped = [baseFlow].filter((f) => flowOnChain(f, "ethereum"));
    expect(drawn(buildGraphLayout(machines, scoped, [], {}, "ethereum").edges)).toBe(false);
    // A chain-less flow still draws.
    const legacy = [{ from: A, to: B, type: "controller" }].filter((f) => flowOnChain(f, "ethereum"));
    expect(drawn(buildGraphLayout(machines, legacy, [], {}, "ethereum").edges)).toBe(true);
  });
});

describe("buildGroupControllers — controls_detail chain keying", () => {
  const machines = buildMachines(ETHERFI_COMPANY_RICH, functionData);
  const safeAddr = RICH_ADDRESSES.SAFE;

  // The Safe primary-owns machines[0] (→ one group). It carries controls_detail
  // rows for that same address on both chains — a CREATE2 twin governed on each.
  // The canvas is scoped to ethereum, so only the ethereum row's functions may
  // attach to the visible node; the base row keys to its own chain and finds no
  // ethereum child.
  function safeWith(detail) {
    return [
      {
        address: safeAddr,
        type: "safe",
        primary_for: [machines[0].address],
        co_controls: [],
        controls_detail: detail,
      },
    ];
  }

  it("attaches only the active chain's controls_detail row to the node", () => {
    const principals = safeWith([
      { address: machines[0].address, chain: "ethereum", functions: ["pauseOnEth"], capabilities: ["pause"] },
      { address: machines[0].address, chain: "base", functions: ["pauseOnBase"], capabilities: ["pause"] },
    ]);
    const { nodes } = buildGraphLayout(machines, [], principals, {}, "ethereum");
    const group = nodes.find((n) => n.type === "group" && n.id === safeAddr);
    const governs = group.data.controllers[0].governs;
    expect(governs).toHaveLength(1);
    // Only ethereum's function attaches; the same-address base row must not fold
    // onto the ethereum node (today it overwrites the ethereum row, last-wins).
    expect(governs[0].functions).toEqual(["pauseOnEth"]);
  });

  it("attaches a chain-less legacy row on any active chain", () => {
    const principals = safeWith([
      { address: machines[0].address, functions: ["pauseLegacy"], capabilities: ["pause"] },
    ]);
    const { nodes } = buildGraphLayout(machines, [], principals, {}, "ethereum");
    const group = nodes.find((n) => n.type === "group" && n.id === safeAddr);
    expect(group.data.controllers[0].governs[0].functions).toEqual(["pauseLegacy"]);
  });
});

// Indirect callers derive from the SAME agency-gated reach walk as the canvas
// overlay (fund_flows adjacency + controls_detail agency index) — not from the
// per-contract control_graph blobs, whose relations (external_call_target &
// co.) once leaked callee owners into the governance path. A principal only
// publishes as indirect when its walk was LICENSED to stand on a direct
// caller: reaching one through a non-agency power (pause-only) is where the
// claim ends, not a route to the function.
describe("collectIndirectCallers — witnessed-agency walk", () => {
  const CALLER = "0x1111111111111111111111111111111111111111";
  const MID = "0x2222222222222222222222222222222222222222";
  const OWNER_SAFE = "0x3333333333333333333333333333333333333333";
  const PAUSER_SAFE = "0x4444444444444444444444444444444444444444";

  // fn is gated by CALLER (a contract); OWNER_SAFE owns MID which controls
  // CALLER; PAUSER_SAFE can only pause CALLER.
  const fn = {
    controllers: [
      { label: "authority", principals: [{ address: CALLER, resolved_type: "contract" }] },
    ],
  };

  function companyWith(principals, extraFlows = []) {
    return {
      contracts: [{ address: CALLER, control_graph: { nodes: [], edges: [] } }],
      principals,
      fund_flows: extraFlows,
    };
  }

  it("publishes a principal whose agency route stands on the direct caller, with the route as path", () => {
    const companyData = companyWith(
      [
        {
          address: OWNER_SAFE,
          type: "safe",
          label: "Owner Safe",
          details: { threshold: 2 },
          controls: [MID],
          controls_detail: [{ address: MID, capabilities: ["ownership"] }],
        },
      ],
      [
        { from: OWNER_SAFE, to: MID, type: "principal", relation: "controller_value" },
        // MID is a plain contract standpoint (no controls_detail) — the walk
        // stays blind through it, matching the backend closure.
        { from: MID, to: CALLER, type: "controller", relation: "controller_value" },
      ],
    );
    const ctx = buildIndirectCallerContext(companyData, null);
    const indirect = collectIndirectCallers(collectDirectCallers(fn), ctx);
    expect(indirect.map((p) => p.address)).toEqual([OWNER_SAFE]);
    expect(indirect[0].resolvedType).toBe("safe");
    // Trail renders caller-upward: [direct caller, ...route..., principal].
    expect(indirect[0].path.map((p) => p.address)).toEqual([CALLER, MID, OWNER_SAFE]);
    expect(indirect[0].path[0].relation).toBe("direct");
    expect(indirect[0].path[1].relation).toBe("controller_value");
  });

  it("does not publish a principal whose only witnessed power over the caller is non-agency", () => {
    const companyData = companyWith(
      [
        {
          address: PAUSER_SAFE,
          type: "safe",
          label: "Pauser",
          details: {},
          controls: [CALLER],
          controls_detail: [{ address: CALLER, capabilities: ["pause"] }],
        },
      ],
      [{ from: PAUSER_SAFE, to: CALLER, type: "principal", relation: "controller_value" }],
    );
    const ctx = buildIndirectCallerContext(companyData, null);
    const indirect = collectIndirectCallers(collectDirectCallers(fn), ctx);
    // PAUSER_SAFE reaches CALLER but was never licensed to stand on it — a
    // pause power confers no route to the functions CALLER can call.
    expect(indirect).toEqual([]);
  });

  it("ignores principals with no agency route to a direct caller", () => {
    const companyData = companyWith(
      [
        {
          address: OWNER_SAFE,
          type: "safe",
          label: "Unrelated Safe",
          details: {},
          controls: [MID],
          controls_detail: [{ address: MID, capabilities: ["ownership"] }],
        },
      ],
      // OWNER_SAFE owns MID, but no edge carries MID → CALLER: the graph
      // holds no route to the direct caller, so nothing may be published.
      [{ from: OWNER_SAFE, to: MID, type: "principal" }],
    );
    const ctx = buildIndirectCallerContext(companyData, null);
    const indirect = collectIndirectCallers(collectDirectCallers(fn), ctx);
    expect(indirect).toEqual([]);
  });
});

// Band assignment is a claim about a contract, not just a coordinate: band 2 is
// "interfaces & plumbing" (holds no authority, holds no value) and band 0 is
// "control surface". Both are read off summary-derived fields that are
// three-state on the payload, so the not-determined member has to land somewhere
// that asserts neither.
describe("layoutGroupInterior banding — three-state summary inputs", () => {
  // Bands are packed top-to-bottom and EMPTY bands take no space, so a band is
  // only observable relative to a reference card packed in the same call: same
  // row y => same band, greater y => a later band.
  const REF0 = { address: "0xref0000000000000000000000000000000000000", name: "Ref Timelock", has_timelock: true, role_evidence: "witnessed" };
  const REF1 = { address: "0xref1000000000000000000000000000000000000", name: "Ref Handler", role: "value_handler", role_evidence: "witnessed" };
  const SUBJECT = "0xaaa0000000000000000000000000000000000001";

  const relative = (reference, machine) => {
    const subject = { address: SUBJECT, name: "Subject", ...machine };
    const interior = layoutGroupInterior(
      [{ id: reference.address }, { id: subject.address }],
      [reference, subject],
      0,
    );
    return {
      ref: interior.positions.get(reference.address).y,
      subject: interior.positions.get(subject.address).y,
    };
  };

  it("puts a PROVEN timelock in the control band", () => {
    const { ref, subject } = relative(REF0, { has_timelock: true, role: "utility", role_evidence: "witnessed" });
    expect(subject).toBe(ref);
  });

  it("does not put a NOT-DETERMINED timelock flag in the control band", () => {
    // NEGATIVE CONTROL for the test above: promoting every non-false flag would
    // badge an unanalysed contract a control surface.
    const { ref, subject } = relative(REF0, { has_timelock: null, role: "value_handler", role_evidence: "witnessed" });
    expect(subject).toBeGreaterThan(ref);
  });

  it("keeps a role with NO summary evidence out of the plumbing band", () => {
    // `role: "utility"` reached through nothing but nulls is not evidence that a
    // contract is plumbing. It takes the neutral band-1 catchall instead, which
    // is the reference card's band.
    const { ref, subject } = relative(REF1, { role: "utility", role_evidence: "not_determined" });
    expect(subject).toBe(ref);
  });

  it("still puts a WITNESSED utility role in the plumbing band", () => {
    // POSITIVE CONTROL: hedging every utility row would empty band 2.
    const { ref, subject } = relative(REF1, { role: "utility", role_evidence: "witnessed" });
    expect(subject).toBeGreaterThan(ref);
  });
});
