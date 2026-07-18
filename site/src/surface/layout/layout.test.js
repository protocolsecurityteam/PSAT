// Direct tests for the pure helpers extracted from ProtocolSurface.jsx.
// Previously exercised only through the rendered surface — these run the
// builders against the rich fixture so a regression in any of them shows
// up before we hit a render assertion.

import { describe, it, expect } from "vitest";

import {
  ETHERFI_COMPANY_RICH,
  RICH_ADDRESSES,
} from "../../test/fixtures.js";
import { buildMachines } from "./buildMachines.js";
import { collectPrincipals } from "./controlGraph.js";
import { guardSummary } from "./guardSummary.js";
import { buildSearchResults } from "./search.js";
import { aggregateEdges, assignGroups, buildGraphLayout, groupHeaderHeight, layoutGroupInterior } from "./elkLayout.js";
import { buildControlAdjacency, flowOnChain } from "./governancePath.js";
import { entityKey } from "../entityKey.js";

// buildMachines reads functions by the composite (chain, address) token; the
// fixture is single-chain (no chain field → "ethereum"), so key it the same way.
const functionData = Object.fromEntries(
  ETHERFI_COMPANY_RICH.contracts.map((c) => [entityKey(c.chain, c.address), c.functions || []]),
);

describe("buildMachines", () => {
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
});

describe("collectPrincipals", () => {
  it("returns a direct caller for a guarded fixture function", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "pause");
    const { direct } = collectPrincipals(fn, ETHERFI_COMPANY_RICH);
    expect(direct).toHaveLength(1);
    expect(direct[0].resolvedType).toBe("safe");
  });

  it("returns no direct caller for a public-authority function", () => {
    const fn = ETHERFI_COMPANY_RICH.contracts[0].functions.find((f) => f.function === "deposit");
    const { direct } = collectPrincipals(fn, ETHERFI_COMPANY_RICH);
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

describe("buildControlAdjacency — chain scope (inv. 13)", () => {
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

describe("flowOnChain — canvas fund-flow scope (R3, inv. 13)", () => {
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

describe("buildGroupControllers — controls_detail chain keying (R4, inv. 13)", () => {
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
