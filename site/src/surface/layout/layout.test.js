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
import { aggregateEdges, assignGroups, buildGraphLayout } from "./elkLayout.js";

const functionData = Object.fromEntries(
  ETHERFI_COMPANY_RICH.contracts.map((c) => [c.address, c.functions || []]),
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

  it("returns contracts when mode=all", () => {
    const results = buildSearchResults(machines, principals, "all", "name", "");
    expect(results.every((r) => r.kind === "contract")).toBe(true);
    expect(results.length).toBe(machines.length);
  });

  it("filters by query against name/address/type", () => {
    const results = buildSearchResults(machines, principals, "all", "name", "Vault");
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("Vault");
  });

  it("supports `value > 1m` style numeric filters", () => {
    const machinesWithValue = machines.map((m) => ({ ...m, total_usd: m.address === RICH_ADDRESSES.VAULT ? 5_000_000 : 100 }));
    const results = buildSearchResults(machinesWithValue, principals, "all", "value", "value > 1m");
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
