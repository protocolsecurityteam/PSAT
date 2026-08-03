import { describe, it, expect } from "vitest";

import {
  buildControlAdjacency,
  buildControlEdgeIndex,
  controlReach,
  dedupeAndTagRows,
  edgeClaims,
  governancePathTargets,
  shortestControlPath,
} from "./governancePath.js";

const TIMELOCK = "0x1111111111111111111111111111111111111111";
const POOL = "0x2222222222222222222222222222222222222222";
const VAULT = "0x3333333333333333333333333333333333333333";
const NFT = "0x4444444444444444444444444444444444444444";

describe("buildControlAdjacency", () => {
  it("keeps control-relation edges and drops value flows", () => {
    const adj = buildControlAdjacency([
      { from: TIMELOCK, to: POOL, type: "principal" },
      { from: TIMELOCK, to: VAULT, type: "controller" },
      { from: POOL, to: NFT, type: "controls" },
      { from: POOL, to: VAULT, type: "controls_value" }, // value → excluded
    ]);
    expect([...adj.get(TIMELOCK)]).toEqual(expect.arrayContaining([POOL, VAULT]));
    expect([...adj.get(POOL)]).toEqual([NFT]); // controls_value dropped
  });

  it("ignores self-edges and lowercases", () => {
    const adj = buildControlAdjacency([
      { from: TIMELOCK.toUpperCase(), to: TIMELOCK, type: "principal" }, // self
      { from: TIMELOCK.toUpperCase(), to: POOL.toUpperCase(), type: "principal" },
    ]);
    expect(adj.has(TIMELOCK) && adj.get(TIMELOCK).has(TIMELOCK)).toBe(false);
    expect(adj.get(TIMELOCK).has(POOL)).toBe(true);
  });
});

describe("governancePathTargets", () => {
  it("walks the control graph transitively, excluding the start", () => {
    const adj = buildControlAdjacency([
      { from: TIMELOCK, to: POOL, type: "principal" },
      { from: POOL, to: VAULT, type: "controls" },
      { from: VAULT, to: NFT, type: "controls" },
    ]);
    expect(governancePathTargets(TIMELOCK, adj).sort()).toEqual([POOL, VAULT, NFT].sort());
    expect(governancePathTargets(TIMELOCK, adj)).not.toContain(TIMELOCK);
  });

  it("terminates on a cycle", () => {
    const adj = buildControlAdjacency([
      { from: TIMELOCK, to: POOL, type: "controls" },
      { from: POOL, to: TIMELOCK, type: "controls" },
    ]);
    expect(governancePathTargets(TIMELOCK, adj)).toEqual([POOL]);
  });

  it("returns empty for an address with no outbound control edges", () => {
    const adj = buildControlAdjacency([{ from: POOL, to: VAULT, type: "controls" }]);
    expect(governancePathTargets(TIMELOCK, adj)).toEqual([]);
  });
});

describe("dedupeAndTagRows", () => {
  it("collapses identical addresses (the payload's duplicate-contract rows)", () => {
    const rows = dedupeAndTagRows([
      { address: NFT, name: "WithdrawRequestNFT", is_proxy: true },
      { address: NFT.toUpperCase(), name: "WithdrawRequestNFT", is_proxy: true }, // same address
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].address).toBe(NFT);
  });

  it("tags a genuine same-name proxy/impl family (different addresses)", () => {
    const rows = dedupeAndTagRows([
      { address: POOL, name: "RolesAuthority", is_proxy: true },
      { address: VAULT, name: "RolesAuthority", is_proxy: false },
    ]);
    const byAddr = Object.fromEntries(rows.map((r) => [r.address, r.tag]));
    expect(byAddr[POOL]).toBe("proxy");
    expect(byAddr[VAULT]).toBe("impl");
  });

  it("leaves a same-name family untagged when they don't split proxy/impl", () => {
    const rows = dedupeAndTagRows([
      { address: POOL, name: "UpgradeableBeacon", is_proxy: false },
      { address: VAULT, name: "UpgradeableBeacon", is_proxy: false },
    ]);
    expect(rows.every((r) => r.tag === undefined)).toBe(true);
  });
});


// The etherfi row-0 shape, in miniature: a queue reaching a vault three hops out
// through a solver and a teller, with a decoy branch and a cycle back to the
// start so the walks have something to get wrong.
const SOLVER = "0x5555555555555555555555555555555555555555";
const TELLER = "0x6666666666666666666666666666666666666666";
const FAR = "0x7777777777777777777777777777777777777777";
const OFFGRAPH = "0x8888888888888888888888888888888888888888";

const REACH_FLOWS = [
  { from: POOL, to: SOLVER, type: "principal", relation: "role_principal", label: "roles 77" },
  { from: SOLVER, to: TELLER, type: "principal", relation: "role_principal", label: "roles 12" },
  { from: TELLER, to: VAULT, type: "controller", relations: [{ relation: "role_principal", label: "roles 2,3" }] },
  { from: VAULT, to: FAR, type: "controls" },
  { from: FAR, to: NFT, type: "controls" },
  { from: SOLVER, to: POOL, type: "principal" }, // cycle back to the start
  { from: TIMELOCK, to: NFT, type: "principal" }, // decoy branch, off the walk
  { from: POOL, to: TELLER, type: "controls_value" }, // value, never a control hop
];

describe("controlReach", () => {
  it("records the hop distance of the SHORTEST route to each reached node", () => {
    const reach = controlReach(POOL, buildControlAdjacency(REACH_FLOWS));
    expect(reach.get(SOLVER)).toBe(1);
    expect(reach.get(TELLER)).toBe(2);
    expect(reach.get(VAULT)).toBe(3);
    expect(reach.get(FAR)).toBe(4);
    expect(reach.get(NFT)).toBe(5);
  });

  it("excludes the start even when the graph cycles back to it", () => {
    const reach = controlReach(POOL, buildControlAdjacency(REACH_FLOWS));
    expect(reach.has(POOL)).toBe(false);
  });

  it("excludes what only a value flow would have reached", () => {
    // TELLER is reached at hop 2 through the control chain, never at hop 1
    // through the controls_value edge.
    expect(controlReach(POOL, buildControlAdjacency(REACH_FLOWS)).get(TELLER)).toBe(2);
  });

  it("is empty for an address with no outbound control edges", () => {
    expect(controlReach(NFT, buildControlAdjacency(REACH_FLOWS)).size).toBe(0);
    expect(controlReach("", buildControlAdjacency(REACH_FLOWS)).size).toBe(0);
  });
});

describe("edgeClaims", () => {
  it("normalizes the scalar single-claim shape", () => {
    expect(edgeClaims({ relation: "role_principal", label: "roles 77" })).toEqual([
      { relation: "role_principal", label: "roles 77" },
    ]);
  });

  it("normalizes the multi-claim list shape", () => {
    expect(edgeClaims({ relations: [{ relation: "controller_value", label: "hook" }, { relation: "x" }] })).toEqual([
      { relation: "controller_value", label: "hook" },
      { relation: "x", label: null },
    ]);
  });

  it("claims nothing for an edge the control graph never witnessed one for", () => {
    expect(edgeClaims({ type: "controller" })).toEqual([]);
    expect(edgeClaims(null)).toEqual([]);
  });
});

describe("shortestControlPath", () => {
  it("walks the host→target route and carries each hop's edge", () => {
    const { host, hops } = shortestControlPath([POOL], VAULT, buildControlEdgeIndex(REACH_FLOWS));
    expect(host).toBe(POOL);
    expect(hops.map((h) => [h.from, h.to])).toEqual([
      [POOL, SOLVER],
      [SOLVER, TELLER],
      [TELLER, VAULT],
    ]);
    expect(hops.map((h) => edgeClaims(h.flow))).toEqual([
      [{ relation: "role_principal", label: "roles 77" }],
      [{ relation: "role_principal", label: "roles 12" }],
      [{ relation: "role_principal", label: "roles 2,3" }],
    ]);
  });

  it("picks the host that reaches the target in the fewest hops", () => {
    const { host, hops } = shortestControlPath([POOL, TELLER], VAULT, buildControlEdgeIndex(REACH_FLOWS));
    expect(host).toBe(TELLER);
    expect(hops).toHaveLength(1);
  });

  it("reports an absent route as null hops, never as an empty path", () => {
    const { host, hops } = shortestControlPath([POOL], OFFGRAPH, buildControlEdgeIndex(REACH_FLOWS));
    expect(hops).toBeNull();
    expect(host).toBeNull();
  });

  it("returns a zero-hop route when the target IS the host", () => {
    expect(shortestControlPath([POOL], POOL, buildControlEdgeIndex(REACH_FLOWS)).hops).toEqual([]);
  });

  it("refuses to walk with no host, no target, or no index", () => {
    const index = buildControlEdgeIndex(REACH_FLOWS);
    expect(shortestControlPath([], VAULT, index).hops).toBeNull();
    expect(shortestControlPath([POOL], "", index).hops).toBeNull();
    expect(shortestControlPath([POOL], VAULT, null).hops).toBeNull();
  });
});

describe("buildControlEdgeIndex", () => {
  it("scopes to the active chain like the adjacency does (inv. 13)", () => {
    const index = buildControlEdgeIndex(
      [
        { from: POOL, to: VAULT, type: "principal", to_chain: "base", from_chain: "base" },
        { from: POOL, to: SOLVER, type: "principal", to_chain: "ethereum", from_chain: "ethereum" },
      ],
      "ethereum",
    );
    expect([...index.get(POOL).keys()]).toEqual([SOLVER]);
  });
});
