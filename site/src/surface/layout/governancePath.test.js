import { describe, it, expect } from "vitest";

import { buildControlAdjacency, governancePathTargets, dedupeAndTagRows } from "./governancePath.js";

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
