import { describe, it, expect } from "vitest";

import {
  buildAgencyIndex,
  buildControlAdjacency,
  buildControlEdgeIndex,
  controlClosure,
  dedupeAndTagRows,
  edgeClaims,
  shortestControlPath,
} from "./governancePath.js";

const TIMELOCK = "0x1111111111111111111111111111111111111111";
const POOL = "0x2222222222222222222222222222222222222222";
const VAULT = "0x3333333333333333333333333333333333333333";
const NFT = "0x4444444444444444444444444444444444444444";

describe("buildControlAdjacency", () => {
  it("keeps control-relation edges — controls_value included — and drops typeless value rows", () => {
    const adj = buildControlAdjacency([
      { from: TIMELOCK, to: POOL, type: "principal" },
      { from: TIMELOCK, to: VAULT, type: "controller" },
      { from: POOL, to: NFT, type: "controls" },
      // The backend emits controls_value INSTEAD OF controls for an owner
      // whose target moves value — it is an ownership hop, not value movement.
      { from: POOL, to: VAULT, type: "controls_value" },
      { from: VAULT, to: NFT, label: "rebalance", usd: 5 }, // value row → excluded
    ]);
    expect([...adj.get(TIMELOCK)]).toEqual(expect.arrayContaining([POOL, VAULT]));
    expect([...adj.get(POOL)].sort()).toEqual([VAULT, NFT].sort());
    expect(adj.has(VAULT)).toBe(false); // the typeless value row is never a hop
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
  { from: POOL, to: TELLER, label: "swap", usd: 5 }, // typeless value row, never a control hop
];

describe("controlClosure — shortest distances", () => {
  it("records the hop distance of the SHORTEST route to each reached node", () => {
    const { distances } = controlClosure(POOL, buildControlAdjacency(REACH_FLOWS));
    expect(distances.get(SOLVER)).toBe(1);
    // TELLER is reached at hop 2 through the control chain, never at hop 1
    // through the typeless value row.
    expect(distances.get(TELLER)).toBe(2);
    expect(distances.get(VAULT)).toBe(3);
    expect(distances.get(FAR)).toBe(4);
    expect(distances.get(NFT)).toBe(5);
  });

  it("excludes the start even when the graph cycles back to it", () => {
    const { distances } = controlClosure(POOL, buildControlAdjacency(REACH_FLOWS));
    expect(distances.has(POOL)).toBe(false);
  });

  it("is empty for an address with no outbound control edges", () => {
    expect(controlClosure(NFT, buildControlAdjacency(REACH_FLOWS)).distances.size).toBe(0);
    expect(controlClosure("", buildControlAdjacency(REACH_FLOWS)).distances.size).toBe(0);
  });
});

// The etherfi pause-EOA shape, in miniature: an EOA whose only witnessed power
// on POOL is pause, while POOL is stored as VAULT's controller — the walk must
// reach POOL and stop, never claiming VAULT through a power that confers no
// agency. TIMELOCK is the contrast case: witnessed ownership over POOL, so the
// walk continues through it.
const EOA = "0x9999999999999999999999999999999999999999";

const GATED_FLOWS = [
  { from: EOA, to: POOL, type: "principal", relation: "role_principal", label: "roles 14" },
  { from: TIMELOCK, to: POOL, type: "principal", relation: "controller_value", label: "owner" },
  { from: POOL, to: VAULT, type: "controller", relation: "controller_value", label: "pool" },
  { from: VAULT, to: NFT, type: "controls" },
];

const GATED_PRINCIPALS = [
  {
    address: EOA,
    controls_detail: [{ address: POOL, chain: "ethereum", capabilities: ["pause"], functions: ["pauseUntil"] }],
  },
  {
    address: TIMELOCK,
    controls_detail: [{ address: POOL, chain: "ethereum", capabilities: ["ownership", "pause"], functions: ["upgradeTo"] }],
  },
];

describe("buildAgencyIndex", () => {
  it("keeps only agency-conferring targets, but keeps EVERY detailed principal", () => {
    const index = buildAgencyIndex(GATED_PRINCIPALS);
    // Pause confers no agency — the entry exists (the principal IS emitted,
    // its powers are witnessed) and licenses nothing.
    expect(index.get(EOA).size).toBe(0);
    expect([...index.get(TIMELOCK)]).toEqual([POOL]);
  });

  it("has no entry for an address the payload never details — a different state from empty", () => {
    const index = buildAgencyIndex(GATED_PRINCIPALS);
    expect(index.has(POOL)).toBe(false);
  });

  it("scopes detail entries to the active chain (inv. 13), keeping legacy chainless entries", () => {
    const index = buildAgencyIndex(
      [
        {
          address: EOA,
          controls_detail: [
            { address: POOL, chain: "base", capabilities: ["ownership"] },
            { address: VAULT, capabilities: ["upgrade"] }, // legacy, no chain
          ],
        },
      ],
      "ethereum",
    );
    expect(index.get(EOA).has(POOL)).toBe(false);
    expect(index.get(EOA).has(VAULT)).toBe(true);
  });
});

describe("controlClosure — agency gating", () => {
  const adj = buildControlAdjacency(GATED_FLOWS);
  const agency = buildAgencyIndex(GATED_PRINCIPALS);

  it("stops at a target held only by a non-agency power: pause reaches, it never confers", () => {
    const { distances } = controlClosure(EOA, adj, agency);
    expect(distances.get(POOL)).toBe(1);
    expect(distances.has(VAULT)).toBe(false);
    expect(distances.has(NFT)).toBe(false);
  });

  it("continues through a target held by an agency power", () => {
    const { distances } = controlClosure(TIMELOCK, adj, agency);
    expect(distances.get(POOL)).toBe(1);
    expect(distances.get(VAULT)).toBe(2);
    expect(distances.get(NFT)).toBe(3);
  });

  it("walks blind from a standpoint the payload holds no capability detail for", () => {
    // POOL is a plain contract node — the backend closure walks contract nodes
    // blind, and so does this one.
    const { distances } = controlClosure(POOL, adj, agency);
    expect(distances.get(VAULT)).toBe(1);
    expect(distances.get(NFT)).toBe(2);
  });

  it("without an agency index the walk is blind everywhere (machine-only reconstruction)", () => {
    const { distances } = controlClosure(EOA, adj, null);
    expect(distances.get(NFT)).toBe(3);
  });

  it("re-enters a terminal direct target through an agency route, keeping the shorter distance", () => {
    // S pauses B directly, but also owns A which controls B: B's shortest
    // distance stays hop 1, and the walk resumes through B at hop 2 — the
    // ownership route is one the control graph carries, and hiding what lies
    // beyond it would under-claim.
    const dAdj = buildControlAdjacency([
      { from: EOA, to: VAULT, type: "principal" }, // pause-only, terminal
      { from: EOA, to: POOL, type: "principal" }, // ownership, continues
      { from: POOL, to: VAULT, type: "controller" },
      { from: VAULT, to: NFT, type: "controls" },
    ]);
    const dAgency = buildAgencyIndex([
      {
        address: EOA,
        controls_detail: [
          { address: VAULT, capabilities: ["pause"] },
          { address: POOL, capabilities: ["ownership"] },
        ],
      },
    ]);
    const { distances, expandHops } = controlClosure(EOA, dAdj, dAgency);
    expect(distances.get(VAULT)).toBe(1); // shortest reach: the direct pause
    expect(expandHops.get(VAULT)).toBe(2); // expansion resumes via ownership of POOL
    expect(distances.get(NFT)).toBe(3);
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
