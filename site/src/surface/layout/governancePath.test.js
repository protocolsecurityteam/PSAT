import { describe, it, expect } from "vitest";

import {
  buildAgencyIndex,
  buildControlAdjacency,
  buildControlEdgeIndex,
  controlClosure,
  controlPathEdges,
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

describe("controlPathEdges", () => {
  const adj = buildControlAdjacency(REACH_FLOWS);
  const pathEdges = controlPathEdges(POOL, adj, controlClosure(POOL, adj));

  it("carries every hop of the spine, in direction", () => {
    expect(pathEdges.has(`${POOL}>${SOLVER}`)).toBe(true);
    expect(pathEdges.has(`${SOLVER}>${TELLER}`)).toBe(true);
    expect(pathEdges.has(`${TELLER}>${VAULT}`)).toBe(true);
    expect(pathEdges.has(`${VAULT}>${FAR}`)).toBe(true);
    expect(pathEdges.has(`${FAR}>${NFT}`)).toBe(true);
  });

  it("drops the cycle back to the start and the off-walk branch", () => {
    // SOLVER→POOL runs backwards (hop 1 → hop 0) — no route it shortens.
    expect(pathEdges.has(`${SOLVER}>${POOL}`)).toBe(false);
    // TIMELOCK is outside the closure entirely.
    expect(pathEdges.has(`${TIMELOCK}>${NFT}`)).toBe(false);
    // The value flow was never a control hop.
    expect(pathEdges.has(`${POOL}>${TELLER}`)).toBe(false);
    expect(pathEdges.size).toBe(5);
  });

  it("keeps BOTH parents' edges into a shared child (diamond)", () => {
    // start → A, start → B, A → C, B → C. C is hop 2 either way, so both
    // arriving edges are shortest routes: dropping one would claim a route the
    // walk never ruled out.
    const dAdj = buildControlAdjacency([
      { from: POOL, to: SOLVER, type: "controls" },
      { from: POOL, to: TELLER, type: "controls" },
      { from: SOLVER, to: VAULT, type: "controls" },
      { from: TELLER, to: VAULT, type: "controls" },
    ]);
    const edges = controlPathEdges(POOL, dAdj, controlClosure(POOL, dAdj));
    expect([...edges].sort()).toEqual(
      [
        `${POOL}>${SOLVER}`,
        `${POOL}>${TELLER}`,
        `${SOLVER}>${VAULT}`,
        `${TELLER}>${VAULT}`,
      ].sort(),
    );
  });

  it("drops a same-tier edge — it is a detour, not a route", () => {
    const sAdj = buildControlAdjacency([
      { from: POOL, to: SOLVER, type: "controls" },
      { from: POOL, to: TELLER, type: "controls" },
      { from: SOLVER, to: TELLER, type: "controls" }, // hop 1 → hop 1
    ]);
    const edges = controlPathEdges(POOL, sAdj, controlClosure(POOL, sAdj));
    expect(edges.has(`${SOLVER}>${TELLER}`)).toBe(false);
    expect(edges.size).toBe(2);
  });

  it("is empty without a start, an adjacency, or a closure", () => {
    expect(controlPathEdges("", adj, controlClosure(POOL, adj)).size).toBe(0);
    expect(controlPathEdges(POOL, null, controlClosure(POOL, adj)).size).toBe(0);
    expect(controlPathEdges(POOL, adj, null).size).toBe(0);
    // A start with no outbound control edges reaches nothing to route to.
    expect(controlPathEdges(NFT, adj, controlClosure(NFT, adj)).size).toBe(0);
  });

  it("lowercases both endpoints so canvas addresses match", () => {
    const uAdj = buildControlAdjacency([{ from: POOL.toUpperCase(), to: SOLVER.toUpperCase(), type: "controls" }]);
    const edges = controlPathEdges(POOL.toUpperCase(), uAdj, controlClosure(POOL, uAdj));
    expect([...edges]).toEqual([`${POOL}>${SOLVER}`]);
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

  it("lights no route out of a terminal node", () => {
    const closure = controlClosure(EOA, adj, agency);
    const edges = controlPathEdges(EOA, adj, closure);
    expect([...edges]).toEqual([`${EOA}>${POOL}`]);
  });

  it("re-enters a terminal direct target through an agency route, keeping the shorter chip", () => {
    // S pauses B directly, but also owns A which controls B: B's chip stays
    // hop 1, and the walk resumes through B at hop 2 — the ownership route is
    // one the control graph carries, and hiding what lies beyond it would
    // under-claim.
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

    // Every hop chip has a COMPLETE lit route: the licensing edge into the
    // re-entered node (POOL→VAULT, an expansion edge that shortens no
    // distance) lights alongside the shortest-arrival edges, so NFT's chip
    // traces EOA→POOL→VAULT→NFT without a gap.
    const edges = controlPathEdges(EOA, dAdj, controlClosure(EOA, dAdj, dAgency));
    expect(edges.has(`${EOA}>${POOL}`)).toBe(true);
    expect(edges.has(`${POOL}>${VAULT}`)).toBe(true);
    expect(edges.has(`${VAULT}>${NFT}`)).toBe(true);
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
