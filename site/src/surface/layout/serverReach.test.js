// Consumption of the server-computed reach block (SURFACE_REACH_UNIFICATION_
// SPEC.md payload schema). The scorer walked; these tests pin that the client
// only follows its keys — three distinct states in, three distinct states out,
// and nothing rendered where the witness is absent.

import { describe, it, expect } from "vitest";

import { deriveReachOverlay } from "./serverReach.js";

const S = "0x1111111111111111111111111111111111111111"; // selected
const A = "0x2222222222222222222222222222222222222222"; // hop 1
const B = "0x3333333333333333333333333333333333333333"; // hop 2
const C = "0x4444444444444444444444444444444444444444"; // frontier destination
const TWIN = "0x5555555555555555555555555555555555555555"; // base-chain twin

const key = (addr, chain = "ethereum") => `${chain}::${addr}`;

const REACH = {
  model: "scorer_closure_v1",
  entities: {
    [key(S)]: {
      reached: {
        [key(A)]: { hop: 1, basis: "signal_seed" },
        [key(B)]: { hop: 2, basis: "walked_hop" },
        // Another chain's twin must not leak onto this chain's overlay.
        [key(TWIN, "base")]: { hop: 1, basis: "signal_seed" },
      },
      parents: {
        [key(A)]: key(S),
        [key(B)]: key(A),
        [key(TWIN, "base")]: key(S, "base"),
      },
      frontier: [
        { from: key(B), to: key(C), reason: "gate_does_not_confer_this_scope", basis: "conferral" },
        { from: key(B, "base"), to: key(TWIN, "base"), reason: "gate_scope_not_determined", basis: "conferral" },
      ],
    },
  },
};

describe("deriveReachOverlay — walked state", () => {
  it("maps reached keys to bare lowercased addresses at their hop", () => {
    const overlay = deriveReachOverlay(REACH, "ethereum", S);
    expect(overlay.distances.get(A)).toBe(1);
    expect(overlay.distances.get(B)).toBe(2);
  });

  it("reconstructs the walk-tree edges from the parents map", () => {
    const overlay = deriveReachOverlay(REACH, "ethereum", S);
    expect(overlay.pathEdges.has(`${S}>${A}`)).toBe(true);
    expect(overlay.pathEdges.has(`${A}>${B}`)).toBe(true);
    expect(overlay.pathEdges.size).toBe(2);
  });

  it("drops a reached entry carrying no hop — an unwitnessed distance is not published", () => {
    const overlay = deriveReachOverlay(
      { entities: { [key(S)]: { reached: { [key(A)]: { basis: "walked_hop" } } } } },
      "ethereum",
      S,
    );
    expect(overlay.distances.size).toBe(0);
  });
});

describe("deriveReachOverlay — chain filtering (inv. 13)", () => {
  it("keeps only the active chain's keys out of reached / parents / frontier", () => {
    const overlay = deriveReachOverlay(REACH, "ethereum", S);
    expect(overlay.distances.has(TWIN)).toBe(false);
    expect([...overlay.pathEdges].every((pair) => !pair.includes(TWIN))).toBe(true);
    expect(overlay.frontier.has(TWIN)).toBe(false);
  });

  it("resolves the record itself by the active chain's entity key", () => {
    // S's record is keyed ethereum::S — scoped to base there is no record for
    // this address, and absence is not reach.
    expect(deriveReachOverlay(REACH, "base", S)).toBeNull();
  });

  it("coalesces a legacy chain spelling inside a record's keys", () => {
    const legacy = {
      entities: {
        [key(S)]: { reached: { [`mainnet::${A}`]: { hop: 1, basis: "signal_seed" } } },
      },
    };
    const overlay = deriveReachOverlay(legacy, "ethereum", S);
    expect(overlay.distances.get(A)).toBe(1);
  });
});

describe("deriveReachOverlay — not_determined frontier", () => {
  it("keys frontier entries by destination, carrying the scorer's reason token", () => {
    const overlay = deriveReachOverlay(REACH, "ethereum", S);
    expect(overlay.frontier.get(C)).toEqual({
      from: B,
      to: C,
      reason: "gate_does_not_confer_this_scope",
      basis: "conferral",
    });
  });

  it("drops a frontier entry whose destination is reached — reached wins", () => {
    const merged = {
      entities: {
        [key(S)]: {
          reached: { [key(A)]: { hop: 1, basis: "signal_seed" } },
          frontier: [{ from: key(S), to: key(A), reason: "gate_scope_not_determined", basis: "conferral" }],
        },
      },
    };
    const overlay = deriveReachOverlay(merged, "ethereum", S);
    expect(overlay.frontier.size).toBe(0);
  });
});

describe("deriveReachOverlay — fail closed", () => {
  it("is null with no reach block at all", () => {
    expect(deriveReachOverlay(undefined, "ethereum", S)).toBeNull();
    expect(deriveReachOverlay(null, "ethereum", S)).toBeNull();
  });

  it("is null for an entity the block carries no record for", () => {
    expect(deriveReachOverlay(REACH, "ethereum", A)).toBeNull();
  });

  it("is null with no selected address", () => {
    expect(deriveReachOverlay(REACH, "ethereum", null)).toBeNull();
  });

  it("yields empty (not fabricated) maps for a record with empty members", () => {
    const overlay = deriveReachOverlay(
      { entities: { [key(S)]: { reached: {}, parents: {}, frontier: [] } } },
      "ethereum",
      S,
    );
    expect(overlay.distances.size).toBe(0);
    expect(overlay.pathEdges.size).toBe(0);
    expect(overlay.frontier.size).toBe(0);
  });
});
