import { describe, it, expect } from "vitest";

import { deriveAvailableChains, defaultChainFor, pickActiveChain } from "./chainScope.js";

describe("deriveAvailableChains", () => {
  it("counts per chain, coalescing NULL/missing/mainnet to ethereum (matches key derivation)", () => {
    const chains = deriveAvailableChains([
      { chain: "ethereum" },
      { chain: null }, // legacy NULL ≡ ethereum
      { chain: undefined }, // missing ≡ ethereum
      { chain: "mainnet" }, // alias ≡ ethereum
      { chain: "base" },
      { chain: "base" },
    ]);
    expect(chains).toEqual([
      { name: "ethereum", count: 4 },
      { name: "base", count: 2 },
    ]);
  });

  it("puts ethereum first, then orders by count desc then name", () => {
    const chains = deriveAvailableChains([
      { chain: "base" },
      { chain: "base" },
      { chain: "arbitrum" },
      { chain: "ethereum" },
    ]);
    expect(chains.map((c) => c.name)).toEqual(["ethereum", "base", "arbitrum"]);
  });

  it("returns [] for no contracts", () => {
    expect(deriveAvailableChains([])).toEqual([]);
    expect(deriveAvailableChains()).toEqual([]);
  });
});

describe("defaultChainFor", () => {
  it("prefers ethereum, else the largest chain, else ethereum", () => {
    expect(defaultChainFor([{ name: "base", count: 3 }, { name: "ethereum", count: 1 }])).toBe("ethereum");
    expect(defaultChainFor([{ name: "base", count: 3 }, { name: "arbitrum", count: 1 }])).toBe("base");
    expect(defaultChainFor([])).toBe("ethereum");
  });
});

describe("pickActiveChain", () => {
  const available = [
    { name: "ethereum", count: 2 },
    { name: "base", count: 1 },
  ];

  it("honors a valid chosen chain", () => {
    expect(pickActiveChain(available, "base")).toBe("base");
  });

  it("coalesces aliases/casing before matching", () => {
    expect(pickActiveChain(available, "MAINNET")).toBe("ethereum");
    expect(pickActiveChain(available, "Base")).toBe("base");
  });

  it("degrades an unknown/typo'd/off-protocol chosen chain to the default (never blank)", () => {
    expect(pickActiveChain(available, "solana")).toBe("ethereum"); // not in protocol
    expect(pickActiveChain(available, "bqse")).toBe("ethereum"); // typo
    expect(pickActiveChain(available, "")).toBe("ethereum");
    expect(pickActiveChain(available, null)).toBe("ethereum");
  });

  it("falls back to the largest chain when the protocol has no ethereum deployment", () => {
    const noEth = [{ name: "base", count: 3 }, { name: "arbitrum", count: 1 }];
    expect(pickActiveChain(noEth, "unknownchain")).toBe("base");
  });
});
