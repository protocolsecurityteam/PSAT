import { describe, it, expect } from "vitest";

import { buildLabelMaps, lookupLabel, resolveLabelName } from "./addressLabels.js";

const ADDR = "0xABCDabcd00000000000000000000000000001234";
const addrLower = ADDR.toLowerCase();

describe("buildLabelMaps", () => {
  it("splits global and chain-qualified rows, lowercasing addresses", () => {
    const maps = buildLabelMaps({
      labels: { [ADDR]: { name: "Global" } },
      chain_labels: { base: { [ADDR]: { name: "Base" } } },
    });
    expect(maps.global.get(addrLower)).toBe("Global");
    expect(maps.byChain.get("base").get(addrLower)).toBe("Base");
  });

  it("tolerates the legacy shape with no chain_labels", () => {
    const maps = buildLabelMaps({ labels: { [ADDR]: { name: "Global" } } });
    expect(maps.global.get(addrLower)).toBe("Global");
    expect(maps.byChain.size).toBe(0);
  });

  it("tolerates null/empty responses", () => {
    const maps = buildLabelMaps(null);
    expect(maps.global.size).toBe(0);
    expect(maps.byChain.size).toBe(0);
  });
});

describe("lookupLabel — chain-specific wins else global", () => {
  const maps = buildLabelMaps({
    labels: { [ADDR]: { name: "Global" } },
    chain_labels: { base: { [ADDR]: { name: "Base" } } },
  });

  it("returns the chain override when present", () => {
    expect(lookupLabel(maps, ADDR, "base")).toBe("Base");
  });

  it("falls back to global when the chain has no override", () => {
    expect(lookupLabel(maps, ADDR, "ethereum")).toBe("Global");
  });

  it("returns global when no chain is given", () => {
    expect(lookupLabel(maps, ADDR)).toBe("Global");
  });

  it("returns null for an unknown address", () => {
    expect(lookupLabel(maps, "0x0000000000000000000000000000000000000000", "base")).toBeNull();
  });
});

describe("resolveLabelName — polymorphic labels prop", () => {
  it("reads a plain Map (legacy global-only callers)", () => {
    const m = new Map([[addrLower, "Legacy"]]);
    expect(resolveLabelName(m, ADDR)).toBe("Legacy");
    // A chain arg is ignored for the legacy Map shape.
    expect(resolveLabelName(m, ADDR, "base")).toBe("Legacy");
  });

  it("reads the maps struct with chain fallback", () => {
    const maps = buildLabelMaps({
      labels: { [ADDR]: { name: "Global" } },
      chain_labels: { base: { [ADDR]: { name: "Base" } } },
    });
    expect(resolveLabelName(maps, ADDR, "base")).toBe("Base");
    expect(resolveLabelName(maps, ADDR, "ethereum")).toBe("Global");
  });
});
