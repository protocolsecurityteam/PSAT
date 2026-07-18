import { describe, it, expect } from "vitest";

import { coalesceChain, entityKey } from "./entityKey.js";

const ADDR = "0xAbC0000000000000000000000000000000000001";

describe("coalesceChain", () => {
  it("maps NULL/empty/undefined/mainnet to ethereum (NULL ≡ mainnet convention)", () => {
    expect(coalesceChain(null)).toBe("ethereum");
    expect(coalesceChain(undefined)).toBe("ethereum");
    expect(coalesceChain("")).toBe("ethereum");
    expect(coalesceChain("  ")).toBe("ethereum");
    expect(coalesceChain("mainnet")).toBe("ethereum");
    expect(coalesceChain("MAINNET")).toBe("ethereum");
  });

  it("lowercases and passes other chains through", () => {
    expect(coalesceChain("Base")).toBe("base");
    expect(coalesceChain("ethereum")).toBe("ethereum");
  });
});

describe("entityKey", () => {
  it("lowercases the address and prefixes the coalesced chain", () => {
    expect(entityKey("base", ADDR)).toBe("base::0xabc0000000000000000000000000000000000001");
  });

  it("keys the same address on two chains distinctly", () => {
    expect(entityKey("ethereum", ADDR)).not.toBe(entityKey("base", ADDR));
  });

  it("collides a NULL-chain row with the explicit ethereum row (legacy convention)", () => {
    expect(entityKey(null, ADDR)).toBe(entityKey("ethereum", ADDR));
    expect(entityKey("mainnet", ADDR)).toBe(entityKey("ethereum", ADDR));
  });
});
