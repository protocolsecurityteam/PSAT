import { describe, expect, it } from "vitest";

import { safeDetailsSignersText as safeSignersText } from "./safeThreshold.js";

describe("safeSignersText", () => {
  it("shows a published threshold over its owners", () => {
    expect(safeSignersText({ owners: ["0xa", "0xb", "0xc"], threshold: 2 })).toBe("2/3");
  });

  it("keeps a missing threshold not determined, never reading the owner count as signatures", () => {
    expect(safeSignersText({ owners: ["0xa", "0xb", "0xc"] })).toBe("3 signers · threshold not determined");
    expect(safeSignersText({ owners: ["0xa"], threshold: 0 })).toBe("1 signer · threshold not determined");
  });

  it("is null with no owners", () => {
    expect(safeSignersText({ threshold: 2 })).toBeNull();
    expect(safeSignersText(null)).toBeNull();
  });
});
