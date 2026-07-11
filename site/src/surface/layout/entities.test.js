import { describe, it, expect } from "vitest";

import { buildEntityIndex } from "./entities.js";

const PRIMARY = "0x1111111111111111111111111111111111111111"; // group owner
const VAULT = "0x3333333333333333333333333333333333333333";

describe("buildEntityIndex", () => {
  it("carries both facets for a timelock that is machine and principal", () => {
    const idx = buildEntityIndex(
      [{ address: VAULT }, { address: PRIMARY }],
      [{ address: PRIMARY, type: "timelock" }],
    );
    expect(idx.get(VAULT).machine).toBeTruthy();
    expect(idx.get(VAULT).principal).toBeNull();
    expect(idx.get(PRIMARY).machine).toBeTruthy();
    expect(idx.get(PRIMARY).principal).toBeTruthy();
  });
});
