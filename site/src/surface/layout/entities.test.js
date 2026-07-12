import { describe, it, expect } from "vitest";

import { buildEntityIndex, resolveEntity } from "./entities.js";

const PRIMARY = "0x1111111111111111111111111111111111111111"; // group owner
const VAULT = "0x3333333333333333333333333333333333333333";
const OFF_INDEX = "0x4444444444444444444444444444444444444444"; // owner EOA, no node
// A role-id pseudo address: >20 bytes of leading zeros (isRoleIdAddress heuristic).
const ROLE_ID = "0x0000000000000000000000000000000000000000000000000000000000000005";

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

describe("resolveEntity", () => {
  const idx = buildEntityIndex([{ address: VAULT, owner: OFF_INDEX }], []);

  it("returns the index hit as-is when the address is known", () => {
    expect(resolveEntity(idx, VAULT)).toBe(idx.get(VAULT));
  });

  it("returns null for a null/empty address", () => {
    expect(resolveEntity(idx, null)).toBeNull();
    expect(resolveEntity(idx, "")).toBeNull();
  });

  it("synthesizes a minimal principal for an off-index target, honoring the hint", () => {
    const ent = resolveEntity(idx, OFF_INDEX, {
      machines: [{ address: VAULT, owner: OFF_INDEX }],
      hint: { type: "eoa", label: "deployer", details: { note: "x" } },
    });
    expect(ent.machine).toBeNull();
    expect(ent.principal).toMatchObject({
      address: OFF_INDEX,
      type: "eoa",
      label: "deployer",
      details: { note: "x" },
    });
    // controls derives from machines naming this address as owner.
    expect(ent.principal.controls).toEqual([VAULT]);
  });

  it("defaults an unhinted off-index target to type 'unknown' with a label fallback", () => {
    const ent = resolveEntity(idx, OFF_INDEX);
    expect(ent.principal.type).toBe("unknown");
    expect(ent.principal.label).toBe("unknown");
    expect(ent.principal.controls).toEqual([]);
  });

  it("never synthesizes a principal for a role-id pseudo address", () => {
    expect(resolveEntity(idx, ROLE_ID, { hint: { type: "eoa" } })).toBeNull();
  });
});
