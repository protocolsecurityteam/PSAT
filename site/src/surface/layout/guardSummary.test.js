import { describe, expect, it } from "vitest";
import { guardSummary } from "./guardSummary.js";

describe("compact capability emptiness witness", () => {
  it("preserves exact-empty behavior without shipping the capability tree", () => {
    const old = { status: "resolved_empty", capability_expr: { kind: "finite_set", membership_quality: "exact", members: [] } };
    expect(guardSummary({ status: "resolved_empty", capability_proven_empty: true })).toEqual(guardSummary(old));
    expect(guardSummary({ status: "resolved_empty", capability_proven_empty: true }).kind).toBe("resolved_empty");
  });
  it("does not interpret a missing or false witness as an empty or public caller set", () => {
    for (const fn of [{ capability_proven_empty: true }, { capability_expr: { kind: "finite_set", membership_quality: "exact", members: [] } }, {}, { capability_proven_empty: false }, { capability_proven_empty: null }]) {
      expect(guardSummary(fn).kind).not.toBe("resolved_empty");
      expect(guardSummary(fn).kind).not.toBe("public");
    }
  });
});
