import { describe, expect, it } from "vitest";

import { formatUsdTotal, usdIsLowerBound } from "./usdBound.js";

describe("usdBound", () => {
  it("marks a total over unvalued rows as a lower bound", () => {
    expect(usdIsLowerBound({ total_usd: 5000, holdings_coverage: { unvalued_rows: 2 } })).toBe(true);
    expect(usdIsLowerBound({ total_usd: 5000, holdings_coverage: { unvalued_rows: 0 } })).toBe(false);
    expect(usdIsLowerBound({ total_usd: 5000 })).toBe(false);
    expect(usdIsLowerBound(null)).toBe(false);
  });

  it("formats a lower bound with ≥ and leaves an exact total alone", () => {
    expect(formatUsdTotal(1234567, true)).toBe("≥ $1.2M");
    expect(formatUsdTotal(1234567, false)).toBe("$1.2M");
    expect(formatUsdTotal(0, true)).toBeNull();
  });
});
