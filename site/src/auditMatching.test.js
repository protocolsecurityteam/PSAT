import { describe, it, expect } from "vitest";

import { matchesEra, parseAuditTs } from "./auditMatching.js";

// Unix seconds
const TS_NOV_2023 = 1698796800; // 2023-11-01
const TS_FEB_2024 = 1706745600; // 2024-02-01

const IMPL_V1 = {
  address: "0x1111111111111111111111111111111111111111",
  block_introduced: 18000000,
  block_replaced: 19000000,
  timestamp_introduced: TS_NOV_2023,
  timestamp_replaced: TS_FEB_2024,
};

const IMPL_V2_CURRENT = {
  address: "0x2222222222222222222222222222222222222222",
  block_introduced: 19000000,
  timestamp_introduced: TS_FEB_2024,
};

describe("parseAuditTs", () => {
  it("returns null for falsy input", () => {
    expect(parseAuditTs(null)).toBeNull();
    expect(parseAuditTs(undefined)).toBeNull();
    expect(parseAuditTs("")).toBeNull();
  });

  it("returns null for an unparseable string", () => {
    expect(parseAuditTs("not-a-date")).toBeNull();
  });

  it("parses ISO dates into milliseconds", () => {
    expect(parseAuditTs("2023-11-15")).toBe(Date.parse("2023-11-15"));
  });
});

describe("matchesEra: reviewed_commit is strictly address-bound", () => {
  const cov = {
    audit_id: 1,
    match_type: "reviewed_commit",
    impl_address: IMPL_V2_CURRENT.address,
    date: "2024-03-15",
  };

  it("attaches to the impl whose address matches", () => {
    expect(matchesEra(cov, IMPL_V2_CURRENT)).toBe(true);
  });

  it("does NOT fall through to temporal matching on other impls", () => {
    // Even if the audit date fits V1's era, reviewed_commit should
    // stay pinned to the address it was proven against.
    const earlyCov = { ...cov, date: "2023-11-15" };
    expect(matchesEra(earlyCov, IMPL_V1)).toBe(false);
  });

  it("matches case-insensitively", () => {
    const mixedCase = { ...cov, impl_address: cov.impl_address.toUpperCase() };
    expect(matchesEra(mixedCase, IMPL_V2_CURRENT)).toBe(true);
  });
});

describe("matchesEra: impl_era / direct uses temporal placement", () => {
  // Backend pins cov.impl_address to the CURRENT impl (V2) because it
  // only has a Contract row for the current impl. If matchesEra
  // short-circuited on address equality, every `direct` audit would
  // land on the current era even when its date clearly belongs to a
  // past era. The fix: for non-reviewed_commit rows, fall through to
  // block-range then date-range (with 14-day grace).
  it("places a mid-era impl_era audit on V1 by date", () => {
    const cov = {
      audit_id: 1,
      match_type: "impl_era",
      impl_address: IMPL_V2_CURRENT.address, // backend pinned to current
      date: "2023-12-15", // mid V1 era (Nov 1 → Feb 1)
      covered_from_block: null,
      covered_to_block: null,
    };
    expect(matchesEra(cov, IMPL_V1)).toBe(true);
    // Does NOT spread to V2 — date is far outside V2's era even with grace.
    expect(matchesEra(cov, IMPL_V2_CURRENT)).toBe(false);
  });

  it("does NOT attach a 2024-10-08 audit to a 2026 current impl (Rewards Router regression)", () => {
    // Real case from EtherFiRewardsRouter: a Certora audit dated
    // 2024-10-08 has impl_address pinned to the 2026 current impl by
    // the backend. It should NOT appear on the 2026 era — it belongs
    // on the Oct 2024 era of a past impl.
    const TS_OCT_18_2024 = 1729209600; // 2024-10-18
    const TS_MAR_26_2025 = 1742947200; // 2025-03-26
    const TS_FEB_12_2026 = 1770940800; // 2026-02-12
    const oct2024Impl = {
      address: "0xcb160af093564e44dc4c07bc03b828354e0fee77",
      timestamp_introduced: TS_OCT_18_2024,
      timestamp_replaced: TS_MAR_26_2025,
    };
    const feb2026Current = {
      address: "0x408de8d339f40086c5643ee4778e0f872ab5e423",
      timestamp_introduced: TS_FEB_12_2026,
    };
    const cov = {
      audit_id: 25,
      match_type: "direct",
      impl_address: feb2026Current.address, // backend pinned to current
      date: "2024-10-08",
    };
    // Within 14-day grace of oct2024Impl.timestamp_introduced → MATCH
    expect(matchesEra(cov, oct2024Impl)).toBe(true);
    // Far outside feb2026Current's grace zone → NO MATCH
    expect(matchesEra(cov, feb2026Current)).toBe(false);
  });

  it("accepts audits within 14-day grace of an era boundary", () => {
    // Audit 10 days before V1's intro — engagement likely predates the
    // public deploy.
    const cov = {
      audit_id: 7,
      match_type: "direct",
      impl_address: null,
      date: new Date((TS_NOV_2023 - 10 * 86400) * 1000).toISOString(),
    };
    expect(matchesEra(cov, IMPL_V1)).toBe(true);
  });

  it("rejects audits more than 14 days outside an era", () => {
    // Audit 20 days before V1's intro — too far to plausibly cover V1.
    const cov = {
      audit_id: 8,
      match_type: "direct",
      impl_address: null,
      date: new Date((TS_NOV_2023 - 20 * 86400) * 1000).toISOString(),
    };
    expect(matchesEra(cov, IMPL_V1)).toBe(false);
  });

  it("falls back to addrMatch when the audit has no date", () => {
    // Without a date we can't temporally place the audit; the only
    // signal is the backend's impl_address pin.
    const cov = {
      audit_id: 2,
      match_type: "impl_era",
      impl_address: IMPL_V2_CURRENT.address,
      date: null,
    };
    expect(matchesEra(cov, IMPL_V2_CURRENT)).toBe(true);
    expect(matchesEra(cov, IMPL_V1)).toBe(false);
  });

  it("uses block range when covered_from_block / covered_to_block are set", () => {
    const cov = {
      audit_id: 3,
      match_type: "direct",
      impl_address: null,
      covered_from_block: 18500000,
      covered_to_block: 18600000,
    };
    expect(matchesEra(cov, IMPL_V1)).toBe(true);
    expect(matchesEra(cov, IMPL_V2_CURRENT)).toBe(false);
  });

  it("returns false if neither address, block range, nor date resolves", () => {
    const cov = {
      audit_id: 4,
      match_type: "impl_era",
      impl_address: null,
      date: null,
      covered_from_block: null,
      covered_to_block: null,
    };
    expect(matchesEra(cov, IMPL_V1)).toBe(false);
    expect(matchesEra(cov, IMPL_V2_CURRENT)).toBe(false);
  });

  it("handles an open-ended current era (no block_replaced / timestamp_replaced)", () => {
    const cov = {
      audit_id: 5,
      match_type: "impl_era",
      impl_address: null,
      date: "2025-09-01",
      covered_from_block: null,
      covered_to_block: null,
    };
    expect(matchesEra(cov, IMPL_V2_CURRENT)).toBe(true);
    expect(matchesEra(cov, IMPL_V1)).toBe(false);
  });
});

describe("matchesEra: defensive handling", () => {
  it("returns false for an empty coverage row with no date or block range", () => {
    expect(matchesEra({}, IMPL_V1)).toBe(false);
  });

  it("returns false when cov is an empty coverage row and impl is null", () => {
    // No address match, no blocks, no date → cannot resolve to any era.
    expect(matchesEra({}, null)).toBe(false);
  });
});

// An ABSENT era bound is not a bound value: folding `block_introduced` to -Infinity
// and `block_replaced` to Infinity answered the hard block constraint "yes" from the
// absence of the data the constraint tests (L-26). A poll-detected impl publishes
// `block_introduced: null`.
describe("matchesEra: an undetermined era window cannot satisfy a block constraint", () => {
  const BOUNDED_COV = {
    match_type: "impl_era",
    match_confidence: "high",
    impl_address: "0x9999999999999999999999999999999999999999",
    covered_from_block: 18500000,
    covered_to_block: 18600000,
    date: "2023-12-01",
  };

  it("does not spread a bounded audit onto an era with no introduction block", () => {
    const pollIntroduced = {
      address: "0x3333333333333333333333333333333333333333",
      block_introduced: null,
      block_replaced: 19000000,
      // No timestamps either, so the temporal fall-through has nothing and the
      // only remaining signal is addrMatch — which is false here.
    };
    expect(matchesEra(BOUNDED_COV, pollIntroduced)).toBe(false);
  });

  it("does not spread a bounded audit onto an era whose successor block is unknown", () => {
    // `block_replaced` PRESENT and null: a successor exists whose block was never
    // determined, so the era's end is unknown rather than infinite.
    const unknownEnd = {
      address: "0x3333333333333333333333333333333333333333",
      block_introduced: 19500000,
      block_replaced: null,
    };
    expect(matchesEra(BOUNDED_COV, unknownEnd)).toBe(false);
  });

  it("still evaluates the constraint against a fully-bounded era", () => {
    // POSITIVE CONTROL: declining on every era would drop every block-bounded match.
    expect(matchesEra(BOUNDED_COV, IMPL_V1)).toBe(true);
    expect(matchesEra({ ...BOUNDED_COV, covered_from_block: 19100000, covered_to_block: 19200000 }, IMPL_V1)).toBe(false);
  });

  it("still treats a missing block_replaced KEY as the open-ended current era", () => {
    // POSITIVE CONTROL for the key-presence rule: the current impl's era really
    // does run to now, and requiring both bounds would drop its matches.
    const late = { ...BOUNDED_COV, covered_from_block: 19500000, covered_to_block: 19600000 };
    expect(matchesEra(late, IMPL_V2_CURRENT)).toBe(true);
  });
});

describe("matchesEra: the temporal branch applies the same rule to timestamps", () => {
  const DATED_COV = {
    match_type: "impl_era",
    match_confidence: "high",
    impl_address: "0x9999999999999999999999999999999999999999",
    date: "2023-12-01",
  };

  it("does not place an audit inside an era with no introduction timestamp", () => {
    const noStart = { address: "0x3333333333333333333333333333333333333333", timestamp_replaced: TS_FEB_2024 };
    expect(matchesEra(DATED_COV, noStart)).toBe(false);
  });

  it("does not place an audit inside an era whose successor timestamp is unknown", () => {
    const unknownEnd = {
      address: "0x3333333333333333333333333333333333333333",
      timestamp_introduced: TS_NOV_2023,
      timestamp_replaced: null,
    };
    expect(matchesEra(DATED_COV, unknownEnd)).toBe(false);
  });

  it("still places an audit in a bounded era and in the open-ended current one", () => {
    // POSITIVE CONTROLS: the grace-zone placement that drives every name-based
    // match must survive, including the current impl's key-absent open end.
    expect(matchesEra(DATED_COV, IMPL_V1)).toBe(true);
    expect(matchesEra({ ...DATED_COV, date: "2024-06-01" }, IMPL_V2_CURRENT)).toBe(true);
  });

  it("still falls back to addrMatch when the era carries nothing", () => {
    const bare = { address: "0x9999999999999999999999999999999999999999" };
    expect(matchesEra(DATED_COV, bare)).toBe(true);
    expect(matchesEra(DATED_COV, { address: "0x1111111111111111111111111111111111111111" })).toBe(false);
  });
});
