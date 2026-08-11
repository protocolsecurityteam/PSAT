import { describe, expect, it } from "vitest";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import {
  MISSING_WITNESS_CATEGORIES,
  assignPools,
  ceilingBearingEntities,
  confidenceZone,
  groupKey,
  isClosed,
  refusalCount,
  statusLines,
} from "./confidenceZone.js";
import { deductionRows } from "./derive.js";
import { ceilingText, pointsText } from "./format.js";

const ROWS = deductionRows(ETHERFI, { byEntity: new Map(), implToProxy: new Map() });
const ZONE = confidenceZone(ETHERFI, ROWS);
const LEVERS = ETHERFI.provenance.unresolved_levers.levers;

function lever(patch = {}) {
  return {
    capability: "authority.replace",
    principal: "EOA 0x1111111111111111111111111111111111111111",
    chain: "ethereum",
    points_ceiling: 1,
    ceiling_usd: 100,
    entities_total: 1,
    proof_frontier: "magnitude",
    by_basis: {
      reached_unwitnessed: {
        ceiling_usd: 100,
        entities: 1,
        entities_contributing: 1,
        entities_refused_by_reason: {},
        missing_witnesses: { reach_magnitude_not_witnessed: 1 },
        entities_itemized: [{ entity: "ethereum::0xaaa", ceiling_usd: 100, refusal: null }],
      },
    },
    ...patch,
  };
}

const docOf = (levers) => ({ provenance: { unresolved_levers: { levers } } });

describe("confidence zone — the missing-witness table", () => {
  it("carries every category, including the two this corpus never renders", () => {
    expect(MISSING_WITNESS_CATEGORIES.map((c) => c.id)).toEqual([
      "reachability",
      "magnitude",
      "value",
      "effect",
    ]);
    // The table is 1:1 — no token may sit under two categories, or a row's
    // label would depend on which category happened to be checked first.
    const tokens = MISSING_WITNESS_CATEGORIES.flatMap((c) => c.tokens);
    expect(new Set(tokens).size).toBe(tokens.length);
  });
});

describe("confidence zone — figures", () => {
  it("keeps the ≤ on every bound and never rounds a real ceiling to zero", () => {
    expect(ceilingText(2198979.34)).toBe("≤ $2.20M");
    expect(ceilingText(158998.41)).toBe("≤ $159k");
    expect(ceilingText(29548326.43)).toBe("≤ $29.5M");
    expect(ceilingText(585086302.95)).toBe("≤ $585.1M");
    // Sub-cent ceilings are measured figures, so they say so rather than
    // rounding into a $0 nobody proved.
    expect(ceilingText(0.000453)).toBe("< $0.01");
    expect(ceilingText(1.876e-15)).toBe("< $0.01");
    expect(ceilingText(null)).toBeNull();
  });

  it("trims trailing zeros only behind a decimal point", () => {
    expect(pointsText(20.25)).toBe("20.25");
    expect(pointsText(16.5)).toBe("16.5");
    expect(pointsText(8.4)).toBe("8.4");
    // A round hundred is a hundred, not a one.
    expect(pointsText(100)).toBe("100");
    expect(pointsText(0.0004)).toBe("0.0004");
    expect(pointsText(null)).toBeNull();
  });
});

describe("confidence zone — which question a row is about", () => {
  it("reads Reachability off the basis that carries the dollars", () => {
    // Lever 0: the money sits behind hops it could not establish; the reached
    // basis is a proven $0 and says nothing about the stake.
    const lines = statusLines(LEVERS[0]);
    expect(lines).toHaveLength(1);
    expect(lines[0].basis).toBe("behind_unestablished_hops");
    expect(lines[0].categoryId).toBe("reachability");
    expect(lines[0].ceilingUsd).toBe(2198979.34);
    expect(lines[0].entities).toBe(21);
  });

  it("reads Reach magnitude off the basis that carries the dollars", () => {
    const lines = statusLines(LEVERS[1]);
    expect(lines).toHaveLength(1);
    expect(lines[0].basis).toBe("reached_unwitnessed");
    expect(lines[0].categoryId).toBe("magnitude");
    expect(lines[0].entities).toBe(12);
  });

  it("renders both questions with their own figures when both bases carry money", () => {
    // Not in this corpus: every admitted row has exactly one basis holding the
    // dollars. The rule is that the two figures never merge, so the case is
    // built rather than waited for.
    const both = lever({
      ceiling_usd: 300,
      by_basis: {
        behind_unestablished_hops: {
          ceiling_usd: 200,
          entities: 4,
          entities_refused_by_reason: {},
          missing_witnesses: { gate_does_not_confer_this_scope: 4 },
          entities_itemized: [],
        },
        reached_unwitnessed: {
          ceiling_usd: 100,
          entities: 2,
          entities_refused_by_reason: {},
          missing_witnesses: { reach_magnitude_not_witnessed: 2 },
          entities_itemized: [],
        },
      },
    });
    const lines = statusLines(both);
    expect(lines.map((l) => [l.categoryId, l.ceilingUsd, l.entities])).toEqual([
      ["reachability", 200, 4],
      ["magnitude", 100, 2],
    ]);
  });

  it("prints nothing for the basis whose ceiling is a proven $0", () => {
    const zeroed = lever({
      by_basis: {
        ...lever().by_basis,
        behind_unestablished_hops: {
          ceiling_usd: 0,
          entities: 9,
          entities_refused_by_reason: {},
          missing_witnesses: { gate_does_not_confer_this_scope: 9 },
          entities_itemized: [],
        },
      },
    });
    expect(statusLines(zeroed).map((l) => l.basis)).toEqual(["reached_unwitnessed"]);
  });

  it("publishes an unrecognised token raw rather than guessing its category", () => {
    // Lever 11 (flow.out) carries token_identity_not_decidable, which no
    // category claims. The row still names its question; the stray token rides
    // along verbatim.
    const flow = LEVERS.find((l) => l.capability === "flow.out");
    const [line] = statusLines(flow);
    expect(line.categoryId).toBe("magnitude");
    expect(line.unknownTokens).toEqual([{ token: "token_identity_not_decidable", count: 1 }]);
  });

  it("leaves a basis it has no reading for uncategorised", () => {
    const strange = lever({
      by_basis: { some_future_basis: { ceiling_usd: 5, entities: 1, missing_witnesses: {} } },
    });
    expect(statusLines(strange)[0].categoryId).toBeNull();
  });
});

describe("confidence zone — refusals", () => {
  it("folds every refusal reason on the dollar-carrying bases into one count", () => {
    // Lever 5: 6 sheets with nothing observed and 1 unpriced, one consequence.
    expect(LEVERS[5].by_basis.reached_unwitnessed.entities_refused_by_reason).toEqual({
      no_rows: 6,
      unpriced: 1,
    });
    expect(refusalCount(LEVERS[5])).toBe(7);
  });

  it("counts no refusal off a basis holding none of the money", () => {
    const zeroBasis = lever({
      by_basis: {
        ...lever().by_basis,
        behind_unestablished_hops: {
          ceiling_usd: 0,
          entities: 3,
          entities_refused_by_reason: { unpriced: 3 },
          missing_witnesses: {},
          entities_itemized: [],
        },
      },
    });
    expect(refusalCount(zeroBasis)).toBe(0);
  });
});

describe("confidence zone — what closes a lever", () => {
  it("drops a lever whose act ranks benign", () => {
    const benign = lever();
    expect(isClosed(benign, { finding: { severity_proven: 0 } })).toBe(true);
    expect(isClosed(benign, { finding: { severity_proven: 0.25 } })).toBe(false);
  });

  it("drops a lever whose ceiling resolved to a proven $0", () => {
    expect(isClosed(lever({ ceiling_usd: 0 }), null)).toBe(true);
  });

  it("keeps a lever whose ceiling was never bounded", () => {
    expect(isClosed(lever({ ceiling_usd: null }), null)).toBe(false);
  });
});

describe("confidence zone — pools", () => {
  it("pools the three questions that reach one $2.20M pot, and counts the union", () => {
    const [a, b, c] = ZONE.rows;
    expect([a, b, c].map((r) => r.pool?.name)).toEqual(["A", "A", "A"]);
    expect(a.pool.contracts).toBe(23);
    // The union is bigger than any member's own set — the pool is the money
    // seen from three angles, not one angle counted three times.
    expect(ceilingBearingEntities(a.lever).size).toBe(21);
    expect(a.pool.ceilingUsd).toBe(2198979.34);
  });

  it("keeps the ≤ $29.5M question out of pool A, overlap or not", () => {
    const big = ZONE.rows.find((r) => r.lever.ceiling_usd === 29548326.43);
    const poolA = ZONE.rows[0];
    const shared = [...ceilingBearingEntities(big.lever)].filter((e) =>
      ceilingBearingEntities(poolA.lever).has(e),
    );
    // It overlaps pool A heavily and still does not join it: a different
    // ceiling is a different pot, and merging them would print one figure over
    // two sums.
    expect(shared.length).toBeGreaterThan(0);
    expect(big.pool).toBeNull();
  });

  it("pools the two base questions separately, as pool B", () => {
    const base = ZONE.rows.filter((r) => r.lever.chain === "base");
    expect(base.map((r) => r.pool?.name)).toEqual(["B", "B"]);
    expect(base[0].pool.contracts).toBe(7);
  });

  it("needs an overlap, not merely an equal ceiling", () => {
    const one = lever({ ceiling_usd: 100 });
    const other = lever({
      principal: "EOA 0x2222222222222222222222222222222222222222",
      ceiling_usd: 100,
      by_basis: {
        reached_unwitnessed: {
          ceiling_usd: 100,
          entities: 1,
          entities_refused_by_reason: {},
          missing_witnesses: { reach_magnitude_not_witnessed: 1 },
          entities_itemized: [{ entity: "ethereum::0xbbb", ceiling_usd: 100, refusal: null }],
        },
      },
    });
    const rows = [{ lever: one, pool: null }, { lever: other, pool: null }];
    assignPools(rows);
    expect(rows.map((r) => r.pool)).toEqual([null, null]);
  });

  it("needs the same chain", () => {
    const rows = [
      { lever: lever(), pool: null },
      { lever: lever({ chain: "base" }), pool: null },
    ];
    assignPools(rows);
    expect(rows.map((r) => r.pool)).toEqual([null, null]);
  });
});

describe("confidence zone — rows", () => {
  it("collapses the eight transfer_policy holders onto one key", () => {
    // Eight principals, one unanswered set: answering it answers all eight, so
    // the queue asks the question once and counts the holders.
    const transfer = LEVERS.filter((l) => l.capability === "transfer_policy.configure");
    expect(transfer).toHaveLength(8);
    expect(new Set(transfer.map(groupKey)).size).toBe(1);
  });

  it("splits levers whose by_basis differ, however alike they look", () => {
    const one = lever();
    const other = lever({
      principal: "EOA 0x2222222222222222222222222222222222222222",
      by_basis: {
        reached_unwitnessed: {
          ...lever().by_basis.reached_unwitnessed,
          entities_itemized: [{ entity: "ethereum::0xbbb", ceiling_usd: 100, refusal: null }],
        },
      },
    });
    expect(groupKey(one)).not.toBe(groupKey(other));
    const zone = confidenceZone(docOf([one, other]), []);
    expect(zone.rows).toHaveLength(2);
  });

  it("groups levers whose by_basis is byte-identical", () => {
    const one = lever();
    const other = lever({ principal: "EOA 0x2222222222222222222222222222222222222222" });
    const zone = confidenceZone(docOf([one, other]), []);
    expect(zone.rows).toHaveLength(1);
    expect(zone.rows[0].levers).toHaveLength(2);
    expect(zone.rows[0].controllers).toEqual([
      "0x1111111111111111111111111111111111111111",
      "0x2222222222222222222222222222222222222222",
    ]);
  });

  it("never merges two capabilities under one label", () => {
    const one = lever();
    const other = lever({ capability: "ownership.transfer" });
    expect(confidenceZone(docOf([one, other]), []).rows).toHaveLength(2);
  });

  it("counts the tail in levers, not in rows", () => {
    // 20 levers stay open; the visible six carry one lever each, so fourteen
    // questions remain — eight of them inside the single grouped row.
    expect(ZONE.open).toBe(20);
    expect(ZONE.rows).toHaveLength(6);
    expect(ZONE.remaining).toBe(14);
  });

  it("keeps the producer's arrival order", () => {
    expect(ZONE.rows.map((r) => r.lever.points_ceiling)).toEqual([
      20.25, 20.25, 16.5, 12.15, 9.9, 8.4,
    ]);
  });

  it("publishes nothing at all when the document carries no rollup", () => {
    const zone = confidenceZone({ provenance: {} }, ROWS);
    expect(zone.published).toBe(false);
    expect(zone.rows).toEqual([]);
  });

  it("joins each lever to the finding that carries its functions and targets", () => {
    for (const row of ZONE.rows) {
      expect(row.row).toBeTruthy();
      expect(row.row.finding.capability).toBe(row.lever.capability);
      expect(row.row.finding.principal).toBe(row.lever.principal);
    }
  });
});
