import { describe, it, expect } from "vitest";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import {
  foldLambda,
  lambdaAtWeaknessOne,
  lambdaOf,
  lambdaWithout,
  protectionDelta,
  rankedFindings,
  recoveryFrom,
} from "./fold.js";

const FINDINGS = ETHERFI.findings;

describe("fold — reconstruction of the published grade", () => {
  it("reproduces the document's λ to 4dp", () => {
    // The pin that makes every counterfactual on this page trustworthy: if the
    // fold drifts from the producer's, the modeled recoveries are fiction.
    expect(lambdaOf(FINDINGS)).toBe(78.5611);
    expect(lambdaOf(FINDINGS)).toBe(ETHERFI.grade_lambda);
  });

  it("reproduces every published net_points_lambda", () => {
    for (const row of rankedFindings(FINDINGS)) {
      expect(row.net, `finding ${row.index}`).toBe(FINDINGS[row.index].net_points_lambda);
    }
  });

  it("ranks by raw points descending, ties by document order", () => {
    const ranked = rankedFindings(FINDINGS);
    expect(ranked.map((r) => r.index).slice(0, 5)).toEqual([0, 1, 2, 3, 4]);
    expect(ranked[0].raw).toBe(10.5);
    expect(ranked[1].raw).toBe(8.4);
    expect(ranked[1].net).toBe(5.04);
  });

  it("folds an empty population to a clean 100", () => {
    expect(foldLambda([])).toBe(100);
  });
});

describe("fold — an unwitnessed raw refuses the reconstruction", () => {
  const BLANK = [{ raw_points: 20 }, { raw_points: null }];

  it("never reads an absent raw_points as a proven zero", () => {
    // Number(null) is 0: coercing here would publish a λ of 80 built on a
    // charge nobody witnessed, and rank the blank row dead last as if it were
    // the cheapest finding in the protocol.
    expect(lambdaOf(BLANK)).toBeNull();
    expect(lambdaOf(BLANK)).not.toBe(80);
    expect(lambdaOf([{ raw_points: 20 }, {}])).toBeNull();
    expect(foldLambda([20, null])).toBeNull();
  });

  it("refuses every counterfactual built on the same population", () => {
    expect(lambdaWithout(BLANK, [0])).toBeNull();
    expect(recoveryFrom(BLANK, [0])).toEqual({ before: null, after: null, recovery: null });
    expect(lambdaAtWeaknessOne([{ raw_points: null, weakness: 0.5 }], 0)).toBeNull();
    expect(protectionDelta([{ raw_points: null, weakness: 0.5 }], 0)).toBeNull();
    // …and stays refused when the blank row is somebody else's.
    expect(protectionDelta([{ raw_points: 10, weakness: 0.5 }, { raw_points: null }], 0)).toBeNull();
  });

  it("marks every net not-determined rather than publishing a partial fold", () => {
    const ranked = rankedFindings(BLANK);
    expect(ranked.map((r) => r.index)).toEqual([0, 1]); // the blank sorts last
    expect(ranked.map((r) => r.raw)).toEqual([20, null]);
    expect(ranked.map((r) => r.net)).toEqual([null, null]);
  });

  it("still folds a genuine zero, which is a witnessed charge", () => {
    expect(lambdaOf([{ raw_points: 10 }, { raw_points: 0 }])).toBe(90);
  });
});

describe("fold — counterfactuals", () => {
  it("recovers more than the removed nets, because rank decay promotes survivors", () => {
    const { before, after, recovery } = recoveryFrom(FINDINGS, [0, 1]);
    expect(before).toBe(78.5611);
    expect(after).toBe(83.6141);
    expect(recovery).toBe(5.053);
    // The nets of the two removed rows sum to 15.54 — the naive answer, and the
    // wrong one by more than 10 points in the other direction.
    const naive = FINDINGS[0].net_points_lambda + FINDINGS[1].net_points_lambda;
    expect(naive).toBe(15.54);
    expect(recovery).toBeLessThan(naive);
    expect(lambdaWithout(FINDINGS, [0, 1])).toBe(after);
  });

  it("prices each credited principal's strength as a λ delta", () => {
    // Pinned against the approved prototype's protection column.
    expect(protectionDelta(FINDINGS, 0)).toBe(19.5);
    expect(protectionDelta(FINDINGS, 1)).toBe(32.76);
    expect(protectionDelta(FINDINGS, 8)).toBe(1.0192);
    expect(protectionDelta(FINDINGS, 9)).toBe(1.0192);
  });

  it("re-ranks the weakened finding rather than scaling its net in place", () => {
    // finding 9 is rank 9 today; at weakness 1.0 its raw rises from 4.95 to 9
    // and it takes a rank above eight of the rows now ahead of it. Scaling its
    // own net in place would have moved λ by four hundredths of a point — its
    // net is 0.0499 — against the 1.0192 the re-rank actually costs.
    expect(lambdaAtWeaknessOne(FINDINGS, 9)).toBe(77.5419);
    expect(rankedFindings(FINDINGS)[9].index).toBe(9);
  });

  it("has no protection delta to report for an already-unconditional principal", () => {
    // weakness 1.0 is "anyone": there is no credited strength to remove, so
    // both counterfactuals refuse rather than returning the unchanged λ.
    expect(FINDINGS[26].weakness).toBe(1.0);
    expect(lambdaAtWeaknessOne(FINDINGS, 26)).toBeNull();
    expect(protectionDelta(FINDINGS, 26)).toBeNull();
    expect(protectionDelta([{ raw_points: 1 }], 0)).toBeNull();
  });
});
