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
    expect(lambdaOf(FINDINGS)).toBe(54.7638);
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
    expect(ranked[0].raw).toBe(20.25);
    expect(ranked[1].raw).toBe(20.25);
    expect(ranked[1].net).toBe(12.15);
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
    expect(before).toBe(54.7638);
    expect(after).toBe(64.3437);
    expect(recovery).toBe(9.5799);
    // The nets of the two removed rows sum to 32.4 — the naive answer, and the
    // wrong one by more than 22 points in the other direction.
    const naive = FINDINGS[0].net_points_lambda + FINDINGS[1].net_points_lambda;
    expect(naive).toBe(32.4);
    expect(recovery).toBeLessThan(naive);
    expect(lambdaWithout(FINDINGS, [0, 1])).toBe(after);
  });

  it("prices each credited principal's strength as a λ delta", () => {
    // Pinned against the approved prototype's protection column.
    expect(protectionDelta(FINDINGS, 7)).toBe(41.8457);
    expect(protectionDelta(FINDINGS, 4)).toBe(23.3333);
    expect(protectionDelta(FINDINGS, 2)).toBe(11.1);
    expect(protectionDelta(FINDINGS, 3)).toBe(11.1);
  });

  it("re-ranks the weakened finding rather than scaling its net in place", () => {
    // finding 7 is rank 7 today; at weakness 1.0 its raw is 60 and it takes
    // rank 0. Scaling its own net would have moved λ by 1.5 points.
    expect(lambdaAtWeaknessOne(FINDINGS, 7)).toBe(12.9181);
    expect(rankedFindings(FINDINGS)[7].index).toBe(7);
  });

  it("has no protection delta to report for an already-unconditional principal", () => {
    // weakness 1.0 (anyone) and weakness 0.9 (EOA above the ceiling) still
    // return a number only when there is credited strength to remove.
    expect(lambdaAtWeaknessOne(FINDINGS, 10)).toBeNull();
    expect(protectionDelta(FINDINGS, 10)).toBeNull();
    expect(protectionDelta([{ raw_points: 1 }], 0)).toBeNull();
  });
});
