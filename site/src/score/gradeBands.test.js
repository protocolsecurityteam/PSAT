import { describe, it, expect } from "vitest";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import { bandsFor, letterFor, toneForLetter } from "./gradeBands.js";

const MODEL = "1.0.1-provisional";

describe("gradeBands — letter from λ, keyed by model version", () => {
  it("maps every band's floor and the value just under it", () => {
    const cases = [
      [100, "A"],
      [88, "A"],
      [87.99, "A−"],
      [80, "A−"],
      [79.99, "B+"],
      [72, "B+"],
      [71.99, "B"],
      [64, "B"],
      [63.99, "B−"],
      [56, "B−"],
      [55.99, "C+"],
      [48, "C+"],
      [47.99, "C"],
      [40, "C"],
      [39.99, "D"],
      [30, "D"],
      [29.99, "F"],
      [0, "F"],
    ];
    for (const [lambda, letter] of cases) {
      expect(letterFor(MODEL, lambda).letter, `λ=${lambda}`).toBe(letter);
    }
  });

  it("puts the published etherfi λ in C+", () => {
    expect(letterFor(MODEL, 54.7638)).toEqual({ letter: "C+", tone: "c", calibrated: true });
  });

  it("carries a table for the current model version, so the letter renders", () => {
    // The band table is keyed by model_version and an unknown version gets NO
    // letter by design, so a version bump with no entry here silently strips
    // the published letter. This asserts the current version has one — and it
    // reads that version off the GOLDEN rather than naming a literal, because a
    // literal is exactly what goes stale at the bump this test exists to catch.
    expect(bandsFor(ETHERFI.model_version)).not.toBeNull();
    expect(letterFor(ETHERFI.model_version, ETHERFI.grade_lambda).calibrated).toBe(true);
    expect(letterFor(ETHERFI.model_version, ETHERFI.grade_lambda).letter).not.toBeNull();
  });

  it("prices 1.1.0 λ on 1.0.1's cut points, and says what that moved", () => {
    // The reasoned carry-forward: same cuts, so the same λ reads the same
    // letter, and the etherfi λ movement (55.009 -> 73.251) is published as a
    // C+ -> B+ migration rather than absorbed by re-cutting the table. 84.017
    // is the intermediate — magnitudes floored, none composed back yet — and it
    // reads A−, which is why the two halves are pinned separately.
    expect(letterFor("1.1.0-provisional", 55.009).letter).toBe("C+");
    expect(letterFor("1.1.0-provisional", 84.017).letter).toBe("A−");
    expect(letterFor("1.1.0-provisional", 73.251).letter).toBe("B+");
    expect(bandsFor("1.1.0-provisional")).toEqual(bandsFor(MODEL));
  });

  it("prices 1.2.0 λ on the same cut points, and lets the letter FALL", () => {
    // The carry-forward reasoned a second time, in the direction that tests it.
    // 1.2.0 gives code control a magnitude, λ falls 73.2508 -> 71.7053, and
    // 71.7053 is under the 72.0 B+ floor by 0.2947 — so the published letter
    // honestly drops B+ -> B rather than being held up by a recut nobody
    // calibrated. Both λ read against the SAME table is the whole claim.
    expect(bandsFor("1.2.0-provisional")).toEqual(bandsFor("1.1.0-provisional"));
    expect(letterFor("1.2.0-provisional", 73.2508).letter).toBe("B+");
    expect(letterFor("1.2.0-provisional", 71.7053).letter).toBe("B");
    // The published document lands on the B side of that boundary.
    expect(ETHERFI.model_version).toBe("1.2.0-provisional");
    expect(letterFor(ETHERFI.model_version, ETHERFI.grade_lambda)).toEqual({
      letter: "B",
      tone: "b",
      calibrated: true,
    });
  });

  it("withholds the letter for a model version with no band table", () => {
    const result = letterFor("2.0.0-experimental", 54.7638);
    expect(result.letter).toBeNull();
    expect(result.calibrated).toBe(false);
    expect(bandsFor("2.0.0-experimental")).toBeNull();
  });

  it("withholds the letter when λ itself is not a number", () => {
    // The withheld-grade state carries grade_lambda: null. A band lookup on
    // null must not fall through to F — that would publish a grade nobody
    // computed.
    expect(letterFor(MODEL, null).letter).toBeNull();
    expect(letterFor(MODEL, null).calibrated).toBe(true);
  });

  it("shares a tone across a letter family", () => {
    expect(toneForLetter("A−")).toBe("a");
    expect(toneForLetter("B+")).toBe("b");
    expect(toneForLetter("")).toBe("");
  });
});
