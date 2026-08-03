import { describe, it, expect } from "vitest";

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
