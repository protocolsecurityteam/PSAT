// Letter bands for the published λ, keyed by the model version that produced
// it. A band table is a calibration against one model's arithmetic: reading λ
// from model 1.0.2 through 1.0.1's cut points would publish a letter nobody
// calibrated. An unknown version therefore gets NO letter — λ is shown bare
// and labelled uncalibrated, which is the not_determined state for the letter.

const BANDS = {
  "1.0.1-provisional": [
    ["A", 88],
    ["A−", 80],
    ["B+", 72],
    ["B", 64],
    ["B−", 56],
    ["C+", 48],
    ["C", 40],
    ["D", 30],
    ["F", -Infinity],
  ],
};

export function bandsFor(modelVersion) {
  return BANDS[modelVersion] || null;
}

// Tone class suffix — the letter's family, so A and A− share a colour.
export function toneForLetter(letter) {
  const head = String(letter || "").charAt(0).toLowerCase();
  return ["a", "b", "c", "d", "f"].includes(head) ? head : "";
}

// { letter, tone, calibrated }. `calibrated: false` means this model version
// has no band table: the caller must render λ with no letter and say so.
export function letterFor(modelVersion, lambda) {
  const bands = bandsFor(modelVersion);
  if (!bands) return { letter: null, tone: "", calibrated: false };
  if (typeof lambda !== "number" || !Number.isFinite(lambda)) {
    return { letter: null, tone: "", calibrated: true };
  }
  for (const [letter, floor] of bands) {
    if (lambda >= floor) return { letter, tone: toneForLetter(letter), calibrated: true };
  }
  return { letter: null, tone: "", calibrated: true };
}
