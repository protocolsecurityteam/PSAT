// Letter bands for the published λ, keyed by the model version that produced
// it. A band table is a calibration against one model's arithmetic: reading λ
// from model 1.0.2 through 1.0.1's cut points would publish a letter nobody
// calibrated. An unknown version therefore gets NO letter — λ is shown bare
// and labelled uncalibrated, which is the not_determined state for the letter.

const LETTER_CUTS = [
  ["A", 88],
  ["A−", 80],
  ["B+", 72],
  ["B", 64],
  ["B−", 56],
  ["C+", 48],
  ["C", 40],
  ["D", 30],
  ["F", -Infinity],
];

// 1.1.0-provisional carries 1.0.1's cut points forward DELIBERATELY, and the
// reasoning is the calibration — a copy with no argument would be the silent
// re-use this file exists to prevent.
//
// What moved. 1.1.0 stops charging a finding the reached entity's whole balance
// sheet when no witness proved how much the reach moves: those rows drop from a
// value band of 0.5–1.0 to the unpriced floor of 0.15, so λ RISES without any
// protocol becoming safer. Measured on the only local protocol (etherfi,
// protocol 1): λ 55.009 → 84.017, which crosses C+ → A− under these cuts.
//
// Why the cuts do not move with it.
//   1. Moving them would fit the table to ONE protocol's λ. That is the same
//      objection that keeps every constant in this model marked provisional, and
//      a nine-band table fitted to a single point is not a calibration.
//   2. The λ shift is transient BY DESIGN. It is the conservative half of a
//      matched pair: this version floors an unwitnessed magnitude, and the
//      composition pass that follows restores a WITNESSED magnitude to the
//      gate-control class and pushes λ back down. Cut points fitted to the gap
//      between them would be recalibrated again immediately, and in the interim
//      they would hide the very movement they were fitted to.
//   3. The letter is not the only published number. The confidence axis is
//      first-class output and it falls as λ rises — the unproven magnitude moves
//      OUT of the grade and INTO the reach-magnitude confidence term. A reader
//      seeing A− beside a confidence in the teens is being told exactly what
//      happened; a table quietly re-cut to hold the letter at C+ would tell them
//      nothing and would assert a calibration nobody performed.
//
// So the letter delta is published as a migration fact rather than absorbed.
const BANDS = {
  "1.0.1-provisional": LETTER_CUTS,
  "1.1.0-provisional": LETTER_CUTS,
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
