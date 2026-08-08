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
// protocol becoming safer. Its composition pass then gives part of that class a
// WITNESSED magnitude back — the destination function's own flow.out figure,
// reached along a path every hop of which carries an act-as witness — and λ
// falls again on witnesses rather than on sheets. Measured across the VERSION
// BOUNDARY — the last published 1.0.1 document against the first 1.1.0 one, on
// the only local protocol (etherfi, protocol 1), with the intermediate figure
// shown because the two halves move λ in opposite directions:
//
//     λ           54.1614 → 84.0166 (floored) → 73.2508    letter C+ → A− → B+
//     confidence     29.0 → 18.6
//     exposure_usd  $1,227,107,593.64 → $76.07 → $18,059,003.86
//
// Three facts a reader needs before treating that confidence drop as the price
// paid for the letter, because it is not:
//   (a) the reach-magnitude term does NOT bind the headline here. min() is
//       taken on value_priced_pct 18.6; the magnitude term sits at 37.6, a
//       clear 19.0pp above it. The new term is real but it is not what the
//       published confidence is reporting.
//   (b) the strictest figure this model publishes about magnitude —
//       reach_magnitude_witnessed_of_reaching_pct — WOULD bind if it were the
//       term, and composition is the only thing that moves it: flooring an
//       unwitnessed magnitude mints no witness. It went 15.3 → 25.6, on the 40
//       signals composition answered and on nothing else.
//   (c) the 29.0 → 18.6 fall happened WITHIN 1.0.1, in the binding
//       value_priced term — the dust third state plus a discovery-fixed
//       perimeter that widened 295 → 468 entities by admitting signer wallets,
//       so confidence now answers "what share of {protocol contracts ∪ signer
//       wallets} did we price" — not in the magnitude term and not from this
//       change. The letter improvement and the confidence fall are both real
//       and both published; they are not a trade this change made.
//
// Why the cuts do not move with it.
//   1. Moving them would fit the table to ONE protocol's λ. That is the same
//      objection that keeps every constant in this model marked provisional, and
//      a nine-band table fitted to a single point is not a calibration.
//   2. The λ shift is a matched pair and only one half of it has settled. This
//      version floors an unwitnessed magnitude (λ 84.0166) and its composition
//      pass restores a witnessed one (λ 73.2508) — but composition recovers
//      only where all three witnesses exist, and on this corpus that is 13
//      entities out of a gate-control class of dozens. Every act-as witness the
//      pipeline learns to produce moves λ down again from here. Cut points
//      fitted to a mid-recovery λ would be recalibrated on the next one, and in
//      the interim they would hide the very movement they were fitted to.
//   3. The letter is not the only published number, and the grade's own
//      coverage travels beside it: provenance.exposure_coverage says how many
//      findings the exposure ratio was measured over, so an A− standing on a
//      numerator summed from a handful of rows cannot be read as "measured
//      safe". A table quietly re-cut to hold the letter at C+ would assert a
//      calibration nobody performed and would hide that coverage question
//      behind a familiar-looking letter.
//
// So the letter delta is published as a migration fact rather than absorbed.
//
// ---------------------------------------------------------------------------
//
// 1.2.0-provisional carries the same cut points forward AGAIN — and this time
// carrying them forward is what publishes a letter DROP rather than what
// preserves one. That direction is the argument's own test: a table that is
// only ever re-cut when the letter would fall is not a calibration, it is a
// ratchet, and 1.1.0's three reasons would be worth nothing if they only ever
// got applied when they were free.
//
// What moved. 1.2.0 gives code control the magnitude it never had. "Which
// function does replacing the whole implementation let you call?" has no
// answer — the answer is all of them, including ones that do not exist yet — so
// 1.1.0 left every upgrade.implementation, exec.arbitrary and
// delegatecall.execute row at the unpriced floor. The row holding
// upgrade.implementation over a $3,622,582,124.76 proxy scored 0.9504 while a
// $90.06 withdrawal scored 7.29. (That proxy is the LARGEST of the eight priced
// hosts that row reaches; the row's own published total is their sum,
// $4,217,100,556.98, which is the figure the migration record quotes.) The
// answer that needs no further witness is
// the controlled node's OWN priced sheet: replacing what that node does removes
// the one thing that stood between the principal and its holdings. It is
// published as a proven CEILING — an at-most, never an amount — only at the
// node the code control is over, and only where a balance was actually
// observed and priced. Measured across the version boundary, again on the only
// local protocol (etherfi, protocol 1):
//
//     λ             73.2508 → 71.7053         letter B+ → B
//     confidence       18.6 → 18.6            (its magnitude term 37.6 → 40.9)
//     exposure_usd  $18,059,003.86 → $18,059,003.86
//
// Why the cuts do not move with it either. The 1.1.0 reasons above are not
// simply re-asserted; each has a different force here:
//   1. Fitting to one protocol is now WORSE, not better. 1.1.0's objection was
//      that a nine-band table cut against a single λ is not a calibration. The
//      only way to preserve B+ here is to move the 72.0 floor below 71.7053 —
//      a cut point chosen by reading this one protocol's λ after the fact, and
//      by 0.2947 of a point. That is reason 1 with the sign flipped, and it is
//      the most direct form of the thing this file exists to prevent.
//   2. Nothing a band table is calibrated AGAINST changed. 1.1.0 changed what
//      counts as a witnessed magnitude and did not earn a recut; 1.2.0 changes
//      strictly less. BASE_SEVERITY, the weakness ladder, VALUE_BANDS' own cut
//      points and the λ discount are untouched, and raw_points is the same
//      product it was. What changed is that one class of finding now HAS a
//      magnitude to band, so it enters arithmetic the table was already cut
//      for. Re-cutting the letters because more findings can be priced would
//      fit the table to the pipeline's coverage rather than to the model.
//   3. The half-settled objection applies here too, and points the same way. A
//      ceiling lands only where a balance was observed: on this corpus 49
//      code-control calls were refused one, 36 of them because no balance has
//      ever been recorded at that node. That is an observation gap the pipeline
//      is expected to close, and every balance it learns to see moves λ down
//      again from here. Cut points fitted to today's observation coverage would
//      be recalibrated on the next one — and in the interim they would hide the
//      movement they were fitted to.
//
// One thing to read with the drop, because the letter alone will mislead:
// nothing at etherfi got worse between these two documents. The same timelock
// behind the same 6-of-10 multisig holds the same capability over the same
// proxy. What changed is that the tool can now see how much is behind that
// door. A model that could not see it would publish B+ for a protocol whose
// upgrade key was a single EOA, which is the defect this version corrects.
//
// So, again: the letter delta is published as a migration fact rather than
// absorbed.
const BANDS = {
  "1.0.1-provisional": LETTER_CUTS,
  "1.1.0-provisional": LETTER_CUTS,
  "1.2.0-provisional": LETTER_CUTS,
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
