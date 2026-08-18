// The scorer's grade fold, re-implemented on the published document so the
// page can answer counterfactuals ("what if this finding were gone / this
// safe were an EOA") without asking the backend to score a hypothetical.
//
// λ = 100 − Σ raw_i × 0.6^rank_i, rank by raw_points descending. Each term is
// rounded to 4dp before summing, which is what the producer publishes as
// `net_points_lambda` and what its own λ is the sum of — see the pin in
// fold.test.js reconstructing the etherfi λ exactly.
//
// Nets are NEVER summed to model a change: rank decay means removing a finding
// promotes every finding below it, so the recovered points always exceed the
// removed nets. Every counterfactual here re-ranks and re-folds.

const DECAY = 0.6;

export function round4(value) {
  return Math.round(value * 1e4) / 1e4;
}

// A finding whose raw_points is absent or non-numeric has an unwitnessed
// charge, not a zero one — and `Number(null)` is 0, so coercing here would
// publish a proven zero the document never proved (and sink the row to last
// rank, moving every net below it). null instead, and the fold refuses.
function rawOf(finding) {
  const raw = finding?.raw_points;
  return typeof raw === "number" && Number.isFinite(raw) ? raw : null;
}

// Rank order: raw descending, ties broken by position in the document so the
// ordering is total and reproducible. An unwitnessed raw has no place in that
// order; it sorts last so the list stays renderable, and every net goes null.
function rankOrder(raws) {
  return raws
    .map((raw, index) => ({ raw, index }))
    .sort((a, b) => {
      if (a.raw === null || b.raw === null) {
        if (a.raw === b.raw) return a.index - b.index;
        return a.raw === null ? 1 : -1;
      }
      return b.raw - a.raw || a.index - b.index;
    });
}

function reconstructable(raws) {
  return raws.every((raw) => raw !== null);
}

// null — never a number — when any raw in the population is unwitnessed: one
// missing term makes both the sum and the rank order of every other term
// unproven, so there is no λ to publish.
export function foldLambda(raws) {
  if (!reconstructable(raws)) return null;
  let charged = 0;
  rankOrder(raws).forEach((entry, rank) => {
    charged += round4(entry.raw * Math.pow(DECAY, rank));
  });
  return round4(100 - charged);
}

// [{ index, rank, raw, net }] in rank order — the order the ledger, the
// deduction list and the callout grouping all walk. `raw`/`net` are null where
// the reconstruction refused; callers render those not-determined.
export function rankedFindings(findings) {
  const raws = (findings || []).map(rawOf);
  const ok = reconstructable(raws);
  return rankOrder(raws).map((entry, rank) => ({
    index: entry.index,
    rank,
    raw: entry.raw,
    net: ok ? round4(entry.raw * Math.pow(DECAY, rank)) : null,
  }));
}

export function lambdaOf(findings) {
  return foldLambda((findings || []).map(rawOf));
}

// λ with `dropIndices` removed from the population and everything below them
// promoted a rank.
export function lambdaWithout(findings, dropIndices) {
  const drop = new Set(dropIndices);
  return foldLambda((findings || []).filter((_, i) => !drop.has(i)).map(rawOf));
}

// Modeled recovery from fixing a group: the λ the protocol would hold if those
// findings did not exist, minus the λ it holds now.
export function recoveryFrom(findings, dropIndices) {
  const before = lambdaOf(findings);
  const after = lambdaWithout(findings, dropIndices);
  if (before === null || after === null) return { before, after, recovery: null };
  return { before, after, recovery: round4(after - before) };
}

// λ if this finding's principal were as weak as an unconditional one. raw scales
// linearly in weakness, so raw(w=1) = raw / weakness. A finding with no positive
// weakness has no modeled protection to remove — null, not zero.
export function lambdaAtWeaknessOne(findings, index) {
  const finding = (findings || [])[index];
  const weakness = Number(finding?.weakness);
  if (!Number.isFinite(weakness) || weakness <= 0 || weakness >= 1) return null;
  const own = rawOf(finding);
  if (own === null) return null;
  const raws = findings.map(rawOf);
  raws[index] = own / weakness;
  return foldLambda(raws);
}

// Points of λ this finding's principal strength is modeled to be saving.
// null when the finding carries no credited strength.
export function protectionDelta(findings, index) {
  const weakened = lambdaAtWeaknessOne(findings, index);
  const current = lambdaOf(findings);
  if (weakened === null || current === null) return null;
  return round4(current - weakened);
}
