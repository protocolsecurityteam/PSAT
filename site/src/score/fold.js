// The scorer's grade fold, re-implemented so the page can answer
// counterfactuals without the backend.
//
// λ = 100 − Σ raw_i × 0.6^rank_i, ranked by raw_points descending, each term
// rounded to 4dp (the published `net_points_lambda`; fold.test.js pins
// etherfi's λ).
//
// Nets are never summed to model a change: removing a finding promotes
// everything below it. Every counterfactual re-ranks and re-folds.

const DECAY = 0.6;

export function round4(value) {
  return Math.round(value * 1e4) / 1e4;
}

// Unwitnessed, not zero: `Number(null)` is 0, which would publish a proven zero
// and re-rank everything.
function rawOf(finding) {
  const raw = finding?.raw_points;
  return typeof raw === "number" && Number.isFinite(raw) ? raw : null;
}

// Raw descending, ties by document position. Unwitnessed raws sort last and
// every net goes null.
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

// One missing term makes the sum and every rank unproven, so null.
export function foldLambda(raws) {
  if (!reconstructable(raws)) return null;
  let charged = 0;
  rankOrder(raws).forEach((entry, rank) => {
    charged += round4(entry.raw * Math.pow(DECAY, rank));
  });
  return round4(100 - charged);
}

// `raw`/`net` are null where the reconstruction refused.
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

export function lambdaWithout(findings, dropIndices) {
  const drop = new Set(dropIndices);
  return foldLambda((findings || []).filter((_, i) => !drop.has(i)).map(rawOf));
}

export function recoveryFrom(findings, dropIndices) {
  const before = lambdaOf(findings);
  const after = lambdaWithout(findings, dropIndices);
  if (before === null || after === null) return { before, after, recovery: null };
  return { before, after, recovery: round4(after - before) };
}

// raw scales linearly in weakness, so raw(w=1) = raw / weakness. No positive
// weakness means null, not zero.
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

export function protectionDelta(findings, index) {
  const weakened = lambdaAtWeaknessOne(findings, index);
  const current = lambdaOf(findings);
  if (weakened === null || current === null) return null;
  return round4(current - weakened);
}
