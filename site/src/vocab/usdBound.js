import { formatUsd } from "../surface/format.js";

// `holdings_coverage.unvalued_rows > 0`: the entry holds assets with no USD
// value, so its `total_usd` (and any sum including it) is a lower bound.
export function usdIsLowerBound(entry) {
  return Number(entry?.holdings_coverage?.unvalued_rows) > 0;
}

// `formatUsd` with the lower-bound mark. Null where `formatUsd` is.
export function formatUsdTotal(value, lowerBound) {
  const text = formatUsd(value);
  if (!text) return null;
  return lowerBound ? `≥ ${text}` : text;
}
