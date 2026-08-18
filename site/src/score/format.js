// Formatters for the score page. Separate from surface/format.js because the
// score page needs three significant figures on the dollar totals (the audit
// block sets $4.08B against $4.17B — one decimal collapses both to $4.1B).

export function shortAddress(address) {
  const value = String(address || "");
  if (value.length < 12) return value;
  return `${value.slice(0, 6)}…${value.slice(-4)}`;
}

export function usdCompact(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const abs = Math.abs(value);
  if (abs >= 1e9) return `$${(value / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `$${(value / 1e6).toFixed(2)}M`;
  if (abs >= 1e3) return `$${(value / 1e3).toFixed(1)}K`;
  return `$${value.toFixed(0)}`;
}

// The confidence zone's own dollar formatter, apart from usdCompact because an
// at-most is read against its neighbours: the zone puts $2.20M, $29.5M and $159k
// in one column, where usdCompact's fixed two-decimal step prints $159.0K and
// $29.55M — more digits than the bound has meaning for. Sub-cent figures are
// real ceilings the producer measured, so they print as "< $0.01" rather than
// rounding to a zero nobody proved.
function usdCeiling(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value === 0) return "$0.00";
  if (value < 0.01) return "< $0.01";
  if (value < 1e3) return `$${value.toFixed(2)}`;
  if (value < 1e6) return `$${(value / 1e3).toFixed(value < 1e4 ? 1 : 0)}k`;
  if (value < 1e9) return `$${(value / 1e6).toFixed(value < 1e7 ? 2 : 1)}M`;
  return `$${(value / 1e9).toFixed(2)}B`;
}

// An at-most, never an amount: the ≤ is part of the figure and travels with it.
export function ceilingText(value) {
  const figure = usdCeiling(value);
  if (figure === null) return null;
  return figure.startsWith("<") ? figure : `≤ ${figure}`;
}

// Trailing zeros come off so "up to 16.50" reads as 16.5, but only after a
// decimal point — a bare 100 must not be stripped to 1.
export function pointsText(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value === 0) return "0";
  const trim = (text) => (text.includes(".") ? text.replace(/0+$/, "").replace(/\.$/, "") : text);
  const two = trim(value.toFixed(2));
  return two === "0" ? trim(value.toFixed(4)) : two;
}

// Percent of a total. null — never 0 — when either side is unwitnessed, so an
// unmeasured share can't render as a measured zero.
export function pctOf(part, total) {
  if (typeof part !== "number" || !Number.isFinite(part)) return null;
  if (typeof total !== "number" || !Number.isFinite(total) || total <= 0) return null;
  return (part / total) * 100;
}

const COUNT_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];

export function countWord(n) {
  return COUNT_WORDS[n] || String(n);
}

export function splitEntity(entity) {
  const value = String(entity || "");
  const at = value.indexOf("::");
  if (at < 0) return { chain: "ethereum", address: value.toLowerCase() };
  return { chain: value.slice(0, at).toLowerCase(), address: value.slice(at + 2).toLowerCase() };
}
