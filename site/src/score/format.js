// Score-page formatters: three significant figures, since $4.08B vs $4.17B
// collapse to $4.1B at one decimal.

import { middleSlice } from "../shared/format.js";

export function shortAddress(address) {
  const value = String(address || "");
  if (value.length < 12) return value;
  return middleSlice(value, "…");
}

export function usdCompact(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const abs = Math.abs(value);
  if (abs >= 1e9) return `$${(value / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `$${(value / 1e6).toFixed(2)}M`;
  if (abs >= 1e3) return `$${(value / 1e3).toFixed(1)}K`;
  return `$${value.toFixed(0)}`;
}

// At-mosts are read against neighbours, so fewer digits than usdCompact.
// Sub-cent ceilings print "< $0.01", not a zero nobody proved.
function usdCeiling(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value === 0) return "$0.00";
  if (value < 0.01) return "< $0.01";
  if (value < 1e3) return `$${value.toFixed(2)}`;
  if (value < 1e6) return `$${(value / 1e3).toFixed(value < 1e4 ? 1 : 0)}k`;
  if (value < 1e9) return `$${(value / 1e6).toFixed(value < 1e7 ? 2 : 1)}M`;
  return `$${(value / 1e9).toFixed(2)}B`;
}

export function ceilingText(value) {
  const figure = usdCeiling(value);
  if (figure === null) return null;
  return figure.startsWith("<") ? figure : `≤ ${figure}`;
}

// Only after a decimal point: 100 must not become 1.
export function pointsText(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value === 0) return "0";
  const trim = (text) => (text.includes(".") ? text.replace(/0+$/, "").replace(/\.$/, "") : text);
  const two = trim(value.toFixed(2));
  return two === "0" ? trim(value.toFixed(4)) : two;
}

// null, never 0, when either side is unwitnessed.
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
