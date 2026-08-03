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
