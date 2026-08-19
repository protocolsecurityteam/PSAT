// Middle-truncation core shared by the three address shorteners. The three
// call sites keep their historical guard/fallback/joiner semantics (they are
// NOT interchangeable — "..." vs ".." vs "…", "Unknown" vs "" fallbacks), but
// the slice geometry lives here once.
export function middleSlice(value, joiner) {
  return `${value.slice(0, 6)}${joiner}${value.slice(-4)}`;
}

export function shortenAddress(value) {
  if (!value || typeof value !== "string" || !value.startsWith("0x") || value.length < 12) {
    return value || "Unknown";
  }
  return middleSlice(value, "...");
}
