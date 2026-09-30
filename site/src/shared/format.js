// Slice geometry shared by the three address shorteners; their guards,
// fallbacks and joiners differ on purpose.
export function middleSlice(value, joiner) {
  return `${value.slice(0, 6)}${joiner}${value.slice(-4)}`;
}

export function shortenAddress(value) {
  if (!value || typeof value !== "string" || !value.startsWith("0x") || value.length < 12) {
    return value || "Unknown";
  }
  return middleSlice(value, "...");
}
