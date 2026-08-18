export function shortenAddress(value) {
  if (!value || typeof value !== "string" || !value.startsWith("0x") || value.length < 12) {
    return value || "Unknown";
  }
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}
