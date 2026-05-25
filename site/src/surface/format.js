// Pure formatters + small predicates used across the surface tree.
// No React, no closures — safe to import from anywhere.

export function shortAddr(address) {
  if (!address || address.length < 12) return address || "";
  return address.slice(0, 6) + ".." + address.slice(-4);
}

export function formatDelay(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return "";
  if (value >= 86400) return `${Math.round(value / 86400)}d`;
  if (value >= 3600) return `${Math.round(value / 3600)}h`;
  return `${Math.round(value / 60)}m`;
}

// Short type badge for a principal — "6/10 SAFE", "TL · 2d", or the bare
// type ("EOA", "PROXY_ADMIN"). Shared by the group header, the controllers
// accordion rows, and anywhere a principal needs a one-glance label so they
// never drift apart.
export function principalBadge(p) {
  const owners = Array.isArray(p?.details?.owners) ? p.details.owners : [];
  const threshold = p?.details?.threshold;
  const delay = p?.details?.delay;
  if (p?.type === "safe" && threshold) return `${threshold}/${owners.length || "?"} SAFE`;
  if (p?.type === "timelock" && delay) return `TL · ${formatDelay(delay)}`;
  return (p?.type || "").toUpperCase();
}

export function maskWebhook(url) {
  if (!url) return "";
  const value = String(url);
  if (value.length <= 24) return value;
  return `${value.slice(0, 18)}...${value.slice(-8)}`;
}

export function functionName(signature) {
  return String(signature || "?").split("(")[0] || "?";
}

export function isRoleConstant(name) {
  return /^[A-Z][A-Z0-9_]+$/.test(name);
}

export function hasHint(name, hints) {
  return hints.some((hint) => name.includes(hint));
}

export function isRoleIdAddress(address) {
  const hex = address.slice(2);
  const leadingZeros = hex.match(/^0*/)[0].length;
  return leadingZeros >= 24;
}

export function isHexAddress(value) {
  return /^0x[a-fA-F0-9]{40}$/.test(String(value || ""));
}

export function formatUsd(value) {
  if (!value || value < 0.01) return null;
  if (value >= 1e9) return `$${(value / 1e9).toFixed(1)}B`;
  if (value >= 1e6) return `$${(value / 1e6).toFixed(1)}M`;
  if (value >= 1e3) return `$${(value / 1e3).toFixed(1)}K`;
  return `$${value.toFixed(2)}`;
}

export function formatEventAgo(detectedAt) {
  if (!detectedAt) return null;
  const d = new Date(detectedAt);
  if (Number.isNaN(d.getTime())) return null;
  const seconds = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 30 * 86400) return `${Math.floor(seconds / 86400)}d ago`;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export function dedupeShas(list) {
  const fulls = new Map(); // prefix(7) → full sha
  const shorts = new Set();
  for (const raw of list || []) {
    const sha = String(raw || "").trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(sha)) continue;
    if (sha.length >= 20) fulls.set(sha.slice(0, 7), sha);
    else if (sha.length >= 4) shorts.add(sha);
  }
  const out = [...fulls.values()];
  for (const s of shorts) {
    if (!fulls.has(s.slice(0, 7))) out.push(s);
  }
  return out;
}
