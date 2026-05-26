// `display_name` is the user-facing label for a contract entry. Falls
// back through display_name → contract_name → run_name. The proxy
// shortlist exists because raw `contract_name` values like
// "TransparentUpgradeableProxy" are useless in lists — when we hit
// one, prefer the run_name (which is usually the protocol's own name).

const GENERIC_PROXY_NAMES = new Set([
  "uupsproxy",
  "erc1967proxy",
  "transparentupgradeableproxy",
  "proxy",
  "beaconproxy",
  "ossifiableproxy",
  "withdrawalsmanagerproxy",
  "upgradeablebeacon",
]);

export function displayName(entry) {
  const explicit = entry?.display_name || "";
  if (explicit) {
    return explicit;
  }
  const contractName = entry?.contract_name || "";
  if (GENERIC_PROXY_NAMES.has(contractName.toLowerCase())) {
    return entry.run_name || contractName;
  }
  return contractName || entry?.run_name || "";
}

// For a proxy contract, lead with the implementation's name (what the proxy
// actually executes) and tuck the generic proxy template into a "via …"
// suffix — otherwise every UUPS proxy in a list reads as the identical
// "UUPSProxy". Non-proxy rows just get their own name. Used by both the
// addresses modal and the protocol monitoring console so the two stay in
// sync. Returns "" when there's nothing usable; callers decide the fallback.
export function proxyDisplayName({ name, isProxy, implName } = {}) {
  const raw = name || "";
  if (isProxy && implName) {
    if (!raw || raw.toLowerCase() === implName.toLowerCase()) return implName;
    return `${implName} (via ${raw})`;
  }
  return raw;
}
