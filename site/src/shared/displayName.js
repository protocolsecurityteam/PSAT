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
