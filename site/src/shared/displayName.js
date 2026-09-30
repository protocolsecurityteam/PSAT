// A proxy leads with its implementation's name and a "via …" suffix, or every
// UUPS proxy reads "UUPSProxy". "" when nothing's usable.
export function proxyDisplayName({ name, isProxy, implName } = {}) {
  const raw = name || "";
  if (isProxy && implName) {
    if (!raw || raw.toLowerCase() === implName.toLowerCase()) return implName;
    return `${implName} (via ${raw})`;
  }
  return raw;
}
