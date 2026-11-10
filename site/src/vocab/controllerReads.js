// Overview `controller_reads.<id>` tokens. An unlisted token renders raw.
const BLOCK_BASIS = {
  head_before_read: (n) => (n == null ? null : `read at latest, head ≈ block ${n}`),
  log_block: (n) => (n == null ? null : `set at block ${n}`),
  not_determined: () => "read block not determined",
};

const OBSERVED_VIA = {
  eth_call: "via eth_call",
  eth_call_impl_fallback: "via eth_call (implementation fallback)",
  eth_call_error: "eth_call errored",
  beacon_owner: "via beacon owner",
  event_log: "from event log",
  storage_poll: "from storage poll",
};

// The entry's read of `controllerId`, only when the read's value is `address`:
// function principals come from the policy stage and can disagree with the
// current value, and a mismatched read would date the wrong principal.
export function controllerReadFor(entry, controllerId, address) {
  if (!controllerId || !address) return null;
  const read = entry?.controller_reads?.[controllerId];
  if (!read || typeof read.value !== "string") return null;
  return read.value.toLowerCase() === String(address).toLowerCase() ? read : null;
}

// "read at latest, head ≈ block N · via eth_call". Null for no read.
export function controllerReadText(read) {
  if (!read) return null;
  const basis = read.block_basis;
  const blockWord = BLOCK_BASIS[basis] ? BLOCK_BASIS[basis](read.block_number) : null;
  const parts = [blockWord || basis || null];
  if (read.observed_via) parts.push(OBSERVED_VIA[read.observed_via] || read.observed_via);
  return parts.filter(Boolean).join(" · ") || null;
}

// Overview entry `controller_values_state`: null makes no claim.
const CONTROLLER_VALUES_STATE = {
  not_determined: "controller values not determined for this deployment",
};

// Shape: {token, word, notDetermined} or null.
export function controllerValuesNote(entry) {
  const token = entry?.controller_values_state;
  if (token == null) return null;
  return { token, word: CONTROLLER_VALUES_STATE[token] || token, notDetermined: token === "not_determined" };
}
