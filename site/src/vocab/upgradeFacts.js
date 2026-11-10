// Overview `upgrade_count_basis.recorded_count_relation` tokens. An unlisted
// token renders raw beside the count, never as a guessed word.
const COUNT_RELATION = {
  exact: (n) => `${n} recorded upgrade${n === 1 ? "" : "s"}`,
  upper_bound: (n) => `up to ${n} upgrade${n === 1 ? "" : "s"}`,
  not_determined: (n) => `${n} upgrade${n === 1 ? "" : "s"} · bound not determined`,
};

// The entry's upgrade count with how it relates to the recorded upgrades.
// Null when the entry makes no claim. A published basis with no count is a
// count that was not determined, never zero.
export function upgradeCountText(entry) {
  const count = entry?.upgrade_count;
  const basis = entry?.upgrade_count_basis;
  // The backend never publishes a zero (a post-exclusion zero is unproven).
  if (typeof count !== "number" || !(count > 0)) {
    return basis ? "upgrades not determined" : null;
  }
  const relation = basis?.recorded_count_relation;
  if (relation == null) return `${count} upgrade${count === 1 ? "" : "s"}`;
  const word = COUNT_RELATION[relation];
  return word ? word(count) : `${count} upgrade${count === 1 ? "" : "s"} · ${relation}`;
}

// Overview `last_upgrade_state` tokens other than `established`. An unlisted
// token renders raw.
const LAST_UPGRADE_STATE_WORD = {
  not_determined: "not determined",
};

export function lastUpgradeStateWord(token) {
  return LAST_UPGRADE_STATE_WORD[token] || token;
}
