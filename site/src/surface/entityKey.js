// Frontend entity identity is (chain, address), not bare address (multichain
// invariant 13). Same address on two chains = two distinct entities. These
// helpers are the single home for building that composite key so every keyed
// Map/Set/lookup coalesces chain the same way.
//
// Data reality: legacy backend rows have `chain` NULL/absent — the documented
// convention (routers/jobs.py, services/audits/coverage.py) is NULL ≡
// "ethereum". We coalesce here so legacy single-chain payloads key identically
// whether the row says "ethereum" or nothing at all.

export function coalesceChain(chain) {
  const c = String(chain ?? "").trim().toLowerCase();
  if (!c || c === "mainnet") return "ethereum";
  return c;
}

// Composite entity key. "::" can appear in neither a chain name nor a 0x
// address, so `${chain}::${address}` is collision-free — no chain/address pair
// can alias another.
export function entityKey(chain, address) {
  return `${coalesceChain(chain)}::${String(address || "").toLowerCase()}`;
}
