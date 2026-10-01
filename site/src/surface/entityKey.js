// Entity identity is (chain, address); these helpers are the single
// place that builds the key. Legacy rows have NULL chain, which means
// "ethereum".

export function coalesceChain(chain) {
  const c = String(chain ?? "").trim().toLowerCase();
  if (!c || c === "mainnet") return "ethereum";
  return c;
}

// "::" appears in neither a chain name nor an address, so keys can't collide.
export function entityKey(chain, address) {
  return `${coalesceChain(chain)}::${String(address || "").toLowerCase()}`;
}

// Legacy principals without ``chains`` are kept on any chain.
export function principalOnChain(principal, activeChain) {
  if (!activeChain) return true;
  const chains = Array.isArray(principal?.chains) ? principal.chains : null;
  if (!chains || !chains.length) return true;
  return chains.some((c) => coalesceChain(c) === activeChain);
}
