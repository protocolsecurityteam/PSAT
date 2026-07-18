// Chain-scope derivation for the Surface page (multichain inv. 13). Pure — no
// React. Kept out of ProtocolSurface so the coalescing here provably matches the
// key derivation (entityKey), and so the "unknown/invalid ?chain falls back to
// default, never a blank canvas" contract is unit-testable in isolation.

import { coalesceChain } from "./entityKey.js";

// Chains a protocol actually has contracts on, with per-chain contract counts.
// Only contracts carry a chain; a NULL/missing chain coalesces to "ethereum"
// (legacy convention) using the SAME coalesceChain as the entity keys, so the
// pill counts can never drift from what the scoped page renders. Ethereum
// first, then by contract count desc, then name.
export function deriveAvailableChains(contracts = []) {
  const counts = new Map();
  for (const c of contracts) {
    const ch = coalesceChain(c?.chain);
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => {
      if (a.name === "ethereum") return -1;
      if (b.name === "ethereum") return 1;
      return b.count - a.count || a.name.localeCompare(b.name);
    });
}

// The chain the page falls back to with no valid explicit pick: ethereum if the
// protocol touches it, else its largest chain, else ethereum.
export function defaultChainFor(availableChains = []) {
  if (availableChains.some((c) => c.name === "ethereum")) return "ethereum";
  return availableChains[0]?.name || "ethereum";
}

// Resolve the active chain. A `chosenChain` (from ?chain= / the switcher) wins
// only when the protocol actually deploys on it — an unknown, typo'd, or
// off-protocol value silently degrades to the default chain rather than
// scoping the page to nothing. `chosenChain` is coalesced first so ?chain=
// aliases (mainnet, casing) resolve like everything else.
export function pickActiveChain(availableChains = [], chosenChain = null) {
  const chosen = chosenChain ? coalesceChain(chosenChain) : null;
  if (chosen && availableChains.some((c) => c.name === chosen)) return chosen;
  return defaultChainFor(availableChains);
}
