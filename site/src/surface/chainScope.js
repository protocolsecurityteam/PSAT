// Chain scope for the Surface page (inv. 13), kept pure so it provably
// coalesces like entityKey and invalid ?chain falls back to the default rather
// than a blank canvas.

import { coalesceChain } from "./entityKey.js";

// Same coalesceChain as the entity keys, so pill counts match what renders.
// Ethereum first, then count desc, then name.
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

export function defaultChainFor(availableChains = []) {
  if (availableChains.some((c) => c.name === "ethereum")) return "ethereum";
  return availableChains[0]?.name || "ethereum";
}

// An unknown or off-protocol ?chain degrades to the default rather than scoping
// to nothing.
export function pickActiveChain(availableChains = [], chosenChain = null) {
  const chosen = chosenChain ? coalesceChain(chosenChain) : null;
  if (chosen && availableChains.some((c) => c.name === chosen)) return chosen;
  return defaultChainFor(availableChains);
}
