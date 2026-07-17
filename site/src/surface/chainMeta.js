// Display metadata for chains — labels + accent colors for the chain switcher
// pills and the entity-card deployment badge. Chain *truth* (which chains
// exist, their explorer URLs) lives in chains.json / blockExplorer.js; this is
// purely cosmetic presentation, keyed by canonical chain name.

import { coalesceChain } from "./entityKey.js";

const LABELS = {
  ethereum: "Ethereum",
  optimism: "Optimism",
  bsc: "BNB Chain",
  polygon: "Polygon",
  zksync: "zkSync",
  base: "Base",
  mode: "Mode",
  arbitrum: "Arbitrum",
  avalanche: "Avalanche",
  linea: "Linea",
  berachain: "Berachain",
  blast: "Blast",
  scroll: "Scroll",
};

const COLORS = {
  ethereum: "#627eea",
  base: "#0052ff",
  arbitrum: "#28a0f0",
  optimism: "#ff0420",
  polygon: "#8247e5",
  zksync: "#8c8dfc",
  scroll: "#ffd9a8",
};

const DEFAULT_COLOR = "#94a3b8";

export function chainLabel(chain) {
  const c = coalesceChain(chain);
  return LABELS[c] || c.charAt(0).toUpperCase() + c.slice(1);
}

export function chainColor(chain) {
  return COLORS[coalesceChain(chain)] || DEFAULT_COLOR;
}
