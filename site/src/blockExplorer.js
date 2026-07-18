// Block-explorer links, driven by the generated chain registry
// (`chains.json`, emitted from utils/chains.py by scripts/gen_chains_json.py —
// chains.json is the single source of chain truth on the frontend). No
// hand-maintained chain map here: adding a chain to the registry + regenerating
// the JSON is all it takes for links to work.

import CHAINS from "./chains.json";

// canonical name (lowercased) → { base, name }. `base` is the explorer origin
// with no trailing slash (e.g. "https://etherscan.io"); `name` is the human
// label derived from the explorer hostname's domain label (etherscan.io →
// "Etherscan", optimistic.etherscan.io → "Etherscan", basescan.org →
// "Basescan"), so a link labels itself per chain without a second map.
function explorerName(baseUrl) {
  try {
    const host = new URL(baseUrl).hostname; // e.g. "optimistic.etherscan.io"
    const domain = host.split(".").at(-2) || host; // "etherscan"
    return domain.charAt(0).toUpperCase() + domain.slice(1);
  } catch {
    return "Explorer";
  }
}

const CHAIN_INFO = new Map();
for (const c of CHAINS) {
  if (!c?.name || !c?.explorer_base_url) continue;
  const base = String(c.explorer_base_url).replace(/\/+$/, "");
  CHAIN_INFO.set(c.name.toLowerCase(), { base, name: explorerName(base) });
}

// "mainnet" is the one documented alias for ethereum (the registry carries it
// but chains.json only emits canonical names). Keep it resolvable so callers
// passing the legacy alias still land on Etherscan.
const ETHEREUM = CHAIN_INFO.get("ethereum");
if (ETHEREUM) CHAIN_INFO.set("mainnet", ETHEREUM);

function infoFor(chain) {
  return CHAIN_INFO.get(String(chain || "ethereum").toLowerCase()) || ETHEREUM || null;
}

export function blockExplorerAddressUrl(address, chain = "ethereum") {
  if (!address) return null;
  const info = infoFor(chain);
  if (!info) return null;
  return `${info.base}/address/${address}`;
}

// Human name of the explorer a `blockExplorerAddressUrl` link lands on, so a
// link labels itself correctly per chain instead of hardcoding "Etherscan".
export function blockExplorerName(chain = "ethereum") {
  const info = infoFor(chain);
  return info ? info.name : "Explorer";
}
