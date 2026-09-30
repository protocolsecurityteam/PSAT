// Explorer links from the generated chain registry (`chains.json`, via
// scripts/gen_chains_json.py); no hand-maintained map.

import CHAINS from "./chains.json";

// `name` comes from the explorer hostname (optimistic.etherscan.io →
// "Etherscan"), so no second map.
function explorerName(baseUrl) {
  try {
    const host = new URL(baseUrl).hostname;
    const domain = host.split(".").at(-2) || host;
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

// chains.json only emits canonical names; keep the legacy "mainnet" alias
// working.
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

export function blockExplorerName(chain = "ethereum") {
  const info = infoFor(chain);
  return info ? info.name : "Explorer";
}
