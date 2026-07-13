const ADDRESS_EXPLORERS = {
  ethereum: "https://etherscan.io/address/",
  mainnet: "https://etherscan.io/address/",
  base: "https://basescan.org/address/",
  arbitrum: "https://arbiscan.io/address/",
  optimism: "https://optimistic.etherscan.io/address/",
  polygon: "https://polygonscan.com/address/",
};

export function blockExplorerAddressUrl(address, chain = "ethereum") {
  if (!address) return null;
  const base = ADDRESS_EXPLORERS[String(chain || "ethereum").toLowerCase()] || ADDRESS_EXPLORERS.ethereum;
  return `${base}${address}`;
}

const EXPLORER_NAMES = {
  ethereum: "Etherscan",
  mainnet: "Etherscan",
  base: "Basescan",
  arbitrum: "Arbiscan",
  optimism: "Etherscan",
  polygon: "Polygonscan",
};

// Human name of the explorer a `blockExplorerAddressUrl` link lands on, so a
// link labels itself correctly per chain instead of hardcoding "Etherscan".
export function blockExplorerName(chain = "ethereum") {
  return EXPLORER_NAMES[String(chain || "ethereum").toLowerCase()] || "Explorer";
}
