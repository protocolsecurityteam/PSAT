const ADDRESS_EXPLORERS_BY_CHAIN_ID = {
  1: "https://etherscan.io/address/",
  10: "https://optimistic.etherscan.io/address/",
  56: "https://bscscan.com/address/",
  137: "https://polygonscan.com/address/",
  8453: "https://basescan.org/address/",
  42161: "https://arbiscan.io/address/",
  534352: "https://scrollscan.com/address/",
  81457: "https://blastscan.io/address/",
};

export function blockExplorerAddressUrl(address, chainId) {
  if (!address) return null;
  const parsedChainId = Number.parseInt(chainId, 10);
  if (!Number.isInteger(parsedChainId) || parsedChainId <= 0) return null;
  const base = ADDRESS_EXPLORERS_BY_CHAIN_ID[parsedChainId];
  if (!base) return null;
  return `${base}${address}`;
}

export function blockExplorerTxUrl(txHash, chainId) {
  if (!txHash) return null;
  const addressUrl = blockExplorerAddressUrl("0x", chainId);
  if (!addressUrl) return null;
  return `${addressUrl.replace("/address/0x", "/tx/")}${txHash}`;
}
