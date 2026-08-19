import { describe, it, expect } from "vitest";

import { blockExplorerAddressUrl, blockExplorerName } from "./blockExplorer.js";

const ADDR = "0x1111111111111111111111111111111111111111";

describe("blockExplorerAddressUrl (driven by chains.json)", () => {
  it("builds the address URL for a chain in the registry", () => {
    expect(blockExplorerAddressUrl(ADDR, "ethereum")).toBe(`https://etherscan.io/address/${ADDR}`);
    expect(blockExplorerAddressUrl(ADDR, "base")).toBe(`https://basescan.org/address/${ADDR}`);
  });

  it("covers chains the old 5-chain map missed (regression: was hardcoded)", () => {
    // scroll / linea were not in the old hardcoded map; chains.json carries them.
    expect(blockExplorerAddressUrl(ADDR, "scroll")).toBe(`https://scrollscan.com/address/${ADDR}`);
    expect(blockExplorerAddressUrl(ADDR, "linea")).toBe(`https://lineascan.build/address/${ADDR}`);
  });

  it("keeps the mainnet → ethereum alias", () => {
    expect(blockExplorerAddressUrl(ADDR, "mainnet")).toBe(`https://etherscan.io/address/${ADDR}`);
  });

  it("falls back to ethereum for an unknown chain instead of throwing", () => {
    expect(blockExplorerAddressUrl(ADDR, "nonexistent-chain")).toBe(`https://etherscan.io/address/${ADDR}`);
    expect(blockExplorerAddressUrl(ADDR, null)).toBe(`https://etherscan.io/address/${ADDR}`);
  });

  it("returns null for a missing address", () => {
    expect(blockExplorerAddressUrl(null, "base")).toBeNull();
  });
});

describe("blockExplorerName (derived from explorer hostname)", () => {
  it("names the explorer per chain", () => {
    expect(blockExplorerName("ethereum")).toBe("Etherscan");
    expect(blockExplorerName("base")).toBe("Basescan");
    expect(blockExplorerName("polygon")).toBe("Polygonscan");
    // optimism's explorer is optimistic.etherscan.io → the domain label is etherscan.
    expect(blockExplorerName("optimism")).toBe("Etherscan");
  });

  it("keeps the mainnet alias and a graceful default", () => {
    expect(blockExplorerName("mainnet")).toBe("Etherscan");
    expect(blockExplorerName("nonexistent-chain")).toBe("Etherscan");
  });
});
