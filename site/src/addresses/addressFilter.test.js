import { describe, it, expect } from "vitest";
import {
  HIGH_SOURCES,
  bulkAnalyzeCandidates,
  computeCurrentImplAddrs,
  isPureHistorical,
  splitHistorical,
} from "./addressFilter.js";

const PROXY = "0x1111111111111111111111111111111111111111";
const CURRENT_IMPL = "0x2222222222222222222222222222222222222222";
const STALE_IMPL = "0x3333333333333333333333333333333333333333";
const STANDALONE = "0x4444444444444444444444444444444444444444";

function row(overrides = {}) {
  return {
    address: STANDALONE,
    name: "",
    is_proxy: false,
    implementation_address: null,
    implementation_name: null,
    discovery_sources: [],
    ...overrides,
  };
}

describe("addressFilter", () => {
  it("treats every high-confidence source as active", () => {
    for (const src of HIGH_SOURCES) {
      const r = row({ discovery_sources: [src] });
      expect(isPureHistorical(r, new Set())).toBe(false);
    }
  });

  it("flags a row tagged only with upgrade_history as historical", () => {
    const r = row({
      address: STALE_IMPL,
      name: "EtherFiNodesManager",
      discovery_sources: ["upgrade_history"],
    });
    expect(isPureHistorical(r, new Set())).toBe(true);
  });

  it("flags a row tagged only with structural_adoption as historical", () => {
    // structural_adoption is added by the upgrade-history sweep on the
    // discovery-confidence-gating branch; the filter should treat it the
    // same as upgrade_history since neither is in HIGH_SOURCES.
    const r = row({ discovery_sources: ["structural_adoption"] });
    expect(isPureHistorical(r, new Set())).toBe(true);
  });

  it("keeps a row visible if it is the current impl of a proxy", () => {
    const r = row({
      address: CURRENT_IMPL,
      discovery_sources: ["upgrade_history"],
    });
    const current = new Set([CURRENT_IMPL]);
    expect(isPureHistorical(r, current)).toBe(false);
  });

  it("matches current-impl addresses case-insensitively", () => {
    const r = row({
      address: CURRENT_IMPL.toUpperCase(),
      discovery_sources: ["upgrade_history"],
    });
    const current = new Set([CURRENT_IMPL]);
    expect(isPureHistorical(r, current)).toBe(false);
  });

  it("treats missing discovery_sources as historical", () => {
    const r = row({ discovery_sources: undefined });
    expect(isPureHistorical(r, new Set())).toBe(true);
  });

  it("computes current-impl set from is_proxy + implementation_address", () => {
    const rows = [
      row({ address: PROXY, is_proxy: true, implementation_address: CURRENT_IMPL }),
      row({ address: STALE_IMPL, discovery_sources: ["upgrade_history"] }),
      row({ address: CURRENT_IMPL, discovery_sources: ["upgrade_history"] }),
    ];
    expect(computeCurrentImplAddrs(rows)).toEqual(new Set([CURRENT_IMPL]));
  });

  it("ignores non-proxy rows when computing current-impl set", () => {
    const rows = [
      row({ is_proxy: false, implementation_address: CURRENT_IMPL }),
    ];
    expect(computeCurrentImplAddrs(rows).size).toBe(0);
  });

  describe("bulkAnalyzeCandidates", () => {
    it("picks up unanalyzed active rows", () => {
      const rows = [
        row({ address: STANDALONE, analyzed: false, discovery_sources: ["deployer_expansion"] }),
      ];
      const result = bulkAnalyzeCandidates(rows, new Set());
      expect(result.map((r) => r.address)).toEqual([STANDALONE]);
    });

    it("excludes already-analyzed rows", () => {
      const rows = [
        row({ address: STANDALONE, analyzed: true, discovery_sources: ["deployer_expansion"] }),
      ];
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });

    it("excludes pure-historical rows even when they slip into the input view", () => {
      const rows = [
        row({
          address: STALE_IMPL,
          analyzed: false,
          discovery_sources: ["upgrade_history"],
        }),
      ];
      // simulates the case where the user toggled "Show historical" and the
      // row is visible — the bulk action must still skip it.
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });

    it("includes the live impl even when its only source is upgrade_history", () => {
      const rows = [
        row({
          address: CURRENT_IMPL,
          analyzed: false,
          discovery_sources: ["upgrade_history"],
        }),
      ];
      const result = bulkAnalyzeCandidates(rows, new Set([CURRENT_IMPL]));
      expect(result.map((r) => r.address)).toEqual([CURRENT_IMPL]);
    });

    it("skips compare-mode synthesized rows", () => {
      const rows = [
        row({
          address: STANDALONE,
          analyzed: false,
          discovery_sources: ["deployer_expansion"],
          _compareStatus: "matched",
        }),
      ];
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });
  });

  it("splits a realistic payload into active vs historical", () => {
    const rows = [
      row({
        address: PROXY,
        is_proxy: true,
        implementation_address: CURRENT_IMPL,
        implementation_name: "EtherFiNodesManager",
        discovery_sources: ["deployer_expansion", "exa_deep_research"],
      }),
      row({
        address: CURRENT_IMPL,
        name: "EtherFiNodesManager",
        discovery_sources: ["upgrade_history"],
      }),
      row({
        address: STALE_IMPL,
        name: "EtherFiNodesManager",
        discovery_sources: ["upgrade_history"],
      }),
      row({
        address: STANDALONE,
        name: "RewardsRouter",
        discovery_sources: ["dapp_crawl"],
      }),
    ];
    const { active, historical } = splitHistorical(rows);
    const activeAddrs = active.map((r) => r.address).sort();
    const historicalAddrs = historical.map((r) => r.address).sort();
    expect(activeAddrs).toEqual([PROXY, CURRENT_IMPL].sort());
    expect(historicalAddrs).toEqual([STALE_IMPL, STANDALONE].sort());
  });
});
