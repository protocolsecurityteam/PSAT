import { describe, it, expect } from "vitest";
import {
  bulkAnalyzeCandidates,
  candidateReasonText,
  computeCurrentImplAddrs,
  isPureHistorical,
  membershipState,
  prunedReasonText,
  splitMembership,
} from "./addressFilter.js";

const PROXY = "0x1111111111111111111111111111111111111111";
const CURRENT_IMPL = "0x2222222222222222222222222222222222222222";
const STALE_IMPL = "0x3333333333333333333333333333333333333333";
const STANDALONE = "0x4444444444444444444444444444444444444444";
const OWNER = "0x5555555555555555555555555555555555555555";

function row(overrides = {}) {
  return {
    address: STANDALONE,
    name: "",
    is_proxy: false,
    implementation_address: null,
    implementation_name: null,
    membership_state: "member",
    membership_witnesses: [],
    membership_reason: null,
    ...overrides,
  };
}

const HISTORICAL_WITNESS = { rule: "w2_structural", via_address: PROXY, edge_kind: "historical_implementation" };
const LIVE_IMPL_WITNESS = { rule: "w2_structural", via_address: PROXY, edge_kind: "implementation" };

describe("addressFilter", () => {
  describe("membershipState", () => {
    it("reads the payload field", () => {
      expect(membershipState(row({ membership_state: "candidate" }))).toBe("candidate");
      expect(membershipState(row({ membership_state: "pruned" }))).toBe("pruned");
    });

    it("defaults rows without the field to member so they stay visible", () => {
      expect(membershipState({ address: STANDALONE })).toBe("member");
    });
  });

  describe("splitMembership", () => {
    it("partitions rows by membership_state", () => {
      const rows = [
        row({ address: PROXY, membership_state: "member" }),
        row({ address: STANDALONE, membership_state: "candidate" }),
        row({ address: STALE_IMPL, membership_state: "pruned" }),
      ];
      const { members, candidates, pruned } = splitMembership(rows);
      expect(members.map((r) => r.address)).toEqual([PROXY]);
      expect(candidates.map((r) => r.address)).toEqual([STANDALONE]);
      expect(pruned.map((r) => r.address)).toEqual([STALE_IMPL]);
    });
  });

  describe("isPureHistorical", () => {
    it("flags a member admitted only as a historical implementation", () => {
      const r = row({ address: STALE_IMPL, membership_witnesses: [HISTORICAL_WITNESS] });
      expect(isPureHistorical(r, new Set())).toBe(true);
    });

    it("keeps a historical-witnessed member visible when it is the live impl of a proxy", () => {
      const r = row({ address: CURRENT_IMPL, membership_witnesses: [HISTORICAL_WITNESS] });
      expect(isPureHistorical(r, new Set([CURRENT_IMPL]))).toBe(false);
    });

    it("matches current-impl addresses case-insensitively", () => {
      const r = row({ address: CURRENT_IMPL.toUpperCase(), membership_witnesses: [HISTORICAL_WITNESS] });
      expect(isPureHistorical(r, new Set([CURRENT_IMPL]))).toBe(false);
    });

    it("keeps members with any non-historical admitting witness", () => {
      const r = row({ membership_witnesses: [HISTORICAL_WITNESS, LIVE_IMPL_WITNESS] });
      expect(isPureHistorical(r, new Set())).toBe(false);
      expect(isPureHistorical(row({ membership_witnesses: [{ rule: "w6_llama_seed", via_address: null }] }), new Set())).toBe(false);
    });

    it("never hides a member without recorded witnesses", () => {
      expect(isPureHistorical(row(), new Set())).toBe(false);
    });

    it("only applies to members", () => {
      const r = row({ membership_state: "candidate", membership_witnesses: [HISTORICAL_WITNESS] });
      expect(isPureHistorical(r, new Set())).toBe(false);
    });
  });

  describe("candidateReasonText", () => {
    it("names the probed block and out-of-perimeter reads", () => {
      const r = row({
        membership_state: "candidate",
        membership_reason: {
          kind: "probe_unresolved",
          probe_block: 1234,
          resolved_reads: { owner: OWNER },
          unresolved_reads: ["authority"],
        },
      });
      expect(candidateReasonText(r)).toBe(
        "probed at block 1234 — owner 0x5555...5555 not in perimeter; authority resolved nowhere",
      );
    });

    it("handles a probe where nothing resolved", () => {
      const r = row({
        membership_state: "candidate",
        membership_reason: {
          kind: "probe_unresolved",
          probe_block: 9,
          resolved_reads: {},
          unresolved_reads: ["owner", "authority"],
        },
      });
      expect(candidateReasonText(r)).toBe("probed at block 9 — owner, authority resolved nowhere");
    });

    it("names an unroutable chain", () => {
      const r = row({
        membership_state: "candidate",
        membership_reason: { kind: "chain_not_routable", chain: "hyperevm" },
      });
      expect(candidateReasonText(r)).toBe("probe pending — chain hyperevm not routable");
    });

    it("says when no probe attempt exists yet", () => {
      const r = row({ membership_state: "candidate", membership_reason: { kind: "no_probe_attempt" } });
      expect(candidateReasonText(r)).toBe("no probe attempt yet");
    });

    it("says when the probe attempt failed", () => {
      const r = row({ membership_state: "candidate", membership_reason: { kind: "probe_error" } });
      expect(candidateReasonText(r)).toBe("probe attempt failed");
    });

    it("surfaces an unknown reason kind verbatim, never a vague default", () => {
      const r = row({ membership_state: "candidate", membership_reason: { kind: "future_reason_kind" } });
      expect(candidateReasonText(r)).toBe("future_reason_kind");
    });
  });

  describe("prunedReasonText", () => {
    it("names the code-absent probe block", () => {
      const r = row({
        membership_state: "pruned",
        membership_reason: { kind: "code_absent", code_probe_block: 777 },
      });
      expect(prunedReasonText(r)).toBe("no code at block 777");
    });
  });

  it("computes current-impl set from is_proxy + implementation_address", () => {
    const rows = [
      row({ address: PROXY, is_proxy: true, implementation_address: CURRENT_IMPL }),
      row({ address: STALE_IMPL }),
      row({ address: CURRENT_IMPL }),
    ];
    expect(computeCurrentImplAddrs(rows)).toEqual(new Set([CURRENT_IMPL]));
  });

  it("ignores non-proxy rows when computing current-impl set", () => {
    const rows = [row({ is_proxy: false, implementation_address: CURRENT_IMPL })];
    expect(computeCurrentImplAddrs(rows).size).toBe(0);
  });

  describe("bulkAnalyzeCandidates", () => {
    it("picks up unanalyzed rows", () => {
      const rows = [row({ address: STANDALONE, analyzed: false })];
      expect(bulkAnalyzeCandidates(rows, new Set()).map((r) => r.address)).toEqual([STANDALONE]);
    });

    it("excludes already-analyzed rows", () => {
      const rows = [row({ address: STANDALONE, analyzed: true })];
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });

    it("excludes pure-historical members even when they slip into the input view", () => {
      const rows = [row({ address: STALE_IMPL, analyzed: false, membership_witnesses: [HISTORICAL_WITNESS] })];
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });

    it("excludes pruned rows — no code, nothing to analyze", () => {
      const rows = [
        row({
          address: STALE_IMPL,
          analyzed: false,
          membership_state: "pruned",
          membership_reason: { kind: "code_absent", code_probe_block: 1 },
        }),
      ];
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });

    it("includes the live impl even when its witness is historical-only", () => {
      const rows = [row({ address: CURRENT_IMPL, analyzed: false, membership_witnesses: [HISTORICAL_WITNESS] })];
      expect(bulkAnalyzeCandidates(rows, new Set([CURRENT_IMPL])).map((r) => r.address)).toEqual([CURRENT_IMPL]);
    });

    it("skips compare-mode synthesized rows", () => {
      const rows = [row({ address: STANDALONE, analyzed: false, _compareStatus: "matched" })];
      expect(bulkAnalyzeCandidates(rows, new Set())).toEqual([]);
    });
  });

  it("splits a realistic payload into the three display sections", () => {
    const rows = [
      row({
        address: PROXY,
        is_proxy: true,
        implementation_address: CURRENT_IMPL,
        membership_witnesses: [{ rule: "w6_llama_seed", via_address: null }],
      }),
      row({ address: CURRENT_IMPL, membership_witnesses: [HISTORICAL_WITNESS] }),
      row({ address: STALE_IMPL, membership_witnesses: [HISTORICAL_WITNESS] }),
      row({
        address: STANDALONE,
        membership_state: "candidate",
        membership_reason: { kind: "no_probe_attempt" },
      }),
    ];
    const { members, candidates, pruned } = splitMembership(rows);
    expect(members.map((r) => r.address).sort()).toEqual([PROXY, CURRENT_IMPL, STALE_IMPL].sort());
    expect(candidates.map((r) => r.address)).toEqual([STANDALONE]);
    expect(pruned).toEqual([]);
    const current = computeCurrentImplAddrs(rows);
    expect(isPureHistorical(rows[1], current)).toBe(false); // live impl stays
    expect(isPureHistorical(rows[2], current)).toBe(true); // stale impl hides
  });
});
