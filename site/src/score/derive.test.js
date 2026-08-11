import { describe, it, expect } from "vitest";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import {
  BOUND_DIRECTIONS,
  auditPosture,
  buildContractIndex,
  calloutsFor,
  cautionsFor,
  coalitionWord,
  confidenceChannels,
  controllerAddress,
  deductionRows,
  fixFirst,
  groupRows,
  isProvenNoReach,
  keysetOverlapsFor,
  ledgerSegments,
  principalAddresses,
  principalChip,
  projectScore,
  protectionRows,
  resolveTargets,
  safeShape,
  timelockProposer,
  undeterminedTargets,
  ceilingReasonLabel,
  sheetDisposition,
  sheetStateLabel,
  upgradeBypassCount,
  valueCell,
} from "./derive.js";
import { lambdaOf, recoveryFrom } from "./fold.js";

const F = ETHERFI.findings;
const view = projectScore(ETHERFI, []);

describe("derive — principals", () => {
  it("reads the controller off the principal string, never principal_unit", () => {
    // finding 0's principal_unit is a member of the Safe; the acting principal
    // is the Safe itself. Naming the member would attribute k-of-n power to one
    // key holder.
    expect(F[0].principal_unit).toBe("ethereum::0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde");
    expect(controllerAddress(F[0])).toBe("0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5");
    expect(controllerAddress(F[26])).toBeNull(); // "ANYONE anyone" carries no address
  });

  it("parses the principal shape into a chip", () => {
    expect(principalChip(F[2])).toEqual({ kind: "eoa", label: "EOA" });
    expect(principalChip(F[8])).toEqual({ kind: "timelock", label: "Timelock 2d" });
    expect(principalChip(F[0])).toEqual({ kind: "safe", label: "Safe 4/8" });
    expect(principalChip(F[3])).toEqual({ kind: "timelock", label: "Timelock 10d" });
    expect(principalChip(F[26])).toEqual({ kind: "anyone", label: "Anyone" });
  });

  it("names the coalition from k/n, not from the weakness rung", () => {
    // 0.35 is safe_majority on the ladder and 4/8 is not a majority — exactly
    // one signer short. Inverting the rung would have to guess, and here it
    // would guess wrong.
    expect(coalitionWord(safeShape(F[1]))).toBe("majority"); // 4/6
    expect(coalitionWord(safeShape(F[0]))).toBe("minority"); // 4/8
    expect(coalitionWord({ k: 1, n: 5 })).toBe("single signer");
    expect(coalitionWord({ k: 5, n: 7 })).toBe("supermajority");
    expect(coalitionWord(null)).toBeNull();
  });

  it("distinguishes a routed timelock from an unproven proposer set", () => {
    expect(timelockProposer(F[3])).toEqual({ text: "via Safe 6/10", proven: true });
    expect(timelockProposer(F[8])).toEqual({ text: "proposer unproven", proven: false });
  });
});

describe("derive — value cell", () => {
  it("strips the band qualifier and carries the direction separately", () => {
    expect(valueCell(F[1])).toEqual({ determined: true, text: "$10M-$100M", direction: "not_determined" });
    expect(valueCell(F[2])).toEqual({ determined: true, text: "<$100k", direction: "not_determined" });
    // A band the producer never measured is a third state, not a $0 cell.
    expect(valueCell(F[5])).toEqual({ determined: false, text: null, direction: null });
  });

  it("allow-lists every direction the producer actually publishes", () => {
    // The allow-list nulls an unknown direction SILENTLY — the badge vanishes
    // rather than erroring — so a producer that mints a new token and a page
    // that does not learn it disagree with no diagnostic anywhere. This is the
    // lockstep check: whatever the document carries has to be in the list.
    const published = new Set(
      [...ETHERFI.findings, ...(ETHERFI.provenance?.subsumed_rows || [])]
        .map((f) => f.value_at_stake_bound_direction)
        .filter((d) => d != null),
    );
    expect(published.size).toBeGreaterThan(0);
    for (const direction of published) expect(BOUND_DIRECTIONS).toContain(direction);
    // "ceiling" is no longer a token only a constructed row can carry: the
    // chain-log sweep proved sheets empty, and a row every one of whose
    // contributing entities is a proven $0 with no coverage gap publishes it.
    // The uncalibrated-arm register was updated to match, so this asserts the
    // corpus side of that removal.
    expect(published.has("ceiling")).toBe(true);
    const carrier = [...ETHERFI.findings, ...(ETHERFI.provenance?.subsumed_rows || [])].find(
      (f) => f.value_at_stake_bound_direction === "ceiling",
    );
    // And it reaches the cell as a real badge rather than being nulled away.
    expect(valueCell(carrier).direction).toBe("ceiling");
    expect(valueCell(carrier).determined).toBe(true);
  });

  it("reads a ceiling and a two-sided unknown as their own directions, never as a floor", () => {
    // A total composed entirely of extraction ceilings publishes "<= " and must
    // never reach the cell as an at-least.
    expect(valueCell({ value_band: "<= $10M-$100M", value_at_stake_bound_direction: "ceiling" })).toEqual({
      determined: true,
      text: "$10M-$100M",
      direction: "ceiling",
    });
    // Ceilings under a coverage gap: bounded in neither direction, band
    // unqualified, and the old boolean says false — which is not "exact".
    expect(
      valueCell({
        value_band: "$10M-$100M",
        value_at_stake_bound_direction: "not_determined",
        value_at_stake_is_floor: false,
      }),
    ).toEqual({ determined: true, text: "$10M-$100M", direction: "not_determined" });
  });

  it("refuses to infer a direction from the boolean a document carries alone", () => {
    // The boolean is a two-valued answer to a three-sided question: a document
    // that predates the direction field cannot distinguish a proven floor from
    // a sum of ceilings, so the cell claims neither.
    expect(valueCell({ value_band: ">= $1M-$10M", value_at_stake_is_floor: true }).direction).toBeNull();
    expect(valueCell({ value_band: "$1M-$10M", value_at_stake_bound_direction: "sideways" }).direction).toBeNull();
    // "exact" is not in the producer's vocabulary: a total with no coverage gap
    // and no ceiling in it is published as not_determined, not as two-sided.
    expect(valueCell({ value_band: "$1M-$10M", value_at_stake_bound_direction: "exact" }).direction).toBeNull();
  });

  it("keeps not_determined as a third state — never $0, never blank", () => {
    const cell = valueCell(F[4]);
    expect(cell.determined).toBe(false);
    expect(cell.text).toBeNull();
    expect(F[4].value_band).toBe("not_determined");
  });

  it("reads a proven_no_reach basis as an earned negative, not an unknown", () => {
    expect(isProvenNoReach({ value_at_stake_basis: "proven_no_reach", value_state: "not_determined" })).toBe(true);
    expect(isProvenNoReach(F[10])).toBe(false);
  });
});

describe("derive — targets", () => {
  const CONTRACTS = [
    {
      address: "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
      chain: "ethereum",
      name: "WeETH",
      implementation: "0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3",
    },
    { address: "0x352180974c71f84a934953cf49c4e538a6f9c997", chain: "ethereum", name: "BoringVault" },
  ];
  const index = buildContractIndex(CONTRACTS);

  it("collapses a proxy and its implementation to one target", () => {
    const targets = resolveTargets(
      [
        "ethereum::0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
        "ethereum::0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3",
        "ethereum::0x352180974c71f84a934953cf49c4e538a6f9c997",
      ],
      index,
    );
    expect(targets.map((t) => t.name)).toEqual(["WeETH", "BoringVault"]);
  });

  it("names an implementation-only reach through its proxy's contract row", () => {
    const [target] = resolveTargets(["ethereum::0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3"], index);
    expect(target.name).toBe("WeETH");
    // Label and address name ONE entity: the canonical contract the label came
    // from. A button carrying the raw implementation would navigate somewhere
    // other than the "WeETH" it is labelled with. The raw entity is still on
    // the row for anything that needs the reached key itself.
    expect(target.address).toBe("0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee");
    expect(target.short).toBe("0xcd5f…b7ee");
    expect(target.entity).toBe("ethereum::0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3");
  });

  it("keeps an entity with no contract row rather than dropping it", () => {
    const [target] = resolveTargets(["ethereum::0x3311c72a04d2779f4425c036dbc40d14fec0162b"], index);
    expect(target.name).toBeNull();
    expect(target.short).toBe("0x3311…162b");
  });

  it("does not confuse the same address on two chains", () => {
    const targets = resolveTargets(
      ["ethereum::0x352180974c71f84a934953cf49c4e538a6f9c997", "base::0x352180974c71f84a934953cf49c4e538a6f9c997"],
      index,
    );
    expect(targets).toHaveLength(2);
    expect(targets[1].name).toBeNull();
  });

  it("falls back to the undetermined instances when reach was never witnessed", () => {
    expect(F[22].reach_entities).toHaveLength(0);
    const rows = deductionRows(ETHERFI, index);
    const row = rows.find((r) => r.index === 22);
    expect(row.reachWitnessed).toBe(false);
    // The hosts are shown apart, so the target list holds only the
    // undetermined entities that are NOT the row's own hosts — on this row
    // every undetermined instance IS a host, and the list is empty while the
    // hosts still render.
    const hostKeys = new Set(row.hosts.map((h) => h.canonical));
    const expected = undeterminedTargets(F[22], index).filter((t) => !hostKeys.has(t.canonical));
    expect(row.targets.length).toBe(expected.length);
    expect(row.hosts.length).toBeGreaterThan(0);
    expect(F[22].host_entities.length).toBe(2);
  });
});

describe("derive — rows and ledger", () => {
  it("scales both bars against the largest raw points", () => {
    const [first, second, third] = view.rows;
    expect(first.trackPct).toBeCloseTo(100, 6);
    expect(first.fillPct).toBeCloseTo(100, 6);
    expect(second.fillPct).toBeCloseTo((5.04 / 10.5) * 100, 6);
    expect(third.trackPct).toBeCloseTo((7.29 / 10.5) * 100, 6);
  });

  it("merges everything under 0.4 points into one tail segment", () => {
    const { kept, segments } = ledgerSegments(view.rows, ETHERFI.grade_lambda);
    expect(kept).toBe(78.5611);
    expect(segments).toHaveLength(7);
    expect(segments.at(-1).id).toBe("tail");
    expect(segments.at(-1).title).toBe("22 more findings · −0.65");
    expect(segments[0].title).toBe("Safe 4/8 · upgrade.implementation · −10.50");
    // Every segment plus the kept share accounts for the whole 100.
    const total = kept + segments.reduce((sum, s) => sum + s.basis, 0);
    expect(total).toBeCloseTo(100, 2);
  });

  it("charges each row the published net, not the reconstruction of it", () => {
    // The re-fold agrees with every published net on this corpus (fold.test
    // pins that); where they could disagree the document wins — spec §3.2
    // pins the row to −net_points_lambda.
    for (const row of view.rows) expect(row.net).toBe(F[row.index].net_points_lambda);
    const doc = { findings: F.map((f, i) => (i === 0 ? { ...f, net_points_lambda: 19.5 } : f)) };
    const rows = deductionRows(doc, buildContractIndex([]));
    expect(rows[0].index).toBe(0);
    expect(rows[0].net).toBe(19.5);
    expect(rows[0].fillPct).toBeCloseTo((19.5 / 10.5) * 100, 6);
    // A published field that is present but not a number is unwitnessed.
    const blank = { findings: F.map((f, i) => (i === 0 ? { ...f, net_points_lambda: null } : f)) };
    expect(deductionRows(blank, buildContractIndex([]))[0].net).toBeNull();
  });

  it("shows raw points only when the document withheld the nets", () => {
    const withheld = {
      findings: F.map(({ net_points_lambda, ...rest }) => rest),
    };
    const rows = deductionRows(withheld, buildContractIndex([]));
    expect(rows[0].net).toBeNull();
    expect(rows[0].raw).toBe(10.5);
    expect(rows[0].fillPct).toBe(0);
  });
});

describe("derive — callouts", () => {
  it("groups consecutive rows sharing (principal_kind, capability)", () => {
    const groups = groupRows(view.rows);
    expect(groups[0].rows.map((r) => r.index)).toEqual([0]);
    expect(groups[0].kind).toBe("safe");
    expect(groups[0].sum).toBe(10.5);
    expect(groups[1].rows.map((r) => r.index)).toEqual([1]);
    // Same kind as the group above it, split by CAPABILITY: row 0 is
    // upgrade.implementation and row 1 is authority.replace.
    expect(groups[1].kind).toBe("safe");
    expect(groups[2].rows.map((r) => r.index)).toEqual([2]);
    expect(groups[2].kind).toBe("eoa");
  });

  it("keeps a recurrence of the same (kind, capability) apart when it is not adjacent", () => {
    // Run-length, not group-by-key: a hole that reappears further down the
    // ranking is a second story about a second set of rows, and merging the
    // two would sum points that are nowhere near each other on the bar.
    const rows = [
      { index: 0, net: 9, capability: "flow.out", finding: { principal_kind: "eoa" } },
      { index: 1, net: 8, capability: "pause.set", finding: { principal_kind: "eoa" } },
      { index: 2, net: 7, capability: "flow.out", finding: { principal_kind: "eoa" } },
    ];
    const groups = groupRows(rows);
    expect(groups.map((g) => g.rows.map((r) => r.index))).toEqual([[0], [1], [2]]);
    expect(groups.map((g) => g.sum)).toEqual([9, 8, 7]);
  });

  it("has no sum for a group whose nets were never published", () => {
    const rows = [
      { index: 0, net: null, capability: "flow.out", finding: { principal_kind: "eoa" } },
      { index: 1, net: null, capability: "flow.out", finding: { principal_kind: "eoa" } },
    ];
    const groups = groupRows(rows);
    expect(groups).toHaveLength(1);
    expect(groups[0].sum).toBeNull();
    expect(groups[0].sum).not.toBe(0);
    // …and with no λ to hang them on there is nothing to place on the bar.
    expect(calloutsFor(rows, null)).toEqual([]);
  });

  it("names a group worth exactly the threshold", () => {
    const rows = [
      { index: 0, net: 5, capability: "flow.out", finding: { principal_kind: "eoa" } },
      { index: 1, net: 4.999, capability: "pause.set", finding: { principal_kind: "safe" } },
    ];
    expect(calloutsFor(rows, 90).map((c) => c.text)).toEqual(["one EOA outflow path", "1 other"]);
  });

  it("names leading groups worth 5 points or more and collapses the rest", () => {
    const callouts = calloutsFor(view.rows, ETHERFI.grade_lambda);
    expect(callouts.map((c) => c.text)).toEqual([
      "one Safe upgrade path",
      "one Safe authority hole",
      "26 others",
    ]);
    expect(callouts[0].sum).toBe(10.5);
    expect(callouts[1].sum).toBe(5.04);
    expect(callouts[2].sum).toBeCloseTo(5.8989, 3);
    // Positions are the midpoints of the spans each group occupies on the bar.
    expect(callouts[0].centerPct).toBeCloseTo(83.8111, 3);
  });

  it("stops naming at the first group under the threshold", () => {
    const rows = [
      { index: 0, net: 9, capability: "flow.out", finding: { principal_kind: "eoa" } },
      { index: 1, net: 4, capability: "pause.set", finding: { principal_kind: "eoa" } },
      { index: 2, net: 7, capability: "exec.arbitrary", finding: { principal_kind: "eoa" } },
    ];
    const callouts = calloutsFor(rows, 80);
    // The 7-point group is NOT named: it sits behind a group that fell under
    // the threshold, and callouts read left to right along the bar.
    expect(callouts.map((c) => c.text)).toEqual(["one EOA outflow path", "2 others"]);
  });
});

describe("derive — fix first", () => {
  it("models recovery by re-folding the survivors", () => {
    const fix = fixFirst(ETHERFI, view.rows);
    expect(fix.count).toBe(1);
    expect(fix.subject).toBe("the one Safe upgrade path");
    expect(fix.verb).toBe("Harden");
    expect(fix.recovery).toBe(3.2074);
    expect(fix.lambdaBefore).toBe(78.5611);
    expect(fix.lambdaAfter).toBe(81.7685);
    expect(fix.subsumed).toContain("ownership.transfer");
    expect(fix.subsumed).toContain("pause.set");
    expect(fix.exampleFunction).toBe("upgradeToAndCall");
  });

  it("picks etherfi's leading group because it recovers the most, not because it is first", () => {
    const groups = groupRows(view.rows);
    const recoveries = groups
      .slice(0, 2)
      .map((g) => recoveryFrom(ETHERFI.findings, g.rows.map((r) => r.index)).recovery);
    expect(recoveries).toEqual([3.2074, 1.1074]);
    expect(fixFirst(ETHERFI, view.rows).recovery).toBe(Math.max(...recoveries));
  });

  it("prefers a many-row group over a costlier single row when it recovers more", () => {
    // Six equal 10-point findings: one EOA outflow, then five Safe freezes.
    // The first group charges the most (net 10 against 13.8336 spread over
    // five rows) but removing it only promotes the survivors one rank —
    // 0.7776 points. Removing the five collapses the tail: 13.8336.
    const nets = [10, 6, 3.6, 2.16, 1.296, 0.7776];
    const doc = {
      findings: nets.map((net, i) => ({
        raw_points: 10,
        net_points_lambda: net,
        principal_kind: i === 0 ? "eoa" : "safe",
        capability: i === 0 ? "flow.out" : "pause.set",
      })),
    };
    const rows = deductionRows(doc, buildContractIndex([]));
    const groups = groupRows(rows);
    expect(groups.map((g) => g.sum)).toEqual([10, 13.8336]);
    expect(recoveryFrom(doc.findings, [0]).recovery).toBe(0.7776);
    expect(recoveryFrom(doc.findings, [1, 2, 3, 4, 5]).recovery).toBe(13.8336);

    const fix = fixFirst(doc, rows);
    expect(fix.count).toBe(5);
    expect(fix.subject).toBe("the five Safe freeze switches");
    expect(fix.recovery).toBe(13.8336);
  });
});

describe("derive — the withheld projection", () => {
  const WITHHELD = {
    ...ETHERFI,
    grade_state: "not_determined",
    grade_lambda: null,
    findings: F.map(({ net_points_lambda, ...rest }) => rest),
  };

  it("publishes no λ and nothing derived from one", () => {
    const withheld = projectScore(WITHHELD, []);
    expect(withheld.withheld).toBe(true);
    expect(withheld.lambda).toBeNull();
    expect(withheld.fix).toBeNull();
    expect(withheld.callouts).toEqual([]);
    // The fold could still reconstruct the withheld quantity from the raws —
    // which is exactly why the projection must not ask it to.
    expect(lambdaOf(WITHHELD.findings)).toBe(78.5611);
  });
});

describe("derive — protections", () => {
  it("ranks by λ-delta, not by the finding's own net", () => {
    const rows = protectionRows(ETHERFI);
    expect(rows.map((r) => r.index)).toEqual([3, 1, 7, 0]);
    expect(rows.map((r) => r.delta)).toEqual([51.3656, 32.76, 21.4015, 19.5]);
    // finding 3 charges a point and a third and protects fifty-one: the 10-day
    // timelock is what stands between a $4.16B ceiling and its holder, and the
    // ranking has to read the delta rather than the charge to see that — by the
    // charge it would sit fourth, behind the row it outprotects by thirty-two.
    expect(rows[0].net).toBe(1.3686);
    expect(rows[0].avoidedPct).toBeCloseTo(97.4, 1);
    expect(rows[0].widthPct).toBe(100);
    expect(rows[1].widthPct).toBeCloseTo(71.68, 1);
  });

  it("describes who holds each protection", () => {
    const rows = protectionRows(ETHERFI);
    expect(rows.map((r) => r.who)).toEqual(["via Safe 6/10", "majority", "majority", "minority"]);
    expect(rows[0].what).toBe("upgrade.implementation on >$1B");
  });

  it("carries the value cell whole, direction and all", () => {
    const rows = protectionRows(ETHERFI);
    expect(rows[0].value).toEqual({ determined: true, text: ">$1B", direction: "not_determined" });
    // The flattened text stays for consumers that only print, but it is not
    // the row's only account of the band: `valueText: null` on an unmeasured
    // band is indistinguishable from a row that carries no value at all.
    expect(rows[0].valueText).toBe(">$1B");
    const unmeasured = protectionRows({
      ...ETHERFI,
      findings: ETHERFI.findings.map((f) => ({ ...f, value_band: "not_determined" })),
    });
    expect(unmeasured[0].value).toEqual({ determined: false, text: null, direction: null });
    expect(unmeasured[0].valueText).toBeNull();
  });

  it("excludes principals with no credited coordination", () => {
    const rows = protectionRows(ETHERFI, 99);
    for (const row of rows) {
      expect(["safe", "timelock"]).toContain(row.finding.principal_kind);
      expect(row.finding.weakness).toBeLessThan(0.9);
    }
    expect(rows.some((r) => r.index === 2)).toBe(false); // EOA
    expect(rows.some((r) => r.index === 26)).toBe(false); // anyone
  });
});

describe("derive — cautions", () => {
  it("names a shared key set from the overlap table", () => {
    const cautions = cautionsFor(ETHERFI, F[0]);
    expect(cautions[0].text).toBe(
      "shares 7 owners with Safe 0x5ec5…adde — not an independent key set",
    );
  });

  it("matches every address the principal acts through, not just the displayed one", () => {
    // finding 0's principal string carries 0xf46d…e2b5; its other address
    // 0xa000…cd52 is witnessed only in principal_addresses[], and the overlap
    // 0xa000…cd52 ↔ 0xf46d…e2b5 names neither the displayed address nor the
    // principal_unit. Parsing the string alone drops it.
    expect(principalAddresses(F[0])).toEqual([
      "0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52",
      "0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5",
    ]);
    const overlaps = keysetOverlapsFor(ETHERFI, F[0]);
    expect(overlaps.map((o) => [o.other, o.sharedOwners])).toEqual([
      ["ethereum::0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde", 7],
      ["ethereum::0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde", 5],
      ["ethereum::0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52", 5],
    ]);
    expect(cautionsFor(ETHERFI, F[0])[1].text).toBe(
      "shares 5 owners with Safe 0x5ec5…adde — not an independent key set",
    );
  });

  it("falls back to the principal string when no address list was published", () => {
    const { principal_addresses, ...noList } = F[0];
    expect(principal_addresses).toHaveLength(2);
    expect(principalAddresses(noList)).toEqual(["0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5"]);
    expect(principalAddresses({ principal: "ANYONE anyone" })).toEqual([]);
  });

  it("counts the upgrades that went round a timelock", () => {
    // 15: the upgrade-history fold counts one more safe_direct execution than
    // the 1.4.0 document did, over the same per-contract witnesses.
    expect(upgradeBypassCount(ETHERFI)).toBe(15);
    const cautions = cautionsFor(ETHERFI, F[3]);
    expect(cautions.map((c) => c.text)).toContain(
      "15 witnessed upgrades bypassed this timelock (executed directly by a Safe)",
    );
  });

  it("surfaces the registry self-grant and the unproven proposer set", () => {
    expect(cautionsFor(ETHERFI, F[1]).map((c) => c.text)).toContain(
      "this owner can grant itself any role on the registry it governs",
    );
    const timelock = cautionsFor(ETHERFI, F[8]);
    expect(timelock.find((c) => c.tone === "attr").text).toBe(
      "no delay credit — the proposer set is unproven",
    );
  });

  it("says nothing about a key set the document did not witness as shared", () => {
    // The timelock at 0x80ce… appears in no overlap row that proves a shared
    // coalition can act as both; absence of a witness is not a caution.
    expect(cautionsFor(ETHERFI, F[8]).some((c) => c.text.includes("independent key set"))).toBe(false);
    // …while a Safe that IS witnessed as sharing its whole key set gets one.
    expect(cautionsFor(ETHERFI, F[0])[2].text).toBe(
      "shares 5 owners with Safe 0xa000…cd52 — not an independent key set",
    );
  });
});

describe("derive — audit posture", () => {
  it("reads the published figures rather than re-joining them", () => {
    const posture = auditPosture(ETHERFI);
    // This document is folded over a corpus with almost no audit rows synced:
    // 4 reports discovered, 2 contracts matched, none proven on-chain. The
    // figures are re-pinned to what the producer published rather than held at
    // the richer corpus's numbers.
    expect(posture.reportsOnFile).toBe(4);
    expect(posture.contractsCovered).toBe(2);
    expect(posture.contractsProven).toBe(0);
    expect(posture.contractsTotal).toBe(250);
    expect(posture.trackedTotalUsd).toBe(4262312400.05);
    // value_proven_usd is null — no covered entity was priced — and an
    // unwitnessed numerator has no share, which is a third state and not 0%.
    // The contract side DID answer: 0 of 250 proven is a measured zero.
    expect(posture.valueProvenPct).toBeNull();
    expect(posture.contractProvenPct).toBe(0);
    // The classifier's bucket is absent from this document's
    // non_coverage_classified, so the count is unwitnessed rather than zero.
    expect(posture.provablyDiffers).toBeNull();
  });

  it("keeps an unwitnessed count as null rather than 0", () => {
    const posture = auditPosture({
      provenance: {
        value: { tracked_total_usd: null },
        audit_posture: {
          reports_on_file: null,
          contracts_covered: null,
          contracts_proven: null,
          contracts_total: 210,
          value_covered_usd: null,
          value_proven_usd: null,
          non_coverage_classified: {},
        },
      },
    });
    expect(posture.reportsOnFile).toBeNull();
    expect(posture.contractsCovered).toBeNull();
    expect(posture.valueProvenPct).toBeNull();
    expect(posture.contractProvenPct).toBeNull();
    expect(posture.provablyDiffers).toBeNull();
  });

  it("has nothing to report when the document carries no posture block", () => {
    expect(auditPosture({})).toBeNull();
  });
});

describe("derive — confidence", () => {
  it("tags whichever channel actually is the minimum", () => {
    const channels = confidenceChannels(ETHERFI);
    // Read off the document: value_priced_pct is nowhere near the floor —
    // it sits at 65.1 while the magnitude term is at 43.6 and holds the
    // minimum. That the tag follows the data rather than a pinned channel is
    // the property under test.
    expect(channels.map((c) => c.pct)).toEqual([46, 60.4, 65.1, 43.6]);
    expect(channels.filter((c) => c.isMin).map((c) => c.id)).toEqual([
      "reach_magnitude_witnessed_pct",
    ]);
  });

  it("moves the tag when a different channel is lowest", () => {
    const channels = confidenceChannels({
      model_parameters: {
        confidence_detail: {
          capability_scored_pct: 80,
          reachability_answered_pct: 12,
          value_priced_pct: 40,
        },
      },
    });
    expect(channels.filter((c) => c.isMin).map((c) => c.id)).toEqual(["reachability_answered_pct"]);
  });

  it("leaves an unmeasured channel null and never tags it as the minimum", () => {
    const channels = confidenceChannels({
      model_parameters: { confidence_detail: { capability_scored_pct: 30 } },
    });
    expect(channels[1].pct).toBeNull();
    expect(channels.filter((c) => c.isMin).map((c) => c.id)).toEqual(["capability_scored_pct"]);
  });
});

describe("derive — sheet disposition (1.4.0 airdrop_determined)", () => {
  const disposedFinding = (over = {}) => ({
    ...F[0],
    reach_sheet_ceiling_magnitudes: [
      {
        entity: "ethereum::0x1b7a4c37c5b2b0b3b0d0f0a0b0c0d0e0f0a0b0c0",
        published_usd: 0,
        sheet_usd: 0,
        sheet_state: "airdrop_determined",
        ceiling_reason: "airdrop_determined",
        bound_direction: "ceiling",
      },
    ],
    ...over,
  });

  it("labels the new sheet state and ceiling reason rather than dropping them", () => {
    // The label tables are NOT allow-lists: a token the page cannot name is
    // still a token the document published, so the fall-through is the raw
    // token and never a blank.
    expect(sheetStateLabel("airdrop_determined")).toBe("airdrop-delivered");
    expect(ceilingReasonLabel("airdrop_determined")).toBe("airdrop-delivered");
    expect(sheetStateLabel("some_future_state")).toBe("some_future_state");
    expect(ceilingReasonLabel("some_future_reason")).toBe("some_future_reason");
    expect(sheetStateLabel(null)).toBeNull();
  });

  it("carries the disposed figure WITH its reason, so $0 is never bare", () => {
    const d = sheetDisposition(disposedFinding());
    expect(d.count).toBe(1);
    expect(d.usd).toBe(0);
    expect(d.usdText).toBe("$0");
    expect(d.label).toBe("airdrop-delivered");
    // The SUBSTANCE of the sentence, not just that it mentions a distribution.
    // The superseded note said these holdings are "not presented as positions
    // this protocol holds", which describes what the page does and lets a
    // reader assume the $0 covers them. It does not, and the two clauses that
    // say so are the ones worth pinning: the holdings are still held, and this
    // document does not value them.
    expect(d.reason).toMatch(/STILL HELD/);
    expect(d.reason).toMatch(/not_determined/);
    expect(d.reason).toMatch(/PRICES/);
    expect(d.reason).toMatch(/mass distribution/i);
    // And it must NOT revert to describing the page's own behaviour.
    expect(d.reason).not.toMatch(/not presented as positions/i);
    // A DELIVERY claim. Real tokens arrive this way, so none of these words may
    // appear beside the figure.
    for (const word of [/spam/i, /scam/i, /junk/i, /worthless/i]) {
      expect(d.reason).not.toMatch(word);
    }
  });

  it("publishes no number rather than another zero when the document withheld one", () => {
    const d = sheetDisposition(
      disposedFinding({
        reach_sheet_ceiling_magnitudes: [
          { entity: "ethereum::0xabc", published_usd: null, sheet_state: "airdrop_determined" },
        ],
      }),
    );
    expect(d.usd).toBeNull();
    expect(d.usdText).toBeNull();
  });

  it("reads the shipped document's own disposed rows and no others", () => {
    // The golden's corpus no longer determines ANY sheet by delivery shape —
    // provenance.value.sheet_states counts airdrop_determined at 0, and so does
    // the ceiling-reason census — so the count re-pins from 1 to 0. That is the
    // document's own witnessed zero, not an unasked question, and it makes this
    // a pure negative control again: no row may grow a disposition the document
    // does not name.
    expect(ETHERFI.provenance.value.sheet_states.airdrop_determined).toBe(0);
    const disposed = F.filter((finding) => sheetDisposition(finding) !== null);
    expect(disposed.length).toBe(0);
  });

  it("reaches the deduction row so the cell can render it", () => {
    const doc = { findings: F.map((f, i) => (i === 0 ? disposedFinding() : f)) };
    const rows = deductionRows(doc, buildContractIndex([]));
    const row = rows.find((r) => r.index === 0);
    expect(row.sheetDisposition.usdText).toBe("$0");
    // The constructed row and nothing else: the golden itself carries no
    // disposed sheet, so the only cell that may render one is the row the
    // substitution above put it on.
    expect(rows.filter((r) => r.sheetDisposition).length).toBe(1);
  });

  it("leaves BOUND_DIRECTIONS alone — the disposition is not a direction", () => {
    // The bound direction of a disposed sheet ceiling is still `ceiling`; the
    // new token belongs to the state/reason vocabularies and must not be smuggled
    // into the direction allow-list, where it would render as a bound nobody proved.
    expect(BOUND_DIRECTIONS).toEqual(["floor", "ceiling", "not_determined"]);
    expect(valueCell({ value_band: "<$100k", value_at_stake_bound_direction: "airdrop_determined" }).direction).toBeNull();
  });
});
