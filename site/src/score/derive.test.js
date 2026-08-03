import { describe, it, expect } from "vitest";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import {
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
  upgradeBypassCount,
  valueCell,
} from "./derive.js";
import { lambdaOf, recoveryFrom } from "./fold.js";

const F = ETHERFI.findings;
const view = projectScore(ETHERFI, []);

describe("derive — principals", () => {
  it("reads the controller off the principal string, never principal_unit", () => {
    // finding 3's principal_unit is a member of the Safe; the acting principal
    // is the Safe itself. Naming the member would attribute k-of-n power to one
    // key holder.
    expect(F[3].principal_unit).toBe("ethereum::0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde");
    expect(controllerAddress(F[3])).toBe("0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52");
    expect(controllerAddress(F[10])).toBeNull(); // "ANYONE anyone" carries no address
  });

  it("parses the principal shape into a chip", () => {
    expect(principalChip(F[0])).toEqual({ kind: "eoa", label: "EOA" });
    expect(principalChip(F[2])).toEqual({ kind: "timelock", label: "Timelock 2d" });
    expect(principalChip(F[3])).toEqual({ kind: "safe", label: "Safe 3/7" });
    expect(principalChip(F[7])).toEqual({ kind: "timelock", label: "Timelock 10d" });
    expect(principalChip(F[10])).toEqual({ kind: "anyone", label: "Anyone" });
  });

  it("names the coalition from k/n, not from the weakness rung", () => {
    // 0.55 is both safe_minority and safe_uncredited on the ladder; inverting
    // it would have to guess.
    expect(coalitionWord(safeShape(F[4]))).toBe("majority"); // 4/6
    expect(coalitionWord(safeShape(F[3]))).toBe("minority"); // 3/7
    expect(coalitionWord({ k: 1, n: 5 })).toBe("single signer");
    expect(coalitionWord({ k: 5, n: 7 })).toBe("supermajority");
    expect(coalitionWord(null)).toBeNull();
  });

  it("distinguishes a routed timelock from an unproven proposer set", () => {
    expect(timelockProposer(F[7])).toEqual({ text: "via Safe 6/10", proven: true });
    expect(timelockProposer(F[2])).toEqual({ text: "proposer unproven", proven: false });
  });
});

describe("derive — value cell", () => {
  it("strips the floor prefix and tags the floor separately", () => {
    expect(valueCell(F[0])).toEqual({ determined: true, text: "$1M-$10M", floor: true });
    expect(valueCell(F[6])).toEqual({ determined: true, text: "<$100k", floor: false });
    expect(valueCell(F[5])).toEqual({ determined: true, text: ">$1B", floor: true });
  });

  it("keeps not_determined as a third state — never $0, never blank", () => {
    const cell = valueCell(F[10]);
    expect(cell.determined).toBe(false);
    expect(cell.text).toBeNull();
    expect(F[10].value_band).toBe("not_determined");
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
    expect(F[12].reach_entities).toHaveLength(0);
    const rows = deductionRows(ETHERFI, index);
    const row = rows.find((r) => r.index === 12);
    expect(row.reachWitnessed).toBe(false);
    expect(row.targets.length).toBe(undeterminedTargets(F[12], index).length);
    expect(row.targets.length).toBeGreaterThan(0);
  });
});

describe("derive — rows and ledger", () => {
  it("scales both bars against the largest raw points", () => {
    const [first, second, third] = view.rows;
    expect(first.trackPct).toBeCloseTo(100, 6);
    expect(first.fillPct).toBeCloseTo(100, 6);
    expect(second.fillPct).toBeCloseTo(60, 6);
    expect(third.trackPct).toBeCloseTo((16.5 / 20.25) * 100, 6);
  });

  it("merges everything under 0.4 points into one tail segment", () => {
    const { kept, segments } = ledgerSegments(view.rows, ETHERFI.grade_lambda);
    expect(kept).toBe(54.7638);
    expect(segments).toHaveLength(7);
    expect(segments.at(-1).id).toBe("tail");
    expect(segments.at(-1).title).toBe("13 more findings · −0.63");
    expect(segments[0].title).toBe("EOA · authority.replace · −20.25");
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
    expect(rows[0].fillPct).toBeCloseTo((19.5 / 20.25) * 100, 6);
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
    expect(rows[0].raw).toBe(20.25);
    expect(rows[0].fillPct).toBe(0);
  });
});

describe("derive — callouts", () => {
  it("groups consecutive rows sharing (principal_kind, capability)", () => {
    const groups = groupRows(view.rows);
    expect(groups[0].rows.map((r) => r.index)).toEqual([0, 1]);
    expect(groups[0].kind).toBe("eoa");
    expect(groups[0].sum).toBe(32.4);
    expect(groups[1].rows.map((r) => r.index)).toEqual([2]);
    expect(groups[1].kind).toBe("timelock");
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
      "two EOA authority holes",
      "one Timelock authority hole",
      "16 others",
    ]);
    expect(callouts[0].sum).toBe(32.4);
    expect(callouts[1].sum).toBe(5.94);
    expect(callouts[2].sum).toBeCloseTo(6.8962, 3);
    // Positions are the midpoints of the spans each group occupies on the bar.
    expect(callouts[0].centerPct).toBeCloseTo(70.9638, 3);
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
    expect(fix.count).toBe(2);
    expect(fix.subject).toBe("the two EOA authority holes");
    expect(fix.verb).toBe("Move");
    expect(fix.recovery).toBe(9.5799);
    expect(fix.lambdaBefore).toBe(54.7638);
    expect(fix.lambdaAfter).toBe(64.3437);
    expect(fix.subsumed).toEqual(["ownership.transfer", "pause.set"]);
    expect(fix.exampleFunction).toBe("setAuthority");
  });

  it("picks etherfi's leading group because it recovers the most, not because it is first", () => {
    const groups = groupRows(view.rows);
    const recoveries = groups
      .slice(0, 2)
      .map((g) => recoveryFrom(ETHERFI.findings, g.rows.map((r) => r.index)).recovery);
    expect(recoveries).toEqual([9.5799, 1.3424]);
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
    expect(lambdaOf(WITHHELD.findings)).toBe(54.7638);
  });
});

describe("derive — protections", () => {
  it("ranks by λ-delta, not by the finding's own net", () => {
    const rows = protectionRows(ETHERFI);
    expect(rows.map((r) => r.index)).toEqual([7, 4, 2, 3]);
    expect(rows.map((r) => r.delta)).toEqual([41.8457, 23.3333, 11.1, 11.1]);
    // finding 7 charges the least of the four and protects the most.
    expect(rows[0].net).toBe(0.1774);
    expect(rows[0].avoidedPct).toBeCloseTo(99.58, 1);
    expect(rows[0].widthPct).toBe(100);
    expect(rows[1].widthPct).toBeCloseTo(60.06, 1);
  });

  it("describes who holds each protection", () => {
    const rows = protectionRows(ETHERFI);
    expect(rows.map((r) => r.who)).toEqual(["via Safe 6/10", "majority", "proposer unproven", "minority"]);
    expect(rows[0].what).toBe("upgrade.implementation on >$1B");
  });

  it("excludes principals with no credited coordination", () => {
    const rows = protectionRows(ETHERFI, 99);
    for (const row of rows) {
      expect(["safe", "timelock"]).toContain(row.finding.principal_kind);
      expect(row.finding.weakness).toBeLessThan(0.9);
    }
    expect(rows.some((r) => r.index === 0)).toBe(false); // EOA
    expect(rows.some((r) => r.index === 10)).toBe(false); // anyone
  });
});

describe("derive — cautions", () => {
  it("names a shared key set from the overlap table", () => {
    const cautions = cautionsFor(ETHERFI, F[3]);
    expect(cautions[0].text).toBe(
      "shares 7 owners with Safe 0x5ec5…adde — not an independent key set",
    );
  });

  it("matches every address the principal acts through, not just the displayed one", () => {
    // finding 3's principal string carries 0xa000…cd52; its second address
    // 0xf46d…e2b5 is witnessed only in principal_addresses[], and the overlap
    // 0x5ec5…adde ↔ 0xf46d…e2b5 names neither the displayed address nor the
    // principal_unit. Parsing the string alone drops it.
    expect(principalAddresses(F[3])).toEqual([
      "0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52",
      "0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5",
    ]);
    const overlaps = keysetOverlapsFor(ETHERFI, F[3]);
    expect(overlaps.map((o) => [o.other, o.sharedOwners])).toEqual([
      ["ethereum::0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde", 7],
      ["ethereum::0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde", 5],
      ["ethereum::0xf46d3734564ef9a5a16fc3b1216831a28f78e2b5", 5],
    ]);
    expect(cautionsFor(ETHERFI, F[3])[1].text).toBe(
      "shares 5 owners with Safe 0x5ec5…adde — not an independent key set",
    );
  });

  it("falls back to the principal string when no address list was published", () => {
    const { principal_addresses, ...noList } = F[3];
    expect(principal_addresses).toHaveLength(2);
    expect(principalAddresses(noList)).toEqual(["0xa000244b4a36d57ea1ecb39b5f02f255e4c8cd52"]);
    expect(principalAddresses({ principal: "ANYONE anyone" })).toEqual([]);
  });

  it("counts the upgrades that went round a timelock", () => {
    expect(upgradeBypassCount(ETHERFI)).toBe(12);
    const cautions = cautionsFor(ETHERFI, F[7]);
    expect(cautions.map((c) => c.text)).toContain(
      "12 witnessed upgrades bypassed this timelock (executed directly by a Safe)",
    );
  });

  it("surfaces the registry self-grant and the unproven proposer set", () => {
    expect(cautionsFor(ETHERFI, F[4]).map((c) => c.text)).toContain(
      "this owner can grant itself any role on the registry it governs",
    );
    const timelock = cautionsFor(ETHERFI, F[2]);
    expect(timelock.find((c) => c.tone === "attr").text).toBe(
      "no delay credit — the proposer set is unproven",
    );
  });

  it("says nothing about a key set the document did not witness as shared", () => {
    // The timelock at 0x80ce… appears in no overlap row that proves a shared
    // coalition can act as both; absence of a witness is not a caution.
    expect(cautionsFor(ETHERFI, F[2]).some((c) => c.text.includes("independent key set"))).toBe(false);
    // …while a Safe that IS witnessed as sharing its whole key set gets one.
    expect(cautionsFor(ETHERFI, F[5])[0].text).toBe(
      "shares 5 owners with Safe 0x2aca…8adc — not an independent key set",
    );
  });
});

describe("derive — audit posture", () => {
  it("reads the published figures rather than re-joining them", () => {
    const posture = auditPosture(ETHERFI);
    expect(posture.reportsOnFile).toBe(64);
    expect(posture.contractsCovered).toBe(54);
    expect(posture.contractsProven).toBe(35);
    expect(posture.contractsTotal).toBe(210);
    expect(posture.trackedTotalUsd).toBe(4169179083.82);
    expect(posture.valueProvenPct).toBeCloseTo(97.75, 2);
    expect(posture.contractProvenPct).toBeCloseTo(16.67, 2);
    expect(posture.provablyDiffers).toBe(13);
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
    expect(channels.map((c) => c.pct)).toEqual([20.7, 39.2, 40.8]);
    expect(channels.filter((c) => c.isMin).map((c) => c.id)).toEqual(["capability_scored_pct"]);
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
