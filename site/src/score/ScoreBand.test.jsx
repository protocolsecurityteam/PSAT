import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import ScoreBand from "./ScoreBand.jsx";

const CONTRACTS = [
  { address: "0x352180974c71f84a934953cf49c4e538a6f9c997", chain: "ethereum", name: "BoringVault" },
  {
    address: "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
    chain: "ethereum",
    name: "WeETH",
    implementation: "0xa6ca0607190d03cf16fe6f2865cf40c3d160ccf3",
  },
];

function renderBand(props = {}) {
  return render(
    <ScoreBand companyName="etherfi" contracts={CONTRACTS} score={null} error={null} {...props} />,
  );
}

async function openBreakdown() {
  await userEvent.setup().click(screen.getByRole("button", { name: /Full score breakdown/i }));
}

describe("ScoreBand — states", () => {
  it("renders a loading state before either answer arrives", () => {
    renderBand();
    expect(screen.getByText(/Loading the protocol score/i)).toBeInTheDocument();
  });

  it("tells an unknown company apart from an unscored one", () => {
    const unknown = renderBand({
      error: { status: 404, message: '{"detail":"Company not found"}' },
    });
    expect(screen.getByText(/not in the scorer's registry/i)).toBeInTheDocument();
    expect(screen.queryByText(/No score has been computed/i)).not.toBeInTheDocument();
    unknown.unmount();

    renderBand({
      error: {
        status: 404,
        message: '{"detail":"No score has been computed for this protocol yet"}',
      },
    });
    expect(screen.getByText(/No score has been computed for this protocol yet/i)).toBeInTheDocument();
    expect(screen.queryByText(/registry/i)).not.toBeInTheDocument();
  });

  it("renders an unreadable document as a load failure, not as an absent score", () => {
    renderBand({
      error: {
        status: 503,
        message: '{"detail":"Score document could not be read: object missing"}',
      },
    });
    expect(screen.getByText(/could not be loaded — try again/i)).toBeInTheDocument();
    expect(screen.getByText(/not an absent score/i)).toBeInTheDocument();
    expect(screen.queryByText(/No score has been computed/i)).not.toBeInTheDocument();
  });

  it("does not crash on a payload with no findings", () => {
    renderBand({ score: {} });
    expect(screen.getByText(/No score has been computed/i)).toBeInTheDocument();
  });
});

describe("ScoreBand — computed grade", () => {
  it("renders the letter, λ, ledger and stats from the document", () => {
    const { container } = renderBand({ score: ETHERFI });
    expect(screen.getByText("B+")).toBeInTheDocument();
    expect(screen.getByText("78.6")).toBeInTheDocument();
    expect(screen.getByText(/provisional · confidence 43.6%/)).toBeInTheDocument();
    expect(screen.getByText("78.6 kept")).toBeInTheDocument();
    expect(screen.getByText("99.7")).toBeInTheDocument();
    expect(screen.getByText("+67 subsumed")).toBeInTheDocument();
    // kept + 6 deduction segments + the sub-0.4pt tail
    expect(container.querySelectorAll(".sc-ledger-seg")).toHaveLength(8);
    expect(container.querySelector(".sc-ledger-seg.sc-ded").getAttribute("title")).toBe(
      "Safes 3/7 + 4/8 · shared keys · upgrade.implementation · −10.50",
    );
  });

  it("hands each merged-unit member its own handle on the kind chip", async () => {
    // Finding 0 folds two Safes a shared-key coalition can act as. Each k/n on
    // the chip selects its own Safe — one button would have to pick a member
    // for the user, and rendering one member alone would attribute the other
    // member's gates to it.
    const members = ETHERFI.findings[0].principal_addresses;
    expect(members).toHaveLength(2);
    const onSelectEntity = vi.fn();
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    const chip = container.querySelectorAll(".sc-frow")[0].querySelector(".sc-kchip");
    expect(chip.textContent).toBe("Safes 3/7 + 4/8 · shared keys");
    const user = userEvent.setup();
    await user.click(within(chip).getByRole("button", { name: "3/7" }));
    expect(onSelectEntity).toHaveBeenLastCalledWith({
      chain: "ethereum",
      address: members[0],
      label: "Safe 3/7",
    });
    await user.click(within(chip).getByRole("button", { name: "4/8" }));
    expect(onSelectEntity).toHaveBeenLastCalledWith({
      chain: "ethereum",
      address: members[1],
      label: "Safe 4/8",
    });
  });

  it("keeps the breakdown collapsed until asked", async () => {
    const { container } = renderBand({ score: ETHERFI });
    expect(container.querySelector(".score-breakdown")).toBeNull();
    await openBreakdown();
    expect(container.querySelector(".score-breakdown")).toBeTruthy();
    expect(screen.getByText("Deductions")).toBeInTheDocument();
    expect(screen.getByText("Protections")).toBeInTheDocument();
  });

  it("renders the top 8 deduction rows and hides the tail behind its summary", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    expect(container.querySelectorAll(".sc-frow")).toHaveLength(8);
    const tail = screen.getByRole("button", { name: /20 more/ });
    expect(tail.textContent).toContain("−0.19 combined");
    // 16 of the 20 tail rows answer "how much" with nothing at all. The count
    // tracks the document rather than a pinned constant.
    expect(tail.textContent).toContain("16 with value not determined");
    await userEvent.setup().click(tail);
    expect(container.querySelectorAll(".sc-frow")).toHaveLength(28);
  });

  it("renders a disposed sheet as $0 WITH its delivery-shape reason, never as a bare zero", async () => {
    // 1.4.0. A sheet whose remaining holdings all arrived by mass distribution
    // publishes a $0 ceiling. A bare $0 in this cell reads as "this reaches
    // nothing" — a different claim, and one nobody proved — so the figure is
    // rendered with its reason attached, and the reason is about DELIVERY.
    const disposed = {
      ...ETHERFI,
      findings: ETHERFI.findings.map((f, i) =>
        i === 0
          ? {
              ...f,
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
            }
          : f,
      ),
    };
    const { container } = renderBand({ score: disposed });
    await openBreakdown();
    const cells = [...container.querySelectorAll(".sc-val")];
    const badge = cells.map((c) => within(c).queryByText(/airdrop-delivered/i)).find(Boolean);
    expect(badge).toBeTruthy();
    expect(badge.textContent).toContain("$0");
    expect(badge.getAttribute("title")).toMatch(/mass distribution/i);
    // Never a claim about worth: real tokens arrive this way too.
    for (const word of [/spam/i, /scam/i, /junk/i, /worthless/i]) {
      expect(badge.getAttribute("title")).not.toMatch(word);
    }
    // And the badge is never blank — an unlabelled zero is the shape this
    // replaces.
    expect(badge.textContent.trim()).not.toBe("");
  });

  it("grows no disposition badge where the shipped document names none", async () => {
    // This corpus determines NO sheet by delivery shape — the state census
    // counts airdrop_determined at 0 — so the positive arm lives on the
    // constructed document above and what is left here is the negative, which
    // still has teeth: nineteen rows carry an unanswered or tiny value, and a
    // badge that appeared on any of them would be a state invented by the page.
    const carriers = ETHERFI.findings
      .map((f, i) => [
        i,
        (f.reach_sheet_ceiling_magnitudes || []).filter(
          (m) => m?.ceiling_reason === "airdrop_determined" || m?.sheet_state === "airdrop_determined",
        ),
      ])
      .filter(([, records]) => records.length > 0);
    expect(carriers).toHaveLength(0);

    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    // Every row, tail included — a badge hiding behind the summary is still a
    // badge the document did not witness.
    await userEvent.setup().click(screen.getByRole("button", { name: /20 more/ }));
    const cells = [...container.querySelectorAll(".sc-val")];
    expect(cells).toHaveLength(ETHERFI.findings.length);
    const badges = cells.map((c) =>
      [...c.querySelectorAll(".sc-fl")].find((b) => /airdrop-delivered/i.test(b.textContent)),
    );
    expect(badges.filter(Boolean)).toHaveLength(0);
    for (const cell of cells) expect(cell.textContent).not.toMatch(/airdrop/i);
  });

  it("tags a bound the producer proved and italicises an undetermined one — never $0", async () => {
    // The corpus carries NO floor row: the producer withdrew the direction from
    // every row that had one, because a total summed out of extraction ceilings
    // is not an at-least. What each priced row wears is the fall-through badge,
    // which is a published state and not a missing field.
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    await userEvent.setup().click(screen.getByRole("button", { name: /20 more/ }));
    const cells = [...container.querySelectorAll(".sc-val")];
    expect(cells.some((c) => within(c).queryByText("floor"))).toBe(false);
    const priced = cells.find((c) => c.textContent.startsWith("$1M-$10M"));
    expect(within(priced).getByText("bound not determined")).toBeInTheDocument();
    const nd = cells.filter((c) => c.querySelector(".sc-nd"));
    // 19 of the 28 rows: this corpus prices nine and leaves the rest with no
    // band at all, and a band nobody measured is a blank cell's own state.
    expect(nd).toHaveLength(19);
    expect(nd[0].textContent).toBe("value not determined");
    expect(cells.some((c) => c.textContent.trim() === "$0")).toBe(false);
  });

  it("never paints a floor on a total the producer bounds the other way", async () => {
    // The producer's two claims and its fall-through, on three rows of one
    // document: the ceiling and the undetermined bound must not read as an
    // at-least, and a row whose document names no direction — the boolean
    // alone cannot answer it — wears no badge at all.
    const doc = structuredClone(ETHERFI);
    const [ceiling, unbounded, silent] = doc.findings;
    Object.assign(ceiling, { value_band: "<= $1M-$10M", value_at_stake_bound_direction: "ceiling" });
    Object.assign(unbounded, {
      value_band: "$1M-$10M",
      value_at_stake_bound_direction: "not_determined",
      value_at_stake_is_floor: false,
    });
    // No direction field at all — the shape every pre-existing document has.
    delete silent.value_at_stake_bound_direction;
    Object.assign(silent, { value_band: "$1M-$10M", value_at_stake_is_floor: true });
    const { container } = render(
      <ScoreBand companyName="etherfi" contracts={CONTRACTS} score={doc} error={null} />,
    );
    await openBreakdown();
    await userEvent.setup().click(screen.getByRole("button", { name: /20 more/ }));
    const cells = [...container.querySelectorAll(".sc-val")].filter((c) =>
      c.textContent.includes("$1M-$10M"),
    );
    const badges = cells.map((cell) => {
      // The qualifier is carried as a badge, never left on the band text.
      expect(cell.textContent).not.toContain(">=");
      expect(cell.textContent).not.toContain("<=");
      return cell.querySelector(".sc-fl")?.textContent ?? null;
    });
    // Four cells, not three: row 7 is banded $1M-$10M in the shipped document
    // and the case does not touch it, so it keeps whatever the producer
    // published — which is the fall-through badge.
    expect(badges.sort()).toEqual([
      "bound not determined",
      "bound not determined",
      "ceiling",
      null,
    ]);
  });

  it("marks unwitnessed reach differently from proven reach", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    await userEvent.setup().click(screen.getByRole("button", { name: /20 more/ }));
    const targets = [...container.querySelectorAll(".sc-targets")];
    const unwitnessed = targets.filter((t) => t.textContent.includes("reach not witnessed"));
    expect(unwitnessed.length).toBeGreaterThan(0);
    for (const row of unwitnessed) expect(row.querySelector(".sc-arr")).toBeNull();
    const witnessed = targets.filter((t) => t.querySelector(".sc-arr"));
    expect(witnessed.length).toBeGreaterThan(0);
    for (const row of witnessed) expect(row.textContent).not.toContain("reach not witnessed");
  });

  it("expands a target list in place and collapses it again", async () => {
    const user = userEvent.setup();
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    // Row 1, not row 0: row 0's three hosts and no reach all fit on the
    // collapsed line, so it has nothing to expand. Row 1 hides sixty-one hosts
    // and twelve reached contracts behind the control.
    const firstRow = container.querySelectorAll(".sc-frow")[1].querySelector(".sc-targets");
    const more = /\+\d+ more/;
    expect(within(firstRow).getByRole("button", { name: more })).toBeInTheDocument();
    await user.click(within(firstRow).getByRole("button", { name: more }));
    expect(within(firstRow).getByRole("button", { name: "less" })).toBeInTheDocument();
    expect(firstRow.textContent).toContain("0xeda6…4e70");
    await user.click(within(firstRow).getByRole("button", { name: "less" }));
    expect(within(firstRow).getByRole("button", { name: more })).toBeInTheDocument();
  });

  it("renders the modeled fix-first recovery from a re-fold", async () => {
    renderBand({ score: ETHERFI });
    await openBreakdown();
    const fix = screen.getByText(/modeled recovery up to/).closest(".sc-fix");
    expect(fix.textContent).toContain("Harden the one Safe upgrade path");
    expect(fix.textContent).toContain("3.2 points");
    expect(fix.textContent).toContain("λ 78.6 → 81.8");
    expect(fix.textContent).toContain("ownership.transfer");
    expect(fix.textContent).toContain("fixing upgradeToAndCall alone does not release them");
  });

  it("renders the protections column and the audit posture verbatim", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    expect(screen.getByText(/each dollar weighted by how dangerous/)).toBeInTheDocument();
    const saved = [...container.querySelectorAll(".sc-prot-saved")].map((n) => n.textContent);
    expect(saved).toEqual(["+51.4", "+32.8", "+21.4", "+19.5"]);
    expect(screen.getByText("4 reports on file")).toBeInTheDocument();
    expect(screen.getByText(/15 witnessed upgrades bypassed this timelock/)).toBeInTheDocument();
    const byContract = screen.getByText(/contracts matched to an audit/);
    expect(byContract.textContent).toContain("2 / 250");
    expect(byContract.textContent).toContain("0 proven on-chain");
  });

  it("publishes no provably-differs warning, whatever the count says", async () => {
    // The classifier's "deployed source provably differs" bucket does not hold
    // to the standard the word claims, so the line is not rendered — the number
    // stays in the payload and in the projection (derive.test.js pins it) for a
    // consumer that can qualify it. This corpus classifies none into that
    // bucket, so the positive arm is carried on a constructed document: with a
    // count of 13 in hand the page must still publish nothing.
    expect(
      ETHERFI.provenance.audit_posture.non_coverage_classified,
    ).not.toHaveProperty("deployed_source_provably_differs");
    const counted = {
      ...ETHERFI,
      provenance: {
        ...ETHERFI.provenance,
        audit_posture: {
          ...ETHERFI.provenance.audit_posture,
          non_coverage_classified: {
            ...ETHERFI.provenance.audit_posture.non_coverage_classified,
            deployed_source_provably_differs: 13,
          },
        },
      },
    };
    const withCount = renderBand({ score: counted });
    await openBreakdown();
    expect(screen.queryByText(/provably differs/)).not.toBeInTheDocument();
    withCount.unmount();

    renderBand({ score: ETHERFI });
    await openBreakdown();
    expect(screen.queryByText(/provably differs/)).not.toBeInTheDocument();
  });

  it("renders no earned-negatives line when the corpus has none", async () => {
    // The shipped corpus now witnesses six — the self-service payout proofs —
    // so the empty arm is constructed. An empty list is a proven zero and still
    // gets no line: nothing to say is said with nothing.
    expect(ETHERFI.earned_negatives).toHaveLength(6);
    renderBand({ score: { ...ETHERFI, earned_negatives: [] } });
    await openBreakdown();
    expect(screen.queryByText(/proven to have no reach/)).not.toBeInTheDocument();
  });

  it("renders an earned-negatives line when there are any", async () => {
    renderBand({
      score: { ...ETHERFI, earned_negatives: [{ entity: "a" }, { entity: "b" }] },
    });
    await openBreakdown();
    expect(screen.getByText(/functions proven to have no reach/).textContent).toContain("2");
  });

  it("tags the confidence channel that is the minimum", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    const channels = [...container.querySelectorAll(".sc-channel")];
    // Four terms, all four measured on this document; the tag follows whichever
    // is actually lowest rather than the one that happened to be first. On this
    // document that is the FOURTH channel — reach magnitude witnessed at 43.6,
    // which is also the published confidence_pct, so the headline and the tag
    // name the same term.
    expect(channels).toHaveLength(4);
    expect(channels[0].querySelector(".sc-hd")).toBeNull();
    expect(channels[1].querySelector(".sc-hd")).toBeNull();
    expect(channels[2].querySelector(".sc-hd")).toBeNull();
    expect(channels[3].querySelector(".sc-hd").textContent).toBe("min");
    expect(container.querySelector(".scz-big").textContent).toBe(`${ETHERFI.confidence_pct.toFixed(1)}%`);
    expect(screen.getByText(/how much of the protocol the grade is built on/)).toBeInTheDocument();
  });

  it("renders λ with no letter when the model version has no band table", () => {
    renderBand({ score: { ...ETHERFI, model_version: "9.9.9-unreleased" } });
    expect(screen.getByText("78.6")).toBeInTheDocument();
    expect(screen.queryByText("B+")).not.toBeInTheDocument();
    expect(screen.getByText(/bands uncalibrated for this model version/)).toBeInTheDocument();
  });

  it("hides the provisional badge once confidence clears 50%", () => {
    renderBand({ score: { ...ETHERFI, confidence_pct: 72.4 } });
    expect(screen.queryByText(/provisional/)).not.toBeInTheDocument();
  });
});

describe("ScoreBand — withheld grade", () => {
  const WITHHELD = {
    ...ETHERFI,
    grade_state: "not_determined",
    grade_lambda: null,
    grade_exposure: null,
    confidence_pct: null,
    findings: ETHERFI.findings.map(({ net_points_lambda, exposure_usd, ...rest }) => rest),
    provenance: {
      ...ETHERFI.provenance,
      exposure_usd: null,
      grade_withheld: {
        grade_lambda_computed: 54.7638,
        confidence_pct_computed: 20.7,
        exposure_usd_computed: 1178742982.54,
        reason: "no priced value in the perimeter, so the exposure denominator is not_determined",
        per_finding: [],
      },
    },
  };

  it("publishes no letter, no λ and no ledger", () => {
    const { container } = renderBand({ score: WITHHELD });
    expect(screen.getByText("The grade is withheld.")).toBeInTheDocument();
    expect(screen.queryByText("B+")).not.toBeInTheDocument();
    expect(container.querySelector(".sc-ledger-bar")).toBeNull();
    expect(container.querySelector(".sc-grade-letter")).toBeNull();
  });

  it("reads the computed figures out of provenance.grade_withheld", () => {
    renderBand({ score: WITHHELD });
    expect(screen.getByText(/no priced value in the perimeter/)).toBeInTheDocument();
    expect(screen.getByText("54.76")).toBeInTheDocument();
    expect(screen.getByText("20.7%")).toBeInTheDocument();
  });

  it("shows raw points with no net column, and no exposure tile", async () => {
    const { container } = renderBand({ score: WITHHELD });
    await openBreakdown();
    const points = [...container.querySelectorAll(".sc-pts")].map((n) => n.textContent);
    expect(points[0]).toBe("10.50");
    expect(points.some((p) => p.startsWith("−"))).toBe(false);
    expect(container.querySelector(".sc-shield")).toBeNull();
    expect(container.querySelector(".sc-prot")).toBeNull();
  });

  it("still publishes the audit posture, which is not a grade quantity", async () => {
    renderBand({ score: WITHHELD });
    await openBreakdown();
    expect(screen.getByText("4 reports on file")).toBeInTheDocument();
  });

  it("publishes no fix-first, because its whole claim is a λ the producer withheld", async () => {
    const { container } = renderBand({ score: WITHHELD });
    await openBreakdown();
    expect(container.querySelector(".sc-fix")).toBeNull();
    expect(screen.queryByText(/modeled recovery/)).not.toBeInTheDocument();
    expect(screen.queryByText(/rank decay promotes/)).not.toBeInTheDocument();
    // The λ is reconstructible from the raw points — nothing in the breakdown
    // may quote it, under that name or as a bare number.
    const breakdown = container.querySelector(".score-breakdown");
    expect(breakdown.textContent).not.toContain("λ");
    expect(breakdown.textContent).not.toContain("54.7");
    expect(breakdown.textContent).not.toContain("64.3");
  });

  it("summarises the tail as not-determined rather than −0.00 combined", async () => {
    renderBand({ score: WITHHELD });
    await openBreakdown();
    const tail = screen.getByRole("button", { name: /20 more/ });
    expect(tail.textContent).toContain("combined points not determined");
    expect(tail.textContent).not.toContain("0.00");
    expect(tail.textContent).not.toContain("−");
  });
});

describe("ScoreBand — an unwitnessed raw", () => {
  // grade_lambda still published, but one finding's raw_points is absent: the
  // fold cannot reconstruct that row's charge, and neither can the page.
  const BLANK_RAW = {
    ...ETHERFI,
    findings: [
      { ...ETHERFI.findings[0] },
      { ...ETHERFI.findings[1], raw_points: null, net_points_lambda: undefined },
    ],
  };

  it("renders the row's points as not determined, never as 0.00", async () => {
    const { container } = renderBand({ score: BLANK_RAW });
    await openBreakdown();
    const points = [...container.querySelectorAll(".sc-pts")].map((n) => n.textContent);
    expect(points).toEqual(["−10.50", "not determined"]);
    expect(points.some((p) => p.includes("0.00"))).toBe(false);
    expect(container.querySelectorAll(".sc-pts .sc-nd")).toHaveLength(1);
  });
});

describe("ScoreBand — entities select on the surface", () => {
  // Row 6 of the corpus: EOA 0xf855…, setAuthority on a single host, reaching
  // BoringVault first through the control graph. The shape these cases need is
  // one host and a reach set wider than it — the row that HAS that shape moves
  // whenever the ranking does, so it is selected by index here and the index is
  // asserted against the principal below.
  const ROW = 6;
  const CONTROLLER = "0xf8553c8552f906c19286f21711721e206ee4909e";
  const FIRST_TARGET = "0x352180974c71f84a934953cf49c4e538a6f9c997";
  const HOST = "0x989468982b08aefa46e37cd0086142a86fa466d7";

  it("is pinned to the row it says it is", () => {
    expect(ETHERFI.findings[ROW].principal).toBe(`EOA ${CONTROLLER}`);
    expect(ETHERFI.findings[ROW].host_entities).toEqual([`ethereum::${HOST}`]);
    expect(ETHERFI.findings[ROW].reach_entities).toContain(`ethereum::${FIRST_TARGET}`);
  });

  async function openRowZero(onSelectEntity) {
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    return container.querySelectorAll(".sc-frow")[ROW];
  }

  it("asks for the example function on its published host contract", async () => {
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    const button = within(row).getByRole("button", { name: "setAuthority" });
    await userEvent.setup().click(button);
    // host_entities publishes the contract the function was witnessed on —
    // this row's single host is the solver, never the first reach entity
    // (BoringVault, whose own setAuthority is someone else's gate).
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: HOST,
      functionSignature: "setAuthority",
      label: "setAuthority",
      // The controller rides along as a highlight hint so the resolved row can
      // mark the caller chip the row named — it is not a second entity request.
      highlight: { functionSignature: "setAuthority", controllers: [CONTROLLER] },
    });
    expect(HOST).not.toBe(FIRST_TARGET);
  });

  it("selects the controller from the kind chip, like the protections side", async () => {
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    await userEvent.setup().click(within(row).getByRole("button", { name: "EOA" }));
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: CONTROLLER,
      label: "EOA",
    });
    expect(ETHERFI.findings[ROW].principal).toContain(CONTROLLER);
  });

  it("selects a target contract with no function", async () => {
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    const targets = row.querySelector(".sc-targets");
    await userEvent.setup().click(within(targets).getByRole("button", { name: /BoringVault/ }));
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: FIRST_TARGET,
      label: "BoringVault",
      // The contract is what is asked for; the pair the row was about rides
      // along for the card to mark if it carries it.
      highlight: { functionSignature: "setAuthority", controllers: [CONTROLLER] },
      // …and so does the host the reach STARTED at, so the surface can show the
      // route to a contract the controller never touches directly.
      reachedFrom: [HOST],
    });
  });

  it("marks the reach boundary and keeps reached names quieter than hosts", async () => {
    // The arrow is the row's boundary between "acts on directly" (hosts, before
    // it) and "reaches through the control graph" (after it); the two sides have
    // to stay distinguishable at a glance, which is what the classes carry.
    const row = await openRowZero(vi.fn());
    const targets = row.querySelector(".sc-targets");
    expect(targets.querySelector(".sc-arr").textContent).toBe("→ reaches");
    expect(targets.querySelectorAll(".sc-host").length).toBeGreaterThan(0);
    expect(targets.querySelectorAll(".sc-reached").length).toBeGreaterThan(0);
    // Every entity after the arrow is a reached one, never a host.
    const arrow = targets.querySelector(".sc-arr");
    for (const el of targets.querySelectorAll(".sc-reached")) {
      expect(arrow.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
  });

  it("names no reach origin on the host itself", async () => {
    // The host is where the function IS. Handing it a reached-from would say it
    // is downstream of itself and put a route on a card that has none.
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    const host = row.querySelector(".sc-targets .sc-host");
    await userEvent.setup().click(within(host).getByRole("button", { name: /0x9894…66d7/ }));
    expect(onSelectEntity.mock.calls[0][0]).not.toHaveProperty("reachedFrom");
  });

  it("selects the function the fix-first callout names", async () => {
    const onSelectEntity = vi.fn();
    renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    const fix = screen.getByText(/modeled recovery up to/).closest(".sc-fix");
    await userEvent.setup().click(within(fix).getByRole("button", { name: "upgradeToAndCall" }));
    // The fix-first group's worst row is witnessed on THREE hosts, so there is
    // no one contract the callout's function click can land on. It asks for the
    // function and the pair and names no address — which is the third state,
    // not a default to the first host in the list.
    expect(ETHERFI.findings[0].host_entities.length).toBe(3);
    expect(onSelectEntity).toHaveBeenCalledWith(
      expect.objectContaining({
        functionSignature: "upgradeToAndCall",
        chain: "ethereum",
        highlight: {
          functionSignature: "upgradeToAndCall",
          controllers: ETHERFI.findings[0].principal_addresses,
        },
      }),
    );
    expect(onSelectEntity.mock.calls[0][0]).not.toHaveProperty("address");
  });

  it("hints the example function it displays, never the n it only counts", async () => {
    // Row 0 charges 3 functions and displays one of them. The hint has to be
    // the one the user read: naming the other 2 would mark rows the row never
    // showed, and naming none would drop the mark the click was for.
    const onSelectEntity = vi.fn();
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    const row = container.querySelectorAll(".sc-frow")[0];
    const targets = row.querySelector(".sc-targets");
    await userEvent.setup().click(within(targets).getAllByRole("button")[0]);
    const { highlight } = onSelectEntity.mock.calls[0][0];
    expect(highlight.functionSignature).toBe("upgradeToAndCall");
    expect(highlight.controllers).toEqual(ETHERFI.findings[0].principal_addresses);
  });

  it("activates from the keyboard, as the role it carries promises", async () => {
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    within(row).getByRole("button", { name: "setAuthority" }).focus();
    await userEvent.setup().keyboard("{Enter}");
    expect(onSelectEntity).toHaveBeenCalledTimes(1);
  });

  it("carries the reach-not-witnessed qualifier into the button's own interaction", async () => {
    const onSelectEntity = vi.fn();
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    await userEvent.setup().click(screen.getByRole("button", { name: /20 more/ }));
    const lists = [...container.querySelectorAll(".sc-targets")];
    const unwitnessed = lists.filter((el) => el.textContent.includes("reach not witnessed"));
    expect(unwitnessed.length).toBeGreaterThan(0);
    for (const list of unwitnessed) {
      // The host buttons are exempt: where the function LIVES is a witnessed
      // fact regardless of what its reach turned out to be.
      const hostButtons = [...list.querySelectorAll('.sc-host [role="button"]')];
      for (const button of hostButtons) {
        expect(button.getAttribute("title")).toMatch(/the function lives here$/);
        expect(button.getAttribute("title")).not.toMatch(/reach not witnessed/);
      }
      const buttons = [...list.querySelectorAll('[role="button"]')].filter(
        (b) => !b.closest(".sc-host"),
      );
      for (const button of buttons) {
        // Still clickable — going to an entity is not a claim about reach —
        // but the third state travels with the control.
        expect(button.getAttribute("aria-label")).toMatch(/reach not witnessed$/);
        expect(button.getAttribute("title")).toMatch(/reach not witnessed$/);
      }
      expect(hostButtons.length + buttons.length).toBeGreaterThan(0);
    }
    const witnessed = lists.filter((el) => el.querySelector(".sc-arr"));
    for (const list of witnessed) {
      for (const button of list.querySelectorAll('[role="button"]')) {
        expect(button.getAttribute("title")).not.toMatch(/reach not witnessed/);
        expect(button.getAttribute("aria-label")).toBeNull();
      }
    }
  });

  // The keyset-overlap caution rides on finding 2, published as "Safe 4/8
  // 0xf46d…e2b5". Pairing it with finding 0 puts a caution row and a protection
  // row in one two-row document by CONSTRUCTION, rather than by hunting for a
  // corpus row that happens to carry both — the caution's rendering is what
  // these cases are about, not which rows the full ranking puts where.
  const KEYSET = { ...ETHERFI, findings: [ETHERFI.findings[0], ETHERFI.findings[2]] };

  it("makes every protection principal and every Safe named in a caution selectable", async () => {
    const onSelectEntity = vi.fn();
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    const rows = [...container.querySelectorAll(".sc-prot")];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.querySelector(".sc-kchip")).toHaveAttribute("role", "button");
    }
    await userEvent.setup().click(rows[0].querySelector(".sc-kchip"));
    // The strongest protection on this document is the 10-day timelock, and the
    // chip asks for the TIMELOCK's own address — the thing that would have to be
    // removed for the delta to be realised — not the Safe that proposes to it.
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761",
      label: "Timelock 10d",
    });
    container.remove();

    const keyset = renderBand({ score: KEYSET, onSelectEntity });
    await openBreakdown();
    const caution = [...keyset.container.querySelectorAll(".sc-caut")].find((el) =>
      el.textContent.includes("not an independent key set"),
    );
    onSelectEntity.mockClear();
    await userEvent.setup().click(within(caution).getByRole("button"));
    expect(onSelectEntity).toHaveBeenCalledWith(
      expect.objectContaining({ address: "0x5ec5e6b4eb6827914ca8bc3ae02c39417242adde" }),
    );
    // The sentence is unchanged — the control wraps text that was already there.
    expect(caution.textContent).toBe(
      "⚠ shares 7 owners with Safe 0x5ec5…adde — not an independent key set",
    );
  });

  it("leaves the protections column inert with no handler wired", async () => {
    const { container } = renderBand({ score: KEYSET });
    await openBreakdown();
    for (const chip of container.querySelectorAll(".sc-prot .sc-kchip")) {
      expect(chip).not.toHaveAttribute("role");
      expect(chip.className).not.toContain("sc-lnk");
    }
    const caution = [...container.querySelectorAll(".sc-caut")].find((el) =>
      el.textContent.includes("not an independent key set"),
    );
    expect(caution.querySelector('[role="button"]')).toBeNull();
    expect(caution.textContent).toBe(
      "⚠ shares 7 owners with Safe 0x5ec5…adde — not an independent key set",
    );
  });

  it("renders the same text as plain elements with no handler wired", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    const row = container.querySelectorAll(".sc-frow")[ROW];
    expect(row.querySelector(".sc-addr").textContent).toBe("setAuthority");
    // The unwired chip is a plain span, not a dead button.
    expect(row.querySelector(".sc-kchip").getAttribute("role")).toBeNull();
    // Only controls that can act are buttons: the capability's glossary "?"
    // and the target expander. Entity references degrade to plain spans.
    const buttons = [...row.querySelectorAll("button")].map((b) => b.textContent);
    expect(buttons).toEqual(["?", "+9 more"]);
  });

  it("keeps the wired row's text identical to the unwired one", async () => {
    const plain = renderBand({ score: ETHERFI });
    await openBreakdown();
    const before = plain.container.querySelector(".sc-frow").textContent;
    plain.unmount();
    const wired = renderBand({ score: ETHERFI, onSelectEntity: vi.fn() });
    await openBreakdown();
    expect(wired.container.querySelector(".sc-frow").textContent).toBe(before);
  });
});

describe("ScoreBand — #score hash deep link", () => {
  it("opens the breakdown, scrolls the band into view, and consumes the hash", async () => {
    window.history.replaceState({}, "", "/company/etherfi#score");
    const scrolled = vi.fn();
    Element.prototype.scrollIntoView = scrolled;
    renderBand({ score: ETHERFI });
    // The breakdown is open without anyone clicking the toggle…
    expect(await screen.findByText("Deductions")).toBeInTheDocument();
    // …the band scrolled itself into view…
    await vi.waitFor(() => expect(scrolled).toHaveBeenCalled());
    // …and the hash is consumed so a later popstate cannot re-trigger it.
    expect(window.location.hash).toBe("");
    window.history.replaceState({}, "", "/");
  });

  it("a click's popstate signal opens an already-mounted band (same-page case)", async () => {
    window.history.replaceState({}, "", "/company/etherfi");
    renderBand({ score: ETHERFI });
    expect(screen.queryByText("Deductions")).not.toBeInTheDocument();
    window.history.replaceState({}, "", "/company/etherfi#score");
    window.dispatchEvent(new PopStateEvent("popstate"));
    expect(await screen.findByText("Deductions")).toBeInTheDocument();
    expect(window.location.hash).toBe("");
    window.history.replaceState({}, "", "/");
  });

  it("a hash arriving while the score is still loading opens once it lands", async () => {
    window.history.replaceState({}, "", "/company/etherfi#score");
    const view = renderBand(); // loading — no score yet
    expect(window.location.hash).toBe("#score"); // not consumed early
    view.rerender(
      <ScoreBand companyName="etherfi" contracts={CONTRACTS} score={ETHERFI} error={null} />,
    );
    expect(await screen.findByText("Deductions")).toBeInTheDocument();
    expect(window.location.hash).toBe("");
    window.history.replaceState({}, "", "/");
  });
});

describe("ScoreBand — protections carry the capability glossary", () => {
  it("wraps the protection row's capability in the ? tag, value suffix intact", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    const what = container.querySelector(".sc-prot-what");
    expect(what).toBeTruthy();
    // Same reading as before, plus the glossary affordance.
    expect(what.textContent).toMatch(/^\S+\.\S+\? on /);
    const q = what.querySelector(".sc-cap-q");
    await userEvent.setup().click(q);
    expect(screen.getByRole("note")).toBeInTheDocument();
  });
});

describe("ScoreBand — protections publish the band's direction", () => {
  const withFindings = (patch) => ({
    ...ETHERFI,
    findings: ETHERFI.findings.map((f) => ({ ...f, ...patch })),
  });

  it("badges a proven direction beside the band, outside the ellipsised text", async () => {
    const { container } = renderBand({ score: withFindings({ value_at_stake_bound_direction: "ceiling" }) });
    await openBreakdown();
    const heads = [...container.querySelectorAll(".sc-prot-head")];
    expect(heads).toHaveLength(4);
    for (const head of heads) {
      const badge = head.querySelector(".sc-fl");
      expect(badge.textContent).toBe("ceiling");
      expect(badge.title).toMatch(/^at most this much/);
      // Outside `.sc-prot-what` (which ellipsises) and before `.sc-prot-saved`,
      // whose margin-left:auto keeps it right-aligned regardless.
      expect(head.querySelector(".sc-prot-what").contains(badge)).toBe(false);
      expect(badge.nextElementSibling.className).toBe("sc-prot-saved");
    }
  });

  it("says the direction was never proven when the producer proved none", async () => {
    // Every finding in the corpus is at bound_direction not_determined, so all
    // four protection rows wear the refusal chip.
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    const badges = [...container.querySelectorAll(".sc-prot-head .sc-fl")].map((n) => n.textContent);
    expect(badges).toEqual(Array(4).fill("bound not determined"));
  });

  it("keeps an earned negative apart from an unmeasured band", async () => {
    // The corpus has no proven_no_reach finding, so nothing else exercises this
    // arm — and publishing it as "not determined" would contradict the same
    // finding's deduction row, which prints the earned negative.
    expect(ETHERFI.findings.some((f) => f.value_at_stake_basis === "proven_no_reach")).toBe(false);
    const { container } = renderBand({
      score: withFindings({ value_band: "not_determined", value_at_stake_basis: "proven_no_reach" }),
    });
    await openBreakdown();
    const heads = [...container.querySelectorAll(".sc-prot-head")];
    expect(heads).toHaveLength(4);
    for (const head of heads) {
      expect(within(head).getByText("proven no reach")).toBeInTheDocument();
      expect(head.querySelector(".sc-nd")).toBeNull();
      expect(head.querySelector(".sc-fl")).toBeNull();
    }
  });

  it("prints an unmeasured band as not determined, never as no value", async () => {
    const { container } = renderBand({ score: withFindings({ value_band: "not_determined" }) });
    await openBreakdown();
    const heads = [...container.querySelectorAll(".sc-prot-head")];
    expect(heads).toHaveLength(4);
    for (const head of heads) {
      expect(head.querySelector(".sc-fl")).toBeNull();
      expect(head.querySelector(".sc-nd").textContent).toBe("value not determined");
      expect(head.querySelector(".sc-prot-what").textContent).not.toMatch(/ on /);
    }
  });
});

describe("ScoreBand — #score hash on an unopenable band", () => {
  it("leaves the hash alone in the error state, then opens when the score lands", async () => {
    window.history.replaceState({}, "", "/company/etherfi#score");
    const view = renderBand({ error: { status: 503, message: "boom" } });
    // Nothing to open — the request must not be eaten.
    expect(window.location.hash).toBe("#score");
    view.rerender(
      <ScoreBand companyName="etherfi" contracts={CONTRACTS} score={ETHERFI} error={null} />,
    );
    expect(await screen.findByText("Deductions")).toBeInTheDocument();
    expect(window.location.hash).toBe("");
    window.history.replaceState({}, "", "/");
  });
});
