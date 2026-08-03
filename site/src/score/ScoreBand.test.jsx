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
    expect(screen.getByText("C+")).toBeInTheDocument();
    expect(screen.getByText("54.8")).toBeInTheDocument();
    expect(screen.getByText(/provisional · confidence 20.7%/)).toBeInTheDocument();
    expect(screen.getByText("54.8 kept")).toBeInTheDocument();
    expect(screen.getByText("71.7")).toBeInTheDocument();
    expect(screen.getByText("+41 subsumed")).toBeInTheDocument();
    // kept + 6 deduction segments + the sub-0.4pt tail
    expect(container.querySelectorAll(".sc-ledger-seg")).toHaveLength(8);
    expect(container.querySelector(".sc-ledger-seg.sc-ded").getAttribute("title")).toBe(
      "EOA · authority.replace · −20.25",
    );
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
    const tail = screen.getByRole("button", { name: /11 more/ });
    expect(tail.textContent).toContain("−0.12 combined");
    expect(tail.textContent).toContain("8 with value not determined");
    await userEvent.setup().click(tail);
    expect(container.querySelectorAll(".sc-frow")).toHaveLength(19);
  });

  it("tags a floor band and italicises an undetermined one — never $0", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    await userEvent.setup().click(screen.getByRole("button", { name: /11 more/ }));
    const cells = [...container.querySelectorAll(".sc-val")];
    const floor = cells.find((c) => c.textContent.startsWith("$1M-$10M"));
    expect(within(floor).getByText("floor")).toBeInTheDocument();
    const nd = cells.filter((c) => c.querySelector(".sc-nd"));
    expect(nd).toHaveLength(8);
    expect(nd[0].textContent).toBe("value not determined");
    expect(cells.some((c) => c.textContent.trim() === "$0")).toBe(false);
  });

  it("marks unwitnessed reach differently from proven reach", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    await userEvent.setup().click(screen.getByRole("button", { name: /11 more/ }));
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
    const firstRow = container.querySelector(".sc-frow .sc-targets");
    expect(within(firstRow).getByRole("button", { name: /\+5 more/ })).toBeInTheDocument();
    await user.click(within(firstRow).getByRole("button", { name: /\+5 more/ }));
    expect(within(firstRow).getByRole("button", { name: "less" })).toBeInTheDocument();
    expect(firstRow.textContent).toContain("0xeda6…4e70");
    await user.click(within(firstRow).getByRole("button", { name: "less" }));
    expect(within(firstRow).getByRole("button", { name: /\+5 more/ })).toBeInTheDocument();
  });

  it("renders the modeled fix-first recovery from a re-fold", async () => {
    renderBand({ score: ETHERFI });
    await openBreakdown();
    const fix = screen.getByText(/modeled recovery up to/).closest(".sc-fix");
    expect(fix.textContent).toContain("Move the two EOA authority holes");
    expect(fix.textContent).toContain("9.6 points");
    expect(fix.textContent).toContain("λ 54.8 → 64.3");
    expect(fix.textContent).toContain("ownership.transfer");
    expect(fix.textContent).toContain("fixing setAuthority alone does not release them");
  });

  it("renders the protections column and the audit posture verbatim", async () => {
    const { container } = renderBand({ score: ETHERFI });
    await openBreakdown();
    expect(screen.getByText(/each dollar weighted by how dangerous/)).toBeInTheDocument();
    const saved = [...container.querySelectorAll(".sc-prot-saved")].map((n) => n.textContent);
    expect(saved).toEqual(["+41.8", "+23.3", "+11.1", "+11.1"]);
    expect(screen.getByText("64 reports on file")).toBeInTheDocument();
    expect(screen.getByText(/12 witnessed upgrades bypassed this timelock/)).toBeInTheDocument();
    const byContract = screen.getByText(/contracts matched to an audit/);
    expect(byContract.textContent).toContain("54 / 210");
    expect(byContract.textContent).toContain("35");
  });

  it("renders no earned-negatives line when the corpus has none", async () => {
    renderBand({ score: ETHERFI });
    await openBreakdown();
    expect(ETHERFI.earned_negatives).toHaveLength(0);
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
    expect(channels).toHaveLength(3);
    expect(channels[0].querySelector(".sc-hd").textContent).toBe("min");
    expect(channels[1].querySelector(".sc-hd")).toBeNull();
    expect(channels[2].querySelector(".sc-hd")).toBeNull();
    expect(screen.getByText(/it measures how much of the protocol the grade is built on/)).toBeInTheDocument();
  });

  it("renders λ with no letter when the model version has no band table", () => {
    renderBand({ score: { ...ETHERFI, model_version: "9.9.9-unreleased" } });
    expect(screen.getByText("54.8")).toBeInTheDocument();
    expect(screen.queryByText("C+")).not.toBeInTheDocument();
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
    expect(screen.queryByText("C+")).not.toBeInTheDocument();
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
    expect(points[0]).toBe("20.25");
    expect(points.some((p) => p.startsWith("−"))).toBe(false);
    expect(container.querySelector(".sc-shield")).toBeNull();
    expect(container.querySelector(".sc-prot")).toBeNull();
  });

  it("still publishes the audit posture, which is not a grade quantity", async () => {
    renderBand({ score: WITHHELD });
    await openBreakdown();
    expect(screen.getByText("64 reports on file")).toBeInTheDocument();
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
    const tail = screen.getByRole("button", { name: /11 more/ });
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
    expect(points).toEqual(["−20.25", "not determined"]);
    expect(points.some((p) => p.includes("0.00"))).toBe(false);
    expect(container.querySelectorAll(".sc-pts .sc-nd")).toHaveLength(1);
  });
});

describe("ScoreBand — entities select on the surface", () => {
  // Row 0 of the corpus: EOA 0x2322…, setAuthority, reaching BoringVault first.
  const CONTROLLER = "0x2322ba43eff1542b6a7baed35e66099ea0d12bd1";
  const FIRST_TARGET = "0x352180974c71f84a934953cf49c4e538a6f9c997";
  const HOST = "0x7c12c550fe8857380b8f5a9e55d9145a0d7a7198";

  async function openRowZero(onSelectEntity) {
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    return container.querySelector(".sc-frow");
  }

  it("asks for the example function on its published host contract", async () => {
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    const button = within(row).getByRole("button", { name: "setAuthority" });
    await userEvent.setup().click(button);
    // host_entities publishes the contract the function was witnessed on —
    // row 0's single host is AtomicQueue, never the first reach entity
    // (BoringVault, whose own setAuthority is someone else's gate).
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: HOST,
      functionSignature: "setAuthority",
      label: "setAuthority",
      // The controller rides along as a highlight hint so the resolved row can
      // mark the caller chip the row named — it is not a second entity request.
      highlight: { functionSignature: "setAuthority", controller: CONTROLLER },
    });
    expect(HOST).not.toBe(FIRST_TARGET);
  });

  it("selects the controller named in the principal string, not a unit member", async () => {
    const onSelectEntity = vi.fn();
    const row = await openRowZero(onSelectEntity);
    await userEvent.setup().click(within(row).getByRole("button", { name: /0x2322…2bd1/ }));
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: CONTROLLER,
      label: CONTROLLER,
    });
    expect(ETHERFI.findings[0].principal).toContain(CONTROLLER);
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
      highlight: { functionSignature: "setAuthority", controller: CONTROLLER },
    });
  });

  it("selects the function the fix-first callout names", async () => {
    const onSelectEntity = vi.fn();
    renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    const fix = screen.getByText(/modeled recovery up to/).closest(".sc-fix");
    await userEvent.setup().click(within(fix).getByRole("button", { name: "setAuthority" }));
    expect(onSelectEntity).toHaveBeenCalledWith(
      expect.objectContaining({
        functionSignature: "setAuthority",
        chain: "ethereum",
        // The fix-first group's worst row has one host, so the callout's
        // function click lands there directly, pair and all.
        address: HOST,
        highlight: { functionSignature: "setAuthority", controller: CONTROLLER },
      }),
    );
  });

  it("hints the example function it displays, never the n it only counts", async () => {
    // Row 4 charges 60 functions and displays one of them. The hint has to be
    // the one the user read: naming the other 59 would mark rows the row never
    // showed, and naming none would drop the mark the click was for.
    const onSelectEntity = vi.fn();
    const { container } = renderBand({ score: ETHERFI, onSelectEntity });
    await openBreakdown();
    const row = container.querySelectorAll(".sc-frow")[4];
    expect(row.textContent).toContain("60 functions");
    const targets = row.querySelector(".sc-targets");
    await userEvent.setup().click(within(targets).getAllByRole("button")[0]);
    const { highlight } = onSelectEntity.mock.calls[0][0];
    expect(highlight.functionSignature).toBe("setAuthority");
    expect(highlight.controller).toBe(ETHERFI.findings[4].principal.match(/0x[0-9a-f]{40}/)[0]);
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
    await userEvent.setup().click(screen.getByRole("button", { name: /11 more/ }));
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
    expect(onSelectEntity).toHaveBeenCalledWith({
      chain: "ethereum",
      address: "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761",
      label: "Timelock 10d",
    });

    const caution = [...container.querySelectorAll(".sc-caut")].find((el) =>
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
    const { container } = renderBand({ score: ETHERFI });
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
    const row = container.querySelector(".sc-frow");
    expect(row.querySelector(".sc-addr").textContent).toBe("setAuthority · 0x2322…2bd1");
    // Only the target expander is a button; nothing that cannot act is one.
    const buttons = [...row.querySelectorAll("button")].map((b) => b.textContent);
    expect(buttons).toEqual(["+5 more"]);
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
