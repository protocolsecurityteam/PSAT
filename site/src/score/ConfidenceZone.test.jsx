import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import ETHERFI from "../test/fixtures/score_etherfi.json";
import ConfidenceZone from "./ConfidenceZone.jsx";
import { projectScore } from "./derive.js";

const CONTRACTS = [
  { address: "0x352180974c71f84a934953cf49c4e538a6f9c997", chain: "ethereum", name: "BoringVault" },
];

function renderZone(doc = ETHERFI, onSelect = undefined) {
  return render(<ConfidenceZone doc={doc} view={projectScore(doc, CONTRACTS)} onSelect={onSelect} />);
}

const LEVERS = ETHERFI.provenance.unresolved_levers.levers;

function docWithLevers(levers) {
  return {
    ...ETHERFI,
    provenance: { ...ETHERFI.provenance, unresolved_levers: { levers } },
  };
}

describe("ConfidenceZone — the confidence half", () => {
  it("renders the headline and the four meters, min tagged where the minimum is", () => {
    const { container } = renderZone();
    expect(container.querySelector(".scz-big").textContent).toBe("43.6%");
    const channels = [...container.querySelectorAll(".sc-channel")];
    expect(channels).toHaveLength(4);
    expect(channels.filter((c) => c.querySelector(".sc-hd"))).toHaveLength(1);
    expect(channels[3].querySelector(".sc-hd").textContent).toBe("min");
    expect(screen.getByText(/the lowest of the four/)).toBeInTheDocument();
  });

  it("prints an unpublished confidence as not determined, never as 0%", () => {
    renderZone({ ...ETHERFI, confidence_pct: null });
    expect(screen.queryByText("0.0%")).not.toBeInTheDocument();
    const headline = document.querySelector(".scz-big");
    expect(headline.textContent).toBe("not determined");
  });
});

describe("ConfidenceZone — the table", () => {
  it("names the four columns and carries the intro verbatim", () => {
    const { container } = renderZone();
    expect([...container.querySelectorAll(".scz-thead span")].map((s) => s.textContent)).toEqual([
      "could cost",
      "proven",
      "not yet verified",
      "dollar ceiling",
    ]);
    expect(
      screen.getByText(/Each row is a proven permission whose consequence has not been verified/),
    ).toBeInTheDocument();
    expect(screen.getByText(/rows sharing one pool are never added together/)).toBeInTheDocument();
  });

  it("says nothing here is charged", () => {
    const { container } = renderZone();
    expect(container.querySelector(".scz-tag").textContent).toBe("not determined · not in λ");
  });

  it("names no λ when the producer withheld one", () => {
    const { container } = render(
      <ConfidenceZone doc={ETHERFI} view={projectScore(ETHERFI, CONTRACTS)} withheld />,
    );
    expect(container.querySelector(".scz-tag").textContent).toBe("not determined · not in the grade");
    expect(container.textContent).not.toContain("λ");
    // The queue itself survives: a points ceiling is severity × weakness ×
    // band, the same shape as the raw points the withheld state still prints.
    expect(container.querySelectorAll(".scz-trow")).toHaveLength(6);
  });

  it("renders six rows and counts the rest in levers", () => {
    const { container } = renderZone();
    expect(container.querySelectorAll(".scz-trow")).toHaveLength(6);
    const tail = screen.getByRole("button", { name: /14 more/ });
    expect(tail.textContent).toBe("+ 14 more▼");
    expect(tail.className).toBe("sc-tail-btn");
  });

  it("expands the tail in place and collapses it again", async () => {
    const user = userEvent.setup();
    const { container } = renderZone();
    // 20 open levers over 17 rows: the head shows six, and the button counts
    // the fourteen QUESTIONS behind it — four of which share one row, so the
    // label is not the number of rows it reveals.
    await user.click(screen.getByRole("button", { name: /14 more/ }));
    expect(container.querySelectorAll(".scz-trow")).toHaveLength(17);
    await user.click(screen.getByRole("button", { name: /hide the tail/ }));
    expect(container.querySelectorAll(".scz-trow")).toHaveLength(6);
    expect(screen.getByRole("button", { name: /14 more/ })).toBeInTheDocument();
  });

  it("gives the revealed rows the same anatomy as the head", async () => {
    const { container } = renderZone();
    await userEvent.setup().click(screen.getByRole("button", { name: /14 more/ }));
    const revealed = [...container.querySelectorAll(".scz-trow")].slice(6);
    expect(revealed).toHaveLength(11);
    for (const row of revealed) {
      expect(row.querySelector(".scz-pc").textContent).toMatch(/score points$/);
      expect(row.querySelector(".sc-kchip")).toBeTruthy();
      expect(row.querySelector(".sc-cap")).toBeTruthy();
      expect(row.querySelector(".scz-miss").textContent).not.toBe("");
      expect(row.querySelector(".scz-chain").textContent).toMatch(/^(ethereum|base)$/);
    }
    // The grouped row rides in the tail, holder chip and all — and it is the
    // only one, because the other transfer_policy holders differ in what the
    // row would say about them.
    const chips = revealed.map((r) => r.querySelector(".scz-nprin")?.textContent ?? null);
    expect(chips.filter(Boolean)).toEqual(["× 4 holders"]);
    // Pools are assigned over every row, not only the visible ones: the five
    // transfer_policy rows reach one $1.45M pot, and the tail says so once per
    // row so a reader cannot add them up.
    const pooled = [...container.querySelectorAll(".scz-poolchip")].map((n) => n.textContent);
    expect(pooled.filter((t) => t.startsWith("⬡ POOL C"))).toHaveLength(5);
    expect(pooled).toHaveLength(10);
  });

  it("prints each row's points as an at-most, never as a charge", () => {
    const { container } = renderZone();
    const points = [...container.querySelectorAll(".scz-pc")].map((n) => n.textContent);
    expect(points).toEqual([
      "up to 20.25score points",
      "up to 20.25score points",
      "up to 16.5score points",
      "up to 12.15score points",
      "up to 9.9score points",
      "up to 8.4score points",
    ]);
    for (const cell of container.querySelectorAll(".scz-pc")) {
      expect(cell.textContent).not.toContain("−");
    }
  });

  it("chooses the status off the basis holding the dollars", () => {
    const { container } = renderZone();
    const rows = [...container.querySelectorAll(".scz-trow")];
    // Row 0's money sits behind unestablished hops; rows 1 and 2 reach theirs.
    expect(rows[0].querySelector(".scz-miss").textContent).toBe(
      "Reachability? — ≤ $2.20M behind 21 unconfirmed paths",
    );
    expect(rows[1].querySelector(".scz-miss").textContent).toBe(
      "Reach magnitude? — ≤ $2.20M · path proven to 12 contracts",
    );
  });

  it("opens the canonical reading behind each status ?", async () => {
    const { container } = renderZone();
    const row = container.querySelectorAll(".scz-trow")[1];
    await userEvent.setup().click(within(row.querySelector(".scz-miss")).getByRole("button"));
    expect(screen.getByRole("note").textContent).toBe(
      "The permission provably reaches these contracts. The amount it can move at them has not " +
        "been measured. The dollar figure is the sum of what they hold, an upper bound only.",
    );
  });

  it("prints the pool once per member, with the union count", () => {
    const { container } = renderZone();
    const chips = [...container.querySelectorAll(".scz-poolchip")].map((n) => n.textContent);
    expect(chips).toEqual([
      "⬡ POOL A · 23 contracts",
      "⬡ POOL A · 23 contracts",
      "⬡ POOL A · 23 contracts",
      "⬡ POOL B · 7 contracts",
      "⬡ POOL B · 7 contracts",
    ]);
    // The ≤ $29.5M row is the sixth and wears no pool: a different ceiling is
    // a different pot however much of it the sets share.
    const rows = [...container.querySelectorAll(".scz-trow")];
    expect(rows[5].querySelector(".scz-stake").textContent).toBe("≤ $29.5M");
    expect(rows[5].querySelector(".scz-poolchip")).toBeNull();
  });

  it("folds the refusals into one amber chip and never shows them as $0", () => {
    const { container } = renderZone();
    const rows = [...container.querySelectorAll(".scz-trow")];
    expect(rows[3].querySelector(".scz-ref").textContent).toBe("+5 not yet priced");
    expect(rows[4].querySelector(".scz-ref").textContent).toBe("+4 not yet priced");
    // Six no_rows plus one unpriced, one consequence, one chip.
    expect(rows[5].querySelector(".scz-ref").textContent).toBe("+7 not yet priced");
    expect(rows[0].querySelector(".scz-ref")).toBeNull();
    for (const cell of container.querySelectorAll(".scz-ceiling")) {
      expect(cell.textContent).not.toContain("$0.00");
    }
  });

  it("renders a ceiling nobody could bound louder, not as a small number", () => {
    const unbounded = {
      ...LEVERS[0],
      ceiling_usd: null,
      entities_total: 9,
      by_basis: {
        reached_unwitnessed: {
          ceiling_usd: null,
          entities: 9,
          entities_refused_by_reason: { unpriced: 9 },
          missing_witnesses: { closure_entity_value_not_determined: 9 },
          entities_itemized: [],
        },
      },
    };
    const { container } = render(
      <ConfidenceZone
        doc={docWithLevers([unbounded])}
        view={projectScore(docWithLevers([unbounded]), CONTRACTS)}
      />,
    );
    const cell = container.querySelector(".scz-ceiling");
    expect(cell.querySelector(".scz-unbounded").textContent).toBe(
      "no upper limit known — 9 contracts involved",
    );
    expect(cell.textContent).not.toContain("$0");
    expect(container.querySelector(".scz-miss").textContent).toContain("no upper limit known");
  });

  it("chips the holder count on a grouped row and names every one of them", () => {
    // The eight transfer_policy holders wait on one byte-identical set, but the
    // row speaks for all of them: only the four the document gives the SAME
    // function, kind and points ceiling merge. The other four each get a row.
    const transfer = LEVERS.filter((l) => l.capability === "transfer_policy.configure");
    const doc = docWithLevers(transfer);
    const { container } = render(<ConfidenceZone doc={doc} view={projectScore(doc, CONTRACTS)} />);
    const rows = [...container.querySelectorAll(".scz-trow")];
    expect(rows).toHaveLength(5);

    const grouped = rows[0];
    expect(grouped.querySelector(".scz-nprin").textContent).toBe("× 4 holders");
    expect(grouped.querySelector(".sc-kchip").textContent).toBe("EOA");
    expect(grouped.querySelector(".sc-addr").textContent).toContain("addAsset");
    const merged = transfer
      .filter((l) => l.points_ceiling === 6.75 && !l.principal.includes("0xa4c5"))
      .map((l) => l.principal.match(/0x[0-9a-f]{40}/)[0]);
    expect(merged).toHaveLength(4);
    for (const controller of merged) {
      expect(grouped.querySelector(".sc-addr").textContent).toContain(
        `${controller.slice(0, 6)}…${controller.slice(-4)}`,
      );
    }

    // 0xa4c5… holds removeAsset and stands alone rather than being spoken for.
    const removeRow = rows.find((r) => r.textContent.includes("removeAsset"));
    expect(removeRow.querySelector(".scz-nprin")).toBeNull();
    expect(removeRow.querySelector(".sc-addr").textContent).toContain("0xa4c5…6bb4");
    expect(grouped.textContent).not.toContain("removeAsset");
    expect(grouped.textContent).not.toContain("0xa4c5…6bb4");

    // …and the three Safes are not published as EOAs. The last one is a merged
    // unit (two principal_addresses), so its chip is the unit, not one k/n.
    const safes = rows.filter((r) => /Safe/.test(r.querySelector(".sc-kchip").textContent));
    expect(safes.map((r) => r.querySelector(".sc-kchip").textContent)).toEqual([
      "Safe 2/5",
      "Safe 2/7",
      "2 Safes · shared keys",
    ]);
    for (const safe of safes) expect(safe.querySelector(".scz-nprin")).toBeNull();

    // Five rows, none hidden: no tail, so no control offering one.
    expect(container.querySelector(".sc-tail-btn")).toBeNull();
  });

  it("publishes an unrecognised witness token raw rather than guessing", () => {
    const flow = LEVERS.find((l) => l.capability === "flow.out");
    const doc = docWithLevers([flow]);
    const { container } = render(<ConfidenceZone doc={doc} view={projectScore(doc, CONTRACTS)} />);
    const stray = container.querySelector(".scz-missline.scz-sec");
    expect(stray.textContent).toBe("not determined — token_identity_not_decidable × 1");
  });

  it("renders the zone with no rollup as not determined, not as an empty queue", () => {
    const doc = { ...ETHERFI, provenance: { ...ETHERFI.provenance, unresolved_levers: undefined } };
    const { container } = render(<ConfidenceZone doc={doc} view={projectScore(doc, CONTRACTS)} />);
    expect(container.querySelector(".scz-empty").textContent).toMatch(/^not determined/);
    expect(container.querySelector(".scz-thead")).toBeNull();
  });

  it("says every lever closed when the rollup is published and nothing is open", () => {
    const doc = docWithLevers([{ ...LEVERS[0], ceiling_usd: 0 }]);
    const { container } = render(<ConfidenceZone doc={doc} view={projectScore(doc, CONTRACTS)} />);
    expect(container.querySelector(".scz-empty").textContent).toMatch(/Every admitted lever closed/);
  });
});

describe("ConfidenceZone — the proven half is the deductions row", () => {
  it("carries the same chip, capability tag, action line and targets", () => {
    const { container } = renderZone();
    const row = container.querySelectorAll(".scz-trow")[1];
    expect(row.querySelector(".sc-kchip").textContent).toBe("EOA");
    expect(row.querySelector(".sc-cap").textContent).toBe("authority.replace?");
    expect(row.querySelector(".sc-addr").textContent).toBe("setAuthority · 0xf855…909e");
    const targets = row.querySelector(".sc-targets");
    expect(targets.querySelector(".sc-arr").textContent).toBe("→ reaches");
    expect(targets.querySelector(".sc-host")).toBeTruthy();
    expect(row.querySelector(".scz-chain").textContent).toBe("ethereum");
  });

  it("selects entities through the same pathway the deductions tab uses", async () => {
    const onSelect = vi.fn();
    const { container } = renderZone(ETHERFI, onSelect);
    const row = container.querySelectorAll(".scz-trow")[1];
    await userEvent.setup().click(within(row).getByRole("button", { name: "setAuthority" }));
    expect(onSelect).toHaveBeenCalledWith(
      expect.objectContaining({
        functionSignature: "setAuthority",
        label: "setAuthority",
        highlight: {
          functionSignature: "setAuthority",
          controllers: ["0xf8553c8552f906c19286f21711721e206ee4909e"],
        },
      }),
    );
  });

  it("names the unproven proposer set rather than leaving the row silent", () => {
    const { container } = renderZone();
    const timelock = [...container.querySelectorAll(".scz-trow")].find((r) =>
      r.textContent.includes("Timelock 2d"),
    );
    expect(timelock.querySelector(".scz-nd-line").textContent).toBe("proposer not determined");
  });

  it("degrades to plain text with no handler wired", () => {
    const { container } = renderZone();
    const row = container.querySelectorAll(".scz-trow")[1];
    // The only buttons left are the two "?" affordances and the target
    // expander — an entity reference that cannot act is not a control.
    expect(row.querySelectorAll('[role="button"]')).toHaveLength(0);
    expect([...row.querySelectorAll("button")].map((b) => b.textContent)).toEqual([
      "?",
      "+9 more",
      "?",
    ]);
  });
});
