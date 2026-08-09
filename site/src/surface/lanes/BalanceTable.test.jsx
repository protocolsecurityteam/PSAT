import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { BalanceTable } from "./BalanceTable.jsx";

const row = (over = {}) => ({
  token_symbol: "TKN",
  token_name: "Token",
  token_address: "0xtoken",
  raw_balance: "1000000000000000000",
  decimals: 18,
  usd_value: 1234,
  usd_value_state: "measured",
  price_usd: 1234,
  ...over,
});

const machine = (balances, over = {}) => ({
  address: "0xaaa",
  balances,
  total_usd: null,
  holdings_coverage: { rows: balances.length, page_cap: 100, state: "not_determined", unvalued_rows: 0 },
  ...over,
});

// Two buttons can be on screen at once (dust filter + withheld disclosure), so
// every selector here picks by text content rather than by "the button".
const dustButton = () =>
  screen.getAllByRole("button").find((b) => /Hide priced|Show all/i.test(b.textContent));
const withheldToggle = () =>
  screen.getAllByRole("button").find((b) => /mass distribution/i.test(b.textContent));

describe("BalanceTable — a measured zero is not an unknown value", () => {
  it("renders a MEASURED $0 holding as a measured zero", async () => {
    render(
      <BalanceTable
        machine={machine([row({ token_symbol: "ZERO", usd_value: 0, usd_value_state: "measured" })], {
          holdings_coverage: { rows: 1, page_cap: 100, state: "not_determined", unvalued_rows: 0 },
        })}
      />,
    );
    // A measured zero is dust, so the default filter hides the row; the claim
    // under test is what the CELL says once it is shown.
    await userEvent.click(screen.getByRole("button"));
    // `formatUsd(0)` is null and 0 is falsy, so this used to print the same em
    // dash an unpriced row printed.
    expect(screen.getByText("$0.00")).toBeInTheDocument();
    expect(screen.queryByText("not priced")).toBeNull();
  });

  it("renders an UNDETERMINED value as not priced, never as a number", () => {
    render(
      <BalanceTable
        machine={machine([row({ usd_value: null, usd_value_state: "not_determined" })], {
          holdings_coverage: { rows: 1, page_cap: 100, state: "not_determined", unvalued_rows: 1 },
        })}
      />,
    );
    expect(screen.getByText("not priced")).toBeInTheDocument();
    expect(screen.queryByText("$0.00")).toBeNull();
  });

  it("falls back to usd_value on a pre-fix payload with no state key", () => {
    render(<BalanceTable machine={machine([row({ usd_value: null, usd_value_state: undefined })])} />);
    expect(screen.getByText("not priced")).toBeInTheDocument();
  });

  it("keeps rendering a priced holding as its money figure", () => {
    // POSITIVE CONTROL: hedging every row would erase every real figure.
    render(<BalanceTable machine={machine([row({ usd_value: 5000 })])} />);
    expect(screen.getByText("$5.0K")).toBeInTheDocument();
  });
});

describe("BalanceTable — the dust filter keeps what it cannot price", () => {
  it("hides a priced-worthless row and keeps the unpriced one", async () => {
    const balances = [
      row({ token_symbol: "BIG", usd_value: 5000 }),
      row({ token_symbol: "DUST", usd_value: 0 }),
      row({ token_symbol: "UNK", usd_value: null, usd_value_state: "not_determined" }),
    ];
    render(<BalanceTable machine={machine(balances)} />);

    expect(screen.getByText("BIG")).toBeInTheDocument();
    expect(screen.queryByText("DUST")).toBeNull();
    // The unpriced row survives the filter — an unknown value is not a small one.
    expect(screen.getByText("UNK")).toBeInTheDocument();
    // ...and the filter no longer claims to be hiding everything under $10.
    expect(screen.getByRole("button")).toHaveTextContent("Hide priced <$10 (1)");
    // The row's own cell is what carries the pricing state to the reader.
    expect(screen.getByText("not priced")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button"));
    expect(screen.getByText("DUST")).toBeInTheDocument();
  });
});

// The two prose notes this lane used to render — the unpriced-coverage sentence
// and the priced-only-total sentence — were removed by owner directive: the
// per-row "not priced" cell is how the reader sees the total's coverage. These
// pin the phrases out so they cannot silently return.
describe("BalanceTable — the removed coverage prose stays removed", () => {
  const GONE = [
    /unpriced holdings? (is|are) still listed/i,
    /an unknown value is not a small one/i,
    // Not the bare "hidden by the filter above" — the empty-list line owns that
    // wording and is untouched; this is the clause only the removed note carried.
    /discovery does not name/i,
    /have no determined USD value/i,
    /counts only the priced ones/i,
  ];

  const assertGone = () => {
    for (const phrase of GONE) expect(document.body.textContent).not.toMatch(phrase);
  };

  it("renders neither sentence on a view carrying every fact that used to raise them", async () => {
    const balances = [
      row({ token_symbol: "BIG", usd_value: 5000 }),
      row({ token_symbol: "UNK", usd_value: null, usd_value_state: "not_determined" }),
      row({
        token_symbol: "CANA",
        usd_value: null,
        usd_value_state: "not_determined",
        reference_shape: "absent_from_universe",
      }),
    ];
    render(
      <BalanceTable
        machine={machine(balances, {
          total_usd: 5000,
          holdings_coverage: { rows: 100, page_cap: 100, state: "may_be_incomplete", unvalued_rows: 2 },
        })}
      />,
    );
    assertGone();
    // ...on the unfiltered view too, where the second note never rendered anyway.
    await userEvent.click(dustButton());
    assertGone();
  });
});

describe("BalanceTable — an unpriced token the protocol never names folds into the same hidden group", () => {
  // THE EVIDENCE. Locally 2,432 unpriced readings carry `absent_from_universe`
  // (CANA, SKIMCHI — hand-sent dust that never arrived by mass distribution, so
  // the disposition rule correctly declines to withhold it) against 23 that carry
  // `in_universe` (weETHs, an ether.fi wrapper). The first group is junk in
  // substance; the second is a real holding whose price nobody determined.
  const unknown = (symbol) =>
    row({
      token_symbol: symbol,
      usd_value: null,
      usd_value_state: "not_determined",
      reference_shape: "absent_from_universe",
      disposition_state: "presented",
    });
  const named = (symbol) =>
    row({
      token_symbol: symbol,
      usd_value: null,
      usd_value_state: "not_determined",
      reference_shape: "in_universe",
      disposition_state: "presented",
    });

  it("folds the unnamed ones and keeps the named one — an unknown value is not a small one", async () => {
    render(<BalanceTable machine={machine([row({ token_symbol: "BIG" }), named("weETHs"), unknown("CANA"), unknown("SKIMCHI")])} />);

    expect(screen.getByText("BIG")).toBeInTheDocument();
    // The POSITIVE CONTROL, and the reason this rule is two conjuncts rather
    // than "hide the unpriced": weETHs is unpriced and real.
    expect(screen.getByText("weETHs")).toBeInTheDocument();
    expect(screen.queryByText("CANA")).toBeNull();
    expect(screen.queryByText("SKIMCHI")).toBeNull();

    // ONE toggle, ONE combined count — never a second filter control.
    expect(screen.getAllByRole("button").filter((b) => /Hide priced|Show all/i.test(b.textContent))).toHaveLength(1);
    expect(dustButton()).toHaveTextContent("Hide priced <$10 and unnamed by discovery (2)");

    await userEvent.click(dustButton());
    expect(screen.getByText("CANA")).toBeInTheDocument();
    expect(screen.getByText("SKIMCHI")).toBeInTheDocument();
  });

  it("states the fold in the button's count alone, with no accompanying note", () => {
    render(<BalanceTable machine={machine([row({ token_symbol: "BIG" }), named("weETHs"), unknown("CANA"), unknown("SKIMCHI")])} />);
    expect(dustButton()).toHaveTextContent("Hide priced <$10 and unnamed by discovery (2)");
    expect(screen.queryAllByRole("note").filter((n) => /unpriced/i.test(n.textContent))).toHaveLength(0);
  });

  it("keeps a NOT_DETERMINED reference row visible — absence of a verdict is not a proven absence", () => {
    // FAIL-TOWARD-SHOWING CONTROL, both shapes of missing verdict: an explicit
    // `not_determined` and a payload carrying no key at all. `absent_from_universe`
    // is an EARNED negative; neither of these earns it.
    render(
      <BalanceTable
        machine={machine([
          row({ token_symbol: "BIG" }),
          row({ token_symbol: "NOTDET", usd_value: null, usd_value_state: "not_determined", reference_shape: "not_determined" }),
          row({ token_symbol: "NOKEY", usd_value: null, usd_value_state: "not_determined" }),
        ])}
      />,
    );
    expect(screen.getByText("NOTDET")).toBeInTheDocument();
    expect(screen.getByText("NOKEY")).toBeInTheDocument();
    expect(dustButton()).toHaveTextContent("Hide priced <$10 (0)");
  });

  it("never folds a PRICED row on the reference ground", () => {
    // A measured dollar figure is a fact about worth that discovery cannot
    // overturn: only the $10 rule may act on a priced row.
    render(
      <BalanceTable
        machine={machine([
          row({ token_symbol: "REALBUTUNNAMED", usd_value: 5000, reference_shape: "absent_from_universe" }),
        ])}
      />,
    );
    expect(screen.getByText("REALBUTUNNAMED")).toBeInTheDocument();
    expect(dustButton()).toHaveTextContent("Hide priced <$10 (0)");
  });

  it("does not name the reference ground on a view that folded nothing for it", () => {
    // NEGATIVE CONTROL: a permanent mention would claim a filter this view is
    // not applying.
    render(<BalanceTable machine={machine([row({ token_symbol: "BIG" }), row({ token_symbol: "DUST", usd_value: 0 })])} />);
    expect(dustButton()).toHaveTextContent("Hide priced <$10 (1)");
    expect(document.body.textContent).not.toMatch(/unnamed by discovery/i);
  });

  it("says what the filter did when it folded every row", () => {
    render(<BalanceTable machine={machine([unknown("CANA"), row({ token_symbol: "DUST", usd_value: 0 })])} />);
    // NOT "No holdings priced above $10": that would be a false claim about a
    // list which is also hiding an unpriced row.
    expect(screen.getByText("Every holding is hidden by the filter above")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/No holdings priced above/i);
  });
});

describe("BalanceTable — holdings coverage", () => {
  it("says the list may be incomplete when the fetch hit the page cap", () => {
    render(
      <BalanceTable
        machine={machine([row()], {
          holdings_coverage: { rows: 100, page_cap: 100, state: "may_be_incomplete", unvalued_rows: 0 },
        })}
      />,
    );
    expect(screen.getByText(/Holdings may be incomplete/i)).toBeInTheDocument();
    expect(screen.getByText(/lower bounds/i)).toBeInTheDocument();
  });

  it("does not claim incompleteness when the cap was not hit", () => {
    // NEGATIVE CONTROL: a permanent hedge on every contract would carry no
    // information about the 7 contracts that really are at the cap.
    render(<BalanceTable machine={machine([row()])} />);
    expect(screen.queryByText(/Holdings may be incomplete/i)).toBeNull();
  });

  it("says nothing in prose about unvalued rows — the row's own cell carries that", () => {
    render(
      <BalanceTable
        machine={machine([row(), row({ token_symbol: "UNK", usd_value: null, usd_value_state: "not_determined" })], {
          total_usd: 1234,
          holdings_coverage: { rows: 2, page_cap: 100, state: "not_determined", unvalued_rows: 1 },
        })}
      />,
    );
    expect(screen.queryByRole("note")).toBeNull();
    expect(screen.getByText("not priced")).toBeInTheDocument();
  });

  it("still discloses truncation on a contract that also holds unvalued rows", () => {
    // The truncation sentence is the one coverage claim this lane still makes,
    // and unvalued rows must not suppress it: locally all 7 at-the-cap contracts
    // also carry unpriced assets.
    render(
      <BalanceTable
        machine={machine([row(), row({ token_symbol: "UNK", usd_value: null, usd_value_state: "not_determined" })], {
          total_usd: 1234,
          holdings_coverage: { rows: 100, page_cap: 100, state: "may_be_incomplete", unvalued_rows: 4 },
        })}
      />,
    );
    const notes = screen.getAllByRole("note");
    expect(notes).toHaveLength(1);
    expect(notes[0]).toHaveTextContent(/Holdings may be incomplete/i);
  });

  it("does not read an empty holdings list as holding nothing", () => {
    render(<BalanceTable machine={machine([])} />);
    expect(screen.getByText("No token balances recorded")).toBeInTheDocument();
  });
});

describe("BalanceTable — airdrop-delivered rows are labelled, never suppressed", () => {
  const junk = () =>
    row({
      token_symbol: "JUNK",
      token_name: "claim at t.ly/x",
      usd_value: null,
      usd_value_state: "not_determined",
      delivery_shape: "fan_out_all",
      reference_shape: "absent_from_universe",
      // The BACKEND'S verdict, which is the conjunction of both shapes above.
      // The page reads this field and never re-derives it from the two.
      disposition_state: "disposed",
      delivery_shape_basis: "own-history scan 0..25710573",
    });

  it("still renders the row — a suppressed row is a deletion nobody can see", async () => {
    render(
      <BalanceTable
        machine={machine([row(), junk()], {
          holdings_coverage: {
            rows: 2,
            page_cap: 100,
            state: "not_determined",
            unvalued_rows: 1,
            airdrop_delivered_rows: 1,
          },
        })}
      />,
    );
    // Collapsed is not suppressed: the row is one click away and nothing else
    // stands between the reader and it.
    await userEvent.click(withheldToggle());
    expect(screen.getByText("JUNK")).toBeInTheDocument();
  });

  it("labels it by DELIVERY SHAPE and never calls it worthless", async () => {
    render(<BalanceTable machine={machine([row(), junk()])} />);
    // Real tokens arrive this way (uniETH at fan-out 101, HEX at 199/399/399),
    // so any of these words would be a claim the evidence does not carry — of
    // the collapsed summary as much as of the expanded note.
    const forbidden = [/spam/i, /scam/i, /junk/i, /worthless/i];
    const summary = withheldToggle();
    expect(summary).toBeDefined();
    for (const word of forbidden) {
      expect(summary.textContent).not.toMatch(word);
    }

    await userEvent.click(summary);
    const note = screen.getAllByRole("note").find((n) => /mass distribution|transfer logs/i.test(n.textContent));
    expect(note).toBeDefined();
    expect(note).toHaveTextContent(/not about what it is worth/i);
    // The threshold, not a size: the claim is a log count in one transaction,
    // never a recipient count.
    expect(note).toHaveTextContent(/published fan-out threshold of same-token transfer logs/i);
    for (const word of [...forbidden, /hundreds of recipients/i]) {
      expect(note.textContent).not.toMatch(word);
    }
  });

  it("keeps it out of the presented holdings, dust filter or not", async () => {
    render(<BalanceTable machine={machine([row(), junk()])} />);
    // The dust button counts only the presented holdings: one priced $1,234 row
    // is above $10, so nothing is hidden by the filter.
    expect(dustButton()).toHaveTextContent("Hide priced <$10 (0)");
    await userEvent.click(dustButton());
    // Showing all PRESENTED holdings does not expand the withheld disclosure:
    // the two controls are independent.
    expect(screen.queryByText("JUNK")).toBeNull();
    await userEvent.click(withheldToggle());
    expect(screen.getByText("JUNK")).toBeInTheDocument();
  });

  it("is collapsed to one counted line by default, and expands to the rows", async () => {
    render(<BalanceTable machine={machine([row(), junk(), junk()])} />);
    // The count is what the collapsed line carries.
    expect(withheldToggle()).toHaveTextContent("2 tokens arrived by mass distribution and are not positions");
    expect(withheldToggle()).toHaveAttribute("aria-expanded", "false");
    // Collapsed: no withheld rows, and only the holdings list is rendered.
    expect(screen.queryByText("JUNK")).toBeNull();
    expect(document.querySelectorAll(".ps-balance-list")).toHaveLength(1);

    await userEvent.click(withheldToggle());
    expect(withheldToggle()).toHaveAttribute("aria-expanded", "true");
    expect(screen.getAllByText("JUNK")).toHaveLength(2);
    expect(document.querySelectorAll(".ps-balance-list")).toHaveLength(2);

    await userEvent.click(withheldToggle());
    expect(screen.queryByText("JUNK")).toBeNull();
  });

  it("says one token in the singular", () => {
    render(<BalanceTable machine={machine([row(), junk()])} />);
    expect(withheldToggle()).toHaveTextContent("1 token arrived by mass distribution and is not a position");
  });

  it("renders no withheld section at all when nothing is disposed", () => {
    // NEGATIVE CONTROL: a permanent empty disclosure would be noise on every
    // contract that holds only real positions.
    render(<BalanceTable machine={machine([row(), row({ token_symbol: "TWO" })])} />);
    expect(withheldToggle()).toBeUndefined();
    expect(document.querySelector(".ps-balance-withheld")).toBeNull();
    expect(document.body.textContent).not.toMatch(/mass distribution/i);
  });

  it("presents a has_direct_delivery and a not_determined row normally", () => {
    // FAIL-CLOSED CONTROL: only the proven all-quantifier withholds a row. An
    // earned negative and an unmeasured pair are different states and neither
    // is disposed.
    render(
      <BalanceTable
        machine={machine([
          row({ token_symbol: "REAL", delivery_shape: "has_direct_delivery", disposition_state: "presented" }),
          row({ token_symbol: "UNK2", delivery_shape: "not_determined", disposition_state: "presented" }),
          row({ token_symbol: "NOKEY" }),
        ])}
      />,
    );
    expect(screen.queryByRole("note")).toBeNull();
    for (const symbol of ["REAL", "UNK2", "NOKEY"]) {
      expect(screen.getByText(symbol)).toBeInTheDocument();
    }
  });
});

describe("BalanceTable — the withholding rule is the backend's, not the page's", () => {
  // THE REGRESSION THIS PINS. The page used to split on `delivery_shape ===
  // "fan_out_all"` alone, which is half of a two-part rule. These three are
  // mass-distributed AND named by the protocol's own discovery, so the score
  // spares them — and the page withheld all three anyway: HEX x34, WETH x4 and
  // base USDC x1, one of them a fully-liquid stablecoin.
  const spared = (symbol) =>
    row({
      token_symbol: symbol,
      usd_value: null,
      usd_value_state: "not_determined",
      delivery_shape: "fan_out_all",
      reference_shape: "in_universe",
      disposition_state: "presented",
    });

  it("keeps a mass-distributed holding the protocol's own discovery names", () => {
    render(<BalanceTable machine={machine([spared("HEX"), spared("WETH"), spared("USDC")])} />);
    for (const symbol of ["HEX", "WETH", "USDC"]) {
      expect(screen.getByText(symbol)).toBeInTheDocument();
    }
    // The LIST half of the regression, and it has to be asserted on text
    // content: role="note" takes no accessible name from its content, so a
    // `queryByRole("note", { name: ... })` matches nothing whatever the page
    // renders and would pass over the very bug this pins. The withheld section
    // is collapsed by default, so its COLLAPSED line is what a regression would
    // show — assert on the whole render, not just the notes it expands to.
    expect(withheldToggle()).toBeUndefined();
    expect(document.body.textContent).not.toMatch(/mass distribution/i);
    // And they are in the holdings list rather than under a withheld heading:
    // one list is rendered, and all three rows are in it.
    const lists = document.querySelectorAll(".ps-balance-list");
    expect(lists).toHaveLength(1);
    for (const symbol of ["HEX", "WETH", "USDC"]) {
      expect(within(lists[0]).getByText(symbol)).toBeInTheDocument();
    }
  });

  it("treats a missing verdict as PRESENTED, never as disposed", () => {
    // Fail closed toward showing a real holding: a payload with no verdict is a
    // payload that judged nothing, and hiding a holding on that basis would be
    // the page inventing a claim.
    render(
      <BalanceTable machine={machine([row({ token_symbol: "NOVERDICT", delivery_shape: "fan_out_all" })])} />,
    );
    expect(screen.getByText("NOVERDICT")).toBeInTheDocument();
    expect(withheldToggle()).toBeUndefined();
    expect(document.body.textContent).not.toMatch(/mass distribution/i);
    const lists = document.querySelectorAll(".ps-balance-list");
    expect(lists).toHaveLength(1);
    expect(within(lists[0]).getByText("NOVERDICT")).toBeInTheDocument();
  });
});
