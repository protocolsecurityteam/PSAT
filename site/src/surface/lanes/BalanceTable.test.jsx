import { render, screen } from "@testing-library/react";
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

describe("BalanceTable — unknown references remain visible", () => {
  it("does not hide unpriced holdings using legacy universe classification", () => {
    render(<BalanceTable machine={machine([row({ token_symbol: "UNKNOWN", usd_value: null,
      usd_value_state: "not_determined", reference_shape: "absent_from_universe" })])} />);
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    expect(dustButton()).toHaveTextContent("Hide priced <$10 (0)");
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
    expect(screen.getByText(/omitted assets are unknown/i)).toBeInTheDocument();
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

describe("BalanceTable — retired classifications and partial observations", () => {
  it("shows legacy disposed rows as holdings without an airdrop category", () => {
    render(<BalanceTable machine={machine([row({ token_symbol: "HELD", usd_value: null,
      usd_value_state: "not_determined", delivery_shape: "fan_out_all", disposition_state: "disposed" })])} />);
    expect(screen.getByText("HELD")).toBeInTheDocument();
    expect(screen.getByText("not priced")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/mass distribution|not a position/i);
  });
  it("keeps newer partial evidence separate from the retained total", () => {
    render(<BalanceTable machine={machine([row({ token_symbol: "OLD" })], {
      total_usd: 1234,
      partial_balance_observations: [row({ token_symbol: "NEW", usd_value: 9999 })],
    })} />);
    expect(screen.getByText("Newer partial observations (1)")).toBeInTheDocument();
    expect(screen.getByText(/not added to the retained total/i)).toBeInTheDocument();
    expect(screen.getByText("$1.2K observed")).toBeInTheDocument();
  });
  it("does not size tokens from assumed decimals", () => {
    render(<BalanceTable machine={machine([row({ decimals_known: false })])} />);
    expect(screen.getByText("quantity scale unknown")).toBeInTheDocument();
  });
});


it("shows new partial holdings after an accepted empty snapshot with no native row", () => {
  render(<BalanceTable machine={machine([], {
    total_usd: null,
    holdings_coverage: { state: "may_be_incomplete" },
    partial_balance_observations: [row({ token_symbol: "PREFIX", usd_value: 9999 })],
  })} />);
  expect(screen.getByText("Newer partial observations (1)")).toBeInTheDocument();
  expect(screen.getByText("PREFIX")).toBeInTheDocument();
  expect(screen.getByText(/not added to the retained total/i)).toBeInTheDocument();
  expect(screen.getByText(/Holdings may be incomplete/i)).toBeInTheDocument();
  expect(screen.queryByText(/observed$/i)).toBeNull();
});
