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

describe("BalanceTable — the dust filter's asymmetry is disclosed", () => {
  it("hides a priced-worthless row and keeps the unpriced one, saying so", async () => {
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
    expect(screen.getByText(/unpriced holding is still listed/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button"));
    expect(screen.getByText("DUST")).toBeInTheDocument();
    // NEGATIVE CONTROL: the asymmetry note belongs to the filtered view only.
    expect(screen.queryByText(/unpriced holding is still listed/i)).toBeNull();
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

  it("says the total counts only priced holdings when some are unvalued", () => {
    render(
      <BalanceTable
        machine={machine([row(), row({ token_symbol: "UNK", usd_value: null, usd_value_state: "not_determined" })], {
          total_usd: 1234,
          holdings_coverage: { rows: 2, page_cap: 100, state: "not_determined", unvalued_rows: 1 },
        })}
      />,
    );
    expect(screen.getByText(/counts only the priced ones/i)).toBeInTheDocument();
  });

  it("discloses truncation AND unvalued rows when both facts hold", () => {
    // The truncation sentence returned early, so the contract at the page cap
    // that ALSO holds unpriced assets lost the pricing disclosure — the row where the
    // total is least trustworthy. Locally all 7 at-the-cap contracts are that shape.
    render(
      <BalanceTable
        machine={machine([row(), row({ token_symbol: "UNK", usd_value: null, usd_value_state: "not_determined" })], {
          total_usd: 1234,
          holdings_coverage: { rows: 100, page_cap: 100, state: "may_be_incomplete", unvalued_rows: 4 },
        })}
      />,
    );
    // The coverage note is the first of the two notes this view can render (the second
    // is the dust-filter asymmetry note); both sentences must be in the SAME element,
    // so a composed string is asserted rather than two separate matches.
    const note = screen.getAllByRole("note")[0];
    expect(note).toHaveTextContent(/Holdings may be incomplete/i);
    expect(note).toHaveTextContent(/4 of 100 holdings have no determined USD value/i);
    expect(note).toHaveTextContent(/counts only the priced ones/i);
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

  it("still renders the row — a suppressed row is a deletion nobody can see", () => {
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
    expect(screen.getByText("JUNK")).toBeInTheDocument();
  });

  it("labels it by DELIVERY SHAPE and never calls it worthless", () => {
    render(<BalanceTable machine={machine([row(), junk()])} />);
    const note = screen.getAllByRole("note").find((n) => /mass distribution/i.test(n.textContent));
    expect(note).toBeDefined();
    expect(note).toHaveTextContent(/not about what it is worth/i);
    // Real tokens arrive this way (uniETH at fan-out 101, HEX at 199/399/399),
    // so any of these words would be a claim the evidence does not carry.
    for (const word of [/spam/i, /scam/i, /junk/i, /worthless/i]) {
      expect(note.textContent).not.toMatch(word);
    }
  });

  it("keeps it out of the presented holdings, dust filter or not", async () => {
    render(<BalanceTable machine={machine([row(), junk()])} />);
    // The dust button counts only the presented holdings: one priced $1,234 row
    // is above $10, so nothing is hidden by the filter.
    expect(screen.getByRole("button")).toHaveTextContent("Hide priced <$10 (0)");
    // And the unpriced-shown note is about presented holdings too, so an
    // airdrop-delivered unpriced row must not raise it.
    expect(screen.queryByText(/unpriced holding is still listed/i)).toBeNull();
    await userEvent.click(screen.getByRole("button"));
    expect(screen.getByText("JUNK")).toBeInTheDocument();
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
    // renders and would pass over the very bug this pins.
    const withheldNote = screen.queryAllByRole("note").find((n) => /mass distribution/i.test(n.textContent));
    expect(withheldNote).toBeUndefined();
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
    const note = screen.queryAllByRole("note").find((n) => /mass distribution/i.test(n.textContent));
    expect(note).toBeUndefined();
    const lists = document.querySelectorAll(".ps-balance-list");
    expect(lists).toHaveLength(1);
    expect(within(lists[0]).getByText("NOVERDICT")).toBeInTheDocument();
  });
});
