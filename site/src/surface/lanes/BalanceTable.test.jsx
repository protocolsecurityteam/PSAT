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

  it("does not read an empty holdings list as holding nothing", () => {
    render(<BalanceTable machine={machine([])} />);
    expect(screen.getByText("No token balances recorded")).toBeInTheDocument();
  });
});
