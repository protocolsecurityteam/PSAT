import { useState } from "react";

import { formatUsd } from "../format.js";

// The USD cell for one holding. Three states, and the two that used to render
// identically are the point: `usd_value: 0` is PRICED and worth less than half a
// cent, `usd_value: null` is "nobody determined what this is worth" — 1,001 of
// 1,376 local rows — and `0` is falsy in JS, so both printed the same em dash.
// `formatUsd` itself returns null below a cent, so a measured zero cannot be
// routed through it either.
function usdCell(row) {
  const determined = row?.usd_value_state
    ? row.usd_value_state === "measured"
    // Pre-fix payloads carry no state key. `usd_value` is the producer's own
    // discriminator and encodes unpriced correctly as null, so fall back to it
    // rather than treating a key-less row as either answer.
    : row?.usd_value != null;
  if (!determined) return { text: "not priced", className: "ps-balance-usd unpriced" };
  const formatted = formatUsd(row.usd_value);
  // A measured value under a cent (including exactly 0) is still a measurement.
  return { text: formatted || "$0.00", className: "ps-balance-usd" };
}

// Whether this contract's holdings list can be reported as the whole set.
// `holdings_coverage.state` is two-valued by construction — the backend cannot
// prove completeness (see company_overview) — so this only ever answers
// "cannot rule truncation out".
// TWO INDEPENDENT FACTS, and both are disclosed when both hold. Truncation is
// about assets that were never read; unvalued rows are about assets that were read and
// could not be priced. Returning the first and skipping the second — which this did —
// silently dropped the pricing disclosure for exactly the contracts where the total is
// least trustworthy: locally 7 of 7 at-the-cap contracts also carry unvalued rows.
function coverageNote(machine) {
  const cov = machine?.holdings_coverage;
  if (!cov) return null;
  const parts = [];
  if (cov.state === "may_be_incomplete") {
    parts.push(
      `Holdings may be incomplete: the fetch returned a full page (${cov.page_cap}). Assets beyond it were never read, so this list and any total from it are lower bounds.`,
    );
  }
  if (cov.unvalued_rows > 0) {
    parts.push(
      `${cov.unvalued_rows} of ${cov.rows} holdings have no determined USD value, so the total below counts only the priced ones.`,
    );
  }
  return parts.length ? parts.join(" ") : null;
}

export function BalanceTable({ machine }) {
  const [hideDust, setHideDust] = useState(true);

  const note = coverageNote(machine);

  if (!machine.balances || machine.balances.length === 0) {
    // An empty list is not "holds nothing": the fetch conflates no-tokens with a
    // failed read, and the failure is recorded only in the operational log
    // (utils/etherscan.get_token_balances). Say what is known.
    return <div className="ps-lane-empty">No token balances recorded</div>;
  }

  // Unpriced rows are KEPT by the dust filter on purpose — a holding of unknown
  // value is not known to be under $10, and hiding it would be the same
  // null-as-zero fold this table just stopped making in the value cell. That
  // asymmetry used to be invisible: the button said "<$10" while silently
  // applying two different rules. It is now counted out loud below.
  const isDust = (b) => {
    const determined = b?.usd_value_state ? b.usd_value_state === "measured" : b?.usd_value != null;
    return determined && b.usd_value < 10;
  };
  const filtered = hideDust ? machine.balances.filter((b) => !isDust(b)) : machine.balances;
  const hiddenCount = machine.balances.length - filtered.length;
  const unpricedShown = filtered.filter(
    (b) => (b?.usd_value_state ? b.usd_value_state !== "measured" : b?.usd_value == null),
  ).length;

  return (
    <section className="ps-balance-section">
      <div className="ps-balance-header">
        <span>Balances</span>
        {machine.total_usd ? <span className="ps-balance-total">{formatUsd(machine.total_usd)}</span> : null}
      </div>
      {note ? <div className="ps-balance-coverage" role="note">{note}</div> : null}
      <button
        className={`ps-balance-filter${hideDust ? " active" : ""}`}
        onClick={() => setHideDust(!hideDust)}
      >
        {hideDust ? `Hide priced <$10 (${hiddenCount})` : "Show all"}
      </button>
      {hideDust && unpricedShown > 0 ? (
        <div className="ps-balance-coverage" role="note">
          {unpricedShown} unpriced {unpricedShown === 1 ? "holding is" : "holdings are"} still listed — an
          unknown value is not a small one.
        </div>
      ) : null}
      <div className="ps-balance-list">
        {filtered.map((b, i) => {
          const human = Number(b.raw_balance) / (10 ** b.decimals);
          const amount = human >= 1e6 ? `${(human / 1e6).toFixed(1)}M`
            : human >= 1e3 ? `${(human / 1e3).toFixed(1)}K`
            : human >= 1 ? human.toFixed(2)
            : human.toFixed(6);
          const usd = usdCell(b);
          return (
            <div key={i} className="ps-balance-row">
              <div className="ps-balance-token">
                <span className="ps-balance-symbol">{b.token_symbol}</span>
                <span className="ps-balance-name">{b.token_name}</span>
              </div>
              <div className="ps-balance-values">
                <span className="ps-balance-amount">{amount}</span>
                <span className={usd.className}>{usd.text}</span>
              </div>
            </div>
          );
        })}
        {filtered.length === 0 && <div className="ps-lane-empty">No holdings priced above $10</div>}
      </div>
    </section>
  );
}
