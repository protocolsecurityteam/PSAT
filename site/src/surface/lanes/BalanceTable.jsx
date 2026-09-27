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
// "cannot rule truncation out". Truncation is about assets that were never read;
// pricing coverage is a separate fact, and it is carried per row by the "not
// priced" cell rather than by a sentence here.
function coverageNote(machine) {
  const cov = machine?.holdings_coverage;
  if (cov?.state !== "may_be_incomplete") return null;
  return `Holdings may be incomplete: the provider read was interrupted or capped. Retained observations may be older; omitted assets are unknown.`;
}

function BalanceRow({ row }) {
  const human = Number(row.raw_balance) / 10 ** row.decimals;
  const amount = row.decimals_known === false || row.decimals_known === null ? "quantity scale unknown" :
    human >= 1e6
      ? `${(human / 1e6).toFixed(1)}M`
      : human >= 1e3
        ? `${(human / 1e3).toFixed(1)}K`
        : human >= 1
          ? human.toFixed(2)
          : human.toFixed(6);
  const usd = usdCell(row);
  return (
    <div className="ps-balance-row">
      <div className="ps-balance-token">
        <span className="ps-balance-symbol">{row.token_symbol}</span>
        <span className="ps-balance-name">{row.token_name}</span>
      </div>
      <div className="ps-balance-values" title={row.observed_at ? `Observed ${row.observed_at}` : "Observation time unknown"}>
        <span className="ps-balance-amount">{amount}</span>
        <span className={usd.className}>{usd.text}</span>
      </div>
    </div>
  );
}

export function BalanceTable({ machine }) {
  const [hideDust, setHideDust] = useState(true);

  const note = coverageNote(machine);

  const holdings = machine.balances || [];
  const partialObservations = machine.partial_balance_observations || [];
  if (holdings.length === 0 && partialObservations.length === 0) {
    // An empty list is not "holds nothing": the fetch conflates no-tokens with a
    // failed or unattempted class. Say only what was recorded.
    return <div className="ps-lane-empty">No token balances recorded</div>;
  }

  // Unpriced rows are KEPT by the dust filter on the strength of their price
  // alone — a holding of unknown value is not known to be under $10, and hiding
  // it for being unpriced would be the same null-as-zero fold this table just
  // stopped making in the value cell. The button label below names every ground
  // it is acting on, and each kept row carries its own "not priced" cell.
  const isUnpriced = (b) => (b?.usd_value_state ? b.usd_value_state !== "measured" : b?.usd_value == null);
  const isDust = (b) => !isUnpriced(b) && b.usd_value < 10;
  const filtered = hideDust ? holdings.filter((b) => !isDust(b)) : holdings;
  const hiddenCount = holdings.length - filtered.length;
  const filterLabel = `Hide priced <$10 (${hiddenCount})`;

  return (
    <section className="ps-balance-section">
      <div className="ps-balance-header">
        <span>Balances</span>
        {machine.total_usd != null ? <span className="ps-balance-total">{formatUsd(machine.total_usd) || "$0.00"} observed</span> : null}
      </div>
      {note ? <div className="ps-balance-coverage" role="note">{note}</div> : null}
      <button
        className={`ps-balance-filter${hideDust ? " active" : ""}`}
        onClick={() => setHideDust(!hideDust)}
      >
        {hideDust ? filterLabel : "Show all"}
      </button>
      <div className="ps-balance-list">
        {filtered.map((b, i) => (
          <BalanceRow key={i} row={b} />
        ))}
        {filtered.length === 0 && (
          // Says what the FILTER did, not what the contract holds: with the
          // reference ground folding rows too, "nothing above $10" would be a
          // false statement about a list that may also be hiding unpriced rows.
          <div className="ps-lane-empty">
            {hiddenCount > 0 ? "Every holding is hidden by the filter above" : "No holdings to list"}
          </div>
        )}
      </div>
      {machine.partial_balance_observations?.length > 0 && (
        <details className="ps-balance-partial">
          <summary>Newer partial observations ({machine.partial_balance_observations.length})</summary>
          <div role="note">Separate provider prefix; not added to the retained total.</div>
          {machine.partial_balance_observations.map((row, i) => <BalanceRow key={i} row={row} />)}
        </details>
      )}
    </section>
  );
}
