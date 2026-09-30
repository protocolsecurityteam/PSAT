import { useState } from "react";

import { formatUsd } from "../format.js";

// `usd_value: 0` is priced (under half a cent); `null` is unpriced (most rows).
// Both are falsy in JS and used to print the same dash; `formatUsd` also
// returns null below a cent.
function usdCell(row) {
  const determined = row?.usd_value_state
    ? row.usd_value_state === "measured"
    // Pre-fix payloads have no state key; `usd_value` null already means
    // unpriced.
    : row?.usd_value != null;
  if (!determined) return { text: "not priced", className: "ps-balance-usd unpriced" };
  const formatted = formatUsd(row.usd_value);
  return { text: formatted || "$0.00", className: "ps-balance-usd" };
}

// `holdings_coverage.state` can only say truncation isn't ruled out
// (completeness is unprovable). Pricing coverage is shown per row.
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
    // Not "holds nothing": the fetch conflates no tokens with failed or
    // unattempted.
    return <div className="ps-lane-empty">No token balances recorded</div>;
  }

  // The dust filter keeps unpriced rows: unknown value isn't known to be under
  // $10.
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
          // Describes the filter, not the holdings.
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
