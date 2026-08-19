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

// Whether the backend WITHHELD this balance from the holdings claim. The row is
// still PUBLISHED and LABELLED — a suppressed row is a deletion nobody can see —
// but it is not presented as a position this contract holds, so it is out of the
// holdings list, out of the holdings count, and shown under its own heading.
//
// READ THE BACKEND'S VERDICT; DO NOT RE-DERIVE IT. `disposition_state` exists
// precisely so a consumer does not restate the rule, and restating it is how
// this page went wrong: it split on `delivery_shape === "fan_out_all"` alone,
// which is only HALF the conjunction. The other half is the protocol-reference
// conjunct, and without it the page withheld HEX, WETH and base USDC — real
// assets, one of them a fully-liquid stablecoin — that the score itself spares.
// A page that re-derives a two-part rule will sooner or later carry one part.
//
// A DELIVERY claim, never a worth claim. Real tokens arrive this way (uniETH at
// fan-out 101, HEX at 199/399/399), so the label says how the balance arrived
// and the word "spam" appears nowhere: that would be a claim the evidence does
// not carry.
const DISPOSED = "disposed";

export function isAirdropDelivered(row) {
  // Absence of the field is NOT disposal: a payload from before this field
  // existed, or a row the backend declined to judge, must keep its place in the
  // holdings list. Fail closed toward showing a real holding.
  return row?.disposition_state === DISPOSED;
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
  return `Holdings may be incomplete: the fetch returned a full page (${cov.page_cap}). Assets beyond it were never read, so this list and any total from it are lower bounds.`;
}

function BalanceRow({ row }) {
  const human = Number(row.raw_balance) / 10 ** row.decimals;
  const amount =
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
      <div className="ps-balance-values">
        <span className="ps-balance-amount">{amount}</span>
        <span className={usd.className}>{usd.text}</span>
      </div>
    </div>
  );
}

export function BalanceTable({ machine }) {
  const [hideDust, setHideDust] = useState(true);
  const [showWithheld, setShowWithheld] = useState(false);

  const note = coverageNote(machine);

  if (!machine.balances || machine.balances.length === 0) {
    // An empty list is not "holds nothing": the fetch conflates no-tokens with a
    // failed read, and the failure is recorded only in the operational log
    // (services/clients/etherscan.get_token_balances). Say what is known.
    return <div className="ps-lane-empty">No token balances recorded</div>;
  }

  // Unpriced rows are KEPT by the dust filter on the strength of their price
  // alone — a holding of unknown value is not known to be under $10, and hiding
  // it for being unpriced would be the same null-as-zero fold this table just
  // stopped making in the value cell. The button label below names every ground
  // it is acting on, and each kept row carries its own "not priced" cell.
  const isUnpriced = (b) => (b?.usd_value_state ? b.usd_value_state !== "measured" : b?.usd_value == null);
  const isDust = (b) => !isUnpriced(b) && b.usd_value < 10;
  // The SECOND reason to fold a row out of the default view, and the only one
  // that may act on an unpriced row: the protocol's own discovery does not name
  // this token at all. Locally that separates 2,432 unpriced readings (CANA,
  // SKIMCHI — hand-sent dust the disposition rule correctly declines to withhold,
  // because it did not arrive by mass distribution) from the 23 unpriced readings
  // the protocol does name (weETHs, an ether.fi wrapper), which stay listed.
  //
  // TWO CONJUNCTS, BOTH REQUIRED, and the reference conjunct is READ, never
  // re-derived: `absent_from_universe` is an EARNED negative (see
  // utils/balance_status), so a missing reference row publishes `not_determined`
  // and a row carrying no key at all reads as undefined — neither is a proven
  // absence, and both stay VISIBLE. Fail toward showing, the same direction as
  // the disposition rule above. A priced row is never folded on this ground: a
  // measured dollar figure is a fact about worth that discovery cannot overturn.
  const isUnknownToProtocol = (b) => isUnpriced(b) && b?.reference_shape === "absent_from_universe";
  // ONE hidden group, two admissions into it. Splitting these into two toggles
  // would ask the reader to reason about a filter matrix to answer "what is this
  // contract holding"; folding them into one keeps the default view honest and
  // the button label names each ground it acted on.
  const isFolded = (b) => isDust(b) || isUnknownToProtocol(b);
  // Split BEFORE the fold filter: the two questions are independent, and an
  // airdrop-delivered row must be listed whatever it is worth.
  const holdings = machine.balances.filter((b) => !isAirdropDelivered(b));
  const airdropped = machine.balances.filter(isAirdropDelivered);
  const filtered = hideDust ? holdings.filter((b) => !isFolded(b)) : holdings;
  const hiddenCount = holdings.length - filtered.length;
  const unknownFolded = hideDust ? holdings.filter(isUnknownToProtocol).length : 0;
  // The button names every ground it is acting on. When nothing was folded for
  // the reference ground the label must not mention it — a permanent mention
  // would claim a filter the view is not applying.
  const filterLabel = unknownFolded
    ? `Hide priced <$10 and unnamed by discovery (${hiddenCount})`
    : `Hide priced <$10 (${hiddenCount})`;

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
      {airdropped.length > 0 ? (
        // COLLAPSED, NOT SUPPRESSED. The rows stay reachable in one click and
        // keep their label; only the default density changes.
        <div className="ps-balance-withheld">
          <button
            type="button"
            className="ps-balance-withheld-toggle"
            aria-expanded={showWithheld}
            onClick={() => setShowWithheld((v) => !v)}
          >
            <span>
              {airdropped.length} {airdropped.length === 1 ? "token" : "tokens"} arrived by mass distribution and{" "}
              {airdropped.length === 1 ? "is not a position" : "are not positions"}
            </span>
            <span className="ps-balance-caret">{showWithheld ? "▾" : "▸"}</span>
          </button>
          {showWithheld ? (
            // The toggle line itself carries the whole claim ("arrived by mass
            // distribution", "not positions"); the expanded view is just the rows.
            <div className="ps-balance-list">
              {airdropped.map((b, i) => (
                <BalanceRow key={i} row={b} />
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
