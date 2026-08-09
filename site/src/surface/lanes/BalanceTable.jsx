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
  // Split BEFORE the dust filter: the two questions are independent, and an
  // airdrop-delivered row must be listed whatever it is worth.
  const holdings = machine.balances.filter((b) => !isAirdropDelivered(b));
  const airdropped = machine.balances.filter(isAirdropDelivered);
  const filtered = hideDust ? holdings.filter((b) => !isDust(b)) : holdings;
  const hiddenCount = holdings.length - filtered.length;
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
        {filtered.map((b, i) => (
          <BalanceRow key={i} row={b} />
        ))}
        {filtered.length === 0 && <div className="ps-lane-empty">No holdings priced above $10</div>}
      </div>
      {airdropped.length > 0 ? (
        <>
          {/*
            States the THRESHOLD, not a size. The superseded wording said every
            delivery "went to hundreds of recipients at once", which is false of
            42 of its own carriers on the reference corpus — the smallest
            disposed fan-out measured is 27 — and it used the recipient meter,
            which is not what the threshold is calibrated on. The meter is
            same-token transfer LOGS in one transaction, and a log count is an
            upper bound on distinct recipients; the only claim the evidence
            carries is that every delivery cleared the published threshold.
          */}
          <div className="ps-balance-coverage" role="note">
            {airdropped.length} {airdropped.length === 1 ? "balance" : "balances"} below arrived only by mass
            distribution — every delivery on record carried at least the published fan-out threshold of same-token
            transfer logs in one transaction. They are listed because the contract does hold them, and kept out of
            the holdings above because arriving in a distribution is not taking a position. This is a statement
            about how the balance arrived and not about what it is worth.
          </div>
          <div className="ps-balance-list">
            {airdropped.map((b, i) => (
              <BalanceRow key={i} row={b} />
            ))}
          </div>
        </>
      ) : null}
    </section>
  );
}
