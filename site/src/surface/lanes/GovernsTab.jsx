import { useState } from "react";

import { fnChipClass, formatUsd, shortAddr } from "../format.js";
import { GotoArrow } from "../GotoArrow.jsx";

// One shared row for both Governs sections. Collapsed content is identical
// everywhere: contract name (+ proxy/impl tag), short address, USD value when
// known. Clicking the row head previews the contract on the canvas (gold marker
// + pan) — no selection change; the trailing arrow commits to its card. A ghost
// "N fns" button appears only when the row carries function data (every Can Call
// row does; governance-path rows are reachability-only and never do) and expands
// to the full function-chip list.
function GovernsRow({ row, onPreview, onNavigate }) {
  const [open, setOpen] = useState(false);
  const label = row.name || shortAddr(row.address);
  const functions = Array.isArray(row.functions) ? row.functions : [];
  const usd = formatUsd(row.total_usd);

  return (
    <div className="ps-governs-row">
      <div
        className="ps-governs-head"
        role="button"
        tabIndex={0}
        onClick={() => onPreview && onPreview(row.address)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onPreview && onPreview(row.address);
          }
        }}
      >
        <span className="ps-governs-name">
          {label}
          {row.tag ? <span className="ps-governs-tag"> ({row.tag})</span> : null}
        </span>
        <span className="ps-governs-addr">{shortAddr(row.address)}</span>
        {usd ? <span className="ps-governs-value">{usd}</span> : null}
        {functions.length > 0 ? (
          <button
            type="button"
            className="ps-governs-expand"
            aria-expanded={open}
            onClick={(e) => {
              e.stopPropagation();
              setOpen((v) => !v);
            }}
          >
            {functions.length} fns
            <span className="ps-governs-caret">{open ? "▾" : "▸"}</span>
          </button>
        ) : null}
        {onNavigate && (
          <GotoArrow onCommit={() => onNavigate({ type: "contract", address: row.address, label })} label={`Go to ${label}`} />
        )}
      </div>
      {open && functions.length > 0 && (
        <div className="ps-ctrl-fns">
          {functions.map((fn) => (
            <span className={`ps-ctrl-fnchip ${fnChipClass(fn)}`} key={fn}>{fn}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// The Governs tab of the universal entity card: "authority OUT" — what this
// entity can do TO other contracts. Two sections share one row shape:
//
//   1. Can Call — one row per governed contract (client-inverted from every
//      contract's per-function authority, so it resolves for machine-only
//      authorities too). Rows carry the concrete function list, expandable.
//   2. Appears in governance path for — the server-walked reached set (the
//      same record the canvas reach chips render). Reachability-only, so rows
//      carry no function list (no expand button). `frontierCount` — on-page
//      destinations the server walk could NOT confirm a path to — renders as
//      a count line only, never as rows: not_determined stays a distinct
//      third state from reached.
//
// Both lists are pre-deduped and proxy/impl-tagged by the card. Every row body
// previews the contract on the canvas; its arrow commits to the contract's card.
export function GovernsTab({ canCallRows, pathRows, frontierCount = 0, onPreview, onNavigate }) {
  if (!canCallRows.length && !pathRows.length && !frontierCount) {
    return <div className="ps-lane-empty">Governs nothing</div>;
  }

  return (
    <div className="ps-governs">
      {canCallRows.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">
            <span title="Verified from per-function access control — the concrete privileged functions this entity can call on other contracts">
              Can Call ({canCallRows.length})
            </span>
          </div>
          {canCallRows.map((row) => (
            <GovernsRow key={row.address} row={row} onPreview={onPreview} onNavigate={onNavigate} />
          ))}
        </section>
      )}

      {pathRows.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">
            <span title="The server-computed control-graph walk — does not imply direct call rights on these contracts' privileged functions">
              Appears In Governance Path For ({pathRows.length})
            </span>
          </div>
          {pathRows.map((row) => (
            <GovernsRow key={row.address} row={row} onPreview={onPreview} onNavigate={onNavigate} />
          ))}
        </section>
      )}

      {frontierCount > 0 && (
        <div className="ps-governs-ndcount">
          reach unconfirmed · {frontierCount} destination{frontierCount === 1 ? "" : "s"}
        </div>
      )}
    </div>
  );
}
