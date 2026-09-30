import { useState } from "react";

import { fnChipClass, formatUsd, shortAddr } from "../format.js";
import { GotoArrow } from "../GotoArrow.jsx";
import { clickable } from "../../shared/clickable.js";

// Shared row: head previews, arrow commits. The "N fns" button appears only on
// Can Call rows (path rows are reachability-only).
function GovernsRow({ row, onPreview, onNavigate }) {
  const [open, setOpen] = useState(false);
  const label = row.name || shortAddr(row.address);
  const functions = Array.isArray(row.functions) ? row.functions : [];
  const usd = formatUsd(row.total_usd);

  return (
    <div className="ps-governs-row">
      <div
        className="ps-governs-head"
        {...clickable(() => onPreview && onPreview(row.address))}
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

// Authority out, in two sections sharing one row shape:
//
// 1. Can Call — per governed contract, client-inverted so machine-only
//      authorities resolve; expandable functions.
// 2. Appears in governance path for — the server-walked reached set (same as
//      the canvas chips). `frontierCount` is only a count line: not_determined
//      stays distinct from reached.
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
