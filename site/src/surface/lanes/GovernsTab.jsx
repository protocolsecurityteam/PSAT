import { useState } from "react";

import { fnChipClass, formatUsd, shortAddr } from "../format.js";

// The Governs tab of the universal entity card: "authority OUT" — what this
// entity can do TO other contracts. Two sections mirror the old PrincipalDetail:
//
//   1. Can Call — one row per governed contract (client-inverted from every
//      contract's per-function authority, so it resolves for machine-only
//      authorities too). Collapsed by default; expands to the full function
//      list. Capability tags come from the server when the entity also has a
//      principal facet (controls_detail); otherwise the row shows a count.
//   2. Appears in governance path for — the (transitive) reachability set, with
//      a pager + focus-on-click, kept from PrincipalDetail.
//
// Both lists are pre-deduped and proxy/impl-tagged by the card.
export function GovernsTab({ canCallRows, capabilitiesByContract, pathRows, onNavigate, onFocusContract }) {
  const [expanded, setExpanded] = useState(() => new Set());
  const [focusIdx, setFocusIdx] = useState(0);

  if (!canCallRows.length && !pathRows.length) {
    return <div className="ps-lane-empty">Governs nothing</div>;
  }

  const toggle = (address) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(address)) next.delete(address);
      else next.add(address);
      return next;
    });

  return (
    <div className="ps-governs">
      {canCallRows.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">
            <span title="Verified from per-function access control — the concrete privileged functions this entity can call on other contracts">
              Can Call ({canCallRows.length})
            </span>
          </div>
          {canCallRows.map((row) => {
            const caps = capabilitiesByContract.get(row.address) || [];
            const isOpen = expanded.has(row.address);
            const label = row.name || shortAddr(row.address);
            return (
              <div className="ps-governs-row" key={row.address}>
                <div className="ps-governs-head">
                  <button
                    type="button"
                    className="ps-governs-toggle"
                    aria-expanded={isOpen}
                    onClick={() => toggle(row.address)}
                  >
                    <span className={`ps-governs-caret${isOpen ? " ps-governs-caret-open" : ""}`}>▸</span>
                    <span className="ps-governs-name">
                      {label}
                      {row.tag ? <span className="ps-governs-tag"> ({row.tag})</span> : null}
                    </span>
                    <span className="ps-governs-summary">
                      {caps.length ? caps.join(", ") : `${row.functions.length} fn`}
                    </span>
                  </button>
                  <button
                    type="button"
                    className="ps-governs-goto"
                    title={`View ${label}`}
                    onClick={() => onNavigate && onNavigate({ type: "contract", address: row.address })}
                  >
                    →
                  </button>
                </div>
                {isOpen && (
                  <div className="ps-ctrl-fns">
                    {row.functions.map((fn) => (
                      <span className={`ps-ctrl-fnchip ${fnChipClass(fn)}`} key={fn}>{fn}</span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </section>
      )}

      {pathRows.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            {/* Reachability over the control graph — does not, on its own, imply
                direct call rights on these contracts' privileged functions. */}
            <span title="Computed from the recursive control graph — does not imply direct call rights on these contracts' privileged functions">
              Appears In Governance Path For ({pathRows.length})
            </span>
            {pathRows.length > 1 && (
              <div className="ps-search-arrows" style={{ marginLeft: 8 }}>
                <button onClick={() => {
                  const prev = (focusIdx - 1 + pathRows.length) % pathRows.length;
                  setFocusIdx(prev);
                  onFocusContract && onFocusContract(pathRows[prev].address);
                }}>◀</button>
                <span className="ps-search-counter">{focusIdx + 1} / {pathRows.length}</span>
                <button onClick={() => {
                  const next = (focusIdx + 1) % pathRows.length;
                  setFocusIdx(next);
                  onFocusContract && onFocusContract(pathRows[next].address);
                }}>▶</button>
              </div>
            )}
          </div>
          {pathRows.map((row, i) => (
            <div
              key={row.address}
              className={`ps-principal-controlled ps-principal-clickable${i === focusIdx ? " ps-principal-focused" : ""}`}
              onClick={() => {
                setFocusIdx(i);
                onFocusContract && onFocusContract(row.address);
              }}
            >
              <span className="ps-principal-controlled-name">
                {row.name || shortAddr(row.address)}
                {row.tag ? <span className="ps-governs-tag"> ({row.tag})</span> : null}
              </span>
              <span className="ps-principal-controlled-addr">{shortAddr(row.address)}</span>
              {row.total_usd ? <span className="ps-search-preview-value">{formatUsd(row.total_usd)}</span> : null}
              <span className="ps-principal-goto">→</span>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}
