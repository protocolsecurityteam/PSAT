import { fnChipClass, formatUsd } from "../format.js";
import { EntityRef } from "../EntityRef.jsx";

// Shared row: head previews, arrow commits. The "N fns" button appears only on
// Can Call rows (path rows are reachability-only).
function GovernsRow({ row, onPreview, onNavigate }) {
  const functions = Array.isArray(row.functions) ? row.functions : [];
  return (
    <EntityRef
      address={row.address}
      name={row.name}
      tag={row.tag}
      value={formatUsd(row.total_usd)}
      summary={functions.length > 0 ? `${functions.length} fns` : null}
      onPreview={onPreview}
      onNavigate={onNavigate}
    >
      <div className="ps-ctrl-fns">
        {functions.map((fn) => (
          <span className={`ps-ctrl-fnchip ${fnChipClass(fn)}`} key={fn}>{fn}</span>
        ))}
      </div>
    </EntityRef>
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
