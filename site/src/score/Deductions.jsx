import { useState } from "react";

const VISIBLE_ROWS = 8;
const TARGETS_SHORT = 3;

// Phase 4 turns the contract names, the controller address and the example
// function into buttons that select the entity on the embedded surface. Until
// that selection handle exists they render as plain text — an element that
// looks clickable and does nothing is worse than one that doesn't.
function TargetList({ row }) {
  const [open, setOpen] = useState(false);
  const { targets, reachWitnessed, undeterminedCount } = row;
  if (!targets.length) return null;
  const shown = open ? targets : targets.slice(0, TARGETS_SHORT);
  const hiddenCount = targets.length - shown.length;
  return (
    <div className={`sc-targets${open ? " sc-open" : ""}`}>
      {reachWitnessed ? (
        <span className="sc-arr">→</span>
      ) : (
        <span className="sc-ndp">reach not witnessed ·</span>
      )}{" "}
      {shown.map((target, i) => (
        <span key={target.canonical}>
          {i > 0 && " · "}
          {target.name ? <b>{target.name}</b> : null} {target.short}
        </span>
      ))}
      {hiddenCount > 0 && (
        <>
          {" "}
          <button type="button" className="sc-tbtn" onClick={() => setOpen(true)}>
            +{hiddenCount} more
          </button>
        </>
      )}
      {open && targets.length > TARGETS_SHORT && (
        <>
          {" "}
          <button type="button" className="sc-tbtn" onClick={() => setOpen(false)}>
            less
          </button>
        </>
      )}
      {reachWitnessed && undeterminedCount > 0 && (
        <span className="sc-ndp"> · +{undeterminedCount} not determined</span>
      )}
    </div>
  );
}

function DeductionRow({ row }) {
  const { chip, value } = row;
  const detail = [...row.functions];
  if (row.controller) detail.push(`${row.controller.slice(0, 6)}…${row.controller.slice(-4)}`);
  return (
    <div className="sc-frow">
      <span className="sc-pts">
        {row.net !== null ? (
          `−${row.net.toFixed(2)}`
        ) : row.raw !== null ? (
          row.raw.toFixed(2)
        ) : (
          <span className="sc-nd">not determined</span>
        )}
      </span>
      <div>
        <div className="sc-who">
          <span className={`sc-kchip sc-kchip-${chip.kind}`}>{chip.label}</span>
          <span className="sc-cap">{row.capability}</span>
          {/* Phase 4: function name + controller become surface selections. */}
          <span className="sc-addr">{detail.join(" · ")}</span>
        </div>
        <div className="sc-fbar">
          <div className="sc-track" style={{ width: `${row.trackPct}%` }} />
          <div className="sc-fill" style={{ width: `${row.fillPct}%` }} />
        </div>
        <TargetList row={row} />
      </div>
      <span className="sc-val">
        {value.determined ? (
          <>
            {value.text}
            {value.floor && <span className="sc-fl">floor</span>}
          </>
        ) : row.provenNoReach ? (
          <>proven no reach</>
        ) : (
          <span className="sc-nd">value not determined</span>
        )}
      </span>
    </div>
  );
}

function FixFirst({ fix }) {
  if (!fix) return null;
  return (
    <div className="sc-fix">
      <span className="sc-fixk">Fix first</span>
      <span>
        {fix.verb} {fix.subject}
        {fix.remedy} — modeled recovery up to <b>{fix.recovery.toFixed(1)} points</b> (λ{" "}
        {fix.lambdaBefore.toFixed(1)} → {fix.lambdaAfter.toFixed(1)}; rank decay promotes the
        remaining findings).
        {fix.subsumed.length > 0 && (
          <>
            {" "}
            {fix.count === 1 ? "This row also subsumes" : "These rows also subsume"}{" "}
            {fix.subsumed.map((capability, i) => (
              <span key={capability}>
                {i > 0 && (i === fix.subsumed.length - 1 ? " and " : ", ")}
                <b>{capability}</b>
              </span>
            ))}
            {fix.exampleFunction ? ` — fixing ${fix.exampleFunction} alone does not release them.` : "."}
          </>
        )}
      </span>
    </div>
  );
}

export default function Deductions({ view }) {
  const [tailOpen, setTailOpen] = useState(false);
  const rows = view.rows;
  const head = rows.slice(0, VISIBLE_ROWS);
  const tail = rows.slice(VISIBLE_ROWS);
  // A total over rows whose nets were never published is not a total. Summing
  // them as zeroes would render "−0.00 combined" — a measured-looking figure
  // for a quantity the document withheld.
  const tailSummable = tail.every((r) => r.net !== null);
  const tailSum = tailSummable
    ? Math.round(tail.reduce((sum, r) => sum + r.net, 0) * 100) / 100
    : null;
  const tailNd = tail.filter((r) => !r.value.determined && !r.provenNoReach).length;

  return (
    <div>
      <h2 className="sc-band-title">Deductions</h2>
      {head.map((row) => (
        <DeductionRow key={row.index} row={row} />
      ))}
      {tailOpen && tail.map((row) => <DeductionRow key={row.index} row={row} />)}
      {tail.length > 0 && (
        <button type="button" className="sc-tail-btn" onClick={() => setTailOpen((was) => !was)}>
          {tailOpen ? (
            <>
              <span className="sc-tail-chev">▲</span> hide the tail
            </>
          ) : (
            <>
              + {tail.length} more ·{" "}
              {tailSum === null ? (
                <i className="sc-nd">combined points not determined</i>
              ) : (
                `−${tailSum.toFixed(2)} combined`
              )}
              {tailNd > 0 && (
                <>
                  {" "}
                  · {tailNd} with <i>value not determined</i>
                </>
              )}
              <span className="sc-tail-chev">▼</span>
            </>
          )}
        </button>
      )}
      <FixFirst fix={view.fix} />
    </div>
  );
}
