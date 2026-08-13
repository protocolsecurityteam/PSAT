import { useState } from "react";

import BoundBadge from "./BoundBadge.jsx";
import CapabilityTag from "./CapabilityTag.jsx";
import EntityButton from "./EntityButton.jsx";
import TailToggle from "./TailToggle.jsx";
import { ActorLine, ControllersLine, TargetList } from "./rowAnatomy.jsx";

const VISIBLE_ROWS = 8;

// The disposed part of a row's sheet, printed with its figure attached. A zero
// with no reason beside it reads as "this reaches nothing"; the reason is what
// makes it a delivery-shape statement instead. `usdText: null` means the
// document published no number for the disposed entries, and that renders as
// not-determined rather than as another zero.
function SheetDispositionBadge({ disposition }) {
  if (!disposition) return null;
  return (
    <span className="sc-fl" title={disposition.reason}>
      {disposition.usdText || "not determined"} · {disposition.label}
    </span>
  );
}

function DeductionRow({ row, onSelect }) {
  const { chip, value } = row;
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
          <CapabilityTag capability={row.capability} />
          <ActorLine row={row} onSelect={onSelect} />
        </div>
        <ControllersLine
          row={row}
          controllers={row.controllers?.length ? row.controllers : row.controller ? [row.controller] : []}
          onSelect={onSelect}
        />
        <div className="sc-fbar">
          <div className="sc-track" style={{ width: `${row.trackPct}%` }} />
          <div className="sc-fill" style={{ width: `${row.fillPct}%` }} />
        </div>
        <TargetList row={row} onSelect={onSelect} />
      </div>
      <span className="sc-val">
        {value.determined ? (
          <>
            {value.text}
            <BoundBadge direction={value.direction} />
          </>
        ) : row.provenNoReach ? (
          <>proven no reach</>
        ) : (
          <span className="sc-nd">value not determined</span>
        )}
        <SheetDispositionBadge disposition={row.sheetDisposition} />
      </span>
    </div>
  );
}

function FixFirst({ fix, onSelect }) {
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
                <b>
                  <CapabilityTag capability={capability} />
                </b>
              </span>
            ))}
            {fix.exampleFunction ? (
              <>
                {" — fixing "}
                <EntityButton
                  onSelect={onSelect}
                  target={{
                    chain: fix.host?.chain || fix.chain,
                    ...(fix.host ? { address: fix.host.address } : {}),
                    functionSignature: fix.exampleFunction,
                    label: fix.exampleFunction,
                    ...(fix.controllers?.length
                      ? { highlight: { functionSignature: fix.exampleFunction, controllers: fix.controllers } }
                      : {}),
                  }}
                  title={`Show ${fix.exampleFunction} on the control surface`}
                >
                  {fix.exampleFunction}
                </EntityButton>
                {" alone does not release them."}
              </>
            ) : (
              "."
            )}
          </>
        )}
      </span>
    </div>
  );
}

export default function Deductions({ view, onSelect }) {
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
        <DeductionRow key={row.index} row={row} onSelect={onSelect} />
      ))}
      {tailOpen && tail.map((row) => <DeductionRow key={row.index} row={row} onSelect={onSelect} />)}
      {tail.length > 0 && (
        <TailToggle open={tailOpen} onToggle={() => setTailOpen((was) => !was)}>
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
        </TailToggle>
      )}
      <FixFirst fix={view.fix} onSelect={onSelect} />
    </div>
  );
}
