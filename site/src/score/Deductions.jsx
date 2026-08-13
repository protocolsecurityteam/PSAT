import { Fragment, useState } from "react";

import BoundBadge from "./BoundBadge.jsx";
import CapabilityTag from "./CapabilityTag.jsx";
import EntityButton, { entityProps } from "./EntityButton.jsx";
import TailToggle from "./TailToggle.jsx";
import { shortAddress } from "./format.js";
import { ActorLine, TargetList } from "./rowAnatomy.jsx";

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

// The kind chip is the row's handle on who acts — clickable exactly like the
// protections side's chip. A merged chip splits into one handle per member:
// each k/n selects its own Safe, so no click has to pick a member for the
// user. On the single-member kinds the whole chip selects the controller; a
// principal with no address (Anyone) stays a plain chip.
function KindChip({ row, onSelect }) {
  const { chip } = row;
  const chain = row.finding?.chain;
  if (chip.members?.length) {
    return (
      <span className={`sc-kchip sc-kchip-${chip.kind}`}>
        {"Safes "}
        {chip.members.map((member, i) => (
          <Fragment key={member.address}>
            {i > 0 && " + "}
            <EntityButton
              onSelect={onSelect}
              target={{ chain, address: member.address, label: `Safe ${member.shape}` }}
              title={`Show Safe ${member.shape} (${shortAddress(member.address)}) on the control surface`}
            >
              {member.shape}
            </EntityButton>
          </Fragment>
        ))}
        {" · shared keys"}
      </span>
    );
  }
  const props = entityProps({
    onSelect,
    target: { chain, address: row.controller, label: chip.label },
    title: row.controller ? `Show ${shortAddress(row.controller)} on the control surface` : undefined,
  });
  return (
    <span className={`sc-kchip sc-kchip-${chip.kind}${props ? " sc-lnk" : ""}`} {...(props || {})}>
      {chip.label}
    </span>
  );
}

function DeductionRow({ row, onSelect }) {
  const { value } = row;
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
          <KindChip row={row} onSelect={onSelect} />
          <CapabilityTag capability={row.capability} />
          <ActorLine row={row} onSelect={onSelect} />
        </div>
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
