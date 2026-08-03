import { Fragment, useState } from "react";

import EntityButton from "./EntityButton.jsx";

const VISIBLE_ROWS = 8;
const TARGETS_SHORT = 3;

// What this row is ABOUT, carried alongside the entity a click asks for: the
// example function the row DISPLAYS (never the other n−1 it counts — the user
// read this one) and the controller it names. The surface marks that pair on
// the card it opens, or marks less; nothing here asserts the pair is on any
// particular contract.
function highlightHint(row) {
  if (!row.exampleFunction && !row.controller) return undefined;
  return { functionSignature: row.exampleFunction || "", controller: row.controller || "" };
}

function TargetList({ row, onSelect }) {
  const [open, setOpen] = useState(false);
  const { hosts, targets, reachWitnessed, undeterminedCount } = row;
  if (!hosts.length && !targets.length) return null;
  const hint = highlightHint(row);
  // Hosts and reach share the collapsed line's budget, hosts first — a row
  // with dozens of hosts must not push its reach out of the line entirely.
  const shownHosts = open ? hosts : hosts.slice(0, TARGETS_SHORT);
  const shown = open ? targets : targets.slice(0, Math.max(0, TARGETS_SHORT - shownHosts.length));
  const hiddenCount = hosts.length - shownHosts.length + targets.length - shown.length;
  return (
    <div className={`sc-targets${open ? " sc-open" : ""}`}>
      {/* The hosts come first and apart: they are the contracts the function
          is ON — where the named controller acts directly. Everything after
          the arrow is reach through the control graph, a different (weaker)
          relationship that must not read as more direct calls. */}
      {shownHosts.map((host, i) => {
        const label = host.name || host.short;
        return (
          <span key={host.canonical} className="sc-host">
            {i > 0 && " · "}
            <EntityButton
              onSelect={onSelect}
              target={{ chain: host.chain, address: host.address, label, highlight: hint }}
              title={`Show ${label} on the control surface — the function lives here`}
            >
              {host.name ? <b>{host.name}</b> : null} {host.short}
            </EntityButton>
          </span>
        );
      })}
      {hosts.length > 0 && (targets.length > 0 || undeterminedCount > 0 || !reachWitnessed) && " "}
      {/* The not-witnessed note survives an empty list: hosts are where the
          function IS, which says nothing about what it reaches. */}
      {reachWitnessed && shown.length > 0 && (
        <span className="sc-arr">{shownHosts.length ? "→ reaches" : "→"}</span>
      )}
      {!reachWitnessed && (
        <span className="sc-ndp">
          {shownHosts.length ? "· reach not witnessed" : "reach not witnessed"}
          {shown.length > 0 ? " ·" : ""}
        </span>
      )}{" "}
      {shown.map((target, i) => {
        const label = target.name || target.short;
        // Where the reach STARTED. The row's hosts are the contracts the named
        // controller acts on directly; this entity is downstream of them, and
        // its own card says nothing about the deduction without that. All hosts
        // ride along — the surface picks whichever one actually reaches this
        // entity in the graph it carries, which the score document does not say.
        const reachedFrom = hosts.map((host) => host.address);
        // Navigating to an entity is not a claim that the capability reaches
        // it. Where reach was never witnessed the button still works, but the
        // qualifier rides along in the interaction — a screen-reader user or a
        // hover must not lose the third state the line carries visually.
        const qualifier = reachWitnessed ? "" : " — reach not witnessed";
        return (
          <span key={target.canonical} className="sc-reached">
            {i > 0 && " · "}
            <EntityButton
              onSelect={onSelect}
              target={{
                chain: target.chain,
                address: target.address,
                label,
                highlight: hint,
                ...(reachWitnessed && reachedFrom.length ? { reachedFrom } : {}),
              }}
              title={`Show ${label} on the control surface${qualifier}`}
              ariaLabel={reachWitnessed ? undefined : `${label} — reach not witnessed`}
            >
              {target.name ? <b>{target.name}</b> : null} {target.short}
            </EntityButton>
          </span>
        );
      })}
      {hiddenCount > 0 && (
        <>
          {" "}
          <button type="button" className="sc-tbtn" onClick={() => setOpen(true)}>
            +{hiddenCount} more
          </button>
        </>
      )}
      {open && hosts.length + targets.length > TARGETS_SHORT && (
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

function DeductionRow({ row, onSelect }) {
  const { chip, value } = row;
  // The function click names its host when the document does: a single-host
  // row selects that contract and marks the function/controller pair on it.
  // A multi-host row's displayed example could live on any of them, so the
  // click stays name-only and the surface graph resolves or declines.
  const host = row.hosts.length === 1 ? row.hosts[0] : null;
  const detail = row.functions.map((part) =>
    part === row.exampleFunction ? (
      <EntityButton
        key={part}
        onSelect={onSelect}
        target={{
          chain: host?.chain || row.finding?.chain,
          ...(host ? { address: host.address } : {}),
          functionSignature: part,
          label: part,
          // The controller rides along so the resolved row can mark the caller
          // chip too — the row names an action AND who can take it.
          highlight: highlightHint(row),
        }}
        title={`Show ${part} on the control surface`}
      >
        {part}
      </EntityButton>
    ) : (
      <span key={part}>{part}</span>
    ),
  );
  if (row.controller) {
    detail.push(
      <EntityButton
        key="controller"
        onSelect={onSelect}
        target={{ chain: row.finding?.chain, address: row.controller, label: row.controller }}
        title="Show this controller on the control surface"
      >
        {`${row.controller.slice(0, 6)}…${row.controller.slice(-4)}`}
      </EntityButton>,
    );
  }
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
          <span className="sc-addr">
            {detail.map((node, i) => (
              <Fragment key={i}>
                {i > 0 && " · "}
                {node}
              </Fragment>
            ))}
          </span>
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
                <b>{capability}</b>
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
                    ...(fix.controller
                      ? { highlight: { functionSignature: fix.exampleFunction, controller: fix.controller } }
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
      <FixFirst fix={view.fix} onSelect={onSelect} />
    </div>
  );
}
