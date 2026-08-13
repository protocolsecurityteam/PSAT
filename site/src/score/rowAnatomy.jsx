// The anatomy of a score-page row: who acts, on what, and how far it reaches.
// Lifted out of Deductions.jsx so the confidence zone's "proven" cell is the
// SAME components rather than a second reading of the same fields — an entity
// click has to mean one thing on this page, and a row that renders its targets
// twice will eventually render them two different ways.

import { Fragment, useState } from "react";

import EntityButton from "./EntityButton.jsx";

export const TARGETS_SHORT = 3;

// What this row is ABOUT, carried alongside the entity a click asks for: the
// example function the row DISPLAYS (never the other n−1 it counts — the user
// read this one) and the controllers it names — every member of a merged unit,
// because which member gates a given host is the card's fact, not this row's.
// The surface marks the pair its own caller list witnesses, or marks less;
// nothing here asserts any pair is on any particular contract.
export function highlightHint(row) {
  const controllers = row.controllers?.length ? row.controllers : row.controller ? [row.controller] : [];
  if (!row.exampleFunction && !controllers.length) return undefined;
  return { functionSignature: row.exampleFunction || "", controllers };
}

// The row's action line: the example function, the count of the ones it stands
// for, and the address(es) holding the permission. `controllers` is a list
// because one row can speak for several holders of an identical gap; on a
// single-holder row it is the one controller the principal string names.
export function ActorLine({ row, controllers = [], onSelect }) {
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
  for (const controller of controllers) {
    detail.push(
      <EntityButton
        key={`controller-${controller}`}
        onSelect={onSelect}
        target={{ chain: row.finding?.chain, address: controller, label: controller }}
        title="Show this controller on the control surface"
      >
        {`${controller.slice(0, 6)}…${controller.slice(-4)}`}
      </EntityButton>,
    );
  }
  return (
    <span className="sc-addr">
      {detail.map((node, i) => (
        <Fragment key={i}>
          {i > 0 && " · "}
          {node}
        </Fragment>
      ))}
    </span>
  );
}

export function TargetList({ row, onSelect }) {
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
