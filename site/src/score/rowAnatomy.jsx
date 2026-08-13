// The anatomy of a score-page row: who acts, on what, and how far it reaches.
// Lifted out of Deductions.jsx so the protections panel and the confidence
// zone's "proven" cell are the SAME components rather than second readings of
// the same fields — an entity click has to mean one thing on this page, and a
// row that renders its targets twice will eventually render them two
// different ways.

import { Fragment, useState } from "react";

import EntityButton, { entityProps } from "./EntityButton.jsx";
import { shortAddress } from "./format.js";

export const TARGETS_SHORT = 3;

// The kind chip is a row's handle on WHO ACTS, on every panel that renders
// one. A merged chip splits into one handle per member: each k/n selects its
// own Safe, so no click has to pick a member for the user. A single-member
// chip selects its controller whole — the interactive props go onto the chip
// span itself rather than a wrapper, which would become the flex item and
// change what the row lays out. A principal with no address stays plain.
export function KindChip({ chip, chain, controller, onSelect }) {
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
  // A merged chip whose member shapes are unwitnessed has no honest single
  // target: the one address on hand is an arbitrary member, and clicking it
  // under the unit's label would attribute the whole unit's power to one Safe
  // — the exact misattribution the member handles exist to prevent.
  const props = chip.merged
    ? null
    : entityProps({
        onSelect,
        target: { chain, address: controller, label: chip.label },
        title: controller ? `Show ${shortAddress(controller)} on the control surface` : undefined,
      });
  return (
    <span className={`sc-kchip sc-kchip-${chip.kind}${props ? " sc-lnk" : ""}`} {...(props || {})}>
      {chip.label}
    </span>
  );
}

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

// The row's action line: the example function and, on rows that aggregate
// several holders of one identical gap (the possible-deductions table), the
// addresses holding the permission.
export function ActorLine({ row, controllers = [], onSelect }) {
  // The function click names its host when the document does: a single-host
  // row selects that contract and marks the function/controller pair on it.
  // A multi-host row's displayed example could live on any of them, so the
  // click stays name-only and the surface graph resolves or declines.
  const host = row.hosts.length === 1 ? row.hosts[0] : null;
  const detail = [];
  if (row.exampleFunction) {
    detail.push(
      <EntityButton
        key={row.exampleFunction}
        onSelect={onSelect}
        target={{
          chain: host?.chain || row.finding?.chain,
          ...(host ? { address: host.address } : {}),
          functionSignature: row.exampleFunction,
          label: row.exampleFunction,
          // The controller rides along so the resolved row can mark the caller
          // chip too — the row names an action AND who can take it.
          highlight: highlightHint(row),
        }}
        title={`Show ${row.exampleFunction} on the control surface`}
      >
        {row.exampleFunction}
      </EntityButton>,
    );
  }
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
  const { hosts, targets, reachWitnessed } = row;
  if (!hosts.length && !targets.length) return null;
  const hint = highlightHint(row);
  // Hosts and reach share the collapsed line's budget, hosts first — a row
  // with dozens of hosts must not push its reach out of the line entirely.
  const shownHosts = open ? hosts : hosts.slice(0, TARGETS_SHORT);
  const shown = open ? targets : targets.slice(0, Math.max(0, TARGETS_SHORT - shownHosts.length));
  const hiddenCount = hosts.length - shownHosts.length + targets.length - shown.length;
  return (
    <div className={`sc-targets${open ? " sc-open" : ""}`}>
      {/* The entity line ellipsises on its own, INSIDE this child — the
          expander button is a sibling the flex row never shrinks, so a run of
          long names can eat the line but never the control that reveals the
          rest. */}
      <span className="sc-targets-line">
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
      {hosts.length > 0 && (targets.length > 0 || !reachWitnessed) && " "}
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
      </span>
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
    </div>
  );
}
