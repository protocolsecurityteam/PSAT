// Row anatomy shared by deductions, protections and the confidence zone, so an
// entity click means one thing.

import { Fragment, useState } from "react";

import EntityButton, { entityProps } from "./EntityButton.jsx";
import { shortAddress } from "./format.js";

const TARGETS_SHORT = 3;

// A merged chip splits into one handle per member so no click picks a member
// for the user. Props go on the chip span; a wrapper would change the flex
// layout.
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
  // No honest single target: clicking an arbitrary member would attribute the
  // unit's power to one Safe.
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

// The displayed example function and every named controller; the surface marks
// only pairs its own caller list witnesses.
function highlightHint(row) {
  const controllers = row.controllers?.length ? row.controllers : row.controller ? [row.controller] : [];
  if (!row.exampleFunction && !controllers.length) return undefined;
  return { functionSignature: row.exampleFunction || "", controllers };
}

export function ActorLine({ row, controllers = [], onSelect }) {
  // Multi-host rows keep the click name-only: the example could live on any
  // host.
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
  // Hosts first within the collapsed budget, so many hosts can't push reach off
  // the line.
  const shownHosts = open ? hosts : hosts.slice(0, TARGETS_SHORT);
  const shown = open ? targets : targets.slice(0, Math.max(0, TARGETS_SHORT - shownHosts.length));
  const hiddenCount = hosts.length - shownHosts.length + targets.length - shown.length;
  return (
    <div className={`sc-targets${open ? " sc-open" : ""}`}>
      {/* Ellipsises inside this child; the expander is a non-shrinking sibling. */}
      <span className="sc-targets-line">
      {/*
        Hosts (direct) before the arrow; reach through the graph after, a
        weaker relationship.
      */}
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
      {/* Hosts say nothing about reach, so the note survives an empty list. */}
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
        // Where reach started; the surface picks whichever host actually
        // reaches this entity.
        const reachedFrom = hosts.map((host) => host.address);
        // Navigating isn't a claim of reach; the qualifier keeps the third
        // state for screen readers and hover.
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
