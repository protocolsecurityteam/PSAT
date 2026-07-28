import React from "react";

import { shortAddr } from "../../format.js";
import { contractTypeForMachine } from "./helpers.js";
import { relativeTime, stateRows } from "../../../monitoring/format.js";

// Monitoring status strip — the entity header in Activity's entity mode. Shows
// monitoring STATE only (type badge, live state grid, scan freshness), never
// analysis facts (TVL / role / audit) that live on Detail / Audits.
// `eventsState` is the per-contract event read's outcome (present / pending /
// not_determined). "none recorded" is a positive claim about the contract, so it
// is only made when the read actually answered — which is why the default for an
// OMITTED prop is "pending", not "present": a call site that never says the read
// answered must not inherit the proven state.
export function StatusStrip({ machine, contract, lastEventAt, now, eventsState = "pending" }) {
  const name = machine?.name || shortAddr(machine?.address);
  const type = contract?.contract_type || contractTypeForMachine(machine);
  const rows = contract ? stateRows(contract) : [];
  const scanned = contract?.updated_at ? relativeTime(contract.updated_at, now) : null;

  return (
    <div className="ps-activity-strip">
      <div className="ps-activity-strip-top">
        <span className="ps-activity-strip-name" title={name}>{name}</span>
        <span className={`ps-activity-badge ${type}`}>{type}</span>
        {contract ? (
          <span className={`ps-activity-strip-active${contract.is_active ? "" : " off"}`}>
            {contract.is_active ? "● active" : "○ paused"}
          </span>
        ) : null}
      </div>
      <div className="ps-activity-strip-sub">
        {type} {shortAddr(machine?.address)}
        {scanned ? ` · scanned ${scanned}` : ""}
      </div>
      {contract ? (
        <div className="ps-activity-kv">
          {rows.map((r) => (
            <React.Fragment key={r.k}>
              <div className="k">{r.k}</div>
              <div className={`v${r.tone ? " " + r.tone : ""}`}>{r.v}</div>
            </React.Fragment>
          ))}
          <div className="k">Last event</div>
          <div className="v muted">
            {lastEventAt
              ? relativeTime(lastEventAt, now)
              : eventsState === "present"
                ? "none recorded"
                : "not determined"}
          </div>
        </div>
      ) : (
        <div className="ps-activity-kv">
          <div className="k">Status</div>
          <div className="v muted">not monitored</div>
        </div>
      )}
    </div>
  );
}
