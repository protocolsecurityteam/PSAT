import React from "react";

import { shortAddr } from "../../format.js";
import { contractTypeForMachine } from "../monitoring/helpers.js";
import { relativeTime, stateRows } from "../../../monitoring/format.js";

// Monitoring status strip — the entity header in Activity's entity mode. Shows
// monitoring STATE only (type badge, live state grid, scan freshness), never
// analysis facts (TVL / role / audit) that live on Detail / Audits.
export function StatusStrip({ machine, contract, lastEventAt, now }) {
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
          <div className="v muted">{lastEventAt ? relativeTime(lastEventAt, now) : "none recorded"}</div>
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
