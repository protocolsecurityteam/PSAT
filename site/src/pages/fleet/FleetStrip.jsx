import React from "react";

import {
  PROCESS_PILL_LABEL,
  TONE_DOT,
  countUnhealthy,
  daemonPulse,
  daemonTone,
  pillSub,
  watcherStale,
  watcherSub,
} from "./fleetHealth.js";

// Fleet system-health strip. Drives the "all background processes" view of
// the monitor page from /api/fleet: heartbeat-backed daemons plus the
// derived-liveness runtime watchers. Health states (running/idle/error/
// unknown/stale) all render; selecting a pill fills the dock with that
// process's detail (DaemonDetail.jsx).

export function FleetStrip({ fleet, selected, onSelectProcess, rates }) {
  const daemons = fleet?.daemons || [];
  const watchers = fleet?.watchers || null;
  const selKey = selected?.type === "process" ? selected.key : null;

  const pills = daemons.map((d) => {
    const rate = rates?.[d.process];
    const tone = daemonTone(d, rate);
    return {
      key: d.process,
      label: PROCESS_PILL_LABEL[d.process] || d.label,
      tone,
      sub: pillSub(d, tone, rate),
      pulse: daemonPulse(d),
    };
  });
  if (watchers) {
    const wTone = watcherStale(watchers) ? "warn" : "ok";
    pills.push({ key: "watchers", label: "Watchers", tone: wTone, sub: watcherSub(watchers), pulse: false });
  }

  const unhealthy = countUnhealthy(fleet);

  return (
    <div className="sys-strip">
      <span className="sys-label">Fleet</span>
      {pills.map((p) => {
        const pillCls = p.tone === "err" ? "err" : p.tone === "warn" ? "warn" : "";
        return (
          <button
            key={p.key}
            type="button"
            className={`sys-pill ${pillCls}${selKey === p.key ? " sel" : ""}`.replace(/\s+/g, " ").trim()}
            onClick={() => onSelectProcess(p.key)}
            aria-pressed={selKey === p.key}
          >
            <span className={`d${p.pulse ? " pulse" : ""}`} style={{ background: TONE_DOT[p.tone] }} />
            {p.label}
            <span className="sub">{p.sub}</span>
          </button>
        );
      })}
      {pills.length > 0 && (
        unhealthy > 0 ? (
          <span className="sys-summary" style={{ color: "#f87171" }}>⚠ {unhealthy} unhealthy</span>
        ) : (
          <span className="sys-summary" style={{ color: "#22c55e" }}>✓ all healthy</span>
        )
      )}
    </div>
  );
}
