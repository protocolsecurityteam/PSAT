import { Handle, Position } from "@xyflow/react";

import { formatDelay, formatUsd, shortAddr } from "../format.js";
import { ROLE_META } from "../meta.js";

export function ContractNode({ data }) {
  const m = data.machine;
  const roleColor = (ROLE_META[m.role] || ROLE_META.utility).color;
  // Passthrough timelocks would otherwise read as plain contracts. Re-labels
  // only; ownership is unchanged.
  const TIMELOCK_COLOR = "#9a8a6e";
  const accent = m.isTimelock ? TIMELOCK_COLOR : roleColor;
  const roleLabel = m.isTimelock
    ? "Timelock"
    : (ROLE_META[m.role] || ROLE_META.utility).singular;
  const delayStr = m.isTimelock ? formatDelay(m.timelockDelay) : "";
  const chip = data.selectionChip;
  // Stacks a row higher when the out/browse chip occupies the slot.
  const reachStacked = Boolean(data.browseChip || chip?.out);
  return (
    <div
      className={`ps-node${data.selected ? " ps-node-selected" : ""}${data.focused ? " ps-node-focused" : ""}${
        data.reachChip ? " ps-node-reach" : ""
      }`}
      style={{ borderLeftColor: accent }}
      onClick={data.onSelect}
    >
      {/* Transitive reach: the chip is the whole claim; the card is untouched. */}
      {data.reachChip && (
        <div
          className={`ps-node-chip ps-node-chip--reach${reachStacked ? " ps-node-chip--stacked" : ""}`}
          title="reached from the selected entity through the control graph"
        >
          {data.reachChip}
        </div>
      )}
      {/* Takes the --out slot; the selection's own out-chip yields while shown. */}
      {data.browseChip && (
        <div className="ps-node-chip ps-node-chip--browse">{data.browseChip}</div>
      )}
      {chip?.out && !data.browseChip && (
        <div className="ps-node-chip ps-node-chip--out">{chip.out}</div>
      )}
      {chip?.in && (
        <div className="ps-node-chip ps-node-chip--in">{chip.in}</div>
      )}
      <Handle type="target" position={Position.Top} id="ctrl-in" className="ps-handle" />
      <Handle type="target" position={Position.Left} id="value-in" className="ps-handle" />
      <Handle type="source" position={Position.Right} id="value-out" className="ps-handle" />
      <Handle type="source" position={Position.Bottom} id="ctrl-out" className="ps-handle" />
      <div className="ps-node-header">
        <span className="ps-node-name">{m.name || shortAddr(m.address)}</span>
      </div>
      {m.capabilities && m.capabilities.length > 0 && (
        <div className="ps-node-caps">
          {m.capabilities.map((cap) => (
            <span key={cap} className="ps-node-cap">{cap}</span>
          ))}
        </div>
      )}
      {m.standards && m.standards.length > 0 && (
        <div className="ps-node-standards">{m.standards.join(" · ")}</div>
      )}
      <div className="ps-node-addr">{shortAddr(m.address)}</div>
      {/*
        Safe-owned timelocks otherwise render as their functional role with
        nothing flagging the delay gate.
      */}
      {m.isTimelock && (
        <div className="ps-node-timelock" title={`timelock${delayStr ? ` · ${delayStr} delay` : ""}`}>
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true">
            <circle cx="6" cy="6.4" r="4.4" stroke="#9a8a6e" strokeWidth="1.1" />
            <path d="M6 4v2.6l1.7 1.1" stroke="#9a8a6e" strokeWidth="1.1" strokeLinecap="round" />
          </svg>
          <span>TIMELOCK{delayStr ? ` · ${delayStr} delay` : ""}</span>
        </div>
      )}
      {/*
        Without it a proxy looks identical to a regular contract, hiding the
        most security-relevant attribute.
      */}
      {m.is_proxy && (
        <div
          className="ps-node-proxy"
          title={`${m.proxy_type ? `${m.proxy_type} ` : ""}proxy${
            m.upgrade_count != null ? ` · ${m.upgrade_count} upgrade${m.upgrade_count === 1 ? "" : "s"}` : ""
          }`}
        >
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true">
            <rect x="3.4" y="0.9" width="7.6" height="7.6" rx="1.3" stroke="#9a8a6e" strokeWidth="1.1" />
            <rect x="0.9" y="3.4" width="7.6" height="7.6" rx="1.3" fill="#141820" stroke="#cbb99c" strokeWidth="1.1" />
          </svg>
          <span>
            {m.proxy_type === "gnosis_safe" ? "SAFE PROXY" : "PROXY"}
            {m.upgrade_count != null && m.upgrade_count > 0
              ? ` · ${m.upgrade_count} upgrade${m.upgrade_count === 1 ? "" : "s"}`
              : ""}
          </span>
        </div>
      )}
      <div className="ps-node-role" style={{ color: accent }}>{roleLabel}</div>
      {m.total_usd ? <div className="ps-node-balance">{formatUsd(m.total_usd)}</div> : null}
    </div>
  );
}
