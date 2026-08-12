import { Handle, Position } from "@xyflow/react";

import { formatDelay, formatUsd, shortAddr } from "../format.js";
import { ROLE_META } from "../meta.js";

export function ContractNode({ data }) {
  const m = data.machine;
  const roleColor = (ROLE_META[m.role] || ROLE_META.utility).color;
  // A passthrough timelock contract (control-graph type=timelock) defaults to
  // its functional role label; surface the timelock identity so it isn't read
  // as a plain contract and lines up with the Timelocks filter. Owner
  // attribution is unchanged — this re-labels, it doesn't re-attribute.
  const TIMELOCK_COLOR = "#9a8a6e";
  const accent = m.isTimelock ? TIMELOCK_COLOR : roleColor;
  const roleLabel = m.isTimelock
    ? "Timelock"
    : (ROLE_META[m.role] || ROLE_META.utility).singular;
  const delayStr = m.isTimelock ? formatDelay(m.timelockDelay) : "";
  const chip = data.selectionChip;
  // The reach chip shares the above-the-card slot with the out/browse chip, so
  // it stacks a row higher when one of those is present rather than landing on
  // top of it.
  const reachStacked = Boolean(data.browseChip || chip?.out);
  return (
    <div
      className={`ps-node${data.selected ? " ps-node-selected" : ""}${data.focused ? " ps-node-focused" : ""}${
        data.reachChip ? " ps-node-reach" : data.reachNdChip ? " ps-node-reach-nd" : ""
      }`}
      style={{ borderLeftColor: accent }}
      onClick={data.onSelect}
    >
      {/* Transitive reach (purple, above the card): the selection reaches this
          contract over the control graph in N hops. The card itself is left
          untouched — the chip is the whole claim. */}
      {data.reachChip && (
        <div
          className={`ps-node-chip ps-node-chip--reach${reachStacked ? " ps-node-chip--stacked" : ""}`}
          title="reached from the selected entity through the control graph"
        >
          {data.reachChip}
        </div>
      )}
      {/* not_determined frontier (dashed violet): the server walk was refused
          a hop short of this contract, so its reach is unconfirmed — a hedged
          claim, never the walked one. The title carries the refusal reason
          token. A reached node never wears this (reached wins upstream). */}
      {!data.reachChip && data.reachNdChip && (
        <div
          className={`ps-node-chip ps-node-chip--reach-nd${reachStacked ? " ps-node-chip--stacked" : ""}`}
          title={data.reachNdChip}
        >
          reach unconfirmed
        </div>
      )}
      {/* Browse-fallback note (gold, above the card): who the browsed
          off-graph principal is and what it can call here. Takes the --out
          slot, so the selection's own out-chip yields while it's shown. */}
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
      {/* Timelock marker. A timelock contract is owned by a Safe (passthrough),
          so by default it renders as whatever functional role the classifier
          gave it ("Value Handler") with nothing flagging the delay-gated
          control surface it actually is. */}
      {m.isTimelock && (
        <div className="ps-node-timelock" title={`timelock${delayStr ? ` · ${delayStr} delay` : ""}`}>
          <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true">
            <circle cx="6" cy="6.4" r="4.4" stroke="#9a8a6e" strokeWidth="1.1" />
            <path d="M6 4v2.6l1.7 1.1" stroke="#9a8a6e" strokeWidth="1.1" strokeLinecap="round" />
          </svg>
          <span>TIMELOCK{delayStr ? ` · ${delayStr} delay` : ""}</span>
        </div>
      )}
      {/* Proxy marker. Without it the card is identical to a regular
          contract, hiding that most protocol contracts are upgradeable —
          the single most security-relevant attribute on the canvas. The
          impl name + functions already render as the card's identity;
          this just declares the proxy wrapper + how often it's changed. */}
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
