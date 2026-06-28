import { Handle, Position } from "@xyflow/react";

import { formatUsd, shortAddr } from "../format.js";
import { ROLE_META } from "../meta.js";

export function ContractNode({ data }) {
  const m = data.machine;
  const roleColor = (ROLE_META[m.role] || ROLE_META.utility).color;
  const chip = data.selectionChip;
  return (
    <div
      className={`ps-node${data.selected ? " ps-node-selected" : ""}${data.focused ? " ps-node-focused" : ""}`}
      style={{ borderLeftColor: roleColor }}
      onClick={data.onSelect}
    >
      {chip?.out && (
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
      {data.otherCallers && data.otherCallers.length > 0 && (
        <button
          type="button"
          className="ps-node-callers"
          title={`${data.otherCallers.length} additional authorized caller(s) — click to inspect: ${data.otherCallers
            .map((c) => `${c.type} ${c.address}`)
            .join(", ")}`}
          onClick={(e) => {
            e.stopPropagation();
            data.onSelect?.();
          }}
        >
          +{data.otherCallers.length} callers
        </button>
      )}
      <div className="ps-node-addr">{shortAddr(m.address)}</div>
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
      <div className="ps-node-role" style={{ color: roleColor }}>{(ROLE_META[m.role] || ROLE_META.utility).label.replace(/s$/, "")}</div>
      {m.total_usd ? <div className="ps-node-balance">{formatUsd(m.total_usd)}</div> : null}
    </div>
  );
}
