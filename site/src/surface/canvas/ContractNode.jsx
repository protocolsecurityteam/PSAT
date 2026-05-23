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
      {m.chain ? <div className="ps-node-standards">{m.chain}</div> : null}
      <div className="ps-node-role" style={{ color: roleColor }}>{(ROLE_META[m.role] || ROLE_META.utility).label.replace(/s$/, "")}</div>
      {m.total_usd ? <div className="ps-node-balance">{formatUsd(m.total_usd)}</div> : null}
    </div>
  );
}
