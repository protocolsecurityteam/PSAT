import { Handle, Position } from "@xyflow/react";

import { shortAddr } from "../format.js";
import { PRINCIPAL_COLORS } from "../meta.js";

export function PrincipalNode({ data }) {
  const p = data.principal;
  const color = PRINCIPAL_COLORS[p.type] || "#64748b";
  const owners = Array.isArray(p.details?.owners) ? p.details.owners : [];
  const threshold = p.details?.threshold;
  const delay = p.details?.delay;

  return (
    <div
      className={`ps-principal-node${data.isGuardian ? " ps-principal-node--guardian" : ""}${data.focused ? " ps-node-focused" : ""}`}
      style={{ "--principal-color": color, cursor: data.onSelect ? "pointer" : "default" }}
      onClick={data.onSelect}
    >
      <Handle type="target" position={Position.Top} id="ctrl-in" className="ps-handle" />
      <Handle type="source" position={Position.Bottom} id="ctrl-out" className="ps-handle" />
      {data.isGuardian && <div className="ps-principal-cocaption">co-controller</div>}
      <div className="ps-principal-badge" style={{ background: color + "22", color }}>
        {p.type === "safe" && threshold ? `${threshold}/${owners.length} SAFE` : p.type.toUpperCase()}
      </div>
      <div className="ps-principal-addr">{shortAddr(p.address)}</div>
      {p.type === "timelock" && delay && (
        <div className="ps-principal-detail">
          {Number(delay) >= 86400 ? `${Math.round(Number(delay) / 86400)}d` : Number(delay) >= 3600 ? `${Math.round(Number(delay) / 3600)}h` : `${Math.round(Number(delay) / 60)}m`} delay
        </div>
      )}
      {p.type === "safe" && owners.length > 0 && (
        <div className="ps-principal-owners">
          {owners.map((o) => (
            <div key={o} className="ps-principal-owner">
              <span className="ps-owner-dot" />
              {shortAddr(o)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
