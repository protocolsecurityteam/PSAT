import { useLayoutEffect, useRef } from "react";
import { Handle, Position } from "@xyflow/react";

import { formatUsd, principalBadge, shortAddr } from "../format.js";
import { PRINCIPAL_COLORS } from "../meta.js";

// The primary row uses the group's own colour so a timelock-owned group reads
// timelock.
const CO_ACCENT = "#d99a4e";

// Clicking selects the controller (highlights what it governs, opens its card).
function ControllerRow({ controller, accent, selected, focused, onSelect }) {
  const { isPrimary, label, address, capabilities, functions = [], governs } = controller;
  // Falls back to function names so the summary is never blank.
  const capsSummary = capabilities.length
    ? capabilities.join(", ")
    : functions.length
    ? functions.slice(0, 3).join(", ") + (functions.length > 3 ? ` +${functions.length - 3}` : "")
    : "";

  return (
    <div
      className={`ps-ctrl-row ps-ctrl-row--${isPrimary ? "primary" : "co"}${selected ? " ps-ctrl-row--selected" : ""}${focused ? " ps-ctrl-row--focused" : ""}`}
      style={{ "--ctrl-accent": accent }}
    >
      <div
        className="ps-ctrl-head nodrag"
        onClick={(e) => {
          e.stopPropagation();
          onSelect();
        }}
      >
        <span className={`ps-ctrl-tag ps-ctrl-tag--${isPrimary ? "primary" : "co"}`}>{isPrimary ? "primary" : "co"}</span>
        <span className="ps-ctrl-badge" style={{ background: `${accent}22`, color: accent }}>{label}</span>
        <span className="ps-ctrl-addr">{shortAddr(address)}</span>
        <span className="ps-ctrl-caps">{capsSummary}</span>
        <span className="ps-ctrl-governs">governs {governs.length}</span>
      </div>
    </div>
  );
}

// A principal's box: the header acts as the principal, the Controllers
// accordion lists primary and co-controllers, and child cards render inside via
// parentId.
export function GroupNode({ data }) {
  const p = data.principal;
  const color = PRINCIPAL_COLORS[p.type] || "#64748b";
  const badge = principalBadge(p);
  const tvl = data.totalUsd > 0 ? formatUsd(data.totalUsd) : null;
  const chip = data.selectionChip;
  const controllers = Array.isArray(data.controllers) ? data.controllers : [];

  const selectedAddr = data.selectedControllerAddr || null;
  const focusedAddr = data.focusedControllerAddr || null;
  const onMeasureBand = data.onMeasureBand;

  // Reports the natural band height so the layout reserves exactly that.
  const innerRef = useRef(null);
  useLayoutEffect(() => {
    if (!innerRef.current || !onMeasureBand) return;
    const h = innerRef.current.offsetHeight;
    if (h > 0) onMeasureBand(h);
  }, [controllers, onMeasureBand]);

  // Transparent body: any tint sits above the edges layer and dims lines
  // crossing the group.
  return (
    <div
      className={`ps-group-node ps-group-${p.type}${data.focused ? " ps-group-focused" : ""}${data.selected ? " ps-group-selected" : ""}${
        data.reachChip ? " ps-group-reach" : ""
      }`}
      style={{
        "--principal-color": color,
        "--principal-bg": "transparent",
        "--principal-header-bg-top": `${color}cc`,
        "--principal-header-bg-bot": `${color}77`,
      }}
    >
      {data.reachChip && (
        <div
          className={`ps-node-chip ps-node-chip--reach${chip?.out ? " ps-node-chip--stacked" : ""}`}
          title="reached from the selected entity through the control graph"
        >
          {data.reachChip}
        </div>
      )}
      {chip?.out && (
        <div className="ps-node-chip ps-node-chip--out">{chip.out}</div>
      )}
      {chip?.in && (
        <div className="ps-node-chip ps-node-chip--in">{chip.in}</div>
      )}
      {/*
        ctrl-in/ctrl-out carry cross-group bundles; stub-bottom and stub-top
        are where outbound/inbound contract stubs meet them.
      */}
      <Handle type="target" position={Position.Top} id="ctrl-in" className="ps-handle" />
      <Handle type="source" position={Position.Bottom} id="ctrl-out" className="ps-handle" />
      <Handle type="target" position={Position.Bottom} id="stub-bottom" className="ps-handle" />
      <Handle type="source" position={Position.Top} id="stub-top" className="ps-handle" />

      {/* Pinned to the reserved height so cards start flush below it. */}
      <div className="ps-group-head" style={data.headerHeight ? { height: data.headerHeight } : undefined}>
        <div className="ps-group-head-inner" ref={innerRef}>
          <div
            className="ps-group-header"
            onClick={(e) => {
              e.stopPropagation();
              if (data.onSelect) data.onSelect();
            }}
          >
            <div className="ps-group-header-row">
              <span className="ps-group-badge">{badge}</span>
              <span className="ps-group-addr">{shortAddr(p.address)}</span>
              <span className="ps-group-count">
                {data.childCount} contract{data.childCount === 1 ? "" : "s"}
                {tvl ? ` · ${tvl}` : ""}
              </span>
            </div>
          </div>

          {controllers.length > 0 && (
            <div className="ps-group-controllers">
              <div className="ps-group-controllers-label">Controllers</div>
              {controllers.map((c, i) => (
                <ControllerRow
                  key={`${c.address}-${i}`}
                  controller={c}
                  accent={c.isPrimary ? color : CO_ACCENT}
                  selected={selectedAddr != null && c.address?.toLowerCase() === selectedAddr}
                  focused={focusedAddr != null && c.address?.toLowerCase() === focusedAddr}
                  onSelect={() => data.onSelectController && data.onSelectController(c.address)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
