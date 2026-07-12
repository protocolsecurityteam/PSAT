import { useLayoutEffect, useRef } from "react";
import { Handle, Position } from "@xyflow/react";

import { formatUsd, principalBadge, shortAddr } from "../format.js";
import { PRINCIPAL_COLORS } from "../meta.js";

// Co-controller accent (amber). The primary row uses the group's own
// principal color so a timelock-owned group reads timelock, not teal.
const CO_ACCENT = "#d99a4e";

// Light category tint for a function chip — upgrade/ownership, pause, and
// fund movements get a hint of color so the dangerous powers pop out of a
// long list. Everything else stays neutral. Polish, not load-bearing.
function fnChipClass(fn) {
  if (/upgrade|transferownership|renounceownership|setowner|changeadmin/i.test(fn)) return "ps-ctrl-fnchip--upgrade";
  if (/pause/i.test(fn)) return "ps-ctrl-fnchip--pause";
  if (/recover|withdraw|sweep|sendto|fund|claim|seize/i.test(fn)) return "ps-ctrl-fnchip--fund";
  return "";
}

// One accordion row: a controller's badge + full capability summary (every
// tag, comma-separated like the rest of the app — never truncated), expanding
// to the contracts it governs and the exact functions it can call on each.
// Clicking it both expands the row and selects the controller, which
// highlights the contracts it governs on the canvas (mirroring a click on the
// group header). The detail renders in-flow — it pushes the rows below it down
// and grows the reserved header band so the group extends rather than
// overlapping its cards/neighbours (GroupNode measures the band; the layout
// re-packs to fit).
function ControllerRow({ controller, accent, open, selected, focused, onToggle, onSelect }) {
  const { isPrimary, label, address, capabilities, functions = [], governs } = controller;
  // Capability tags (all of them, comma-separated, never truncated). When a
  // controller's functions map to no high-level tag, fall back to function
  // names like the sidebar's "Can Call" so the summary is never blank.
  const capsSummary = capabilities.length
    ? capabilities.join(", ")
    : functions.length
    ? functions.slice(0, 3).join(", ") + (functions.length > 3 ? ` +${functions.length - 3}` : "")
    : "";

  return (
    <div
      className={`ps-ctrl-row ps-ctrl-row--${isPrimary ? "primary" : "co"}${open ? " ps-ctrl-row--open" : ""}${selected ? " ps-ctrl-row--selected" : ""}${focused ? " ps-ctrl-row--focused" : ""}`}
      style={{ "--ctrl-accent": accent }}
    >
      <div
        className="ps-ctrl-head nodrag"
        onClick={(e) => {
          e.stopPropagation();
          onSelect();
          onToggle();
        }}
      >
        <span className="ps-ctrl-caret">{open ? "▾" : "▸"}</span>
        <span className={`ps-ctrl-tag ps-ctrl-tag--${isPrimary ? "primary" : "co"}`}>{isPrimary ? "primary" : "co"}</span>
        <span className="ps-ctrl-badge" style={{ background: `${accent}22`, color: accent }}>{label}</span>
        <span className="ps-ctrl-addr">{shortAddr(address)}</span>
        <span className="ps-ctrl-caps">{capsSummary}</span>
        <span className="ps-ctrl-governs">governs {governs.length}</span>
      </div>
      {open && (
        <div className="ps-ctrl-detail nodrag" onClick={(e) => e.stopPropagation()}>
          {governs.map((g) => (
            <div className="ps-ctrl-detail-line" key={g.address}>
              <span className="ps-ctrl-cname">{g.name}</span>
              <span className="ps-ctrl-fns">
                {/* Every function, never truncated — the detail is the only
                    place to read them, and the band grows to fit. */}
                {g.functions.map((f) => (
                  <span className={`ps-ctrl-fnchip ${fnChipClass(f)}`} key={f}>{f}</span>
                ))}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Container node that wraps every contract a single principal owns. The
// colored header acts as the principal: clicking it opens the same detail
// panel a standalone PrincipalNode would. Below it, a Controllers accordion
// lists every principal with authority inside the box — the primary owner
// (teal/type-colored, tagged PRIMARY) and every co-controller (amber, tagged
// CO) — each expanding to the exact functions it can call per contract, and
// each selecting/highlighting its governed contracts on click. The child
// contract cards render inside the container via React Flow's parentId
// mechanism, starting below the reserved header band; opening a row grows that
// band (the layout re-packs) so nothing is overlapped.
export function GroupNode({ data }) {
  const p = data.principal;
  const color = PRINCIPAL_COLORS[p.type] || "#64748b";
  const badge = principalBadge(p);
  const tvl = data.totalUsd > 0 ? formatUsd(data.totalUsd) : null;
  const chip = data.selectionChip;
  const controllers = Array.isArray(data.controllers) ? data.controllers : [];

  // Expansion is controlled by SurfaceCanvas (data.expandedIdx) so the layout
  // can grow this group's header band to fit the open row. Exclusive: one row
  // open at a time. Default all collapsed.
  const openIdx = data.expandedIdx ?? null;
  const selectedAddr = data.selectedControllerAddr || null;
  const focusedAddr = data.focusedControllerAddr || null;
  const onMeasureBand = data.onMeasureBand;

  // Measure the real rendered band height (colored bar + accordion, including
  // any open row's in-flow detail and any wrapped capability summaries) and
  // report it so the layout reserves exactly that and re-packs the canvas. The
  // inner wrapper is auto-height; the outer band is pinned + clipped, so this
  // reads the natural content height regardless of the current reservation.
  const innerRef = useRef(null);
  useLayoutEffect(() => {
    if (!innerRef.current || !onMeasureBand) return;
    const h = innerRef.current.offsetHeight;
    if (h > 0) onMeasureBand(openIdx, h);
  }, [openIdx, controllers, onMeasureBand]);

  // Body is transparent on purpose — even an 8% colored tint sits above
  // the React Flow edges layer and dims any line crossing the group.
  // The colored header bar + 2px colored border carry all the type
  // identity; the body just needs to let edges read through. `cc` ≈ 80%
  // top of header, `77` ≈ 47% bottom.
  return (
    <div
      className={`ps-group-node ps-group-${p.type}${data.focused ? " ps-group-focused" : ""}${data.selected ? " ps-group-selected" : ""}`}
      style={{
        "--principal-color": color,
        "--principal-bg": "transparent",
        "--principal-header-bg-top": `${color}cc`,
        "--principal-header-bg-bot": `${color}77`,
      }}
    >
      {chip?.out && (
        <div className="ps-node-chip ps-node-chip--out">{chip.out}</div>
      )}
      {chip?.in && (
        <div className="ps-node-chip ps-node-chip--in">{chip.in}</div>
      )}
      {/* Edges terminate on the group itself: ctrl-in (top) / ctrl-out
          (bottom) carry the aggregated cross-group bundles. stub-bottom (a
          target at the same bottom-centre spot ctrl-out leaves from) is where an
          outbound contract stub lands. stub-top (top-centre, same spot the
          inbound bundle arrives) is where an inbound stub leaves to drop down to
          the contract it feeds. */}
      <Handle type="target" position={Position.Top} id="ctrl-in" className="ps-handle" />
      <Handle type="source" position={Position.Bottom} id="ctrl-out" className="ps-handle" />
      <Handle type="target" position={Position.Bottom} id="stub-bottom" className="ps-handle" />
      <Handle type="source" position={Position.Top} id="stub-top" className="ps-handle" />

      {/* Header band: pinned to the exact height the layout reserved
          (data.headerHeight, derived from the measured inner content) so the
          contract cards always start flush below it. */}
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
              <div className="ps-group-controllers-label">Controllers — click to see functions</div>
              {controllers.map((c, i) => (
                <ControllerRow
                  key={`${c.address}-${i}`}
                  controller={c}
                  accent={c.isPrimary ? color : CO_ACCENT}
                  open={openIdx === i}
                  selected={selectedAddr != null && c.address?.toLowerCase() === selectedAddr}
                  focused={focusedAddr != null && c.address?.toLowerCase() === focusedAddr}
                  onToggle={() => data.onToggleController && data.onToggleController(i)}
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
