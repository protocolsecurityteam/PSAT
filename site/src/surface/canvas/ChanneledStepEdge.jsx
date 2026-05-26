import { BaseEdge, getSmoothStepPath } from "@xyflow/react";

import { routeOrthogonal } from "./orthogonalRouter.js";

export function ChanneledStepEdge(props) {
  const {
    id,
    source,
    target,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    data,
    style,
    markerEnd,
    markerStart,
    interactionWidth,
  } = props;

  // Lane offsets are intentionally not applied. The bundling visual
  // (every edge sharing a handle traveling through the same `STUB`-px
  // perpendicular trunk before forking) only emerges when all edges
  // start at the exact same point on the handle — lane-fanning would
  // spread them across the side and break the shared-stub overlap.
  // The lane fields on `data` are still populated by assignEdgeLanes
  // for any future tooling that wants them.
  const sx = sourceX;
  const sy = sourceY;
  const tx = targetX;
  const ty = targetY;

  // elkLayout swaps the obstacle list per edge: top-level groups for
  // cross-group bundles, siblings of the parent group for intra-group
  // ones. Both lists arrive in the same absolute world-coord frame as
  // sourceX/Y / targetX/Y, so the same routing pass handles them.
  const obstacles = data?.obstacles || [];

  // Inbound stub: a contract called into from another aggregation. The bundle
  // arrives at the box top "as normal"; here we draw ONLY the part below the
  // header — a straight drop from the header's bottom edge (directly above the
  // contract) down to its top handle. Everything that would sit over the header
  // is omitted, so the header reads as hiding the line (it appears to continue
  // invisibly up to the bundle). data.headerHeight marks where the header ends.
  if (data?.stub && data?.inbound) {
    // sy is the group's outer-top (the handle sits on the 2px border); the
    // header band starts inside that border, so its bottom is +2 below the
    // reserved headerHeight. Start the drop there so it never paints over the
    // header. Clamp to the contract top so degenerate cases don't draw upward.
    const GROUP_BORDER = 2;
    const headerBottom = sy + GROUP_BORDER + (data.headerHeight || 0);
    const startY = Math.min(headerBottom, ty);
    return (
      <BaseEdge
        id={id}
        path={`M ${tx} ${startY} L ${tx} ${ty}`}
        style={style}
        markerEnd={markerEnd}
        markerStart={markerStart}
        interactionWidth={interactionWidth}
      />
    );
  }

  // The outbound stub lands on the group's bottom-edge handle (the same spot
  // the shared bundle leaves from), but it arrives from INSIDE the box —
  // descending from the contract above. Position.Bottom would make the router
  // approach from below, overshooting past the handle and doubling back. Treat
  // the target as top-facing so it drops straight in and meets the bundle's
  // start cleanly, reading as one continuous line.
  const targetPos = data?.stub ? "top" : targetPosition;

  // Two render paths, in order of preference:
  //   1. Multi-bend orthogonal router (`routeOrthogonal`). Prefers the
  //      5-segment bus-stub shape so every edge from the same handle
  //      shares its first / last perpendicular segment — that overlap
  //      is what produces the bundled "trunk" visual. Falls back to a
  //      3-segment route when 5 can't find a clear column.
  //   2. getSmoothStepPath. Last-resort fallback when the router gives
  //      up (e.g. mixed handle axes that routeOrthogonal doesn't model).
  //
  // Edges never carry their own label any more — selection chips
  // render on the related contract nodes themselves (data.selectionChip
  // in ContractNode / GroupNode), so the geometry only has to draw the
  // path. Cable thickness at the shared trunk communicates weight.
  const polyline = routeOrthogonal({
    sx, sy, tx, ty,
    sourcePos: sourcePosition,
    targetPos,
    obstacles,
    sourceId: source,
    targetId: target,
  });
  const path = polyline
    ? polylinePath(polyline)
    : getSmoothStepPath({
        sourceX: sx,
        sourceY: sy,
        targetX: tx,
        targetY: ty,
        sourcePosition,
        targetPosition: targetPos,
        borderRadius: 0,
      })[0];

  return (
    <BaseEdge
      id={id}
      path={path}
      style={style}
      markerEnd={markerEnd}
      markerStart={markerStart}
      interactionWidth={interactionWidth}
    />
  );
}

// SVG path with sharp 90° corners through the given orthogonal
// waypoints. ELK guarantees consecutive points share an axis, so a
// straight L between each pair is correct.
function polylinePath(pts) {
  let d = `M ${pts[0].x} ${pts[0].y}`;
  for (let i = 1; i < pts.length; i++) {
    d += ` L ${pts[i].x} ${pts[i].y}`;
  }
  return d;
}
