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

  // Lane offsets are deliberately not applied: the bundled trunk only emerges
  // when every edge starts at the same point on the handle.
  const sx = sourceX;
  const sy = sourceY;
  const tx = targetX;
  const ty = targetY;

  // Per-edge obstacle lists from elkLayout, all in absolute world coords.
  const obstacles = data?.obstacles || [];

  // Inbound stub: only the part below the header is drawn, so the header
  // appears to hide the line up to the bundle.
  if (data?.stub && data?.inbound) {
    // sy is the group's outer top on the 2px border, so the header band ends
    // 2px lower. Clamped so degenerate cases don't draw upward.
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

  // The outbound stub arrives from inside the box; Position.Bottom would
  // approach from below and double back.
  const targetPos = data?.stub ? "top" : targetPosition;

  // The orthogonal router first (5-segment bus stubs make the shared trunk;
  // 3-segment fallback), then getSmoothStepPath when it gives up (mixed handle
  // axes). Edges carry no labels; chips render on the nodes.
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

// ELK guarantees consecutive points share an axis.
function polylinePath(pts) {
  let d = `M ${pts[0].x} ${pts[0].y}`;
  for (let i = 1; i < pts.length; i++) {
    d += ` L ${pts[i].x} ${pts[i].y}`;
  }
  return d;
}
