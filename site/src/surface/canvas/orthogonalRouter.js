// Multi-bend orthogonal router for cross-group edges. Returns the full polyline
// (3 or 5 waypoints) so every segment clears the obstacles. Handles same-axis
// cases only; mixed-axis falls back to the caller's smoothstep.

// Clears the coloured border but keeps the second bend in the source's lane.
const STUB = 24;

const OBSTACLE_PADDING = 20;

export function routeOrthogonal({
  sx, sy, tx, ty,
  sourcePos, targetPos,
  obstacles,
  sourceId, targetId,
}) {
  // Source/target stay obstacles, shrunk at the handle, because a GroupNode's
  // top handle sits below its visible top; filtering the group out let routes
  // re-enter it (EtherFi Timelock → 3/6 SAFE).
  const obs = (obstacles || []).map((o) => {
    if (o.id === sourceId) return shrinkAtHandle(o, sourcePos, sx, sy);
    if (o.id === targetId) return shrinkAtHandle(o, targetPos, tx, ty);
    return o;
  });

  const sAxisV = sourcePos === "top" || sourcePos === "bottom";
  const tAxisV = targetPos === "top" || targetPos === "bottom";

  // Prefer 5 segments even when 3 would clear: edges sharing a handle share the
  // first/last STUB-px segment, which reads as one trunk.
  if (sAxisV && tAxisV) {
    return (
      tryFiveSegmentV(sx, sy, tx, ty, sourcePos, targetPos, obs)
      || tryThreeSegmentV(sx, sy, tx, ty, sourcePos, targetPos, obs)
    );
  }
  if (!sAxisV && !tAxisV) {
    return (
      tryFiveSegmentH(sx, sy, tx, ty, sourcePos, targetPos, obs)
      || tryThreeSegmentH(sx, sy, tx, ty, sourcePos, targetPos, obs)
    );
  }
  // Mixed-axis edges are rare; leave them to smoothstep.
  return null;
}

// No-op unless the handle is inside the obstacle (only GroupNode's header
// offset does that).
function shrinkAtHandle(o, pos, hx, hy) {
  if (pos === "top" && hy > o.y) {
    return { ...o, y: hy, h: Math.max(0, o.h - (hy - o.y)) };
  }
  if (pos === "bottom" && hy < o.y + o.h) {
    return { ...o, h: Math.max(0, hy - o.y) };
  }
  if (pos === "left" && hx > o.x) {
    return { ...o, x: hx, w: Math.max(0, o.w - (hx - o.x)) };
  }
  if (pos === "right" && hx < o.x + o.w) {
    return { ...o, w: Math.max(0, hx - o.x) };
  }
  return o;
}

function segmentClear(a, b, obstacles) {
  const xLo = Math.min(a.x, b.x);
  const xHi = Math.max(a.x, b.x);
  const yLo = Math.min(a.y, b.y);
  const yHi = Math.max(a.y, b.y);
  for (const o of obstacles) {
    if (xHi <= o.x || xLo >= o.x + o.w) continue;
    if (yHi <= o.y || yLo >= o.y + o.h) continue;
    return false;
  }
  return true;
}

function polylineClear(pts, obstacles) {
  for (let i = 1; i < pts.length; i++) {
    if (!segmentClear(pts[i - 1], pts[i], obstacles)) return false;
  }
  return true;
}

// V-H-V: (sx,sy) → (sx,cy) → (tx,cy) → (tx,ty)
// cy is constrained to the exit side of both handles so a far midpoint can't
// back into the target from below. Null means escalate to 5 segments.
function tryThreeSegmentV(sx, sy, tx, ty, sourcePos, targetPos, obstacles) {
  const sDir = sourcePos === "bottom" ? 1 : -1;
  const tDir = targetPos === "bottom" ? 1 : -1;
  const natural = (sy + ty) / 2;
  const candidates = perpendicularCandidates(natural, obstacles, "y");
  for (const cy of candidates) {
    if ((cy - sy) * sDir <= 0) continue;
    if ((cy - ty) * tDir <= 0) continue;
    const pts = [
      { x: sx, y: sy },
      { x: sx, y: cy },
      { x: tx, y: cy },
      { x: tx, y: ty },
    ];
    if (polylineClear(pts, obstacles)) return pts;
  }
  return null;
}

// H-V-H: (sx,sy) → (cx,sy) → (cx,ty) → (tx,ty)
function tryThreeSegmentH(sx, sy, tx, ty, sourcePos, targetPos, obstacles) {
  const sDir = sourcePos === "right" ? 1 : -1;
  const tDir = targetPos === "right" ? 1 : -1;
  const natural = (sx + tx) / 2;
  const candidates = perpendicularCandidates(natural, obstacles, "x");
  for (const cx of candidates) {
    if ((cx - sx) * sDir <= 0) continue;
    if ((cx - tx) * tDir <= 0) continue;
    const pts = [
      { x: sx, y: sy },
      { x: cx, y: sy },
      { x: cx, y: ty },
      { x: tx, y: ty },
    ];
    if (polylineClear(pts, obstacles)) return pts;
  }
  return null;
}

// V-H-V-H-V: (sx,sy) → (sx,y1) → (xm,y1) → (xm,y2) → (tx,y2) → (tx,ty)
function tryFiveSegmentV(sx, sy, tx, ty, sourcePos, targetPos, obstacles) {
  const sDir = sourcePos === "bottom" ? 1 : -1;
  const tDir = targetPos === "bottom" ? 1 : -1;

  const y1Candidates = directionalCandidates(sy, sDir, obstacles, "y");
  const y2Candidates = directionalCandidates(ty, tDir, obstacles, "y");
  const xmCandidates = perpendicularCandidates((sx + tx) / 2, obstacles, "x");

  // Bounded to keep per-edge cost predictable.
  const Y_CAP = Math.min(5, y1Candidates.length);
  for (let i = 0; i < Y_CAP; i++) {
    for (let j = 0; j < Y_CAP; j++) {
      const y1 = y1Candidates[i];
      const y2 = y2Candidates[j];
      for (const xm of xmCandidates) {
        const pts = [
          { x: sx, y: sy },
          { x: sx, y: y1 },
          { x: xm, y: y1 },
          { x: xm, y: y2 },
          { x: tx, y: y2 },
          { x: tx, y: ty },
        ];
        if (polylineClear(pts, obstacles)) return pts;
      }
    }
  }
  return null;
}

// H-V-H-V-H: mirror of tryFiveSegmentV.
function tryFiveSegmentH(sx, sy, tx, ty, sourcePos, targetPos, obstacles) {
  const sDir = sourcePos === "right" ? 1 : -1;
  const tDir = targetPos === "right" ? 1 : -1;

  const x1Candidates = directionalCandidates(sx, sDir, obstacles, "x");
  const x2Candidates = directionalCandidates(tx, tDir, obstacles, "x");
  const ymCandidates = perpendicularCandidates((sy + ty) / 2, obstacles, "y");

  const X_CAP = Math.min(5, x1Candidates.length);
  for (let i = 0; i < X_CAP; i++) {
    for (let j = 0; j < X_CAP; j++) {
      const x1 = x1Candidates[i];
      const x2 = x2Candidates[j];
      for (const ym of ymCandidates) {
        const pts = [
          { x: sx, y: sy },
          { x: x1, y: sy },
          { x: x1, y: ym },
          { x: x2, y: ym },
          { x: x2, y: ty },
          { x: tx, y: ty },
        ];
        if (polylineClear(pts, obstacles)) return pts;
      }
    }
  }
  return null;
}

// Natural midpoint plus a slot either side of each obstacle, nearest first.
function perpendicularCandidates(natural, obstacles, axis) {
  const out = [natural];
  for (const o of obstacles) {
    const lo = axis === "x" ? o.x : o.y;
    const hi = lo + (axis === "x" ? o.w : o.h);
    out.push(lo - OBSTACLE_PADDING);
    out.push(hi + OBSTACLE_PADDING);
  }
  out.sort((a, b) => Math.abs(a - natural) - Math.abs(b - natural));
  return out;
}

// Only values past `base` in the handle direction, so a stub never retraces
// through the node.
function directionalCandidates(base, dir, obstacles, axis) {
  const primary = base + dir * STUB;
  const out = [primary];
  for (const o of obstacles) {
    const lo = axis === "x" ? o.x : o.y;
    const hi = lo + (axis === "x" ? o.w : o.h);
    out.push(lo - OBSTACLE_PADDING);
    out.push(hi + OBSTACLE_PADDING);
  }
  return out
    .filter((v) => (v - base) * dir > 0)
    .sort((a, b) => Math.abs(a - primary) - Math.abs(b - primary));
}
