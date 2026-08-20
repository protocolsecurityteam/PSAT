// Edge obstacle attachment for ChanneledStepEdge routing. Split from
// elkLayout.js.

import { CHILD_W, CHILD_H } from "./nodeSizing.js";

// Top-level node bounding boxes. ChanneledStepEdge uses these to pick
// a centerY (or centerX) that doesn't drive the edge's middle segment
// through the interior of a group container.
function collectObstacles(nodes) {
  const out = [];
  for (const n of nodes) {
    if (n.parentId) continue;
    if (n.type !== "group" && n.type !== "contract") continue;
    // Groups carry ELK-computed dims on style; contracts use the same
    // CHILD_W/CHILD_H we hand ELK for top-level layout. The rendered
    // .ps-node may be a touch smaller, but a slightly oversized
    // obstacle is fine — we'd rather route around a card than clip it.
    const w = n.style?.width ?? CHILD_W;
    const h = n.style?.height ?? CHILD_H;
    out.push({
      id: n.id,
      x: n.position?.x || 0,
      y: n.position?.y || 0,
      w,
      h,
    });
  }
  return out;
}

// Attach the right obstacle list per edge:
//   - cross-group edges get top-level groups + standalone contracts so
//     they route around other group containers
//   - intra-group edges get the OTHER children of their parent group
//     (in absolute world coords) so they don't slice through siblings
// All edges sharing the same obstacle list reference the same array so
// React Flow's prop diff doesn't churn.
export function attachObstacles(edges, nodes) {
  const topLevel = collectObstacles(nodes);
  const nodeById = new Map();
  for (const n of nodes) nodeById.set(n.id, n);

  // Children grouped by parent, with positions translated to absolute
  // world coords. ReactFlow gives edge components absolute sourceX /
  // targetX, so obstacles need to match that frame.
  const siblingsByParent = new Map();
  for (const n of nodes) {
    if (!n.parentId) continue;
    const parent = nodeById.get(n.parentId);
    if (!parent) continue;
    const absX = (parent.position?.x || 0) + (n.position?.x || 0);
    const absY = (parent.position?.y || 0) + (n.position?.y || 0);
    const w = n.style?.width ?? CHILD_W;
    const h = n.style?.height ?? CHILD_H;
    if (!siblingsByParent.has(n.parentId)) siblingsByParent.set(n.parentId, []);
    siblingsByParent.get(n.parentId).push({ id: n.id, x: absX, y: absY, w, h });
  }

  return edges.map((e) => {
    let obstacles = topLevel;
    // Stubs live inside their source group (contract → that group's bottom
    // edge), so they route around the same siblings the intra-group edges do.
    if (e.data?.intraGroup || e.data?.stub) {
      const src = nodeById.get(e.source);
      const parentId = src?.parentId;
      const siblings = parentId ? siblingsByParent.get(parentId) : null;
      if (siblings) obstacles = siblings;
    }
    return {
      ...e,
      data: { ...(e.data || {}), obstacles },
    };
  });
}
