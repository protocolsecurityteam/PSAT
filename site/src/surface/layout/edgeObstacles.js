
import { CHILD_W, CHILD_H } from "./nodeSizing.js";

function collectObstacles(nodes) {
  const out = [];
  for (const n of nodes) {
    if (n.parentId) continue;
    if (n.type !== "group" && n.type !== "contract") continue;
    // Oversized obstacles are fine: better to route around a card than clip it.
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

// Cross-group edges avoid top-level groups and standalone contracts;
// intra-group edges avoid their siblings. Shared arrays keep React Flow's prop
// diff stable.
export function attachObstacles(edges, nodes) {
  const topLevel = collectObstacles(nodes);
  const nodeById = new Map();
  for (const n of nodes) nodeById.set(n.id, n);

  // Absolute coords: edge components get absolute sourceX/targetX.
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
