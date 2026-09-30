import { useEffect, useRef } from "react";
import { useReactFlow, useStoreApi } from "@xyflow/react";

// Never zooms in past this, but zooms out as far as needed so a large group
// fits instead of losing its header off-screen.
const MAX_FOCUS_ZOOM = 1.2;
const FIT_MARGIN = 24;

export function FocusOnNode({ address, focusKey, principals }) {
  const { fitBounds, getInternalNode, getNodes } = useReactFlow();
  const store = useStoreApi();
  const lastKey = useRef(null);
  useEffect(() => {
    if (!address || focusKey === lastKey.current) return;
    lastKey.current = focusKey;

    // Grouped nodes have parent-relative positions; the absolute one is on the
    // internal node.
    const rectFor = (addr) => {
      if (!addr) return null;
      // Legacy checksummed ids: find the node case-insensitively, then get the
      // internal node by its own id.
      const found = getNodes().find((n) => n.id === addr)
        || getNodes().find((n) => n.id?.toLowerCase() === addr.toLowerCase());
      const internal = getInternalNode(addr)
        || getInternalNode(addr.toLowerCase())
        || (found ? getInternalNode(found.id) : null);
      const node = internal || found;
      if (!node) return null;
      return {
        x: internal?.internals?.positionAbsolute?.x ?? node.positionAbsolute?.x ?? node.position?.x ?? 0,
        y: internal?.internals?.positionAbsolute?.y ?? node.positionAbsolute?.y ?? node.position?.y ?? 0,
        w: node.measured?.width || node.width || 220,
        h: node.measured?.height || node.height || 120,
      };
    };

    // Let ReactFlow finish positioning.
    const timer = setTimeout(() => {
      let rect = rectFor(address);
      if (!rect) {
        // Node-less principal: fit the group boxes whose accordions list it;
        // with no row anywhere, fit its touched contract cards.
        const lc = address.toLowerCase();
        const p = (principals || []).find((x) => x.address?.toLowerCase() === lc);
        const hasRow = getNodes().some(
          (n) =>
            n.type === "group" &&
            (n.data?.controllers || []).some((c) => c.address?.toLowerCase() === lc),
        );
        const targets = new Map();
        for (const a of [...(p?.controls || []), ...(p?.co_controls || [])]) {
          const addrLc = String(a).toLowerCase();
          const node = getNodes().find((n) => n.id?.toLowerCase() === addrLc);
          if (!node) continue;
          const targetId = hasRow ? node.parentId || node.id : node.id;
          if (!targets.has(targetId)) {
            const r = rectFor(targetId);
            if (r) targets.set(targetId, r);
          }
        }
        const rects = [...targets.values()];
        if (!rects.length) return;
        const x1 = Math.min(...rects.map((r) => r.x));
        const y1 = Math.min(...rects.map((r) => r.y));
        const x2 = Math.max(...rects.map((r) => r.x + r.w));
        const y2 = Math.max(...rects.map((r) => r.y + r.h));
        rect = { x: x1, y: y1, w: x2 - x1, h: y2 - y1 };
      }
      // Inflate the target to the viewport's extent at MAX_FOCUS_ZOOM so
      // fitBounds caps there for small targets.
      const { width: vw, height: vh } = store.getState();
      const bw = Math.max(rect.w + FIT_MARGIN * 2, vw / MAX_FOCUS_ZOOM);
      const bh = Math.max(rect.h + FIT_MARGIN * 2, vh / MAX_FOCUS_ZOOM);
      fitBounds(
        { x: rect.x + rect.w / 2 - bw / 2, y: rect.y + rect.h / 2 - bh / 2, width: bw, height: bh },
        // FIT_MARGIN is already in the bounds; default padding would undercut
        // MAX_FOCUS_ZOOM.
        { duration: 400, padding: 0 },
      );
    }, 100);
    return () => clearTimeout(timer);
  }, [address, focusKey, principals, getInternalNode, getNodes, fitBounds, store]);
  return null;
}
