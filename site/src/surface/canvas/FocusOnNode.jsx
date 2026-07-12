import { useEffect, useRef } from "react";
import { useReactFlow, useStoreApi } from "@xyflow/react";

// Focus zoom ceiling: the camera never zooms IN past this, but zooms OUT as
// far as needed to fit the focused target. A contract card focuses exactly as
// a plain setCenter(zoom 1.2) did; a group box taller/wider than the
// viewport at 1.2 (a safe/EOA owning many contracts) fits entirely instead
// of centering its middle and pushing the header label off-screen.
const MAX_FOCUS_ZOOM = 1.2;
const FIT_MARGIN = 24;

export function FocusOnNode({ address, focusKey, principals }) {
  const { fitBounds, getInternalNode, getNodes } = useReactFlow();
  const store = useStoreApi();
  const lastKey = useRef(null);
  useEffect(() => {
    if (!address || focusKey === lastKey.current) return;
    lastKey.current = focusKey;

    // node.position is RELATIVE to the parent group for nodes inside
    // a group container (every contract inside a Safe / EOA group on
    // this page). The resolved absolute position lives on the
    // internal-node representation, not the public node, so we look
    // it up via getInternalNode. Without this, focusing a grouped
    // contract centres the camera at the group's local origin
    // (sometimes thousands of px from where the card actually
    // renders, e.g. StakedTokenV1 inside the EOA group).
    const rectFor = (addr) => {
      if (!addr) return null;
      const internal = getInternalNode(addr) || getInternalNode(addr.toLowerCase());
      const node = internal
        || getNodes().find((n) => n.id === addr)
        || getNodes().find((n) => n.id?.toLowerCase() === addr.toLowerCase());
      if (!node) return null;
      return {
        x: internal?.internals?.positionAbsolute?.x ?? node.positionAbsolute?.x ?? node.position?.x ?? 0,
        y: internal?.internals?.positionAbsolute?.y ?? node.positionAbsolute?.y ?? node.position?.y ?? 0,
        w: node.measured?.width || node.width || 220,
        h: node.measured?.height || node.height || 120,
      };
    };

    // Small delay to let ReactFlow finish rendering positions
    const timer = setTimeout(() => {
      let rect = rectFor(address);
      if (!rect) {
        // Node-less principal (a co-controller safe/EOA that owns no group
        // box). Two framings:
        //   - listed in some group's Controllers accordion → fit the group
        //     box(es) holding its touched contracts (headers included), so
        //     its gold-marked row is in frame, matching a group-header focus.
        //   - footprint-less (no node, no row anywhere) → zoom to the touched
        //     contract cards themselves, exactly like browsing a contract —
        //     that's where the gold dots + off-graph chip land.
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
      // Inflate the target rect to at least the viewport's extent at
      // MAX_FOCUS_ZOOM, keeping it centered. fitBounds' computed zoom
      // (min of the per-axis fits) then caps at MAX_FOCUS_ZOOM for anything
      // smaller and drops only as far as the larger dimension requires.
      const { width: vw, height: vh } = store.getState();
      const bw = Math.max(rect.w + FIT_MARGIN * 2, vw / MAX_FOCUS_ZOOM);
      const bh = Math.max(rect.h + FIT_MARGIN * 2, vh / MAX_FOCUS_ZOOM);
      fitBounds(
        { x: rect.x + rect.w / 2 - bw / 2, y: rect.y + rect.h / 2 - bh / 2, width: bw, height: bh },
        // padding 0: FIT_MARGIN is already baked into the bounds, and the
        // default 10% padding would undercut MAX_FOCUS_ZOOM for small nodes.
        { duration: 400, padding: 0 },
      );
    }, 100);
    return () => clearTimeout(timer);
  }, [address, focusKey, principals, getInternalNode, getNodes, fitBounds, store]);
  return null;
}
