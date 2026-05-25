import { useCallback, useEffect, useState } from "react";
import {
  Background,
  Controls,
  Panel,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";

import { elkLayout } from "../layout/elkLayout.js";
import { ChanneledStepEdge } from "./ChanneledStepEdge.jsx";
import { ContractNode } from "./ContractNode.jsx";
import { FocusOnNode } from "./FocusOnNode.jsx";
import { GroupNode } from "./GroupNode.jsx";
import { PrincipalNode } from "./PrincipalNode.jsx";
import { PrincipalTourNav } from "./PrincipalTourNav.jsx";

const nodeTypes = { contract: ContractNode, principal: PrincipalNode, group: GroupNode };
const edgeTypes = { channeled: ChanneledStepEdge };

// Selection-time legend. Renders only while a contract is selected so
// the chip-color convention (warm = selected acts outward, cool =
// other acts on selected) doesn't have to be memorised — the legend
// is right there with the chips it explains. Uses "acts on" because
// the edges represent any directed relationship (controls / calls /
// sends value / owns / proxies-to); the chip text spells out which
// specifically.
function SelectionLegend() {
  return (
    <div className="ps-selection-legend">
      <div className="ps-selection-legend-row">
        <span className="ps-selection-legend-swatch ps-selection-legend-swatch--out" />
        <span>selected acts on this contract</span>
      </div>
      <div className="ps-selection-legend-row">
        <span className="ps-selection-legend-swatch ps-selection-legend-swatch--in" />
        <span>this contract acts on selected</span>
      </div>
    </div>
  );
}

export function SurfaceCanvas({ machines, fundFlows, principals, selectedAddress, focusAddress, focusedAddress, highlightedAddresses, onSelectMachine, onSelectPrincipal, principalTour, onTourGo, onTourBack }) {
  const [initNodes, setInitNodes] = useState([]);
  const [initEdges, setInitEdges] = useState([]);

  // Which controller row (if any) is expanded, and the measured header-band
  // height per (group, open-row) state (keyed "groupId:idx" / "groupId:c").
  // Both feed elkLayout so the open row's group grows its header band and ELK
  // re-packs the canvas to make room — the group extends rather than
  // overlapping cards/neighbours. GroupNode reports the real band height via
  // onMeasureBand; we only re-store (and thus re-layout) when it actually
  // changes, so it converges.
  const [expanded, setExpanded] = useState(null);
  const [bandHeights, setBandHeights] = useState({});

  // Run elk layout (async)
  useEffect(() => {
    let cancelled = false;
    elkLayout(machines, fundFlows, principals, expanded, bandHeights).then(({ nodes: n, edges: e }) => {
      if (!cancelled) {
        setInitNodes(n);
        setInitEdges(e);
      }
    });
    return () => { cancelled = true; };
  }, [machines, fundFlows, principals, expanded, bandHeights]);

  const toggleController = useCallback((groupId, idx) => {
    setExpanded((cur) => (cur && cur.groupId === groupId && cur.idx === idx ? null : { groupId, idx }));
  }, []);

  const measureBand = useCallback((groupId, idx, height) => {
    setBandHeights((cur) => {
      const key = `${groupId}:${idx ?? "c"}`;
      if (Math.abs((cur[key] || 0) - height) <= 1) return cur;
      return { ...cur, [key]: height };
    });
  }, []);

  // Clicking a controller row selects that principal so the existing logic
  // highlights the contracts it governs (dims everything else + chips them) and
  // opens its sidebar. Looks the full principal up from the list so the sidebar
  // gets every field. focus:false keeps the camera put — selecting the primary
  // would otherwise pan/zoom to its (large) group node, which the user reads as
  // an unwanted zoom-in; we only want the highlight.
  const selectController = useCallback((addr) => {
    const lc = addr?.toLowerCase();
    const p = (principals || []).find((x) => x.address?.toLowerCase() === lc);
    if (p && onSelectPrincipal) onSelectPrincipal(p, { focus: false });
  }, [principals, onSelectPrincipal]);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (!initNodes.length) return;
    const sel = selectedAddress?.toLowerCase();
    // Find all nodes connected to the selected node AND, in the same
    // pass, the per-contract chip data. Owner-grouping moves the
    // principal→contract relationship from an edge into the
    // parent/child hierarchy — so the parent group of the selected
    // node AND every child of a selected group both count as
    // "connected" even though no edge exists between them.
    //
    // selectionChips: Map<addrLc, { out?: string, in?: string }> —
    // each related contract can carry up to two chips, one per
    // direction, because bidirectional relationships are common in
    // this data (101 pairs in the etherfi protocol). "out" means
    // `sel` acts on this contract, "in" means this contract acts on
    // `sel`. Renders as banners above (out) and below (in) the card,
    // restoring what the old per-edge chip layout showed when two
    // edges existed between the same pair.
    const connectedNodes = new Set();
    const selectionChips = new Map();
    // Edges from a selected co-controller (a guardian-rail node, or a group)
    // to the contracts it controls — drawn only while selected, so the rail
    // stays a clean band rather than permanent cross-group fanout.
    const coControllerEdges = [];
    if (sel) {
      connectedNodes.add(sel);
      const addChip = (addrLc, caps, direction) => {
        if (!addrLc || addrLc === sel || !caps) return;
        let entry = selectionChips.get(addrLc);
        if (!entry) {
          entry = {};
          selectionChips.set(addrLc, entry);
        }
        const existing = entry[direction];
        if (existing) {
          // Same direction seen twice — happens when the same
          // (other, sel) pair surfaces through multiple aggregated
          // bundles. Union the caps within the direction.
          const set = new Set(existing.split(", ").filter(Boolean));
          for (const c of caps.split(", ")) if (c) set.add(c);
          entry[direction] = [...set].join(", ");
        } else {
          entry[direction] = caps;
        }
      };
      // Aggregated edges carry the underlying sample list in
      // data.samples; walk those instead of the bundle endpoints so
      // clicking a child contract still lights up the actual contracts
      // it touches, not just the parent groups. Each chip's caps come
      // from its OWN sample, not the bundle's union — bundles can mix
      // flow shapes (e.g. one sample has `value-in`, another has
      // `ownership`) and a union'd chip would falsely imply every child
      // has the same relationship to the selected node.
      for (const e of initEdges) {
        const samples = e.data?.samples;
        const fallbackCaps = e.data?.capabilities || [];
        const fallbackFlowType = e.data?.flowType;
        const items = samples && samples.length > 0
          ? samples.map((s) => ({
              from: s.from?.toLowerCase(),
              to: s.to?.toLowerCase(),
              caps: s.capabilities || fallbackCaps,
              flowType: s.flowType || fallbackFlowType,
            }))
          : [{
              from: e.source?.toLowerCase(),
              to: e.target?.toLowerCase(),
              caps: fallbackCaps,
              flowType: fallbackFlowType,
            }];
        for (const { from, to, caps, flowType } of items) {
          const capsText = (caps || []).join(", ") || flowType || "";
          if (from === sel) {
            connectedNodes.add(to);
            addChip(to, capsText, "out");
          }
          if (to === sel) {
            connectedNodes.add(from);
            addChip(from, capsText, "in");
          }
        }
      }
      // Principal clicks: chips on every child the principal owns.
      // The principal-source fund-flow edges were pruned at
      // elkLayout's fundFlow loop ("if (principalByAddr.has(from))
      // continue") to keep the canvas clean, so the sample walk above
      // can't see these relationships — synthesize them from the
      // parent/child hierarchy instead, with cap text derived from the
      // principal's type (safe-controlled / timelock-controlled / ...).
      const selPrincipal = (principals || []).find(
        (p) => p.address?.toLowerCase() === sel,
      );
      // Per-contract capability detail for the selected principal
      // (server-computed principal.controls_detail, passthrough-resolved), so a
      // chip says what the controller can actually DO ("pause, fund-out", or
      // concrete function names) rather than a generic "<type>-controlled".
      // Used for both the group children (primary) and the co-controlled set.
      const detailByContract = new Map();
      for (const d of selPrincipal?.controls_detail || []) {
        if (d?.address) detailByContract.set(d.address.toLowerCase(), d);
      }
      const capsTextFor = (addrLc) => {
        const d = detailByContract.get(addrLc);
        const caps = d?.capabilities || [];
        const fns = d?.functions || [];
        return caps.length
          ? caps.join(", ")
          : fns.length
          ? fns.slice(0, 3).join(", ") + (fns.length > 3 ? ` +${fns.length - 3}` : "")
          : `${selPrincipal?.type || "principal"}-controlled`;
      };
      for (const n of initNodes) {
        const nid = n.id?.toLowerCase();
        const pid = n.parentId?.toLowerCase();
        if (pid === sel) {
          connectedNodes.add(nid);
          if (selPrincipal) {
            addChip(nid, capsTextFor(nid), "out");
          }
        }
        if (nid === sel && pid) connectedNodes.add(pid);
      }

      // Co-controller selection. The selected principal (a guardian-rail node,
      // or a group that also co-controls elsewhere) may hold authority on
      // contracts it isn't the primary owner of (principal.co_controls). Those
      // relationships have no permanent edge — the owner-grouping dropped
      // principal→contract edges to kill fanout — so on select we light up the
      // contracts it controls (and their containing groups, so a highlighted
      // child isn't dimmed along with its box) and draw its edges, which all
      // vanish on deselect.
      const coControls = Array.isArray(selPrincipal?.co_controls) ? selPrincipal.co_controls : [];
      if (coControls.length) {
        const nodeByAddr = new Map(initNodes.map((n) => [n.id?.toLowerCase(), n]));
        // A co-controller selected from inside a group's accordion has no node
        // of its own (it isn't a primary group), so we can't anchor an edge to
        // it — the chips + dimming below still convey what it governs. Only
        // draw the dashed edges when the selected principal IS a node on the
        // canvas (i.e. a primary group that also co-controls elsewhere).
        const selHasNode = nodeByAddr.has(sel);
        for (const c of coControls) {
          const t = c?.toLowerCase();
          const tn = t && nodeByAddr.get(t);
          if (!tn) continue;
          connectedNodes.add(t);
          if (tn.parentId) connectedNodes.add(tn.parentId.toLowerCase());
          addChip(t, capsTextFor(t), "out");
          if (!selHasNode) continue;
          coControllerEdges.push({
            id: `co-${sel}-${t}`,
            source: selPrincipal.address,
            target: tn.id,
            sourceHandle: "ctrl-out",
            targetHandle: "ctrl-in",
            type: "smoothstep",
            style: { stroke: "#d99a4e", strokeWidth: 1.5, strokeDasharray: "4 3" },
            animated: true,
            data: { coControl: true },
          });
        }
      }
    }

    // Audit-coverage highlight takes precedence when active: non-covered
    // nodes dim, covered ones get a green ring so the user sees exactly
    // which contracts an audit touched. Falls back to the connected-node
    // dimming when no audit is selected.
    const hiActive = highlightedAddresses && highlightedAddresses.size > 0;

    const foc = focusedAddress?.toLowerCase();
    setNodes(
      initNodes.map((n) => {
        const nid = n.id?.toLowerCase();
        const inAudit = hiActive && highlightedAddresses.has(nid);
        const dimmed = hiActive ? !inAudit : (sel && !connectedNodes.has(nid));
        const focused = foc && nid === foc;
        // Merge — don't replace — n.style. Group containers carry
        // ELK-computed width/height in n.style and we'd otherwise blow
        // them away each time selection changes.
        const baseStyle = n.style || {};
        const style = dimmed
          ? { ...baseStyle, opacity: 0.2 }
          : inAudit
          ? { ...baseStyle, boxShadow: "0 0 0 2px #22c55e, 0 0 12px rgba(34,197,94,0.55)", borderRadius: 6 }
          : baseStyle;
        return {
          ...n,
          style,
          data: {
            ...n.data,
            selected: n.id === selectedAddress,
            focused,
            selectionChip: selectionChips.get(nid) || null,
            // Dispatch by node kind: contract nodes carry .machine,
            // principal AND group nodes both carry .principal. A click on
            // a group's header (the only pointer-events-active region)
            // opens the principal detail just like a standalone
            // PrincipalNode click, so users get the same drill-in either
            // way.
            onSelect: n.data.principal
              ? () => onSelectPrincipal && onSelectPrincipal(n.data.principal)
              : () => onSelectMachine(n.data.machine),
            // Controllers-accordion wiring for group nodes: which row is open
            // (so GroupNode renders its detail), which controller is currently
            // selected (so the row reads as active), plus the toggle / select /
            // measure callbacks that drive expansion, highlighting, and the
            // grow-on-expand re-layout.
            ...(n.type === "group"
              ? {
                  expandedIdx: expanded && expanded.groupId === n.id ? expanded.idx : null,
                  selectedControllerAddr: sel || null,
                  onToggleController: (idx) => toggleController(n.id, idx),
                  onSelectController: (addr) => selectController(addr),
                  onMeasureBand: (idx, h) => measureBand(n.id, idx, h),
                }
              : null),
          },
        };
      })
    );

    const nextEdges = initEdges.map((e) => {
      const src = e.source?.toLowerCase();
      const tgt = e.target?.toLowerCase();
      // Aggregated bundles already terminate at group endpoints, so
      // the simple endpoint check matches even when the underlying
      // sample edges have different addresses. The both-in-connected
      // clause keeps intra-group child↔child edges visible when the
      // group itself is selected — without it, clicking a group dims
      // every internal wire because none of them touch the group
      // address directly.
      const edgeInAudit = hiActive && highlightedAddresses.has(src) && highlightedAddresses.has(tgt);
      const directlyConnected = src === sel || tgt === sel;
      const related = hiActive
        ? edgeInAudit
        : (!sel || directlyConnected || (connectedNodes.has(src) && connectedNodes.has(tgt)));
      return {
        ...e,
        style: {
          ...e.style,
          opacity: related ? 1 : 0.08,
          strokeWidth: related && sel ? 2 : (e.style?.strokeWidth || 1),
        },
        animated: related && e.animated,
      };
    });

    setEdges(coControllerEdges.length ? [...nextEdges, ...coControllerEdges] : nextEdges);
  }, [initNodes, initEdges, principals, selectedAddress, focusedAddress, highlightedAddresses, onSelectMachine, onSelectPrincipal, expanded, toggleController, selectController, measureBand]);

  return (
    <div className="ps-canvas-wrap">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onPaneClick={() => onSelectMachine(null)}
        fitView
        minZoom={0.2}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={24} size={1} />
        <Controls showInteractive={false} />
        <FocusOnNode address={focusAddress?.address} focusKey={focusAddress?.key} />
        {principalTour && principalTour.principals.length > 1 && (
          <Panel position="top-right">
            <PrincipalTourNav tour={principalTour} onGo={onTourGo} onBack={onTourBack} />
          </Panel>
        )}
        {selectedAddress && (
          <Panel position="top-center">
            <SelectionLegend />
          </Panel>
        )}
      </ReactFlow>
    </div>
  );
}
