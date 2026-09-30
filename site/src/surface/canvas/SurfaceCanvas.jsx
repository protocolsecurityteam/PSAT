import { useCallback, useEffect, useState } from "react";
import {
  Background,
  Controls,
  Panel,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";

import { entityKey } from "../entityKey.js";
import { flowTypeWord, principalBadge } from "../format.js";
import { elkLayout } from "../layout/elkLayout.js";
import { ChanneledStepEdge } from "./ChanneledStepEdge.jsx";
import { ContractNode } from "./ContractNode.jsx";
import { FocusOnNode } from "./FocusOnNode.jsx";
import { GroupNode } from "./GroupNode.jsx";
import { buildControlsDetailMap } from "./controlsDetail.js";
import { SelectionLegend } from "./SelectionLegend.jsx";
import { REACH_EDGE_STROKE, edgeOnReachPath, reachChipText } from "./reachOverlay.js";

// Co-controllers live in group accordions; there is no standalone principal
// node type.
const nodeTypes = { contract: ContractNode, group: GroupNode };
const edgeTypes = { channeled: ChanneledStepEdge };

// Everything here is on the single active chain, so bare-address topology sets
// are collision-free; entity lookups still key by (chain, address).
export function SurfaceCanvas({ machines, fundFlows, principals, chain = "ethereum", selectedAddress, focusAddress, focusedAddress, highlightedAddresses, reachDistances, reachPathEdges, onSelectMachine, onSelectPrincipal }) {
  const [initNodes, setInitNodes] = useState([]);
  const [initEdges, setInitEdges] = useState([]);

  // Measured band height per group, so ELK reserves exactly what renders. Only
  // re-stored on change, so it converges.
  const [bandHeights, setBandHeights] = useState({});

  useEffect(() => {
    let cancelled = false;
    elkLayout(machines, fundFlows, principals, bandHeights, chain).then(({ nodes: n, edges: e }) => {
      if (!cancelled) {
        setInitNodes(n);
        setInitEdges(e);
      }
    });
    return () => { cancelled = true; };
  }, [machines, fundFlows, principals, bandHeights, chain]);

  const measureBand = useCallback((groupId, height) => {
    setBandHeights((cur) => {
      if (Math.abs((cur[groupId] || 0) - height) <= 1) return cur;
      return { ...cur, [groupId]: height };
    });
  }, []);

  // Uses the full principal from the list so the sidebar gets every field.
  const selectController = useCallback((addr) => {
    const key = entityKey(chain, addr);
    const p = (principals || []).find((x) => entityKey(chain, x.address) === key);
    if (p && onSelectPrincipal) onSelectPrincipal(p);
  }, [principals, onSelectPrincipal, chain]);

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (!initNodes.length) return;
    const selLc = selectedAddress?.toLowerCase();
    // Only the committed selection anchors dimming; browse previews never
    // re-anchor it.
    const sel = selLc;
    // Connected nodes and per-contract chips in one pass. Group containment
    // replaces principal→contract edges, so parent and children count as
    // connected.
    //
    // selectionChips: Map<addrLc, { out?, in? }> ("out": `sel` acts on it;
    // "in": it acts on `sel`); bidirectional pairs are common.
    const connectedNodes = new Set();
    const selectionChips = new Map();
    // Stubs light through the normal edge logic; relatedEdgeIds force-lights
    // the specific bundles the contract feeds, and brightGroups un-dims their
    // boxes without leaking into edge relatedness.
    const relatedEdgeIds = new Set();
    const brightGroups = new Set();
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
          // The same pair can surface through several bundles.
          const set = new Set(existing.split(", ").filter(Boolean));
          for (const c of caps.split(", ")) if (c) set.add(c);
          entry[direction] = [...set].join(", ");
        } else {
          entry[direction] = caps;
        }
      };
      // Walk the bundle's samples so chips land on the actual contracts, each
      // with its own sample's caps: a union would imply every child shares the
      // relationship.
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
          // Through the display word map, so a chip says "can call", never
          // `principal`.
          const capsText = (caps || []).join(", ") || flowTypeWord(flowType) || "";
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
      // Principal-source flows are pruned in elkLayout, so synthesize chips
      // from the group hierarchy.
      const selPrincipal = (principals || []).find(
        (p) => entityKey(chain, p.address) === entityKey(chain, sel),
      );
      // Chips say what the controller can actually do, from controls_detail.
      const detailByContract = buildControlsDetailMap(selPrincipal?.controls_detail, chain);
      const capsTextFor = (addrLc) => {
        const d = detailByContract.get(entityKey(chain, addrLc));
        const caps = d?.capabilities || [];
        const fns = d?.functions || [];
        return caps.length
          ? caps.join(", ")
          : fns.length
          ? fns.slice(0, 3).join(", ") + (fns.length > 3 ? ` +${fns.length - 3}` : "")
          : `${selPrincipal?.type || "principal"}-controlled`;
      };
      // Box membership isn't authority: a grouped_with machinery contract gets
      // no chip unless primary_for / co_controls / controls names it.
      const authorityAddrs = new Set(
        [
          ...(Array.isArray(selPrincipal?.primary_for) ? selPrincipal.primary_for : []),
          ...(Array.isArray(selPrincipal?.co_controls) ? selPrincipal.co_controls : []),
          ...(Array.isArray(selPrincipal?.controls) ? selPrincipal.controls : []),
        ]
          .map((a) => a?.toLowerCase())
          .filter(Boolean),
      );
      for (const n of initNodes) {
        const nid = n.id?.toLowerCase();
        const pid = n.parentId?.toLowerCase();
        if (pid === sel && (!selPrincipal || authorityAddrs.has(nid))) {
          connectedNodes.add(nid);
          if (selPrincipal) {
            addChip(nid, capsTextFor(nid), "out");
          }
        }
        if (nid === sel && pid) connectedNodes.add(pid);
      }

      // Light (and chip) contracts the principal controls outside its box:
      // co_controls, plain controls when it owns no box, and primary_for
      // (grouped_with can move an owned contract into another box). No edges:
      // the cross-group lines were the spaghetti grouping removed.
      const reach = [
        ...(Array.isArray(selPrincipal?.primary_for) ? selPrincipal.primary_for : []),
        ...(Array.isArray(selPrincipal?.controls) ? selPrincipal.controls : []),
        ...(Array.isArray(selPrincipal?.co_controls) ? selPrincipal.co_controls : []),
      ];
      if (reach.length) {
        const nodeByAddr = new Map(initNodes.map((n) => [n.id?.toLowerCase(), n]));
        for (const c of reach) {
          const t = c?.toLowerCase();
          const tn = t && nodeByAddr.get(t);
          if (!tn) continue;
          connectedNodes.add(t);
          if (tn.parentId) connectedNodes.add(tn.parentId.toLowerCase());
          addChip(t, capsTextFor(t), "out");
        }
      }

      // Light the bundle a selected contract's stub feeds, matched by id;
      // adding the groups to connectedNodes would light unrelated bundles.
      const selNode = initNodes.find((n) => n.id?.toLowerCase() === sel);
      if (selNode && selNode.type === "contract" && selNode.parentId) {
        const groupAddrs = new Set(
          initNodes.filter((n) => n.type === "group").map((n) => n.id?.toLowerCase()),
        );
        for (const e of initEdges) {
          const eSrc = e.source?.toLowerCase();
          const eTgt = e.target?.toLowerCase();
          if (!groupAddrs.has(eSrc) || !groupAddrs.has(eTgt) || eSrc === eTgt) continue;
          let touchesC = false;
          for (const s of e.data?.samples || []) {
            if (s.from?.toLowerCase() === sel || s.to?.toLowerCase() === sel) { touchesC = true; break; }
          }
          if (!touchesC) continue;
          relatedEdgeIds.add(e.id);
          brightGroups.add(eSrc);
          brightGroups.add(eTgt);
        }
      }
    }

    // An audit/agent highlight takes precedence over connected-node dimming.
    const hiActive = highlightedAddresses && highlightedAddresses.size > 0;

    const foc = focusedAddress?.toLowerCase();
    // Gold marks the browsed entity only, never what it controls; suppressed on
    // the committed selection.
    const browseLc = foc && foc !== selLc ? foc : null;
    // Fallback for a principal with no node or accordion row: dot the contracts
    // it touches, each with a chip naming it. Any real footprint suppresses
    // this.
    let browseFallback = null;
    let browseChips = null;
    if (browseLc) {
      const browseKey = entityKey(chain, browseLc);
      const hasNode = initNodes.some((n) => n.id?.toLowerCase() === browseLc);
      const hasRow =
        !hasNode &&
        initNodes.some(
          (n) =>
            n.type === "group" &&
            (n.data.controllers || []).some((c) => entityKey(chain, c.address) === browseKey),
        );
      if (!hasNode && !hasRow) {
        const bp = (principals || []).find((p) => entityKey(chain, p.address) === browseKey);
        const touched = [...(bp?.controls || []), ...(bp?.co_controls || [])]
          .map((a) => String(a).toLowerCase());
        if (touched.length) {
          browseFallback = new Set(touched);
          browseChips = new Map();
          const detailByAddr = buildControlsDetailMap(bp?.controls_detail, chain);
          // The search preview already shows the address.
          const who = principalBadge(bp);
          for (const t of browseFallback) {
            const d = detailByAddr.get(entityKey(chain, t));
            const fns = d?.functions || [];
            let what;
            if (fns.length) {
              // Names up to ~55 chars then "+N more"; a count if even the first
              // is too long.
              const names = [];
              for (const f of fns) {
                if ([...names, f].join(", ").length > 55) break;
                names.push(f);
              }
              what = names.length
                ? `calls ${names.join(", ")}${fns.length > names.length ? ` +${fns.length - names.length} more` : ""}`
                : `calls ${fns.length} function${fns.length === 1 ? "" : "s"}`;
            } else {
              what = (d?.capabilities || []).join(", ") || "has authority";
            }
            browseChips.set(t, `${who} (not on graph) · ${what}`);
          }
        }
      }
    }
    // Reached nodes get a hop chip and no card treatment (a tint would be a
    // weaker duplicate). reachChips: hop >= 2 only (hop 1 has the acts-on
    // chip). reachBright: closure nodes and their groups, exempt from the dim.
    // Suppressed under an audit/agent overlay.
    const reachActive = !hiActive && sel && reachDistances && reachDistances.size > 0;
    const reachChips = new Map();
    const reachBright = new Set();
    if (reachActive) {
      const parentOf = new Map(initNodes.map((n) => [n.id?.toLowerCase(), n.parentId?.toLowerCase() || null]));
      for (const [addr, hop] of reachDistances) {
        if (!parentOf.has(addr)) continue;
        reachBright.add(addr);
        const text = reachChipText(hop);
        if (text) reachChips.set(addr, text);
      }
      for (const addr of [...reachBright]) {
        const parent = parentOf.get(addr);
        if (parent) reachBright.add(parent);
      }
    }

    // Light the drawn edges on the reach tree, including the stubs, so a
    // bundled hop isn't broken at the groups.
    const reachPathActive = Boolean(reachActive && reachPathEdges && reachPathEdges.size);
    const reachPathSources = new Set();
    const reachPathTargets = new Set();
    if (reachPathActive) {
      for (const pair of reachPathEdges) {
        const [from, to] = pair.split(">");
        reachPathSources.add(from);
        reachPathTargets.add(to);
      }
    }
    setNodes(
      initNodes.map((n) => {
        const nid = n.id?.toLowerCase();
        const inAudit = hiActive && highlightedAddresses.has(nid);
        // The selection is never dimmed by an overlay. Browse-marked nodes (and
        // groups listing the browsed principal) are exempt from every dim
        // source.
        const isFoc = (foc && nid === foc) || (browseFallback != null && browseFallback.has(nid));
        const hasBrowsedRow =
          browseLc &&
          n.type === "group" &&
          (n.data.controllers || []).some((c) => c.address?.toLowerCase() === browseLc);
        const dimmed = !isFoc && !hasBrowsedRow && !reachBright.has(nid) &&
          (hiActive ? (!inAudit && nid !== sel) : (sel && !connectedNodes.has(nid) && !brightGroups.has(nid)));
        const focused = isFoc && nid !== selLc;
        // Merge, don't replace: groups carry ELK width/height in n.style.
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
            selected: nid === selLc,
            focused,
            reachChip: reachChips.get(nid) || null,
            selectionChip: selectionChips.get(nid) || null,
            browseChip: browseChips?.get(nid) || null,
            // Contract nodes carry .machine; principal and group nodes carry
            // .principal.
            onSelect: n.data.principal
              ? () => onSelectPrincipal && onSelectPrincipal(n.data.principal)
              : () => onSelectMachine(n.data.machine),
            ...(n.type === "group"
              ? {
                  selectedControllerAddr: sel || null,
                  focusedControllerAddr: browseLc,
                  onSelectController: (addr) => selectController(addr),
                  onMeasureBand: (h) => measureBand(n.id, h),
                }
              : null),
          },
        };
      })
    );

    const nextEdges = initEdges.map((e) => {
      const src = e.source?.toLowerCase();
      const tgt = e.target?.toLowerCase();
      // Bundles terminate at groups, so the endpoint check works; the
      // both-connected clause keeps intra-group edges lit when the group is
      // selected.
      const edgeInAudit = hiActive && highlightedAddresses.has(src) && highlightedAddresses.has(tgt);
      const directlyConnected = src === sel || tgt === sel;
      // A stub belongs to its contract end; lighting on that alone makes a
      // cross-group path light end to end without lighting every stub in the
      // box.
      const stubContractEnd = e.data?.stub ? (e.data.inbound ? tgt : src) : null;
      const stubRelated = stubContractEnd != null && connectedNodes.has(stubContractEnd);
      // Match the role (outbound = hop leaves, inbound = hop lands), not mere
      // membership.
      const stubOnReachPath =
        reachPathActive &&
        stubContractEnd != null &&
        (e.data.inbound ? reachPathTargets.has(stubContractEnd) : reachPathSources.has(stubContractEnd));
      const onReachPath =
        reachPathActive && (stubOnReachPath || edgeOnReachPath(e, reachPathEdges));
      // Hop-1 edges keep the selection style; violet would demote the stronger
      // claim.
      const selectionOwned = directlyConnected || relatedEdgeIds.has(e.id) || stubRelated;
      const related = hiActive
        ? edgeInAudit
        : (!sel || selectionOwned || onReachPath || (connectedNodes.has(src) && connectedNodes.has(tgt)));
      const reachStyled = !hiActive && onReachPath && !selectionOwned;
      const baseWidth = e.style?.strokeWidth || 1;
      return {
        ...e,
        style: {
          ...e.style,
          opacity: related ? 1 : 0.08,
          ...(reachStyled ? { stroke: REACH_EDGE_STROKE } : null),
          strokeWidth: reachStyled
            ? Math.max(2.5, baseWidth)
            : related && sel
            ? 2
            : baseWidth,
        },
        animated: related && e.animated,
      };
    });

    setEdges(nextEdges);
  }, [initNodes, initEdges, principals, chain, selectedAddress, focusedAddress, highlightedAddresses, reachDistances, reachPathEdges, onSelectMachine, onSelectPrincipal, selectController, measureBand]);

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
        <FocusOnNode address={focusAddress?.address} focusKey={focusAddress?.key} principals={principals} />
        {selectedAddress && (
          <Panel position="top-center">
            <SelectionLegend
              onClear={() => onSelectMachine(null)}
              hasReach={Boolean(reachDistances && [...reachDistances.values()].some((hop) => reachChipText(hop)))}
            />
          </Panel>
        )}
      </ReactFlow>
    </div>
  );
}
