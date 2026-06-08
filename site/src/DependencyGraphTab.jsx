/**
 * DependencyGraphTab — interactive SVG visualization of the contract dependency
 * graph. Follows the same pan/zoom/drag pattern as the permission GraphTab.
 *
 * Expects a `data` prop containing the output of build_dependency_visualization()
 * (the contents of dependency_graph_viz.json).
 */

import { useEffect, useMemo, useRef, useState } from "react";

import { blockExplorerAddressUrl } from "./blockExplorer.js";
import { shortenAddress, wrapText } from "./graph.js";
import { buildDependencyGraph, layoutDependencyGraph, computeEdgeGeometry } from "./dependencyGraph.js";

// ── Node body renderer (JSX version of svgDependencyNodeMarkup) ────────────

function renderNodeBody(node) {
  const isRect = node.shape === "rect";
  const maxChars = isRect ? 28 : 16;
  const titleLines = wrapText(node.title, maxChars, isRect ? 2 : 3);
  const subtitleLines = wrapText(node.subtitle, maxChars, 2);
  const metaLines = wrapText(node.meta, maxChars, 2);

  const centerX = node.width / 2;
  const centerY = node.height / 2;
  const titleStartY = isRect ? 30 : centerY - 28;
  const subtitleStartY = titleStartY + titleLines.length * 17 + 12;
  const metaStartY = subtitleStartY + subtitleLines.length * 15 + 14;

  const renderBlock = (lines, className, startY) =>
    lines.map((line, i) => (
      <text key={`${className}-${i}`} className={className} x="0" y={startY + i * 15} textAnchor="middle">
        {line}
      </text>
    ));

  return (
    <>
      <g className="graph-svg-shape" fill={node.fill} stroke={node.stroke} strokeWidth="3">
        {node.shape === "circle" ? (
          <ellipse cx={centerX} cy={centerY} rx={node.width / 2} ry={node.height / 2} />
        ) : (
          <rect x="0" y="0" width={node.width} height={node.height} rx="22" ry="22" />
        )}
      </g>
      <g transform={`translate(${centerX}, ${titleStartY})`} fill={node.text}>
        {renderBlock(titleLines, "graph-svg-title", 0)}
        {renderBlock(subtitleLines, "graph-svg-subtitle", subtitleLines.length ? subtitleStartY - titleStartY : 0)}
        {renderBlock(metaLines, "graph-svg-meta", metaLines.length ? metaStartY - titleStartY : 0)}
      </g>
    </>
  );
}

// ── Edge slot distribution ─────────────────────────────────────────────────

function edgeSlotPercents(count) {
  if (count <= 1) return [50];
  const start = 18;
  const end = 82;
  const step = (end - start) / (count - 1);
  return Array.from({ length: count }, (_, i) => start + i * step);
}

// ── Detail panel for selected node ─────────────────────────────────────────

function ScannerAddressLink({ address, chainId, short = false }) {
  if (!address) return null;
  const href = blockExplorerAddressUrl(address, chainId);
  if (!href) return <span className="mono">{short ? shortenAddress(address) : address}</span>;
  return (
    <a
      className="scanner-link mono"
      href={href}
      target="_blank"
      rel="noreferrer"
    >
      {short ? shortenAddress(address) : address}
    </a>
  );
}

function DependencyNodeDetails({ node, chainId }) {
  if (!node) {
    return (
      <div className="detail-panel">
        <p className="empty">Click a node to view details.</p>
      </div>
    );
  }

  return (
    <div className="detail-panel">
      <h3>{node.title || node.label}</h3>
      <div className="kv-grid">
        <div className="kv-row">
          <span className="key">Address</span>
          <ScannerAddressLink address={node.address} chainId={chainId} />
        </div>
        <div className="kv-row">
          <span className="key">Type</span>
          <span>{node.type}</span>
        </div>
        {node.proxy_type && (
          <div className="kv-row">
            <span className="key">Proxy Type</span>
            <span>{node.proxy_type}</span>
          </div>
        )}
        {node.implementation && (
          <div className="kv-row">
            <span className="key">Implementation</span>
            <ScannerAddressLink address={node.implementation} chainId={chainId} short />
          </div>
        )}
        {node.beacon && (
          <div className="kv-row">
            <span className="key">Beacon</span>
            <ScannerAddressLink address={node.beacon} chainId={chainId} short />
          </div>
        )}
        {node.admin && (
          <div className="kv-row">
            <span className="key">Admin</span>
            <ScannerAddressLink address={node.admin} chainId={chainId} short />
          </div>
        )}
        {node.source?.length > 0 && (
          <div className="kv-row">
            <span className="key">Discovered via</span>
            <span>{node.source.join(", ")}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default function DependencyGraphTab({ data: dataProp, runName, chainId = null }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [fetched, setFetched] = useState(null);
  const stageRef = useRef(null);
  const svgRef = useRef(null);
  const viewportRef = useRef(null);
  const transformRef = useRef({ x: 0, y: 0, scale: 1 });
  const rafRef = useRef(0);
  const dragRef = useRef(null);

  // If data isn't passed inline, try fetching the artifact
  useEffect(() => {
    if (dataProp) {
      setFetched(null);
      return;
    }
    if (!runName) return;
    let cancelled = false;
    fetch(`/api/analyses/${encodeURIComponent(runName)}/artifact/dependency_graph_viz.json`)
      .then((r) => (r.ok ? r.json() : null))
      .then((json) => { if (!cancelled) setFetched(json); })
      .catch(() => { if (!cancelled) setFetched(null); });
    return () => { cancelled = true; };
  }, [dataProp, runName]);

  const data = dataProp || fetched;

  useEffect(() => {
    setSelectedNode(null);
  }, [data]);

  // Build and layout graph
  const graph = useMemo(() => {
    const visual = buildDependencyGraph(data);
    if (!visual) return null;
    return layoutDependencyGraph(visual);
  }, [data]);

  if (!graph) {
    return <p className="empty">No dependency graph data available.</p>;
  }

  const graphBounds = useMemo(() => {
    const margin = 40;
    const minX = Math.min(...graph.nodes.map((n) => n.x)) - margin;
    const minY = Math.min(...graph.nodes.map((n) => n.y)) - margin;
    const maxX = Math.max(...graph.nodes.map((n) => n.x + n.width)) + margin;
    const maxY = Math.max(...graph.nodes.map((n) => n.y + n.height)) + margin;
    return { minX, minY, maxX, maxY, width: maxX - minX, height: maxY - minY };
  }, [graph]);

  // Edge path geometry
  const edgeGeometry = useMemo(() => {
    const outgoingById = new Map();
    const incomingById = new Map();

    for (const edge of graph.edges) {
      if (!edge.from || !edge.to) continue;
      const out = outgoingById.get(edge.from.id) || [];
      out.push(edge);
      outgoingById.set(edge.from.id, out);
      const inc = incomingById.get(edge.to.id) || [];
      inc.push(edge);
      incomingById.set(edge.to.id, inc);
    }

    return graph.edges
      .filter((e) => e.from && e.to)
      .map((edge) => {
        const outgoing = outgoingById.get(edge.from.id) || [];
        const incoming = incomingById.get(edge.to.id) || [];
        const sourceIndex = outgoing.indexOf(edge);
        const targetIndex = incoming.indexOf(edge);
        const sourcePercents = edgeSlotPercents(outgoing.length);
        const targetPercents = edgeSlotPercents(incoming.length);
        const startX = edge.from.x + edge.from.width;
        const startY = edge.from.y + (edge.from.height * (sourcePercents[sourceIndex] || 50)) / 100;
        const endX = edge.to.x;
        const endY = edge.to.y + (edge.to.height * (targetPercents[targetIndex] || 50)) / 100;
        const curve = Math.max(50, (endX - startX) / 2.2);
        return {
          ...edge,
          startX,
          startY,
          endX,
          endY,
          path: `M ${startX} ${startY} C ${startX + curve} ${startY}, ${endX - curve} ${endY}, ${endX} ${endY}`,
        };
      });
  }, [graph]);

  // Pan / zoom / drag — identical pattern to GraphTab
  useEffect(() => {
    function applyTransform() {
      const viewport = viewportRef.current;
      if (!viewport) return;
      const { x, y, scale } = transformRef.current;
      viewport.setAttribute("transform", `translate(${x} ${y}) scale(${scale})`);
    }

    function scheduleApply() {
      if (rafRef.current) return;
      rafRef.current = window.requestAnimationFrame(() => {
        rafRef.current = 0;
        applyTransform();
      });
    }

    const stage = stageRef.current;
    const svg = svgRef.current;
    if (!stage || !svg || !graph) return undefined;

    // Fit graph to viewport
    const rect = stage.getBoundingClientRect();
    const paddingX = 56;
    const paddingY = 44;
    const fitScaleX = ((rect.width - paddingX * 2) / graphBounds.width) * (graph.width / rect.width);
    const fitScaleY = ((rect.height - paddingY * 2) / graphBounds.height) * (graph.height / rect.height);
    const scale = Math.min(Math.max(Math.min(fitScaleX, fitScaleY) * 1.12, 0.94), 2.9);
    transformRef.current = {
      x: (graph.width - graphBounds.width * scale) / 2 - graphBounds.minX * scale,
      y: (graph.height - graphBounds.height * scale) / 2 - graphBounds.minY * scale,
      scale,
    };
    applyTransform();

    function onWheel(event) {
      event.preventDefault();
      const svgRect = svg.getBoundingClientRect();
      const pointX = event.clientX - svgRect.left;
      const pointY = event.clientY - svgRect.top;
      const current = transformRef.current;
      const factor = event.deltaY < 0 ? 1.08 : 0.92;
      const nextScale = Math.min(3.6, Math.max(0.22, current.scale * factor));
      const worldX = (pointX - current.x) / current.scale;
      const worldY = (pointY - current.y) / current.scale;
      transformRef.current = { scale: nextScale, x: pointX - worldX * nextScale, y: pointY - worldY * nextScale };
      scheduleApply();
    }

    function onPointerDown(event) {
      if (event.button !== 0) return;
      if (event.target !== stage && event.target !== svg) return;
      dragRef.current = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: transformRef.current.x,
        originY: transformRef.current.y,
      };
      stage.classList.add("dragging");
      stage.setPointerCapture(event.pointerId);
    }

    function onPointerMove(event) {
      const drag = dragRef.current;
      if (!drag || drag.pointerId !== event.pointerId) return;
      const sensitivity = 1.45;
      transformRef.current = {
        ...transformRef.current,
        x: drag.originX + (event.clientX - drag.startX) * sensitivity,
        y: drag.originY + (event.clientY - drag.startY) * sensitivity,
      };
      scheduleApply();
    }

    function stopDrag(event) {
      const drag = dragRef.current;
      if (!drag || (event && drag.pointerId !== event.pointerId)) return;
      dragRef.current = null;
      stage.classList.remove("dragging");
      if (event) stage.releasePointerCapture(event.pointerId);
    }

    stage.addEventListener("wheel", onWheel, { passive: false });
    stage.addEventListener("pointerdown", onPointerDown);
    stage.addEventListener("pointermove", onPointerMove);
    stage.addEventListener("pointerup", stopDrag);
    stage.addEventListener("pointercancel", stopDrag);

    return () => {
      stage.removeEventListener("wheel", onWheel);
      stage.removeEventListener("pointerdown", onPointerDown);
      stage.removeEventListener("pointermove", onPointerMove);
      stage.removeEventListener("pointerup", stopDrag);
      stage.removeEventListener("pointercancel", stopDrag);
      if (rafRef.current) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = 0;
      }
    };
  }, [graph, graphBounds]);

  // Stats for toolbar
  const typeCount = (type) => graph.nodes.filter((n) => n.type === type || n.kind === type).length;

  return (
    <div className="stack">
      <div className="graph-toolbar">
        <span className="chip alt">{graph.nodes.length} contracts</span>
        <span className="chip alt">{graph.edges.length} edges</span>
        {typeCount("proxy") > 0 && <span className="chip alt">{typeCount("proxy")} proxies</span>}
        {typeCount("factory") > 0 && <span className="chip alt">{typeCount("factory")} factories</span>}
        {typeCount("created") > 0 && <span className="chip alt">{typeCount("created")} created</span>}
        {typeCount("library") > 0 && <span className="chip alt">{typeCount("library")} libraries</span>}
      </div>
      <div className="graph-layout">
        <div className="graph-panel">
          <div className="graph-legend">
            <span className="chip alt">Left to right: target contract → dependencies (by call depth)</span>
            <span className="chip" style={{ background: "#ecfeff", borderColor: "#0f766e" }}>Target</span>
            <span className="chip" style={{ background: "#fff7ed", borderColor: "#d97706" }}>Proxy</span>
            <span className="chip" style={{ background: "#dcfce7", borderColor: "#16a34a" }}>Implementation</span>
            <span className="chip" style={{ background: "#eff6ff", borderColor: "#2563eb" }}>Library</span>
            <span className="chip" style={{ background: "#fff1f2", borderColor: "#e11d48" }}>Factory</span>
            <span className="chip" style={{ background: "#fdf2f8", borderColor: "#db2777" }}>Created</span>
            <span className="chip" style={{ background: "#f1f5f9", borderColor: "#64748b" }}>Regular</span>
          </div>
          <div ref={stageRef} className="graph-stage svg-stage">
            <svg ref={svgRef} className="graph-svg-root" viewBox={`0 0 ${graph.width} ${graph.height}`}>
              <defs>
                <marker id="dep-graph-arrow" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(34, 29, 23, 0.24)" />
                </marker>
              </defs>
              <g ref={viewportRef}>
                {edgeGeometry.map((edge, index) => {
                  const mx = (edge.startX + edge.endX) / 2;
                  const my = (edge.startY + edge.endY) / 2;
                  return (
                    <g key={`${edge.from.id}-${edge.to.id}-${index}`}>
                      <path
                        className="graph-edge"
                        d={edge.path}
                        markerEnd="url(#dep-graph-arrow)"
                      />
                      <text
                        x={mx} y={my - 6}
                        textAnchor="middle"
                        style={{ fontSize: 9, fontWeight: 700, fill: "#6b7280", pointerEvents: "none" }}
                      >
                        {edge.label}
                      </text>
                    </g>
                  );
                })}
                {graph.nodes.map((node) => (
                  <g
                    key={node.id}
                    className={`graph-svg-node dep-${node.kind} ${selectedNode?.id === node.id ? "selected" : ""}`}
                    transform={`translate(${node.x}, ${node.y})`}
                    onPointerDown={(e) => e.stopPropagation()}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode(node);
                    }}
                    style={{ cursor: "pointer" }}
                  >
                    <title>
                      {[node.title, node.subtitle, node.meta].filter(Boolean).join(" | ")}
                    </title>
                    {renderNodeBody(node)}
                  </g>
                ))}
              </g>
            </svg>
          </div>
        </div>
        <DependencyNodeDetails node={selectedNode} chainId={chainId} />
      </div>
    </div>
  );
}
