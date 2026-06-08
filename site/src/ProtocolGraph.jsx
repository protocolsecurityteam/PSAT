/**
 * ProtocolGraph — nested containment layout.
 * Ownership = visual nesting. Gating = inline role pills on functions.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

// ── Helpers ──────────────────────────────────────────────────────────────────

function shortAddr(addr) {
  if (!addr || addr.length < 12) return addr || "";
  return addr.slice(0, 6) + ".." + addr.slice(-4);
}

const ROLE_COLORS = {
  PROPOSER: "#00D4AA", EXECUTOR: "#6366F1", CANCELLER: "#FF6B35",
  ADMIN: "#6366F1", ORACLE: "#00D4AA", PAUSER: "#F59E0B", UPGRADER: "#EC4899",
};

function roleColor(role) {
  if (!role) return "#777";
  const upper = role.toUpperCase();
  for (const [key, color] of Object.entries(ROLE_COLORS)) {
    if (upper.includes(key)) return color;
  }
  return "#777";
}

function Pill({ label, color }) {
  return (
    <span style={{
      padding: "1px 6px", borderRadius: 6, background: color + "18",
      color, fontSize: 8, fontWeight: 600, fontFamily: "JetBrains Mono, monospace", whiteSpace: "nowrap",
    }}>{label}</span>
  );
}

// ── Zone node (Safe / Timelock containers) ───────────────────────────────────

function ZoneNode({ data }) {
  const [queueOpen, setQueueOpen] = useState(false);
  const queueItems = data.queueItems || [];
  const color = data.color || "#FF6B35";

  return (
    <div className="rf-zone" style={{ borderColor: color + "44", minWidth: data.width, minHeight: data.height }}>
      <div className="rf-zone-header">
        <div className="rf-zone-header-left">
          <span className="rf-zone-tag" style={{ color }}>{data.tag}</span>
          <span className="rf-zone-name">{data.label}</span>
          <span className="rf-zone-addr">{shortAddr(data.address)}</span>
        </div>
        {queueItems.length > 0 && (
          <button className="rf-queue-badge" style={{ background: color }} onClick={() => setQueueOpen(!queueOpen)}>
            {queueItems.length}
          </button>
        )}
      </div>

      {/* Metadata rows */}
      {data.meta?.map((m, i) => (
        <div key={i} className="rf-zone-meta" style={{ background: m.color + "12" }}>
          <span style={{ color: m.color, fontWeight: 600, fontSize: 9 }}>{m.label}</span>
          <span style={{ color: m.color + "88", fontSize: 9 }}>{m.value}</span>
        </div>
      ))}

      {/* Roles */}
      {data.roles?.length > 0 && (
        <div className="rf-zone-roles">
          {data.roles.map((r, i) => (
            <div key={i} className="rf-zone-role" style={{ background: roleColor(r.name) + "12" }}>
              <span style={{ color: roleColor(r.name), fontWeight: 600 }}>{r.name}</span>
              <span style={{ color: roleColor(r.name) + "88" }}>→ {r.holder}</span>
            </div>
          ))}
        </div>
      )}

      {/* Queue panel */}
      {queueOpen && (
        <div className="rf-zone-queue">
          <div className="rf-zone-queue-hdr" style={{ color }}>Pending {data.queueLabel || "Queue"}</div>
          {queueItems.map((item, i) => (
            <div key={i} className="rf-zone-queue-block" style={{ borderLeftColor: color }}>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                <span className="rf-fn-name">{item.function}</span>
                {item.target && <span className="rf-fn-mutation">→ {item.target}</span>}
                {item.eta && <Pill label={`ETA ${item.eta}`} color={color} />}
              </div>
              {item.description && <div className="rf-fn-mutation">{item.description}</div>}
              {item.pills?.length > 0 && <div className="rf-pills">{item.pills.map((p, pi) => <Pill key={pi} label={p.label} color={p.color || "#777"} />)}</div>}
              {item.signers && (
                <div className="rf-pills">
                  {item.signers.map((s, si) => (
                    <Pill key={si} label={`${s.name} ${s.confirmed ? "✓" : "pending"}`} color={s.confirmed ? "#00D4AA" : "#777"} />
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Contract card node ───────────────────────────────────────────────────────

function ContractNode({ data }) {
  const borderColor = data.isProxy ? "#FF6B35" : "#00D4AA";
  return (
    <div className="rf-contract-card" style={{ borderColor }}>
      <div className="rf-contract-top">
        <div>
          <div className="rf-contract-name">{data.label}</div>
          <div className="rf-contract-addr">
            {shortAddr(data.address)}
            {data.implementation && <> → {shortAddr(data.implementation)}</>}
          </div>
        </div>
        <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
          {data.isProxy && <Pill label={`eip1967`} color="#FF6B35" />}
          {data.upgradeCount != null && <Pill label={`${data.upgradeCount} upgrades`} color="#FF6B35" />}
          <Pill label={data.riskLevel || "unknown"} color={data.riskLevel === "high" ? "#FF6B35" : data.riskLevel === "medium" ? "#F59E0B" : "#00D4AA"} />
        </div>
      </div>

      {/* Function groups */}
      {data.functionGroups?.map((group, gi) => (
        <div key={gi} className="rf-fn-group">
          <div className="rf-fn-group-hdr" style={{ background: group.color + "12", borderLeftColor: group.color }}>
            <span style={{ color: group.color }}>{group.label}</span>
          </div>
          {group.functions.map((fn, fi) => (
            <div key={fi} className="rf-fn-row">
              <span className="rf-fn-dot" style={{ background: fn.dotColor || group.color }} />
              <span className="rf-fn-name">{fn.name}</span>
              {fn.role && <Pill label={fn.role} color={roleColor(fn.role)} />}
              {fn.effects?.map((e, ei) => <Pill key={ei} label={e} color={e.includes("impl") ? "#EC4899" : e.includes("owner") ? "#FF6B35" : "#777"} />)}
              {fn.mutation && <span className="rf-fn-mutation">{fn.mutation}</span>}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

// ── Role legend (sits inside the Timelock zone) ──────────────────────────────

function RoleLegendNode({ data }) {
  return (
    <div className="rf-role-legend">
      <div className="rf-role-legend-hdr">
        <span style={{ color: "#6366F1", fontWeight: 600 }}>RoleRegistry</span>
        <span className="rf-contract-addr">{shortAddr(data.address)}</span>
        {!data.scanned && <Pill label="not yet scanned" color="#777" />}
      </div>
      {data.roles?.map((r, i) => (
        <div key={i} className="rf-zone-role" style={{ background: roleColor(r.name) + "12" }}>
          <span style={{ color: roleColor(r.name), fontWeight: 600 }}>{r.name}</span>
          <span style={{ color: roleColor(r.name) + "88" }}>→ {r.holder}</span>
        </div>
      ))}
    </div>
  );
}

// ── Node types ───────────────────────────────────────────────────────────────

const nodeTypes = {
  zone: ZoneNode,
  contract: ContractNode,
  roleLegend: RoleLegendNode,
};

// ── Build function groups from effective_permissions ─────────────────────────

function buildFunctionGroups(functions) {
  if (!functions?.length) return [];
  const ownerFns = [], registryFns = [], otherFns = [];

  for (const fn of functions) {
    const name = fn.function?.replace(/\(.*/, "()") || "?";
    const owner = fn.direct_owner;
    const controllers = fn.controllers || [];
    const effects = fn.effect_labels || [];
    const action = fn.action_summary || "";
    const hasOwner = !!owner;
    const hasRegistry = controllers.some((c) => c.label === "roleRegistry");

    let role = null;
    if (hasRegistry) {
      if (name.includes("pause") || name.includes("Pause")) role = "PAUSER";
      else if (name.includes("upgrade")) role = "UPGRADER";
      else if (name.includes("execute") || name.includes("Oracle") || name.includes("Validator")) role = "ORACLE_EXEC";
      else role = "ADMIN";
    }

    let mutation = "";
    if (action.startsWith("Writes or calls into:")) mutation = action.replace("Writes or calls into:", "writes").trim();
    else if (action.startsWith("Transfers")) mutation = action.toLowerCase();
    else if (action.startsWith("Changes")) mutation = action.toLowerCase();
    else if (action.startsWith("Calls an external")) mutation = "external contract call";
    else if (action.startsWith("Sends assets")) mutation = "sends assets out";

    const entry = {
      name, role,
      effects: effects.filter((e) => e !== "external_contract_call").slice(0, 2),
      mutation,
      dotColor: role ? roleColor(role) : hasOwner ? "#FF6B35" : "#777",
    };

    if (hasRegistry) registryFns.push(entry);
    else if (hasOwner) ownerFns.push(entry);
    else otherFns.push(entry);
  }

  const groups = [];
  if (ownerFns.length) groups.push({ label: `owner-gated · ${ownerFns.length} fns`, color: "#FF6B35", functions: ownerFns });
  if (registryFns.length) groups.push({ label: `roleRegistry-gated · ${registryFns.length} fns`, color: "#6366F1", functions: registryFns });
  if (otherFns.length) groups.push({ label: `other · ${otherFns.length} fns`, color: "#777", functions: otherFns });
  return groups;
}

// ── Build graph ──────────────────────────────────────────────────────────────

function buildGraph(companyData, functionData) {
  const nodes = [];
  const edges = [];
  const { contracts } = companyData;
  const timelockAddr = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761";
  const registryAddr = "0x62247d29b4b9becf4bb73e0c722cf6445cfc7ce9";

  const timelockOwned = contracts.filter((c) => c.owner?.toLowerCase() === timelockAddr);
  const eoaOwned = contracts.filter((c) => c.owner && c.owner.toLowerCase() !== timelockAddr && !c.name?.toLowerCase().includes("timelock"));

  // Figure out how many contracts to lay out for sizing
  const tlContracts = timelockOwned.filter((c) => c.address?.toLowerCase() !== timelockAddr);
  const cardW = 520;
  const cardGap = 16;
  const innerW = cardW + 340; // card + role legend side by side

  // Placeholder sizes — will be updated after card layout
  let tlZoneH = 400;
  let safeZoneH = 600;

  // ── Safe zone (outermost) ──
  nodes.push({
    id: "safe-zone",
    type: "zone",
    draggable: false,
    position: { x: 0, y: 0 },
    style: { width: innerW + 120, height: safeZoneH },
    data: {
      tag: "[GNOSIS SAFE] 3/5 threshold",
      label: "EtherFi Protocol Safe",
      address: "0x1a2b3c4d5e6f7890abcdef1234567890abcd1234",
      color: "#00D4AA",
      width: innerW + 120,
      height: safeZoneH,
      meta: [
        { label: "signers", value: "Mike S. · Rok M. · Shivam B. · +2", color: "#00D4AA" },
      ],
      roles: [
        { name: "PROPOSER", holder: "this safe" },
        { name: "EXECUTOR", holder: "this safe" },
        { name: "CANCELLER", holder: "this safe" },
      ],
      queueLabel: "Safe Txs",
      queueItems: [
        {
          function: "schedule(upgradeTo, EtherFiAdmin, 0x4f2a..)",
          description: "once signed → schedules timelock op → 3d delay → new impl goes live",
          pills: [{ label: "2/3 confirmed", color: "#00D4AA" }],
          signers: [
            { name: "Mike S.", confirmed: true },
            { name: "Rok M.", confirmed: true },
            { name: "Shivam B.", confirmed: false },
          ],
        },
      ],
    },
  });

  // ── Timelock zone (nested inside Safe) ──
  nodes.push({
    id: "timelock-zone",
    type: "zone",
    draggable: false,
    position: { x: 30, y: 180 },
    parentId: "safe-zone",
    extent: "parent",
    style: { width: innerW + 60, height: tlZoneH },
    data: {
      tag: "[TIMELOCK] 3-day delay",
      label: "EtherFiTimelock",
      address: timelockAddr,
      color: "#FF6B35",
      width: innerW + 60,
      height: tlZoneH,
      meta: [
        { label: `owns ${tlContracts.length} contracts`, value: "shown below", color: "#FF6B35" },
      ],
      roles: [
        { name: "PROPOSER", holder: "Safe 0x1a2b.." },
        { name: "EXECUTOR", holder: "Safe 0x1a2b.." },
        { name: "CANCELLER", holder: "Safe 0x1a2b.." },
      ],
      queueLabel: "Timelock Ops",
      queueItems: [
        {
          function: "upgradeTo(0x4f2a..e891)",
          target: "EtherFiAdmin",
          eta: "14h 23m",
          description: "new impl changes executeTasks() oracle validation · adds slashing penalty caps",
          pills: [{ label: "UPGRADER", color: "#EC4899" }, { label: "block 21,847,231", color: "#777" }],
        },
        {
          function: "updateAcceptableRebaseApr(450)",
          target: "EtherFiAdmin",
          eta: "2d 6h",
          description: "raises max rebase APR 3.00% → 4.50% for post-Pectra yield",
          pills: [{ label: "config_change", color: "#00D4AA" }, { label: "ORACLE_EXECUTOR", color: "#00D4AA" }],
        },
      ],
    },
  });

  // ── RoleLegend (inside Timelock zone) ──
  nodes.push({
    id: "role-legend",
    type: "roleLegend",
    draggable: false,
    position: { x: 30, y: 220 },
    parentId: "timelock-zone",
    extent: "parent",
    data: {
      address: registryAddr,
      scanned: false,
      roles: [
        { name: "ADMIN_ROLE", holder: "Safe 0x1a2b.." },
        { name: "ORACLE_EXECUTOR", holder: "0x7f89..3a01" },
        { name: "PAUSER_ROLE", holder: "Safe 0x1a2b.." },
        { name: "UPGRADER_ROLE", holder: "Timelock 0x9f26.." },
      ],
    },
  });

  // ── Contract cards (inside Timelock zone) ──
  const sorted = [...tlContracts].sort((a, b) => {
    const aFns = functionData[a.address]?.length || 0;
    const bFns = functionData[b.address]?.length || 0;
    return bFns - aFns;
  });

  // Layout: single column, stacked vertically
  let cardY = 220; // start after role legend
  const cardX = 300;

  for (const contract of sorted) {
    const addr = contract.address;
    const fns = functionData[addr] || [];
    const functionGroups = buildFunctionGroups(fns);
    const hasRegistry = Object.values(contract.controllers || {}).some(
      (v) => typeof v === "string" && v.toLowerCase() === registryAddr
    );

    const nodeId = `contract-${addr}`;
    nodes.push({
      id: nodeId,
      type: "contract",
      draggable: false,
      position: { x: cardX, y: cardY },
      parentId: "timelock-zone",
      extent: "parent",
      data: {
        label: contract.name,
        address: addr,
        isProxy: contract.is_proxy,
        upgradeCount: contract.upgrade_count,
        riskLevel: contract.risk_level,
        implementation: contract.implementation,
        hasRoleRegistry: hasRegistry,
        functionGroups,
      },
    });

    // Conservative height estimate: base + per-function + per-group header
    const estH = 90 + fns.length * 22 + functionGroups.length * 32;
    cardY += estH + cardGap;
  }

  // ── Update zone sizes to fit content ──
  tlZoneH = cardY + 40;
  safeZoneH = tlZoneH + 220;

  // Update the zone nodes with correct sizes
  const safeNode = nodes.find((n) => n.id === "safe-zone");
  if (safeNode) {
    safeNode.style.height = safeZoneH;
    safeNode.data.height = safeZoneH;
  }
  const tlNode = nodes.find((n) => n.id === "timelock-zone");
  if (tlNode) {
    tlNode.style.height = tlZoneH;
    tlNode.data.height = tlZoneH;
  }

  // ── EOA zone (separate, next to Safe zone) ──
  if (eoaOwned.length > 0) {
    const eoaAddr = eoaOwned[0]?.owner || "";
    nodes.push({
      id: "eoa-zone",
      type: "zone",
      draggable: false,
      position: { x: innerW + 180, y: 0 },
      style: { width: 400, height: 140 + eoaOwned.slice(0, 8).length * 55 },
      data: {
        tag: "[EOA] owner",
        label: "Token Admin",
        address: eoaAddr,
        color: "#00D4AA",
        width: 400,
        height: 140 + eoaOwned.slice(0, 8).length * 55,
        meta: [{ label: `owns ${eoaOwned.length} contracts`, value: "token distributions", color: "#00D4AA" }],
      },
    });

    let eoaY = 120;
    for (const contract of eoaOwned.slice(0, 8)) {
      nodes.push({
        id: `eoa-contract-${contract.address}`,
        type: "contract",
        draggable: false,
        position: { x: 20, y: eoaY },
        parentId: "eoa-zone",
        extent: "parent",
        data: {
          label: contract.name,
          address: contract.address,
          isProxy: contract.is_proxy,
          upgradeCount: contract.upgrade_count,
          riskLevel: contract.risk_level,
          functionGroups: [],
        },
      });
      eoaY += 50;
    }
  }

  return { nodes, edges };
}

// ── Main component ───────────────────────────────────────────────────────────

export default function ProtocolGraph({ companyName }) {
  const [companyData, setCompanyData] = useState(null);
  const [functionData, setFunctionData] = useState({});
  const [error, setError] = useState(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (!companyName) return;
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch(`/api/company/${encodeURIComponent(companyName)}`);
        if (!res.ok) throw new Error("Failed to load");
        const data = await res.json();
        if (cancelled) return;
        setCompanyData(data);

        const fnData = {};
        for (const contract of data.contracts) {
          if (!contract.analysis_job_id) continue;
          try {
            const lookupId = contract.implementation_analysis_job_id || contract.analysis_job_id;
            const fnRes = await fetch(`/api/analyses/${lookupId}/artifact/effective_permissions`);
            if (fnRes.ok) {
              const perms = await fnRes.json();
              fnData[contract.address] = perms.functions || [];
            }
          } catch {}
        }
        if (cancelled) return;
        setFunctionData(fnData);
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [companyName]);

  useEffect(() => {
    if (!companyData) return;
    const { nodes: n, edges: e } = buildGraph(companyData, functionData);
    setNodes(n);
    setEdges(e);
  }, [companyData, functionData]);

  if (error) return <p className="empty">Failed to load: {error}</p>;
  if (!companyData) return <p className="empty">Loading protocol graph...</p>;

  return (
    <ReactFlowProvider>
      <GraphInner nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} />
    </ReactFlowProvider>
  );
}

function GraphInner({ nodes: rawNodes, edges, onNodesChange, onEdgesChange }) {
  const { setViewport, getViewport, getNodes } = useReactFlow();
  const containerRef = useRef(null);
  const layoutDoneRef = useRef(false);
  const [layoutedNodes, setLayoutedNodes] = useState(rawNodes);

  useEffect(() => {
    layoutDoneRef.current = false;
    setLayoutedNodes(rawNodes);
  }, [rawNodes]);

  // Post-render: measure actual DOM heights, reflow children within each parent
  const onNodesChangeWrapped = useCallback((changes) => {
    onNodesChange(changes);
    if (layoutDoneRef.current) return;

    const current = getNodes();
    const measured = current.filter((n) => n.measured?.height > 0);
    if (measured.length < current.length || measured.length < 3) return;

    layoutDoneRef.current = true;
    const GAP = 16;

    // Group children by parentId
    const childrenByParent = {};
    for (const node of measured) {
      const pid = node.parentId || "__root__";
      if (!childrenByParent[pid]) childrenByParent[pid] = [];
      childrenByParent[pid].push(node);
    }

    const updates = [];
    for (const [pid, children] of Object.entries(childrenByParent)) {
      if (pid === "__root__") continue;
      // Sort children by y position
      children.sort((a, b) => a.position.y - b.position.y);
      let nextY = children[0].position.y;
      for (const child of children) {
        if (child.position.y < nextY) {
          updates.push({ id: child.id, y: nextY });
        } else {
          nextY = child.position.y;
        }
        nextY = nextY + (child.measured?.height || 100) + GAP;
      }

      // Resize the parent to fit
      const parentNode = measured.find((n) => n.id === pid);
      if (parentNode) {
        const newH = nextY + 30;
        if (newH > (parentNode.measured?.height || 0)) {
          updates.push({ id: pid, height: newH });
        }
      }
    }

    if (updates.length > 0) {
      setLayoutedNodes((prev) =>
        prev.map((n) => {
          const upd = updates.find((u) => u.id === n.id);
          if (!upd) return n;
          const result = { ...n };
          if (upd.y != null) result.position = { ...n.position, y: upd.y };
          if (upd.height != null) {
            result.style = { ...n.style, height: upd.height };
            if (result.data) result.data = { ...result.data, height: upd.height };
          }
          return result;
        })
      );
    }
  }, [onNodesChange, getNodes]);

  // Fast zoom
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    function handleWheel(e) {
      e.preventDefault();
      const { x, y, zoom } = getViewport();
      const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
      const newZoom = Math.min(4, Math.max(0.05, zoom * factor));
      const rect = el.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      setViewport({ x: mx - (mx - x) * (newZoom / zoom), y: my - (my - y) * (newZoom / zoom), zoom: newZoom }, { duration: 0 });
    }
    el.addEventListener("wheel", handleWheel, { passive: false });
    return () => el.removeEventListener("wheel", handleWheel);
  }, [getViewport, setViewport]);

  return (
    <div ref={containerRef} style={{ width: "100%", height: "100%" }}>
      <ReactFlow
        nodes={layoutedNodes}
        edges={edges}
        onNodesChange={onNodesChangeWrapped}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.05}
        maxZoom={4}
        zoomOnScroll={false}
        panOnScroll={false}
        defaultEdgeOptions={{ type: "smoothstep" }}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#2D2D2D" gap={40} size={1} />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(n) => {
            if (n.id === "safe-zone") return "#00D4AA";
            if (n.id === "timelock-zone") return "#FF6B35";
            if (n.id === "eoa-zone") return "#00D4AA";
            if (n.id === "role-legend") return "#6366F1";
            return "#FF6B35";
          }}
          style={{ background: "#1A1A1A" }}
        />
      </ReactFlow>
    </div>
  );
}
