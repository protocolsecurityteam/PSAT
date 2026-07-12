import { useEffect, useMemo, useState } from "react";

import { formatDelay, formatUsd, principalBadge, shortAddr } from "../format.js";
import { machineFunctions, tabForLane } from "../lane.js";
import { LANE_META, MACHINE_TABS, ROLE_META } from "../meta.js";
import { BalanceTable } from "./BalanceTable.jsx";
import { GovernsTab } from "./GovernsTab.jsx";
import { LaneColumn } from "./LaneColumn.jsx";
import { OpsLane } from "./OpsLane.jsx";

export function ContractMachine({
  machine,
  onSelectGuard,
  onNavigate,
  companyName,
  highlightedFunctionKey,
  highlightedContract = false,
  onOpenDependencyGraph,
  governsIndex,
  principal = null,
}) {
  const [activeTab, setActiveTab] = useState("control");
  const usdLabel = formatUsd(machine.total_usd);
  const highlightedFunction = useMemo(
    () => machineFunctions(machine).find((fnView) => fnView.key === highlightedFunctionKey) || null,
    [machine, highlightedFunctionKey],
  );

  useEffect(() => {
    if (highlightedFunction) setActiveTab(tabForLane(highlightedFunction.lane));
  }, [highlightedFunction]);

  const governsRows = useMemo(
    () => governsIndex?.get((machine.address || "").toLowerCase()) || [],
    [governsIndex, machine.address],
  );
  // Capability tags for governed contracts, when this entity also has a
  // server-side principal facet (controls_detail carries the high-level
  // capability vocabulary; the client-side inversion has only effect labels).
  const capabilitiesByContract = useMemo(() => {
    const map = new Map();
    for (const detail of principal?.controls_detail || []) {
      const addr = (detail?.address || "").toLowerCase();
      const caps = Array.isArray(detail?.capabilities) ? detail.capabilities : [];
      if (addr && caps.length) map.set(addr, caps);
    }
    return map;
  }, [principal]);

  const tabCounts = {
    control: machine.lanes.top.length + machine.lanes.ops.length,
    inflows: machine.lanes.left.length,
    outflows: machine.lanes.right.length,
    balances: machine.balances?.length || 0,
    governs: governsRows.length,
  };

  const owners = Array.isArray(principal?.details?.owners) ? principal.details.owners : [];
  const threshold = principal?.details?.threshold;
  const delay = principal?.details?.delay;

  return (
    <article
      className={`ps-machine${highlightedContract ? " ps-machine-score-highlight" : ""}`}
      style={machine.total_usd ? { borderLeft: "2px solid #f59e0b33" } : undefined}
    >
      <header className="ps-machine-header">
        <div className="ps-machine-header-row">
          <div className="ps-machine-title-wrap">
            <div className="ps-machine-name">{machine.name || shortAddr(machine.address)}</div>
            <div className="ps-machine-address">{shortAddr(machine.address)}</div>
          </div>
        </div>
        <div className="ps-machine-badges">
          <span className="ps-badge" style={{ "--badge-accent": (ROLE_META[machine.role] || ROLE_META.utility).color }}>{(ROLE_META[machine.role] || ROLE_META.utility).label.replace(/s$/, "")}</span>
          {/* Deposit-destination call-out for value_handler contracts that
              actually hold funds. The role badge above is jargon — this one
              answers the user-facing question "where does my money go?"
              directly. Gated on total_usd>0 so we don't mislabel zero-TVL
              receivers (e.g. a router that pulls then forwards). */}
          {machine.role === "value_handler" && Number(machine.total_usd) > 0 ? (
            <span className="ps-badge" style={{ "--badge-accent": "#22c55e" }}>Deposit destination</span>
          ) : null}
          {machine.is_proxy ? <span className="ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{machine.proxy_type || "proxy"}</span> : null}
          {machine.upgrade_count != null ? <span className="ps-badge" style={{ "--badge-accent": "#8b92a8" }}>{machine.upgrade_count} upgrades</span> : null}
          <span className="ps-badge" style={{ "--badge-accent": "#6b7590" }}>{machine.totalFunctions} functions</span>
          {usdLabel && <span className="ps-badge" style={{ "--badge-accent": "#f59e0b" }}>{usdLabel}</span>}
        </div>
        {/* Dual-facet contracts (an analyzed timelock/safe the server also
            emits as a principal): fold the principal metadata PrincipalDetail
            showed into a compact strip. Everything else about it is covered by
            the Governs tab. */}
        {principal && (
          <div className="ps-machine-principal-strip">
            <span className="ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{principalBadge(principal)}</span>
            {principal.type === "safe" && threshold ? (
              <span className="ps-machine-principal-meta">{threshold}/{owners.length || "?"} signers</span>
            ) : null}
            {principal.type === "timelock" && delay > 0 ? (
              <span className="ps-machine-principal-meta">{formatDelay(delay)} delay</span>
            ) : null}
          </div>
        )}
        {onOpenDependencyGraph && (
          <div className="ps-machine-actions">
            <button
              type="button"
              className="ps-machine-header-action"
              onClick={() => onOpenDependencyGraph(machine)}
            >
              Dependency graph
            </button>
          </div>
        )}
      </header>

      <div className="ps-machine-tabs">
        {MACHINE_TABS.map((t) => (
          <button
            key={t.key}
            className={`ps-machine-tab${activeTab === t.key ? " active" : ""}`}
            onClick={() => setActiveTab(t.key)}
          >
            {t.label}
            {tabCounts[t.key] > 0 && <span className="ps-machine-tab-count">{tabCounts[t.key]}</span>}
          </button>
        ))}
        {tabCounts.governs > 0 && (
          <button
            className={`ps-machine-tab${activeTab === "governs" ? " active" : ""}`}
            onClick={() => setActiveTab("governs")}
          >
            Governs
            <span className="ps-machine-tab-count">{tabCounts.governs}</span>
          </button>
        )}
      </div>

      {activeTab === "control" && (
        <>
          <LaneColumn
            title={LANE_META.top.label}
            laneKey="top"
            items={machine.lanes.top}
            onSelect={onSelectGuard}
            onNavigate={onNavigate}
            highlightedFunctionKey={highlightedFunctionKey}
          />
          {machine.lanes.ops.length > 0 && (
            <OpsLane
              items={machine.lanes.ops}
              onSelect={onSelectGuard}
              onNavigate={onNavigate}
              highlightedFunctionKey={highlightedFunctionKey}
            />
          )}
        </>
      )}
      {activeTab === "inflows" && (
        <LaneColumn
          title={LANE_META.left.label}
          laneKey="left"
          items={machine.lanes.left}
          onSelect={onSelectGuard}
          onNavigate={onNavigate}
          highlightedFunctionKey={highlightedFunctionKey}
        />
      )}
      {activeTab === "outflows" && (
        <LaneColumn
          title={LANE_META.right.label}
          laneKey="right"
          items={machine.lanes.right}
          onSelect={onSelectGuard}
          onNavigate={onNavigate}
          highlightedFunctionKey={highlightedFunctionKey}
        />
      )}
      {activeTab === "balances" && (
        <BalanceTable machine={machine} />
      )}
      {activeTab === "governs" && (
        <GovernsTab
          rows={governsRows}
          capabilitiesByContract={capabilitiesByContract}
          onNavigate={onNavigate}
        />
      )}
    </article>
  );
}
