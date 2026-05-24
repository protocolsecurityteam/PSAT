import { useEffect, useMemo, useState } from "react";

import { formatUsd, shortAddr } from "../format.js";
import { machineFunctions, tabForLane } from "../lane.js";
import { LANE_META, MACHINE_TABS, ROLE_META } from "../meta.js";
import { BalanceTable } from "./BalanceTable.jsx";
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

  const tabCounts = {
    control: machine.lanes.top.length + machine.lanes.ops.length,
    inflows: machine.lanes.left.length,
    outflows: machine.lanes.right.length,
    balances: machine.balances?.length || 0,
  };

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

      {machine.other_callers && machine.other_callers.length > 0 && (
        <div className="ps-machine-callers">
          <div className="ps-machine-callers-label">
            Other authorized callers ({machine.other_callers.length})
          </div>
          <div className="ps-machine-callers-list">
            {machine.other_callers.map((c) => (
              <button
                key={c.address}
                type="button"
                className="ps-machine-caller"
                title={`${c.address}${
                  c.functions && c.functions.length ? ` — ${c.functions.join(", ")}` : ""
                }`}
                onClick={() => onNavigate({ type: c.type || "eoa", address: c.address, label: c.label })}
              >
                <span className="ps-machine-caller-head">
                  <span className="ps-machine-caller-type">{c.type || "eoa"}</span>
                  {c.label && c.label !== c.type ? c.label : shortAddr(c.address)}
                </span>
                {(c.capabilities?.length || c.functions?.length) ? (
                  <span className="ps-machine-caller-caps">
                    {c.capabilities && c.capabilities.length
                      ? c.capabilities.join(", ")
                      : c.functions.slice(0, 3).join(", ") +
                        (c.functions.length > 3 ? ` +${c.functions.length - 3}` : "")}
                  </span>
                ) : null}
              </button>
            ))}
          </div>
        </div>
      )}

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
    </article>
  );
}
