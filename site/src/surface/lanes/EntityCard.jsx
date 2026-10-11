import { useEffect, useMemo, useState } from "react";

import { chainColor, chainLabel } from "../chainMeta.js";
import { formatDelay, formatUsd, principalLabel, shortAddr } from "../format.js";
import { controllerEnumerationNote } from "../../vocab/principalNotes.js";
import { machineFunctions, tabForLane } from "../lane.js";
import { LANE_META, MACHINE_TABS, ROLE_META, TYPE_META } from "../meta.js";
import { dedupeAndTagRows } from "../layout/governancePath.js";
import { BalanceTable } from "./BalanceTable.jsx";
import { DependsOnTab } from "./DependsOnTab.jsx";
import { GovernsTab } from "./GovernsTab.jsx";
import { LaneColumn } from "./LaneColumn.jsx";
import { ReachPath } from "./ReachPath.jsx";
import { OpsLane } from "./OpsLane.jsx";

// One card for every selection: a machine facet gives the five-tab contract
// card; a principal-only entity collapses to Governs; dual-facet entities fold
// the principal into the contract card's header.
export function EntityCard({
  machine = null,
  principal = null,
  onSelectGuard,
  onNavigate,
  onPreview,
  highlightedFunctionKey,
  highlightedCaller = null,
  governsIndex,
  reachDistances = null,
  reachFrontierCount = 0,
  reachPath = null,
  machines = [],
  chain = "ethereum",
  showChain = false,
}) {
  const isMachine = Boolean(machine);
  const address = (machine?.address || principal?.address || "").toLowerCase();
  // Principals carry no chain. Shown only on multichain protocols.
  const entityChain = machine?.chain || chain;

  const machineByAddr = useMemo(() => {
    const map = new Map();
    for (const m of machines) {
      const addr = (m.address || "").toLowerCase();
      if (addr && !map.has(addr)) map.set(addr, m);
    }
    return map;
  }, [machines]);

  // Client-inverted so machine-only authorities work too.
  const canCallRows = useMemo(() => {
    const rows = (governsIndex?.get(address) || []).map((row) => {
      const m = machineByAddr.get(row.contractAddress);
      return {
        address: row.contractAddress,
        name: row.contractName,
        is_proxy: Boolean(m?.is_proxy),
        total_usd: m?.total_usd || 0,
        functions: row.functions,
      };
    });
    return dedupeAndTagRows(rows);
  }, [governsIndex, address, machineByAddr]);

  // The server's reached set, same as the canvas chips; no record means no
  // rows. The not_determined frontier is only the count line.
  const pathRows = useMemo(() => {
    const rows = [];
    for (const addr of reachDistances ? reachDistances.keys() : []) {
      const m = machineByAddr.get(addr);
      if (!m) continue;
      rows.push({ address: m.address, name: m.name, is_proxy: Boolean(m.is_proxy), total_usd: m.total_usd || 0 });
    }
    return dedupeAndTagRows(rows);
  }, [reachDistances, machineByAddr]);

  const highlightedFunction = useMemo(
    () => (isMachine ? machineFunctions(machine).find((fnView) => fnView.key === highlightedFunctionKey) || null : null),
    [isMachine, machine, highlightedFunctionKey],
  );

  const [activeTab, setActiveTab] = useState(() => (isMachine ? "control" : "governs"));

  useEffect(() => {
    if (highlightedFunction) setActiveTab(tabForLane(highlightedFunction.lane));
  }, [highlightedFunction]);

  const owners = Array.isArray(principal?.details?.owners) ? principal.details.owners : [];
  const threshold = principal?.details?.threshold;
  const delay = principal?.details?.delay;
  const principalType = principal ? TYPE_META[principal.type] || TYPE_META.unknown : null;

  const name = machine?.name || (principal ? principalLabel(principal.label, principal.type, principal.address) : shortAddr(address));
  const fullAddress = machine?.address || principal?.address || address;

  const usdLabel = isMachine ? formatUsd(machine.total_usd) : null;
  const enumerationNote = controllerEnumerationNote(machine) || controllerEnumerationNote(principal);

  const tabCounts = isMachine
    ? {
        control: machine.lanes.top.length + machine.lanes.ops.length,
        inflows: machine.lanes.left.length,
        outflows: machine.lanes.right.length,
        // Counts holdings: a withheld balance is listed but not counted. Uses
        // the backend's `disposition_state`; re-deriving the conjunction would
        // carry half of it.
        balances: (machine.balances || []).length,
        governs: canCallRows.length,
      }
    : { governs: canCallRows.length };

  const accent = isMachine
    ? (machine.total_usd ? "#f59e0b33" : null)
    : principalType.accent;

  return (
    <article
      className="ps-machine"
      style={accent ? { borderLeft: `2px solid ${accent}` } : undefined}
    >
      <header className="ps-machine-header">
        <div className="ps-machine-header-row">
          <div className="ps-machine-title-wrap">
            <div className="ps-machine-name">{name}</div>
            <div className="ps-machine-address">{fullAddress}</div>
          </div>
        </div>
        <div className="ps-machine-badges">
          {showChain && (
            <span className="tag tag-md ps-badge ps-badge-chain" style={{ "--badge-accent": chainColor(entityChain), "--chain-color": chainColor(entityChain) }}>
              <span className="ps-chain-dot" />
              {chainLabel(entityChain)}
            </span>
          )}
          {isMachine && (
            <>
              <span className="tag tag-md ps-badge" style={{ "--badge-accent": (ROLE_META[machine.role] || ROLE_META.utility).color }}>{(ROLE_META[machine.role] || ROLE_META.utility).singular}</span>
              {/*
                Gated on total_usd>0 so a pull-then-forward router isn't
                mislabeled.
              */}
              {machine.role === "value_handler" && Number(machine.total_usd) > 0 ? (
                <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#22c55e" }}>Deposit destination</span>
              ) : null}
              {machine.is_proxy ? <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{machine.proxy_type || "proxy"}</span> : null}
              {machine.upgrade_count != null ? <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#8b92a8" }}>{machine.upgrade_count} upgrades</span> : null}
              <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#6b7590" }}>{machine.totalFunctions} functions</span>
              {usdLabel && <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#f59e0b" }}>{usdLabel}</span>}
              {/*
                Machine-only timelocks (EtherFiTimelock) have no principal
                entry; skipped when the principal badge renders, to avoid
                double-badging.
              */}
              {machine.isTimelock && principal?.type !== "timelock" ? (
                <>
                  <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>Timelock</span>
                  {machine.timelockDelay > 0 ? (
                    <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{formatDelay(machine.timelockDelay)} delay</span>
                  ) : null}
                </>
              ) : null}
            </>
          )}
          {enumerationNote && (
            <span
              className="tag tag-md ps-badge ps-badge-not-determined"
              style={{ "--badge-accent": "#b45309" }}
              title={enumerationNote.statuses.map((s) => s.word).join("; ")}
            >
              Controllers not determined
            </span>
          )}
          {principal && (
            <>
              <span className="tag tag-md ps-badge" style={{ "--badge-accent": principalType.accent }}>{principalType.label}</span>
              {principal.type === "safe" && threshold ? (
                <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#6a9e94" }}>{threshold}/{owners.length} threshold</span>
              ) : null}
              {principal.type === "timelock" && delay > 0 ? (
                <span className="tag tag-md ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{formatDelay(delay)} delay</span>
              ) : null}
            </>
          )}
        </div>
      </header>

      {/* Above the tabs: the route is why this card is open. */}
      <ReachPath reachPath={reachPath} />

      {principal?.type === "safe" && owners.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr">Signers ({owners.length})</div>
          {owners.map((addr) => (
            <div key={addr} className="ps-principal-signer">{addr}</div>
          ))}
        </section>
      )}

      <div className="ps-machine-tabs">
        {isMachine &&
          MACHINE_TABS.map((t) => (
            <button
              key={t.key}
              className={`ps-machine-tab${activeTab === t.key ? " active" : ""}`}
              onClick={() => setActiveTab(t.key)}
            >
              {t.label}
              {tabCounts[t.key] > 0 && <span className="ps-machine-tab-count">{tabCounts[t.key]}</span>}
            </button>
          ))}
        <button
          className={`ps-machine-tab${activeTab === "governs" ? " active" : ""}`}
          onClick={() => setActiveTab("governs")}
        >
          Governs
          {tabCounts.governs > 0 && <span className="ps-machine-tab-count">{tabCounts.governs}</span>}
        </button>
        {isMachine && (
          <button
            className={`ps-machine-tab${activeTab === "depends" ? " active" : ""}`}
            onClick={() => setActiveTab("depends")}
          >
            Depends
          </button>
        )}
      </div>

      {isMachine && activeTab === "control" && (
        <>
          <LaneColumn
            title={LANE_META.top.label}
            laneKey="top"
            items={machine.lanes.top}
            onSelect={onSelectGuard}
            onNavigate={onNavigate}
            onPreview={onPreview}
            highlightedFunctionKey={highlightedFunctionKey}
            highlightedCaller={highlightedCaller}
          />
          {machine.lanes.ops.length > 0 && (
            <OpsLane
              items={machine.lanes.ops}
              onSelect={onSelectGuard}
              onNavigate={onNavigate}
              onPreview={onPreview}
              highlightedFunctionKey={highlightedFunctionKey}
              highlightedCaller={highlightedCaller}
            />
          )}
        </>
      )}
      {isMachine && activeTab === "inflows" && (
        <LaneColumn
          title={LANE_META.left.label}
          laneKey="left"
          items={machine.lanes.left}
          onSelect={onSelectGuard}
          onNavigate={onNavigate}
          onPreview={onPreview}
          highlightedFunctionKey={highlightedFunctionKey}
          highlightedCaller={highlightedCaller}
        />
      )}
      {isMachine && activeTab === "outflows" && (
        <LaneColumn
          title={LANE_META.right.label}
          laneKey="right"
          items={machine.lanes.right}
          onSelect={onSelectGuard}
          onNavigate={onNavigate}
          onPreview={onPreview}
          highlightedFunctionKey={highlightedFunctionKey}
          highlightedCaller={highlightedCaller}
        />
      )}
      {isMachine && activeTab === "balances" && <BalanceTable machine={machine} />}
      {activeTab === "governs" && (
        <GovernsTab
          canCallRows={canCallRows}
          pathRows={pathRows}
          frontierCount={reachFrontierCount}
          onPreview={onPreview}
          onNavigate={onNavigate}
        />
      )}
      {isMachine && activeTab === "depends" && (
        <DependsOnTab
          machine={machine}
          machines={machines}
          onPreview={onPreview}
          onNavigate={onNavigate}
        />
      )}
    </article>
  );
}
