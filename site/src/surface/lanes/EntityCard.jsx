import { useEffect, useMemo, useState } from "react";

import { formatDelay, formatUsd, principalLabel, shortAddr } from "../format.js";
import { machineFunctions, tabForLane } from "../lane.js";
import { LANE_META, MACHINE_TABS, ROLE_META, TYPE_META } from "../meta.js";
import { dedupeAndTagRows, governancePathTargets } from "../layout/governancePath.js";
import { BalanceTable } from "./BalanceTable.jsx";
import { GovernsTab } from "./GovernsTab.jsx";
import { LaneColumn } from "./LaneColumn.jsx";
import { OpsLane } from "./OpsLane.jsx";

// The one card for every surface selection. A `machine` facet (function lanes)
// yields the full five-tab contract card; a `principal` facet (safe/EOA/
// timelock) contributes identity badges, a signers list, and — for a
// principal-only entity — collapses the card to the Governs tab alone. A
// timelock/safe the server emits as BOTH renders the contract card with the
// principal facet folded into its header + capability tags.
export function EntityCard({
  machine = null,
  principal = null,
  onSelectGuard,
  onNavigate,
  onFocusContract,
  highlightedFunctionKey,
  highlightedContract = false,
  onOpenDependencyGraph,
  governsIndex,
  controlAdjacency,
  machines = [],
  initialTab = null,
}) {
  const isMachine = Boolean(machine);
  const address = (machine?.address || principal?.address || "").toLowerCase();

  const machineByAddr = useMemo(() => {
    const map = new Map();
    for (const m of machines) {
      const addr = (m.address || "").toLowerCase();
      if (addr && !map.has(addr)) map.set(addr, m);
    }
    return map;
  }, [machines]);

  // Can Call rows (authority OUT): client-inverted governed set, deduped and
  // proxy/impl-tagged. Works for machine-only authorities (not just principals).
  const canCallRows = useMemo(() => {
    const rows = (governsIndex?.get(address) || []).map((row) => ({
      address: row.contractAddress,
      name: row.contractName,
      is_proxy: Boolean(machineByAddr.get(row.contractAddress)?.is_proxy),
      functions: row.functions,
    }));
    return dedupeAndTagRows(rows);
  }, [governsIndex, address, machineByAddr]);

  // Governance-path rows: server reachability for a principal facet, else the
  // client-side transitive control walk for a machine-only authority. Filtered
  // to known machines (so we can name + focus them), deduped, proxy/impl-tagged.
  const pathRows = useMemo(() => {
    const source = principal?.controls?.length
      ? principal.controls
      : governancePathTargets(address, controlAdjacency);
    const rows = [];
    for (const addr of source) {
      const m = machineByAddr.get(String(addr).toLowerCase());
      if (!m) continue;
      rows.push({ address: m.address, name: m.name, is_proxy: Boolean(m.is_proxy), total_usd: m.total_usd || 0 });
    }
    return dedupeAndTagRows(rows);
  }, [principal, address, controlAdjacency, machineByAddr]);

  // Capability tags per governed contract, when a server-side principal facet
  // exists (controls_detail carries the high-level capability vocabulary the
  // client-side inversion lacks).
  const capabilitiesByContract = useMemo(() => {
    const map = new Map();
    for (const detail of principal?.controls_detail || []) {
      const addr = (detail?.address || "").toLowerCase();
      const caps = Array.isArray(detail?.capabilities) ? detail.capabilities : [];
      if (addr && caps.length) map.set(addr, caps);
    }
    return map;
  }, [principal]);

  const highlightedFunction = useMemo(
    () => (isMachine ? machineFunctions(machine).find((fnView) => fnView.key === highlightedFunctionKey) || null : null),
    [isMachine, machine, highlightedFunctionKey],
  );

  // A navigate can request the Governs tab pre-opened; honor it only when there
  // is a Governs tab worth landing on (rows > 0). A principal-only card has no
  // other tab, so it always opens on Governs.
  const [activeTab, setActiveTab] = useState(() => {
    if (!isMachine) return "governs";
    return initialTab === "governs" && canCallRows.length ? "governs" : "control";
  });

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

  const tabCounts = isMachine
    ? {
        control: machine.lanes.top.length + machine.lanes.ops.length,
        inflows: machine.lanes.left.length,
        outflows: machine.lanes.right.length,
        balances: machine.balances?.length || 0,
        governs: canCallRows.length,
      }
    : { governs: canCallRows.length };

  const accent = isMachine
    ? (machine.total_usd ? "#f59e0b33" : null)
    : principalType.accent;

  return (
    <article
      className={`ps-machine${highlightedContract ? " ps-machine-score-highlight" : ""}`}
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
          {isMachine && (
            <>
              <span className="ps-badge" style={{ "--badge-accent": (ROLE_META[machine.role] || ROLE_META.utility).color }}>{(ROLE_META[machine.role] || ROLE_META.utility).label.replace(/s$/, "")}</span>
              {/* Deposit-destination call-out for value_handler contracts that
                  actually hold funds — plain-language answer to "where does my
                  money go?" Gated on total_usd>0 so a pull-then-forward router
                  isn't mislabeled. */}
              {machine.role === "value_handler" && Number(machine.total_usd) > 0 ? (
                <span className="ps-badge" style={{ "--badge-accent": "#22c55e" }}>Deposit destination</span>
              ) : null}
              {machine.is_proxy ? <span className="ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{machine.proxy_type || "proxy"}</span> : null}
              {machine.upgrade_count != null ? <span className="ps-badge" style={{ "--badge-accent": "#8b92a8" }}>{machine.upgrade_count} upgrades</span> : null}
              <span className="ps-badge" style={{ "--badge-accent": "#6b7590" }}>{machine.totalFunctions} functions</span>
              {usdLabel && <span className="ps-badge" style={{ "--badge-accent": "#f59e0b" }}>{usdLabel}</span>}
            </>
          )}
          {/* Identity badges for the principal facet (type + threshold/delay).
              Same slot for a principal-only card and a dual-facet contract. */}
          {principal && (
            <>
              <span className="ps-badge" style={{ "--badge-accent": principalType.accent }}>{principalType.label}</span>
              {principal.type === "safe" && threshold ? (
                <span className="ps-badge" style={{ "--badge-accent": "#6a9e94" }}>{threshold}/{owners.length} threshold</span>
              ) : null}
              {principal.type === "timelock" && delay > 0 ? (
                <span className="ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{formatDelay(delay)} delay</span>
              ) : null}
            </>
          )}
        </div>
        {isMachine && onOpenDependencyGraph && (
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
      </div>

      {isMachine && activeTab === "control" && (
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
      {isMachine && activeTab === "inflows" && (
        <LaneColumn
          title={LANE_META.left.label}
          laneKey="left"
          items={machine.lanes.left}
          onSelect={onSelectGuard}
          onNavigate={onNavigate}
          highlightedFunctionKey={highlightedFunctionKey}
        />
      )}
      {isMachine && activeTab === "outflows" && (
        <LaneColumn
          title={LANE_META.right.label}
          laneKey="right"
          items={machine.lanes.right}
          onSelect={onSelectGuard}
          onNavigate={onNavigate}
          highlightedFunctionKey={highlightedFunctionKey}
        />
      )}
      {isMachine && activeTab === "balances" && <BalanceTable machine={machine} />}
      {activeTab === "governs" && (
        <GovernsTab
          canCallRows={canCallRows}
          capabilitiesByContract={capabilitiesByContract}
          pathRows={pathRows}
          onNavigate={onNavigate}
          onFocusContract={onFocusContract}
        />
      )}
    </article>
  );
}
