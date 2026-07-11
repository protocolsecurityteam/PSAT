import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { isBytecodeVerifiedAudit } from "./auditCoverage.js";
import { api } from "./api/client.js";
import { useIsAdmin } from "./api/useIsAdmin.js";
import { listAddressLabels } from "./api/addressLabels.js";
import { getCoverage } from "./api/audits.js";
import { AgentPanel } from "./surface/inspector/AgentPanel.jsx";
import { formatUsd, isRoleIdAddress } from "./surface/format.js";
import { findFunctionView } from "./surface/lane.js";
import { ROLE_META } from "./surface/meta.js";
import { buildMachines } from "./surface/layout/buildMachines.js";
import { buildEntityIndex } from "./surface/layout/entities.js";
import { useSurfaceSelection } from "./surface/useSurfaceSelection.js";
import { SurfaceCanvas } from "./surface/canvas/SurfaceCanvas.jsx";
import { ContractMachine } from "./surface/lanes/ContractMachine.jsx";
import { DependencyGraphModal } from "./surface/modals/DependencyGraphModal.jsx";
import { AuditsListPanel } from "./surface/sidebar/AuditsListPanel.jsx";
import { DetailEmptyState } from "./surface/sidebar/DetailEmptyState.jsx";
import { DraggableSidebar } from "./surface/sidebar/DraggableSidebar.jsx";
import { InspectorCard } from "./surface/sidebar/InspectorCard.jsx";
import { PrincipalDetail } from "./surface/sidebar/PrincipalDetail.jsx";
import { RoleFilterBar } from "./surface/sidebar/RoleFilterBar.jsx";
import { SidebarTabs } from "./surface/sidebar/SidebarTabs.jsx";
import { UpgradesSidebarPanel } from "./surface/sidebar/UpgradesSidebarPanel.jsx";
import { SurfaceMonitoringPanel } from "./surface/sidebar/monitoring/SurfaceMonitoringPanel.jsx";
import { SearchModesBar } from "./surface/sidebar/search/SearchModesBar.jsx";
import { SearchNavigator } from "./surface/sidebar/search/SearchNavigator.jsx";

export default function ProtocolSurface({
  companyName,
  initialData = null,
  initialCoverage = null,
  initialFunctions = null,
  embedded = false,
}) {
  const isAdmin = useIsAdmin();
  // initialData / initialFunctions let a parent (CompanyOverview) hand
  // us the /api/company/{name} payload and /functions map it already
  // fetched, so we don't fire duplicate requests on mount. Fixtures
  // (vitest, e2e) still embed functions on each contract entry, so
  // fall back to those when neither prop is provided.
  const [companyData, setCompanyData] = useState(initialData);
  // Derive functionData from props so a CompanyOverview-supplied
  // initialFunctions that arrives AFTER mount (its /functions fetch
  // resolves after /api/company) flows in. The previous
  // useState(initialFunctionData) seeded once and never resynced, so
  // the embedded surface stayed permanently empty on hard refresh.
  // Precedence: prop > locally fetched > inline-on-contract fixtures.
  const [locallyFetched, setLocallyFetched] = useState(null);
  const functionData = useMemo(() => {
    if (initialFunctions && Object.keys(initialFunctions).length > 0) return initialFunctions;
    if (locallyFetched && Object.keys(locallyFetched).length > 0) return locallyFetched;
    const source = companyData?.contracts || initialData?.contracts;
    if (Array.isArray(source) && source.some((c) => Array.isArray(c.functions))) {
      return Object.fromEntries(
        source.filter((c) => c.address).map((c) => [c.address, c.functions || []]),
      );
    }
    return {};
  }, [initialFunctions, locallyFetched, companyData, initialData]);
  const [functionsLoading, setFunctionsLoading] = useState(false);
  // Search mode lives on the parent so the mode-pill bar can render at
  // top-left while the rest of SearchNavigator stays in the centre overlay.
  const [searchMode, setSearchMode] = useState("all");
  // Single URL writer. Persists a committed selection as ?sel=<addr>&view=
  // <contract|principal> (principal selections are now shareable/restorable),
  // plus the radar deep-link's ?score=1&fn=<sig>. Called imperatively ONLY from
  // the committing wrappers (select + radar) and the mount restore's URL
  // normalization — never from a focus preview (search browsing / contract
  // pager) and never on plain render. Because it fires only after a user commit
  // (which can only happen after the machines-gated mount restore has run and
  // read the params), it cannot race the restore; no separate write gate is
  // needed beyond the per-restore refs below. Legacy ?focus is dropped on every
  // write so old-style params don't linger next to ?sel.
  const syncUrl = useCallback(({ sel = null, view = null, radar: radarSig = null } = {}) => {
    if (embedded) return;
    const url = new URL(window.location.href);
    if (sel) {
      url.searchParams.set("sel", sel);
      if (view) url.searchParams.set("view", view);
      else url.searchParams.delete("view");
    } else {
      url.searchParams.delete("sel");
      url.searchParams.delete("view");
    }
    url.searchParams.delete("focus");
    if (radarSig) {
      url.searchParams.set("score", "1");
      if (radarSig.signature) url.searchParams.set("fn", radarSig.signature);
      else url.searchParams.delete("fn");
    } else {
      url.searchParams.delete("score");
      url.searchParams.delete("fn");
    }
    window.history.replaceState({}, "", url.toString());
  }, [embedded]);
  const [error, setError] = useState(null);
  const [headerCollapsed, setHeaderCollapsed] = useState(true);
  const [dependencyGraphMachine, setDependencyGraphMachine] = useState(null);

  // Right sidebar mode: "detail", "agent", "audits", "monitoring", or
  // "upgrades". Agent and Monitor are admin-only, so non-admins open in
  // Detail; admins open in Agent (the chat is the most useful first stop).
  // A canvas click switches to Detail in all modes (handlers below).
  const [sidebarMode, setSidebarMode] = useState(() => (isAdmin ? "agent" : "detail"));
  // If the admin key clears while an admin-only tab is open, fall back to
  // Detail so the hidden tab's content can't linger.
  useEffect(() => {
    if (!isAdmin && (sidebarMode === "agent" || sidebarMode === "monitoring")) {
      setSidebarMode("detail");
    }
  }, [isAdmin, sidebarMode]);
  // Per-proxy upgrade history cache, keyed by job_id. Server's
  // /api/company/{name} returns upgrade_count=null for protocols whose
  // chain monitor hasn't ingested events yet (the static-analysis blob in
  // /api/analyses/{job_id} has the real numbers). We populate this lazily
  // each time the user opens a proxy in the Upgrades tab so subsequent
  // visits skip the round-trip and the global proxy list can show real
  // counts for already-opened proxies.
  const [upgradeHistoryCache, setUpgradeHistoryCache] = useState({});
  const cacheUpgradeHistory = useCallback((jobId, history, deps) => {
    if (!jobId) return;
    setUpgradeHistoryCache((prev) => ({ ...prev, [jobId]: { history, deps } }));
  }, []);

  // Coverage payload — one call, cached locally. Used to build the audits
  // list + the audit_id → address-set map for highlight propagation. When
  // the embedded surface gets it from CompanyOverview via initialCoverage,
  // skip the duplicate fetch.
  const [coverageData, setCoverageData] = useState(initialCoverage);
  const [coverageError, setCoverageError] = useState(null);
  const [coverageLoading, setCoverageLoading] = useState(false);

  // Active audit: when non-null, its covered contracts get a green ring
  // and everything else dims on the canvas.
  const [activeAuditId, setActiveAuditId] = useState(null);

  // Admin-curated address → name map. Fetched once; edits are optimistic
  // against the local copy and persisted via the admin-gated PUT/DELETE.
  const [addressLabels, setAddressLabels] = useState(new Map());
  const refreshAddressLabels = useCallback(() => {
    listAddressLabels()
      .then((d) => {
        const m = new Map();
        for (const [addr, info] of Object.entries(d?.labels || {})) {
          m.set(String(addr).toLowerCase(), info.name);
        }
        setAddressLabels(m);
      })
      .catch(() => { /* labels are best-effort — keep whatever we had */ });
  }, []);
  useEffect(() => { refreshAddressLabels(); }, [refreshAddressLabels]);
  useEffect(() => {
    if (!companyName) return undefined;
    if (initialCoverage) {
      setCoverageData(initialCoverage);
      setCoverageError(null);
      setCoverageLoading(false);
      return undefined;
    }
    let cancelled = false;
    setCoverageLoading(true);
    setCoverageError(null);
    getCoverage(companyName)
      .then((d) => { if (!cancelled) { setCoverageData(d); setCoverageLoading(false); } })
      .catch((e) => { if (!cancelled) { setCoverageError(e?.message || "Failed"); setCoverageLoading(false); } });
    return () => { cancelled = true; };
  }, [companyName, initialCoverage]);

  // Agent-emitted highlights: addresses the LLM mentioned in its last
  // answer, intersected server-side with the protocol's in-scope contracts.
  // Plain state so AgentPanel can replace it via setHighlightedAddresses.
  const [agentHighlights, setAgentHighlights] = useState(null);

  // Audit-coverage highlight set (Audits tab): the contracts a picked audit
  // bytecode-verifiably covers. Merged with agent + selection highlights into
  // highlightedAddresses below (defined after the selection/visibility derives
  // it also depends on).
  const auditHighlights = useMemo(() => {
    if (activeAuditId == null || !coverageData) return null;
    const out = new Set();
    for (const entry of coverageData.coverage || []) {
      const addr = (entry.address || "").toLowerCase();
      if (!addr) continue;
      if ((entry.audits || []).some((a) => a.audit_id === activeAuditId && isBytecodeVerifiedAudit(a))) {
        out.add(addr);
      }
    }
    return out.size ? out : null;
  }, [activeAuditId, coverageData]);

  const setHighlightedAddresses = setAgentHighlights;
  const [enabledRoles, setEnabledRoles] = useState(() => {
    const initial = new Set();
    for (const [role, meta] of Object.entries(ROLE_META)) {
      if (meta.defaultOn) initial.add(role);
    }
    return initial;
  });

  useEffect(() => {
    if (!companyName) return undefined;
    setError(null);
    let cancelled = false;

    const haveCompanyData = Boolean(initialData);
    // Fixtures (vitest, e2e) still embed functions on each contract,
    // so detect that and skip the /functions fetch in that case.
    const initialFixtureFunctions =
      !initialFunctions &&
      Array.isArray(initialData?.contracts) &&
      initialData.contracts.some((c) => Array.isArray(c.functions));
    const haveFunctions = Boolean(initialFunctions) || initialFixtureFunctions;

    if (haveCompanyData) setCompanyData(initialData);

    // Fire both fetches in parallel — /api/company and /functions are
    // independent. /functions is the heavy one (was 120-290 ms + 2.13 MB
    // of payload inside the main endpoint); doing it alongside keeps the
    // canvas TTI down without waiting on the function inspector data.
    if (!haveCompanyData) {
      fetch(`/api/company/${encodeURIComponent(companyName)}`)
        .then((r) => {
          if (!r.ok) throw new Error("Failed to load company overview");
          return r.json();
        })
        .then((d) => {
          if (cancelled) return;
          setCompanyData(d);
          // Older / mocked /api/company responses still embed functions
          // on contract entries (e2e fixtures, legacy backend). The
          // functionData memo picks those up from companyData.contracts;
          // no explicit copy needed here.
        })
        .catch((err) => { if (!cancelled) setError(err.message || "Failed to load surface"); });
    }

    if (haveFunctions) {
      // initialFunctions (or fixture-embedded functions) supplied — clear
      // any prior loading state so machines aren't gated unnecessarily.
      setFunctionsLoading(false);
    } else if (embedded) {
      // CompanyOverview already fires /functions for the embedded surface
      // and threads the result back via initialFunctions; firing again
      // here doubled the network + DB cost per page-load. Wait for the
      // prop instead and surface functionsLoading=true so buildMachines
      // keeps analyzed contracts visible during the gap.
      setFunctionsLoading(true);
    } else {
      setFunctionsLoading(true);
      fetch(`/api/company/${encodeURIComponent(companyName)}/functions`)
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (cancelled) return;
          const incoming = d && typeof d === "object" && d.functions;
          if (incoming && Object.keys(incoming).length > 0) {
            setLocallyFetched(incoming);
          }
          setFunctionsLoading(false);
        })
        .catch(() => { if (!cancelled) setFunctionsLoading(false); });
    }

    return () => {
      cancelled = true;
    };
  }, [companyName, initialData, initialFunctions]);

  const allMachines = useMemo(
    () => (companyData ? buildMachines(companyData, functionData, { functionsLoading }) : []),
    [companyData, functionData, functionsLoading]
  );

  // computeProtocolScore (used by DetailEmptyState) iterates
  // contract.functions for its action axes. Functions live on a
  // separate endpoint now, so splice them back onto each contract for
  // the score-only consumer. The buildMachines call above already
  // consumes the keyed map directly.
  const companyDataWithFunctions = useMemo(() => {
    if (!companyData) return null;
    if (!functionData || Object.keys(functionData).length === 0) return companyData;
    return {
      ...companyData,
      contracts: (companyData.contracts || []).map((c) =>
        c.address && functionData[c.address] ? { ...c, functions: functionData[c.address] } : c
      ),
    };
  }, [companyData, functionData]);

  const machines = useMemo(
    () => allMachines.filter((m) => enabledRoles.has(m.role || "utility")),
    [allMachines, enabledRoles]
  );

  // Address-keyed entity index over ALL machines + ALL principals (no
  // visibility filtering). Selection state stores addresses only and resolves
  // entities through this index per render, so denormalized snapshots can
  // never go stale and role-filtered-off targets still resolve.
  const entityIndex = useMemo(
    () => buildEntityIndex(allMachines, companyData?.principals || []),
    [allMachines, companyData]
  );

  const {
    selection,
    radarSelection,
    focus,
    selectedMachine,
    selectedPrincipal,
    selectedGuard,
    focusedAddress,
    select,
    guard,
    radar,
    focusPreview,
  } = useSurfaceSelection({ entityIndex, machines, companyName });

  // Restore a persisted selection from the URL on initial data load. Reads the
  // new ?sel=&view= pair, falling back to the legacy ?focus= param so old links
  // still resolve. The reducer owns view resolution: ?view wins when present,
  // else the entity's facet default. A radar deep-link (?score) is left to the
  // radar-restore effect below. Runs once, gated on machines so the entity
  // index can resolve the address; this read happens before any user commit can
  // fire the URL writer, so the writer never clobbers these params first.
  const restoredSelection = useRef(false);
  useEffect(() => {
    if (embedded || restoredSelection.current || !machines.length) return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("score")) return;
    const addr = params.get("sel") || params.get("focus");
    if (!addr) return;
    restoredSelection.current = true;
    const lc = addr.toLowerCase();
    const entity = entityIndex.get(lc);
    if (entity) {
      // ?view wins when present; else match the reducer's facet default so a
      // legacy ?focus link normalizes to the same view a fresh select would.
      const view =
        params.get("view") ||
        (entity.machine && !entity.principal ? "contract" : "principal");
      select(addr, { view });
      syncUrl({ sel: addr, view });
    } else {
      // A garbage/off-index address becomes a camera preview, never a
      // synthesized junk selection card.
      focusPreview(addr);
    }
  }, [embedded, machines, entityIndex, select, focusPreview, syncUrl]);

  const handleToggleRole = useCallback((role) => {
    setEnabledRoles((prev) => {
      const next = new Set(prev);
      if (next.has(role)) next.delete(role);
      else next.add(role);
      return next;
    });
  }, []);

  const handleSelectMachine = useCallback((machine) => {
    // Any committed selection transition drops the agent-emitted green-ring
    // overlay — clearing belongs to the transition, not just the deselect, so a
    // stale highlight set can't outrank the new selection's dimming.
    setAgentHighlights(null);
    if (machine) {
      select(machine.address, { view: "contract" });
      syncUrl({ sel: machine.address, view: "contract" });
    } else {
      // Pane click / deselect — full clear.
      select(null);
      syncUrl({});
    }
  }, [select, syncUrl]);

  const handleSelectGuard = useCallback((fnView) => guard(fnView?.key || null), [guard]);

  const handleRadarExampleClick = useCallback((example) => {
    const targetAddress = example?.contractAddress?.toLowerCase();
    if (!targetAddress) return;
    const machine = allMachines.find((m) => m.address?.toLowerCase() === targetAddress);
    if (!machine) return;
    const fnView = findFunctionView(machine, example);
    setEnabledRoles((prev) => {
      const role = machine.role || "utility";
      if (prev.has(role)) return prev;
      const next = new Set(prev);
      next.add(role);
      return next;
    });
    setSidebarMode("detail");
    setAgentHighlights(null);
    radar(machine.address, fnView?.key || null);
    syncUrl({ sel: machine.address, view: "contract", radar: { signature: fnView?.signature } });
  }, [allMachines, radar, syncUrl]);

  const restoredExampleSelection = useRef(false);
  useEffect(() => {
    if (embedded || restoredExampleSelection.current || !allMachines.length) return;
    const params = new URLSearchParams(window.location.search);
    const focus = params.get("sel") || params.get("focus");
    const fn = params.get("fn");
    let target = null;
    if (focus && params.get("score")) {
      target = { contractAddress: focus, functionSignature: fn || "", selector: fn || "" };
    } else if (window.location.pathname.endsWith("/surface")) {
      try {
        const pending = JSON.parse(sessionStorage.getItem("psat:surfaceRadarExample") || "null");
        if (pending?.companyName === companyName && pending?.contractAddress) {
          target = pending;
          sessionStorage.removeItem("psat:surfaceRadarExample");
        }
      } catch {
        sessionStorage.removeItem("psat:surfaceRadarExample");
      }
    }
    if (!target) return;
    const machine = allMachines.find((m) => m.address?.toLowerCase() === target.contractAddress.toLowerCase());
    if (!machine) return;
    restoredExampleSelection.current = true;
    handleRadarExampleClick({
      contractAddress: machine.address,
      functionSignature: target.functionSignature || "",
      selector: target.selector || "",
    });
  }, [allMachines, companyName, embedded, handleRadarExampleClick]);

  // Clicking a Safe/Timelock/EOA node on the canvas selects the principal
  // (opens the detail panel with signers / delay / controlled contracts)
  // and focuses it — same behaviour as clicking a single-principal guard
  // badge, just driven from the node itself.
  const handleSelectPrincipal = useCallback((principal) => {
    if (!principal) return;
    setAgentHighlights(null);
    select(principal.address, { view: "principal" });
    syncUrl({ sel: principal.address, view: "principal" });
  }, [select, syncUrl]);

  const visiblePrincipals = useMemo(() => {
    const visibleAddrs = new Set(machines.map((m) => m.address?.toLowerCase()));
    return (companyData?.principals || []).filter((p) =>
      !isRoleIdAddress(p.address || "") &&
      (p.controls || []).some((a) => visibleAddrs.has(a.toLowerCase()))
    );
  }, [machines, companyData]);

  // Highlighted addresses on the canvas: union of agent highlights (Agent tab)
  // and the audit-coverage set (Audits tab). Either source drives the green
  // ring + dim. Lowercased Set for O(1) canvas comparison; null when no source
  // is active so the canvas falls back to selection dimming. A selected
  // principal's reach is NOT routed through here — the canvas's own selection
  // path lights co_controls with the normal relatedness dim + chips, and the
  // green overlay treatment is reserved for agent/audit sets (owner decision
  // 2026-07-11).
  const highlightedAddresses = useMemo(() => {
    if (!auditHighlights && !agentHighlights) return null;
    const merged = new Set();
    if (auditHighlights) for (const a of auditHighlights) merged.add(a);
    if (agentHighlights) for (const a of agentHighlights) merged.add(a);
    return merged.size ? merged : null;
  }, [auditHighlights, agentHighlights]);

  // Role-toggle reconciliation. Toggling a role off removes its contracts (and
  // any principal whose whole touch set was those contracts) from the visible
  // set — but the selection still points at the now-hidden address, stranding a
  // sidebar card for a node that no longer exists. Reconcile ONLY on a roles
  // change (not on any visibility change) so a deliberate navigate to a
  // role-filtered-off contract still selects it. Keyed on enabledRoles; machines
  // /visiblePrincipals are already the post-toggle sets when this runs.
  const prevRolesRef = useRef(enabledRoles);
  useEffect(() => {
    if (prevRolesRef.current === enabledRoles) return;
    prevRolesRef.current = enabledRoles;
    const addr = selection?.address;
    if (!addr) return;
    const stillVisible =
      machines.some((m) => m.address?.toLowerCase() === addr) ||
      visiblePrincipals.some((p) => p.address?.toLowerCase() === addr);
    if (!stillVisible) {
      select(null);
      syncUrl({});
    }
  }, [enabledRoles, machines, visiblePrincipals, selection, select, syncUrl]);

  const handleNavigate = useCallback((target) => {
    // Surface the navigation result in the Detail panel. Contract targets no
    // longer no-op when role-filtered off the canvas — the entity index spans
    // all machines. `hint` lets resolveEntity synthesize a principal card for
    // off-index targets (e.g. per-function caller buttons) in one canonical
    // place.
    setSidebarMode("detail");
    setAgentHighlights(null);
    const view = target.type === "contract" ? "contract" : "principal";
    select(target.address, { view, hint: view === "principal" ? target : undefined });
    syncUrl({ sel: target.address, view });
  }, [select, syncUrl]);

  const totals = useMemo(() => {
    return machines.reduce(
      (acc, machine) => {
        acc.contracts += 1;
        acc.functions += machine.totalFunctions;
        if (machine.total_usd) { acc.withBalance += 1; acc.totalUsd += machine.total_usd; }
        return acc;
      },
      { contracts: 0, functions: 0, withBalance: 0, totalUsd: 0 }
    );
  }, [machines]);

  if (error) return <p className="empty">Failed: {error}</p>;
  if (!companyData) return <p className="empty">Loading surface...</p>;

  const radarExampleFlyout = sidebarMode === "detail" && radarSelection && selectedMachine && !selectedPrincipal ? (
    <div className="ps-sidebar-flyout-content">
      <ContractMachine
        key={`${selectedMachine.address}:radar`}
        machine={selectedMachine}
        onSelectGuard={handleSelectGuard}
        onNavigate={handleNavigate}
        companyName={companyName}
        highlightedFunctionKey={radarSelection.functionKey}
        highlightedContract={!radarSelection.functionKey}
        onOpenDependencyGraph={setDependencyGraphMachine}
      />
      <InspectorCard selected={selectedGuard} onNavigate={handleNavigate} />
    </div>
  ) : null;

  return (
    <div className="ps-surface ps-surface-fullscreen">
      {/* Overview strip (contracts / functions / with-funds) removed by
          request. The role filter toolbar below occupies this slot now. */}
      {false && (
      <div className={`ps-surface-overlay ${headerCollapsed ? "ps-surface-overlay-collapsed" : ""}`}>
        <button
          className="ps-surface-overlay-toggle"
          onClick={() => setHeaderCollapsed(!headerCollapsed)}
          title={headerCollapsed ? "Expand" : "Minimize"}
        >
          {headerCollapsed ? "\u25BC" : "\u25B2"}
        </button>
        {!headerCollapsed && (
          <div className="ps-surface-header">
            <div>
              <div className="ps-surface-eyebrow">Protocol Surface</div>
              <h2 className="ps-surface-title">{companyName}</h2>
              <p className="ps-surface-copy">
                Each contract shows control paths, operations, inflows, and outflows. Click any guard badge to inspect access control.
              </p>
            </div>
            <div className="ps-surface-stats">
              <div className="ps-surface-stat">
                <span>{totals.contracts}</span>
                <label>contracts</label>
              </div>
              <div className="ps-surface-stat">
                <span>{totals.functions}</span>
                <label>functions</label>
              </div>
              {totals.withBalance > 0 && (
                <div className="ps-surface-stat">
                  <span style={{ color: "#f59e0b" }}>{totals.withBalance}</span>
                  <label>with funds</label>
                </div>
              )}
              {totals.totalUsd > 0 && (
                <div className="ps-surface-stat">
                  <span style={{ color: "#f59e0b" }}>{formatUsd(totals.totalUsd)}</span>
                  <label>tracked value</label>
                </div>
              )}
              {companyData?.tvl?.defillama_tvl && (
                <div className="ps-surface-stat">
                  <span style={{ color: "#8b5cf6" }}>{formatUsd(companyData.tvl.defillama_tvl)}</span>
                  <label>protocol TVL</label>
                </div>
              )}
            </div>
          </div>
        )}
        {headerCollapsed && (
          <div className="ps-surface-header-mini">
            <span className="ps-surface-eyebrow" style={{ margin: 0 }}>{companyName}</span>
            <div className="ps-surface-stats">
              <div className="ps-surface-stat">
                <span>{totals.contracts}</span>
                <label>contracts</label>
              </div>
              <div className="ps-surface-stat">
                <span>{totals.functions}</span>
                <label>functions</label>
              </div>
              {totals.withBalance > 0 && (
                <div className="ps-surface-stat">
                  <span style={{ color: "#f59e0b" }}>{totals.withBalance}</span>
                  <label>with funds</label>
                </div>
              )}
              {totals.totalUsd > 0 && (
                <div className="ps-surface-stat">
                  <span style={{ color: "#f59e0b" }}>{formatUsd(totals.totalUsd)}</span>
                  <label>tracked value</label>
                </div>
              )}
              {companyData?.tvl?.defillama_tvl && (
                <div className="ps-surface-stat">
                  <span style={{ color: "#8b5cf6" }}>{formatUsd(companyData.tvl.defillama_tvl)}</span>
                  <label>protocol TVL</label>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      )}

      {/* Role filter bar — now in the top-left slot where the overview strip used to live */}
      <div className="ps-surface-toolbar-overlay">
        <RoleFilterBar machines={allMachines} enabledRoles={enabledRoles} onToggle={handleToggleRole} />
      </div>

      {/* Search mode pills — top-left slot (where the overview used to be) */}
      <div className="ps-search-modes-overlay">
        <SearchModesBar mode={searchMode} setMode={setSearchMode} />
      </div>

      <div className="ps-surface-search-overlay">
        <SearchNavigator
        machines={machines}
        principals={visiblePrincipals}
        mode={searchMode}
        setMode={setSearchMode}
        onPreview={(item) => { if (item) focusPreview(item.address); }}
        onCommit={(item) => {
          if (!item) return;
          setAgentHighlights(null);
          const view = item.kind === "principal" ? "principal" : "contract";
          select(item.address, { view });
          syncUrl({ sel: item.address, view });
        }}
      />
      </div>

      <div className="ps-layout">
        <ReactFlowProvider>
          <SurfaceCanvas
            machines={machines}
            fundFlows={companyData?.fund_flows}
            principals={visiblePrincipals}
            selectedAddress={selection?.address}
            focusAddress={focus}
            focusedAddress={focusedAddress}
            highlightedAddresses={highlightedAddresses}
            onSelectMachine={(m) => {
              // Auto-switch to Detail when the user clicks a contract
              // ON THE CANVAS so the function lanes are immediately
              // visible. Agent-link clicks go through
              // handleSelectMachine directly (not this wrapper), so
              // they don't trigger this and the user stays in the chat.
              if (m && sidebarMode !== "detail") setSidebarMode("detail");
              handleSelectMachine(m);
            }}
            onSelectPrincipal={(p) => {
              if (p && sidebarMode !== "detail") setSidebarMode("detail");
              handleSelectPrincipal(p);
            }}
          />
        </ReactFlowProvider>
        <DraggableSidebar flyout={radarExampleFlyout}>
          <SidebarTabs
            mode={sidebarMode}
            onSetMode={setSidebarMode}
            auditCount={coverageData?.audit_count}
            showDetail
            isAdmin={isAdmin}
          />
          {sidebarMode === "audits" && (
            <AuditsListPanel
              coverageData={coverageData}
              activeAuditId={activeAuditId}
              onPickAudit={setActiveAuditId}
              loading={coverageLoading}
              error={coverageError}
              machines={machines}
              selectedMachine={selectedMachine}
              selectedPrincipal={selectedPrincipal}
            />
          )}
          {isAdmin && sidebarMode === "monitoring" && (
            <SurfaceMonitoringPanel
              companyData={companyData}
              machines={allMachines}
              selectedMachine={selectedMachine}
              selectedPrincipal={selectedPrincipal}
            />
          )}
          {sidebarMode === "upgrades" && (
            <UpgradesSidebarPanel
              machine={selectedMachine}
              principal={selectedPrincipal}
              companyName={companyName}
              machines={machines}
              onSelect={handleSelectMachine}
              cache={upgradeHistoryCache}
              onCache={cacheUpgradeHistory}
            />
          )}
          {sidebarMode === "detail" && !selectedPrincipal && (!selectedMachine || radarSelection) && (
            <DetailEmptyState
              companyName={companyName}
              companyData={companyDataWithFunctions}
              coverageData={coverageData}
              onExampleClick={handleRadarExampleClick}
            />
          )}
          {sidebarMode === "detail" && selectedPrincipal && (
            <PrincipalDetail
              key={selectedPrincipal.address}
              principal={selectedPrincipal}
              machines={machines}
              onNavigate={handleNavigate}
              onFocusContract={(addr) => focusPreview(addr)}
              addressLabels={addressLabels}
              refreshAddressLabels={refreshAddressLabels}
            />
          )}
          {sidebarMode === "detail" && selectedMachine && !selectedPrincipal && !radarSelection && (
            <ContractMachine
              key={selectedMachine.address}
              machine={selectedMachine}
              onSelectGuard={handleSelectGuard}
              onNavigate={handleNavigate}
              companyName={companyName}
              highlightedFunctionKey={radarSelection?.functionKey}
              onOpenDependencyGraph={setDependencyGraphMachine}
            />
          )}
          {sidebarMode === "detail" && !selectedPrincipal && !radarSelection && (
            <InspectorCard selected={selectedGuard} onNavigate={handleNavigate} />
          )}
          {isAdmin && sidebarMode === "agent" && (
            <AgentPanel
              companyName={companyName}
              selectedMachine={selectedMachine}
              selectedPrincipal={selectedPrincipal}
              onHighlight={setHighlightedAddresses}
              onFocusAddress={(addr) => {
                // Route through the same selection handlers a canvas
                // click uses so we get the connected-edges-stay-bright
                // dim behavior for free.
                const lc = addr.toLowerCase();
                const machine = machines.find(
                  (m) => (m.address || "").toLowerCase() === lc,
                );
                if (machine) {
                  handleSelectMachine(machine);
                  return;
                }
                const principal = visiblePrincipals.find(
                  (p) => (p.address || "").toLowerCase() === lc,
                );
                if (principal) {
                  handleSelectPrincipal(principal);
                  return;
                }
                // Out-of-scope address (typical: an EOA that's a Safe
                // owner / role holder but not itself a canvas node).
                // Fetch its "touch radius" — every contract it has
                // function-level authority over — and write that set
                // into highlightedAddresses. The canvas's existing
                // audit-overlay dim path then dims everything else.
                focusPreview(addr);
                api(
                  `/api/agent/address-touches?company=${encodeURIComponent(companyName)}&address=${encodeURIComponent(addr)}`,
                )
                  .then((data) => {
                    const set = new Set([lc]);
                    for (const t of data?.touches || []) {
                      if (t.address) set.add(t.address.toLowerCase());
                    }
                    setHighlightedAddresses(set);
                  })
                  .catch(() => {
                    // Network/auth error — at least light up the focus
                    // target so the click isn't a no-op.
                    setHighlightedAddresses(new Set([lc]));
                  });
              }}
            />
          )}
        </DraggableSidebar>
      </div>
      <DependencyGraphModal
        machine={dependencyGraphMachine}
        onClose={() => setDependencyGraphMachine(null)}
      />
    </div>
  );
}
