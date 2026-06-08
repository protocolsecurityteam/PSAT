import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { isBytecodeVerifiedAudit } from "./auditCoverage.js";
import { api } from "./api/client.js";
import { listAddressLabels } from "./api/addressLabels.js";
import { getCoverage } from "./api/audits.js";
import { AgentPanel } from "./surface/inspector/AgentPanel.jsx";
import { formatUsd, isRoleIdAddress } from "./surface/format.js";
import { findFunctionView } from "./surface/lane.js";
import { ROLE_META } from "./surface/meta.js";
import { buildMachines } from "./surface/layout/buildMachines.js";
import { SurfaceCanvas } from "./surface/canvas/SurfaceCanvas.jsx";
import { ContractMachine } from "./surface/lanes/ContractMachine.jsx";
import { DependencyGraphModal } from "./surface/modals/DependencyGraphModal.jsx";
import { AuditsListPanel } from "./surface/sidebar/AuditsListPanel.jsx";
import { Breadcrumbs } from "./surface/sidebar/Breadcrumbs.jsx";
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
  const [selectedGuard, setSelectedGuard] = useState(null);
  const [selectedMachine, setSelectedMachine] = useState(null);
  const [selectedPrincipal, setSelectedPrincipal] = useState(null);
  const [radarExampleSelection, setRadarExampleSelection] = useState(null);
  const [suppressSearchFocus, setSuppressSearchFocus] = useState(() => (
    !embedded && Boolean(
      new URLSearchParams(window.location.search).get("score")
        || new URLSearchParams(window.location.search).get("scoreAxis")
        || sessionStorage.getItem("psat:surfaceRadarExample"),
    )
  ));
  // Search mode lives on the parent so the mode-pill bar can render at
  // top-left while the rest of SearchNavigator stays in the centre overlay.
  const [searchMode, setSearchMode] = useState("all");
  const [breadcrumbs, setBreadcrumbs] = useState([]);
  const [focusAddress, setFocusAddress] = useState(null);
  const [focusedAddress, setFocusedAddress] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("focus") || null;
  });
  const focusKeyRef = useRef(0);
  const triggerFocus = useCallback((addr) => {
    focusKeyRef.current += 1;
    setFocusAddress({ address: addr, key: focusKeyRef.current });
    setFocusedAddress(addr || null);
    if (embedded) return;
    // Sync focus address to URL
    const url = new URL(window.location.href);
    if (addr) {
      url.searchParams.set("focus", addr);
      url.searchParams.delete("fn");
      url.searchParams.delete("score");
    } else {
      url.searchParams.delete("focus");
      url.searchParams.delete("fn");
      url.searchParams.delete("score");
    }
    window.history.replaceState({}, "", url.toString());
  }, [embedded]);
  // Multi-principal tour state: { principals: [...], index: 0, sourceContract: "0x...", sourceFunction: "fn" }
  const [principalTour, setPrincipalTour] = useState(null);
  const [error, setError] = useState(null);
  const [headerCollapsed, setHeaderCollapsed] = useState(true);
  const [dependencyGraphMachine, setDependencyGraphMachine] = useState(null);

  // Right sidebar mode: "detail" (default), "agent", "audits",
  // "monitoring", or "upgrades".
  // Default to Agent in both embedded and fullscreen views — the chat
  // interface is the most useful entry point on first load. A canvas
  // click switches to Detail in both modes (handlers below).
  const [sidebarMode, setSidebarMode] = useState("agent");
  // Per-proxy upgrade history cache, keyed by analysis_job_id. Server's
  // /api/company/{name} returns upgrade_count=null for protocols whose
  // chain monitor hasn't ingested events yet (the static-analysis blob in
  // /api/analyses/{analysis_job_id} has the real numbers). We populate this lazily
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

  // Highlighted addresses on the canvas: union of agent highlights (Agent
  // tab) with the audit-coverage set (Audits tab). Either source can drive
  // the green ring. Lowercased Set so the canvas comparison is O(1); null
  // when neither source is active so the canvas falls back to selection-
  // dimming.
  const highlightedAddresses = useMemo(() => {
    const fromAudit = (() => {
      if (activeAuditId == null || !coverageData) return null;
      const out = new Set();
      for (const entry of coverageData.coverage || []) {
        const addr = (entry.address || "").toLowerCase();
        if (!addr) continue;
        if ((entry.audits || []).some((a) => a.audit_id === activeAuditId && isBytecodeVerifiedAudit(a))) {
          out.add(addr);
        }
      }
      return out;
    })();
    if (!fromAudit && !agentHighlights) return null;
    const merged = new Set();
    if (fromAudit) for (const a of fromAudit) merged.add(a);
    if (agentHighlights) for (const a of agentHighlights) merged.add(a);
    return merged.size ? merged : null;
  }, [activeAuditId, coverageData, agentHighlights]);

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
    setSelectedGuard(null);
    setRadarExampleSelection(null);
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

  // Restore focus from URL on initial data load
  const restoredFocus = useRef(false);
  useEffect(() => {
    if (embedded || restoredFocus.current || !machines.length) return;
    const params = new URLSearchParams(window.location.search);
    const urlFocus = params.get("focus");
    if (params.get("score")) return;
    if (urlFocus) {
      restoredFocus.current = true;
      const machine = machines.find((m) => m.address?.toLowerCase() === urlFocus.toLowerCase());
      if (machine) {
        setSelectedMachine(machine);
        setSelectedPrincipal(null);
        setSelectedGuard(null);
        setRadarExampleSelection(null);
      }
      triggerFocus(urlFocus);
    }
  }, [embedded, machines, triggerFocus]);

  const handleToggleRole = useCallback((role) => {
    setEnabledRoles((prev) => {
      const next = new Set(prev);
      if (next.has(role)) next.delete(role);
      else next.add(role);
      return next;
    });
  }, []);

  const handleSelectMachine = useCallback((machine) => {
    setSelectedMachine(machine);
    setSelectedPrincipal(null);
    setSelectedGuard(null);
    setRadarExampleSelection(null);
    triggerFocus(machine?.address || null);
    // Clear any agent-emitted green-ring overlay when selection moves —
    // otherwise pane clicks (which call this with null) leave the
    // previous agent-highlighted address visually "focused".
    if (!machine) setAgentHighlights(null);
  }, [triggerFocus]);

  const handleSelectGuard = useCallback((fnView) => {
    setSelectedGuard(fnView);
    setRadarExampleSelection(null);
  }, []);

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
    setSelectedMachine(machine);
    setSelectedPrincipal(null);
    setSelectedGuard(fnView || null);
    setRadarExampleSelection({
      contractAddress: machine.address,
      functionKey: fnView?.key || null,
    });
    setSuppressSearchFocus(false);
    triggerFocus(machine.address);
    const url = new URL(window.location.href);
    url.searchParams.set("focus", machine.address);
    url.searchParams.set("score", "1");
    if (fnView?.signature) url.searchParams.set("fn", fnView.signature);
    else url.searchParams.delete("fn");
    window.history.replaceState({}, "", url.toString());
  }, [allMachines, triggerFocus]);

  const restoredExampleSelection = useRef(false);
  useEffect(() => {
    if (embedded || restoredExampleSelection.current || !allMachines.length) return;
    const params = new URLSearchParams(window.location.search);
    const focus = params.get("focus");
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
  const handleSelectPrincipal = useCallback((principal, opts) => {
    if (!principal) return;
    setSelectedPrincipal(principal);
    setSelectedMachine(null);
    setSelectedGuard(null);
    setRadarExampleSelection(null);
    setPrincipalTour(null);
    // opts.focus === false selects without moving the camera (controller-row
    // clicks just want the highlight, not a pan/zoom to the principal's node).
    if (principal.address && opts?.focus !== false) triggerFocus(principal.address);
  }, [triggerFocus]);

  const visiblePrincipals = useMemo(() => {
    const visibleAddrs = new Set(machines.map((m) => m.address?.toLowerCase()));
    return (companyData?.principals || []).filter((p) =>
      !isRoleIdAddress(p.address || "") &&
      (p.controls || []).some((a) => visibleAddrs.has(a.toLowerCase()))
    );
  }, [machines, companyData]);

  const navigateToPrincipal = useCallback((target) => {
    let principal = visiblePrincipals.find((p) => p.address?.toLowerCase() === target.address?.toLowerCase());
    if (!principal) {
      const controls = machines
        .filter((m) => m.owner?.toLowerCase() === target.address?.toLowerCase())
        .map((m) => m.address);
      const chainIds = [...new Set(
        machines
          .filter((m) => controls.some((addr) => addr?.toLowerCase() === m.address?.toLowerCase()))
          .map((m) => m.chain_id)
          .filter(Boolean),
      )].sort((a, b) => a - b);
      principal = {
        address: target.address,
        type: target.type,
        label: target.label || target.type,
        details: target.details || {},
        controls,
        chain_ids: chainIds,
        chain_id: chainIds.length === 1 ? chainIds[0] : null,
      };
    }
    setSelectedPrincipal(principal);
    setSelectedMachine(null);
    setSelectedGuard(null);
    setRadarExampleSelection(null);
    triggerFocus(target.address);
  }, [machines, visiblePrincipals, triggerFocus]);

  const handleNavigate = useCallback((target) => {
    // Push current view to breadcrumbs before navigating
    setBreadcrumbs((prev) => {
      const current = selectedPrincipal
        ? { type: selectedPrincipal.type, address: selectedPrincipal.address, label: selectedPrincipal.label }
        : selectedMachine
        ? { type: "contract", address: selectedMachine.address, label: selectedMachine.name }
        : null;
      return current ? [...prev, current] : prev;
    });

    const hasPrincipalTour = target._allPrincipals && target._allPrincipals.length > 1;
    if (hasPrincipalTour) {
      setPrincipalTour({
        principals: target._allPrincipals,
        index: 0,
        sourceContract: target._sourceContract,
        sourceFunction: target._sourceFunction,
      });
    } else {
      setPrincipalTour(null);
    }

    // Surface the navigation result in the Detail panel. Without this,
    // clicking a guard chip from the Agent tab silently mutates state
    // the user can't see — looks like "nothing happened" until they
    // manually click Detail. The chip click is an explicit drill-in
    // request, so swapping to Detail is the right behavior.
    setSidebarMode("detail");

    if (target.type === "contract") {
      const machine = machines.find((m) => m.address?.toLowerCase() === target.address?.toLowerCase());
      if (machine) {
        setSelectedMachine(machine);
        setSelectedPrincipal(null);
        setSelectedGuard(null);
        setRadarExampleSelection(null);
        triggerFocus(machine.address);
      }
    } else {
      navigateToPrincipal(target);
    }
  }, [machines, visiblePrincipals, selectedMachine, selectedPrincipal, triggerFocus, navigateToPrincipal]);

  const handleBreadcrumbNav = useCallback((item, index) => {
    // Truncate breadcrumbs to this point
    setBreadcrumbs((prev) => prev.slice(0, index));
    if (item.type === "contract") {
      const machine = machines.find((m) => m.address?.toLowerCase() === item.address?.toLowerCase());
      if (machine) { setSelectedMachine(machine); setSelectedPrincipal(null); setSelectedGuard(null); setRadarExampleSelection(null); }
    } else {
      const principal = visiblePrincipals.find((p) => p.address?.toLowerCase() === item.address?.toLowerCase());
      if (principal) { setSelectedPrincipal(principal); setSelectedMachine(null); setSelectedGuard(null); setRadarExampleSelection(null); }
    }
  }, [machines, visiblePrincipals]);

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

  const radarExampleFlyout = sidebarMode === "detail" && radarExampleSelection && selectedMachine && !selectedPrincipal ? (
    <div className="ps-sidebar-flyout-content">
      <ContractMachine
        key={`${selectedMachine.address}:radar`}
        machine={selectedMachine}
        onSelectGuard={handleSelectGuard}
        onNavigate={handleNavigate}
        companyName={companyName}
        highlightedFunctionKey={radarExampleSelection.functionKey}
        highlightedContract={!radarExampleSelection.functionKey}
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
        onFocus={(item) => {
          if (suppressSearchFocus || radarExampleSelection) return;
          if (!item) {
            setSelectedMachine(null); setSelectedPrincipal(null);
            setRadarExampleSelection(null);
            setFocusedAddress(null);
            const url = new URL(window.location.href);
            url.searchParams.delete("focus");
            window.history.replaceState({}, "", url.toString());
            return;
          }
          setBreadcrumbs([]);
          if (item.kind === "principal" && item.principal) {
            setSelectedPrincipal(item.principal);
            setSelectedMachine(item.machine);
            setSelectedGuard(null);
            setRadarExampleSelection(null);
            // Focus on the principal node or its first controlled contract
            triggerFocus(item.address || item.machine?.address);
          } else if (item.machine) {
            setSelectedMachine(item.machine);
            setSelectedPrincipal(null);
            setSelectedGuard(null);
            setRadarExampleSelection(null);
            triggerFocus(item.machine.address);
          }
        }}
      />
      </div>

      <div className="ps-layout">
        <ReactFlowProvider>
          <SurfaceCanvas
            machines={machines}
            fundFlows={companyData?.fund_flows}
            principals={visiblePrincipals}
            selectedAddress={selectedMachine?.address || selectedPrincipal?.address}
            focusAddress={focusAddress}
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
            onSelectPrincipal={(p, opts) => {
              if (p && sidebarMode !== "detail") setSidebarMode("detail");
              handleSelectPrincipal(p, opts);
            }}
            principalTour={principalTour}
            onTourGo={(nextIndex) => {
              const p = principalTour.principals[nextIndex];
              setPrincipalTour((prev) => ({ ...prev, index: nextIndex }));
              navigateToPrincipal({
                type: p.resolvedType || "unknown",
                address: p.address,
                label: p.label,
                details: p.details,
              });
            }}
            onTourBack={() => {
              setPrincipalTour(null);
              if (principalTour?.sourceContract) {
                const machine = machines.find((m) => m.address?.toLowerCase() === principalTour.sourceContract?.toLowerCase());
                if (machine) {
                  setSelectedMachine(machine);
                  setSelectedPrincipal(null);
                  setSelectedGuard(null);
                  setRadarExampleSelection(null);
                  triggerFocus(machine.address);
                }
              }
            }}
          />
        </ReactFlowProvider>
        <DraggableSidebar flyout={radarExampleFlyout}>
          <SidebarTabs
            mode={sidebarMode}
            onSetMode={setSidebarMode}
            auditCount={coverageData?.audit_count}
            showDetail
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
            />
          )}
          {sidebarMode === "monitoring" && (
            <SurfaceMonitoringPanel
              companyData={companyData}
              machines={allMachines}
              selectedMachine={
                selectedMachine ||
                allMachines.find((m) => m.address?.toLowerCase() === focusedAddress?.toLowerCase()) ||
                null
              }
            />
          )}
          {sidebarMode === "upgrades" && (
            <UpgradesSidebarPanel
              machine={selectedMachine}
              companyName={companyName}
              machines={machines}
              onSelect={handleSelectMachine}
              cache={upgradeHistoryCache}
              onCache={cacheUpgradeHistory}
            />
          )}
          {sidebarMode === "detail" && (
            <Breadcrumbs items={breadcrumbs} onNavigate={handleBreadcrumbNav} />
          )}
          {sidebarMode === "detail" && !selectedPrincipal && (!selectedMachine || radarExampleSelection) && (
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
              onFocusContract={(addr) => triggerFocus(addr)}
              addressLabels={addressLabels}
              refreshAddressLabels={refreshAddressLabels}
            />
          )}
          {sidebarMode === "detail" && selectedMachine && !selectedPrincipal && !radarExampleSelection && (
            <ContractMachine
              key={selectedMachine.address}
              machine={selectedMachine}
              onSelectGuard={handleSelectGuard}
              onNavigate={handleNavigate}
              companyName={companyName}
              highlightedFunctionKey={radarExampleSelection?.functionKey}
              onOpenDependencyGraph={setDependencyGraphMachine}
            />
          )}
          {sidebarMode === "detail" && !selectedPrincipal && !radarExampleSelection && (
            <InspectorCard selected={selectedGuard} onNavigate={handleNavigate} />
          )}
          {sidebarMode === "agent" && (
            <AgentPanel
              companyName={companyName}
              selectedMachine={selectedMachine}
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
                triggerFocus(addr);
                const focusChainId = selectedMachine?.chain_id;
                if (!focusChainId) {
                  setHighlightedAddresses(new Set([lc]));
                  return;
                }
                api(
                  `/api/agent/address-touches?company=${encodeURIComponent(companyName)}&address=${encodeURIComponent(addr)}&chain_id=${encodeURIComponent(focusChainId)}`,
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
