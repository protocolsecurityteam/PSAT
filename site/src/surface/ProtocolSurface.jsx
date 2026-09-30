import { companyApi } from "../api/client.js";
import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { api } from "../api/client.js";
import { useIsAdmin } from "../api/useIsAdmin.js";
import { AgentPanel } from "./inspector/AgentPanel.jsx";
import { findCaller, findFunctionMatches, findFunctionView } from "./lane.js";
import { useSurfaceSelection } from "./useSurfaceSelection.js";
import { coalesceChain, entityKey, principalOnChain } from "./entityKey.js";
import { SurfaceCanvas } from "./canvas/SurfaceCanvas.jsx";
import { EntityCard } from "./lanes/EntityCard.jsx";
import { AuditsListPanel } from "./sidebar/AuditsListPanel.jsx";
import { DetailEmptyState } from "./sidebar/DetailEmptyState.jsx";
import { DraggableSidebar } from "./sidebar/DraggableSidebar.jsx";
import { InspectorCard } from "./sidebar/InspectorCard.jsx";
import { SidebarTabs } from "./sidebar/SidebarTabs.jsx";
import { ActivityPanel } from "./sidebar/activity/ActivityPanel.jsx";
import { SurfaceFilterPanel } from "./SurfaceFilterPanel.jsx";
import { useChainScope } from "./hooks/useChainScope.js";
import { useAuditCoverage } from "./hooks/useAuditCoverage.js";
import { useSurfaceModel } from "./hooks/useSurfaceModel.js";
import { useReachOverlay } from "./hooks/useReachOverlay.js";
import StaleBanner from "../shared/StaleBanner.jsx";

// Re-exported for existing importers.
export { auditHighlightSet } from "./hooks/useAuditCoverage.js";

export { principalOnChain };

function ProtocolSurface({
  companyName,
  initialData = null,
  initialCoverage = null,
  initialFunctions = null,
  initialScore = undefined,
  embedded = false,
}, ref) {
  const isAdmin = useIsAdmin();
  // A parent (CompanyOverview) may hand in data it already fetched, avoiding
  // duplicate requests. Fixtures embed functions per contract instead.
  const [companyData, setCompanyData] = useState(initialData);
  const [sectionMetas, setSectionMetas] = useState([]);
  const { availableChains, activeChain, isMultichain, rescopeChain } = useChainScope({
    companyData,
    embedded,
  });

  // Derived, not seeded state: the parent's /functions can arrive after mount
  // (a seeded useState stayed empty on hard refresh). Precedence: prop >
  // locally fetched > inline fixtures.
  const [locallyFetched, setLocallyFetched] = useState(null);
  const functionData = useMemo(() => {
    if (initialFunctions && Object.keys(initialFunctions).length > 0) return initialFunctions;
    if (locallyFetched && Object.keys(locallyFetched).length > 0) return locallyFetched;
    const source = companyData?.contracts || initialData?.contracts;
    if (Array.isArray(source) && source.some((c) => Array.isArray(c.functions))) {
      // Composite keys, like the /functions payload: a bare address would let
      // one chain's functions overwrite another's (inv. 13).
      return Object.fromEntries(
        source
          .filter((c) => c.address && coalesceChain(c.chain) === activeChain)
          .map((c) => [entityKey(c.chain, c.address), c.functions || []]),
      );
    }
    return {};
  }, [initialFunctions, locallyFetched, companyData, initialData, activeChain]);
  const [functionsLoading, setFunctionsLoading] = useState(false);
  // The single URL writer: ?sel=<addr> for a committed selection,
  // ?score=1&fn=<sig> for radar. Called only from committing wrappers and the
  // mount restore, never from previews, so it can't race the restore. Drops
  // legacy ?focus/?view on every write.
  const syncUrl = useCallback(({ sel = null, radar: radarSig = null } = {}) => {
    if (embedded) return;
    const url = new URL(window.location.href);
    if (sel) {
      url.searchParams.set("sel", sel);
    } else {
      url.searchParams.delete("sel");
    }
    url.searchParams.delete("view");
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

  // Agent is admin-only and the most useful first stop for admins; everyone
  // else opens in Detail.
  const [sidebarMode, setSidebarMode] = useState(() => (isAdmin ? "agent" : "detail"));
  // Don't leave admin-only content on screen after the key clears.
  useEffect(() => {
    if (!isAdmin && sidebarMode === "agent") {
      setSidebarMode("detail");
    }
  }, [isAdmin, sidebarMode]);
  // Upgrade history per proxy job, fetched lazily: /api/company reports
  // upgrade_count=null until the chain monitor ingests events.
  const [upgradeHistoryCache, setUpgradeHistoryCache] = useState({});
  const cacheUpgradeHistory = useCallback((jobId, history, deps) => {
    if (!jobId) return;
    setUpgradeHistoryCache((prev) => ({ ...prev, [jobId]: { history, deps } }));
  }, []);

  const {
    coverageData,
    coverageError,
    coverageLoading,
    activeAuditId,
    setActiveAuditId,
    auditHighlights,
  } = useAuditCoverage({ companyName, initialCoverage, sidebarMode, activeChain });

  const [agentHighlights, setAgentHighlights] = useState(null);

  const setHighlightedAddresses = setAgentHighlights;

  useEffect(() => {
    if (!companyName) return undefined;
    setError(null);
    setSectionMetas([]);
    let cancelled = false;
    const controller = new AbortController();

    const haveCompanyData = Boolean(initialData);
    const initialFixtureFunctions =
      !initialFunctions &&
      Array.isArray(initialData?.contracts) &&
      initialData.contracts.some((c) => Array.isArray(c.functions));
    const haveFunctions = Boolean(initialFunctions) || initialFixtureFunctions;

    if (haveCompanyData) setCompanyData(initialData);

    // In parallel: /functions is the heavy one (~2 MB).
    if (!haveCompanyData) {
      Promise.all([
        companyApi(`/api/company/${encodeURIComponent(companyName)}`, { signal: controller.signal }),
        companyApi(`/api/company/${encodeURIComponent(companyName)}/summary`, { signal: controller.signal }),
      ]).then(([overview, summary]) => {
        if (!cancelled) setSectionMetas((current) => [...current, overview.meta, summary.meta]);
        return { ...overview.data, ...summary.data };
      })
        .then((d) => {
          if (cancelled) return;
          setCompanyData(d);
          // Legacy/mocked responses embed functions per contract; the
          // functionData memo picks those up.
        })
        .catch((err) => { if (!cancelled) setError(err.message || "Failed to load surface"); });
    }

    if (haveFunctions) {
      setFunctionsLoading(false);
    } else if (embedded) {
      // CompanyOverview already fetches /functions for the embedded surface;
      // wait for the prop rather than doubling the cost. functionsLoading keeps
      // analyzed contracts visible meanwhile.
      setFunctionsLoading(true);
    } else {
      setFunctionsLoading(true);
      companyApi(`/api/company/${encodeURIComponent(companyName)}/functions`, { signal: controller.signal })
        .then(({ data: d, meta }) => {
          if (cancelled) return;
          setSectionMetas((current) => [...current, meta]);
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
      controller.abort();
    };
  }, [companyName, initialData, initialFunctions]);

  const {
    scopedCompanyData,
    allMachines,
    governsIndex,
    controlEdgeIndex,
    scopedFundFlows,
    principalsByAddress,
    entityIndex,
  } = useSurfaceModel({ companyData, functionData, functionsLoading, activeChain, isMultichain });

  const {
    selection,
    radarSelection,
    reachHosts,
    focus,
    selectedMachine,
    selectedPrincipal,
    selectedGuard,
    focusedAddress,
    select,
    guard,
    radar,
    focusPreview,
  } = useSurfaceSelection({ entityIndex, machines: allMachines, companyName, chain: activeChain });

  // Restore the selection from ?sel= (or legacy ?focus=) once machines exist.
  // Legacy ?view= is ignored: the address alone picks the card. ?score deep
  // links are handled by the radar restore.
  const restoredSelection = useRef(false);
  useEffect(() => {
    if (embedded || restoredSelection.current || !allMachines.length) return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("score")) return;
    const addr = params.get("sel") || params.get("focus");
    if (!addr) return;
    restoredSelection.current = true;
    if (entityIndex.get(entityKey(activeChain, addr))) {
      select(addr);
      syncUrl({ sel: addr });
    } else {
      // An unknown address previews; it never synthesizes a junk card.
      focusPreview(addr);
    }
  }, [embedded, allMachines, entityIndex, activeChain, select, focusPreview, syncUrl]);

  // A chain switch rescopes everything: the same address may be a different
  // contract (or absent) on the new chain. ?chain= is omitted for the default.
  const handleSelectChain = useCallback((name) => {
    rescopeChain(name);
    setAgentHighlights(null);
    setActiveAuditId(null);
    select(null);
  }, [rescopeChain, setActiveAuditId, select]);

  const handleSelectMachine = useCallback((machine) => {
    // Every committed transition drops overlay highlights so a stale one can't
    // outrank the new selection's dimming. A plain tab switch keeps the audit
    // pick.
    setAgentHighlights(null);
    setActiveAuditId(null);
    if (machine) {
      select(machine.address);
      syncUrl({ sel: machine.address });
    } else {
      select(null);
      syncUrl({});
    }
  }, [select, syncUrl]);

  // Ignored while a form field has focus.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== "Escape" || !selection) return;
      const t = e.target;
      if (
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          t.tagName === "SELECT" ||
          t.isContentEditable)
      ) {
        return;
      }
      handleSelectMachine(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selection, handleSelectMachine]);

  const handleSelectGuard = useCallback((fnView) => guard(fnView?.key || null), [guard]);

  // Same behaviour as clicking a single-principal guard badge.
  const handleSelectPrincipal = useCallback((principal, reachedFrom = null) => {
    if (!principal) return;
    setAgentHighlights(null);
    setActiveAuditId(null);
    select(principal.address, reachedFrom ? { reachedFrom } : {});
    syncUrl({ sel: principal.address });
  }, [select, syncUrl]);

  const selectMachineExample = useCallback((machine, fnView, callerAddress = null, reachedFrom = null) => {
    setSidebarMode("detail");
    setAgentHighlights(null);
    setActiveAuditId(null);
    radar(machine.address, fnView?.key || null, callerAddress, reachedFrom);
    syncUrl({ sel: machine.address, radar: { signature: fnView?.signature } });
  }, [radar, syncUrl]);

  // The single entrypoint for selections requested from outside the surface
  // (score page, ?score deep link, sessionStorage handoff).
  //
  // Returns a discriminated outcome: function-not-on-contract,
  // name-on-several-contracts and on-another-chain are different facts. A
  // function with no contract resolves only on a unique match
  // (findFunctionMatches). A cross-chain request parks while the chain
  // rescopes, then re-runs.
  const pendingCrossChain = useRef(null);

  const selectExample = useCallback((example) => {
    const address = String(example?.contractAddress || "").toLowerCase();
    const named = Boolean(example?.functionSignature || example?.selector);
    // What the score row was about; it never changes what's selected, and each
    // part must survive a lookup against the card's own lanes to be marked.
    const hint = example?.highlight || null;
    // A merged-unit row names every member; the card's caller list decides
    // which one gates this function.
    const hintedControllers = (
      Array.isArray(hint?.controllers) ? hint.controllers : hint?.controller ? [hint.controller] : []
    )
      .map((address) => String(address || "").toLowerCase())
      .filter(Boolean);
    const findHintedCaller = (fnView) => {
      for (const controller of hintedControllers) {
        const hit = findCaller(fnView, controller);
        if (hit) return hit;
      }
      return null;
    };
    // Lets the card show the route; the route must exist in this graph's own
    // edges.
    const reachedFrom = example?.reachedFrom || null;
    const hintOutcome = (fnView, caller, unpaired = false) =>
      hint
        ? {
            highlight: {
              function: fnView ? "marked" : unpaired ? "unpaired" : "not-on-card",
              controller: caller ? "marked" : hintedControllers.length ? "not-a-caller" : "none",
            },
          }
        : {};
    if (!address && !named) return { ok: false, kind: "empty" };
    // Identity is (chain, address) (inv. 13). Switch chains only when the
    // payload witnesses the entity there; otherwise not-found.
    const requestedChain = coalesceChain(example?.chain || activeChain);
    if (requestedChain !== activeChain) {
      // Otherwise handleSelectChain would silently fall back to the default and
      // "switched" would be a lie.
      const scopable = availableChains.some((c) => c.name === requestedChain);
      // An explicit witness only: principalOnChain's no-list default (every
      // chain) doesn't count.
      const witnessedThere =
        scopable &&
        Boolean(address) &&
        ((companyData?.contracts || []).some(
          (c) => coalesceChain(c.chain) === requestedChain && (c.address || "").toLowerCase() === address,
        ) ||
          (companyData?.principals || []).some(
            (p) =>
              (p.address || "").toLowerCase() === address &&
              Array.isArray(p.chains) &&
              p.chains.some((c) => coalesceChain(c) === requestedChain),
          ));
      if (!witnessedThere) return { ok: false, kind: "not-found" };
      pendingCrossChain.current = example;
      handleSelectChain(requestedChain);
      return { ok: true, kind: "chain-switch", chain: requestedChain };
    }
    if (!address) {
      const matches = findFunctionMatches(allMachines, example);
      if (!matches.length) return { ok: false, kind: "not-found" };
      // Among contracts sharing the name, only the one whose function this
      // controller can call is the charged action.
      const paired = hintedControllers.length ? matches.filter((m) => findHintedCaller(m.fnView)) : [];
      const pool = paired.length ? paired : matches;
      if (pool.length > 1) {
        const hosts = new Set(pool.map((m) => String(m.machine?.address || "").toLowerCase()));
        return { ok: false, kind: "ambiguous-function", count: pool.length, hosts: hosts.size };
      }
      const only = pool[0];
      const matchedCaller = findHintedCaller(only.fnView);
      selectMachineExample(only.machine, only.fnView, matchedCaller, reachedFrom);
      return { ok: true, kind: "function", ...hintOutcome(only.fnView, matchedCaller) };
    }
    const entry = entityIndex.get(entityKey(activeChain, address));
    if (!entry) return { ok: false, kind: "not-found" };
    // Machine facet wins, as in the selection hook.
    if (!entry.machine) {
      if (!entry.principal) return { ok: false, kind: "not-found" };
      setSidebarMode("detail");
      handleSelectPrincipal(entry.principal, reachedFrom);
      return { ok: true, kind: "principal" };
    }
    const machine = entry.machine;
    const fnView = findFunctionView(machine, example);
    // The hinted function and caller are marked together on this card's lanes
    // or not at all: ringing a same-named function under someone else's gate
    // would misattribute the charge.
    let marked = fnView;
    let matchedCaller = findHintedCaller(marked);
    let unpaired = false;
    if (!fnView && hint?.functionSignature) {
      const hinted = findFunctionView(machine, { functionSignature: hint.functionSignature });
      const hintedCaller = findHintedCaller(hinted);
      if (hinted && hintedCaller) {
        marked = hinted;
        matchedCaller = hintedCaller;
      } else if (hinted) {
        unpaired = true;
      }
    }
    selectMachineExample(machine, marked, matchedCaller, reachedFrom);
    // The outcome describes the request, not the hint.
    if (fnView) return { ok: true, kind: "function", ...hintOutcome(marked, matchedCaller) };
    return { ok: true, kind: "contract", functionMissing: named, ...hintOutcome(marked, matchedCaller, unpaired) };
  }, [activeChain, allMachines, availableChains, companyData, entityIndex, handleSelectChain, handleSelectPrincipal, selectMachineExample]);

  useEffect(() => {
    const pending = pendingCrossChain.current;
    if (!pending) return;
    if (coalesceChain(pending.chain || activeChain) !== activeChain) return;
    pendingCrossChain.current = null;
    selectExample(pending);
  }, [activeChain, selectExample]);

  useImperativeHandle(ref, () => ({ selectExample }), [selectExample]);

  const restoredExampleSelection = useRef(false);
  useEffect(() => {
    if (embedded || restoredExampleSelection.current || !allMachines.length) return;
    // Before /functions lands, machines have empty lanes and would answer "not
    // on this contract", latching the wrong result.
    if (functionsLoading) return;
    const params = new URLSearchParams(window.location.search);
    const focus = params.get("sel") || params.get("focus");
    const fn = params.get("fn");
    if (!focus || !params.get("score")) return;
    const target = { contractAddress: focus, functionSignature: fn || "", selector: fn || "" };
    if (
      selectExample({
        contractAddress: target.contractAddress,
        chain: target.chain,
        functionSignature: target.functionSignature || "",
        selector: target.selector || "",
      }).ok
    ) {
      restoredExampleSelection.current = true;
    }
  }, [allMachines, companyName, embedded, functionsLoading, selectExample]);

  const {
    visiblePrincipals,
    highlightedAddresses,
    reachDistances,
    reachPathEdges,
    reachFrontierOnPage,
    nameForAddress,
    reachPath,
  } = useReachOverlay({
    companyData,
    activeChain,
    selection,
    reachHosts,
    allMachines,
    entityIndex,
    controlEdgeIndex,
    auditHighlights,
    agentHighlights,
  });

  // Null clears the focus so a stale ring can't outlive browsing. Stable
  // identity: SearchNavigator's reset effect depends on it.
  const handleSearchPreview = useCallback(
    (item) => focusPreview(item ? item.address : null),
    [focusPreview],
  );

  const handleNavigate = useCallback((target) => {
    // The card follows the target's facets, so a machine-only authority opens
    // its contract card. `hint` lets resolveEntity synthesize a card for
    // off-index targets.
    setSidebarMode("detail");
    setAgentHighlights(null);
    setActiveAuditId(null);
    select(target.address, { hint: { ...target } });
    syncUrl({ sel: target.address });
  }, [select, syncUrl]);

  if (error) return <p className="empty">Failed: {error}</p>;
  if (!companyData) return <p className="empty">Loading surface...</p>;

  // Score arrivals mark the named function row and caller chip on the one card,
  // or nothing if no row answers. Machine-facet only.
  const radarFunctionKey = selectedMachine ? radarSelection?.functionKey || null : null;
  const radarCallerAddress = radarFunctionKey ? radarSelection?.callerAddress || null : null;

  return (
    <div className="ps-surface ps-surface-fullscreen">
      {/*
        Floats like the selection toast so the fullscreen layout keeps its
        height.
      */}
      <StaleBanner metas={sectionMetas} className="company-select-toast" />
      <SurfaceFilterPanel
        machines={allMachines}
        principals={visiblePrincipals}
        availableChains={availableChains}
        activeChain={activeChain}
        isMultichain={isMultichain}
        onSelectChain={handleSelectChain}
        onPreview={handleSearchPreview}
        onCommit={(item) => {
          if (!item) return;
          setAgentHighlights(null);
          setActiveAuditId(null);
          select(item.address);
          syncUrl({ sel: item.address });
        }}
      />

      <div className="ps-layout">
        <ReactFlowProvider>
          <SurfaceCanvas
            machines={allMachines}
            fundFlows={scopedFundFlows}
            principals={visiblePrincipals}
            chain={activeChain}
            selectedAddress={selection?.address}
            focusAddress={focus}
            focusedAddress={focusedAddress}
            highlightedAddresses={highlightedAddresses}
            reachDistances={reachDistances}
            reachPathEdges={reachPathEdges}
            onSelectMachine={(m) => {
              // Canvas clicks switch to Detail so the lanes are visible;
              // agent-link clicks bypass this wrapper so the user stays in
              // chat.
              if (m && sidebarMode !== "detail") setSidebarMode("detail");
              handleSelectMachine(m);
            }}
            onSelectPrincipal={(p) => {
              if (p && sidebarMode !== "detail") setSidebarMode("detail");
              handleSelectPrincipal(p);
            }}
          />
        </ReactFlowProvider>
        <DraggableSidebar>
          <SidebarTabs
            mode={sidebarMode}
            onSetMode={setSidebarMode}
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
              machines={allMachines}
              selectedMachine={selectedMachine}
              selectedPrincipal={selectedPrincipal}
              onClearSelection={() => handleSelectMachine(null)}
              onPreview={(addr) => focusPreview(addr)}
              onNavigate={handleNavigate}
            />
          )}
          {sidebarMode === "activity" && (
            <ActivityPanel
              companyData={companyData}
              companyName={companyName}
              machines={allMachines}
              selectedMachine={selectedMachine}
              selectedPrincipal={selectedPrincipal}
              onSelect={handleSelectMachine}
              onPreview={(addr) => focusPreview(addr)}
              onNavigate={handleNavigate}
              isAdmin={isAdmin}
              cache={upgradeHistoryCache}
              onCache={cacheUpgradeHistory}
              chain={activeChain}
            />
          )}
          {/*
            Machine and principal selections are mutually exclusive, so Detail
            shows the one card or the empty state.
          */}
          {sidebarMode === "detail" && !selectedPrincipal && !selectedMachine && (
            <DetailEmptyState
              companyName={companyName}
              initialScore={initialScore}
              companyData={scopedCompanyData}
              machines={allMachines}
              principals={visiblePrincipals}
              onSelectAddress={select}
            />
          )}
          {sidebarMode === "detail" && (selectedMachine || selectedPrincipal) && (
            <EntityCard
              key={selectedMachine ? selectedMachine.address : selectedPrincipal.address}
              machine={selectedMachine}
              principal={
                selectedMachine
                  ? principalsByAddress.get((selectedMachine.address || "").toLowerCase()) || null
                  : selectedPrincipal
              }
              onSelectGuard={handleSelectGuard}
              onNavigate={handleNavigate}
              onPreview={(addr) => focusPreview(addr)}
              highlightedFunctionKey={radarFunctionKey}
              highlightedCaller={radarCallerAddress}
              governsIndex={governsIndex}
              reachDistances={reachDistances}
              reachFrontierCount={reachFrontierOnPage}
              reachPath={reachPath}
              machines={allMachines}
              chain={activeChain}
              showChain={isMultichain}
            />
          )}
          {sidebarMode === "detail" && selectedMachine && (
            <InspectorCard selected={selectedGuard} onNavigate={handleNavigate} onPreview={(addr) => focusPreview(addr)} />
          )}
          {isAdmin && sidebarMode === "agent" && (
            <AgentPanel
              companyName={companyName}
              selectedMachine={selectedMachine}
              selectedPrincipal={selectedPrincipal}
              onHighlight={setHighlightedAddresses}
              onFocusAddress={(addr) => {
                // Same handlers as a canvas click, for the edge-dimming
                // behaviour.
                const lc = addr.toLowerCase();
                const machine = allMachines.find(
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
                // Off-canvas address (e.g. a Safe owner EOA): highlight every
                // contract it has authority over and dim the rest.
                focusPreview(addr);
                api(
                  `/api/agent/address-touches?company=${encodeURIComponent(companyName)}&address=${encodeURIComponent(addr)}${isMultichain ? `&chain=${encodeURIComponent(activeChain)}` : ""}`,
                )
                  .then((data) => {
                    const set = new Set([lc]);
                    for (const t of data?.touches || []) {
                      if (t.address) set.add(t.address.toLowerCase());
                    }
                    setHighlightedAddresses(set);
                  })
                  .catch(() => {
                    // On error at least light the target.
                    setHighlightedAddresses(new Set([lc]));
                  });
              }}
            />
          )}
        </DraggableSidebar>
      </div>
    </div>
  );
}

export default forwardRef(ProtocolSurface);
