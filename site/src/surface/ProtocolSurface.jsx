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

// Audit-coverage highlight set — lives with the coverage hook; re-exported
// here for existing importers (tests target this module's public surface).
export { auditHighlightSet } from "./hooks/useAuditCoverage.js";

// Chain-scope predicate for principals lives in entityKey.js (shared with the
// indirect-caller derivation); re-exported here for existing importers.
export { principalOnChain };

function ProtocolSurface({
  companyName,
  initialData = null,
  initialCoverage = null,
  initialFunctions = null,
  embedded = false,
}, ref) {
  const isAdmin = useIsAdmin();
  // initialData / initialFunctions let a parent (CompanyOverview) hand
  // us the /api/company/{name} payload and /functions map it already
  // fetched, so we don't fire duplicate requests on mount.
  const [companyData, setCompanyData] = useState(initialData);
  const { availableChains, activeChain, isMultichain, rescopeChain } = useChainScope({
    companyData,
    embedded,
  });

  // Derive functionData from props so a CompanyOverview-supplied
  // initialFunctions that arrives AFTER mount (its /functions fetch
  // resolves after /api/company) flows in. The previous
  // useState(initialFunctionData) seeded once and never resynced, so
  // the embedded surface stayed permanently empty on hard refresh.
  // Precedence: prop > locally fetched.
  const [locallyFetched, setLocallyFetched] = useState(null);
  const functionData = useMemo(() => {
    if (initialFunctions && Object.keys(initialFunctions).length > 0) return initialFunctions;
    if (locallyFetched && Object.keys(locallyFetched).length > 0) return locallyFetched;
    return {};
  }, [initialFunctions, locallyFetched]);
  const [functionsLoading, setFunctionsLoading] = useState(false);
  // Single URL writer. Persists a committed selection as ?sel=<addr> — the
  // address alone determines which card renders, so no view axis is stored.
  // Also writes the radar deep-link's ?score=1&fn=<sig>. Called imperatively
  // ONLY from the committing wrappers (select + radar) and the mount restore's
  // URL normalization — never from a focus preview (search browsing / contract
  // pager) and never on plain render. Because it fires only after a user commit
  // (which can only happen after the machines-gated mount restore has run and
  // read the params), it cannot race the restore; no separate write gate is
  // needed beyond the per-restore refs below.
  const syncUrl = useCallback(({ sel = null, radar: radarSig = null } = {}) => {
    if (embedded) return;
    const url = new URL(window.location.href);
    if (sel) {
      url.searchParams.set("sel", sel);
    } else {
      url.searchParams.delete("sel");
    }
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

  // Right sidebar mode: "detail", "agent", "audits", or "activity". Agent is
  // admin-only, so non-admins open in Detail; admins open in Agent (the chat is
  // the most useful first stop). Activity is public (its write controls gate
  // internally). A canvas click switches to Detail in all modes (handlers below).
  const [sidebarMode, setSidebarMode] = useState(() => (isAdmin ? "agent" : "detail"));
  // If the admin key clears while the admin-only Agent tab is open, fall back to
  // Detail so the hidden tab's content can't linger. Activity stays allowed.
  useEffect(() => {
    if (!isAdmin && sidebarMode === "agent") {
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

  const {
    coverageData,
    coverageError,
    coverageLoading,
    activeAuditId,
    setActiveAuditId,
    auditHighlights,
  } = useAuditCoverage({ companyName, initialCoverage, sidebarMode, activeChain });

  // Agent-emitted highlights: addresses the LLM mentioned in its last
  // answer, intersected server-side with the protocol's in-scope contracts.
  // Plain state so AgentPanel can replace it via setHighlightedAddresses.
  const [agentHighlights, setAgentHighlights] = useState(null);

  const setHighlightedAddresses = setAgentHighlights;

  useEffect(() => {
    if (!companyName) return undefined;
    setError(null);
    let cancelled = false;

    const haveCompanyData = Boolean(initialData);
    const haveFunctions = Boolean(initialFunctions);

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

  // Restore a persisted selection from ?sel= on initial data load. The address
  // alone determines the card. A radar deep-link (?score) is
  // left to the radar-restore effect below. Runs once, gated on machines so the
  // entity index can resolve the address; this read happens before any user
  // commit can fire the URL writer, so the writer never clobbers these params
  // first.
  const restoredSelection = useRef(false);
  useEffect(() => {
    if (embedded || restoredSelection.current || !allMachines.length) return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("score")) return;
    const addr = params.get("sel");
    if (!addr) return;
    restoredSelection.current = true;
    if (entityIndex.get(entityKey(activeChain, addr))) {
      select(addr);
      syncUrl({ sel: addr });
    } else {
      // A garbage/off-index address becomes a camera preview, never a
      // synthesized junk selection card.
      focusPreview(addr);
    }
  }, [embedded, allMachines, entityIndex, activeChain, select, focusPreview, syncUrl]);

  // Switching chains rescopes the entire page: clear the selection (the same
  // address can be a different contract — or absent — on the new chain), drop
  // overlay highlights, and write the shareable ?chain= param (omitted for the
  // default chain so those links stay clean). The URL selection params are
  // cleared alongside since they refer to the old chain's entity.
  const handleSelectChain = useCallback((name) => {
    rescopeChain(name);
    setAgentHighlights(null);
    setActiveAuditId(null);
    select(null);
  }, [rescopeChain, setActiveAuditId, select]);

  const handleSelectMachine = useCallback((machine) => {
    // Any committed selection transition drops the overlay highlights — the
    // agent green-ring set AND the picked-audit set. Clearing belongs to the
    // transition, not just the deselect, so a stale highlight can't outrank the
    // new selection's dimming. (A plain tab-switch keeps the audit pick so
    // returning to Audits re-lights it; committing to an entity ends it.)
    setAgentHighlights(null);
    setActiveAuditId(null);
    if (machine) {
      select(machine.address);
      syncUrl({ sel: machine.address });
    } else {
      // Pane click / deselect — full clear.
      select(null);
      syncUrl({});
    }
  }, [select, syncUrl]);

  // Escape clears the committed selection — the same full clear a pane click
  // does, just discoverable from the keyboard. Ignored while a form field has
  // focus so it never fights the search input's own key handling.
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

  // Clicking a Safe/Timelock/EOA node on the canvas selects the principal
  // (opens the detail panel with signers / delay / controlled contracts)
  // and focuses it — same behaviour as clicking a single-principal guard
  // badge, just driven from the node itself.
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

  // The single entrypoint for a selection requested from outside the surface:
  // the score page's entity buttons (through the imperative handle below), the
  // ?score deep link and the sessionStorage handoff all land here, so no caller
  // carries its own copy of the selection transition.
  //
  // The result is a discriminated outcome, never a bare boolean: "selected the
  // contract but the named function is not on it", "that name is on several
  // contracts" and "that entity is on another chain" are three different facts
  // and a caller that collapses them tells the user something untrue. A request
  // that names a function but no contract is resolved against the whole graph,
  // and only a unique match selects — see findFunctionMatches.
  // A cross-chain request parks here while handleSelectChain re-scopes the
  // graph; the effect below selectExample re-runs it once the active chain
  // matches, on the freshly scoped entity index.
  const pendingCrossChain = useRef(null);

  const selectExample = useCallback((example) => {
    const address = String(example?.contractAddress || "").toLowerCase();
    const named = Boolean(example?.functionSignature || example?.selector);
    // The optional highlight hint: what the score row was ABOUT (its example
    // function and the controller it named), as opposed to what the click asked
    // to select. It never changes which entity is selected or what the outcome
    // is called — it only says what to mark once the card is up, and every part
    // of it has to survive a lookup against that card's own lanes to be marked.
    const hint = example?.highlight || null;
    // One controller or several: a merged-unit row names every member, and
    // which member gates THIS card's function is the card's own fact — the
    // caller list decides, never the hint's ordering.
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
    // Where the request says this entity was REACHED FROM (a score-page click on
    // a transitive target names the host the controller acts on directly). Like
    // the hint it never changes which entity is selected or what the outcome is
    // called — it only lets the card show the route, and the route still has to
    // exist in this graph's own control edges to be shown.
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
    // Identity is (chain, address) (inv. 13) and the surface renders one chain
    // at a time. Another chain's entity is not a miss when the payload
    // witnesses it there: switch the page's scope to that chain and park the
    // request — the effect below re-runs it once the graph has re-scoped, so
    // there is never a second copy of the selection logic. A chain the payload
    // does NOT witness the entity on refuses as not-found: "it is on that
    // chain" is exactly the claim this graph cannot make.
    const requestedChain = coalesceChain(example?.chain || activeChain);
    if (requestedChain !== activeChain) {
      // The page can only scope to a chain it has contracts on — outside that,
      // handleSelectChain would silently degrade to the default and the
      // "switched" outcome would be a lie.
      const scopable = availableChains.some((c) => c.name === requestedChain);
      // The witness must be explicit: a contract row on that chain, or a
      // principal whose OWN chains list names it. principalOnChain's
      // legacy-payload default (no list → every chain) is exactly the
      // default-as-witness shape this check exists to refuse.
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
      // The hinted controller narrows a shared name to the witnessed pair: the
      // graph lists callers per function, so among the contracts carrying this
      // name, the one whose function this controller can actually call IS the
      // action the score row charged — same-named functions under someone
      // else's gate are different actions and never candidates.
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
    // Machine facet wins over principal — same precedence the selection hook
    // applies, so a timelock contract opens the richer card either way.
    if (!entry.machine) {
      if (!entry.principal) return { ok: false, kind: "not-found" };
      setSidebarMode("detail");
      handleSelectPrincipal(entry.principal, reachedFrom);
      return { ok: true, kind: "principal" };
    }
    const machine = entry.machine;
    const fnView = findFunctionView(machine, example);
    // A contract click carries no function of its own, so the hinted example
    // function is resolved against THIS card's lanes — and only as the whole
    // pair. A same-named function the hinted controller cannot call is a
    // different action under someone else's gate; ringing it would present
    // that gate as the one the points were charged for. Function and caller
    // are marked together or not at all — an unmarkable hint opens the card
    // with nothing marked, and the caller's `unpaired` outcome says why.
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
    // The outcome describes the request the caller made, not the hint: a click
    // that asked for a contract landed on a contract even when the hint marked
    // a row inside it.
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
    // Machines exist before /functions lands, and a machine with empty lanes
    // answers "that function is not on this contract" — which would restore the
    // contract alone and latch, losing the named function the link carried.
    if (functionsLoading) return;
    const params = new URLSearchParams(window.location.search);
    const focus = params.get("sel");
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

  // Search browse preview. Null (result set changed / emptied) clears the
  // focus address so a stale gold ring can't outlive the browsing session —
  // the committed selection is untouched either way. Stable identity:
  // SearchNavigator's reset effect lists it as a dependency.
  const handleSearchPreview = useCallback(
    (item) => focusPreview(item ? item.address : null),
    [focusPreview],
  );

  const handleNavigate = useCallback((target) => {
    // Surface the navigation result in the Detail panel. The card is chosen from
    // the target's facets, not the caller's guessed type — a machine-only
    // authority (e.g. an analyzed timelock the server never emits as a
    // principal) opens its contract card instead of stranding an empty sidebar.
    // The full target rides along as `hint` so resolveEntity can read its type
    // to synthesize a principal card for off-index targets. The card opens on
    // its default tab — same as clicking the node on the canvas.
    setSidebarMode("detail");
    setAgentHighlights(null);
    setActiveAuditId(null);
    select(target.address, { hint: { ...target } });
    syncUrl({ sel: target.address });
  }, [select, syncUrl]);

  if (error) return <p className="empty">Failed: {error}</p>;
  if (!companyData) return <p className="empty">Loading surface...</p>;

  // Score-page arrivals (radar sub-mode) mark the action the warning was about
  // on the ONE sidebar card, never a second parallel card. The mark is the
  // PAIR the warning named — the function row and, inside it, the caller chip
  // for the controller the row named — or nothing: when no row answers to the
  // name the card simply opens unmarked. A principal-only selection never
  // enters radar mode (it commits through select), so these are machine-facet
  // only.
  const radarFunctionKey = selectedMachine ? radarSelection?.functionKey || null : null;
  const radarCallerAddress = radarFunctionKey ? radarSelection?.callerAddress || null : null;

  return (
    <div className="ps-surface ps-surface-fullscreen">
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
          {/* One universal card for every selection. selectedMachine and
              selectedPrincipal are mutually exclusive (the selection invariant),
              so the Detail panel is: something selected → the card; nothing →
              the empty state. A score-page arrival lands here too — same card,
              with the highlight props set. */}
          {sidebarMode === "detail" && !selectedPrincipal && !selectedMachine && (
            <DetailEmptyState
              companyName={companyName}
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
                // Route through the same selection handlers a canvas
                // click uses so we get the connected-edges-stay-bright
                // dim behavior for free.
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
                // Out-of-scope address (typical: an EOA that's a Safe
                // owner / role holder but not itself a canvas node).
                // Fetch its "touch radius" — every contract it has
                // function-level authority over — and write that set
                // into highlightedAddresses. The canvas's existing
                // audit-overlay dim path then dims everything else.
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
                    // Network/auth error — at least light up the focus
                    // target so the click isn't a no-op.
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
