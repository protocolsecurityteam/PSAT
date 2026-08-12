import { forwardRef, useCallback, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { isBytecodeVerifiedAudit } from "./auditCoverage.js";
import { api } from "./api/client.js";
import { useIsAdmin } from "./api/useIsAdmin.js";
import { getCoverage } from "./api/audits.js";
import { AgentPanel } from "./surface/inspector/AgentPanel.jsx";
import { isRoleIdAddress, principalLabel, shortAddr } from "./surface/format.js";
import { findCaller, findFunctionMatches, findFunctionView } from "./surface/lane.js";
import { buildMachines } from "./surface/layout/buildMachines.js";
import { buildGovernsIndex } from "./surface/layout/governsIndex.js";
import {
  buildControlEdgeIndex,
  edgeClaims,
  flowOnChain,
  shortestControlPath,
} from "./surface/layout/governancePath.js";
import { deriveReachOverlay } from "./surface/layout/serverReach.js";
import { buildEntityIndex } from "./surface/layout/entities.js";
import { useSurfaceSelection } from "./surface/useSurfaceSelection.js";
import { coalesceChain, entityKey, principalOnChain } from "./surface/entityKey.js";
import { chainColor, chainLabel } from "./surface/chainMeta.js";
import { deriveAvailableChains, defaultChainFor, pickActiveChain } from "./surface/chainScope.js";
import { SurfaceCanvas } from "./surface/canvas/SurfaceCanvas.jsx";
import { ChainSwitcher } from "./surface/sidebar/ChainSwitcher.jsx";
import { EntityCard } from "./surface/lanes/EntityCard.jsx";
import { AuditsListPanel } from "./surface/sidebar/AuditsListPanel.jsx";
import { DetailEmptyState } from "./surface/sidebar/DetailEmptyState.jsx";
import { DraggableSidebar } from "./surface/sidebar/DraggableSidebar.jsx";
import { InspectorCard } from "./surface/sidebar/InspectorCard.jsx";
import { SidebarTabs } from "./surface/sidebar/SidebarTabs.jsx";
import { ActivityPanel } from "./surface/sidebar/activity/ActivityPanel.jsx";
import { SearchModesBar } from "./surface/sidebar/search/SearchModesBar.jsx";
import { SearchNavigator } from "./surface/sidebar/search/SearchNavigator.jsx";

// Audit-coverage highlight set: the bytecode-verified-covered contracts for the
// active audit pick (or the whole proven set when ``all``). Returns a Set of
// bare lowercased addresses matched against the canvas's bare node ids. Coverage
// rows are all-chain; only the active chain's rows contribute, so a twin covered
// solely on another chain does NOT light this chain's same-address node (inv. 13).
export function auditHighlightSet(coverage, activeAuditId, activeChain) {
  const showAll = activeAuditId === "all";
  const out = new Set();
  for (const entry of coverage || []) {
    const addr = (entry.address || "").toLowerCase();
    if (!addr) continue;
    if (activeChain && coalesceChain(entry.chain) !== activeChain) continue;
    if ((entry.audits || []).some((a) => isBytecodeVerifiedAudit(a) && (showAll || a.audit_id === activeAuditId))) {
      out.add(addr);
    }
  }
  return out.size ? out : null;
}

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
  // fetched, so we don't fire duplicate requests on mount. Fixtures
  // (vitest, e2e) still embed functions on each contract entry, so
  // fall back to those when neither prop is provided.
  const [companyData, setCompanyData] = useState(initialData);
  // Active-chain scope for the whole page (multichain inv. 13). The Surface
  // renders exactly one chain at a time; `chosenChain` is the user's explicit
  // pick (via the switcher), seeded once from the shareable ?chain= URL param.
  // null = follow the default chain. Read synchronously at mount so the first
  // render is already scoped correctly (no effect race with the selection
  // restore, which is gated on the resulting machines).
  const [chosenChain, setChosenChain] = useState(() => {
    if (embedded || typeof window === "undefined") return null;
    const ch = new URLSearchParams(window.location.search).get("chain");
    return ch ? coalesceChain(ch) : null;
  });

  // Chains this protocol actually has contracts on — derived from the loaded
  // payload (only contracts carry a chain; NULL coalesces to ethereum), never a
  // static list. The switcher offers exactly these; a single-chain protocol
  // yields one entry and no switcher. See chainScope.js. Declared before
  // functionData so the inline-functions map can be chain-scoped too.
  const availableChains = useMemo(
    () => deriveAvailableChains(companyData?.contracts),
    [companyData]
  );
  // The chain the page falls back to with no explicit pick — kept out of the
  // URL so single-chain and default-chain views have clean links.
  const defaultChain = useMemo(() => defaultChainFor(availableChains), [availableChains]);
  // An unknown/typo'd/off-protocol ?chain= degrades to the default (never a
  // blank canvas) — pickActiveChain enforces that.
  const activeChain = useMemo(
    () => pickActiveChain(availableChains, chosenChain),
    [availableChains, chosenChain]
  );
  const isMultichain = availableChains.length > 1;

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
      // Key by the composite (chain, address) token — uniform with the
      // /functions endpoint payload (initialFunctions/locallyFetched), which is
      // now composite-keyed too. Two chains can share an address, so a bare key
      // would last-wins one chain's functions onto the other (inv. 13). The
      // per-chain filter is redundant given the composite key but kept so the
      // inline fixture map stays scoped to what the canvas renders.
      return Object.fromEntries(
        source
          .filter((c) => c.address && coalesceChain(c.chain) === activeChain)
          .map((c) => [entityKey(c.chain, c.address), c.functions || []]),
      );
    }
    return {};
  }, [initialFunctions, locallyFetched, companyData, initialData, activeChain]);
  const [functionsLoading, setFunctionsLoading] = useState(false);
  // Search mode lives on the parent so the mode-pill bar can render at
  // top-left while the rest of SearchNavigator stays in the centre overlay.
  const [searchMode, setSearchMode] = useState("contracts");
  // Single URL writer. Persists a committed selection as ?sel=<addr> — the
  // address alone determines which card renders, so no view axis is stored.
  // Also writes the radar deep-link's ?score=1&fn=<sig>. Called imperatively
  // ONLY from the committing wrappers (select + radar) and the mount restore's
  // URL normalization — never from a focus preview (search browsing / contract
  // pager) and never on plain render. Because it fires only after a user commit
  // (which can only happen after the machines-gated mount restore has run and
  // read the params), it cannot race the restore; no separate write gate is
  // needed beyond the per-restore refs below. Legacy ?focus and ?view are
  // dropped on every write so old-style params don't linger next to ?sel.
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
    // The audit overlay is a function of the Audits tab being open: leaving the
    // tab suppresses it, but activeAuditId is kept so returning re-lights the
    // same pick (persist-on-return). `"all"` is the summary's whole-proven-set
    // highlight; a numeric id is one audit's covered set. Both are one radio —
    // see AuditsListPanel. A committed selection clears activeAuditId (below).
    if (activeAuditId == null || !coverageData || sidebarMode !== "audits") return null;
    return auditHighlightSet(coverageData.coverage, activeAuditId, activeChain);
  }, [activeAuditId, coverageData, sidebarMode, activeChain]);

  const setHighlightedAddresses = setAgentHighlights;

  // The filter panel starts collapsed — it is large, and at first glance the
  // canvas matters more. Nothing in it hides nodes (the Type modes only scope
  // the search), so collapsing it conceals no active state.
  const [filtersOpen, setFiltersOpen] = useState(false);

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

  // Chain-scope every downstream derivation: only the active chain's contracts
  // build machines, so the canvas/selection/entity-index all operate on a
  // single-chain dataset. Principals (chains) and fund_flows (from_chain/
  // to_chain) carry their own chain fields, consumed by principalOnChain and
  // flowOnChain; visiblePrincipals keeps only principals that
  // control a visible (now chain-scoped) machine, and elkLayout keeps only
  // flows whose endpoints are visible contracts.
  const scopedCompanyData = useMemo(() => {
    if (!companyData) return null;
    if (!isMultichain) return companyData; // single chain: no filtering, identical to before
    return {
      ...companyData,
      contracts: (companyData.contracts || []).filter(
        (c) => coalesceChain(c.chain) === activeChain,
      ),
    };
  }, [companyData, isMultichain, activeChain]);

  const allMachines = useMemo(
    () => (scopedCompanyData ? buildMachines(scopedCompanyData, functionData, { functionsLoading, activeChain }) : []),
    [scopedCompanyData, functionData, functionsLoading, activeChain]
  );


  // Authority-OUT index for the contract card's Governs tab: authority address
  // → the contracts + functions it can call. Built once over ALL machines /
  // functions (visibility-agnostic, like the entity index) so a role-filtered
  // target still resolves. Memoized here — never per-render inside the card.
  const governsIndex = useMemo(
    () => buildGovernsIndex(allMachines, functionData),
    [allMachines, functionData]
  );

  // Same control edges, keyed so a hop can name itself (type + the witnessed
  // relation/role label the payload carries). Feeds the reached-from path block
  // on the entity card; built once here, never per render inside it.
  const controlEdgeIndex = useMemo(
    () => buildControlEdgeIndex(companyData?.fund_flows || [], activeChain),
    [companyData, activeChain]
  );

  // Fund flows feeding the canvas are chain-scoped like the principals + the
  // edge index: SurfaceCanvas draws contract→contract edges keyed by bare
  // address, so a same-address twin's flow on another chain must not draw onto
  // this chain's nodes (inv. 13). Same predicate the edge index uses.
  const scopedFundFlows = useMemo(
    () => (companyData?.fund_flows || []).filter((f) => flowOnChain(f, activeChain)),
    [companyData, activeChain]
  );

  // Principal facet by address — lets a dual-facet contract card render its
  // principal strip + capability tags. Most contracts have no entry (null).
  // Chain-scoped: a principal governs on the chain(s) in its ``chains`` list
  // (backend-added), so one observed only on another chain must not attach to a
  // same-address contract card here (inv. 13). Legacy principals without
  // ``chains`` are kept as before.
  const principalsByAddress = useMemo(() => {
    const map = new Map();
    for (const p of companyData?.principals || []) {
      const addr = (p.address || "").toLowerCase();
      if (!addr) continue;
      if (!principalOnChain(p, activeChain)) continue;
      map.set(addr, p);
    }
    return map;
  }, [companyData, activeChain]);

  // Address-keyed entity index over ALL machines + ALL principals (no
  // visibility filtering). Selection state stores addresses only and resolves
  // entities through this index per render, so denormalized snapshots can
  // never go stale and role-filtered-off targets still resolve.
  const entityIndex = useMemo(
    () => buildEntityIndex(allMachines, companyData?.principals || [], activeChain),
    [allMachines, companyData, activeChain]
  );

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

  // Restore a persisted selection from the URL on initial data load. Reads
  // ?sel=, falling back to the legacy ?focus= param so old links still resolve.
  // A legacy ?view= is parsed and IGNORED — the address alone determines the
  // card now, which also un-breaks old ?sel=<addr>&view=principal links whose
  // stored view contradicted the entity's facets. A radar deep-link (?score) is
  // left to the radar-restore effect below. Runs once, gated on machines so the
  // entity index can resolve the address; this read happens before any user
  // commit can fire the URL writer, so the writer never clobbers these params
  // first.
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
    setChosenChain(name);
    setAgentHighlights(null);
    setActiveAuditId(null);
    select(null);
    if (embedded || typeof window === "undefined") return;
    const url = new URL(window.location.href);
    if (name && name !== defaultChain) url.searchParams.set("chain", name);
    else url.searchParams.delete("chain");
    url.searchParams.delete("sel");
    url.searchParams.delete("score");
    url.searchParams.delete("fn");
    window.history.replaceState({}, "", url.toString());
  }, [embedded, defaultChain, select]);

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
    const hintedController = String(hint?.controller || "").toLowerCase() || null;
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
              controller: caller ? "marked" : hintedController ? "not-a-caller" : "none",
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
      const paired = hintedController ? matches.filter((m) => findCaller(m.fnView, hintedController)) : [];
      const pool = paired.length ? paired : matches;
      if (pool.length > 1) {
        const hosts = new Set(pool.map((m) => String(m.machine?.address || "").toLowerCase()));
        return { ok: false, kind: "ambiguous-function", count: pool.length, hosts: hosts.size };
      }
      const only = pool[0];
      const matchedCaller = findCaller(only.fnView, hintedController);
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
    let matchedCaller = findCaller(marked, hintedController);
    let unpaired = false;
    if (!fnView && hint?.functionSignature) {
      const hinted = findFunctionView(machine, { functionSignature: hint.functionSignature });
      const hintedCaller = findCaller(hinted, hintedController);
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

  const visiblePrincipals = useMemo(() => {
    const visibleAddrs = new Set(allMachines.map((m) => m.address?.toLowerCase()));
    // Chain-scope first: a principal observed only on another chain must not
    // ride in on a same-address twin among the (chain-scoped) visible machines
    // (inv. 13). Legacy principals without ``chains`` behave as before.
    return (companyData?.principals || []).filter((p) =>
      !isRoleIdAddress(p.address || "") &&
      principalOnChain(p, activeChain) &&
      (p.controls || []).some((a) => visibleAddrs.has(a.toLowerCase()))
    );
  }, [allMachines, companyData, activeChain]);

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

  // Reach overlay for the SELECTED entity: the SERVER's reach record
  // (companyData.reach, model scorer_closure_v1) — the scorer's own walk,
  // shipped as three distinct states. The client renders; it never re-derives.
  // An absent block or absent entity yields null everything: absence of the
  // witness is not reach (fail closed).
  const reachOverlay = useMemo(
    () => deriveReachOverlay(companyData?.reach, activeChain, selection?.address),
    [companyData, activeChain, selection],
  );
  // Walked state: hop distances the canvas chips show.
  const reachDistances = reachOverlay?.distances.size ? reachOverlay.distances : null;
  // The routes behind those hop counts, reconstructed from the server's
  // `parents` tree. The canvas lights the drawn edges matching these pairs, so
  // a "reach · 3 hops" chip has a visible line back to the selection rather
  // than asking the reader to take the number on faith. Synthesizes nothing —
  // a pair with no drawn edge (an intra-group hop inside a collapsed box)
  // simply lights nothing.
  const reachPathEdges = reachOverlay?.pathEdges.size ? reachOverlay.pathEdges : null;
  // not_determined frontier: destination → the scorer's refusal entry. A
  // distinct third state, never merged into reachDistances — and deliberately
  // NOT rendered on the canvas (owner ruling 2026-08-12: the graph shows
  // proven reach only; the unknowns' home is the score page's confidence zone
  // and the Governs tab's count line below).
  const reachFrontier = reachOverlay?.frontier.size ? reachOverlay.frontier : null;
  // The sidebar's unconfirmed count names only destinations the reader can
  // LOCATE — ones with a node on this page. The server's frontier also names
  // off-page destinations (the scorer's graph is wider than the payload's
  // contract list); advertising those as findable rows would send the reader
  // hunting for nodes the canvas cannot show.
  const reachFrontierOnPage = useMemo(() => {
    if (!reachFrontier) return 0;
    const onPage = new Set(allMachines.map((m) => m.address?.toLowerCase()));
    for (const p of visiblePrincipals) onPage.add((p.address || "").toLowerCase());
    let count = 0;
    for (const addr of reachFrontier.keys()) if (onPage.has(addr)) count += 1;
    return count;
  }, [reachFrontier, allMachines, visiblePrincipals]);

  // Human name for an address on this graph: the contract's, else the
  // principal's, else the short address. Never a bare "unknown" — the short
  // address IS the identity when nothing else names it.
  const nameForAddress = useCallback((addr) => {
    const lc = String(addr || "").toLowerCase();
    if (!lc) return "";
    const entry = entityIndex.get(entityKey(activeChain, lc));
    if (entry?.machine?.name) return entry.machine.name;
    if (entry?.principal) return principalLabel(entry.principal.label, entry.principal.type, lc);
    return shortAddr(lc);
  }, [entityIndex, activeChain]);

  // The route a score-page click-through took to this entity: the deduction row
  // named a host the controller acts on DIRECTLY, and this contract only through
  // the control graph. Walked over the same edges the canvas reach chips use, so the
  // card and the graph cannot disagree. A route this graph does not carry stays
  // an explicit third state (hops: null) — the card says so rather than drawing
  // a shorter path than the truth.
  const reachPath = useMemo(() => {
    const target = selection?.address;
    if (!reachHosts?.length || !target) return null;
    const hostNames = reachHosts.map(nameForAddress);
    const { host, hops } = shortestControlPath(reachHosts, target, controlEdgeIndex);
    if (!hops) return { host: null, hostName: null, hostNames, hops: null };
    if (!hops.length) return null; // the click landed on the host itself
    return {
      host,
      hostName: nameForAddress(host),
      hostNames,
      hops: hops.map((hop) => ({
        from: hop.from,
        to: hop.to,
        fromName: nameForAddress(hop.from),
        toName: nameForAddress(hop.to),
        type: hop.flow?.type || null,
        claims: edgeClaims(hop.flow),
      })),
    };
  }, [reachHosts, selection, controlEdgeIndex, nameForAddress]);

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
      {/* Unified filter panel — top-left. Search + sort + browse nav, then the
          Type filter and Role visibility rows (injected as children), then the
          browse preview. Collapsed to a pill by default — the full panel is
          large and competes with the selection legend on narrow embeds. The
          pill IS the toggle and sits in the same top-left spot in both states;
          collapsed, it wears the active chain (multichain pages — chain scope
          must not be silently hidden behind an unopened panel). */}
      <div className={`ps-filter-overlay${filtersOpen ? "" : " ps-filter-overlay--collapsed"}`}>
        <button
          type="button"
          className="ps-filter-pill"
          onClick={() => {
            if (filtersOpen) {
              // Unmounting the navigator skips its preview cleanup — drop any
              // lingering browse marker along with the panel.
              handleSearchPreview(null);
            }
            setFiltersOpen((was) => !was);
          }}
          aria-expanded={filtersOpen}
          aria-label={filtersOpen ? "Collapse filters" : "Open search and filters"}
        >
          Filters <span className="ps-filter-chev" aria-hidden="true">{filtersOpen ? "▴" : "▾"}</span>
          {!filtersOpen && isMultichain && (
            <span className="ps-filter-chain">
              <span className="ps-chain-dot" style={{ "--chain-color": chainColor(activeChain) }} />
              {chainLabel(activeChain)}
            </span>
          )}
        </button>
        {filtersOpen && (
        <SearchNavigator
          machines={allMachines}
          principals={visiblePrincipals}
          mode={searchMode}
          onPreview={handleSearchPreview}
          onCommit={(item) => {
            if (!item) return;
            setAgentHighlights(null);
            setActiveAuditId(null);
            select(item.address);
            syncUrl({ sel: item.address });
          }}
        >
          {/* Chain row renders only for multi-chain protocols (inv. 13);
              single-chain pages show no chain UI at all. */}
          <ChainSwitcher chains={availableChains} active={activeChain} onSelect={handleSelectChain} />
          <div className="ps-filter-row">
            <span className="ps-filter-gutter">Type</span>
            <SearchModesBar mode={searchMode} setMode={setSearchMode} />
          </div>
        </SearchNavigator>
        )}
      </div>

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
