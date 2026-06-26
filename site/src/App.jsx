import React, { Suspense, lazy, useEffect, useRef, useState } from "react";

import { shortenAddress } from "./graph.js";
import { api } from "./api/client.js";
import ProductHero from "./ProductHero.jsx";
import ErrorBoundary from "./ErrorBoundary.jsx";
import HamburgerMenu from "./HamburgerMenu.jsx";
import {
  TABS,
  buildLocationPath,
  isAddress,
  normalizeTab,
  parseLocationPath,
} from "./router.js";
import { displayName } from "./displayName.js";
import SummaryTab from "./tabs/SummaryTab.jsx";
import PermissionsTab from "./tabs/PermissionsTab.jsx";
import PrincipalsTab from "./tabs/PrincipalsTab.jsx";
import UpgradesTab from "./tabs/UpgradesTab.jsx";
import RawTab from "./tabs/RawTab.jsx";
import GraphTab from "./tabs/GraphTab.jsx";
import PipelineDashboard from "./pages/PipelineDashboard.jsx";
import ProtocolMonitoringPage from "./pages/ProtocolMonitoringPage.jsx";
import CompanyOverview from "./pages/CompanyOverview.jsx";
import LoadingFallback from "./LoadingFallback.jsx";
import RunsPage from "./pages/RunsPage.jsx";

// The control surface and dependency graph are heavy — keep them lazy
// so the home page bundle stays slim. ProtocolSurface is also imported
// separately by CompanyOverview; Vite/Rollup dedupe to a single chunk.
const DependencyGraphTab = lazy(() => import("./DependencyGraphTab.jsx"));
const ProtocolSurface = lazy(() => import("./ProtocolSurface.jsx"));

// TODO: replace this with a real sign-in page + session-based auth. Options
// that fit our Fly deployment: (a) an identity-aware proxy sidecar such as
// oauth2-proxy or Pomerium that authenticates real users (Google/GitHub SSO)
// and injects X-PSAT-Admin-Key server-side so the key never touches a browser,
// or (b) an app-level user system with per-user login + roles (fastapi-users,
// a managed provider like WorkOS/Clerk, etc.). The window.prompt +
// localStorage pattern in api/client.js is a stopgap so admins can click
// buttons during local dev and early prod — a shared-secret bearer token
// sitting in every admin's browser, with no per-user audit log and no
// revocation story beyond rotating the key and logging everyone out.

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export default function App() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedDetail, setSelectedDetail] = useState(null);
  const [viewMode, setViewMode] = useState(() => parseLocationPath(window.location.pathname).mode);
  const [companyName, setCompanyName] = useState(() => { const r = parseLocationPath(window.location.pathname); return r.mode === "company" ? r.value : null; });
  const [companyTab, setCompanyTab] = useState(() => parseLocationPath(window.location.pathname).companyTab || "overview");
  const [menuOpen, setMenuOpen] = useState(false);
  // Initialize activeTab from the URL so /address/<addr>/upgrades loads
  // the upgrades tab directly on refresh — otherwise activeTab starts as
  // "summary" and only flips once loadAnalysis resolves, which means
  // UpgradesTab briefly doesn't mount and any URL-dependent tab content
  // can race with loadAnalysis' state batch.
  const [activeTab, setActiveTab] = useState(() => parseLocationPath(window.location.pathname).tab);
  const [job, setJob] = useState(null);
  const [, setActiveJobs] = useState([]);
  const [form, setForm] = useState({ target: "", name: "", chain: "", analyzeLimit: "5" });
  const [formOpen, setFormOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const analysesRef = useRef([]);
  const activeTabRef = useRef(parseLocationPath(window.location.pathname).tab);
  const doneTimerRef = useRef(null);

  useEffect(() => { analysesRef.current = analyses; }, [analyses]);
  useEffect(() => { activeTabRef.current = activeTab; }, [activeTab]);
  useEffect(() => {
    function handleKey(e) { if (e.key === "Escape" && menuOpen) setMenuOpen(false); }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [menuOpen]);

  function navigate(path, mode) {
    const m = mode || parseLocationPath(path).mode;
    setViewMode(m);
    if (m !== "company") setCompanyName(null);
    window.history.pushState({}, "", path);
  }

  function openCompany(name) {
    setCompanyName(name);
    setCompanyTab("overview");
    setViewMode("company");
    window.history.pushState({}, "", `/company/${encodeURIComponent(name)}`);
  }

  function navigateCompanyTab(tab, params = {}) {
    setCompanyTab(tab);
    const suffix = tab === "overview" ? "" : `/${tab}`;
    const query = new URLSearchParams();
    if (params.focus) query.set("focus", params.focus);
    if (params.fn) query.set("fn", params.fn);
    if (params.score) query.set("score", params.score);
    const search = query.toString();
    window.history.pushState({}, "", `/company/${encodeURIComponent(companyName)}${suffix}${search ? `?${search}` : ""}`);
  }

  async function loadAnalysis(runId, options = {}) {
    try {
      const payload = await api(`/api/analyses/${encodeURIComponent(runId)}`);
      const nextTab = normalizeTab(options.tab ?? activeTabRef.current);
      setSelectedRun(runId);
      setSelectedDetail(payload);
      setActiveTab(nextTab);
      setViewMode("run");
      const address = payload?.address || payload?.contract_analysis?.subject?.address;
      const path = buildLocationPath(runId, address, nextTab);
      window.history[options.history === "replace" ? "replaceState" : "pushState"]({}, "", path);
      return payload;
    } catch (err) {
      console.error("Failed to load analysis:", runId, err);
      return null;
    }
  }

  async function refreshAnalyses() {
    const payload = await api("/api/analyses");
    const filtered = payload.filter((a) => a.address);
    setAnalyses(filtered);
    return filtered;
  }

  // Initial load
  useEffect(() => {
    function handlePopState() {
      const route = parseLocationPath(window.location.pathname);
      setViewMode(route.mode);
      if (route.mode === "company") {
        setCompanyName(route.value);
        setCompanyTab(route.companyTab || "overview");
      } else if (route.mode === "run" || route.mode === "address") {
        setCompanyName(null);
        // For /address/<x> we pass the address directly: /api/analyses/<name>
        // falls back to a by-address lookup and returns the run whose primary
        // address is <x>. This bypasses the merged /api/analyses list — which
        // hides the proxy run behind the impl run and would otherwise cause
        // /address/<proxy>/upgrades to load the impl's detail (where the
        // impl run's upgrade_history doesn't include its own proxy chain).
        loadAnalysis(route.value, { tab: route.tab, history: "replace" });
      } else {
        setCompanyName(null);
      }
    }

    refreshAnalyses().catch(() => null);
    const route = parseLocationPath(window.location.pathname);
    if (route.mode === "company") {
      setCompanyName(route.value);
      setCompanyTab(route.companyTab || "overview");
    } else if (route.mode === "run" || route.mode === "address") {
      loadAnalysis(route.value, { tab: route.tab, history: "replace" });
    }

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  // Job polling — scoped to the current submission's job tree
  useEffect(() => {
    if (!job?.job_id) return undefined;
    let stopped = false;
    let timer;

    // Collect all job IDs belonging to this submission's tree
    function getJobTree(allJobs, rootId) {
      const ids = new Set([rootId]);
      let changed = true;
      while (changed) {
        changed = false;
        for (const j of allJobs) {
          if (ids.has(j.job_id)) continue;
          if (ids.has(j.request?.parent_job_id) || ids.has(j.request?.root_job_id)) {
            ids.add(j.job_id);
            changed = true;
          }
        }
      }
      return ids;
    }

    async function poll() {
      if (stopped) return;
      try {
        const allJobs = await api("/api/jobs");
        if (stopped) return;
        const now = new Date();
        const treeIds = getJobTree(allJobs, job.job_id);
        const treeJobs = allJobs.filter((j) => treeIds.has(j.job_id));
        const visible = treeJobs.filter((j) =>
          j.status === "queued" || j.status === "processing" ||
          ((j.status === "completed" || j.status === "failed") && j.updated_at && now - new Date(j.updated_at) < 30000)
        );
        setActiveJobs(visible);
        const parent = allJobs.find((j) => j.job_id === job.job_id);
        if (parent) setJob(parent);
        const stillRunning = treeJobs.some((j) => j.status === "queued" || j.status === "processing");
        if (!stillRunning && !doneTimerRef.current) {
          doneTimerRef.current = setTimeout(async () => {
            stopped = true; clearInterval(timer); setActiveJobs([]); doneTimerRef.current = null;
            await refreshAnalyses();
          }, 5000);
        }
      } catch {}
    }

    poll();
    timer = setInterval(poll, 2000);
    return () => { stopped = true; clearInterval(timer); if (doneTimerRef.current) { clearTimeout(doneTimerRef.current); doneTimerRef.current = null; } };
  }, [job?.job_id]);

  async function submit(event) {
    event.preventDefault();
    if (!form.target) return;
    setLoading(true);
    try {
      const target = form.target.trim();
      const payload = isAddress(target)
        ? { address: target, name: form.name.trim() || null }
        : {
            company: target,
            chain: form.chain.trim() || null,
            analyze_limit: Number.parseInt(form.analyzeLimit, 10) || 5,
          };
      const nextJob = await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      setJob(nextJob);
      setFormOpen(false);
      navigate("/monitor", "monitor");
    } finally { setLoading(false); }
  }

  async function discoverMore(company) {
    try {
      const nextJob = await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ company, analyze_limit: 5 }) });
      setJob(nextJob);
    } catch (err) { console.error("Failed to start discovery:", err); }
  }

  function handleTabChange(tab) {
    const nextTab = normalizeTab(tab);
    setActiveTab(nextTab);
    const address = selectedDetail?.address || selectedDetail?.contract_analysis?.subject?.address;
    const path = buildLocationPath(selectedRun, address, nextTab);
    window.history.pushState({}, "", path);
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  const isDetail = viewMode === "run" || viewMode === "address";
  const isMonitor = viewMode === "monitor";
  const isCompany = viewMode === "company";

  const detailContent = selectedDetail ? {
    summary: <SummaryTab detail={selectedDetail} />,
    permissions: <PermissionsTab detail={selectedDetail} />,
    principals: <PrincipalsTab detail={selectedDetail} />,
    graph: <GraphTab detail={selectedDetail} />,
    dependencies: (
      <Suspense fallback={<LoadingFallback label="Loading graph..." />}>
        <DependencyGraphTab data={selectedDetail?.dependency_graph_viz} runName={selectedRun} />
      </Suspense>
    ),
    upgrades: <UpgradesTab detail={selectedDetail} />,
    raw: <RawTab detail={selectedDetail} />,
  } : {};

  return (
    <ErrorBoundary>
      {/* Top nav */}
      <nav className={`top-nav ${isCompany && companyTab === "surface" ? "top-nav-dark" : ""}`}>
        <div className="top-nav-left">
          <button className="hamburger-btn" onClick={() => setMenuOpen(!menuOpen)} aria-label="Menu">
            <span className="hamburger-icon" />
          </button>
          <button className="top-nav-brand" onClick={() => { navigate("/", "default"); refreshAnalyses(); }}>PSAT</button>
          {companyName && <span className="top-nav-context">{companyName}</span>}
        </div>
        <div className="top-nav-right">
          <button className="top-nav-submit-btn" onClick={() => setFormOpen(!formOpen)}>
            {formOpen ? "Close" : "+ New Analysis"}
          </button>
        </div>
      </nav>

      {/* Hamburger drawer */}
      {menuOpen && (
        <HamburgerMenu
          onClose={() => setMenuOpen(false)}
          viewMode={viewMode}
          companyName={companyName}
          companyTab={companyTab}
          onNavigate={(path, mode) => { navigate(path, mode); refreshAnalyses(); }}
          onNavigateCompanyTab={navigateCompanyTab}
        />
      )}

      {/* Submit form dropdown */}
      {formOpen && (
        <div className="submit-dropdown">
          <form className="submit-form" onSubmit={submit}>
            <label><span>Address or company</span><input value={form.target} onChange={(e) => setForm((c) => ({ ...c, target: e.target.value }))} placeholder="0x... or etherfi" required /></label>
            <label><span>Run name</span><input value={form.name} onChange={(e) => setForm((c) => ({ ...c, name: e.target.value }))} placeholder="Optional" /></label>
            <label><span>Chain</span><input value={form.chain} onChange={(e) => setForm((c) => ({ ...c, chain: e.target.value }))} placeholder="Optional" /></label>
            <label><span>Analyze limit</span><input type="number" min="1" max="200" value={form.analyzeLimit} onChange={(e) => setForm((c) => ({ ...c, analyzeLimit: e.target.value }))} /></label>
            <button type="submit" disabled={loading}>{loading ? "Starting..." : "Run"}</button>
          </form>
        </div>
      )}

      {/* Page content */}
      {isMonitor && <PipelineDashboard />}

      {isDetail && selectedDetail && (
        <div className="page">
          {/* Proxy banner */}
          {(selectedDetail.proxy_address_display || selectedDetail.proxy_address) && (
            <div className="proxy-banner">
              Proxy at <span className="mono">{shortenAddress(selectedDetail.proxy_address_display || selectedDetail.proxy_address)}</span>
              {selectedDetail.proxy_type_display && <span className="chip alt" style={{ marginLeft: 8, padding: "2px 8px", fontSize: 10 }}>{selectedDetail.proxy_type_display}</span>}
              <span style={{ margin: "0 6px" }}>&rarr;</span>
              Implementation at <span className="mono">{shortenAddress(selectedDetail.address)}</span>
            </div>
          )}
          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Contract Analysis</p>
                <h2>{displayName(selectedDetail) || selectedRun || "Unknown"}</h2>
              </div>
              <div className="meta-stack">
                <div className="mono">{selectedDetail.proxy_address_display || selectedDetail.address || ""}</div>
                <div>{selectedDetail.summary?.control_model || selectedDetail.contract_analysis?.summary?.control_model || ""}</div>
              </div>
            </div>
            <div className="tabs">
              {TABS.map((tab) => (
                <button key={tab} className={`tab ${activeTab === tab ? "active" : ""}`} onClick={() => handleTabChange(tab)}>
                  {tab === "raw" ? "Raw JSON" : tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>
            <div className="tab-panel active">{detailContent[activeTab]}</div>
          </section>
        </div>
      )}

      {isCompany && companyName && companyTab === "overview" && (
        <CompanyOverview
          companyName={companyName}
          onSelectContract={(jobId) => loadAnalysis(jobId, { history: "push" })}
          onNavigateToSurface={(params) => navigateCompanyTab("surface", params)}
        />
      )}
      {isCompany && companyName && companyTab === "surface" && (
        <div className="fullscreen-surface">
          <Suspense fallback={<LoadingFallback label="Loading control surface..." />}>
            <ProtocolSurface companyName={companyName} />
          </Suspense>
        </div>
      )}
      {isCompany && companyName && companyTab === "monitoring" && (
        <ProtocolMonitoringPage companyName={companyName} />
      )}

      {!isDetail && !isMonitor && !isCompany && (
        <>
          <ProductHero />
          <RunsPage
            analyses={analyses}
            onSelect={(runId) => loadAnalysis(runId, { history: "push" })}
            onDiscoverMore={discoverMore}
            onSelectCompany={openCompany}
          />
        </>
      )}
    </ErrorBoundary>
  );
}
