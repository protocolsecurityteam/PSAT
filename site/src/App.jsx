import React, { Suspense, lazy, useEffect, useRef, useState } from "react";

import { api, getAdminKey, setAdminKey } from "./api/client.js";
import { useIsAdmin } from "./api/useIsAdmin.js";
import ProductHero from "./ProductHero.jsx";
import ErrorBoundary from "./ErrorBoundary.jsx";
import HamburgerMenu from "./HamburgerMenu.jsx";
import { isAddress, parseLocationPath } from "./router.js";
import PipelineDashboard from "./pages/PipelineDashboard.jsx";
import CompanyOverview from "./pages/CompanyOverview.jsx";
import LoadingFallback from "./LoadingFallback.jsx";
import RunsPage from "./pages/RunsPage.jsx";

// Lazy so the home bundle stays slim; Vite dedupes it with CompanyOverview's
// import.
const ProtocolSurface = lazy(() => import("./surface/ProtocolSurface.jsx"));

// TODO: replace with real sign-in (an identity-aware proxy like oauth2-proxy
// injecting the admin key server-side, or per-user login + roles). The prompt +
// localStorage key in api/client.js is a stopgap: a shared secret in every
// admin's browser, no per-user audit, no revocation short of rotating the key.


export default function App() {
  const [analyses, setAnalyses] = useState([]);
  const [viewMode, setViewMode] = useState(() => parseLocationPath(window.location.pathname).mode);
  const [companyName, setCompanyName] = useState(() => { const r = parseLocationPath(window.location.pathname); return r.mode === "company" ? r.value : null; });
  const [companyTab, setCompanyTab] = useState(() => parseLocationPath(window.location.pathname).companyTab || "overview");
  const [menuOpen, setMenuOpen] = useState(false);
  const [job, setJob] = useState(null);
  const [, setActiveJobs] = useState([]);
  const [form, setForm] = useState({ target: "", name: "", chain: "", analyzeLimit: "5" });
  const [formOpen, setFormOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const analysesRef = useRef([]);
  const doneTimerRef = useRef(null);
  const isAdmin = useIsAdmin();

  // ?admin=1 prompts once for a key; the only key-entry path now that operator
  // controls are hidden.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("admin") === "1" && !getAdminKey()) {
      const entered = window.prompt("Paste your PSAT admin key:");
      if (entered) setAdminKey(entered);
    }
  }, []);

  useEffect(() => { analysesRef.current = analyses; }, [analyses]);
  useEffect(() => {
    function handleKey(e) { if (e.key === "Escape" && menuOpen) setMenuOpen(false); }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [menuOpen]);

  // /monitor is operator-only.
  useEffect(() => {
    if (viewMode === "monitor" && !isAdmin) navigate("/", "default");
  }, [viewMode, isAdmin]);

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

  function navigateCompanyTab(tab) {
    setCompanyTab(tab);
    const suffix = tab === "overview" ? "" : `/${tab}`;
    window.history.pushState({}, "", `/company/${encodeURIComponent(companyName)}${suffix}`);
  }

  async function refreshAnalyses() {
    const payload = await api("/api/analyses");
    const filtered = payload.filter((a) => a.address);
    setAnalyses(filtered);
    return filtered;
  }

  useEffect(() => {
    function handlePopState() {
      const route = parseLocationPath(window.location.pathname);
      setViewMode(route.mode);
      if (route.mode === "company") {
        setCompanyName(route.value);
        setCompanyTab(route.companyTab || "overview");
      } else {
        setCompanyName(null);
      }
    }

    refreshAnalyses().catch(() => null);
    const route = parseLocationPath(window.location.pathname);
    if (route.mode === "company") {
      setCompanyName(route.value);
      setCompanyTab(route.companyTab || "overview");
    }

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  // Scoped to the current submission's job tree.
  useEffect(() => {
    if (!job?.job_id) return undefined;
    let stopped = false;
    let timer;

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
        const allJobs = await api("/api/jobs", { silent: true });
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


  const isMonitor = viewMode === "monitor";
  const isCompany = viewMode === "company";

  return (
    <ErrorBoundary>
      <nav className={`top-nav ${isCompany && companyTab === "surface" ? "top-nav-dark" : ""}`}>
        <div className="top-nav-left">
          <button className="hamburger-btn" onClick={() => setMenuOpen(!menuOpen)} aria-label="Menu">
            <span className="hamburger-icon" />
          </button>
          <button className="top-nav-brand" onClick={() => { navigate("/", "default"); refreshAnalyses(); }}>PSAT</button>
          {companyName && <span className="top-nav-context">{companyName}</span>}
        </div>
        <div className="top-nav-right">
          {isAdmin && isMonitor && (
            <button className="btn top-nav-submit-btn" onClick={() => setFormOpen(!formOpen)}>
              {formOpen ? "Close" : "+ New Analysis"}
            </button>
          )}
        </div>
      </nav>

      {menuOpen && (
        <HamburgerMenu
          onClose={() => setMenuOpen(false)}
          viewMode={viewMode}
          companyName={companyName}
          companyTab={companyTab}
          isAdmin={isAdmin}
          onNavigate={(path, mode) => { navigate(path, mode); refreshAnalyses(); }}
          onNavigateCompanyTab={navigateCompanyTab}
        />
      )}

      {isAdmin && isMonitor && formOpen && (
        <div className="submit-dropdown">
          <form className="submit-form" onSubmit={submit}>
            <label><span>Address or company</span><input value={form.target} onChange={(e) => setForm((c) => ({ ...c, target: e.target.value }))} placeholder="0x... or etherfi" required /></label>
            <label><span>Run name</span><input value={form.name} onChange={(e) => setForm((c) => ({ ...c, name: e.target.value }))} placeholder="Optional" /></label>
            <label><span>Chain</span><input value={form.chain} onChange={(e) => setForm((c) => ({ ...c, chain: e.target.value }))} placeholder="Optional" /></label>
            <label><span>Analyze limit</span><input type="number" min="1" max="200" value={form.analyzeLimit} onChange={(e) => setForm((c) => ({ ...c, analyzeLimit: e.target.value }))} /></label>
            <button className="btn" type="submit" disabled={loading}>{loading ? "Starting..." : "Run"}</button>
          </form>
        </div>
      )}

      {isMonitor && isAdmin && <PipelineDashboard />}

      {isCompany && companyName && companyTab === "overview" && (
        <CompanyOverview
          companyName={companyName}
          onNavigateToSurface={() => navigateCompanyTab("surface")}
        />
      )}
      {isCompany && companyName && companyTab === "surface" && (
        <div className="fullscreen-surface">
          <Suspense fallback={<LoadingFallback label="Loading control surface..." />}>
            <ProtocolSurface companyName={companyName} />
          </Suspense>
        </div>
      )}
      {!isMonitor && !isCompany && (
        <>
          <ProductHero />
          <RunsPage
            analyses={analyses}
            onSelectCompany={openCompany}
          />
        </>
      )}
    </ErrorBoundary>
  );
}
