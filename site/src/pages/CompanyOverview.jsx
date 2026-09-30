import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api, companyApi } from "../api/client.js";
import { useIsAdmin } from "../api/useIsAdmin.js";
import { chainLabel } from "../surface/chainMeta.js";
import { entityKey } from "../surface/entityKey.js";
import { bytecodeVerifiedAudits } from "../audits/auditCoverage.js";
import LoadingFallback from "../LoadingFallback.jsx";
import ProtocolLogo from "../ProtocolLogo.jsx";
import ScoreBand from "../score/ScoreBand.jsx";
import StaleBanner from "../shared/StaleBanner.jsx";

const ProtocolSurface = lazy(() => import("../surface/ProtocolSurface.jsx"));
const AddressesModal = lazy(() => import("../addresses/AddressesModal.jsx"));
const AuditsAdminModal = lazy(() => import("../audits/AuditsAdminModal.jsx"));

const SELECT_NOTICE_MS = 4000;

// "Absent from this graph" and "name on several contracts" are different facts
// and get different words.
function selectMissNotice(result, label) {
  switch (result?.kind) {
    case "ambiguous-function":
      return result.hosts > 1
        ? `${label} is on ${result.hosts} contracts here — select a contract first, then the function.`
        : `${label} has ${result.count} overloads on its contract — open the contract and pick one.`;
    default:
      return `${label} is not on the control surface.`;
  }
}

export default function CompanyOverview({ companyName, onNavigateToSurface }) {
  const isAdmin = useIsAdmin();
  const [structure, setData] = useState(null);
  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState(null);
  const data = useMemo(() => structure ? { ...structure, ...summary } : null, [structure, summary]);
  const [error, setError] = useState(null);
  const [requestAttempt, setRequestAttempt] = useState(0);
  const [auditCoverage, setAuditCoverage] = useState(null);
  const [functionData, setFunctionData] = useState(null);
  const [functionError, setFunctionError] = useState(null);
  const [sectionMeta, setSectionMeta] = useState({});
  const [addressesModalOpen, setAddressesModalOpen] = useState(false);
  const [auditsAdminOpen, setAuditsAdminOpen] = useState(false);
  const [score, setScore] = useState(null);
  const [scoreError, setScoreError] = useState(null);
  const [selectMiss, setSelectMiss] = useState(null);
  const surfaceRef = useRef(null);
  const surfaceBandRef = useRef(null);

  const noticeSeq = useRef(0);
  // A fresh object each time: identical state wouldn't restart the dismiss
  // timer or re-announce.
  const showNotice = useCallback((text) => {
    noticeSeq.current += 1;
    setSelectMiss(text ? { text, nonce: noticeSeq.current } : null);
  }, []);

  // Score-page clicks select through the surface's own handle, so this page
  // owns no selection logic. Each failure mode gets its own words.
  const handleSelectEntity = useCallback((target) => {
    const label = target?.label || target?.address || "That entity";
    const select = surfaceRef.current?.selectExample;
    // No handle means the lazy surface isn't mounted, not that the entity is
    // absent.
    if (!select) {
      showNotice("The control surface is still loading — try that again in a moment.");
      return;
    }
    // The hint rides along but is never part of the outcome.
    const result = select({
      chain: target?.chain,
      contractAddress: target?.address || "",
      functionSignature: target?.functionSignature || "",
      ...(target?.highlight ? { highlight: target.highlight } : {}),
      ...(target?.reachedFrom ? { reachedFrom: target.reachedFrom } : {}),
    });
    if (!result?.ok) {
      showNotice(selectMissNotice(result, label));
      return;
    }
    // A contract landing without its named function, or with an unpaired hint,
    // is partial; say so, but still go there.
    const hintedFn = target?.highlight?.functionSignature;
    showNotice(
      result.kind === "chain-switch"
        ? `Switched the control surface to ${chainLabel(result.chain)} — ${label} is on that chain.`
        : result.kind === "contract" && result.functionMissing
          ? `${label} is not among that contract's functions on the surface — the contract is selected instead.`
          : result.highlight?.function === "unpaired" && hintedFn
            ? `${hintedFn} on this contract is gated by a different controller than the deduction names — nothing on its card is the deduced action.`
            : null,
    );
    surfaceBandRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [showNotice]);

  useEffect(() => {
    if (!selectMiss) return undefined;
    const timer = setTimeout(() => setSelectMiss(null), SELECT_NOTICE_MS);
    return () => clearTimeout(timer);
  }, [selectMiss]);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const options = { signal: controller.signal };
    setData(null);
    setSummary(null);
    setSummaryError(null);
    setError(null);
    setAuditCoverage(null);
    setFunctionData(null);
    setFunctionError(null);
    setScore(null);
    setScoreError(null);
    setSectionMeta({});
    setSelectMiss(null);
    setAddressesModalOpen(false);
    setAuditsAdminOpen(false);
    const keepMeta = (section, meta) => setSectionMeta((current) => ({ ...current, [section]: meta }));
    companyApi(`/api/company/${encodeURIComponent(companyName)}`, options)
      .then(({ data: d, meta }) => { if (!cancelled) { setData(d); keepMeta("overview", meta); } })
      .catch((e) => { if (!cancelled) setError(e.message); });
    companyApi(`/api/company/${encodeURIComponent(companyName)}/summary`, options)
      .then(({ data: s, meta }) => { if (!cancelled) { setSummary(s); keepMeta("summary", meta); } })
      .catch((e) => { if (!cancelled) setSummaryError(e.message); });
    // Parallel so the overview renders even without audits; failures leave the
    // column empty.
    api(`/api/company/${encodeURIComponent(companyName)}/audit_coverage`, options)
      .then((c) => { if (!cancelled) setAuditCoverage(c); })
      .catch(() => { /* audits optional — keep the page usable */ });
    // Threaded into ProtocolSurface as initialFunctions so it doesn't re-fetch.
    companyApi(`/api/company/${encodeURIComponent(companyName)}/functions`, options)
      .then(({ data: d, meta }) => {
        if (!cancelled) { setFunctionData(d?.functions || {}); keepMeta("functions", meta); }
      })
      .catch((e) => { if (!cancelled) setFunctionError(e.message); });
    // Here rather than in ScoreBand so it runs in parallel with /api/company.
    api(`/api/company/${encodeURIComponent(companyName)}/score`, options)
      .then((d) => { if (!cancelled) setScore(d); })
      .catch((e) => { if (!cancelled) setScoreError({ status: e.status, message: e.message }); });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [companyName, requestAttempt]);

  if (error) return (
    <div className="page"><section className="panel">
      <p className="empty" role="alert">Failed to load company overview: {error}</p>
      <button type="button" onClick={() => setRequestAttempt((attempt) => attempt + 1)}>Retry</button>
    </section></div>
  );
  if (!data) return <div className="page"><section className="panel"><p className="empty">Loading...</p></section></div>;

  const { contracts, ownership_hierarchy: hierarchy } = data;

  // Composite keys so CREATE2 twins keep a row each (inv. 13).
  const coverageByAddr = (() => {
    const map = {};
    for (const row of auditCoverage?.coverage || []) {
      if (row.address) map[entityKey(row.chain, row.address)] = row;
    }
    return map;
  })();

  // Coverage includes past implementations, so intersect with current contracts
  // to keep the ratio meaningful.
  const activeAddrs = new Set(contracts.map((c) => entityKey(c.chain, c.address)));
  const coveredContracts = Object.values(coverageByAddr)
    .filter((r) => activeAddrs.has(entityKey(r.chain, r.address)))
    .filter((r) => bytecodeVerifiedAudits(r.audits).length > 0).length;

  const proxyCount = contracts.filter((c) => c.is_proxy).length;
  return (
    <div className="company-page">
      <section className="company-hero-band">
        <div className="company-hero-inner">
          <ProtocolLogo name={companyName} size="xlarge" />
          <div className="company-hero-title-block">
            <p className="company-hero-eyebrow">Protocol</p>
            <h1 className="company-hero-title">{companyName}</h1>
            <p className="company-hero-subtitle">
              {/* "—" while unloaded: 0 would assert no reports. */}
              {contracts.length} contracts mapped · {auditCoverage?.audit_count ?? "—"} reports on file
            </p>
            <StaleBanner metas={Object.values(sectionMeta)} className="company-hero-subtitle" />
          </div>
          <div className="company-hero-stats">
            {isAdmin ? (
              <button
                type="button"
                className="company-hero-stat company-hero-stat--clickable"
                onClick={() => setAddressesModalOpen(true)}
                title="Browse all addresses"
              >
                <div className="company-hero-stat-value">{contracts.length}</div>
                <div className="company-hero-stat-label">Contracts ↗</div>
              </button>
            ) : (
              <div className="company-hero-stat">
                <div className="company-hero-stat-value">{contracts.length}</div>
                <div className="company-hero-stat-label">Contracts</div>
              </div>
            )}
            {isAdmin ? (
              <button
                type="button"
                className="company-hero-stat company-hero-stat--clickable"
                onClick={() => setAuditsAdminOpen(true)}
                title="Manage audits (admin)"
              >
                <div className="company-hero-stat-value">{auditCoverage?.audit_count ?? "—"}</div>
                <div className="company-hero-stat-label">Reports ↗</div>
              </button>
            ) : (
              <div className="company-hero-stat">
                <div className="company-hero-stat-value">{auditCoverage?.audit_count ?? "—"}</div>
                <div className="company-hero-stat-label">Reports</div>
              </div>
            )}
            <div className="company-hero-stat">
              <div className="company-hero-stat-value">{coveredContracts}</div>
              <div className="company-hero-stat-label">Covered</div>
            </div>
            <div className="company-hero-stat">
              <div className="company-hero-stat-value">{proxyCount}</div>
              <div className="company-hero-stat-label">Proxies</div>
            </div>
          </div>
        </div>
      </section>

      {summaryError && <p role="alert">Company summary unavailable: {summaryError}</p>}
      <ScoreBand
        companyName={companyName}
        contracts={contracts}
        score={score}
        error={scoreError}
        onSelectEntity={handleSelectEntity}
      />

      <section className="company-surface-band" ref={surfaceBandRef}>
        <div className="company-surface-band-header">
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>Control Surface</p>
            <h2 className="company-surface-band-title">
              {contracts.length} contracts · {proxyCount} proxies · audits in the side panel
            </h2>
          </div>
          <div className="company-surface-band-actions">
            {isAdmin && (
              <>
                <button
                  type="button"
                  className="company-surface-action"
                  onClick={() => setAddressesModalOpen(true)}
                  title="Browse, label, and compare addresses"
                >
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M3 7h18" />
                    <path d="M3 12h18" />
                    <path d="M3 17h18" />
                    <circle cx="5" cy="7" r="0.5" fill="currentColor" />
                    <circle cx="5" cy="12" r="0.5" fill="currentColor" />
                    <circle cx="5" cy="17" r="0.5" fill="currentColor" />
                  </svg>
                  <span>Addresses</span>
                  <span className="company-surface-action-count">
                    {data.all_addresses_count ?? contracts.length}
                  </span>
                </button>
                <button
                  type="button"
                  className="company-surface-action"
                  onClick={() => setAuditsAdminOpen(true)}
                  title="Manage audit reports"
                >
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M12 2 4 6v6c0 5 3.5 9.3 8 10 4.5-.7 8-5 8-10V6l-8-4Z" />
                    <path d="m9 12 2 2 4-4" />
                  </svg>
                  <span>Audits</span>
                  {auditCoverage?.audit_count != null && (
                    <span className="company-surface-action-count">{auditCoverage.audit_count}</span>
                  )}
                </button>
              </>
            )}
            <button
              type="button"
              className="company-surface-action primary"
              onClick={onNavigateToSurface}
              title="Open the fullscreen Control Surface"
            >
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M15 3h6v6" />
                <path d="M9 21H3v-6" />
                <path d="M21 3 14 10" />
                <path d="M3 21l7-7" />
              </svg>
              <span>Fullscreen</span>
            </button>
          </div>
        </div>
        <div className="company-surface-embed">
          {/*
            Pass fetched data so the surface skips duplicate /api/company and
            /audit_coverage calls.
          */}
          {functionError ? (
            <div className="panel">
              <p role="alert">Failed to load control surface functions: {functionError}</p>
              <button type="button" onClick={() => setRequestAttempt((attempt) => attempt + 1)}>Retry</button>
            </div>
          ) : <Suspense fallback={<LoadingFallback label="Loading control surface..." />}>
            <ProtocolSurface
              ref={surfaceRef}
              companyName={companyName}
              initialData={data}
              initialCoverage={auditCoverage}
              initialFunctions={functionData}
              initialScore={{ data: score, error: scoreError }}
              embedded
            />
          </Suspense>}
        </div>
      </section>

      {selectMiss && (
        <div className="company-select-toast" role="status">
          {/* Keyed by nonce so a repeat re-announces in the live region. */}
          <span key={selectMiss.nonce}>{selectMiss.text}</span>
        </div>
      )}

      {addressesModalOpen && (
        <Suspense fallback={null}>
          <AddressesModal
            companyName={companyName}
            onClose={() => setAddressesModalOpen(false)}
          />
        </Suspense>
      )}
      {auditsAdminOpen && (
        <Suspense fallback={null}>
          <AuditsAdminModal
            companyName={companyName}
            onClose={() => setAuditsAdminOpen(false)}
          />
        </Suspense>
      )}
    </div>
  );
}
