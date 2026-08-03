import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";

import { api } from "../api/client.js";
import { useIsAdmin } from "../api/useIsAdmin.js";
import { entityKey } from "../surface/entityKey.js";
import { bytecodeVerifiedAudits } from "../auditCoverage.js";
import LoadingFallback from "../LoadingFallback.jsx";
import ProtocolLogo from "../ProtocolLogo.jsx";
import ScoreBand from "../score/ScoreBand.jsx";

const ProtocolSurface = lazy(() => import("../ProtocolSurface.jsx"));
const AddressesModal = lazy(() => import("../AddressesModal.jsx"));
const AuditsAdminModal = lazy(() => import("../AuditsAdminModal.jsx"));

const SELECT_NOTICE_MS = 4000;

// The surface's refusal, put into words. "Absent from this graph", "present but
// on another chain" and "that name is on several contracts" are three separate
// facts; collapsing them into one message would tell the user something the
// surface never said.
function selectMissNotice(result, label) {
  switch (result?.kind) {
    case "ambiguous-function":
      return result.hosts > 1
        ? `${label} is on ${result.hosts} contracts here — select a contract first, then the function.`
        : `${label} has ${result.count} overloads on its contract — open the contract and pick one.`;
    case "chain-mismatch":
      return `${label} is on another chain; the control surface shows one chain at a time.`;
    default:
      return `${label} is not on the control surface.`;
  }
}

export default function CompanyOverview({ companyName, onNavigateToSurface }) {
  const isAdmin = useIsAdmin();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [auditCoverage, setAuditCoverage] = useState(null);
  const [functionData, setFunctionData] = useState(null);
  const [addressesModalOpen, setAddressesModalOpen] = useState(false);
  const [auditsAdminOpen, setAuditsAdminOpen] = useState(false);
  const [score, setScore] = useState(null);
  const [scoreError, setScoreError] = useState(null);
  const [selectMiss, setSelectMiss] = useState(null);
  const surfaceRef = useRef(null);
  const surfaceBandRef = useRef(null);

  const noticeSeq = useRef(0);
  // Every notice is a fresh object even when its text repeats: an identical
  // string would be a no-op state write, so the dismiss timer would never
  // restart (the previous click's timer could kill the new notice in
  // milliseconds) and the live region would have nothing to re-announce.
  const showNotice = useCallback((text) => {
    noticeSeq.current += 1;
    setSelectMiss(text ? { text, nonce: noticeSeq.current } : null);
  }, []);

  // A clicked entity on the score page selects that entity on the embedded
  // surface and brings the surface into view. The selection goes through the
  // surface's own handle — the same transition a canvas click makes — so the
  // score page owns no selection logic of its own. Each way the request can
  // fail to land is a different fact and gets its own words: an entity this
  // graph does not carry, an entity on another chain, and a function name that
  // more than one contract answers to are not the same miss.
  const handleSelectEntity = useCallback((target) => {
    const label = target?.label || target?.address || "That entity";
    const select = surfaceRef.current?.selectExample;
    // The surface is a lazy chunk: no handle yet means "not mounted", which is
    // not the surface saying the entity is absent.
    if (!select) {
      showNotice("The control surface is still loading — try that again in a moment.");
      return;
    }
    // The highlight hint (what the row was about) travels with the request but
    // is not part of it: the surface marks what its own card carries, and a
    // hint it could not mark is never a failed click — the entity the user
    // asked for still landed, so no outcome below is keyed on it.
    const result = select({
      chain: target?.chain,
      contractAddress: target?.address || "",
      functionSignature: target?.functionSignature || "",
      ...(target?.highlight ? { highlight: target.highlight } : {}),
    });
    if (!result?.ok) {
      showNotice(selectMissNotice(result, label));
      return;
    }
    // A contract selected while the function named on it was not found is a
    // partial landing, not a clean one — say so, but still take the user there.
    // Likewise an unpaired hint: the card carries a function by that name, but
    // under a different controller than the deduction charged — silence would
    // read as a broken highlight rather than a refused one.
    const hintedFn = target?.highlight?.functionSignature;
    showNotice(
      result.kind === "contract" && result.functionMissing
        ? `${label} is not among that contract's functions on the surface — the contract is selected instead.`
        : result.highlight?.function === "unpaired" && hintedFn
          ? `${hintedFn} on this contract is gated by a different controller than the deduction names — this contract is reached through the control graph, so only the contract is highlighted.`
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
    setScore(null);
    setScoreError(null);
    api(`/api/company/${encodeURIComponent(companyName)}`)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(e.message); });
    // Audit coverage is a separate concern — fetching it in parallel means
    // the overview still renders even if the audits pipeline hasn't been
    // wired up yet for this protocol. 404 / 500 / network errors are
    // swallowed; the audit column just stays empty.
    api(`/api/company/${encodeURIComponent(companyName)}/audit_coverage`)
      .then((c) => { if (!cancelled) setAuditCoverage(c); })
      .catch(() => { /* audits optional — keep the page usable */ });
    // Functions moved out of /api/company so the main payload could
    // drop from ~3.3 MB to ~1.2 MB. Fetched in parallel and threaded
    // through to ProtocolSurface as initialFunctions so the embedded
    // surface doesn't have to re-fetch.
    api(`/api/company/${encodeURIComponent(companyName)}/functions`)
      .then((d) => { if (!cancelled) setFunctionData(d?.functions || {}); })
      .catch(() => { /* function inspector falls back to empty data */ });
    // Fetched here rather than inside ScoreBand so it travels in parallel with
    // the company payload: mounting the band only after /api/company answered
    // would serialise the two.
    api(`/api/company/${encodeURIComponent(companyName)}/score`)
      .then((d) => { if (!cancelled) setScore(d); })
      .catch((e) => { if (!cancelled) setScoreError({ status: e.status, message: e.message }); });
    return () => { cancelled = true; };
  }, [companyName]);

  if (error) return <div className="page"><section className="panel"><p className="empty">Failed to load company overview: {error}</p></section></div>;
  if (!data) return <div className="page"><section className="panel"><p className="empty">Loading...</p></section></div>;

  const { contracts, ownership_hierarchy: hierarchy } = data;

  // Keyed by the composite (chain, address) entity token (inv. 13): a CREATE2
  // twin on two chains keeps a coverage row each instead of one overwriting the
  // other.
  const coverageByAddr = (() => {
    const map = {};
    for (const row of auditCoverage?.coverage || []) {
      if (row.address) map[entityKey(row.chain, row.address)] = row;
    }
    return map;
  })();

  // Coverage rows include past implementations linked by audit-matcher even
  // after a proxy upgrade, so the raw count overshoots the contract count
  // (e.g. 56 covered of 32 contracts). Intersect with the current contract
  // set so the denominator and numerator are comparable.
  const activeAddrs = new Set(contracts.map((c) => entityKey(c.chain, c.address)));
  const coveredContracts = Object.values(coverageByAddr)
    .filter((r) => activeAddrs.has(entityKey(r.chain, r.address)))
    .filter((r) => bytecodeVerifiedAudits(r.audits).length > 0).length;

  const proxyCount = contracts.filter((c) => c.is_proxy).length;
  return (
    <div className="company-page">
      {/* Hero band — edge-to-edge, no card borders */}
      <section className="company-hero-band">
        <div className="company-hero-inner">
          <ProtocolLogo name={companyName} size="xlarge" />
          <div className="company-hero-title-block">
            <p className="company-hero-eyebrow">Protocol</p>
            <h1 className="company-hero-title">{companyName}</h1>
            <p className="company-hero-subtitle">
              {/* "—" while coverage is unloaded: 0 would assert "no reports
                  on file" before the fetch has answered. */}
              {contracts.length} contracts mapped · {auditCoverage?.audit_count ?? "—"} reports on file
            </p>
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

      <ScoreBand
        companyName={companyName}
        contracts={contracts}
        score={score}
        error={scoreError}
        onSelectEntity={handleSelectEntity}
      />

      {/* Inline Control Surface — real ProtocolSurface, not a static preview. */}
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
          {/* Pass the already-fetched companyData + auditCoverage so the
              embedded surface skips its own /api/company and
              /audit_coverage fetches — both were previously fired a
              second time on every overview page-load. */}
          <Suspense fallback={<LoadingFallback label="Loading control surface..." />}>
            <ProtocolSurface
              ref={surfaceRef}
              companyName={companyName}
              initialData={data}
              initialCoverage={auditCoverage}
              initialFunctions={functionData}
              embedded
            />
          </Suspense>
        </div>
      </section>

      {selectMiss && (
        <div className="company-select-toast" role="status">
          {/* Keyed by the nonce so a repeated notice is a removal + insertion
              inside the live region, which is what makes it announce again. */}
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
