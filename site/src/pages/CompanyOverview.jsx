import { Suspense, lazy, useEffect, useState } from "react";

import { api } from "../api/client.js";
import { bytecodeVerifiedAudits } from "../auditCoverage.js";
import { computeProtocolScore } from "../protocolScore.js";
import LoadingFallback from "../LoadingFallback.jsx";
import ProtocolLogo from "../ProtocolLogo.jsx";
import ProtocolRadar from "../ProtocolRadar.jsx";

const ProtocolSurface = lazy(() => import("../ProtocolSurface.jsx"));
const AddressesModal = lazy(() => import("../AddressesModal.jsx"));
const AuditsAdminModal = lazy(() => import("../AuditsAdminModal.jsx"));

const CHAIN_ORDER = ["ethereum", "base", "arbitrum", "optimism", "linea", "scroll", "zksync", "blast"];

function formatChainName(chain) {
  const normalized = String(chain || "unknown").toLowerCase();
  const labels = {
    bsc: "BSC",
    zksync: "zkSync",
  };
  if (labels[normalized]) return labels[normalized];
  return normalized
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ") || "Unknown";
}

function buildChainEntries(contracts) {
  const counts = new Map();
  for (const contract of contracts || []) {
    const chain = String(contract.chain || "unknown").toLowerCase();
    counts.set(chain, (counts.get(chain) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([chain, count]) => ({
      chain,
      count,
      label: formatChainName(chain),
    }))
    .sort((left, right) => {
      const leftOrder = CHAIN_ORDER.indexOf(left.chain);
      const rightOrder = CHAIN_ORDER.indexOf(right.chain);
      if (leftOrder !== -1 || rightOrder !== -1) {
        return (leftOrder === -1 ? 999 : leftOrder) - (rightOrder === -1 ? 999 : rightOrder);
      }
      if (right.count !== left.count) return right.count - left.count;
      return left.label.localeCompare(right.label);
    });
}

export default function CompanyOverview({ companyName, onSelectContract, onNavigateToSurface }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [auditCoverage, setAuditCoverage] = useState(null);
  const [functionData, setFunctionData] = useState(null);
  const [addressesModalOpen, setAddressesModalOpen] = useState(false);
  const [auditsAdminOpen, setAuditsAdminOpen] = useState(false);

  useEffect(() => {
    let cancelled = false;
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
    return () => { cancelled = true; };
  }, [companyName]);

  if (error) return <div className="page"><section className="panel"><p className="empty">Failed to load company overview: {error}</p></section></div>;
  if (!data) return <div className="page"><section className="panel"><p className="empty">Loading...</p></section></div>;

  const { contracts, ownership_hierarchy: hierarchy } = data;
  const chainEntries = buildChainEntries(contracts);
  const chainSummary = chainEntries.map((entry) => `${entry.label} ${entry.count}`).join(" · ");
  const chainCount = chainEntries.length;
  const chainNoun = chainCount === 1 ? "chain" : "chains";

  // The score uses the full company payload: function-level authority,
  // principal details, upgrade state, and audit coverage. Functions
  // live on a separate endpoint now, so splice them back onto each
  // contract for the scorer.
  const coverageByAddr = (() => {
    const map = {};
    for (const row of auditCoverage?.coverage || []) {
      if (row.address) map[row.address.toLowerCase()] = row;
    }
    return map;
  })();

  const dataForScore = functionData
    ? {
        ...data,
        contracts: contracts.map((c) =>
          c.address && functionData[c.address] ? { ...c, functions: functionData[c.address] } : c
        ),
      }
    : data;
  const { axes, composite, grade } = computeProtocolScore(dataForScore, auditCoverage);
  // Coverage rows include past implementations linked by audit-matcher even
  // after a proxy upgrade, so the raw count overshoots the contract count
  // (e.g. 56 covered of 32 contracts). Intersect with the current contract
  // set so the denominator and numerator are comparable.
  const activeAddrs = new Set(contracts.map((c) => (c.address || "").toLowerCase()));
  const coveredContracts = Object.values(coverageByAddr)
    .filter((r) => activeAddrs.has((r.address || "").toLowerCase()))
    .filter((r) => bytecodeVerifiedAudits(r.audits).length > 0).length;

  const proxyCount = contracts.filter((c) => c.is_proxy).length;
  const openRadarExample = (example) => {
    if (!example?.contractAddress) return;
    sessionStorage.setItem("psat:surfaceRadarExample", JSON.stringify({
      companyName,
      contractAddress: example.contractAddress,
      functionSignature: example.functionSignature || "",
      selector: example.selector || "",
    }));
    onNavigateToSurface({
      focus: example.contractAddress,
      fn: example.functionSignature || example.selector || "",
      score: "1",
    });
  };

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
              {contracts.length} contracts mapped across {chainCount} {chainNoun} · {auditCoverage?.audit_count ?? 0} reports on file
            </p>
            <div className="company-chain-strip" aria-label="Discovered chains">
              {chainEntries.map((entry) => (
                <span key={entry.chain} className="company-chain-chip">
                  <span>{entry.label}</span>
                  <strong>{entry.count}</strong>
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Score + stats on the left, radar on the right */}
      <section className="company-score-band">
        <div className="company-score-left">
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>Composite Score</p>
            <div className={`company-hero-score grade-${grade}`}>
              <span className="company-hero-score-value">{composite}</span>
              <span className="company-hero-score-unit">/ 100</span>
            </div>
            <div className="company-hero-score-label">Grade {grade.toUpperCase()}</div>
            <div className={`company-hero-grade-bar grade-${grade}`}>
              <div className="company-hero-grade-bar-fill" style={{ width: `${Math.max(4, composite)}%` }} />
            </div>
          </div>

          <div className="company-hero-stats">
            <button
              type="button"
              className="company-hero-stat company-hero-stat--clickable"
              onClick={() => setAddressesModalOpen(true)}
              title="Browse all addresses"
            >
              <div className="company-hero-stat-value">{contracts.length}</div>
              <div className="company-hero-stat-label">Contracts ↗</div>
            </button>
            <button
              type="button"
              className="company-hero-stat company-hero-stat--clickable"
              onClick={() => setAuditsAdminOpen(true)}
              title="Manage audits (admin)"
            >
              <div className="company-hero-stat-value">{auditCoverage?.audit_count ?? "—"}</div>
              <div className="company-hero-stat-label">Reports ↗</div>
            </button>
            <div className="company-hero-stat">
              <div className="company-hero-stat-value">{coveredContracts}</div>
              <div className="company-hero-stat-label">Covered</div>
            </div>
            <div className="company-hero-stat">
              <div className="company-hero-stat-value">{proxyCount}</div>
              <div className="company-hero-stat-label">Proxies</div>
            </div>
            <div className="company-hero-stat">
              <div className="company-hero-stat-value">{chainCount}</div>
              <div className="company-hero-stat-label">Chains</div>
            </div>
          </div>
        </div>

        <div className="company-score-right">
          <p className="eyebrow" style={{ margin: 0 }}>Security Radar</p>
          <ProtocolRadar axes={axes} size={300} onExampleClick={openRadarExample} />
        </div>
      </section>

      {/* Inline Control Surface — real ProtocolSurface, not a static preview. */}
      <section className="company-surface-band">
        <div className="company-surface-band-header">
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>Control Surface</p>
            <h2 className="company-surface-band-title">
              {contracts.length} contracts · {chainSummary || "No chain data"} · {proxyCount} proxies
            </h2>
          </div>
          <div className="company-surface-band-actions">
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
              companyName={companyName}
              initialData={data}
              initialCoverage={auditCoverage}
              initialFunctions={functionData}
              embedded
            />
          </Suspense>
        </div>
      </section>

      {addressesModalOpen && (
        <Suspense fallback={null}>
          <AddressesModal
            companyName={companyName}
            onClose={() => setAddressesModalOpen(false)}
            onSelectContract={(row) => {
              // Only jump into the job view for addresses that were actually
              // analyzed; discovered-only rows don't have a job_id. Pass the
              // matching Contract job_id up to the App-level loader.
              const full = contracts.find((c) => c.address?.toLowerCase() === row.address?.toLowerCase());
              if (full?.job_id) onSelectContract(full.job_id);
            }}
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
