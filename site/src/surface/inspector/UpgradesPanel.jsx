import { useState, useEffect } from "react";

import { matchesEra } from "../../auditMatching.js";
import { isBytecodeVerifiedAudit } from "../../auditCoverage.js";
import { api } from "../../api/client.js";
import { blockExplorerAddressUrl } from "../../blockExplorer.js";
import { shortenAddress } from "../../graph.js";

function formatDate(ts) {
  if (!ts) return null;
  return new Date(ts * 1000).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function formatRelative(ts) {
  if (!ts) return null;
  const now = Date.now() / 1000;
  const seconds = Math.max(0, now - ts);
  const days = Math.floor(seconds / 86400);
  if (days < 1) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;
  const years = Math.floor(days / 365);
  const remMonths = Math.floor((days - years * 365) / 30);
  if (remMonths === 0) return `${years} year${years === 1 ? "" : "s"} ago`;
  return `${years}y ${remMonths}mo ago`;
}

function formatSpan(fromTs, toTs) {
  const start = formatDate(fromTs);
  if (!start) return null;
  const end = toTs ? formatDate(toTs) : null;
  return end ? `${start} → ${end}` : start;
}

export function UpgradesPanel({
  upgradeHistory,
  contractId,
  companyName: _companyName,
  contractAddress,
  contractName,
  dependencies,
  loading = false,
}) {
  const history = upgradeHistory;
  const [auditTimeline, setAuditTimeline] = useState(null);
  const [auditTimelineError, setAuditTimelineError] = useState(null);

  useEffect(() => {
    if (!contractId) {
      setAuditTimeline(null);
      setAuditTimelineError(null);
      return;
    }
    let cancelled = false;
    setAuditTimeline(null);
    setAuditTimelineError(null);
    api(`/api/contracts/${encodeURIComponent(contractId)}/audit_timeline`)
      .then((t) => { if (!cancelled) setAuditTimeline(t); })
      .catch((e) => { if (!cancelled) setAuditTimelineError(e.message || String(e)); });
    return () => { cancelled = true; };
  }, [contractId]);

  const coverageRows = auditTimeline?.coverage || [];
  const verifiedCoverageRows = coverageRows.filter(isBytecodeVerifiedAudit);

  if (loading) {
    return <div className="upgr2-empty">Loading upgrade history…</div>;
  }

  if (!history || !Object.keys(history.proxies || {}).length) {
    return (
      <div className="upgr2-empty">
        <div className="upgr2-empty-title">No upgrades on record</div>
        <div className="upgr2-empty-sub">
          {contractId ? "This contract has not been upgraded since deployment." : "Select a proxy to see its upgrade history."}
        </div>
      </div>
    );
  }

  const deps = dependencies || {};
  const targetAddr = (history.target_address || contractAddress || "").toLowerCase();
  const targetProxy = history.proxies?.[targetAddr] || Object.values(history.proxies)[0] || null;
  const otherProxies = Object.entries(history.proxies).filter(([addr]) => addr.toLowerCase() !== targetAddr);

  function implName(addr, fallbackName) {
    if (!addr) return null;
    if (fallbackName) return fallbackName;
    const dep = deps[addr];
    if (dep?.contract_name) return dep.contract_name;
    const nested = Object.values(deps).find(
      (d) => typeof d.implementation === "object" && d.implementation?.address === addr,
    );
    return nested?.implementation?.contract_name || null;
  }

  function isAudited(impl) {
    return verifiedCoverageRows.some((c) => matchesEra(c, impl));
  }

  function auditsFor(impl) {
    return verifiedCoverageRows.filter((c) => matchesEra(c, impl));
  }

  // Implementations from oldest → newest in the artifact; reverse for display
  // so the active impl reads first.
  const impls = Array.isArray(targetProxy?.implementations) ? targetProxy.implementations.slice().reverse() : [];
  const currentImpl = impls[0] || null;
  const currentAudited = currentImpl ? isAudited(currentImpl) : false;
  const upgradeCount = targetProxy?.upgrade_count ?? Math.max(0, impls.length - 1);
  const lastTs = currentImpl?.timestamp_introduced;
  const currentImplHref = currentImpl
    ? blockExplorerAddressUrl(currentImpl.address, currentImpl.chain_id)
    : null;

  function StatusChip({ audited }) {
    return audited ? (
      <span className="upgr2-chip upgr2-chip--ok" title="Bytecode matches an audited version">audited</span>
    ) : (
      <span className="upgr2-chip upgr2-chip--warn" title="No audit covers this exact bytecode">no proof</span>
    );
  }

  function ImplRow({ impl, isCurrent, isFirst }) {
    const name = implName(impl.address, impl.contract_name);
    const span = formatSpan(impl.timestamp_introduced, impl.timestamp_replaced);
    const link = blockExplorerAddressUrl(impl.address, impl.chain_id);
    const audits = auditsFor(impl);
    return (
      <li className={`upgr2-impl${isCurrent ? " upgr2-impl--current" : ""}`}>
        <div className="upgr2-impl-marker" aria-hidden="true">
          <span className="upgr2-impl-dot" />
          {isFirst ? null : <span className="upgr2-impl-line" />}
        </div>
        <div className="upgr2-impl-body">
          <div className="upgr2-impl-row">
            <span className="upgr2-impl-name">{name || shortenAddress(impl.address)}</span>
            {isCurrent ? <span className="upgr2-chip upgr2-chip--current">current</span> : null}
            <StatusChip audited={audits.length > 0} />
          </div>
          <div className="upgr2-impl-row upgr2-impl-row--meta">
            {link ? (
              <a className="upgr2-impl-addr mono" href={link} target="_blank" rel="noreferrer">
                {shortenAddress(impl.address)}
              </a>
            ) : (
              <span className="upgr2-impl-addr mono">{shortenAddress(impl.address)}</span>
            )}
            {span ? <span className="upgr2-impl-span">{span}</span> : null}
          </div>
          {audits.length ? (
            <div className="upgr2-impl-audits">
              {audits.map((a) => (
                <span key={a.audit_id} className="upgr2-audit-chip" title={a.title || a.auditor}>
                  {a.auditor || "audit"}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      </li>
    );
  }

  return (
    <div className="upgr2">
      {/* Focal status: current implementation + audit posture */}
      <header className={`upgr2-status ${currentAudited ? "upgr2-status--ok" : "upgr2-status--warn"}`}>
        <div className="upgr2-status-eyebrow">Current implementation</div>
        <div className="upgr2-status-row">
          <span className="upgr2-status-name">
            {implName(currentImpl?.address, currentImpl?.contract_name) || contractName || "—"}
          </span>
          <StatusChip audited={currentAudited} />
        </div>
        {currentImpl ? (
          <div className="upgr2-status-meta">
            {currentImplHref ? (
              <a
                className="upgr2-status-addr mono"
                href={currentImplHref}
                target="_blank"
                rel="noreferrer"
              >
                {shortenAddress(currentImpl.address)}
              </a>
            ) : (
              <span className="upgr2-status-addr mono">{shortenAddress(currentImpl.address)}</span>
            )}
            {lastTs ? (
              <span className="upgr2-status-since">since {formatDate(lastTs)} · {formatRelative(lastTs)}</span>
            ) : null}
          </div>
        ) : null}
      </header>

      {/* Compact stats row */}
      <div className="upgr2-stats">
        <span><strong>{upgradeCount}</strong> upgrade{upgradeCount === 1 ? "" : "s"}</span>
        {targetProxy?.proxy_type ? <span className="upgr2-stats-sep" /> : null}
        {targetProxy?.proxy_type ? <span className="upgr2-stats-meta">{targetProxy.proxy_type}</span> : null}
        {(() => {
          // Unique audits that bytecode-verify any impl in this history.
          // Counted at audit_id level so a single audit citing multiple
          // impls doesn't double-count.
          const placed = new Set();
          for (const cov of verifiedCoverageRows) {
            for (const impl of impls) {
              if (matchesEra(cov, impl)) {
                placed.add(cov.audit_id);
                break;
              }
            }
          }
          if (placed.size === 0) return null;
          return (
            <>
              <span className="upgr2-stats-sep" />
              <span className="chip upgr2-stats-audits">
                {placed.size} bytecode match{placed.size === 1 ? "" : "es"} in history
              </span>
            </>
          );
        })()}
        {auditTimelineError ? (
          <>
            <span className="upgr2-stats-sep" />
            <span className="upgr2-stats-meta">audit lookup unavailable</span>
          </>
        ) : null}
      </div>

      {/* Timeline: most recent first, one row per impl */}
      {impls.length ? (
        <ol className="upgr2-timeline" aria-label="Implementation timeline">
          {impls.map((impl, idx) => (
            <ImplRow
              key={`${impl.address}-${idx}`}
              impl={impl}
              isCurrent={idx === 0}
              isFirst={idx === impls.length - 1}
            />
          ))}
        </ol>
      ) : null}

      {/* Other proxies — only when more than one is in scope; collapsed by default */}
      {otherProxies.length ? (
        <details className="upgr2-others">
          <summary>{otherProxies.length} other proxy{otherProxies.length === 1 ? "" : "ies"} in this analysis</summary>
          <ul className="upgr2-others-list">
            {otherProxies.map(([addr, p]) => (
              <li key={addr}>
                <span className="mono">{shortenAddress(addr)}</span>
                <span>{p.upgrade_count ?? 0} upgrade{(p.upgrade_count ?? 0) === 1 ? "" : "s"}</span>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

export default UpgradesPanel;
