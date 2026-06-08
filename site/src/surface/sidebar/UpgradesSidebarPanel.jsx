import { useEffect, useState } from "react";

import { api } from "../../api/client.js";
import { UpgradesPanel } from "../inspector/UpgradesPanel.jsx";
import { shortAddr } from "../format.js";

// Sidebar Upgrades tab. Two states:
//   - No machine selected: list proxies in this protocol with upgrade counts.
//     Click a row → focus that proxy on canvas (parent handles selection).
//   - Machine selected (proxy): lazy-fetch the analysis blob for that contract
//     (the per-contract upgrade_history isn't included in /api/company/{name},
  //     so we go via /api/analyses/{analysis_job_id}) and render the existing
//     UpgradesPanel — same layout as the standalone /address/<addr>/upgrades
//     page so the per-impl audit cards (UpgradeAuditCard) appear identically.
export function UpgradesSidebarPanel({ machine, companyName, machines, onSelect, cache, onCache }) {
  const [history, setHistory] = useState(null);
  const [deps, setDeps] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const analysisJobId = machine?.analysis_job_id;
    if (!machine || !machine.is_proxy || !analysisJobId) {
      setHistory(null);
      setDeps({});
      setLoading(false);
      setError(null);
      return;
    }
    const cached = cache && cache[analysisJobId];
    if (cached) {
      setHistory(cached.history || null);
      setDeps(cached.deps || {});
      setLoading(false);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setHistory(null);
    setDeps({});
    // Two lean artifact fetches in parallel instead of the multi-MB
    // /api/analyses/{analysis_job_id} blob — that endpoint merges every artifact
    // (contract_analysis, control_snapshot, effective_permissions, …) and
    // the Upgrades tab only needs upgrade_history + dependencies. Each
    // promise's failure is isolated: if `dependencies` errors out, the
    // timeline still renders with raw addresses instead of resolved
    // contract names.
    const jid = encodeURIComponent(analysisJobId);
    Promise.all([
      api(`/api/analyses/${jid}/artifact/upgrade_history`).catch(() => null),
      api(`/api/analyses/${jid}/artifact/dependencies`).catch(() => null),
    ])
      .then(([uhBody, depsBody]) => {
        if (cancelled) return;
        const h = (uhBody && typeof uhBody === "object") ? uhBody : null;
        const d = (depsBody && typeof depsBody === "object")
          // dependencies artifact body is shaped { dependencies: {...} }
          // when stored via the analysis pipeline; some legacy paths
          // store the inner map directly. Accept either.
          ? (depsBody.dependencies || depsBody)
          : {};
        setHistory(h);
        setDeps(d);
        if (onCache) onCache(analysisJobId, h, d);
      })
      .catch((e) => { if (!cancelled) setError(e.message || String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // cache/onCache deliberately omitted: we read on mount/selection change
    // only so a cache update from this very fetch doesn't retrigger the
    // effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [machine?.analysis_job_id, machine?.is_proxy]);

  if (!machine) {
    const proxies = (machines || []).filter((m) => m.is_proxy);
    if (proxies.length === 0) {
      return (
        <section className="ps-principal-section">
          <div className="ps-inspector-empty">No proxies in this protocol.</div>
        </section>
      );
    }
    // Resolve a count for the badge: prefer the server's value, else the
    // total_upgrades on a previously-fetched analysis blob (lazy-cached as
    // the user clicks into proxies). When neither is known, omit the chip
    // rather than rendering a misleading "0".
    function countFor(m) {
      if (typeof m.upgrade_count === "number" && m.upgrade_count > 0) return m.upgrade_count;
      const cached = cache && cache[m.analysis_job_id];
      const totalUpgrades = cached?.history?.total_upgrades;
      return typeof totalUpgrades === "number" ? totalUpgrades : null;
    }
    // Last-upgrade resolution: the server returns ISO timestamp; fall back
    // to the cached artifact's last_upgrade_block when timestamp is missing
    // (older proxies may have block numbers but no chain timestamp).
    function lastUpgradeFor(m) {
      if (m.last_upgrade_timestamp) {
        const d = new Date(m.last_upgrade_timestamp);
        if (!Number.isNaN(d.getTime())) {
          return { sortKey: d.getTime(), label: d.toLocaleDateString("en-US", { year: "numeric", month: "short" }) };
        }
      }
      if (typeof m.last_upgrade_block === "number" && m.last_upgrade_block > 0) {
        return { sortKey: m.last_upgrade_block, label: `block ${m.last_upgrade_block.toLocaleString()}` };
      }
      // Fall back to anything we cached during a per-proxy load.
      const cached = cache && cache[m.analysis_job_id];
      const targetAddr = (cached?.history?.target_address || m.address || "").toLowerCase();
      const proxy = cached?.history?.proxies?.[targetAddr];
      const block = proxy?.last_upgrade_block;
      if (typeof block === "number" && block > 0) {
        return { sortKey: block, label: `block ${block.toLocaleString()}` };
      }
      return null;
    }
    return (
      <section className="ps-principal-section">
        <div className="ps-upgrades-global-hint">Click a proxy to see its timeline + audit matches.</div>
        <div className="ps-upgrades-global">
          {proxies
            .slice()
            .sort((a, b) => {
              // Most-recently-upgraded first; proxies with no recency data
              // sink to the bottom and tiebreak alphabetically.
              const la = lastUpgradeFor(a);
              const lb = lastUpgradeFor(b);
              if (la && lb) return lb.sortKey - la.sortKey;
              if (la) return -1;
              if (lb) return 1;
              return String(a.name || "").localeCompare(String(b.name || ""));
            })
            .map((m) => {
              const count = countFor(m);
              const last = lastUpgradeFor(m);
              return (
                <button
                  key={m.address}
                  type="button"
                  className="ps-upgrades-row"
                  onClick={() => onSelect && onSelect(m)}
                >
                  <div className="ps-upgrades-row-name">
                    <span>{m.name || shortAddr(m.address)}</span>
                    <span className="ps-upgrades-row-arrow">→</span>
                  </div>
                  <div className="ps-upgrades-row-meta">
                    {count != null ? (
                      <span className="ps-badge" style={{ "--badge-accent": "#8b92a8" }}>
                        {count} upgrade{count === 1 ? "" : "s"}
                      </span>
                    ) : null}
                    {m.proxy_type ? (
                      <span className="ps-badge" style={{ "--badge-accent": "#9a8a6e" }}>{m.proxy_type}</span>
                    ) : null}
                    {last ? (
                      <span className="ps-badge" style={{ "--badge-accent": "var(--tone-ownership)" }}>
                        last {last.label}
                      </span>
                    ) : null}
                  </div>
                </button>
              );
            })}
        </div>
      </section>
    );
  }

  if (!machine.is_proxy) {
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">{machine.name || "This contract"} is not a proxy. No upgrade history.</div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">Failed to load upgrade history: {error}</div>
      </section>
    );
  }

  return (
    <div className="ps-upgrades-sidebar-body">
      <UpgradesPanel
        upgradeHistory={history}
        contractId={machine.contract_id}
        companyName={companyName}
        contractAddress={machine.address}
        contractName={machine.name}
        dependencies={deps}
        loading={loading}
      />
    </div>
  );
}
