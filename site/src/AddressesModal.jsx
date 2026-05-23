import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api/client.js";
import { listAddressLabels } from "./api/addressLabels.js";
import AddressLabelInline from "./AddressLabelInline.jsx";
import {
  bulkAnalyzeCandidates,
  computeCurrentImplAddrs,
  isPureHistorical,
} from "./addressFilter.js";
import { proxyDisplayName } from "./displayName.js";

const ADDRESS_RE = /0x[a-fA-F0-9]{40}/g;

// "Impl (via UUPSProxy)" for proxy rows, raw name otherwise — see
// proxyDisplayName. Thin adapter from the address-inventory row shape.
function prettyAddressName(row) {
  return proxyDisplayName({
    name: row?.name,
    isProxy: row?.is_proxy,
    implName: row?.implementation_name,
  });
}

// Parse any blob of text (comma, newline, whitespace separated) into a
// deduplicated list of lowercased 0x addresses. Anything that doesn't
// match the 40-hex address shape is silently dropped — users routinely
// paste labels + addresses from spreadsheets.
function parseAddressList(raw) {
  const hits = String(raw || "").match(ADDRESS_RE) || [];
  const seen = new Set();
  for (const h of hits) seen.add(h.toLowerCase());
  return [...seen];
}

export default function AddressesModal({ companyName, onClose, onSelectContract }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [labels, setLabels] = useState(new Map());
  const [filter, setFilter] = useState("");
  const [sortBy, setSortBy] = useState("rank"); // rank | name | address
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [newAddress, setNewAddress] = useState("");
  const [newName, setNewName] = useState("");
  const [compareOpen, setCompareOpen] = useState(false);
  const [compareInput, setCompareInput] = useState("");
  const [busyAddr, setBusyAddr] = useState(null); // address currently being deleted/analyzed
  const [showHistorical, setShowHistorical] = useState(false);
  const [bulkAnalyzing, setBulkAnalyzing] = useState(false);

  const refresh = useCallback(() => {
    let cancelled = false;
    // Pulls just the address inventory (~167 KB for ether.fi). The full
    // /api/company response (1+ MB) is fetched by CompanyOverview already
    // and most of it isn't needed here.
    api(`/api/company/${encodeURIComponent(companyName)}/addresses`)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(e.message); });
    listAddressLabels()
      .then((rows) => {
        if (cancelled) return;
        const m = new Map();
        for (const r of rows || []) m.set(String(r.address || "").toLowerCase(), r.name);
        setLabels(m);
      })
      .catch(() => { /* labels are optional; missing key just leaves the map empty */ });
    return () => { cancelled = true; };
  }, [companyName]);

  useEffect(() => {
    const cleanup = refresh();
    return cleanup;
  }, [refresh]);

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose?.(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Lowercased address → row lookup, so compare mode can O(1) check which
  // pasted addresses exist in the protocol.
  const addrIndex = useMemo(() => {
    const m = new Map();
    for (const r of data?.all_addresses || []) {
      m.set(String(r.address || "").toLowerCase(), r);
    }
    return m;
  }, [data]);

  // Compute the set of impl addresses currently behind a proxy in this
  // payload — keeps live impls visible even when their only discovery
  // source is the upgrade-history sweep.
  const currentImplAddrs = useMemo(
    () => computeCurrentImplAddrs(data?.all_addresses || []),
    [data],
  );

  const { activeRows, historicalCount } = useMemo(() => {
    const all = data?.all_addresses || [];
    const active = [];
    let hist = 0;
    for (const r of all) {
      if (isPureHistorical(r, currentImplAddrs)) hist += 1;
      else active.push(r);
    }
    return { activeRows: active, historicalCount: hist };
  }, [data, currentImplAddrs]);

  const parsedCompare = useMemo(() => parseAddressList(compareInput), [compareInput]);

  // In compare mode the row set is the pasted addresses (matched first,
  // missing rows synthesized with minimal shape so the table renders them
  // alongside). Out of compare mode, everything flows through filter+sort.
  const rows = useMemo(() => {
    if (compareOpen && parsedCompare.length > 0) {
      const matched = [];
      const missing = [];
      for (const a of parsedCompare) {
        const hit = addrIndex.get(a);
        if (hit) matched.push({ ...hit, _compareStatus: "matched" });
        else missing.push({ address: a, _compareStatus: "missing", name: "", is_proxy: false, analyzed: false });
      }
      return [...matched, ...missing];
    }

    // Compare mode always uses the full inventory — users paste lists that
    // may legitimately include historical impls and need to see them flagged
    // as matched/missing. Outside compare mode, default to active-only.
    const all = showHistorical ? (data?.all_addresses || []) : activeRows;
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? all.filter((r) => {
          const addr = (r.address || "").toLowerCase();
          const name = (r.name || "").toLowerCase();
          const impl = (r.implementation_name || "").toLowerCase();
          const chain = (r.chain || "").toLowerCase();
          const label = (labels.get(addr) || "").toLowerCase();
          return (
            addr.includes(q) ||
            name.includes(q) ||
            impl.includes(q) ||
            chain.includes(q) ||
            label.includes(q)
          );
        })
      : all;
    const sorted = [...filtered];
    if (sortBy === "rank") {
      sorted.sort((a, b) => {
        const ar = a.rank_score;
        const br = b.rank_score;
        if (ar == null && br == null) return (a.name || "zzz").localeCompare(b.name || "zzz");
        if (ar == null) return 1;
        if (br == null) return -1;
        return br - ar;
      });
    } else if (sortBy === "name") {
      sorted.sort((a, b) =>
        (prettyAddressName(a) || "zzz").localeCompare(prettyAddressName(b) || "zzz"),
      );
    } else if (sortBy === "address") {
      sorted.sort((a, b) => (a.address || "").localeCompare(b.address || ""));
    }
    return sorted;
  }, [data, filter, labels, sortBy, compareOpen, parsedCompare, addrIndex, showHistorical, activeRows]);

  const compareSummary = useMemo(() => {
    if (!compareOpen) return null;
    let matched = 0;
    let missing = 0;
    for (const a of parsedCompare) (addrIndex.has(a) ? matched++ : missing++);
    return { total: parsedCompare.length, matched, missing };
  }, [compareOpen, parsedCompare, addrIndex]);

  const onAnalyze = async (e) => {
    e.preventDefault();
    const addr = newAddress.trim();
    if (!addr) return;
    setAnalyzing(true);
    setAnalyzeResult(null);
    try {
      const res = await api("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          address: addr,
          company: companyName,
          name: newName.trim() || null,
        }),
      });
      setAnalyzeResult({ ok: true, job: res });
      setNewAddress("");
      setNewName("");
      setTimeout(refresh, 2000);
    } catch (err) {
      setAnalyzeResult({ ok: false, error: err?.message || String(err) });
    } finally {
      setAnalyzing(false);
    }
  };

  // Queue analysis for a single missing address without leaving compare
  // mode. The row stays in the "missing" group until refresh picks it up
  // (the job has to write a Contract row first).
  const onAnalyzeMissing = async (address) => {
    setBusyAddr(address);
    try {
      await api("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address, company: companyName }),
      });
      setTimeout(refresh, 2000);
    } catch (err) {
      window.alert(`Queue failed: ${err?.message || err}`);
    } finally {
      setBusyAddr(null);
    }
  };

  // Bulk-analyze every discovered-but-not-analyzed row in the current
  // view. `bulkAnalyzeCandidates` re-applies the historical filter so it
  // stays safe even when the user toggled "Show N historical" — those
  // never get auto-queued.
  const bulkPendingRows = useMemo(
    () => (compareOpen ? [] : bulkAnalyzeCandidates(rows, currentImplAddrs)),
    [rows, currentImplAddrs, compareOpen],
  );

  const onBulkAnalyzePending = async () => {
    if (bulkPendingRows.length === 0) return;
    const ok = window.confirm(
      `Queue analysis for ${bulkPendingRows.length} pending address`
        + `${bulkPendingRows.length === 1 ? "" : "es"}`
        + ` in the current view?`,
    );
    if (!ok) return;
    setBulkAnalyzing(true);
    try {
      for (const r of bulkPendingRows) {
        try {
          // eslint-disable-next-line no-await-in-loop
          await api("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              address: r.address,
              chain: r.chain || null,
              company: companyName,
              name: r.name || null,
            }),
          });
        } catch (err) {
          console.error("Queue failed for", r.address, err);
        }
      }
      setTimeout(refresh, 2000);
    } finally {
      setBulkAnalyzing(false);
    }
  };

  const onAnalyzeAllMissing = async () => {
    if (!compareSummary || compareSummary.missing === 0) return;
    const ok = window.confirm(
      `Queue analysis for ${compareSummary.missing} missing addresses?`,
    );
    if (!ok) return;
    const missing = parsedCompare.filter((a) => !addrIndex.has(a));
    for (const addr of missing) {
      try {
        // Serial loop — the /api/analyze endpoint is cheap (just writes a
        // Job row), so no need to parallelize and risk hammering it.
        // eslint-disable-next-line no-await-in-loop
        await api("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ address: addr, company: companyName }),
        });
      } catch (err) {
        console.error("Queue failed for", addr, err);
      }
    }
    setTimeout(refresh, 2000);
  };

  const onDeleteAddress = async (row) => {
    const label = prettyAddressName(row) || row.address;
    const ok = window.confirm(
      `Delete "${label}" (${row.address}) from ${companyName}?\n\nThis removes the contract row and its audit coverage links.`,
    );
    if (!ok) return;
    setBusyAddr(row.address);
    try {
      await api(
        `/api/company/${encodeURIComponent(companyName)}/addresses/${row.address}`,
        { method: "DELETE" },
      );
      refresh();
    } catch (err) {
      window.alert(`Delete failed: ${err?.message || err}`);
    } finally {
      setBusyAddr(null);
    }
  };

  const handleRowClick = (row) => {
    if (!onSelectContract) return;
    if (row._compareStatus === "missing") return;
    onSelectContract(row);
    onClose?.();
  };

  return (
    <div className="ps-audit-modal-backdrop" onClick={onClose}>
      <div
        className="ps-audit-modal ps-addresses-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="ps-audit-modal-header">
          <div>
            <p className="eyebrow" style={{ margin: 0 }}>Addresses</p>
            <h2 style={{ margin: "4px 0 0", fontSize: 18 }}>
              {data ? `${rows.length} of ${data.all_addresses?.length ?? 0}` : "Loading…"}
              <span style={{ color: "#94a3b8", fontWeight: 400, marginLeft: 8 }}>
                {companyName}
              </span>
              {data && historicalCount > 0 && !compareOpen && (
                <button
                  type="button"
                  className="ps-addresses-modal-historical-toggle"
                  onClick={() => setShowHistorical((v) => !v)}
                  title="Stale impls behind upgraded proxies. Kept for audit-coverage matching; hidden by default."
                >
                  {showHistorical
                    ? `Hide ${historicalCount} historical`
                    : `Show ${historicalCount} historical`}
                </button>
              )}
            </h2>
          </div>
          <div className="ps-audit-modal-actions">
            <button
              type="button"
              className={`ps-audit-modal-btn ${compareOpen ? "primary" : ""}`}
              onClick={() => setCompareOpen((v) => !v)}
              title="Paste a list of addresses to highlight which are already tracked"
            >
              {compareOpen ? "Compare ✓" : "Compare"}
            </button>
            <button type="button" className="ps-audit-modal-btn" onClick={onClose} title="Close">
              ✕
            </button>
          </div>
        </div>

        {compareOpen && (
          <div className="ps-addresses-modal-compare">
            <textarea
              className="ps-addresses-modal-compare-input"
              placeholder="Paste a list of 0x addresses (any separator — spaces, commas, newlines)…"
              value={compareInput}
              onChange={(e) => setCompareInput(e.target.value)}
              rows={3}
            />
            <div className="ps-addresses-modal-compare-summary">
              {compareSummary && compareSummary.total > 0 ? (
                <>
                  <span className="ps-addresses-modal-chip ok">
                    {compareSummary.matched} matched
                  </span>
                  <span className="ps-addresses-modal-chip err">
                    {compareSummary.missing} missing
                  </span>
                  <span style={{ color: "#94a3b8", fontSize: 11 }}>
                    of {compareSummary.total} parsed
                  </span>
                  {compareSummary.missing > 0 && (
                    <button
                      type="button"
                      className="ps-addresses-modal-compare-analyze"
                      onClick={onAnalyzeAllMissing}
                    >
                      Analyze all {compareSummary.missing} missing
                    </button>
                  )}
                </>
              ) : (
                <span style={{ color: "#64748b", fontSize: 11 }}>
                  Nothing pasted yet — paste addresses above to see matches.
                </span>
              )}
            </div>
          </div>
        )}

        {!compareOpen && (
          <div className="ps-addresses-modal-toolbar">
            <input
              type="text"
              className="ps-addresses-modal-search"
              placeholder="Filter by address, name, or label…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <div className="ps-addresses-modal-sort">
              <label>Sort:</label>
              <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
                <option value="rank">Rank (high → low)</option>
                <option value="name">Name (A → Z)</option>
                <option value="address">Address</option>
              </select>
            </div>
            {bulkPendingRows.length > 0 && (
              <button
                type="button"
                className="ps-addresses-modal-bulk-analyze"
                disabled={bulkAnalyzing}
                onClick={onBulkAnalyzePending}
                title="Queue analysis for every discovered-but-not-analyzed row in the current view. Historical impls are never included."
              >
                {bulkAnalyzing
                  ? "Queuing…"
                  : `Analyze ${bulkPendingRows.length} pending`}
              </button>
            )}
          </div>
        )}

        {!compareOpen && (
          <form className="ps-addresses-modal-add" onSubmit={onAnalyze}>
            <input
              type="text"
              placeholder="0x… (queue new contract for analysis)"
              value={newAddress}
              onChange={(e) => setNewAddress(e.target.value)}
              disabled={analyzing}
            />
            <input
              type="text"
              placeholder="Display name (optional)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              disabled={analyzing}
            />
            <button type="submit" disabled={analyzing || !newAddress.trim()}>
              {analyzing ? "Queuing…" : "Analyze"}
            </button>
            {analyzeResult && (
              <span className={`ps-addresses-modal-result ${analyzeResult.ok ? "ok" : "err"}`}>
                {analyzeResult.ok
                  ? `Queued job ${analyzeResult.job?.job_id || analyzeResult.job?.id || "?"}`
                  : analyzeResult.error}
              </span>
            )}
          </form>
        )}

        <div className="ps-addresses-modal-body">
          {error && <p className="ps-audit-modal-empty">Failed to load: {error}</p>}
          {!error && !data && <p className="ps-audit-modal-empty">Loading addresses…</p>}
          {data && rows.length === 0 && !compareOpen && (
            <p className="ps-audit-modal-empty">No addresses match “{filter}”.</p>
          )}
          {data && compareOpen && parsedCompare.length === 0 && (
            <p className="ps-audit-modal-empty">Paste addresses above to start comparing.</p>
          )}
          {data && rows.length > 0 && (
            <table className="ps-addresses-modal-table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Rank</th>
                  <th>Name / Label</th>
                  <th style={{ width: 90 }}>Chain</th>
                  <th>Address</th>
                  <th style={{ width: 100 }}>Status</th>
                  <th style={{ width: 130 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const rank = r.rank_score == null ? null : r.rank_score.toFixed(2);
                  const isMissing = r._compareStatus === "missing";
                  return (
                    <tr
                      key={`${r.chain || "?"}-${r.address}`}
                      className={[
                        onSelectContract && !isMissing ? "ps-addresses-modal-row--clickable" : "",
                        isMissing ? "ps-addresses-modal-row--missing" : "",
                        r._compareStatus === "matched" ? "ps-addresses-modal-row--matched" : "",
                      ]
                        .filter(Boolean)
                        .join(" ")}
                      onClick={() => handleRowClick(r)}
                    >
                      <td className="ps-addresses-modal-rank">
                        {rank ?? <span style={{ opacity: 0.4 }}>—</span>}
                      </td>
                      <td className="ps-addresses-modal-name">
                        <div className="ps-addresses-modal-name-line">
                          <span>
                            {prettyAddressName(r) || (
                              <span style={{ opacity: 0.5 }}>
                                {isMissing ? "(not yet analyzed)" : "(unnamed)"}
                              </span>
                            )}
                          </span>
                          {r.is_proxy && <span className="ps-addresses-modal-chip">proxy</span>}
                        </div>
                        {!isMissing && (
                          <div
                            className="ps-addresses-modal-label"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <AddressLabelInline
                              address={r.address}
                              labels={labels}
                              refreshAll={refresh}
                              size="xs"
                            />
                          </div>
                        )}
                      </td>
                      <td>
                        {r.chain ? (
                          <span className="ps-addresses-modal-chip">{r.chain}</span>
                        ) : (
                          <span style={{ opacity: 0.4 }}>—</span>
                        )}
                      </td>
                      <td className="ps-addresses-modal-addr mono">{r.address}</td>
                      <td>
                        {compareOpen ? (
                          isMissing ? (
                            <span className="ps-addresses-modal-chip err">missing</span>
                          ) : (
                            <span className="ps-addresses-modal-chip ok">matched</span>
                          )
                        ) : r.analyzed ? (
                          <span className="ps-addresses-modal-chip ok">analyzed</span>
                        ) : (
                          <span className="ps-addresses-modal-chip pending">discovered</span>
                        )}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        {isMissing ? (
                          <button
                            type="button"
                            className="ps-audit-modal-btn"
                            disabled={busyAddr === r.address}
                            onClick={() => onAnalyzeMissing(r.address)}
                          >
                            {busyAddr === r.address ? "…" : "Analyze"}
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="ps-audit-modal-btn ps-addresses-modal-delete-btn"
                            disabled={busyAddr === r.address}
                            onClick={() => onDeleteAddress(r)}
                            title="Remove from protocol"
                          >
                            {busyAddr === r.address ? "…" : "Delete"}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
