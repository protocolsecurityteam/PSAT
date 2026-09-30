import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client.js";
import { useIsAdmin } from "../api/useIsAdmin.js";
import { listAddressLabels, buildLabelMaps, resolveLabelName } from "../api/addressLabels.js";
import AddressLabelInline from "./AddressLabelInline.jsx";
import {
  candidateReasonText,
  computeCurrentImplAddrs,
  isPureHistorical,
  membershipState,
  prunedReasonText,
  splitMembership,
} from "./addressFilter.js";
import { proxyDisplayName } from "../shared/displayName.js";
import { Modal, ModalTitle } from "../shared/Modal.jsx";
import { coalesceChain, entityKey } from "../surface/entityKey.js";

const ADDRESS_RE = /0x[a-fA-F0-9]{40}/g;

// Contract rows get per-chain overrides, but mainnet and legacy
// NULL rows map to the global row so single-chain behaviour is unchanged.
function rowLabelChain(row) {
  const c = row?.chain;
  if (!c || String(c).toLowerCase() === "ethereum") return null;
  return c;
}

function prettyAddressName(row) {
  return proxyDisplayName({
    name: row?.name,
    isProxy: row?.is_proxy,
    implName: row?.implementation_name,
  });
}

// Pasted spreadsheet text: anything not a 40-hex address is dropped.
function parseAddressList(raw) {
  const hits = String(raw || "").match(ADDRESS_RE) || [];
  const seen = new Set();
  for (const h of hits) seen.add(h.toLowerCase());
  return [...seen];
}

export default function AddressesModal({ companyName, onClose }) {
  const isAdmin = useIsAdmin();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  // Chain-aware so per-network contract labels resolve.
  const [labels, setLabels] = useState(() => ({ global: new Map(), byChain: new Map() }));
  const [filter, setFilter] = useState("");
  const [sortBy, setSortBy] = useState("rank"); // rank | name | address
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [newAddress, setNewAddress] = useState("");
  const [newName, setNewName] = useState("");
  const [compareOpen, setCompareOpen] = useState(false);
  const [compareInput, setCompareInput] = useState("");
  const [busyAddr, setBusyAddr] = useState(null);
  const [showHistorical, setShowHistorical] = useState(false);
  const [showPruned, setShowPruned] = useState(false);

  const refresh = useCallback(() => {
    let cancelled = false;
    // Just the inventory (~167 KB); CompanyOverview already fetched the full
    // payload.
    api(`/api/company/${encodeURIComponent(companyName)}/addresses`)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(e.message); });
    listAddressLabels()
      .then((resp) => {
        if (cancelled) return;
        setLabels(buildLabelMaps(resp));
      })
      .catch(() => { /* labels are optional */ });
    return () => { cancelled = true; };
  }, [companyName]);

  useEffect(() => {
    const cleanup = refresh();
    return cleanup;
  }, [refresh]);

  // (chain, address) keys so the same address on two chains
  // isn't collapsed.
  const addrIndex = useMemo(() => {
    const m = new Map();
    for (const r of data?.all_addresses || []) {
      m.set(entityKey(r.chain, r.address), r);
    }
    return m;
  }, [data]);

  // Pasted input is chainless, so keyed by bare address with a deterministic
  // winner (ethereum, else first) so labels don't flip.
  const compareWinner = useMemo(() => {
    const m = new Map();
    for (const r of addrIndex.values()) {
      const addr = String(r.address || "").toLowerCase();
      if (!addr) continue;
      const existing = m.get(addr);
      if (!existing || (coalesceChain(r.chain) === "ethereum" && coalesceChain(existing.chain) !== "ethereum")) {
        m.set(addr, r);
      }
    }
    return m;
  }, [addrIndex]);

  // Keeps live impls visible even when their only source is the upgrade-history
  // sweep.
  const currentImplAddrs = useMemo(
    () => computeCurrentImplAddrs(data?.all_addresses || []),
    [data],
  );

  // From the payload's membership_state, never derived client-side.
  const { members, candidates, pruned } = useMemo(
    () => splitMembership(data?.all_addresses || []),
    [data],
  );

  const { activeRows, historicalCount } = useMemo(() => {
    const active = [];
    let hist = 0;
    for (const r of members) {
      if (isPureHistorical(r, currentImplAddrs)) hist += 1;
      else active.push(r);
    }
    return { activeRows: active, historicalCount: hist };
  }, [members, currentImplAddrs]);

  const parsedCompare = useMemo(() => parseAddressList(compareInput), [compareInput]);

  const rows = useMemo(() => {
    if (compareOpen && parsedCompare.length > 0) {
      const matched = [];
      const missing = [];
      for (const a of parsedCompare) {
        const hit = compareWinner.get(a);
        // Pruned rows are tracked (never re-queued) but proven code-absent, so
        // not "matched".
        if (hit) matched.push({ ...hit, _compareStatus: membershipState(hit) === "pruned" ? "pruned" : "matched" });
        else missing.push({ address: a, _compareStatus: "missing", name: "", is_proxy: false, analyzed: false });
      }
      return [...matched, ...missing];
    }

    // Compare mode uses the full inventory; pasted lists may include historical
    // impls.
    const all = showHistorical ? members : activeRows;
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? all.filter((r) => {
          const addr = (r.address || "").toLowerCase();
          const name = (r.name || "").toLowerCase();
          const impl = (r.implementation_name || "").toLowerCase();
          const label = (resolveLabelName(labels, addr, rowLabelChain(r)) || "").toLowerCase();
          return (
            addr.includes(q) ||
            name.includes(q) ||
            impl.includes(q) ||
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
  }, [filter, labels, sortBy, compareOpen, parsedCompare, compareWinner, showHistorical, members, activeRows]);

  const candidateRows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = q
      ? candidates.filter((r) => {
          const addr = (r.address || "").toLowerCase();
          const name = (r.name || "").toLowerCase();
          return addr.includes(q) || name.includes(q);
        })
      : candidates;
    return [...list].sort((a, b) => (a.name || "zzz").localeCompare(b.name || "zzz"));
  }, [candidates, filter]);

  const compareSummary = useMemo(() => {
    if (!compareOpen) return null;
    let matched = 0;
    let missing = 0;
    for (const a of parsedCompare) (compareWinner.has(a) ? matched++ : missing++);
    return { total: parsedCompare.length, matched, missing };
  }, [compareOpen, parsedCompare, compareWinner]);

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

  // The row stays "missing" until the job writes a Contract row.
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

  const onAnalyzeAllMissing = async () => {
    if (!compareSummary || compareSummary.missing === 0) return;
    const ok = window.confirm(
      `Queue analysis for ${compareSummary.missing} missing addresses?`,
    );
    if (!ok) return;
    const missing = parsedCompare.filter((a) => !compareWinner.has(a));
    for (const addr of missing) {
      try {
        // Serial: the endpoint just writes a Job row.
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

  return (
    <Modal
      className="ps-addresses-modal"
      onClose={onClose}
      header={
        <ModalTitle
          eyebrow="Addresses"
          subtitle={companyName}
          extra={data && historicalCount > 0 && !compareOpen && (
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
        >
          {data ? `${rows.length} of ${data.all_addresses?.length ?? 0}` : "Loading…"}
        </ModalTitle>
      }
      actions={
        <button
          type="button"
          className={`ps-audit-modal-btn ${compareOpen ? "primary" : ""}`}
          onClick={() => setCompareOpen((v) => !v)}
          title="Paste a list of addresses to highlight which are already tracked"
        >
          {compareOpen ? "Compare ✓" : "Compare"}
        </button>
      }
    >

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
                <span className="tag tag-pill ps-addresses-modal-chip ok">
                  {compareSummary.matched} matched
                </span>
                <span className="tag tag-pill ps-addresses-modal-chip err">
                  {compareSummary.missing} missing
                </span>
                <span style={{ color: "#94a3b8", fontSize: 11 }}>
                  of {compareSummary.total} parsed
                </span>
                {isAdmin && compareSummary.missing > 0 && (
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
        </div>
      )}

      {isAdmin && !compareOpen && (
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
          <button className="btn" type="submit" disabled={analyzing || !newAddress.trim()}>
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
        {data && rows.length === 0 && candidateRows.length === 0 && pruned.length === 0 && !compareOpen && (
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
                <th>Address</th>
                <th style={{ width: 100 }}>Status</th>
                {isAdmin && <th style={{ width: 130 }}>Actions</th>}
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
                      isMissing ? "ps-addresses-modal-row--missing" : "",
                      r._compareStatus === "matched" ? "ps-addresses-modal-row--matched" : "",
                    ]
                      .filter(Boolean)
                      .join(" ")}
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
                        {r.is_proxy && <span className="tag tag-pill ps-addresses-modal-chip">proxy</span>}
                      </div>
                      {!isMissing && (
                        <div
                          className="ps-addresses-modal-label"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <AddressLabelInline
                            address={r.address}
                            labels={labels}
                            chain={rowLabelChain(r)}
                            refreshAll={refresh}
                            size="xs"
                          />
                        </div>
                      )}
                    </td>
                    <td className="ps-addresses-modal-addr mono">{r.address}</td>
                    <td>
                      {compareOpen ? (
                        isMissing ? (
                          <span className="tag tag-pill ps-addresses-modal-chip err">missing</span>
                        ) : r._compareStatus === "pruned" ? (
                          <span className="tag tag-pill ps-addresses-modal-chip" title={prunedReasonText(r)}>
                            pruned
                          </span>
                        ) : (
                          <span className="tag tag-pill ps-addresses-modal-chip ok">matched</span>
                        )
                      ) : r.analyzed ? (
                        <span className="tag tag-pill ps-addresses-modal-chip ok">analyzed</span>
                      ) : (
                        <span className="tag tag-pill ps-addresses-modal-chip pending">discovered</span>
                      )}
                    </td>
                    {isAdmin && (
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
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {data && !compareOpen && candidateRows.length > 0 && (
          <div className="ps-addresses-modal-candidates">
            <p className="eyebrow" style={{ margin: "16px 0 6px" }}>
              Candidates — awaiting verification ({candidateRows.length})
            </p>
            <table className="ps-addresses-modal-table">
              <thead>
                <tr>
                  <th>Name / Label</th>
                  <th>Address</th>
                  <th>Why not verified</th>
                </tr>
              </thead>
              <tbody>
                {candidateRows.map((r) => (
                  <tr key={`${r.chain || "?"}-${r.address}`}>
                    <td className="ps-addresses-modal-name">
                      {prettyAddressName(r) || <span style={{ opacity: 0.5 }}>(unnamed)</span>}
                    </td>
                    <td className="ps-addresses-modal-addr mono">{r.address}</td>
                    <td>
                      <span className="tag tag-pill ps-addresses-modal-chip pending">candidate</span>{" "}
                      <span style={{ color: "#94a3b8", fontSize: 11 }}>{candidateReasonText(r)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && !compareOpen && pruned.length > 0 && (
          <div className="ps-addresses-modal-pruned">
            <button
              type="button"
              className="ps-addresses-modal-historical-toggle"
              onClick={() => setShowPruned((v) => !v)}
              title="Nominated addresses proven to hold no code at the probed block."
            >
              {showPruned ? `Hide ${pruned.length} pruned` : `Show ${pruned.length} pruned`}
            </button>
            {showPruned && (
              <table className="ps-addresses-modal-table">
                <thead>
                  <tr>
                    <th>Name / Label</th>
                    <th>Address</th>
                    <th>Why pruned</th>
                  </tr>
                </thead>
                <tbody>
                  {pruned.map((r) => (
                    <tr key={`${r.chain || "?"}-${r.address}`}>
                      <td className="ps-addresses-modal-name">
                        {prettyAddressName(r) || <span style={{ opacity: 0.5 }}>(unnamed)</span>}
                      </td>
                      <td className="ps-addresses-modal-addr mono">{r.address}</td>
                      <td>
                        <span className="tag tag-pill ps-addresses-modal-chip err">pruned</span>{" "}
                        <span style={{ color: "#94a3b8", fontSize: 11 }}>{prunedReasonText(r)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
