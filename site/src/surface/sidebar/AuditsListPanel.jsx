import { useState } from "react";

import { bytecodeVerifiedAudits, isBytecodeVerifiedAudit } from "../../auditCoverage.js";
import {
  EQUIVALENCE_META,
  formatAuditDate,
  MATCH_TYPE_META,
  MetaBadge,
} from "../../auditUi.jsx";
import { AuditReadModal } from "../modals/AuditReadModal.jsx";
import { principalLabel, shortAddr } from "../format.js";

function SelectedContractAuditCoverage({ machine, coverageData, onPickAudit }) {
  if (!machine || !coverageData) return null;
  const addresses = [machine.address, machine.implementation]
    .filter(Boolean)
    .map((address) => address.toLowerCase());
  const row = (coverageData.coverage || []).find((entry) =>
    addresses.includes(String(entry.address || "").toLowerCase())
  );
  const verifiedAudits = bytecodeVerifiedAudits(row?.audits);

  if (!row || verifiedAudits.length === 0) {
    return (
      <section className="ps-audits-contract-card">
        <div className="ps-audits-contract-top">
          <span>{machine.name || row?.contract_name || shortAddr(machine.address)}</span>
        </div>
        <div className="ps-audits-contract-addr">{row?.address || machine.address}</div>
        <div className="ps-audits-contract-note">No bytecode match</div>
      </section>
    );
  }

  return (
    <section className="ps-audits-contract-card">
      <div className="ps-audits-contract-top">
        <span>{machine.name || row.contract_name || shortAddr(machine.address)}</span>
        <span className="ps-monitor-muted">
          {verifiedAudits.length} bytecode match{verifiedAudits.length === 1 ? "" : "es"}
        </span>
      </div>
      <div className="ps-audits-contract-addr">{row.address}</div>
      <div className="ps-audits-contract-list">
        {verifiedAudits.map((audit) => {
          const matchMeta = MATCH_TYPE_META[audit.match_type] || MATCH_TYPE_META.direct;
          return (
            <button
              key={audit.audit_id}
              type="button"
              className="ps-audits-contract-row"
              onClick={() => onPickAudit?.(audit.audit_id)}
            >
              <div className="ps-audits-contract-row-main">
                <span>{audit.auditor || "Unknown"}</span>
                <span>{formatAuditDate(audit.date)}</span>
              </div>
              {audit.title && <div className="ps-audits-contract-row-title">{audit.title}</div>}
              <div className="ps-audits-contract-badges">
                <MetaBadge meta={matchMeta} />
                {audit.match_confidence && (
                  <span className="ps-badge" style={{ "--badge-accent": "#6b7590", fontSize: 10 }}>
                    {audit.match_confidence}
                  </span>
                )}
                {audit.equivalence_status && EQUIVALENCE_META[audit.equivalence_status] && (
                  <MetaBadge
                    meta={EQUIVALENCE_META[audit.equivalence_status]}
                    title={audit.equivalence_reason || ""}
                  />
                )}
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}

// A principal (safe/timelock/EOA) has no bytecode of its own, so audit coverage
// is meaningless for it — audits attach to the contracts it controls. Show an
// honest hint pointing at the controlled set instead of pretending nothing is
// selected (which read as the leaked-contract card under the old model).
// Deliberately NOT `.ps-audits-contract-card`: that class is the
// selected-contract coverage card, whose absence is the regression invariant
// for a principal selection.
function SelectedPrincipalAuditHint({ principal }) {
  if (!principal) return null;
  const count = (principal.controls || []).length;
  const typeWord =
    principal.type === "timelock" ? "Timelock" : principal.type === "safe" ? "Safe" : "Principal";
  const name = principalLabel(principal.label, principal.type, principal.address);
  return (
    <section className="ps-principal-section">
      <div className="ps-audits-panel-hint">
        {typeWord} {name} selected — audits apply to contracts. Pick one of its {count} controlled
        contract{count === 1 ? "" : "s"} to see its coverage.
      </div>
    </section>
  );
}

export function AuditsListPanel({ coverageData, activeAuditId, onPickAudit, loading, error, machines, selectedMachine, selectedPrincipal }) {
  const [readingAudit, setReadingAudit] = useState(null);
  if (loading) return <section className="ps-principal-section"><div className="ps-inspector-empty">Loading audits…</div></section>;
  if (error) return <section className="ps-principal-section"><div className="ps-inspector-empty">Failed: {error}</div></section>;
  if (!coverageData) {
    // Coverage hasn't resolved. A selected principal still gets its honest
    // hint (it doesn't depend on coverageData); a contract selection has
    // nothing to show until coverage arrives.
    return selectedPrincipal ? (
      <section className="ps-audits-panel">
        <SelectedPrincipalAuditHint principal={selectedPrincipal} />
      </section>
    ) : null;
  }

  // Resolve lowercase addresses → { name, address } using the machines map
  // so covered contracts are legible instead of just raw hex.
  const contractByAddr = new Map();
  if (Array.isArray(machines)) {
    for (const m of machines) {
      const a = (m.address || "").toLowerCase();
      if (a) contractByAddr.set(a, m);
    }
  }

  // `/api/company/{name}` deduplicates impls under their proxy, but
  // `/audit_coverage` returns one row per Contract DB entity — including
  // the impl and any historical impls. Without filtering, a single
  // audit covering one logical contract emits 2+ entries here, and the
  // ones that aren't on the canvas render as "unknown". Skip any
  // address that isn't in `machines` so the audit's covered list
  // collapses to one entry per logical contract.
  const isOnCanvas = (addr) => contractByAddr.has(addr);

  // Invert: audit_id → { audit, addresses: Set<lowercase>, shaByAddr: Map<addr, sha> }
  // Each coverage row has per-(contract, audit) match metadata — notably
  // matched_commit_sha (Tier 2). Capture it here so the modal can render
  // the SHA next to the contract without fetching per-row detail again.
  const byAudit = new Map();
  for (const entry of coverageData.coverage || []) {
    const addr = (entry.address || "").toLowerCase();
    if (!addr) continue;
    if (!isOnCanvas(addr)) continue;
    for (const a of entry.audits || []) {
      if (!isBytecodeVerifiedAudit(a)) continue;
      const id = a.audit_id;
      if (!byAudit.has(id)) {
        byAudit.set(id, { audit: a, addresses: new Set(), shaByAddr: new Map() });
      }
      const bucket = byAudit.get(id);
      bucket.addresses.add(addr);
      if (a.matched_commit_sha) {
        bucket.shaByAddr.set(addr, a.matched_commit_sha);
      }
    }
  }

  // Sort audits by date desc (nulls last), then id desc. Active audit is
  // displayed first via CSS ordering (to surface the coverage list).
  const entries = [...byAudit.values()].sort((x, y) => {
    const dx = x.audit.date || "";
    const dy = y.audit.date || "";
    if (dx !== dy) return dx < dy ? 1 : -1;
    return (y.audit.audit_id || 0) - (x.audit.audit_id || 0);
  });

  const activeEntry = activeAuditId != null
    ? entries.find((e) => e.audit.audit_id === activeAuditId)
    : null;

  return (
    <>
      <section className="ps-audits-panel">
        {selectedPrincipal ? (
          <SelectedPrincipalAuditHint principal={selectedPrincipal} />
        ) : (
          <SelectedContractAuditCoverage
            machine={selectedMachine}
            coverageData={coverageData}
            onPickAudit={onPickAudit}
          />
        )}
        <div className="ps-audits-panel-hdr">Verified audits ({entries.length})</div>

        {activeEntry && (
          <div className="ps-audits-active-card">
            <div className="ps-audits-active-hdr">
              <span>Covered contracts</span>
              <button
                className="ps-audits-clear"
                onClick={() => onPickAudit(null)}
                title="Clear highlight"
              >
                ✕ clear
              </button>
            </div>
            <div className="ps-audits-covered-list">
              {[...activeEntry.addresses].sort().map((addr) => {
                const m = contractByAddr.get(addr);
                return (
                  <div key={addr} className="ps-audits-covered-row">
                    <span className="ps-audits-covered-name">{m?.name || shortAddr(addr)}</span>
                    <span className="ps-audits-covered-addr">{shortAddr(addr)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div className="ps-audits-list">
          {entries.length === 0 ? (
            <div className="ps-inspector-empty">None</div>
          ) : null}
          {entries.map(({ audit, addresses }) => {
            const isActive = activeAuditId === audit.audit_id;
            return (
              <div
                key={audit.audit_id}
                className={`ps-audits-row ${isActive ? "active" : ""}`}
              >
                <button
                  className="ps-audits-row-main"
                  onClick={() => onPickAudit(isActive ? null : audit.audit_id)}
                >
                  <div className="ps-audits-row-top">
                    <span className="ps-audits-row-auditor">{audit.auditor || "Unknown"}</span>
                    <span className="ps-audits-row-date">{formatAuditDate(audit.date)}</span>
                  </div>
                  {audit.title && <div className="ps-audits-row-title">{audit.title}</div>}
                  <div className="ps-audits-row-meta">
                    matches {addresses.size} contract{addresses.size === 1 ? "" : "s"}
                  </div>
                </button>
                <button
                  className="ps-audits-row-read"
                  onClick={() =>
                    setReadingAudit({
                      audit,
                      addresses,
                      shaByAddr: byAudit.get(audit.audit_id)?.shaByAddr || new Map(),
                    })
                  }
                  title="Read audit"
                >
                  Read ↗
                </button>
              </div>
            );
          })}
        </div>
      </section>
      {readingAudit && (
        <AuditReadModal
          audit={readingAudit.audit}
          addresses={readingAudit.addresses}
          shaByAddr={readingAudit.shaByAddr}
          machines={contractByAddr}
          onClose={() => setReadingAudit(null)}
        />
      )}
    </>
  );
}
