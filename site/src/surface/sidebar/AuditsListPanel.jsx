import { useState } from "react";
import { isBytecodeVerifiedAudit } from "../../audits/auditCoverage.js";
import { formatAuditDate } from "../../audits/auditUi.jsx";
import { AuditReadModal } from "../modals/AuditReadModal.jsx";
import { entityKey } from "../entityKey.js";
import { principalLabel, shortAddr } from "../format.js";
import { EntityRef } from "../EntityRef.jsx";

// Picked-audit state is one radio: null, an audit_id, or ALL_PROVEN.
const ALL_PROVEN = "all";

// Proof-first audits panel (site/prototypes/audit-panel/HANDOFF.md). Only
// assert what's cryptographically verified: one verdict, "Running audited code"
// (isBytecodeVerifiedAudit). Low-confidence or accusatory states are
// deliberately omitted.
const PROVEN = "#4ade80";

// The verdict lives on the (audit × contract) row: one audit can differ per
// contract.
function ProvenVerdict() {
  return (
    <span className="ps-audits-verdict">
      <span className="ps-audits-dot" style={{ background: PROVEN }} />
      Running audited code
    </span>
  );
}

// A principal has no bytecode, so audits attach to what it controls.
// Deliberately not `.ps-audits-contract-card`, whose absence is the
// principal-selection regression invariant.
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

// Expansion is driven by `activeAuditId`, which also rings the covered
// contracts.
function AuditRow({ audit, contracts, open, onToggle, onRead }) {
  return (
    <div className={`ps-audits-arow ${open ? "open" : ""}`}>
      <div className="ps-audits-arow-head">
        <button
          type="button"
          className="ps-audits-arow-btn"
          aria-expanded={open}
          onClick={onToggle}
        >
          <div className="ps-audits-arow-top">
            <span className="ps-audits-arow-aud">{audit.auditor || "Unknown"}</span>
            <span className="ps-audits-arow-date">{formatAuditDate(audit.date)}</span>
          </div>
          {audit.title && <div className="ps-audits-arow-title">{audit.title}</div>}
          <div className="ps-audits-arow-meta">
            <span className="ps-audits-arow-cnt">
              covers {contracts.length} contract{contracts.length === 1 ? "" : "s"}
            </span>
            <span className="ps-audits-arow-caret">▾</span>
          </div>
        </button>
        <button
          type="button"
          className="ps-audits-arow-read"
          onClick={onRead}
          title="Read audit"
        >
          Read ↗
        </button>
      </div>
      {open && (
        <div className="ps-audits-cc-wrap">
          <div className="ps-audits-cc-lead">How this audit covers each contract</div>
          {contracts.map((c) => (
            <div key={c.address} className="ps-audits-cc-row">
              <div className="ps-audits-cc-top">
                <span className="ps-audits-cc-name">{c.name}</span>
                <span className="ps-audits-cc-addr">{shortAddr(c.address)}</span>
              </div>
              <div className="ps-audits-cc-badges">
                <ProvenVerdict />
                {c.sha && <span className="ps-audits-shabadge">{String(c.sha).slice(0, 7)}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ProtocolAuditsView({
  auditEntries,
  provenContracts,
  provenList,
  trackedContracts,
  activeAuditId,
  onPickAudit,
  onRead,
  onPreview,
  onNavigate,
}) {
  // The summary rings every proven contract; an audit row narrows to its own
  // set. Mutually exclusive.
  const allActive = activeAuditId === ALL_PROVEN;
  const canExpand = provenContracts > 0;
  return (
    <>
      <section className="ps-audits-summary">
        <div className="ps-audits-summary-eyebrow">Audit coverage</div>
        <button
          type="button"
          className={`ps-audits-summary-btn ${allActive ? "active" : ""}`}
          aria-expanded={canExpand ? allActive : undefined}
          aria-disabled={!canExpand}
          onClick={() => canExpand && onPickAudit(allActive ? null : ALL_PROVEN)}
        >
          <span className="ps-audits-summary-line">
            <span className="ps-audits-dot" style={{ background: PROVEN }} />
            <span className="ps-audits-summary-big">
              {provenContracts} / {trackedContracts}
            </span>{" "}
            <span className="ps-audits-summary-rest">
              contract{trackedContracts === 1 ? "" : "s"} have a source proof · {auditEntries.length}{" "}
              audit{auditEntries.length === 1 ? "" : "s"}
            </span>
          </span>
          {canExpand && (
            <span className="ps-audits-summary-caret">{allActive ? "▾" : "▸"}</span>
          )}
        </button>
        {allActive && canExpand && (
          <div className="ps-audits-covlist">
            {provenList.map((c) => (
              <EntityRef key={c.address} address={c.address} name={c.name} onPreview={onPreview} onNavigate={onNavigate} />
            ))}
          </div>
        )}
      </section>

      <div className="ps-audits-panel-hint">
        We only show coverage we can cryptographically verify. Nothing else is asserted.
      </div>

      {auditEntries.length === 0 ? (
        <div className="ps-inspector-empty">No source-proven audit coverage.</div>
      ) : (
        <section className="ps-audits-tier">
          <div className="ps-audits-tier-hdr">
            <span className="ps-audits-dot" style={{ background: PROVEN }} />
            <span className="ps-audits-tier-name">Bytecode-verified</span>
            <span className="ps-audits-tier-count">{auditEntries.length}</span>
          </div>
          <div className="ps-audits-tier-blurb">
            Deployed, Etherscan-verified code cryptographically matches the reviewed commit — the
            only coverage we can prove.
          </div>
          <div className="ps-audits-tier-rows">
            {auditEntries.map(({ audit, contracts }) => (
              <AuditRow
                key={audit.audit_id}
                audit={audit}
                contracts={contracts}
                open={activeAuditId === audit.audit_id}
                onToggle={() =>
                  onPickAudit(activeAuditId === audit.audit_id ? null : audit.audit_id)
                }
                onRead={() => onRead(audit)}
              />
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function SelectedContractAuditsView({ machine, byAudit, onClear, onRead }) {
  const key = entityKey(machine.chain, machine.address);
  const covering = [];
  for (const { audit, contracts } of byAudit.values()) {
    const c = contracts.find((x) => entityKey(x.chain, x.address) === key);
    if (c) covering.push({ audit, sha: c.sha });
  }
  covering.sort((x, y) => {
    const dx = x.audit.date || "";
    const dy = y.audit.date || "";
    if (dx !== dy) return dx < dy ? 1 : -1;
    return (y.audit.audit_id || 0) - (x.audit.audit_id || 0);
  });

  const name = machine.name || shortAddr(machine.address);
  const hasProof = covering.length > 0;

  return (
    <>
      <button type="button" className="ps-audits-back" onClick={() => onClear?.()}>
        ← All audits
      </button>
      <section className="ps-audits-contract-card">
        <div className="ps-audits-sc-name">{name}</div>
        {hasProof ? (
          <>
            <div>
              <ProvenVerdict />
            </div>
            <div className="ps-audits-sc-addr">{machine.address}</div>
            <div className="ps-audits-sc-count">
              {covering.length} source-proven audit{covering.length === 1 ? "" : "s"} cover
              {covering.length === 1 ? "s" : ""} this code
            </div>
          </>
        ) : (
          <div className="ps-audits-sc-count">No source-proven audit covers this contract.</div>
        )}
      </section>

      {hasProof ? (
        covering.map(({ audit, sha }) => (
          <div key={audit.audit_id} className="ps-audits-cm-row">
            <div className="ps-audits-cm-main">
              <div className="ps-audits-arow-top">
                <span className="ps-audits-arow-aud">{audit.auditor || "Unknown"}</span>
                <span className="ps-audits-arow-date">{formatAuditDate(audit.date)}</span>
              </div>
              {audit.title && <div className="ps-audits-arow-title">{audit.title}</div>}
              <div className="ps-audits-cc-badges" style={{ marginTop: 2 }}>
                <ProvenVerdict />
                {sha && <span className="ps-audits-shabadge">{String(sha).slice(0, 7)}</span>}
              </div>
            </div>
            <button
              type="button"
              className="ps-audits-arow-read"
              onClick={() => onRead(audit)}
              title="Read audit"
            >
              Read ↗
            </button>
          </div>
        ))
      ) : (
        <div className="ps-audits-panel-hint">
          It may be name-matched in unverified reports — but we make no coverage claim without a
          proof.
        </div>
      )}
    </>
  );
}

export function AuditsListPanel({
  coverageData,
  activeAuditId,
  onPickAudit,
  loading,
  error,
  machines,
  selectedMachine,
  selectedPrincipal,
  onClearSelection,
  onPreview,
  onNavigate,
}) {
  const [readingAudit, setReadingAudit] = useState(null);

  if (loading)
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">Loading audits…</div>
      </section>
    );
  if (error)
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">Failed: {error}</div>
      </section>
    );
  if (!coverageData) {
    return selectedPrincipal ? (
      <section className="ps-audits-panel">
        <SelectedPrincipalAuditHint principal={selectedPrincipal} />
      </section>
    ) : null;
  }

  // Machines are chain-scoped but coverage spans all chains, so join on the
  // composite entity; off-canvas impl rows collapse into their proxy.
  const contractByKey = new Map();
  if (Array.isArray(machines)) {
    for (const m of machines) {
      const a = (m.address || "").toLowerCase();
      if (a) contractByKey.set(entityKey(m.chain, a), m);
    }
  }

  // The endpoint returns one row per Contract entity (proxy, impl, historical
  // impls) with the proxy already unioned; skipping off-canvas entities leaves
  // one entry per logical contract.

  // `trackedContracts` is the honest denominator: contracts here with coverage
  // data.
  const byAudit = new Map();
  const provenKeys = new Set();
  let trackedContracts = 0;
  for (const entry of coverageData.coverage || []) {
    const addr = (entry.address || "").toLowerCase();
    if (!addr) continue;
    const key = entityKey(entry.chain, addr);
    const machine = contractByKey.get(key);
    if (!machine) continue;
    trackedContracts += 1;
    const name = machine.name || entry.contract_name || shortAddr(addr);
    for (const a of entry.audits || []) {
      if (!isBytecodeVerifiedAudit(a)) continue;
      provenKeys.add(key);
      const id = a.audit_id;
      if (!byAudit.has(id)) byAudit.set(id, { audit: a, contracts: [] });
      byAudit
        .get(id)
        .contracts.push({ name, address: addr, chain: entry.chain, sha: a.matched_commit_sha || null });
    }
  }

  const auditEntries = [...byAudit.values()].sort((x, y) => {
    const dx = x.audit.date || "";
    const dy = y.audit.date || "";
    if (dx !== dy) return dx < dy ? 1 : -1;
    return (y.audit.audit_id || 0) - (x.audit.audit_id || 0);
  });

  const provenList = [...provenKeys]
    .map((key) => {
      const m = contractByKey.get(key);
      const addr = (m.address || "").toLowerCase();
      return { address: addr, name: m.name || shortAddr(addr) };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const openRead = (audit) => {
    const bucket = byAudit.get(audit.audit_id);
    const coveredCount = new Set(
      (bucket?.contracts || []).map((c) => entityKey(c.chain, c.address)),
    ).size;
    setReadingAudit({ audit, coveredCount });
  };

  const protocolView = (
    <ProtocolAuditsView
      auditEntries={auditEntries}
      provenContracts={provenKeys.size}
      provenList={provenList}
      trackedContracts={trackedContracts}
      activeAuditId={activeAuditId}
      onPickAudit={onPickAudit}
      onRead={openRead}
      onPreview={onPreview}
      onNavigate={onNavigate}
    />
  );

  return (
    <>
      <section className="ps-audits-panel">
        {selectedPrincipal ? (
          <>
            <SelectedPrincipalAuditHint principal={selectedPrincipal} />
            {protocolView}
          </>
        ) : selectedMachine ? (
          <SelectedContractAuditsView
            machine={selectedMachine}
            byAudit={byAudit}
            onClear={onClearSelection}
            onRead={openRead}
          />
        ) : (
          protocolView
        )}
      </section>
      {readingAudit && (
        <AuditReadModal
          audit={readingAudit.audit}
          coveredCount={readingAudit.coveredCount}
          onClose={() => setReadingAudit(null)}
        />
      )}
    </>
  );
}
