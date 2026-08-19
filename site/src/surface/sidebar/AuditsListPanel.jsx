import { useState } from "react";

import { isBytecodeVerifiedAudit } from "../../audits/auditCoverage.js";
import { formatAuditDate } from "../../audits/auditUi.jsx";
import { AuditReadModal } from "../modals/AuditReadModal.jsx";
import { GotoArrow } from "../GotoArrow.jsx";
import { entityKey } from "../entityKey.js";
import { principalLabel, shortAddr } from "../format.js";

// Sentinel activeAuditId value for the summary's "all proven contracts"
// highlight. The picked-audit state is one radio: null (nothing), a numeric
// audit_id (that audit's covered set), or ALL_PROVEN (every proven contract).
const ALL_PROVEN = "all";

// Proof-first audits panel. See site/prototypes/audit-panel/HANDOFF.md.
//
// The governing principle: only assert what we can cryptographically verify.
// v1 carries a single verdict — "Running audited code" — meaning the deployed,
// Etherscan-verified source hash-matches the reviewed commit
// (equivalence_status='proven' + match_type='reviewed_commit', excluding
// proof_kind='cited_only'; gated by isBytecodeVerifiedAudit). Everything
// low-confidence or accusatory (hash_mismatch, pre_fix_unpatched, cited_only,
// name-heuristic matches) is deliberately omitted. Freshness/drift is out of
// scope for v1.
const PROVEN = "#4ade80";

// The one verdict. It lives on the (audit × contract) row, not the audit — a
// single audit can carry a different verdict per contract. v1 has one verdict,
// so every proven row reads the same, but the shape keeps that honest.
function ProvenVerdict() {
  return (
    <span className="ps-audits-verdict">
      <span className="ps-audits-dot" style={{ background: PROVEN }} />
      Running audited code
    </span>
  );
}

// A principal (safe/timelock/EOA) has no bytecode of its own, so audit coverage
// is meaningless for it — audits attach to the contracts it controls. Show an
// honest hint pointing at the controlled set instead of pretending nothing is
// selected. Deliberately NOT `.ps-audits-contract-card`: that class is the
// selected-contract card, whose absence is the regression invariant for a
// principal selection.
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

// One expandable audit row. Collapsed: auditor · date · title · "covers N".
// Expanded: the per-contract breakdown, each contract carrying its proven
// verdict and matched-commit SHA. Expansion is driven by `activeAuditId` so it
// doubles as the canvas highlight (the covered contracts get a green ring).
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

// Whole-protocol view: the proof-first summary + the single Bytecode-verified
// tier. Also rendered beneath the hint when a principal is selected (a
// principal has no coverage of its own, but the protocol-wide proof summary is
// still worth showing).
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
  // The summary doubles as the whole-proven-set control: click it to ring every
  // source-proven contract at once and list them (one meaning — "has a proof");
  // click an audit row to narrow to that audit's set. Mutually exclusive.
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
              <div
                key={c.address}
                className="ps-audits-covrow"
                role="button"
                tabIndex={0}
                onClick={() => onPreview?.(c.address)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onPreview?.(c.address);
                  }
                }}
              >
                <span className="ps-audits-covrow-name">{c.name}</span>
                <span className="ps-audits-covrow-addr">{shortAddr(c.address)}</span>
                {onNavigate && (
                  <GotoArrow
                    onCommit={() =>
                      onNavigate({ type: "contract", address: c.address, label: c.name })
                    }
                    label={`Go to ${c.name}`}
                  />
                )}
              </div>
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

// Contract-selected mode: the audits that source-prove this one contract. The
// verdict here is the same one shown in the whole-protocol breakdown, keyed to
// the selected contract's address.
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
    // Coverage hasn't resolved. A selected principal still gets its honest
    // hint (it doesn't depend on coverageData); anything else has nothing to
    // show until coverage arrives.
    return selectedPrincipal ? (
      <section className="ps-audits-panel">
        <SelectedPrincipalAuditHint principal={selectedPrincipal} />
      </section>
    ) : null;
  }

  // Resolve (chain, address) → machine so covered contracts are legible instead
  // of raw hex, and so off-canvas impl rows collapse into their proxy. machines
  // is activeChain-scoped but coverageData spans all chains, so the join must
  // key on the composite entity — a base twin sharing an address must not
  // resolve to the ethereum machine.
  const contractByKey = new Map();
  if (Array.isArray(machines)) {
    for (const m of machines) {
      const a = (m.address || "").toLowerCase();
      if (a) contractByKey.set(entityKey(m.chain, a), m);
    }
  }

  // `/api/company/{name}` deduplicates impls under their proxy, but
  // `/audit_coverage` returns one row per Contract DB entity (proxy AND impl
  // AND historical impls). The endpoint already unions a proxy's coverage with
  // its impl's, so every logical contract's proof surfaces under its on-canvas
  // (proxy) entity. Skipping entities that aren't on the canvas both drops the
  // duplicate impl rows and gives one entry per logical contract.

  // audit_id → { audit, contracts: [{ name, address, chain, sha }] }, built from
  // the proven set only. `trackedContracts` is the honest denominator (contracts
  // on this surface we have coverage data for); `provenContracts` the numerator.
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

  // Sort audits by date desc (nulls last), then id desc.
  const auditEntries = [...byAudit.values()].sort((x, y) => {
    const dx = x.audit.date || "";
    const dy = y.audit.date || "";
    if (dx !== dy) return dx < dy ? 1 : -1;
    return (y.audit.audit_id || 0) - (x.audit.audit_id || 0);
  });

  // The proven-contract roster the summary dropdown lists (and the canvas rings
  // when "all" is picked): one entry per distinct source-proven entity, named
  // from its on-canvas machine, sorted by name.
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
