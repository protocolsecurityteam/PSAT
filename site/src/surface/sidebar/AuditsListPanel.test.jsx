// Regression test for the surface-page "unknown contract" bug: the
// audit_coverage endpoint returns one row per Contract DB entity
// (proxy AND impl), but /api/company/{name} dedupes impls under their
// proxy before producing the `machines` list. Without the address
// filter in AuditsListPanel, the impl rows fall through to literal
// "unknown" in the covered-contracts list.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { AuditsListPanel } from "./AuditsListPanel.jsx";

const PROXY = "0x1111111111111111111111111111111111111111";
const IMPL = "0x2222222222222222222222222222222222222222";
const HISTORICAL = "0x3333333333333333333333333333333333333333";

const VERIFIED_AUDIT = {
  audit_id: 42,
  auditor: "Trail of Bits",
  title: "V2",
  date: "2024-03-15",
  match_type: "reviewed_commit",
  equivalence_status: "proven",
  proof_kind: "clean",
  bytecode_drift: false,
  matched_commit_sha: "abc1234deadbeef",
};

// Mirrors the live coverage payload: the audit-matcher writes a coverage
// row per Contract DB entity, so a single audit covering one logical
// contract (proxy + impl) shows up here as two rows. Add a historical
// impl row to confirm those are filtered too.
const COVERAGE = {
  audit_count: 1,
  coverage: [
    { address: PROXY, contract_name: "Vault", audits: [VERIFIED_AUDIT] },
    { address: IMPL, contract_name: "VaultV2", audits: [VERIFIED_AUDIT] },
    { address: HISTORICAL, contract_name: "VaultV1", audits: [VERIFIED_AUDIT] },
  ],
};

// `machines` matches what buildMachines returns after /api/company
// dedup runs — proxy stays, impl/historical are gone.
const MACHINES = [
  { address: PROXY, name: "Vault", is_proxy: true, implementation: IMPL },
];

function renderPanel(activeAuditId = null) {
  return render(
    <AuditsListPanel
      coverageData={COVERAGE}
      activeAuditId={activeAuditId}
      onPickAudit={() => {}}
      loading={false}
      error={null}
      machines={MACHINES}
      selectedMachine={null}
    />,
  );
}

describe("AuditsListPanel", () => {
  it("reports the audit covers one logical contract, not three", () => {
    renderPanel();
    // Audit row meta reads "covers N contract(s)" — without the dedup
    // filter this read "covers 3 contracts" because impl + historical
    // slipped in.
    expect(screen.getByText(/covers 1 contract/i)).toBeInTheDocument();
  });

  it("never renders the literal string 'unknown' for off-canvas impls", () => {
    renderPanel(VERIFIED_AUDIT.audit_id);
    // The per-contract breakdown expands when the audit is active.
    expect(screen.getByText("Vault")).toBeInTheDocument();
    expect(screen.queryByText(/unknown/i)).not.toBeInTheDocument();
    // Confirm by absence: only the proxy address renders, not the impl
    // or historical addresses.
    const body = document.body.textContent || "";
    expect(body).not.toContain(IMPL.slice(0, 10));
    expect(body).not.toContain(HISTORICAL.slice(0, 10));
  });

  it("does not attach a base twin's coverage to the ethereum contract sharing its address", () => {
    // Multichain: machines are activeChain-scoped (ethereum here) but
    // coverageData spans all chains. A base twin at the SAME address must not
    // count toward trackedContracts nor render as covering the ethereum
    // contract — coverage joins must key on (chain, address), not bare address.
    const ADDR = "0x1111111111111111111111111111111111111111";
    const ETH_AUDIT = { ...VERIFIED_AUDIT, audit_id: 42, auditor: "Trail of Bits", date: "2024-03-15" };
    const BASE_AUDIT = { ...VERIFIED_AUDIT, audit_id: 99, auditor: "Base Auditor", date: "2024-05-01" };
    const coverage = {
      audit_count: 2,
      coverage: [
        { address: ADDR, chain: "ethereum", contract_name: "Vault", audits: [ETH_AUDIT] },
        { address: ADDR, chain: "base", contract_name: "Vault", audits: [BASE_AUDIT] },
      ],
    };
    const machines = [{ address: ADDR, chain: "ethereum", name: "Vault", is_proxy: true }];
    render(
      <AuditsListPanel
        coverageData={coverage}
        activeAuditId={null}
        onPickAudit={() => {}}
        loading={false}
        error={null}
        machines={machines}
        selectedMachine={null}
      />,
    );
    // Only the ethereum entry is on-canvas → one tracked contract, one audit.
    expect(screen.queryByText(/Base Auditor/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Trail of Bits/i)).toBeInTheDocument();
    // trackedContracts denominator (in ".ps-audits-summary-big") stays 1/1, not
    // 1/2 — the base twin must not double-count.
    const big = document.querySelector(".ps-audits-summary-big");
    expect(big.textContent.replace(/\s+/g, " ").trim()).toBe("1 / 1");
    // Single audit tier entry, not two.
    expect(document.querySelector(".ps-audits-tier-count").textContent).toBe("1");
  });

  it("SelectedContractAuditsView keys covering audits by (chain, address), not bare address", () => {
    const ADDR = "0x1111111111111111111111111111111111111111";
    const ETH_AUDIT = { ...VERIFIED_AUDIT, audit_id: 42, auditor: "Trail of Bits", date: "2024-03-15" };
    const BASE_AUDIT = { ...VERIFIED_AUDIT, audit_id: 99, auditor: "Base Auditor", date: "2024-05-01" };
    const coverage = {
      audit_count: 2,
      coverage: [
        { address: ADDR, chain: "ethereum", contract_name: "Vault", audits: [ETH_AUDIT] },
        { address: ADDR, chain: "base", contract_name: "Vault", audits: [BASE_AUDIT] },
      ],
    };
    const machines = [{ address: ADDR, chain: "ethereum", name: "Vault", is_proxy: true }];
    render(
      <AuditsListPanel
        coverageData={coverage}
        activeAuditId={null}
        onPickAudit={() => {}}
        loading={false}
        error={null}
        machines={machines}
        selectedMachine={machines[0]}
      />,
    );
    // The selected ethereum contract is covered by exactly one audit; the base
    // twin's audit must not attach.
    expect(screen.getByText(/1 source-proven audit covers/i)).toBeInTheDocument();
    expect(screen.queryByText(/Base Auditor/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Trail of Bits/i)).toBeInTheDocument();
  });

  it("falls back to short address when a machine has no name", () => {
    const machinesNoName = [{ address: PROXY, is_proxy: true, name: "" }];
    render(
      <AuditsListPanel
        coverageData={COVERAGE}
        activeAuditId={VERIFIED_AUDIT.audit_id}
        onPickAudit={() => {}}
        loading={false}
        error={null}
        machines={machinesNoName}
        selectedMachine={null}
      />,
    );
    // shortAddr(PROXY) is "0x1111…1111" — confirm we don't fall back to
    // the literal "unknown" string even in this degenerate case.
    expect(screen.queryByText(/^unknown$/i)).not.toBeInTheDocument();
  });
});
