// M2 track: Audits tab principal awareness. When a principal (safe/timelock/
// EOA) is selected, the Audits tab must not render the selected-contract
// coverage card — audits attach to contracts, not principals. It shows an
// honest hint naming the principal's controlled count instead.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { AuditsListPanel } from "./AuditsListPanel.jsx";

const PROXY = "0x1111111111111111111111111111111111111111";
const IMPL = "0x2222222222222222222222222222222222222222";
const SAFE = "0x9999999999999999999999999999999999999999";

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

const COVERAGE = {
  audit_count: 1,
  coverage: [{ address: PROXY, contract_name: "Vault", audits: [VERIFIED_AUDIT] }],
};

const MACHINES = [{ address: PROXY, name: "Vault", is_proxy: true, implementation: IMPL }];

const SAFE_PRINCIPAL = {
  address: SAFE,
  type: "safe",
  label: "Multisig",
  controls: [PROXY, "0x5555555555555555555555555555555555555555"],
};

function renderPanel(props) {
  return render(
    <AuditsListPanel
      coverageData={COVERAGE}
      activeAuditId={null}
      onPickAudit={() => {}}
      loading={false}
      error={null}
      machines={MACHINES}
      selectedMachine={null}
      selectedPrincipal={null}
      {...props}
    />,
  );
}

describe("AuditsListPanel principal awareness", () => {
  it("shows an honest hint naming the controlled count, not a coverage card", () => {
    renderPanel({ selectedPrincipal: SAFE_PRINCIPAL });

    // Hint names the principal, its type, and the controlled contract count
    // (2). The sentence is split across text nodes, so match on text content.
    const hint = document.querySelector(".ps-audits-panel-hint");
    expect(hint).toBeInTheDocument();
    const text = hint.textContent || "";
    expect(text).toMatch(/2 controlled contracts/i);
    expect(text).toContain("Multisig");
    expect(text).toContain("Safe");

    // The absence of the selected-contract coverage card is the regression
    // invariant for a principal selection.
    expect(document.querySelector(".ps-audits-contract-card")).not.toBeInTheDocument();
    expect(screen.queryByText(/source-proven audit/i)).not.toBeInTheDocument();
  });

  it("renders the proof-first contract card for a contract selection", () => {
    renderPanel({ selectedMachine: MACHINES[0] });

    // The selected-contract card is present with the single proof-first
    // verdict; the principal hint is absent.
    expect(document.querySelector(".ps-audits-contract-card")).toBeInTheDocument();
    expect(screen.getByText(/source-proven audit/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Running audited code/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/controlled contract/i)).not.toBeInTheDocument();
  });

  it("renders no selected card when nothing is selected", () => {
    renderPanel({});
    expect(document.querySelector(".ps-audits-contract-card")).not.toBeInTheDocument();
    expect(screen.queryByText(/controlled contract/i)).not.toBeInTheDocument();
  });
});
