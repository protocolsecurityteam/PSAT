// M2 track T-upgrades: the Upgrades tab is contract-only by nature. When a
// principal (safe/timelock/EOA) is selected, `selectedMachine` is null — the
// same value as "nothing selected" — so the panel must be told a principal is
// selected and show an explicit hint instead of silently rendering the global
// proxy list as if nothing were picked.

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { UpgradesSidebarPanel } from "./UpgradesSidebarPanel.jsx";

const PROXY = "0x1111111111111111111111111111111111111111";
const IMPL = "0x2222222222222222222222222222222222222222";
const SAFE = "0x3333333333333333333333333333333333333333";

const PROXY_MACHINE = { address: PROXY, name: "Vault", is_proxy: true, proxy_type: "EIP1967", job_id: null };
const PLAIN_MACHINE = { address: IMPL, name: "VaultLogic", is_proxy: false };
const MACHINES = [PROXY_MACHINE, PLAIN_MACHINE];

const SAFE_PRINCIPAL = {
  address: SAFE,
  type: "safe",
  label: "Multisig",
  details: { address: SAFE, owners: [], threshold: 2 },
  controls: [PROXY, IMPL],
};

const GLOBAL_HINT = /click a proxy to see its timeline/i;
const PRINCIPAL_HINT = /choose a contract to see its upgrade timeline/i;

function renderPanel(props) {
  return render(
    <UpgradesSidebarPanel
      machine={null}
      principal={null}
      companyName="etherfi"
      machines={MACHINES}
      onSelect={() => {}}
      cache={{}}
      onCache={() => {}}
      {...props}
    />,
  );
}

describe("UpgradesSidebarPanel principal awareness", () => {
  it("shows an explicit hint (not the global list) when a principal is selected", () => {
    renderPanel({ principal: SAFE_PRINCIPAL });
    // The hint names the principal and points at its contracts.
    expect(screen.getByText(PRINCIPAL_HINT)).toBeInTheDocument();
    expect(screen.getByText(/Multisig/)).toBeInTheDocument();
    // Global proxy list is suppressed: its hint and proxy rows are gone.
    expect(screen.queryByText(GLOBAL_HINT)).not.toBeInTheDocument();
    expect(screen.queryByText("Vault")).not.toBeInTheDocument();
    // No proxy upgrade timeline for a principal.
    expect(document.querySelector(".ps-upgrades-sidebar-body")).toBeNull();
  });

  it("falls back to the short address when the principal has no label", () => {
    renderPanel({ principal: { ...SAFE_PRINCIPAL, label: undefined } });
    expect(screen.getByText(PRINCIPAL_HINT)).toBeInTheDocument();
    // shortAddr(SAFE) short form present, no "undefined" leakage.
    expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
  });

  it("renders the contract branch (not the principal hint) when a contract is selected", () => {
    // A non-proxy contract exercises the contract path without a network
    // fetch; the point is the principal hint and global list are both absent.
    renderPanel({ machine: PLAIN_MACHINE });
    expect(screen.queryByText(PRINCIPAL_HINT)).not.toBeInTheDocument();
    expect(screen.queryByText(GLOBAL_HINT)).not.toBeInTheDocument();
    expect(screen.getByText(/is not a proxy\. No upgrade history\./i)).toBeInTheDocument();
  });

  it("renders the global proxy list unchanged when nothing is selected", () => {
    renderPanel({});
    expect(screen.getByText(GLOBAL_HINT)).toBeInTheDocument();
    expect(screen.getByText("Vault")).toBeInTheDocument();
    expect(screen.queryByText(PRINCIPAL_HINT)).not.toBeInTheDocument();
  });
});
