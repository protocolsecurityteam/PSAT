// Covers the collapsible contract groups in the monitoring sidebar:
//   - contracts bucket by contract_type under a labeled group header
//   - groups default to expanded
//   - clicking a header toggles its rows
//   - selecting a contract force-expands its group so the row stays visible

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";

import ProtocolMonitoringPage from "./ProtocolMonitoringPage.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const PROTOCOL_ID = "proto-1";

function makeContract(overrides = {}) {
  return {
    id: `c-${Math.random().toString(36).slice(2, 8)}`,
    address: `0x${"0".repeat(39)}1`,
    chain: "ethereum",
    contract_type: "regular",
    monitoring_config: {},
    last_known_state: {},
    last_scanned_block: 100,
    needs_polling: false,
    is_active: true,
    enrollment_source: "enrollment",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

function mountWithContracts(contracts) {
  setFetchHandler(/\/api\/company\/[^/]+$/, () => ({ protocol_id: PROTOCOL_ID }));
  setFetchHandler(/\/api\/company\/[^/]+\/addresses$/, () => ({ all_addresses: [] }));
  setFetchHandler(/\/api\/protocols\/[^/]+\/monitoring$/, () => contracts);
  setFetchHandler(/\/api\/protocols\/[^/]+\/subscriptions$/, () => []);
  setFetchHandler(/\/api\/protocols\/[^/]+\/events/, () => []);
  return render(<ProtocolMonitoringPage companyName="acme" />);
}

describe("ProtocolMonitoringPage contract groups", () => {
  it("buckets contracts under labeled, expanded group headers", async () => {
    const safe = makeContract({ id: "safe-1", address: "0xaaaa000000000000000000000000000000000001", contract_type: "safe" });
    const proxy = makeContract({ id: "proxy-1", address: "0xbbbb000000000000000000000000000000000002", contract_type: "proxy" });
    const regular = makeContract({ id: "reg-1", address: "0xcccc000000000000000000000000000000000003", contract_type: "regular" });

    mountWithContracts([safe, proxy, regular]);

    await waitFor(() => {
      expect(screen.getByText(/3 watched/i)).toBeTruthy();
    });

    const safeHeader = screen.getByRole("button", { name: /Safes/ });
    const proxyHeader = screen.getByRole("button", { name: /Proxies/ });
    const regularHeader = screen.getByRole("button", { name: /Regular/ });

    expect(safeHeader.getAttribute("aria-expanded")).toBe("true");
    expect(proxyHeader.getAttribute("aria-expanded")).toBe("true");
    expect(regularHeader.getAttribute("aria-expanded")).toBe("true");

    // All three contract rows visible by default.
    expect(document.querySelector('[data-contract-id="safe-1"]')).toBeTruthy();
    expect(document.querySelector('[data-contract-id="proxy-1"]')).toBeTruthy();
    expect(document.querySelector('[data-contract-id="reg-1"]')).toBeTruthy();
  });

  it("collapses and re-expands a group when its header is clicked", async () => {
    const safe = makeContract({ id: "safe-1", contract_type: "safe", address: "0xaaaa000000000000000000000000000000000001" });
    const regular = makeContract({ id: "reg-1", contract_type: "regular", address: "0xcccc000000000000000000000000000000000003" });

    mountWithContracts([safe, regular]);

    await waitFor(() => expect(screen.getByText(/2 watched/i)).toBeTruthy());

    const regularHeader = screen.getByRole("button", { name: /Regular/ });
    fireEvent.click(regularHeader);

    expect(regularHeader.getAttribute("aria-expanded")).toBe("false");
    expect(document.querySelector('[data-contract-id="reg-1"]')).toBeNull();
    // The safe row stays — collapsing one group must not affect others.
    expect(document.querySelector('[data-contract-id="safe-1"]')).toBeTruthy();

    fireEvent.click(regularHeader);
    expect(regularHeader.getAttribute("aria-expanded")).toBe("true");
    expect(document.querySelector('[data-contract-id="reg-1"]')).toBeTruthy();
  });

  it("keeps the group expanded when a contract inside it is selected", async () => {
    // Regression: clicking a row must not bubble into the group header and
    // accidentally toggle it. The row <button> sits in .pm-group-body, a
    // sibling of the header, so propagation can't reach the header — this
    // test would catch a regression if that structure ever changed.
    const regular = makeContract({ id: "reg-1", contract_type: "regular", address: "0xcccc000000000000000000000000000000000003" });

    mountWithContracts([regular]);

    await waitFor(() => expect(screen.getByText(/1 watched/i)).toBeTruthy());

    const regularHeader = screen.getByRole("button", { name: /Regular/ });
    expect(regularHeader.getAttribute("aria-expanded")).toBe("true");

    fireEvent.click(document.querySelector('[data-contract-id="reg-1"]'));

    expect(regularHeader.getAttribute("aria-expanded")).toBe("true");
    expect(document.querySelector('[data-contract-id="reg-1"].sel')).toBeTruthy();
  });

  it("renders the empty state and no group headers when there are no contracts", async () => {
    mountWithContracts([]);

    await waitFor(() => {
      expect(screen.getByText(/No contracts enrolled/i)).toBeTruthy();
    });

    expect(screen.queryByRole("button", { name: /Safes/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Regular/ })).toBeNull();
  });
});
