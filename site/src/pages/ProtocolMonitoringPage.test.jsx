// Covers the collapsible contract groups in the monitoring sidebar:
//   - contracts bucket by contract_type under a labeled group header
//   - groups default to expanded
//   - clicking a header toggles its rows
//   - selecting a contract force-expands its group so the row stays visible

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ProtocolMonitoringPage from "./ProtocolMonitoringPage.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const PROTOCOL_ID = "proto-1";

function makeContract(overrides = {}) {
  return {
    id: `c-${Math.random().toString(36).slice(2, 8)}`,
    address: `0x${"0".repeat(39)}1`,
    chain_id: 1,
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

describe("ProtocolMonitoringPage contract names", () => {
  // Regression: friendlyName used to return `name || implName`, so every
  // proxy fell back to its generic template name ("UUPSProxy") and the
  // whole Proxies group read identically. It must lead with the impl name,
  // matching the addresses page's "Impl (via UUPSProxy)" form.
  function mountWith(contracts, allAddresses) {
    setFetchHandler(/\/api\/company\/[^/]+$/, () => ({ protocol_id: PROTOCOL_ID }));
    setFetchHandler(/\/api\/company\/[^/]+\/addresses$/, () => ({ all_addresses: allAddresses }));
    setFetchHandler(/\/api\/protocols\/[^/]+\/monitoring$/, () => contracts);
    setFetchHandler(/\/api\/protocols\/[^/]+\/subscriptions$/, () => []);
    setFetchHandler(/\/api\/protocols\/[^/]+\/events/, () => []);
    return render(<ProtocolMonitoringPage companyName="acme" />);
  }

  it("shows proxies as 'Impl (via Template)' instead of collapsing to the template name", async () => {
    const eeth = "0x35fa164735182de50811e8e2e824cfb9b6118ac2";
    const weeth = "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee";
    const contracts = [
      makeContract({ id: "proxy-eeth", address: eeth, contract_type: "proxy" }),
      makeContract({ id: "proxy-weeth", address: weeth, contract_type: "proxy" }),
    ];
    const addresses = [
      { address: eeth, name: "UUPSProxy", implementation_name: "EETH", is_proxy: true, chain_id: 1 },
      { address: weeth, name: "UUPSProxy", implementation_name: "WeETH", is_proxy: true, chain_id: 1 },
    ];

    mountWith(contracts, addresses);

    await waitFor(() => expect(screen.getByText(/2 watched/i)).toBeTruthy());

    // Each proxy is distinguishable by its implementation name…
    expect(screen.getByText("EETH (via UUPSProxy)")).toBeTruthy();
    expect(screen.getByText("WeETH (via UUPSProxy)")).toBeTruthy();
    // …and no row renders as the bare template name.
    expect(screen.queryByText("UUPSProxy")).toBeNull();
  });

  it("falls back to a shortened address when the inventory has no name", async () => {
    const addr = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    mountWith([makeContract({ id: "c-unknown", address: addr, contract_type: "proxy" })], []);

    await waitFor(() => expect(screen.getByText(/1 watched/i)).toBeTruthy());

    const row = document.querySelector('[data-contract-id="c-unknown"]');
    expect(row.querySelector(".pm-name").textContent).toBe("0xa0b8...eb48");
  });
});

describe("ProtocolMonitoringPage accessibility", () => {
  it("toggles an event filter chip via the keyboard (Enter/Space)", async () => {
    // Regression: filter chips were <span role="button"> with no onKeyDown
    // and no tabIndex, so keyboard users couldn't activate them. Fix is
    // either real <button>s or role=button + tabIndex=0 + Enter/Space
    // handler. userEvent.keyboard mirrors browser native-button activation
    // (jsdom's fireEvent.keyDown does not), so this fails on the broken
    // <span role="button"> markup and passes once it's a real <button>.
    const user = userEvent.setup();
    const regular = makeContract({ id: "reg-1", contract_type: "regular", address: "0xcccc000000000000000000000000000000000003" });
    mountWithContracts([regular]);

    await waitFor(() => expect(screen.getByText(/1 watched/i)).toBeTruthy());

    const chip = screen.getByRole("button", { name: /^Upgrade$/ });

    // Starts inactive.
    expect(chip.className).not.toMatch(/\bon\b/);

    chip.focus();
    expect(document.activeElement).toBe(chip);

    await user.keyboard("{Enter}");
    expect(chip.className).toMatch(/\bon\b/);

    await user.keyboard(" ");
    expect(chip.className).not.toMatch(/\bon\b/);
  });

  it("gives the webhook URL and label inputs accessible names", async () => {
    // Regression: the modal's two inputs used placeholder-only labelling.
    // Screen readers don't announce placeholders as the field's name, so
    // a user navigating by Tab hears "edit, blank" with no idea what to
    // type. Fix requires aria-label or a wrapping <label>.
    const regular = makeContract({ id: "reg-1", contract_type: "regular", address: "0xcccc000000000000000000000000000000000003" });
    mountWithContracts([regular]);

    await waitFor(() => expect(screen.getByText(/1 watched/i)).toBeTruthy());

    // Open the webhook modal via the NotifMini CTA.
    fireEvent.click(screen.getByRole("button", { name: /Add →/ }));

    // Both inputs must expose an accessible name. getByRole("textbox",
    // { name }) only matches when the field has a real label/aria-label
    // — placeholders don't qualify.
    expect(screen.getByRole("textbox", { name: /webhook url/i })).toBeTruthy();
    expect(screen.getByRole("textbox", { name: /label/i })).toBeTruthy();
  });
});
