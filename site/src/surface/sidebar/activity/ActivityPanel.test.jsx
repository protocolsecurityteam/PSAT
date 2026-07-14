// Render tests for the Activity tab (collapsed Monitor + Upgrades). Covers the
// proxy timeline with enrollment boundary + impl attribution, the non-proxy
// empty state, protocol-wide mode, and admin-vs-non-admin control visibility.

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";

import { ActivityPanel } from "./ActivityPanel.jsx";
import { setFetchHandler } from "../../../test/fetchMock.js";

const PROXY = "0x30880000000000000000000000000000000000f2";
const SAFE = "0x2aca00000000000000000000000000000000008a";
const POOL = "0x9999000000000000000000000000000000009999";
const I1 = "0x1111111111111111111111111111111111111111";
const I2 = "0x2222222222222222222222222222222222222222";
const CUR = "0x3333333333333333333333333333333333333333";

const PROXY_MACHINE = { address: PROXY, name: "LiquidityPool", is_proxy: true, job_id: "job1", chain: "ethereum" };
const SAFE_MACHINE = { address: SAFE, name: "Treasury Safe", is_proxy: false, chain: "ethereum" };

const PROXY_CONTRACT = {
  id: "c-proxy",
  address: PROXY,
  chain: "ethereum",
  contract_type: "proxy",
  monitoring_config: { watch_upgrades: true, watch_ownership: true },
  last_known_state: { implementation: CUR, paused: false },
  last_scanned_block: 400,
  enrollment_block: 250,
  is_active: true,
  created_at: "2025-12-01T00:00:00Z",
  updated_at: "2026-07-13T00:00:00Z",
};

const SAFE_CONTRACT = {
  id: "c-safe",
  address: SAFE,
  chain: "ethereum",
  contract_type: "safe",
  monitoring_config: { watch_safe_signers: true },
  last_known_state: { threshold: 4 },
  last_scanned_block: 400,
  enrollment_block: 250,
  is_active: true,
  created_at: "2025-12-01T00:00:00Z",
  updated_at: "2026-07-13T00:00:00Z",
};

const HISTORY = {
  proxies: {
    [PROXY.toLowerCase()]: {
      proxy_type: "ERC1967",
      current_implementation: CUR,
      upgrade_count: 2,
      implementations: [
        { address: I1, block_introduced: 100, block_replaced: 200, timestamp_introduced: 1700000000 },
        { address: I2, block_introduced: 200, block_replaced: 300, timestamp_introduced: 1710000000 },
        { address: CUR, block_introduced: 300, timestamp_introduced: 1720000000 },
      ],
    },
  },
};

function evRow(id, type, block, data = {}) {
  return {
    id,
    monitored_contract_id: "c-proxy",
    event_type: type,
    block_number: block,
    tx_hash: `0x${id.padEnd(64, "0")}`,
    data,
    detected_at: new Date(1720000000000 + block).toISOString(),
  };
}

function mockActivity({ contracts = [], monitoredEvents = [], history = null, protocolEvents = [] } = {}) {
  setFetchHandler((url) => /\/api\/protocols\/\d+\/monitoring$/.test(url.pathname), () => contracts);
  setFetchHandler((url) => /\/api\/protocols\/\d+\/subscriptions$/.test(url.pathname), () => []);
  setFetchHandler((url) => /\/api\/protocols\/\d+\/events$/.test(url.pathname), () => protocolEvents);
  setFetchHandler((url) => /\/api\/monitored-events$/.test(url.pathname), () => monitoredEvents);
  setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), () => history || {});
  setFetchHandler((url) => /\/api\/company\/[^/]+\/addresses$/.test(url.pathname), () => ({ all_addresses: [] }));
}

function renderPanel(props) {
  return render(
    <ActivityPanel
      companyData={{ protocol_id: 7 }}
      companyName="etherfi"
      machines={[PROXY_MACHINE, SAFE_MACHINE]}
      selectedMachine={null}
      selectedPrincipal={null}
      onSelect={() => {}}
      isAdmin={false}
      cache={{}}
      onCache={() => {}}
      {...props}
    />,
  );
}

describe("ActivityPanel — proxy entity mode", () => {
  beforeEach(() => {
    mockActivity({
      contracts: [PROXY_CONTRACT],
      monitoredEvents: [
        evRow("eupg", "upgraded", 300, { implementation: CUR }),
        evRow("erole", "role_granted", 260, { account: I1, sender: I2 }),
      ],
      history: HISTORY,
    });
  });

  it("renders the status strip, enrollment boundary, and impl attribution", async () => {
    renderPanel({ selectedMachine: PROXY_MACHINE, isAdmin: true });

    // Status strip identity.
    expect(await screen.findByText("LiquidityPool")).toBeInTheDocument();

    // Enrollment boundary pill.
    await waitFor(() => {
      expect(screen.getByText(/Monitoring started/i)).toBeInTheDocument();
    });

    // Per-event impl attribution: the role event at block 260 fired under I2.
    await waitFor(() => {
      expect(screen.getByText(/under impl 0x2222\.\.\.2222/)).toBeInTheDocument();
    });

    // Deep backfill: the first deployment shows below the line.
    expect(screen.getByText(/First deployment/i)).toBeInTheDocument();
  });

  it("shows a read-only watched-for summary and gates the webhook control on admin", async () => {
    const { unmount } = renderPanel({ selectedMachine: PROXY_MACHINE, isAdmin: true });
    await waitFor(() => expect(screen.getByText("Alerts")).toBeInTheDocument());
    const watch = document.querySelector(".ps-activity-watch");
    // The watched set is derived from enrollment → static chips, never toggles.
    expect(within(watch).getByText("Upgrades")).toBeInTheDocument();
    expect(within(watch).queryByRole("button", { name: /^Upgrades$/ })).toBeNull();
    // Admin sees the one real control: the Discord delivery target.
    expect(within(watch).getByText(/attach Discord/i)).toBeInTheDocument();
    unmount();

    renderPanel({ selectedMachine: PROXY_MACHINE, isAdmin: false });
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
    const watch2 = document.querySelector(".ps-activity-watch");
    // The watched-for summary is public (informational)…
    expect(within(watch2).getByText("Upgrades")).toBeInTheDocument();
    // …but the webhook delivery control is admin-only.
    expect(within(watch2).queryByText(/attach Discord/i)).toBeNull();
  });
});

describe("ActivityPanel — non-proxy entity mode", () => {
  beforeEach(() => {
    mockActivity({ contracts: [SAFE_CONTRACT], monitoredEvents: [] });
  });

  it("renders the non-proxy empty state below the boundary", async () => {
    renderPanel({ selectedMachine: SAFE_MACHINE });
    expect(await screen.findByText("Treasury Safe")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/No activity before the line/i)).toBeInTheDocument();
    });
    // No upgrade backfill for a non-proxy.
    expect(screen.queryByText(/First deployment/i)).not.toBeInTheDocument();
  });
});

describe("ActivityPanel — protocol-wide mode", () => {
  beforeEach(() => {
    mockActivity({
      contracts: [PROXY_CONTRACT, SAFE_CONTRACT],
      protocolEvents: [
        { id: "p1", monitored_contract_id: "c-proxy", event_type: "upgraded", block_number: 300, tx_hash: "0xabc", data: { implementation: CUR }, detected_at: "2026-07-12T00:00:00Z" },
      ],
    });
  });

  it("shows the monitored count and the recent feed when nothing is selected", async () => {
    renderPanel({});
    await waitFor(() => {
      expect(screen.getByText(/addresses monitored/i)).toHaveTextContent("2 addresses monitored");
    });
    expect(screen.getByText(/Recent across protocol/i)).toBeInTheDocument();
  });
});

describe("ActivityPanel — principal selected", () => {
  beforeEach(() => {
    mockActivity({ contracts: [PROXY_CONTRACT] });
  });

  it("shows a 'monitoring not enabled' notice for a non-monitored principal", async () => {
    renderPanel({
      selectedMachine: null,
      selectedPrincipal: { address: SAFE, type: "safe", label: "Treasury" },
    });
    expect(await screen.findByText(/monitoring is not enabled/i)).toBeInTheDocument();
    expect(screen.queryByText(/Recent across protocol/i)).not.toBeInTheDocument();
  });
});

describe("ActivityPanel — monitored principal (safe)", () => {
  beforeEach(() => {
    mockActivity({ contracts: [SAFE_CONTRACT], monitoredEvents: [] });
  });

  it("shows the entity timeline when the selected principal is a monitored contract", async () => {
    // A safe IS enrolled for monitoring — selecting it must open its timeline,
    // not the pick-a-contract hint (prototype's "Safe selected" column).
    renderPanel({
      selectedMachine: null,
      selectedPrincipal: { address: SAFE, type: "safe", label: "Treasury Safe" },
    });
    expect(await screen.findByText("Treasury Safe")).toBeInTheDocument();
    expect(screen.getByText("Timeline")).toBeInTheDocument();
    expect(screen.queryByText(/monitoring is not enabled/i)).not.toBeInTheDocument();
  });
});
