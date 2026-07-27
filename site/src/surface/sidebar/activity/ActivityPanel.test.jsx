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

// A second proxy, on a different job, whose history is already in the shared
// cache — i.e. proven-present without a fetch. The discriminating control for
// the not-determined marker: nothing about this entity is unknown.
const POOL_MACHINE = { address: POOL, name: "Pool", is_proxy: true, job_id: "job2", chain: "ethereum" };
const POOL_CONTRACT = { ...PROXY_CONTRACT, id: "c-pool", address: POOL };
const POOL_CACHE = {
  job2: {
    history: {
      proxies: {
        [POOL.toLowerCase()]: {
          proxy_type: "ERC1967",
          current_implementation: CUR,
          upgrade_count: 1,
          implementations: [{ address: CUR, block_introduced: 300, timestamp_introduced: 1720000000 }],
        },
      },
    },
  },
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

function panelElement(props) {
  return (
    <ActivityPanel
      companyData={{ protocol_id: 7 }}
      companyName="etherfi"
      machines={[PROXY_MACHINE, SAFE_MACHINE, POOL_MACHINE]}
      selectedMachine={null}
      selectedPrincipal={null}
      onSelect={() => {}}
      isAdmin={false}
      cache={{}}
      onCache={() => {}}
      {...props}
    />
  );
}

function renderPanel(props) {
  return render(panelElement(props));
}

const notDetermined = () =>
  new Response(JSON.stringify({ detail: "Artifact state not determined" }), {
    status: 503,
    headers: { "Content-Type": "application/json", "X-PSAT-Artifact-State": "not_determined" },
  });

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

describe("ActivityPanel — multichain (F4)", () => {
  // One address deployed on two chains. The ethereum row is a plain safe; the
  // base row is a proxy with upgrade history. The ethereum row is LAST in the
  // payload, so the old bare-address last-wins map would resolve the WRONG
  // (ethereum) row for a base selection. The (chain, address) key must pick base.
  const SHARED = "0x7777000000000000000000000000000000007777";
  const ETH_SAFE_ROW = {
    id: "c-eth", address: SHARED, chain: "ethereum", contract_type: "safe",
    monitoring_config: { watch_safe_signers: true }, last_known_state: { threshold: 2 },
    last_scanned_block: 400, enrollment_block: 250, is_active: true,
    created_at: "2025-12-01T00:00:00Z", updated_at: "2026-07-13T00:00:00Z",
  };
  const BASE_PROXY_ROW = {
    id: "c-base", address: SHARED, chain: "base", contract_type: "proxy",
    monitoring_config: { watch_upgrades: true }, last_known_state: { implementation: CUR },
    last_scanned_block: 400, enrollment_block: 250, is_active: true,
    created_at: "2025-12-01T00:00:00Z", updated_at: "2026-07-13T00:00:00Z",
  };
  const BASE_HISTORY = {
    proxies: {
      [SHARED.toLowerCase()]: {
        proxy_type: "ERC1967", current_implementation: CUR, upgrade_count: 2,
        implementations: [
          { address: I1, block_introduced: 100, block_replaced: 200, timestamp_introduced: 1700000000 },
          { address: CUR, block_introduced: 300, timestamp_introduced: 1720000000 },
        ],
      },
    },
  };

  beforeEach(() => {
    // Order matters: ethereum row LAST so a bare-address map would last-wins it.
    mockActivity({ contracts: [BASE_PROXY_ROW, ETH_SAFE_ROW], monitoredEvents: [], history: BASE_HISTORY });
  });

  it("resolves the active chain's monitoring row for a shared address (base row's watch set, not the ethereum row's)", async () => {
    renderPanel({
      selectedMachine: { address: SHARED, name: "SharedProxy", is_proxy: true, job_id: "jbase", chain: "base" },
      chain: "base",
      isAdmin: true,
    });
    // The watched-for summary is derived from the resolved CONTRACT ROW's
    // monitoring_config (unlike the proxy timeline, which is machine-driven).
    // The base row watches upgrades; the ethereum row watches safe signers.
    const watch = await waitFor(() => {
      const el = document.querySelector(".ps-activity-watch");
      expect(el).toBeTruthy();
      return el;
    });
    expect(within(watch).getByText("Upgrades")).toBeInTheDocument(); // base row resolved
    expect(within(watch).queryByText("Safe activity")).toBeNull(); // NOT the ethereum row
  });

  it("scopes the protocol-wide feed to the active chain (base row only, not ethereum)", async () => {
    renderPanel({ chain: "base" });
    await waitFor(() => {
      expect(screen.getByText(/addresses monitored/i)).toHaveTextContent("1 addresses monitored");
    });
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

describe("ActivityPanel — upgrade history the read could not answer", () => {
  // The timeline draws a proxy with no history as a proxy that has never been
  // upgraded. Whenever /artifact/upgrade_history fails to answer, that render is
  // a claim the server did not make, so the panel says so. A 404 is the only
  // real negative and stays silent.
  //
  // The cases are enumerated because the mapping used to be: only a 503 hedges.
  // A 500, an edge 502/504 (the Fly web-machine autostop shape) and a network
  // failure — which `api` rethrows with no `status` at all — each drew the
  // proven-empty timeline over a history nobody had read. Anything that is not
  // a 404 must reach the marker, including a shape not listed here.
  const upgradeHistoryFails = (respond) => {
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), respond);
  };
  const status = (code, detail) => () =>
    new Response(JSON.stringify({ detail }), {
      status: code,
      headers: { "Content-Type": "application/json" },
    });

  it.each([
    ["503 not determined", status(503, "Artifact state not determined")],
    ["500 server error", status(500, "Internal Server Error")],
    ["502 from the edge", status(502, "Bad Gateway")],
    ["504 from the edge", status(504, "Gateway Timeout")],
    ["a network failure with no status", () => { throw new TypeError("Failed to fetch"); }],
  ])("marks %s as unknown, not absent", async (_label, respond) => {
    upgradeHistoryFails(respond);
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();
  });

  it("leaves a 404 silent — the one proven negative", async () => {
    // NEGATIVE CONTROL. Hedging every failure would put the marker on a proxy
    // whose history the server positively reports it does not have, which is a
    // real answer; the cases above cannot see that over-correction.
    upgradeHistoryFails(status(404, "Artifact not found"));
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
  });

  // The pair above unmounts between arms, so it cannot see the marker outliving
  // the selection that earned it. ActivityPanel renders EntityActivity with no
  // key, so React reuses the instance across selections: a marker held as a bare
  // boolean hedged the *next* entity. These two are the reachable sequences —
  // both render "unknown, not absent" over something that is not unknown.
  it("drops the marker when the next selection's history is served from cache", async () => {
    mockActivity({ contracts: [PROXY_CONTRACT, POOL_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), notDetermined);

    const { rerender } = renderPanel({ selectedMachine: PROXY_MACHINE, cache: POOL_CACHE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();

    rerender(panelElement({ selectedMachine: POOL_MACHINE, cache: POOL_CACHE }));
    // Proven-present: the cached history renders its implementations.
    expect(await screen.findByText(/First deployment/i)).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
  });

  it("drops the marker when the next selection is not a proxy at all", async () => {
    mockActivity({ contracts: [PROXY_CONTRACT, SAFE_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), notDetermined);

    const { rerender } = renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();

    rerender(panelElement({ selectedMachine: SAFE_MACHINE }));
    expect(await screen.findByText("Treasury Safe")).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
  });
});

// The marker is the hedge; these two are the positive claims held in the same
// reused component. Both arrive at the next selection through a path where the
// new answer is still in flight — the case the two cache-hit / non-proxy tests
// above cannot reach, because both of those paths set the state synchronously.
describe("ActivityPanel — state that must not outlive its selection", () => {
  it("does not render the previous proxy's upgrade history while the new one is in flight", async () => {
    mockActivity({ contracts: [PROXY_CONTRACT, POOL_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/analyses\/job1\/artifact\/upgrade_history$/.test(url.pathname), () => HISTORY);
    // job2 never resolves: nothing is known about Pool yet.
    setFetchHandler(
      (url) => /\/analyses\/job2\/artifact\/upgrade_history$/.test(url.pathname),
      () => new Promise(() => {}),
    );

    const { rerender, container } = renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/First deployment/i)).toBeInTheDocument();

    rerender(panelElement({ selectedMachine: POOL_MACHINE }));
    expect(await screen.findByText("Pool")).toBeInTheDocument();
    // LiquidityPool's proven timeline, attributed to Pool. The `proxy` memo
    // falls back to Object.values(history.proxies)[0], so the stale payload
    // renders even though Pool's address is not one of its keys.
    const entity = container.querySelector(".ps-activity-entity");
    expect(/First deployment/i.test(entity.textContent)).toBe(false);
    expect(entity.textContent).not.toContain(I1.slice(0, 8));
  });

  it("does not render the previous contract's events while the new one's are in flight", async () => {
    mockActivity({ contracts: [PROXY_CONTRACT, POOL_CONTRACT] });
    setFetchHandler(
      (url) => /\/api\/monitored-events$/.test(url.pathname),
      (url) =>
        url.searchParams.get("address") === PROXY
          ? [evRow("erole", "role_granted", 260, { account: I1, sender: I2 })]
          : new Promise(() => {}),
    );

    const { rerender, container } = renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/role granted/i)).toBeInTheDocument();

    rerender(panelElement({ selectedMachine: POOL_MACHINE }));
    expect(await screen.findByText("Pool")).toBeInTheDocument();
    const entity = container.querySelector(".ps-activity-entity");
    expect(/role granted/i.test(entity.textContent)).toBe(false);
  });
});
