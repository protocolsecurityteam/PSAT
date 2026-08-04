// Render tests for the Activity tab (collapsed Monitor + Upgrades). Covers the
// proxy timeline with enrollment boundary + impl attribution, the non-proxy
// empty state, protocol-wide mode, and admin-vs-non-admin control visibility.

import React from "react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, within, act } from "@testing-library/react";

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

describe("ActivityPanel — a failed event poll does not erase proven events", () => {
  const evRows = [evRow("eupg", "upgraded", 300, { implementation: CUR })];

  it("says the events were not read instead of 'none recorded'", async () => {
    // First read fails: there is nothing proven to keep, but "none recorded" is a
    // claim about the contract and this read did not answer.
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/api\/monitored-events$/.test(url.pathname), () => {
      throw new TypeError("Failed to fetch");
    });
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/Events were not read/i)).toBeInTheDocument();
    expect(screen.queryByText("none recorded")).toBeNull();
    expect(screen.getByText("not determined")).toBeInTheDocument();
  });

  it("keeps the rows a previous tick proved present when the 30s refresh fails", async () => {
    // The rail polls every 30s. `catch { setEvents([]) }` replaced events already
    // PROVEN present with an empty list, so a transient 502 turned observed
    // activity into "none recorded" and the next tick turned it back. The
    // poll is what makes it a clobber rather than a first-read miss, so the test
    // drives the real interval.
    let calls = 0;
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/api\/monitored-events$/.test(url.pathname), () => {
      calls += 1;
      if (calls === 1) return evRows;
      throw new TypeError("Failed to fetch");
    });
    vi.useFakeTimers();
    try {
      renderPanel({ selectedMachine: PROXY_MACHINE });
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(screen.getByText("Implementation upgraded")).toBeInTheDocument();
      expect(screen.queryByText(/refresh did not complete/i)).toBeNull();

      // The next tick throws. The proven row survives, and the failure is said.
      await act(async () => { await vi.advanceTimersByTimeAsync(30_100); });
      expect(calls).toBeGreaterThan(1);
      expect(screen.getByText(/refresh did not complete/i)).toBeInTheDocument();
      expect(screen.getByText("Implementation upgraded")).toBeInTheDocument();
      expect(screen.queryByText(/Events were not read/i)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("still reports 'none recorded' when the read answered with nothing", async () => {
    // POSITIVE CONTROL: hedging on every empty rail would erase the one case where
    // "this contract has no captured events" is the answer.
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [] });
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText("none recorded")).toBeInTheDocument();
    expect(screen.queryByText(/Events were not read/i)).toBeNull();
  });
});

// A contract whose two proxy signals contradict each other: `is_proxy: false` with
// a `proxy_type`. One real row is exactly this — contract
// 0x3c55986cfee455e2533f4d29006634ecf9b7c03f, `proxy_type: "beacon"`, with 14
// `Upgraded(address)` logs at or before block 25619159.
const BEACON_MACHINE = {
  address: PROXY,
  name: "BeaconProxy",
  is_proxy: false,
  proxy_type: "beacon",
  job_id: "job1",
  chain: "ethereum",
};

describe("ActivityPanel — a contract whose proxyhood contradicts itself", () => {
  it("asks about the history instead of asserting there is none", async () => {
    // `Boolean(is_proxy)` short-circuited to "absent" and never issued the read,
    // so 14 real pre-enrollment upgrades rendered as "No activity before the
    // line." The endpoint answers 503/not_determined for exactly this shape; the
    // panel has to get far enough to hear it.
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [] });
    setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), notDetermined);
    renderPanel({ selectedMachine: BEACON_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();
    expect(screen.queryByText("No activity before the line.")).toBeNull();
  });

  it("renders the history when the contradictory row turns out to have one", async () => {
    // The open state is not "treat it as a non-proxy" either: a history that DOES
    // arrive must render, not be dropped for failing a boolean.
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [], history: HISTORY });
    renderPanel({ selectedMachine: BEACON_MACHINE });
    expect(await screen.findByText("First deployment")).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
  });

  it("still reads a PROVEN non-proxy as absent", async () => {
    // NEGATIVE CONTROL: a row with no proxy signal at all is an answer, and
    // hedging it would put the marker on every Safe and EOA in the protocol.
    mockActivity({ contracts: [SAFE_CONTRACT], monitoredEvents: [] });
    renderPanel({ selectedMachine: SAFE_MACHINE });
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
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

  // The marker is not the only thing on the panel that speaks about the
  // pre-enrollment period. The timeline's own empty state sits directly under
  // it and used to render "No activity before the line." on every one of the
  // shapes above — an unread history yields history=null → proxy=null →
  // below=[], which is the same input as a proven-empty one. The marker said
  // unknown and the line under it said absent, in bold. These three pin the
  // three distinguishable answers apart at the level of the prose, not just
  // the marker.
  const ABSENCE_PROSE = "No activity before the line.";

  it("does not claim absence below the line when the history was never read", async () => {
    upgradeHistoryFails(status(500, "Internal Server Error"));
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();
    expect(screen.queryByText(ABSENCE_PROSE)).toBeNull();
  });

  it("keeps the absence prose for a 404 — the proven negative earns it", async () => {
    // NEGATIVE CONTROL for the test above: suppressing the prose whenever
    // `below` is empty would erase the one case where absence is the answer,
    // and the 500 test alone cannot see that.
    //
    // This arm once PINNED A DEFECT, because a 404 used to mean either
    // "the stage found no proxies" or "the stage raised" and the
    // SPA read both as proven absence. The ambiguity is now removed at its
    // source: routers/analyses only 404s when a Contract row says
    // self-consistently that the target is not a proxy AND the upgrade-history
    // sub-phase recorded no degraded failure; every other shape returns 503 /
    // not_determined, which the arms above cover. So the mapping this arm pins is
    // EARNED, and inverting it would make the SPA hedge the one answer the server
    // is now entitled to give. Verified in-process against the real corpus: the
    // beacon row 0x3c55986c… now answers 503 and a self-consistent non-proxy
    // still answers 404.
    upgradeHistoryFails(status(404, "Artifact not found"));
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(ABSENCE_PROSE)).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
  });

  it("does not claim absence in the no-boundary empty state either", async () => {
    // The other empty state in Timeline.jsx — reached when there is no
    // enrollment_block at all, so there is no line to be before. Same shape:
    // "No activity recorded yet." over a history nobody read.
    const legacy = { ...PROXY_CONTRACT, enrollment_block: null };
    mockActivity({ contracts: [legacy], monitoredEvents: [] });
    setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), status(500, "boom"));
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();
    expect(screen.queryByText("No activity recorded yet.")).toBeNull();
  });

  it("keeps the no-boundary empty state for a 404", async () => {
    // NEGATIVE CONTROL for the test above. Same note as the arm above: the
    // 404 is now earned at the endpoint rather than assumed here.
    const legacy = { ...PROXY_CONTRACT, enrollment_block: null };
    mockActivity({ contracts: [legacy], monitoredEvents: [] });
    setFetchHandler((url) => /\/artifact\/upgrade_history$/.test(url.pathname), status(404, "nope"));
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText("No activity recorded yet.")).toBeInTheDocument();
    expect(screen.queryByText(/unknown, not absent/i)).toBeNull();
  });

  it("treats a 200 whose body is not an object as unread, not empty", async () => {
    // The handler is supposed to 404 rather than serve a non-object, but the
    // client collapses any non-object body to the same `null` a failed read
    // produces — so from the timeline's side it is indistinguishable from an
    // unread history and must not be written as an absence.
    upgradeHistoryFails(() =>
      new Response(JSON.stringify("not an object"), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();
    expect(screen.queryByText(ABSENCE_PROSE)).toBeNull();
  });

  it("treats a 200 whose body is a JSON array as unread, not empty", async () => {
    // `typeof [] === "object"`, so an array would pass a bare object guard,
    // hydrate as a history with no `proxies`, and render the absence prose.
    // The wire permits it (the handler serves list bodies for other artifacts).
    upgradeHistoryFails(() =>
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/unknown, not absent/i)).toBeInTheDocument();
    expect(screen.queryByText(ABSENCE_PROSE)).toBeNull();
  });

  // A read that has not come back yet is the fourth state, and the one the
  // other five tests here cannot see: they all settle. Every proxy selection
  // passes through it, and `api()` (api/client.js) uses bare `fetch` with no
  // timeout and no AbortController, so a stalled connection holds it open
  // indefinitely. Until it settles the panel knows nothing — so it may claim
  // neither absence (the 404 answer) nor unreadability (the 500 hedge).
  it("claims nothing at all while the history read is still in flight", async () => {
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [] });
    setFetchHandler(
      (url) => /\/artifact\/upgrade_history$/.test(url.pathname),
      () => new Promise(() => {}),
    );
    const { container } = renderPanel({ selectedMachine: PROXY_MACHINE });
    // Wait for the boundary — past that point `below` is empty and one of the
    // three empty-state arms is on screen, so the assertions below are live.
    expect(await screen.findByText(/Monitoring started/i)).toBeInTheDocument();
    const entity = container.querySelector(".ps-activity-entity");
    expect(entity.textContent).not.toContain(ABSENCE_PROSE);
    expect(entity.textContent).not.toMatch(/unknown, not absent/i);
    expect(entity.textContent).not.toMatch(/was not read/i);
  });

  it("claims nothing in the no-boundary empty state while the read is in flight", async () => {
    // POSITIVE CONTROL's sibling for the other empty state: the 404 arm below
    // renders "No activity recorded yet." on this same input shape.
    const legacy = { ...PROXY_CONTRACT, enrollment_block: null };
    mockActivity({ contracts: [legacy], monitoredEvents: [] });
    setFetchHandler(
      (url) => /\/artifact\/upgrade_history$/.test(url.pathname),
      () => new Promise(() => {}),
    );
    const { container } = renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText("Timeline")).toBeInTheDocument();
    const entity = container.querySelector(".ps-activity-entity");
    expect(entity.textContent).not.toContain("No activity recorded yet.");
    expect(entity.textContent).not.toMatch(/unknown, not absent/i);
    // …and not the hedge either: hedging an unsettled read says the history
    // could not be obtained, which is a claim nobody has earned yet.
    expect(entity.textContent).not.toMatch(/was not read/i);
  });

  it("renders the backfilled upgrades and neither line when the history reads", async () => {
    // Confirms the prose is the absence-claim channel rather than chrome: a
    // real history replaces it with rows.
    mockActivity({ contracts: [PROXY_CONTRACT], monitoredEvents: [], history: HISTORY });
    renderPanel({ selectedMachine: PROXY_MACHINE });
    expect(await screen.findByText(/First deployment/i)).toBeInTheDocument();
    expect(screen.queryByText(ABSENCE_PROSE)).toBeNull();
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
    // Adopted from a reported repro, inverted to pin the fix. Not rendering the
    // previous proxy's rows is only half of it: this fixture's whole point is
    // that "nothing is known about Pool yet", and the panel used to fill that
    // silence with a bold positive claim about Pool — byte-identical to what a
    // resolved 404 renders, with no marker to tell them apart.
    expect(entity.textContent).not.toContain("No activity before the line.");
    expect(entity.textContent).not.toMatch(/unknown, not absent/i);
    expect(entity.textContent).not.toMatch(/was not read/i);
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

// ---------------------------------------------------------------------------
// Salience: the three-position control, the always-visible hidden count, and
// the routine-run collapse. Invariant 4 (routine hides, never deletes) and
// invariant 5 (unclassified is visible) are what these pin.
// ---------------------------------------------------------------------------

const SALIENT_EVENTS = [
  evRow("s1", "ownership_transferred", 401, { salience: "alert", salience_basis: ["canonical_config_family"] }),
  evRow("s2", "safe_tx_executed", 402, { salience: "not_determined", salience_basis: ["safe_exec_not_enriched"] }),
  evRow("s3", "state_changed_poll", 403, { salience: "routine", salience_basis: ["metric_field_diff"], field: "a" }),
  evRow("s4", "state_changed_poll", 404, { salience: "routine", salience_basis: ["metric_field_diff"], field: "b" }),
  evRow("s5", "state_changed_poll", 405, { salience: "routine", salience_basis: ["metric_field_diff"], field: "c" }),
];

describe("ActivityPanel — salience filter", () => {
  beforeEach(() => {
    mockActivity({ contracts: [SAFE_CONTRACT], monitoredEvents: SALIENT_EVENTS });
  });

  it("defaults to Notable+ and states how many rows that hides", async () => {
    renderPanel({ selectedMachine: SAFE_MACHINE });
    await screen.findByText("Ownership transferred");
    expect(screen.getByRole("button", { name: "Notable+" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "false");
    // The three proven-routine poll diffs.
    await waitFor(() => expect(screen.getByText("3 hidden")).toBeTruthy());
    expect(screen.queryByText(/changed \(polled\)/)).toBeNull();
  });

  it("keeps an unrated Safe execution visible under the default", async () => {
    renderPanel({ selectedMachine: SAFE_MACHINE });
    expect(await screen.findByText("Safe transaction executed")).toBeTruthy();
  });

  it("reveals the routine rows collapsed behind a count when All is chosen", async () => {
    renderPanel({ selectedMachine: SAFE_MACHINE });
    await screen.findByText("Ownership transferred");

    await act(async () => {
      screen.getByRole("button", { name: "All" }).click();
    });

    expect(screen.getByText("0 hidden")).toBeTruthy();
    // Collapsed, not dropped: the count is the row.
    const toggle = screen.getByRole("button", { name: "3 routine events — show" });
    expect(screen.queryByText(/changed \(polled\)/)).toBeNull();

    await act(async () => {
      toggle.click();
    });
    expect(screen.getAllByText(/changed \(polled\)/)).toHaveLength(3);
    expect(screen.getByRole("button", { name: "3 routine events — hide" })).toBeTruthy();
  });

  it("admits only the proven alert at Alerts only, and says so", async () => {
    renderPanel({ selectedMachine: SAFE_MACHINE });
    await screen.findByText("Ownership transferred");

    await act(async () => {
      screen.getByRole("button", { name: "Alerts only" }).click();
    });

    expect(screen.getByText("Ownership transferred")).toBeTruthy();
    expect(screen.queryByText("Safe transaction executed")).toBeNull();
    await waitFor(() => expect(screen.getByText("4 hidden")).toBeTruthy());
  });

  it("filters the protocol-wide feed with the same predicate and count", async () => {
    mockActivity({ contracts: [SAFE_CONTRACT], protocolEvents: SALIENT_EVENTS });
    renderPanel({ selectedMachine: null });
    await screen.findByText("Recent across protocol");
    await waitFor(() => expect(screen.getByText("3 hidden")).toBeTruthy());
  });
});
