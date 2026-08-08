// The Detail tab's protocol-at-a-glance empty state. Every figure must be a
// projection of published data, so these tests pin the derivations that have
// witnesses (score card off the real score fixture, tile counts off the
// filter's own counter, upgrade batching) and the not-determined renderings
// where a source is absent — an unfetchable plane must never read as zero.

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { DetailEmptyState, lastUpgradeBatch } from "./DetailEmptyState.jsx";
import { setFetchHandler } from "../../test/fetchMock.js";
import SCORE_ETHERFI from "../../test/fixtures/score_etherfi.json";

// Module-level fetch caches key on companyName / protocol_id, so each test
// uses a unique pair to stay hermetic.
let seq = 0;
function companyData(overrides = {}) {
  seq += 1;
  return {
    protocol_id: 9000 + seq,
    contract_count: 3,
    all_addresses_count: 7,
    tvl: { total_usd: null, defillama_tvl: 3245360134, source: "defillama", timestamp: "2026-08-01T09:52:13Z" },
    contracts: [],
    ...overrides,
  };
}

function renderPanel(props = {}) {
  seq += 1;
  const finalProps = { companyName: `co${seq}`, companyData: companyData(), ...props };
  return render(<DetailEmptyState {...finalProps} />);
}

const A = "0x" + "a1".repeat(20);
const B = "0x" + "b2".repeat(20);
const C = "0x" + "c3".repeat(20);

describe("lastUpgradeBatch", () => {
  it("collapses a batch sharing the newest timestamp into a count, naming no favourite", () => {
    const batch = lastUpgradeBatch([
      { name: "A", last_upgrade_timestamp: "2026-07-14T20:36:23+00:00" },
      { name: "B", last_upgrade_timestamp: "2026-07-14T20:36:23+00:00" },
      { name: "C", last_upgrade_timestamp: "2026-06-01T00:00:00+00:00" },
    ]);
    expect(batch.count).toBe(2);
    expect(batch.name).toBeNull();
  });

  it("names the contract when exactly one carries the newest timestamp", () => {
    const batch = lastUpgradeBatch([
      { name: "OnlyOne", last_upgrade_timestamp: "2026-07-14T20:36:23+00:00" },
      { name: "Older", last_upgrade_timestamp: "2026-06-01T00:00:00+00:00" },
    ]);
    expect(batch.count).toBe(1);
    expect(batch.name).toBe("OnlyOne");
  });

  it("is null when no upgrade was ever witnessed", () => {
    expect(lastUpgradeBatch([{ name: "A" }])).toBeNull();
    expect(lastUpgradeBatch([])).toBeNull();
  });
});

describe("DetailEmptyState — score card", () => {
  it("renders the calibrated grade, ledger and fix-first from the published document", async () => {
    setFetchHandler(/\/api\/company\/scored\/score$/, () => SCORE_ETHERFI);
    renderPanel({ companyName: "scored" });
    await waitFor(() => expect(screen.getByText("B")).toBeInTheDocument());
    expect(screen.getByText(/71\.7 \/ 100/)).toBeInTheDocument();
    expect(screen.getByText(/confidence 43\.2%/)).toBeInTheDocument();
    expect(screen.getByText(/71\.7 kept/)).toBeInTheDocument();
    expect(screen.getByText(/across 27 findings/)).toBeInTheDocument();
    // The fix-first sentence is the derivation the score page publishes.
    expect(screen.getByText(/Harden the two Safe authority holes/)).toBeInTheDocument();
    // Audit posture rides the same document — no separate fetch.
    expect(screen.getByText(/64 on file/)).toBeInTheDocument();
    // The #score hash asks the overview's band to open + scroll on arrival.
    const link = screen.getByText(/Full score breakdown/);
    expect(link.getAttribute("href")).toBe("/company/scored#score");
  });

  it("says no score is published when the endpoint has none — never zeros", async () => {
    // Default mock answers {} for unstubbed /api/* — a shapeless payload.
    renderPanel();
    await waitFor(() => expect(screen.getByText(/No score published/)).toBeInTheDocument());
    // The rest of the panel still stands.
    expect(screen.getByText(/Who holds privileged surface/i)).toBeInTheDocument();
  });

  it("keeps a transport failure apart from a witnessed absence — and never caches it", async () => {
    seq += 1;
    const name = `failing${seq}`;
    let calls = 0;
    setFetchHandler(new RegExp(`/api/company/${name}/score$`), () => {
      calls += 1;
      return new Response("{}", { status: 503, headers: { "Content-Type": "application/json" } });
    });
    const first = render(<DetailEmptyState companyName={name} companyData={companyData()} />);
    await waitFor(() => expect(screen.getByText(/Score not available right now/)).toBeInTheDocument());
    expect(screen.queryByText(/No score published/)).not.toBeInTheDocument();
    first.unmount();
    // A remount retries — the failure was not pinned in the module cache.
    render(<DetailEmptyState companyName={name} companyData={companyData()} />);
    await waitFor(() => expect(calls).toBe(2));
  });
});

describe("DetailEmptyState — posture tiles", () => {
  it("counts timelocks as the filter does: principals UNION timelock-typed contracts", async () => {
    renderPanel({
      machines: [
        { address: A, name: "EtherFiTimelock", isTimelock: true, totalFunctions: 2 },
        { address: B, name: "Vault", isTimelock: false, totalFunctions: 5 },
      ],
      principals: [
        { type: "timelock", address: C, controls: [] },
        { type: "eoa", address: "0x" + "d4".repeat(20), controls: [] },
        { type: "safe", address: "0x" + "e5".repeat(20), controls: [] },
      ],
    });
    const timelockTile = (await screen.findByText("TIMELOCK")).previousSibling;
    expect(timelockTile.textContent).toBe("2"); // 1 principal + 1 contract node
    expect(screen.getByText("EOA").previousSibling.textContent).toBe("1");
    expect(screen.getByText("SAFE").previousSibling.textContent).toBe("1");
  });

  it("dedups a timelock emitted as BOTH principal and contract node", async () => {
    renderPanel({
      machines: [{ address: A, name: "EtherFiTimelock", isTimelock: true, totalFunctions: 2 }],
      principals: [{ type: "timelock", address: A, controls: [] }],
    });
    const timelockTile = (await screen.findByText("TIMELOCK")).previousSibling;
    expect(timelockTile.textContent).toBe("1");
  });
});

describe("DetailEmptyState — freshness and value", () => {
  it("shows monitoring coverage from the endpoints, and not-determined without them", async () => {
    seq += 1;
    const data = companyData();
    setFetchHandler(new RegExp(`/api/protocols/${data.protocol_id}/monitoring$`), () => [
      { is_active: true },
      { is_active: true },
      { is_active: false },
    ]);
    setFetchHandler(new RegExp(`/api/protocols/${data.protocol_id}/events$`), () => [
      { detected_at: "2026-08-01T09:46:47Z" },
    ]);
    render(<DetailEmptyState companyName={`co${seq}`} companyData={data} />);
    await waitFor(() => expect(screen.getByText(/2 contracts/)).toBeInTheDocument());
    expect(screen.getByText(/last event Aug 1/)).toBeInTheDocument();
    // No witnessed upgrade in this payload → the earned-nothing wording.
    expect(screen.getByText(/none witnessed/)).toBeInTheDocument();
  });

  it("renders the monitoring row as not determined when the plane is unreadable", async () => {
    // Default {} responses are non-lists — a distinct state from proven-empty.
    // Both the monitoring row and (score being absent) the audits row wear it.
    renderPanel();
    await waitFor(() => expect(screen.getAllByText(/not determined/).length).toBeGreaterThan(0));
  });

  it("value rows select their contract on the canvas", async () => {
    const onSelectAddress = vi.fn();
    renderPanel({
      companyData: companyData({
        contracts: [
          { address: A, name: "WeETH", total_usd: 3498555472 },
          { address: B, name: "Restaker", total_usd: 540000000 },
        ],
      }),
      onSelectAddress,
    });
    const row = await screen.findByText("WeETH");
    await userEvent.setup().click(row);
    expect(onSelectAddress).toHaveBeenCalledWith(A);
    // Balances are custodial figures, labelled as such beside the TVL head.
    expect(screen.getByText(/Largest tracked balances/i)).toBeInTheDocument();
    expect(screen.getByText("$3.2B")).toBeInTheDocument();
  });
});
