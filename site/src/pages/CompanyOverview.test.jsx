// Regression: the "Covered" stat counts audit-covered contracts by reducing
// over the protocol's all-chains contract + coverage arrays. Those reductions
// used to key by bare address, so a CREATE2 twin (same address on two chains)
// deduped to a single entry and the count under-reported. Identity is
// (chain, address) (inv. 13): two chains at one address are two covered
// contracts, not one.

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

import CompanyOverview from "./CompanyOverview.jsx";
import { setFetchHandler } from "../test/fetchMock.js";
import SCORE_ETHERFI from "../test/fixtures/score_etherfi.json";

const ADDR = "0x1111111111111111111111111111111111111111";

const VERIFIED_AUDIT = {
  audit_id: 1,
  match_type: "reviewed_commit",
  match_confidence: "high",
  equivalence_status: "proven",
  proof_kind: "clean",
};

function twinContract(chain, name) {
  return {
    address: ADDR,
    chain,
    name,
    role: "value_handler",
    is_proxy: false,
    source_verified: true,
    functions: [],
  };
}

function installTwinMocks() {
  setFetchHandler(
    (url) => url.pathname === "/api/company/twinco",
    () => ({
      protocol_id: 42,
      contracts: [twinContract("ethereum", "EthVault"), twinContract("base", "BaseVault")],
      principals: [],
      fund_flows: [],
      ownership_hierarchy: [],
    }),
  );
  setFetchHandler(
    (url) => url.pathname === "/api/company/twinco/audit_coverage",
    () => ({
      audit_count: 2,
      coverage: [
        { address: ADDR, chain: "ethereum", contract_name: "EthVault", audits: [VERIFIED_AUDIT] },
        { address: ADDR, chain: "base", contract_name: "BaseVault", audits: [VERIFIED_AUDIT] },
      ],
    }),
  );
  setFetchHandler(
    (url) => url.pathname === "/api/company/twinco/functions",
    () => ({ functions: {} }),
  );
}

function coveredStatValue() {
  const label = screen.getByText("Covered");
  const stat = label.closest(".company-hero-stat");
  return stat.querySelector(".company-hero-stat-value").textContent;
}

describe("CompanyOverview — recovery and navigation", () => {
  it("does not display a freshness label for prepared or live data", async () => {
    installTwinMocks();
    const preparedAt = "2026-09-08T22:00:00+00:00";
    setFetchHandler((url) => url.pathname === "/api/company/twinco", () => new Response(JSON.stringify({
      company: "twinco", contracts: [], principals: [], fund_flows: [], ownership_hierarchy: [],
    }), { headers: { "Content-Type": "application/json", "X-PSAT-Prepared-At": preparedAt } }));
    const { rerender } = render(<CompanyOverview companyName="twinco" />);
    await screen.findByRole("heading", { name: "twinco", exact: true });
    expect(screen.queryByText(/Data as of/)).not.toBeInTheDocument();
    setFetchHandler((url) => url.pathname === "/api/company/liveco", () => ({
      company: "liveco", contracts: [], principals: [], fund_flows: [], ownership_hierarchy: [],
    }));
    rerender(<CompanyOverview companyName="liveco" />);
    await screen.findByRole("heading", { name: "liveco", exact: true });
    expect(screen.queryByText(/Data as of/)).not.toBeInTheDocument();
  });

  it("offers recovery when functions are overloaded instead of leaving the surface loading forever", async () => {
    installTwinMocks();
    let attempts = 0;
    setFetchHandler((url) => url.pathname === "/api/company/twinco/functions", () => {
      attempts += 1;
      return attempts === 1
        ? new Response(JSON.stringify({ detail: "Company data is busy." }), {
            status: 503, headers: { "Content-Type": "application/json" },
          })
        : { functions: {} };
    });
    render(<CompanyOverview companyName="twinco" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Failed to load control surface functions");
    expect(screen.getByText("Covered")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry", exact: true }));
    await screen.findByText("Covered");
    await waitFor(() => expect(attempts).toBe(2));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("retries a gateway failure and clears the error on success", async () => {
    installTwinMocks();
    let attempts = 0;
    setFetchHandler((url) => url.pathname === "/api/company/twinco", () => {
      attempts += 1;
      if (attempts === 1) return new Response("<!DOCTYPE html>gateway failure", {
        status: 502, headers: { "Content-Type": "text/html" },
      });
      return { contracts: [], principals: [], fund_flows: [], ownership_hierarchy: [] };
    });
    render(<CompanyOverview companyName="twinco" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("temporarily unavailable");
    expect(screen.queryByText(/DOCTYPE/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry", exact: true }));
    await screen.findByText("Covered");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(attempts).toBe(2);
  });

  it("aborts obsolete requests and ignores late results after company navigation", async () => {
    installTwinMocks();
    let resolveOld;
    let oldSignal;
    setFetchHandler((url) => url.pathname === "/api/company/oldco", (_url, init) => {
      oldSignal = init.signal;
      return new Promise((resolve) => { resolveOld = resolve; });
    });
    const view = render(<CompanyOverview companyName="oldco" />);
    await waitFor(() => expect(oldSignal).toBeDefined());
    view.rerender(<CompanyOverview companyName="twinco" />);
    await screen.findByText("Covered");
    expect(oldSignal.aborted).toBe(true);
    await act(async () => resolveOld(new Response("Old request failed", { status: 503 })));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(coveredStatValue()).toBe("2");
  });

  it("clears a previous company's failure on navigation", async () => {
    installTwinMocks();
    setFetchHandler((url) => url.pathname === "/api/company/badco", () => new Response("unavailable", { status: 503 }));
    const view = render(<CompanyOverview companyName="badco" />);
    await screen.findByRole("alert");
    view.rerender(<CompanyOverview companyName="twinco" />);
    await screen.findByText("Covered");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("CompanyOverview — cross-chain same-address twins", () => {
  beforeEach(() => {
    installTwinMocks();
  });

  it("counts both chains of an audit-covered twin in the Covered stat", async () => {
    render(<CompanyOverview companyName="twinco" onNavigateToSurface={() => {}} />);
    // Wait for the score band (which carries the Covered stat) to render.
    await screen.findByText("Covered");
    // Both the ethereum and base entities are covered — bare-address keying
    // collapsed them to one.
    expect(coveredStatValue()).toBe("2");
    // And the Contracts stat is likewise per-entity, not deduped by address.
    const contractsLabel = screen.getByText("Contracts");
    expect(contractsLabel.closest(".company-hero-stat").querySelector(".company-hero-stat-value").textContent).toBe("2");
  });
});

describe("CompanyOverview — score band wiring", () => {
  it("fetches the score alongside the company payload and renders the grade", async () => {
    installTwinMocks();
    setFetchHandler(
      (url) => url.pathname === "/api/company/twinco/score",
      () => SCORE_ETHERFI,
    );
    render(<CompanyOverview companyName="twinco" onNavigateToSurface={() => {}} />);
    expect(await screen.findByText("B+")).toBeInTheDocument();
    expect(screen.getByText("78.6")).toBeInTheDocument();
  });

  it("keeps the page usable when no score has been computed", async () => {
    installTwinMocks();
    setFetchHandler(
      (url) => url.pathname === "/api/company/twinco/score",
      () =>
        new Response(JSON.stringify({ detail: "No score has been computed for this protocol yet" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        }),
    );
    render(<CompanyOverview companyName="twinco" onNavigateToSurface={() => {}} />);
    expect(await screen.findByText(/No score has been computed/)).toBeInTheDocument();
    // The hero and the surface band are unaffected by an absent score.
    expect(screen.getByText("Covered")).toBeInTheDocument();
  });
});

describe("CompanyOverview — hero subtitle before coverage loads", () => {
  it('renders "—" for reports on file while the coverage fetch is unanswered, never 0', async () => {
    // Company payload answers; coverage never resolves within the test —
    // an unanswered count must not be asserted as "0 reports on file".
    setFetchHandler(
      (url) => url.pathname === "/api/company/slowco",
      () => ({
        protocol_id: 43,
        contracts: [],
        principals: [],
        fund_flows: [],
        ownership_hierarchy: [],
      }),
    );
    setFetchHandler(
      (url) => url.pathname === "/api/company/slowco/audit_coverage",
      () => new Promise(() => {}),
    );
    setFetchHandler(
      (url) => url.pathname === "/api/company/slowco/functions",
      () => ({ functions: {} }),
    );
    render(<CompanyOverview companyName="slowco" onNavigateToSurface={() => {}} />);
    const subtitle = await screen.findByText(/reports on file/);
    expect(subtitle.textContent).toContain("— reports on file");
    expect(subtitle.textContent).not.toMatch(/\b0 reports on file/);
  });
});
