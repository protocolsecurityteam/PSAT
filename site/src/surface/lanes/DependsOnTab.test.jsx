// Render + interaction tests for the Depends-on tab: external/internal split,
// collapse-by-default with expand-on-toggle, and the peek/commit affordances.
// Each case uses a unique job id so the module-level fetch cache in
// dependencies.js can't leak a graph between tests.

import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, waitFor, within } from "@testing-library/react";

import { DependsOnTab } from "./DependsOnTab.jsx";
import { setFetchHandler } from "../../test/fetchMock.js";

const TARGET = "0xdadef1ffbfeaab4f68a9fd181395f68b4e4e7ae0";
const TARGET_IMPL = "0x6bd191582f40012b2f2cdf66bd3d32bde41191f7";
const LP_PROXY = "0x308861a430be4cce5502d0a12724771fc6daf216";
const LP_IMPL = "0x83bc649fcdb2c8da146b2154a559ddedf937ef12";
const LIDO_IMPL = "0x6ca84080381e43938476814be61b779a8bb6a600";

function graphFor() {
  return {
    nodes: [
      { id: "t", address: TARGET_IMPL, label: "RedemptionManager", type: "implementation", is_target: true, source: [] },
      { id: "lp_p", address: LP_PROXY, label: "UUPSProxy", type: "proxy", source: ["dynamic"] },
      { id: "lp_i", address: LP_IMPL, label: "LiquidityPool", type: "implementation", source: ["classification"] },
      { id: "lido", address: LIDO_IMPL, label: "Lido", type: "implementation", source: ["dynamic"] },
    ],
    edges: [
      { from: "t", to: "lp_p", op: "CALL", function_name: "withdraw" },
      { from: "t", to: "lp_p", op: "STATICCALL", function_name: "sharesForAmount" },
      { from: "t", to: "lido", op: "STATICCALL", function_name: "balanceOf" },
      { from: "lp_p", to: "lp_i", op: "DELEGATES_TO" },
    ],
  };
}

function mountDeps({ jobId, graph = graphFor(), onPreview = vi.fn(), onNavigate = vi.fn() } = {}) {
  setFetchHandler(
    (url) => url.pathname.includes("/artifact/dependency_graph_viz"),
    () => graph,
  );
  const machines = [
    { address: TARGET, implementation: TARGET_IMPL, name: "EtherFiRedemptionManager", chain: "ethereum" },
    { address: LP_PROXY, implementation: LP_IMPL, name: "LiquidityPool", chain: "ethereum" },
  ];
  const machine = { address: TARGET, implementation: TARGET_IMPL, impl_job_id: jobId, name: "EtherFiRedemptionManager", chain: "ethereum" };
  const utils = render(
    <DependsOnTab machine={machine} machines={machines} onPreview={onPreview} onNavigate={onNavigate} />,
  );
  return { ...utils, onPreview, onNavigate };
}

describe("DependsOnTab", () => {
  it("splits external integrations from internal calls", async () => {
    const { findByText, getByText } = mountDeps({ jobId: "job-split" });
    // External: Lido, elevated with an Etherscan link
    await findByText("Lido");
    expect(getByText("External integrations (1)")).toBeTruthy();
    expect(getByText("Internal calls (1)")).toBeTruthy();
    const explorer = getByText("Etherscan ↗").closest("a");
    expect(explorer.getAttribute("href")).toContain(LIDO_IMPL);
  });

  it("collapses internal rows by default and expands on the count toggle", async () => {
    const { findByText, queryByText, getByText } = mountDeps({ jobId: "job-collapse" });
    await findByText("LiquidityPool");
    // Chips hidden while collapsed
    expect(queryByText("withdraw")).toBeNull();
    fireEvent.click(getByText(/write/).closest("button"));
    await waitFor(() => expect(queryByText("withdraw")).not.toBeNull());
    expect(queryByText("sharesForAmount")).not.toBeNull();
  });

  it("previews on name click and commits on the arrow", async () => {
    const { findByText, onPreview, onNavigate } = mountDeps({ jobId: "job-peek" });
    const name = await findByText("LiquidityPool");
    fireEvent.click(name);
    expect(onPreview).toHaveBeenCalledWith(LP_PROXY);
    // The GotoArrow commit → onNavigate with the canvas address
    const row = name.closest(".ps-depends-row");
    fireEvent.click(within(row).getByRole("button", { name: /Go to LiquidityPool/ }));
    expect(onNavigate).toHaveBeenCalledWith(expect.objectContaining({ address: LP_PROXY, type: "contract" }));
  });

  it("shows an empty state when there are no outbound calls", async () => {
    const { findByText } = mountDeps({ jobId: "job-empty", graph: { nodes: [{ id: "t", address: TARGET_IMPL, is_target: true }], edges: [] } });
    await findByText("No outbound calls detected");
  });

  it("surfaces an error (not a false empty) when every fetch fails", async () => {
    // All artifact fetches throw → the helper must reject so the error state
    // shows, rather than caching a null that reads as "no dependencies".
    setFetchHandler(
      (url) => url.pathname.includes("/artifact/dependency_graph_viz"),
      () => {
        throw new Error("network down");
      },
    );
    const machine = { address: TARGET, impl_job_id: "job-fail", name: "EtherFiRedemptionManager", chain: "ethereum" };
    const { findByText } = render(
      <DependsOnTab machine={machine} machines={[]} onPreview={() => {}} onNavigate={() => {}} />,
    );
    await findByText("Couldn't load dependency data");
  });
});
