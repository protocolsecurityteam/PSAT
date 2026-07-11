// M2 track: AgentPanel selection awareness. The chat must ask about whatever
// entity is selected — including a principal (safe/timelock/EOA), which has no
// `machine`. The header names the principal (type label + short address +
// threshold) and the POST body's selected_address is the principal's own
// address, NOT a contract it controls (the original leak sent the wrong
// contract to the LLM).

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AgentPanel } from "./AgentPanel.jsx";
import { setFetchHandler } from "../../test/fetchMock.js";

const SAFE = "0x2aca71020de61bb532008049e1bd41e451ae8adc";
const CONTRACT = "0x3088610f2c5c0f4f3f0c2e9a5d6b7c8d9e0f1a2b";

const SAFE_PRINCIPAL = {
  address: SAFE,
  type: "safe",
  label: "Multisig",
  details: { address: SAFE, owners: ["0xa", "0xb", "0xc", "0xd", "0xe", "0xf", "0x0"], threshold: 4 },
  controls: [CONTRACT],
};

const CONTRACT_MACHINE = { address: CONTRACT, name: "LiquidityPool", chain: "ethereum" };

// Capture the POST body sent to /api/agent/chat and end the SSE stream
// immediately so send() resolves.
function installAgentCapture() {
  const captured = { body: null };
  setFetchHandler(
    (url) => url.pathname === "/api/agent/chat",
    (_url, init) => {
      captured.body = JSON.parse(init.body);
      return new Response("", { headers: { "Content-Type": "text/event-stream" } });
    },
  );
  return captured;
}

describe("AgentPanel principal awareness", () => {
  beforeEach(() => {
    installAgentCapture();
  });

  it("headers with the company when nothing is selected (no meta)", () => {
    render(<AgentPanel companyName="etherfi" />);
    const value = document.querySelector(".agent-context-value");
    expect(value.textContent).toContain("etherfi");
    expect(document.querySelector(".agent-context-meta")).not.toBeInTheDocument();
  });

  it("headers with the safe (type + short address + threshold) for a principal", () => {
    render(<AgentPanel companyName="etherfi" selectedPrincipal={SAFE_PRINCIPAL} />);
    const value = document.querySelector(".agent-context-value");
    expect(value.textContent).toContain("Safe");
    // threshold (4) / owners (7)
    expect(value.textContent).toMatch(/4\/7/);
    const meta = document.querySelector(".agent-context-meta");
    expect(meta).toBeInTheDocument();
    expect(meta.textContent).toContain("0x2aca");
    // The controlled contract's name must never appear in the context.
    expect(value.textContent).not.toContain("LiquidityPool");
  });

  it("headers with the contract (unchanged) for a machine selection", () => {
    render(<AgentPanel companyName="etherfi" selectedMachine={CONTRACT_MACHINE} />);
    const value = document.querySelector(".agent-context-value");
    expect(value.textContent).toContain("LiquidityPool");
    expect(document.querySelector(".agent-context-meta")).toBeInTheDocument();
  });

  it("POSTs the principal's own address as selected_address", async () => {
    const captured = installAgentCapture();
    render(<AgentPanel companyName="etherfi" selectedPrincipal={SAFE_PRINCIPAL} />);
    const user = userEvent.setup();
    const box = screen.getByPlaceholderText(/ask about this protocol/i);
    await user.type(box, "who signs?");
    await user.keyboard("{Enter}");
    await waitFor(() => expect(captured.body).not.toBeNull());
    expect(captured.body.selected_address).toBe(SAFE);
  });

  it("POSTs the machine address for a contract selection", async () => {
    const captured = installAgentCapture();
    render(<AgentPanel companyName="etherfi" selectedMachine={CONTRACT_MACHINE} />);
    const user = userEvent.setup();
    const box = screen.getByPlaceholderText(/ask about this protocol/i);
    await user.type(box, "who owns?");
    await user.keyboard("{Enter}");
    await waitFor(() => expect(captured.body).not.toBeNull());
    expect(captured.body.selected_address).toBe(CONTRACT);
    expect(captured.body.selected_chain).toBe("ethereum");
  });
});
