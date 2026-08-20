// Direct render tests for AddressesModal's public prop API (split out of the
// old src/components.test.jsx).

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

import AddressesModal from "./AddressesModal.jsx";
import { setFetchHandler } from "../test/fetchMock.js";
import { installCommonApiMocks } from "../test/commonApiMocks.js";

function expectNoCrash() {
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
}

describe("AddressesModal", () => {
  beforeEach(() => {
    installCommonApiMocks();
  });

  it("renders for a company with onClose callback", async () => {
    render(
      <AddressesModal
        companyName="etherfi"
        onClose={() => {}}
      />,
    );
    await waitFor(() => {
      expect(document.body.textContent).toBeTruthy();
    });
    expectNoCrash();
  });

  it("compare mode: bare address matches on any chain, ethereum row wins the collapse (invariant 13)", async () => {
    const ADDR = "0x2222222222222222222222222222222222222222"; // deployed on ethereum + base
    const BASE_ONLY = "0x3333333333333333333333333333333333333333"; // base only
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+\/addresses$/.test(url.pathname),
      () => ({
        all_addresses: [
          { address: ADDR, chain: "ethereum", name: "Mainnet Vault", is_proxy: false, analyzed: true },
          { address: ADDR, chain: "base", name: "Base Vault", is_proxy: false, analyzed: true },
          { address: BASE_ONLY, chain: "base", name: "Base Only Vault", is_proxy: false, analyzed: true },
        ],
      }),
    );

    render(<AddressesModal companyName="etherfi" onClose={() => {}} />);

    // Wait for the payload to land (header switches off "Loading…").
    await waitFor(() => {
      expect(screen.queryByText(/Loading…/)).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    const textarea = screen.getByPlaceholderText(/Paste a list of 0x addresses/i);
    fireEvent.change(textarea, { target: { value: `${ADDR}\n${BASE_ONLY}` } });

    // Both pasted addresses are tracked: existence is chain-agnostic, so the
    // cross-chain pair AND the base-only address both count as matched.
    await waitFor(() => {
      expect(screen.getByText(/2 matched/)).toBeInTheDocument();
    });
    expect(screen.getByText(/0 missing/)).toBeInTheDocument();
    // A base-only address still matches even though it lives on no ethereum row.
    expect(screen.getByText("Base Only Vault")).toBeInTheDocument();
    // Deterministic collapse winner for the cross-chain pair: the ethereum row,
    // not the base row (which is last in payload order).
    expect(screen.getByText("Mainnet Vault")).toBeInTheDocument();
    expect(screen.queryByText("Base Vault")).not.toBeInTheDocument();
  });
});
