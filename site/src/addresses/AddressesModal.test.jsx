// Direct render tests for AddressesModal's public prop API (split out of the
// old src/components.test.jsx).

import React from "react";
import { describe, it, expect, beforeEach, vi } from "vitest";
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

  it("renders members, candidates with their reason, and pruned behind a count", async () => {
    const MEMBER = "0x1111111111111111111111111111111111111111";
    const CANDIDATE = "0x2222222222222222222222222222222222222222";
    const PRUNED = "0x3333333333333333333333333333333333333333";
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+\/addresses$/.test(url.pathname),
      () => ({
        all_addresses: [
          {
            address: MEMBER,
            chain: "ethereum",
            name: "Vault",
            is_proxy: false,
            analyzed: true,
            membership_state: "member",
            membership_witnesses: [{ rule: "w6_llama_seed", via_address: null }],
            membership_reason: null,
          },
          {
            address: CANDIDATE,
            chain: "ethereum",
            name: "MaybeVault",
            is_proxy: false,
            analyzed: false,
            membership_state: "candidate",
            membership_witnesses: [],
            membership_reason: { kind: "no_probe_attempt" },
          },
          {
            address: PRUNED,
            chain: "ethereum",
            name: "Phantom",
            is_proxy: false,
            analyzed: false,
            membership_state: "pruned",
            membership_witnesses: [],
            membership_reason: { kind: "code_absent", code_probe_block: 999 },
          },
        ],
      }),
    );

    render(<AddressesModal companyName="etherfi" onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.queryByText(/Loading…/)).not.toBeInTheDocument();
    });

    // Member in the main table.
    expect(screen.getByText("Vault")).toBeInTheDocument();
    // Candidate section with its token-templated reason.
    expect(screen.getByText(/Candidates — awaiting verification \(1\)/)).toBeInTheDocument();
    expect(screen.getByText("MaybeVault")).toBeInTheDocument();
    expect(screen.getByText("no probe attempt yet")).toBeInTheDocument();
    // Pruned collapsed behind a count; expands on click with the block fact.
    expect(screen.queryByText("Phantom")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show 1 pruned" }));
    expect(screen.getByText("Phantom")).toBeInTheDocument();
    expect(screen.getByText("no code at block 999")).toBeInTheDocument();
    expectNoCrash();
  });

  it("shows a probed candidate's out-of-perimeter reads", async () => {
    const CANDIDATE = "0x4444444444444444444444444444444444444444";
    const OWNER = "0x5555555555555555555555555555555555555555";
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+\/addresses$/.test(url.pathname),
      () => ({
        all_addresses: [
          {
            address: CANDIDATE,
            chain: "ethereum",
            name: "ParkedVault",
            is_proxy: false,
            analyzed: false,
            membership_state: "candidate",
            membership_witnesses: [],
            membership_reason: {
              kind: "probe_unresolved",
              probe_block: 1234,
              resolved_reads: { owner: OWNER },
              unresolved_reads: ["authority"],
            },
          },
        ],
      }),
    );

    render(<AddressesModal companyName="etherfi" onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.queryByText(/Loading…/)).not.toBeInTheDocument();
    });
    expect(
      screen.getByText("probed at block 1234 — owner 0x5555...5555 not in perimeter; authority resolved nowhere"),
    ).toBeInTheDocument();
    expectNoCrash();
  });

  it("compare mode: a pruned row is tracked but wears a pruned chip, not matched, and is never re-queued", async () => {
    const MEMBER = "0x1111111111111111111111111111111111111111";
    const PRUNED = "0x3333333333333333333333333333333333333333";
    const MISSING = "0x9999999999999999999999999999999999999999";
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+\/addresses$/.test(url.pathname),
      () => ({
        all_addresses: [
          {
            address: MEMBER,
            chain: "ethereum",
            name: "Vault",
            is_proxy: false,
            analyzed: true,
            membership_state: "member",
            membership_witnesses: [{ rule: "w6_llama_seed", via_address: null }],
            membership_reason: null,
          },
          {
            address: PRUNED,
            chain: "ethereum",
            name: "Phantom",
            is_proxy: false,
            analyzed: false,
            membership_state: "pruned",
            membership_witnesses: [],
            membership_reason: { kind: "code_absent", code_probe_block: 999 },
          },
        ],
      }),
    );
    const analyzed = [];
    setFetchHandler(
      (url, init) => url.pathname === "/api/analyze" && init?.method === "POST",
      (url, init) => {
        analyzed.push(JSON.parse(init.body).address);
        return { job_id: "j" };
      },
    );
    // The bulk-analyze control is admin-gated.
    window.localStorage.setItem("psat_admin_key", "test-key");

    render(<AddressesModal companyName="etherfi" onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.queryByText(/Loading…/)).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    const textarea = screen.getByPlaceholderText(/Paste a list of 0x addresses/i);
    fireEvent.change(textarea, { target: { value: `${MEMBER}\n${PRUNED}\n${MISSING}` } });

    // Member row wears matched; the pruned row wears the pruned chip carrying
    // its code-absent fact; only the genuinely missing address is missing.
    await waitFor(() => {
      expect(screen.getByText("1 missing")).toBeInTheDocument();
    });
    const prunedChip = screen.getByText("pruned");
    expect(prunedChip).toHaveAttribute("title", "no code at block 999");
    const chips = screen.getAllByText("matched").filter((el) => el.className.includes("ps-addresses-modal-chip"));
    expect(chips).toHaveLength(1);

    // "Analyze all N missing" queues only the missing address — a proven
    // code-absent row is never re-queued.
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    try {
      fireEvent.click(screen.getByRole("button", { name: /Analyze all 1 missing/ }));
      await waitFor(() => {
        expect(analyzed).toEqual([MISSING]);
      });
    } finally {
      confirmSpy.mockRestore();
    }
    expectNoCrash();
  });

  it("pruned-only inventory shows the pruned section without a stray no-match line", async () => {
    const PRUNED = "0x3333333333333333333333333333333333333333";
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+\/addresses$/.test(url.pathname),
      () => ({
        all_addresses: [
          {
            address: PRUNED,
            chain: "ethereum",
            name: "Phantom",
            is_proxy: false,
            analyzed: false,
            membership_state: "pruned",
            membership_witnesses: [],
            membership_reason: { kind: "code_absent", code_probe_block: 42 },
          },
        ],
      }),
    );

    render(<AddressesModal companyName="etherfi" onClose={() => {}} />);
    await waitFor(() => {
      expect(screen.queryByText(/Loading…/)).not.toBeInTheDocument();
    });
    expect(screen.queryByText(/No addresses match/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show 1 pruned" })).toBeInTheDocument();
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
