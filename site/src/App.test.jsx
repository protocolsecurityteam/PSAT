// Top-level App router smoke tests. Each case sets a target URL,
// renders <App />, and asserts a stable landmark for that route renders
// without throwing. The goal is regression coverage — if any internal
// page (PipelineDashboard, ProtocolSurface, CompanyOverview)
// breaks, one of these will fail.
//
// Each test also asserts the ErrorBoundary fallback ("Something went
// wrong") is NOT showing, so a thrown render error is caught even when
// the surrounding shell still mounts.
//
// Assertions intentionally hit class-name selectors / role-based queries
// rather than full snapshots, to avoid breaking on incidental DOM shape
// changes during legitimate refactors.

import React from "react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

import App from "./App.jsx";
import { setFetchHandler } from "./test/fetchMock.js";
import {
  ANALYSIS_LIST,
  ETHERFI_COMPANY,
  COVERAGE_FIXTURE,
} from "./test/fixtures.js";

function navigateTo(path) {
  window.history.replaceState({}, "", path);
}

function expectNoCrash() {
  // The App-level ErrorBoundary renders this header when a child throws.
  // Asserting absence catches silent crashes that the surrounding nav
  // doesn't expose.
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
}

function installDefaultApiMocks() {
  setFetchHandler(/^\/api\/analyses$/, () => ANALYSIS_LIST);
  setFetchHandler(/^\/api\/jobs/, () => []);
  setFetchHandler(/^\/api\/stats/, () => ({}));
  setFetchHandler(/^\/api\/audits\/pipeline$/, () => ({ groups: [], recent_completed: [] }));
  setFetchHandler(
    (url) => url.pathname === "/api/company/etherfi/audit_coverage",
    () => COVERAGE_FIXTURE,
  );
  setFetchHandler(
    (url) => url.pathname === "/api/company/etherfi",
    () => ETHERFI_COMPANY,
  );
  setFetchHandler(/^\/api\/monitored-contracts/, () => ({ items: [] }));
  setFetchHandler(/^\/api\/address_labels$/, () => ({ labels: {} }));
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+\/audits$/.test(url.pathname),
    () => ({ audit_count: 0, audits: [] }),
  );
  setFetchHandler(
    (url) => /^\/api\/protocols\//.test(url.pathname),
    (url) => {
      // /monitoring, /subscriptions, /events return arrays in real API.
      if (/\/(monitoring|subscriptions|events)/.test(url.pathname)) return [];
      return {};
    },
  );
}

describe("App router smoke tests", () => {
  beforeEach(() => {
    installDefaultApiMocks();
  });

  it("renders the home / runs page at /", async () => {
    navigateTo("/");
    render(<App />);
    expect(await screen.findByText(/Detect every/i)).toBeInTheDocument();
    expect(document.querySelector(".ph-title")).toBeInTheDocument();
    expectNoCrash();
  });

  it("renders the job monitor at /monitor", async () => {
    // /monitor is operator-only; without an admin key the route redirects home.
    window.localStorage.setItem("psat_admin_key", "test-key");
    navigateTo("/monitor");
    render(<App />);
    // The monitor page renders the Active/History zones + the fleet strip
    // immediately (empty state when there's no data) — the zone eyebrow
    // proves the route resolved + the component mounted.
    await waitFor(() => {
      expect(screen.getByText(/Active · queued \+ processing/i)).toBeInTheDocument();
    });
    expectNoCrash();
  });

  it("renders the account page at /account", async () => {
    navigateTo("/account");
    render(<App />);
    expect(await screen.findByText("Sign in to manage alerts")).toBeInTheDocument();
    expect(screen.queryByText(/Detect every/i)).toBeNull();
    expectNoCrash();
  });

  it("opens the sign-in dialog when a request needs an account", async () => {
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: ["github"], dev_login: false }));
    // Any route works; /account renders fastest.
    navigateTo("/account");
    render(<App />);
    await screen.findByText("Sign in to manage alerts");
    act(() => {
      window.dispatchEvent(new Event("psat:auth-required"));
    });
    expect(await screen.findByRole("button", { name: "Continue with GitHub" })).toBeInTheDocument();
  });

  it("?admin=1 asks for the shared key only where the deployment accepts one", async () => {
    const prompt = vi.spyOn(window, "prompt").mockReturnValue(null);
    navigateTo("/?admin=1");
    render(<App />);
    await waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
  });

  it("?admin=1 on production opens sign-in instead of asking for a key", async () => {
    const prompt = vi.spyOn(window, "prompt").mockReturnValue("pasted-key");
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: ["github"], dev_login: false, admin_key: false }));
    // Any route works; /account renders fastest.
    navigateTo("/account?admin=1");
    render(<App />);
    expect(await screen.findByRole("button", { name: "Continue with GitHub" })).toBeInTheDocument();
    expect(prompt).not.toHaveBeenCalled();
  });

  it("?admin=1 on production opens sign-in even with an old key still stored", async () => {
    window.localStorage.setItem("psat_admin_key", "stale-key");
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: ["github"], dev_login: false, admin_key: false }));
    navigateTo("/account?admin=1");
    render(<App />);
    expect(await screen.findByRole("button", { name: "Continue with GitHub" })).toBeInTheDocument();
  });

  it("?admin=1 waits for a returning social sign-in instead of opening sign-in over it", async () => {
    let signedIn = false;
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: ["github"], dev_login: false, admin_key: false }));
    setFetchHandler("/api/me", () => (signedIn
      ? { email: "boss@example.com", is_admin: true }
      : new Response(JSON.stringify({ detail: "Sign in required" }), { status: 401, headers: { "Content-Type": "application/json" } })));
    setFetchHandler("/api/auth/session", async () => {
      await new Promise((r) => setTimeout(r, 200));
      signedIn = true;
      return { status: "signed_in" };
    });
    navigateTo("/account?admin=1&neon_auth_session_verifier=v1");
    render(<App />);
    await waitFor(() => expect(signedIn).toBe(true));
    await new Promise((r) => setTimeout(r, 300));
    expect(screen.queryByRole("button", { name: "Continue with GitHub" })).toBeNull();
  });

  it("a stored key shows no operator UI until the server confirms keys are accepted", async () => {
    window.localStorage.setItem("psat_admin_key", "stale-key");
    setFetchHandler("/api/auth/config", () => new Promise(() => {}));
    navigateTo("/monitor");
    render(<App />);
    await new Promise((r) => setTimeout(r, 300));
    expect(screen.queryByText(/Active · queued \+ processing/i)).toBeNull();
  });

  it("a stored key with an unreadable config settles as non-admin", async () => {
    window.localStorage.setItem("psat_admin_key", "preview-key");
    setFetchHandler("/api/auth/config", () => new Response("", { status: 503 }));
    navigateTo("/monitor");
    render(<App />);
    await waitFor(() => expect(window.location.pathname).toBe("/"));
    expect(window.localStorage.getItem("psat_admin_key")).toBe("preview-key");
  });

  it("a stale stored key on production neither unlocks /monitor nor survives", async () => {
    window.localStorage.setItem("psat_admin_key", "stale-key");
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: [], dev_login: false, admin_key: false }));
    navigateTo("/monitor");
    render(<App />);
    await waitFor(() => expect(window.location.pathname).toBe("/"));
    await waitFor(() => expect(window.localStorage.getItem("psat_admin_key")).toBeNull());
  });

  it("renders the company overview at /company/:name", async () => {
    navigateTo("/company/etherfi");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "etherfi" })).toBeInTheDocument();
    expectNoCrash();
  });

  it("renders the company surface tab at /company/:name/surface", async () => {
    navigateTo("/company/etherfi/surface");
    render(<App />);
    await waitFor(() => {
      expect(document.querySelector(".fullscreen-surface")).toBeInTheDocument();
    });
    expectNoCrash();
  });

  it("survives a ?chain= deep link on the surface route (query params round-trip through the router)", async () => {
    // etherfi is single-chain; an off-protocol ?chain=base must degrade to the
    // default chain (no chain bar, no blank canvas, no throw) rather than
    // scoping the page to a chain the protocol doesn't deploy on.
    navigateTo("/company/etherfi/surface?chain=base");
    render(<App />);
    await waitFor(() => {
      expect(document.querySelector(".fullscreen-surface")).toBeInTheDocument();
    });
    expect(document.querySelector(".ps-chain-bar")).toBeNull();
    expectNoCrash();
  });

  it("applies a valid ?chain= deep link, scoping the surface to that chain", async () => {
    const MULTICHAIN_COMPANY = {
      protocol_id: 9,
      contracts: [
        { address: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", name: "EthA", role: "governance", is_proxy: true, chain: "ethereum", functions: [] },
        { address: "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", name: "BaseB", role: "value_handler", is_proxy: true, chain: "base", functions: [] },
      ],
      principals: [],
      fund_flows: [],
    };
    setFetchHandler((url) => url.pathname === "/api/company/multichain", () => MULTICHAIN_COMPANY);
    setFetchHandler((url) => url.pathname === "/api/company/multichain/audit_coverage", () => ({ coverage: [] }));
    navigateTo("/company/multichain/surface?chain=base");
    render(<App />);
    // The filter panel starts collapsed; the pill itself wears the deep-linked
    // chain so the scope is visible without opening anything.
    const chain = await waitFor(() => {
      const el = document.querySelector(".ps-filter-chain");
      expect(el).toBeTruthy();
      return el;
    });
    expect(chain.textContent).toMatch(/Base/);
    // Expanding shows the switcher with the Base pill active.
    fireEvent.click(document.querySelector('.ps-filter-pill[aria-expanded="false"]'));
    const active = await waitFor(() => {
      const el = document.querySelector(".ps-chain-bar .ps-chain-chip-on");
      expect(el).toBeTruthy();
      return el;
    });
    expect(active.textContent).toMatch(/Base/);
    expectNoCrash();
  });

});
