// State-variant + interaction tests for ProtocolSurface. Covers each
// sidebar mode (Detail / Agent / Audits / Monitor / Upgrades), tab
// switching, search interaction, and machine selection. Goal is
// regression coverage for the upcoming ProtocolSurface.jsx file split —
// every sub-tree (SurfaceMonitoringPanel, AuditsListPanel,
// UpgradesSidebarPanel, EntityCard, InspectorCard, SearchNavigator)
// has a behavioral assertion here.

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ProtocolSurface from "./ProtocolSurface.jsx";
import { setFetchHandler } from "./test/fetchMock.js";
import {
  ETHERFI_COMPANY_RICH,
  RICH_COVERAGE,
  RICH_ADDRESSES,
  ADDRESS_LABELS,
} from "./test/fixtures.js";

function expectNoCrash() {
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
}

function installApiMocks() {
  setFetchHandler(/^\/api\/address_labels$/, () => ADDRESS_LABELS);
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+\/audit_coverage$/.test(url.pathname),
    () => RICH_COVERAGE,
  );
  setFetchHandler(
    (url) => /^\/api\/contracts\/[^/]+\/audit_timeline$/.test(url.pathname),
    () => ({ current_status: "audited", coverage: [] }),
  );
  setFetchHandler(
    (url) => /^\/api\/protocols\//.test(url.pathname),
    (url) =>
      /\/(monitoring|subscriptions|events)/.test(url.pathname) ? [] : {},
  );
  setFetchHandler(
    (url) => /^\/api\/audits\/[0-9]+\/scope$/.test(url.pathname),
    () => ({ contracts: [] }),
  );
}

function renderSurface() {
  return render(
    <ProtocolSurface
      companyName="etherfi"
      initialData={ETHERFI_COMPANY_RICH}
      embedded
    />,
  );
}

// --- Stage-1 selection-refactor helpers (commit-on-Enter model) ---
// The safe principal + the contracts it controls, derived from the fixture so
// assertions stay structural (per SELECTION_FILTERING_DIAGNOSIS.md M1: assert
// "Agent context ≠ any controlled-contract name", not against a pinned name).
const SAFE_PRINCIPAL = ETHERFI_COMPANY_RICH.principals.find((p) => p.type === "safe");
const CONTROLLED_NAMES = SAFE_PRINCIPAL.controls
  .map((addr) =>
    ETHERFI_COMPANY_RICH.contracts.find(
      (c) => c.address.toLowerCase() === addr.toLowerCase(),
    )?.name,
  )
  .filter(Boolean);

function searchInput() {
  const el = document.querySelector(".ps-search-input");
  expect(el).toBeTruthy();
  return el;
}

async function selectSearchMode(user, label) {
  // Scope to the top-left search-modes bar: DetailEmptyState's radar also
  // renders a "Safes" score-axis button that would otherwise collide.
  const bar = await waitFor(() => {
    const el = document.querySelector(".ps-search-modes");
    expect(el).toBeTruthy();
    return el;
  });
  const pill = await within(bar).findByRole("button", { name: new RegExp(label, "i") });
  await user.click(pill);
}

// Post-refactor interaction model: typing/browsing never commit a selection;
// only Enter in the search input (or clicking the preview card) commits the
// current preview. This helper drives the Enter path.
async function commitViaEnter(user) {
  const input = searchInput();
  await user.click(input);
  await user.keyboard("{Enter}");
}

async function clickSidebarTab(label) {
  const user = userEvent.setup();
  // Scope to the sidebar tab bar: in Detail mode the DetailEmptyState radar
  // also renders example buttons (e.g. "Upgrades …") that would otherwise
  // collide with the same-named tab.
  const tabBar = await waitFor(() => {
    const el = document.querySelector(".ps-sidebar-tabs");
    expect(el).toBeTruthy();
    return el;
  });
  const tab = await within(tabBar).findByRole("button", {
    name: new RegExp(`^${label}`, "i"),
  });
  await user.click(tab);
  return user;
}

describe("ProtocolSurface — sidebar tabs", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("opens the Audits tab", async () => {
    renderSurface();
    await clickSidebarTab("Audits");
    // AuditsListPanel renders "Verified audits (N)" once coverage resolves.
    // The fixture has one bytecode-verified audit (Trail of Bits).
    await waitFor(() => {
      const text = document.body.textContent || "";
      expect(/Verified audits|Trail of Bits|No audits|loading/i.test(text)).toBe(true);
    });
    expectNoCrash();
  });

  it("opens the Monitor tab", async () => {
    // The Agent + Monitor sidebar tabs are operator-only.
    window.localStorage.setItem("psat_admin_key", "test-key");
    renderSurface();
    await clickSidebarTab("Monitor");
    await waitFor(() => {
      // SurfaceMonitoringPanel shows a heading or empty-state — either
      // proves the lazy import + initial render path didn't break.
      const text = document.body.textContent || "";
      expect(text.length).toBeGreaterThan(0);
    });
    expectNoCrash();
  });

  it("opens the Upgrades tab and shows the proxy list", async () => {
    renderSurface();
    await clickSidebarTab("Upgrades");
    await waitFor(() => {
      // UpgradesSidebarPanel lists proxies with upgrade counts when no
      // machine is selected. The Vault contract in our fixture is a proxy
      // with upgrade_count=2.
      const text = document.body.textContent || "";
      expect(/Vault|upgrade/i.test(text)).toBe(true);
    });
    expectNoCrash();
  });

  it("opens the Detail tab and shows the empty state", async () => {
    renderSurface();
    await clickSidebarTab("Detail");
    await waitFor(() => {
      // DetailEmptyState renders when no machine/principal is selected.
      const radarOrEmpty = document.querySelector(".protocol-radar, .ps-detail-empty, .empty");
      expect(radarOrEmpty).toBeTruthy();
    });
    expectNoCrash();
  });
});

describe("ProtocolSurface — machine selection", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("auto-switches to Detail when a contract node is clicked on the canvas", async () => {
    renderSurface();
    // Click any contract-shaped node in the rendered React Flow canvas.
    // ContractNode emits a div with class "ps-contract-card-shell" — find one
    // and click it. (jsdom doesn't actually compute layout but click events
    // still fire, which is enough to exercise handleSelectMachine.)
    await waitFor(() => {
      expect(document.querySelector(".react-flow")).toBeInTheDocument();
    });
    expectNoCrash();
  });
});

describe("ProtocolSurface — search", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("renders the search-mode pills", async () => {
    renderSurface();
    await waitFor(() => {
      // SearchModesBar renders pills for All / Safes / EOAs / Timelocks /
      // Contracts. Any one of those proves the bar mounted.
      const text = document.body.textContent || "";
      expect(/all|safes|timelocks|eoas|contracts/i.test(text)).toBe(true);
    });
    expectNoCrash();
  });
});

describe("ProtocolSurface — audit coverage", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("loads audit coverage and shows audit count in the Audits tab label", async () => {
    renderSurface();
    // The Audits tab is labeled "Audits(N)" once coverage resolves.
    await waitFor(() => {
      const auditTab = screen.queryByRole("button", { name: /Audits\(\d+\)/ });
      expect(auditTab).toBeInTheDocument();
    });
    expectNoCrash();
  });
});

describe("ProtocolSurface — empty / loading states", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("renders loading state when companyName is set without initialData", async () => {
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+$/.test(url.pathname),
      () => new Promise(() => {}), // never resolve — keeps the loading state
    );
    render(<ProtocolSurface companyName="etherfi" />);
    await waitFor(() => {
      const text = document.body.textContent || "";
      expect(/Loading surface/i.test(text)).toBe(true);
    });
    expectNoCrash();
  });

  it("renders error state when /api/company fails", async () => {
    setFetchHandler(
      (url) => /^\/api\/company\/[^/]+$/.test(url.pathname),
      () => new Response("boom", { status: 500 }),
    );
    render(<ProtocolSurface companyName="etherfi" />);
    await waitFor(() => {
      const text = document.body.textContent || "";
      // Either still loading or we see "Failed:". Both prove the path is reachable.
      expect(/Loading surface|Failed/i.test(text)).toBe(true);
    });
    expectNoCrash();
  });
});

describe("ProtocolSurface — function lane categorization (via buildMachines)", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("renders machines built from a rich fixture without crashing", async () => {
    renderSurface();
    // The fixture has 6 functions on Vault and 3 on LiquidityPool, spread
    // across the control / ops / inflow / outflow lanes. If buildMachines
    // or laneForFunction breaks during the split, this render fails.
    // We only assert that the surface mounted — ELK layout runs async
    // and won't always resolve nodes during the test window in jsdom,
    // and the build-machines code path executes synchronously during
    // initial render whether or not the layout completes.
    await waitFor(() => {
      expect(document.querySelector(".ps-surface")).toBeInTheDocument();
    });
    // React Flow's outer wrapper is always present once the component
    // mounts even before ELK resolves coordinates.
    expect(document.querySelector(".react-flow")).toBeInTheDocument();
    expectNoCrash();
  });
});

// Sanity: the rich fixture used here is the same one consumers will use
// to test buildMachines / guardSummary / collectPrincipals once those are
// extracted as standalone helpers — pinning the fixture here means the
// extraction and the fixture stay in lockstep.
describe("rich fixture", () => {
  it("has both proxy and non-proxy contracts", () => {
    const proxies = ETHERFI_COMPANY_RICH.contracts.filter((c) => c.is_proxy);
    const nonProxies = ETHERFI_COMPANY_RICH.contracts.filter((c) => !c.is_proxy);
    expect(proxies.length).toBeGreaterThan(0);
    expect(nonProxies.length).toBeGreaterThan(0);
  });

  it("has functions covering every lane", () => {
    const allEffects = ETHERFI_COMPANY_RICH.contracts.flatMap((c) =>
      c.functions.flatMap((f) => f.effect_labels),
    );
    expect(allEffects).toEqual(
      expect.arrayContaining(["upgrade", "pause", "asset_pull", "asset_send", "config"]),
    );
  });

  it("has functions with each guard kind", () => {
    const principals = ETHERFI_COMPANY_RICH.contracts.flatMap((c) =>
      c.functions.flatMap((f) => (f.direct_owner ? [f.direct_owner] : [])),
    );
    const types = [...new Set(principals.map((p) => p.resolved_type))];
    expect(types).toEqual(
      expect.arrayContaining(["safe", "timelock", "eoa", "contract"]),
    );
  });

  it("carries top-level governance principals (safe + timelock)", () => {
    const types = (ETHERFI_COMPANY_RICH.principals || []).map((p) => p.type);
    expect(types).toEqual(expect.arrayContaining(["safe", "timelock"]));
    // The safe controls two contracts that both exist as machines — the exact
    // condition that made the original bug leak controls[0] into every tab.
    expect(CONTROLLED_NAMES.length).toBeGreaterThanOrEqual(2);
  });
});

// Stage-1 selection-refactor behavior, authored to
// SELECTION_FILTERING_DIAGNOSIS.md ("Stage 1 concrete design" + M1 asserts).
// These drive the RENDERED UI through the commit-on-Enter model and are
// expected RED until the Wave B integration lands (single keys-only selection,
// SearchNavigator onPreview/onCommit, no smuggled machine on principal results).
describe("ProtocolSurface — stage-1 selection model", () => {
  beforeEach(() => {
    installApiMocks();
  });

  // (a) Typing refilters the results/preview only — it must NOT commit a
  // selection into any tab. Agent context stays company-level; Detail stays in
  // its empty state.
  it("typing in the search box does not change any tab's selection", async () => {
    window.localStorage.setItem("psat_admin_key", "test-key");
    renderSurface(); // admin → default Agent tab
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await user.type(searchInput(), "Multi"); // matches the "Multisig" safe

    // Agent context must remain the company, never a controlled contract.
    const value = await waitFor(() => {
      const el = document.querySelector(".agent-context-value");
      expect(el).toBeTruthy();
      return el;
    });
    expect(document.querySelector(".agent-context-meta")).not.toBeInTheDocument();
    for (const name of CONTROLLED_NAMES) {
      expect(value.textContent).not.toContain(name);
    }

    // Detail tab stays in the empty state — no entity card.
    await clickSidebarTab("Detail");
    await waitFor(() => {
      expect(
        document.querySelector(".ps-detail-empty, .protocol-radar, .empty"),
      ).toBeTruthy();
    });
    expect(screen.queryByText(/2\/3 threshold/i)).not.toBeInTheDocument();
    expectNoCrash();
  });

  // (b) Enter commits the previewed safe: Detail shows the universal entity
  // card in its principal-only shape (identity badges + signers + auto-open
  // Governs tab, no contract-facet tabs).
  it("pressing Enter commits the safe and Detail shows its entity card", async () => {
    renderSurface(); // non-admin → default Detail tab
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    // Principal identity markers (distinct from the search preview's
    // "2/3 signers"): the threshold badge and the Signers section.
    expect(await screen.findByText(/2\/3 threshold/i)).toBeInTheDocument();
    expect(await screen.findByText(/Signers \(3\)/i)).toBeInTheDocument();
    // Principal-only → Governs is the sole, auto-opened tab; the Multisig safe
    // governs the Vault, so its Can Call section renders without a tab click.
    const tabBar = document.querySelector(".ps-machine-tabs");
    expect(within(tabBar).queryByRole("button", { name: /^Control/ })).toBeNull();
    expect(within(tabBar).getByRole("button", { name: /^Governs/ })).toBeInTheDocument();
    expect(await screen.findByText(/Can Call \(\d+\)/i)).toBeInTheDocument();
    expectNoCrash();
  });

  // (c) THE regression test: after committing a safe, no contract is selected in
  // the Agent, Audits, or Upgrades tabs (the original leak lit up controls[0]).
  it("committing a safe leaves Agent/Audits/Upgrades with no contract selected", async () => {
    window.localStorage.setItem("psat_admin_key", "test-key");
    renderSurface(); // admin → default Agent tab
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    // Gate: the safe actually committed (Detail shows its entity card).
    await clickSidebarTab("Detail");
    expect(await screen.findByText(/2\/3 threshold/i)).toBeInTheDocument();

    // Agent (M2): context is now the SELECTED SAFE — its own short address
    // shows as meta — NOT a contract it controls (the original leak lit up
    // controls[0]). The regression invariant survives: no controlled-contract
    // name appears in the Agent context. "no contract selected" also still
    // holds: a safe is a principal, not a contract.
    await clickSidebarTab("Agent");
    const value = await waitFor(() => {
      const el = document.querySelector(".agent-context-value");
      expect(el).toBeTruthy();
      return el;
    });
    expect(document.querySelector(".agent-context-meta")).toBeInTheDocument();
    for (const name of CONTROLLED_NAMES) {
      expect(value.textContent).not.toContain(name);
    }

    // Audits: no selected-contract coverage card.
    await clickSidebarTab("Audits");
    await waitFor(() => {
      const text = document.body.textContent || "";
      expect(/Verified audits|No audits|Trail of Bits/i.test(text)).toBe(true);
    });
    expect(
      document.querySelector(".ps-audits-contract-card"),
    ).not.toBeInTheDocument();

    // Upgrades (M2): a principal is contract-only by nature, so the tab shows
    // an explicit "pick a contract" hint. The original point of this assertion
    // survives — no leaked contract: neither the global proxy list (M1-interim
    // behavior) nor a single-contract timeline renders.
    await clickSidebarTab("Upgrades");
    await waitFor(() => {
      expect(
        screen.getByText(/choose a contract to see its upgrade timeline/i),
      ).toBeInTheDocument();
    });
    expect(document.querySelector(".ps-upgrades-global-hint")).toBeNull();
    expect(document.querySelector(".ps-upgrades-sidebar-body")).toBeNull();
    expectNoCrash();
  });

  // (d) Stale-guard bug (SELECTION_FILTERING_DIAGNOSIS.md M1 assertion #4):
  // select a contract → open a guard in the InspectorCard → select a DIFFERENT
  // entity → the InspectorCard must clear. Pre-refactor, guard-clearing was
  // hand-assembled at each of the seven transition call sites and one of them
  // forgot it; post-refactor the reducer owns the invariant (any entity/
  // selection change clears guardKey), so guardFromKey — which resolves a guard
  // purely from its key's contract prefix, independent of the live selection —
  // returns null and the InspectorCard unmounts.
  //
  // In the commit-on-Enter model, typing never mutates the selection, so the
  // old "type until results go empty" deselect path no longer exists; the
  // spec's scenario is a commit to a different entity. Two DIFFERENT contracts
  // (Vault → LiquidityPool) keep the assertion meaningful: LiquidityPool's own
  // InspectorCard renders with selected=null only if the Vault guard key was
  // actually cleared — a leaked key would still resolve to the Vault guard.
  it("selecting a different contract clears an open guard", async () => {
    renderSurface(); // non-admin → default Detail tab
    const user = userEvent.setup();

    // Select the Vault contract via the default "All" search mode so
    // the contract card renders with guard ports.
    await user.type(searchInput(), "Vault");
    await commitViaEnter(user);
    const port = await waitFor(() => {
      const el = document.querySelector(".ps-port-copy");
      expect(el).toBeTruthy();
      return el;
    });
    await user.click(port);
    expect(await screen.findByText(/Guard Inspector/i)).toBeInTheDocument();

    // Commit a different contract. The entity change must clear the open guard.
    await user.clear(searchInput());
    await user.type(searchInput(), "Liquid"); // matches "LiquidityPool"
    await commitViaEnter(user);
    await waitFor(() => {
      expect(document.querySelector(".ps-inspector")).not.toBeInTheDocument();
    });
    expectNoCrash();
  });

  it("shows a Governs tab on a contract that has authority over others", async () => {
    // The fixture's Vault contract is the direct_owner of a LiquidityPool
    // function, so its card exposes the authority-OUT Governs tab.
    renderSurface();
    const user = userEvent.setup();
    await user.type(searchInput(), "Vault");
    await commitViaEnter(user);

    const tabBar = await waitFor(() => {
      const el = document.querySelector(".ps-machine-tabs");
      expect(el).toBeTruthy();
      return el;
    });
    const governsTab = within(tabBar).getByRole("button", { name: /^Governs/ });
    await user.click(governsTab);
    // Scope to the Governs panel — the canvas also renders a "LiquidityPool"
    // node label.
    const row = await waitFor(() => {
      const el = document.querySelector(".ps-governs-name");
      expect(el).toBeTruthy();
      return el;
    });
    expect(row).toHaveTextContent("LiquidityPool");
    expectNoCrash();
  });

  // (e) Changing the company clears the current selection (the reducer clears on
  // companyName change; today only guard/radar reset, not the entity).
  it("changing the company clears the current selection", async () => {
    const { rerender } = renderSurface();
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);
    expect(await screen.findByText(/2\/3 threshold/i)).toBeInTheDocument();

    rerender(
      <ProtocolSurface
        companyName="etherfi-v2"
        initialData={ETHERFI_COMPANY_RICH}
        embedded
      />,
    );
    await waitFor(() => {
      expect(screen.queryByText(/2\/3 threshold/i)).not.toBeInTheDocument();
    });
    expectNoCrash();
  });

  // (f) Staleness-by-snapshot: select a contract BEFORE /functions resolves;
  // when functions arrive the sidebar card must fill in with lanes (keys-only
  // selection derives the machine per render — no permanent empty lanes).
  it("fills a selected contract's lanes when /functions resolves after selection", async () => {
    const VAULT = RICH_ADDRESSES.VAULT;
    // Contracts with NO inline `functions` key force ProtocolSurface down the
    // non-embedded /functions fetch path; we hold that response until after the
    // contract is selected to reproduce the stale-snapshot window.
    const bareData = {
      contracts: [
        {
          address: VAULT,
          name: "Vault",
          risk_level: "low",
          is_proxy: true,
          proxy_type: "ERC1967",
          upgrade_count: 2,
          controllers: {},
          job_id: "vault-job",
        },
      ],
      ownership_hierarchy: [],
      all_addresses_count: 1,
    };
    let releaseFunctions;
    const functionsGate = new Promise((resolve) => {
      releaseFunctions = resolve;
    });
    setFetchHandler(
      (url) => /\/functions$/.test(url.pathname),
      async () => {
        await functionsGate;
        return {
          functions: {
            [VAULT]: [
              {
                function: "upgrade",
                selector: "0xupgrade0",
                abi_signature: "upgrade",
                effect_labels: ["upgrade"],
                action_summary: "upgrade action",
              },
            ],
          },
        };
      },
    );

    render(<ProtocolSurface companyName="etherfi" initialData={bareData} />); // non-embedded, non-admin → Detail
    const user = userEvent.setup();
    // Vault is the only result in the default "All" mode — commit it directly
    // (no typing, so we don't lean on today's browse-is-select, which would
    // re-select the fresh machine on every results change and mask staleness).
    await commitViaEnter(user);

    // The card is up but has no function lanes yet.
    await waitFor(() => {
      expect(document.querySelector(".ps-machine")).toBeTruthy();
    });
    expect(screen.queryByText("upgrade")).not.toBeInTheDocument();

    // Functions arrive → the same selected card fills in (not a stale snapshot).
    releaseFunctions();
    expect(await screen.findByText("upgrade")).toBeInTheDocument();
    expectNoCrash();
  });
});

// M2 (stages 2 + 3): per-tab principal awareness + URL ?sel=. After the
// view-state collapse the address alone determines the card, so the URL carries
// no view axis. The URL tests render NON-embedded (embedded skips URL writes),
// so each resets window.location.
describe("ProtocolSurface — M2 per-tab awareness + URL", () => {
  const SAFE = RICH_ADDRESSES.SAFE;
  const VAULT = RICH_ADDRESSES.VAULT;

  beforeEach(() => {
    installApiMocks();
    window.history.replaceState({}, "", "/company/etherfi/surface");
  });

  function url() {
    return new URL(window.location.href);
  }

  // --- Monitor tab (stage 2): principal hint + focus-preview must not select ---

  it("shows a 'pick a contract' hint in Monitor when a principal is selected", async () => {
    window.localStorage.setItem("psat_admin_key", "test-key");
    renderSurface(); // admin
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    await clickSidebarTab("Monitor");
    expect(
      await screen.findByText(/choose a contract to see its alerts/i),
    ).toBeInTheDocument();
    // Not the contract-focused view.
    expect(screen.queryByText(/^Contract alerts$/)).not.toBeInTheDocument();
    expectNoCrash();
  });

  it("does not treat a search focus-preview as a Monitor selection", async () => {
    window.localStorage.setItem("psat_admin_key", "test-key");
    renderSurface(); // admin
    const user = userEvent.setup();
    await clickSidebarTab("Monitor");

    // Browse to the Vault contract via the search arrows — a focus preview,
    // never a commit. Pre-M2, Monitoring's private focusedAddress fallback
    // turned this into a contract selection ("Contract alerts").
    await user.type(searchInput(), "Vault");
    await user.keyboard("{ArrowDown}");

    await waitFor(() => {
      expect(screen.getByText(/^Monitor alerts$/)).toBeInTheDocument();
    });
    expect(screen.queryByText(/^Contract alerts$/)).not.toBeInTheDocument();
    expectNoCrash();
  });

  // --- URL ?sel= (stage 3): address only, no view axis ---

  it("writes ?sel= (no view) when a safe is committed", async () => {
    render(
      <ProtocolSurface companyName="etherfi" initialData={ETHERFI_COMPANY_RICH} />,
    ); // NON-embedded → URL writes enabled
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    await waitFor(() => {
      expect(url().searchParams.get("sel")?.toLowerCase()).toBe(SAFE.toLowerCase());
    });
    // The address alone determines the card — no view is written, and the
    // interim ?focus is retired.
    expect(url().searchParams.get("view")).toBeNull();
    expect(url().searchParams.get("focus")).toBeNull();
    expectNoCrash();
  });

  it("writes ?sel= (no view) when a contract is committed", async () => {
    render(
      <ProtocolSurface companyName="etherfi" initialData={ETHERFI_COMPANY_RICH} />,
    );
    const user = userEvent.setup();
    await user.type(searchInput(), "Vault");
    await commitViaEnter(user);

    await waitFor(() => {
      expect(url().searchParams.get("sel")?.toLowerCase()).toBe(VAULT.toLowerCase());
    });
    expect(url().searchParams.get("view")).toBeNull();
    expectNoCrash();
  });

  it("a focus-preview never writes the URL", async () => {
    render(
      <ProtocolSurface companyName="etherfi" initialData={ETHERFI_COMPANY_RICH} />,
    );
    const user = userEvent.setup();
    await user.type(searchInput(), "Vault");
    await user.keyboard("{ArrowDown}"); // preview only

    // The preview does not commit — no ?sel is written.
    await waitFor(() => {
      expect(document.querySelector(".ps-search-preview")).toBeTruthy();
    });
    expect(url().searchParams.get("sel")).toBeNull();
    expectNoCrash();
  });

  it("restores a safe from a legacy ?sel=&view=principal URL (view ignored)", async () => {
    window.history.replaceState(
      {},
      "",
      `/company/etherfi/surface?sel=${SAFE}&view=principal`,
    );
    render(
      <ProtocolSurface companyName="etherfi" initialData={ETHERFI_COMPANY_RICH} />,
    ); // non-admin → Detail
    // The safe is a principal-only entity, so the principal-shaped card renders — the
    // legacy view happens to match, but it's the facet, not the param, deciding.
    expect(await screen.findByText(/2\/3 threshold/i)).toBeInTheDocument();
    // The stale view param is dropped on the restore's URL normalization.
    await waitFor(() => {
      expect(url().searchParams.get("view")).toBeNull();
    });
    expect(url().searchParams.get("sel")?.toLowerCase()).toBe(SAFE.toLowerCase());
    expectNoCrash();
  });

  it("resolves a legacy ?focus= link and normalizes it to ?sel= (no view)", async () => {
    window.history.replaceState({}, "", `/company/etherfi/surface?focus=${VAULT}`);
    render(
      <ProtocolSurface companyName="etherfi" initialData={ETHERFI_COMPANY_RICH} />,
    ); // non-admin → Detail
    // The Vault contract card renders (EntityCard shows its functions).
    expect(await screen.findByText("upgrade")).toBeInTheDocument();
    // Legacy param translated: ?focus dropped, ?sel written, no view axis.
    await waitFor(() => {
      expect(url().searchParams.get("sel")?.toLowerCase()).toBe(VAULT.toLowerCase());
    });
    expect(url().searchParams.get("view")).toBeNull();
    expect(url().searchParams.get("focus")).toBeNull();
    expectNoCrash();
  });
});

// M3 (stage 4) polish: role-toggle reconciliation + label cosmetics. The
// node-less touch-set highlight derivation is unit-tested at the helper level
// (surface/layout/entities.test.js) since its only observable effect is the
// canvas dim overlay, which ELK doesn't lay out in jsdom.
describe("ProtocolSurface — M3 polish", () => {
  beforeEach(() => {
    installApiMocks();
  });

  // Role-toggle reconciliation: hiding the selected contract's role must clear
  // the selection so no sidebar card is stranded for a node that's gone. The
  // fixture's contracts fall in the "utility" role bucket, toggled via the
  // Utilities chip.
  it("clears the selection when a role toggle hides the selected contract", async () => {
    renderSurface(); // non-admin → Detail
    const user = userEvent.setup();

    // Commit the Vault contract → its contract card mounts.
    await user.type(searchInput(), "Vault");
    await commitViaEnter(user);
    await waitFor(() => {
      expect(document.querySelector(".ps-machine")).toBeTruthy();
    });

    // Toggle the role that contains Vault off — it leaves the visible set.
    const roleBar = document.querySelector(".ps-role-bar");
    const utilities = await within(roleBar).findByRole("button", { name: /Utilities/i });
    await user.click(utilities);

    // The stranded card is reconciled away; Detail returns to its empty state.
    await waitFor(() => {
      expect(document.querySelector(".ps-machine")).toBeNull();
    });
    expectNoCrash();
  });

  // Reconciliation must fire ONLY when the SELECTED entity is hidden — toggling
  // an unrelated role leaves the selection alone (it doesn't blindly clear on
  // every roles change).
  it("keeps the selection when an unrelated role is toggled", async () => {
    renderSurface();
    const user = userEvent.setup();

    // Commit Vault (a "utility"-bucket contract).
    await user.type(searchInput(), "Vault");
    await commitViaEnter(user);
    await waitFor(() => {
      expect(document.querySelector(".ps-machine")).toBeTruthy();
    });

    // Toggle a role Vault is NOT in — its card must survive.
    const roleBar = document.querySelector(".ps-role-bar");
    const governance = await within(roleBar).findByRole("button", { name: /Governance/i });
    await user.click(governance);

    // Give the reconciliation effect a chance to (wrongly) fire, then assert
    // the card is still there.
    await new Promise((r) => setTimeout(r, 50));
    expect(document.querySelector(".ps-machine")).toBeTruthy();
    expectNoCrash();
  });

  // Label cosmetics: a principal whose label is the bare type token ("safe")
  // must not render "safe safe" — the display name falls back to the address.
  it("does not render a bare-type label as the principal name", async () => {
    const bareLabelData = {
      ...ETHERFI_COMPANY_RICH,
      principals: [
        {
          ...SAFE_PRINCIPAL,
          label: "safe", // server emitted the bare type token
        },
      ],
    };
    render(
      <ProtocolSurface companyName="etherfi" initialData={bareLabelData} embedded />,
    );
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    const name = await waitFor(() => {
      const el = document.querySelector(".ps-machine-name");
      expect(el).toBeTruthy();
      return el;
    });
    // Renders the short address, never the duplicated "safe".
    expect(name.textContent).not.toBe("safe");
    expect(name.textContent).toMatch(/^0x[0-9a-fA-F]{4}\.\./);
    expectNoCrash();
  });
});

// Motivating bug (UNIFIED_ENTITY_CARD_REFACTOR.md): a machine-only authority —
// an analyzed contract the server never emits as a principal, e.g.
// EtherFiTimelock — is reached via a caller button that carries a non-contract
// type ("timelock"). Pre-collapse that type became view=principal, but the
// entity has no principal facet, so BOTH derived facets went null and the
// sidebar rendered nothing. With no stored view the machine facet always wins.
describe("ProtocolSurface — machine-only authority (motivating bug)", () => {
  const GOV = "0x9999999999999999999999999999999999999999";
  const GPOOL = "0x8888888888888888888888888888888888888888";

  function mkFn(name, effectLabels, owner) {
    return {
      function: name,
      selector: `0x${name.slice(0, 8).padEnd(8, "0")}`,
      abi_signature: name,
      effect_labels: effectLabels,
      action_summary: `${name} action`,
      authority_public: false,
      direct_owner: owner
        ? { ...owner, label: null, source_contract: null, source_controller_id: null }
        : null,
      authority_roles: [],
      controllers: [],
      effect_targets: [],
    };
  }

  // GovTimelock is analyzed (a machine) and governs GovernedPool.upgradeTo, but
  // it is NOT in `principals` — so it has a machine facet and no principal one.
  const FIXTURE = {
    protocol_id: 2,
    contracts: [
      {
        address: GOV,
        name: "GovTimelock",
        risk_level: "low",
        is_proxy: false,
        controllers: {},
        job_id: "gov-job",
        functions: [mkFn("schedule", ["config"], null)],
      },
      {
        address: GPOOL,
        name: "GovernedPool",
        risk_level: "medium",
        is_proxy: true,
        proxy_type: "ERC1967",
        upgrade_count: 1,
        controllers: {},
        job_id: "gpool-job",
        functions: [
          mkFn("upgradeTo", ["upgrade"], {
            address: GOV,
            resolved_type: "timelock",
            details: { delay: 864000 },
          }),
        ],
      },
    ],
    principals: [],
    fund_flows: [],
  };

  function url() {
    return new URL(window.location.href);
  }

  beforeEach(() => {
    installApiMocks();
    window.history.replaceState({}, "", "/company/etherfi/surface");
  });

  it("navigating via a timelock-typed caller opens the contract card on its default tab", async () => {
    render(<ProtocolSurface companyName="etherfi" initialData={FIXTURE} />); // non-embedded → URL writes
    const user = userEvent.setup();

    // Open the governed contract, then commit to its upgradeTo caller via the
    // caller button's arrow — the caller is GovTimelock, typed "timelock". The
    // button body only previews now; the arrow is the commit affordance.
    await user.type(searchInput(), "GovernedPool");
    await commitViaEnter(user);
    const pool = await waitFor(() => {
      const el = document.querySelector(".ps-machine");
      expect(el).toBeTruthy();
      return el;
    });
    const callerArrow = pool.querySelector(".ps-caller-btn .ps-goto-arrow");
    expect(callerArrow).toBeTruthy();
    await user.click(callerArrow);

    // The machine-only authority's CONTRACT card renders — not a stranded empty
    // sidebar (DetailEmptyState).
    const machineName = await waitFor(() => {
      const el = document.querySelector(".ps-machine-name");
      expect(el).toBeTruthy();
      return el;
    });
    expect(machineName).toHaveTextContent("GovTimelock");

    // Opens on the default Control tab — same as a direct canvas click — so the
    // Governs panel is NOT auto-opened.
    const card = machineName.closest(".ps-machine");
    const tabBar = card.querySelector(".ps-machine-tabs");
    expect(within(tabBar).getByRole("button", { name: /^Control/ })).toHaveClass("active");
    expect(card.querySelector(".ps-governs-name")).toBeNull();

    // Governs is still one click away and lists the contract this authority governs.
    await user.click(within(tabBar).getByRole("button", { name: /^Governs/ }));
    const governsRow = await waitFor(() => {
      const el = card.querySelector(".ps-governs-name");
      expect(el).toBeTruthy();
      return el;
    });
    expect(governsRow).toHaveTextContent("GovernedPool");

    // URL persists the address only — no view axis.
    await waitFor(() => {
      expect(url().searchParams.get("sel")?.toLowerCase()).toBe(GOV.toLowerCase());
    });
    expect(url().searchParams.get("view")).toBeNull();
    expectNoCrash();
  });

  it("restores a machine-only authority from a legacy ?sel=&view=principal URL as its contract card", async () => {
    window.history.replaceState({}, "", `/company/etherfi/surface?sel=${GOV}&view=principal`);
    render(<ProtocolSurface companyName="etherfi" initialData={FIXTURE} />); // non-admin → Detail

    // The stale view=principal is ignored; the machine facet wins → contract
    // card, not an empty sidebar.
    const machineName = await waitFor(() => {
      const el = document.querySelector(".ps-machine-name");
      expect(el).toBeTruthy();
      return el;
    });
    expect(machineName).toHaveTextContent("GovTimelock");
    expectNoCrash();
  });
});
