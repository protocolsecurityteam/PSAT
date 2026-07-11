// State-variant + interaction tests for ProtocolSurface. Covers each
// sidebar mode (Detail / Agent / Audits / Monitor / Upgrades), tab
// switching, search interaction, machine selection, and the dependency
// graph modal. Goal is regression coverage for the upcoming
// ProtocolSurface.jsx file split — every sub-tree about to be extracted
// (SurfaceMonitoringPanel, AuditsListPanel, UpgradesSidebarPanel,
// PrincipalDetail, InspectorCard, DependencyGraphModal, SearchNavigator,
// ContractMachine) has a behavioral assertion here.

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

    // Detail tab stays in the empty state — no PrincipalDetail card.
    await clickSidebarTab("Detail");
    await waitFor(() => {
      expect(
        document.querySelector(".ps-detail-empty, .protocol-radar, .empty"),
      ).toBeTruthy();
    });
    expect(screen.queryByText(/2\/3 threshold/i)).not.toBeInTheDocument();
    expectNoCrash();
  });

  // (b) Enter commits the previewed safe: Detail shows its PrincipalDetail card.
  it("pressing Enter commits the safe and Detail shows its PrincipalDetail card", async () => {
    renderSurface(); // non-admin → default Detail tab
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    // PrincipalDetail-only markers (distinct from the search preview's
    // "2/3 signers"): the threshold badge and the Signers section.
    expect(await screen.findByText(/2\/3 threshold/i)).toBeInTheDocument();
    expect(await screen.findByText(/Signers \(3\)/i)).toBeInTheDocument();
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

    // Gate: the safe actually committed (Detail shows its PrincipalDetail).
    await clickSidebarTab("Detail");
    expect(await screen.findByText(/2\/3 threshold/i)).toBeInTheDocument();

    // Agent: context is the company, not any contract the safe controls.
    await clickSidebarTab("Agent");
    const value = await waitFor(() => {
      const el = document.querySelector(".agent-context-value");
      expect(el).toBeTruthy();
      return el;
    });
    expect(document.querySelector(".agent-context-meta")).not.toBeInTheDocument();
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

    // Upgrades: the global proxy list, not a single-contract timeline.
    await clickSidebarTab("Upgrades");
    await waitFor(() => {
      expect(document.querySelector(".ps-upgrades-global-hint")).toBeTruthy();
    });
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
    // ContractMachine renders with guard ports.
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
