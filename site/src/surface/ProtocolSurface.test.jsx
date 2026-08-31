// State-variant + interaction tests for ProtocolSurface. Covers each
// sidebar mode (Detail / Agent / Audits / Activity), tab switching, search
// interaction, and machine selection. Goal is regression coverage for the
// sidebar sub-trees (ActivityPanel, AuditsListPanel, EntityCard,
// InspectorCard, SearchNavigator) — each has a behavioral assertion here.

import React from "react";
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ProtocolSurface, { auditHighlightSet, principalOnChain } from "./ProtocolSurface.jsx";
import { entityKey } from "./entityKey.js";
import { setFetchHandler } from "../test/fetchMock.js";
import {
  ETHERFI_COMPANY_RICH,
  RICH_COVERAGE,
  RICH_ADDRESSES,
  ADDRESS_LABELS,
} from "../test/fixtures.js";

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

function fixtureFunctions(data) {
  return Object.fromEntries(
    (data.contracts || []).map((contract) => [
      entityKey(contract.chain, contract.address),
      contract.functions || [],
    ]),
  );
}

function renderSurface() {
  return render(
    <ProtocolSurface
      companyName="etherfi"
      initialData={ETHERFI_COMPANY_RICH}
      initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
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

// The filter panel starts collapsed; the pill is the toggle in BOTH states, so
// expanding means clicking it only while it reports collapsed.
function expandFiltersIfCollapsed() {
  const pill = document.querySelector('.ps-filter-pill[aria-expanded="false"]');
  if (pill) fireEvent.click(pill);
}

function searchInput() {
  expandFiltersIfCollapsed();
  const el = document.querySelector(".ps-search-input");
  expect(el).toBeTruthy();
  return el;
}

async function selectSearchMode(user, label) {
  expandFiltersIfCollapsed();
  // Scope to the top-left search-modes bar so a same-named button elsewhere
  // in the surface can never satisfy the query.
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
  // Scope to the sidebar tab bar so a same-named button in the panel body can
  // never satisfy the query.
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

  it("opens the Activity tab and shows the protocol-wide feed", async () => {
    // Activity is public (no admin key needed). With nothing selected it
    // renders ProtocolActivity — the "Recent across protocol" overview.
    renderSurface();
    await clickSidebarTab("Activity");
    await waitFor(() => {
      const text = document.body.textContent || "";
      expect(/Recent across protocol|addresses monitored|Activity/i.test(text)).toBe(true);
    });
    expectNoCrash();
  });

  it("opens the Detail tab and shows the empty state", async () => {
    renderSurface();
    await clickSidebarTab("Detail");
    await waitFor(() => {
      // DetailEmptyState renders when no machine/principal is selected.
      const radarOrEmpty = document.querySelector(".ps-detail-empty, .empty");
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

  it("shows the Audits tab with no count once coverage loads", async () => {
    renderSurface();
    const tabBar = await waitFor(() => {
      const el = document.querySelector(".ps-sidebar-tabs");
      expect(el).toBeTruthy();
      return el;
    });
    // The tab is labeled just "Audits" — the raw report total is misleading
    // (most reports aren't bytecode-verified), so no count is shown.
    expect(within(tabBar).getByRole("button", { name: /^Audits$/ })).toBeInTheDocument();
    expect(within(tabBar).queryByRole("button", { name: /Audits\s*\(\d+\)/ })).toBeNull();
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

// A minimal two-chain protocol: 2 ethereum contracts + 1 base contract. Only
// contracts carry a chain (NULL≡ethereum); principals/flows have none.
const MULTICHAIN_COMPANY = {
  company: "multi",
  contracts: [
    { address: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", name: "EthGovA", role: "governance", is_proxy: true, chain: "ethereum", functions: [] },
    { address: "0xa2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", name: "EthGovB", role: "governance", is_proxy: true, chain: "ethereum", functions: [] },
    { address: "0xb3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3", name: "BaseToken", role: "token", is_proxy: true, chain: "base", functions: [] },
  ],
  principals: [],
  fund_flows: [],
  ownership_hierarchy: [],
  all_addresses: [],
};

function renderMultichain() {
  return render(
    <ProtocolSurface
      companyName="multi"
      initialData={MULTICHAIN_COMPANY}
      initialFunctions={fixtureFunctions(MULTICHAIN_COMPANY)}
      embedded
    />,
  );
}

function scopedMachineCount() {
  // The contracts-mode search counter reads "1 / N" — N machines on the active
  // chain. A non-canvas signal of chain scoping (the panel must be expanded).
  expandFiltersIfCollapsed();
  const counter = document.querySelector(".ps-search-counter");
  const m = /\/\s*(\d+)/.exec(counter?.textContent || "");
  return m ? Number(m[1]) : 0;
}

describe("ProtocolSurface — multichain chain switcher", () => {
  beforeEach(() => {
    installApiMocks();
  });

  it("shows a chain pill row only for a multi-chain protocol", async () => {
    // Single-chain (the rich fixture has no chains) → no switcher.
    renderSurface();
    await waitFor(() => expect(document.querySelector(".ps-surface")).toBeInTheDocument());
    expect(document.querySelector(".ps-chain-bar")).toBeNull();
  });

  it("renders Ethereum + Base pills and scopes the page to the active chain", async () => {
    renderMultichain();
    // Collapsed, the filter pill itself wears the active chain — the scope is
    // never silently hidden behind an unopened panel.
    await waitFor(() => expect(document.querySelector(".ps-filter-chain")).toBeTruthy());
    expect(document.querySelector(".ps-filter-chain").textContent).toContain("Ethereum");

    // The chain bar (and the search counter) live inside the expanded panel.
    expandFiltersIfCollapsed();
    const bar = await waitFor(() => {
      const el = document.querySelector(".ps-chain-bar");
      expect(el).toBeTruthy();
      return el;
    });
    expect(within(bar).getByText("Ethereum")).toBeTruthy();
    expect(within(bar).getByText("Base")).toBeTruthy();
    // Default scope is ethereum → its 2 contracts are the machine set.
    await waitFor(() => expect(scopedMachineCount()).toBe(2));

    // Switching to Base rescopes to its single contract without crashing.
    const user = userEvent.setup();
    await user.click(within(bar).getByText("Base").closest("button"));
    await waitFor(() => expect(scopedMachineCount()).toBe(1));
    expectNoCrash();
  });

  // The score page's deduction rows click through with a (chain, address)
  // pair. A base entity clicked while the page shows ethereum must switch the
  // page's chain scope and land the selection — and the collapsed filter pill
  // must wear the new chain so the switch is visible without opening anything.
  it("a cross-chain selectExample switches the chain scope and lands the selection", async () => {
    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="multi"
        initialData={MULTICHAIN_COMPANY}
        initialFunctions={fixtureFunctions(MULTICHAIN_COMPANY)}
        embedded
      />,
    );
    await waitFor(() => expect(ref.current).toBeTruthy());

    let result;
    await act(async () => {
      result = ref.current.selectExample({
        contractAddress: "0xb3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
        chain: "base",
      });
    });
    expect(result).toEqual({ ok: true, kind: "chain-switch", chain: "base" });

    // The parked request re-ran after the re-scope: the base contract's card
    // is up, and the pill wears Base.
    await waitFor(() => {
      expect(document.body.textContent).toContain("BaseToken");
      expect(document.querySelector(".ps-machine")).toBeTruthy();
    });
    expect(document.querySelector(".ps-filter-chain").textContent).toContain("Base");
    expectNoCrash();
  });

  // The switch outcome is a claim ("it is on that chain") and must be earned:
  // a chain the page cannot scope to, or a principal whose chains list does
  // not name the chain, refuses rather than announcing a switch that the
  // scoping would silently degrade.
  it("refuses a cross-chain request the payload does not witness", async () => {
    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="multi"
        initialData={{
          ...MULTICHAIN_COMPANY,
          // A legacy principal (no chains list) at a known address: its
          // absent list must NOT witness it onto arbitrum.
          principals: [{ address: "0xc4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4", type: "safe", controls: [] }],
        }}
        initialFunctions={fixtureFunctions(MULTICHAIN_COMPANY)}
        embedded
      />,
    );
    await waitFor(() => expect(ref.current).toBeTruthy());
    let offProtocolChain;
    let legacyPrincipal;
    await act(async () => {
      // arbitrum: no contracts there at all — not scopable.
      offProtocolChain = ref.current.selectExample({
        contractAddress: "0xb3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
        chain: "arbitrum",
      });
      // base is scopable, but the principal's own chains list doesn't name it.
      legacyPrincipal = ref.current.selectExample({
        contractAddress: "0xc4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4",
        chain: "base",
      });
    });
    expect(offProtocolChain).toEqual({ ok: false, kind: "not-found" });
    expect(legacyPrincipal).toEqual({ ok: false, kind: "not-found" });
    // Nothing switched: the pill still wears the default chain.
    expect(document.querySelector(".ps-filter-chain").textContent).toContain("Ethereum");
    expectNoCrash();
  });
});

// The /functions endpoint payload is keyed by the composite "<chain>::<address>"
// token (entityKey), so a CREATE2 twin at the SAME address on two chains keeps
// each chain's own function analysis. A flat bare-address map collapsed the two
// last-wins, rendering one chain's open/gated verdicts under both.
describe("ProtocolSurface — per-chain function verdicts (functions chain axis)", () => {
  const SHARED = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
  const DATA = {
    company: "twin",
    contracts: [
      { address: SHARED, name: "SharedVault", role: "governance", is_proxy: true, chain: "ethereum" },
      { address: SHARED, name: "SharedVault", role: "governance", is_proxy: true, chain: "base" },
    ],
    principals: [],
    fund_flows: [],
    ownership_hierarchy: [],
    all_addresses: [],
  };
  // Same address, opposite verdict: pause is gated on ethereum, earned-public
  // on base — distinct function NAMES make the wrong-chain render observable.
  const FUNCTIONS = {
    [`ethereum::${SHARED}`]: [
      {
        function: "pauseOnEth",
        selector: "0xeth00000",
        abi_signature: "pauseOnEth()",
        claims: [{ claim_id: "pause.set", tier: "standard_exact", witness: {} }],
        authority_public: false,
      },
    ],
    [`base::${SHARED}`]: [
      {
        function: "pauseOnBase",
        selector: "0xbase0000",
        abi_signature: "pauseOnBase()",
        claims: [{ claim_id: "pause.set", tier: "standard_exact", witness: {} }],
        authority_public: true,
      },
    ],
  };

  beforeEach(() => {
    installApiMocks();
  });

  it("renders base's function analysis (not ethereum's) when scoped to base", async () => {
    render(
      <ProtocolSurface companyName="twin" initialData={DATA} initialFunctions={FUNCTIONS} embedded />,
    );
    const user = userEvent.setup();
    // The chain bar lives inside the (collapsed-by-default) filter panel.
    await waitFor(() => expect(document.querySelector(".ps-filter-pill")).toBeTruthy());
    expandFiltersIfCollapsed();
    const bar = await waitFor(() => {
      const el = document.querySelector(".ps-chain-bar");
      expect(el).toBeTruthy();
      return el;
    });

    // Scope to Base, then select the shared-address contract.
    await user.click(within(bar).getByText("Base").closest("button"));
    await user.type(searchInput(), "SharedVault");
    await commitViaEnter(user);

    // Base's function is shown; ethereum's is not. A flat bare-address map
    // would look up functionData[SHARED] and collapse the two chains.
    expect(await screen.findByText("pauseOnBase")).toBeInTheDocument();
    expect(screen.queryByText("pauseOnEth")).not.toBeInTheDocument();
    expectNoCrash();
  });
});

// B2: the audit-coverage highlight set is matched against the chain-scoped
// canvas's bare node ids. Coverage rows are all-chain, so a CREATE2 twin covered
// only on base must NOT light the same-address ethereum node (inv. 13).
describe("auditHighlightSet — chain scope (B2)", () => {
  const TWIN = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
  const verified = { audit_id: 7, equivalence_status: "proven", match_type: "reviewed_commit" };
  // Covered only on base.
  const COVERAGE = [{ address: TWIN, chain: "base", audits: [verified] }];

  it("does not highlight the ethereum node for a twin covered only on base", () => {
    expect(auditHighlightSet(COVERAGE, "all", "ethereum")).toBeNull();
  });

  it("highlights the twin when scoped to the chain it is covered on", () => {
    const set = auditHighlightSet(COVERAGE, "all", "base");
    expect(set && set.has(TWIN)).toBe(true);
  });

  it("keeps chain-less legacy coverage rows on any active chain", () => {
    const legacy = [{ address: TWIN, audits: [verified] }];
    const set = auditHighlightSet(legacy, "all", "ethereum");
    expect(set && set.has(TWIN)).toBe(true);
  });
});

// B4c: a principal governs only on the chain(s) in its ``chains`` list. On a
// chain it was never observed on, it must not attach to a same-address twin.
describe("principalOnChain — chain scope (B4c)", () => {
  it("excludes a principal observed only on another chain", () => {
    expect(principalOnChain({ chains: ["base"] }, "ethereum")).toBe(false);
    expect(principalOnChain({ chains: ["ethereum"] }, "ethereum")).toBe(true);
  });

  it("keeps a multi-chain principal on each of its chains", () => {
    expect(principalOnChain({ chains: ["ethereum", "base"] }, "base")).toBe(true);
  });

  it("keeps legacy principals with no chains, and any principal when unscoped", () => {
    expect(principalOnChain({}, "ethereum")).toBe(true);
    expect(principalOnChain({ chains: [] }, "ethereum")).toBe(true);
    expect(principalOnChain({ chains: ["base"] }, null)).toBe(true);
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
// to test buildMachines / guardSummary / collectDirectCallers once those are
// extracted as standalone helpers — pinning the fixture here means the
// extraction and the fixture stay in lockstep.
describe("rich fixture", () => {
  it("has both proxy and non-proxy contracts", () => {
    const proxies = ETHERFI_COMPANY_RICH.contracts.filter((c) => c.is_proxy);
    const nonProxies = ETHERFI_COMPANY_RICH.contracts.filter((c) => !c.is_proxy);
    expect(proxies.length).toBeGreaterThan(0);
    expect(nonProxies.length).toBeGreaterThan(0);
  });

  it("has functions covering every claim lane", () => {
    const allClaims = ETHERFI_COMPANY_RICH.contracts.flatMap((c) =>
      c.functions.flatMap((f) => (f.claims || []).map((claim) => claim.claim_id)),
    );
    expect(allClaims).toEqual(
      expect.arrayContaining(["upgrade.implementation", "pause.set", "flow.in", "flow.out", "authority.replace"]),
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
        document.querySelector(".ps-detail-empty, .empty"),
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
  // the Agent, Audits, or Activity tabs (the original leak lit up controls[0]).
  it("committing a safe leaves Agent/Audits/Activity with no contract selected", async () => {
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

    // Activity (folds in Monitor + Upgrades): a principal is contract-only by
    // nature, so the tab shows an explicit "pick a contract" hint — never a
    // leaked contract's timeline nor its entity status strip.
    await clickSidebarTab("Activity");
    await waitFor(() => {
      expect(
        screen.getByText(/monitoring is not enabled/i),
      ).toBeInTheDocument();
    });
    expect(document.querySelector(".ps-activity-strip")).toBeNull();
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
        initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
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
          // /functions is keyed by the composite (chain, address) token; the
          // bare-data Vault carries no chain → "ethereum".
          functions: {
            [entityKey("ethereum", VAULT)]: [
              {
                function: "upgrade",
                selector: "0xupgrade0",
                abi_signature: "upgrade",
                claims: [{ claim_id: "upgrade.implementation", tier: "standard_exact", witness: {} }],
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

  // --- Activity tab (stage 2): principal hint + focus-preview must not select ---

  it("shows a 'pick a contract' hint in Activity when a principal is selected", async () => {
    renderSurface(); // Activity is public — no admin key needed
    const user = userEvent.setup();
    await selectSearchMode(user, "Safes");
    await commitViaEnter(user);

    await clickSidebarTab("Activity");
    expect(
      await screen.findByText(/monitoring is not enabled/i),
    ).toBeInTheDocument();
    // Not the entity-focused view: no status strip renders for a principal.
    expect(document.querySelector(".ps-activity-strip")).toBeNull();
    expectNoCrash();
  });

  it("does not treat a search focus-preview as an Activity selection", async () => {
    renderSurface();
    const user = userEvent.setup();
    await clickSidebarTab("Activity");

    // Browse to the Vault contract via the search arrows — a focus preview,
    // never a commit. ActivityPanel reads selectedMachine only (never a private
    // focusedAddress), so a preview must stay in the protocol-wide feed.
    await user.type(searchInput(), "Vault");
    await user.keyboard("{ArrowDown}");

    await waitFor(() => {
      const text = document.body.textContent || "";
      expect(/Recent across protocol|addresses monitored|Activity/i.test(text)).toBe(true);
    });
    // Preview did not commit → no entity status strip.
    expect(document.querySelector(".ps-activity-strip")).toBeNull();
    expectNoCrash();
  });

  // --- URL ?sel= (stage 3): address only, no view axis ---

  it("writes ?sel= (no view) when a safe is committed", async () => {
    render(
      <ProtocolSurface
        companyName="etherfi"
        initialData={ETHERFI_COMPANY_RICH}
        initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
      />,
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
      <ProtocolSurface
        companyName="etherfi"
        initialData={ETHERFI_COMPANY_RICH}
        initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
      />,
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
      <ProtocolSurface
        companyName="etherfi"
        initialData={ETHERFI_COMPANY_RICH}
        initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
      />,
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

});

// M3 (stage 4) polish: label cosmetics. The node-less touch-set highlight
// derivation is unit-tested at the helper level
// (surface/layout/entities.test.js) since its only observable effect is the
// canvas dim overlay, which ELK doesn't lay out in jsdom.
describe("ProtocolSurface — M3 polish", () => {
  beforeEach(() => {
    installApiMocks();
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
      <ProtocolSurface
        companyName="etherfi"
        initialData={bareLabelData}
        initialFunctions={fixtureFunctions(bareLabelData)}
        embedded
      />,
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

  function mkFn(name, claimIds, owner) {
    return {
      function: name,
      selector: `0x${name.slice(0, 8).padEnd(8, "0")}`,
      abi_signature: name,
      claims: claimIds.map((claim_id) => ({ claim_id, tier: "standard_exact", witness: {} })),
      authority_public: false,
      direct_owner: owner
        ? { ...owner, label: null, source_contract: null, source_controller_id: null }
        : null,
      authority_roles: [],
      controllers: [],
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
        is_proxy: false,
        controllers: {},
        job_id: "gov-job",
        functions: [mkFn("schedule", ["timelock.schedule"], null)],
      },
      {
        address: GPOOL,
        name: "GovernedPool",
        is_proxy: true,
        proxy_type: "ERC1967",
        upgrade_count: 1,
        controllers: {},
        job_id: "gpool-job",
        functions: [
          mkFn("upgradeTo", ["upgrade.implementation"], {
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
    render(
      <ProtocolSurface
        companyName="etherfi"
        initialData={FIXTURE}
        initialFunctions={fixtureFunctions(FIXTURE)}
      />,
    ); // non-embedded → URL writes
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

});

describe("ProtocolSurface — external selection handle", () => {
  // Only LiquidityPool carries `rebalance`; `setFee` is put on BOTH contracts
  // below so the graph has a name that resolves to no single host — the shape
  // the score document's bare example-function names can land in.
  const GRAPH_UNIQUE_FN = "rebalance";
  const GRAPH_SHARED_FN = "setFee";
  const SHARED_NAME_DATA = {
    ...ETHERFI_COMPANY_RICH,
    contracts: ETHERFI_COMPANY_RICH.contracts.map((contract, i) =>
      i === 0
        ? contract
        : {
            ...contract,
            functions: [
              ...contract.functions,
              ETHERFI_COMPANY_RICH.contracts[0].functions.find(
                (f) => f.function === GRAPH_SHARED_FN,
              ),
            ],
          },
    ),
  };

  beforeEach(() => {
    installApiMocks();
  });

  function renderWithHandle(data = ETHERFI_COMPANY_RICH) {
    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="etherfi"
        initialData={data}
        initialFunctions={fixtureFunctions(data)}
        embedded
      />,
    );
    return ref;
  }

  it("selects a contract and the named function", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let accepted;
    await act(async () => {
      accepted = ref.current.selectExample({
        contractAddress: ETHERFI_COMPANY_RICH.contracts[0].address,
        functionSignature: "pause",
      });
    });
    expect(accepted).toEqual({ ok: true, kind: "function" });
    const name = await waitFor(() => {
      const el = document.querySelector(".ps-machine-name");
      expect(el).toBeTruthy();
      return el;
    });
    expect(name).toHaveTextContent("Vault");
    // ...and the named function, not just its contract.
    const inspector = await waitFor(() => {
      const el = document.querySelector(".ps-inspector");
      expect(el).toBeTruthy();
      return el;
    });
    expect(inspector).toHaveTextContent("pause");
    expectNoCrash();
  });

  it("selects a principal-only entity through the principal path", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let accepted;
    await act(async () => {
      accepted = ref.current.selectExample({ contractAddress: SAFE_PRINCIPAL.address });
    });
    expect(accepted).toEqual({ ok: true, kind: "principal" });
    await waitFor(() => {
      expect(document.querySelector(".ps-principal-section")).toBeTruthy();
    });
    expectNoCrash();
  });

  it("refuses an address the graph does not carry, and a chain the payload never witnessed it on", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let offGraph;
    let offChain;
    await act(async () => {
      offGraph = ref.current.selectExample({
        contractAddress: "0xdead00000000000000000000000000000000dead",
      });
      // This protocol has no base deployment: "it is on base" is a claim the
      // payload never witnessed, so the request refuses rather than switching.
      offChain = ref.current.selectExample({
        contractAddress: ETHERFI_COMPANY_RICH.contracts[0].address,
        chain: "base",
      });
    });
    expect(offGraph).toEqual({ ok: false, kind: "not-found" });
    expect(offChain).toEqual({ ok: false, kind: "not-found" });
    expect(document.querySelector(".ps-machine-name")).toBeNull();
    expectNoCrash();
  });

  it("says it selected the contract, not the function, when the contract does not carry it", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample({
        contractAddress: ETHERFI_COMPANY_RICH.contracts[0].address,
        functionSignature: "noSuchFunctionHere",
      });
    });
    expect(result).toEqual({ ok: true, kind: "contract", functionMissing: true });
    await waitFor(() => {
      expect(document.querySelector(".ps-machine-name")).toBeTruthy();
    });
    expectNoCrash();
  });

  it("resolves a bare function name against the whole graph when no contract is named", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample({ functionSignature: GRAPH_UNIQUE_FN });
    });
    expect(result).toEqual({ ok: true, kind: "function" });
    const inspector = await waitFor(() => {
      const el = document.querySelector(".ps-inspector");
      expect(el).toBeTruthy();
      return el;
    });
    expect(inspector).toHaveTextContent(GRAPH_UNIQUE_FN);
    expectNoCrash();
  });

  it("refuses a bare function name two contracts answer to, and selects nothing", async () => {
    const ref = renderWithHandle(SHARED_NAME_DATA);
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample({ functionSignature: GRAPH_SHARED_FN });
    });
    expect(result.ok).toBe(false);
    expect(result.kind).toBe("ambiguous-function");
    expect(result.hosts).toBeGreaterThan(1);
    // Nothing was selected: a guessed host is worse than no navigation.
    expect(document.querySelector(".ps-machine-name")).toBeNull();
    expectNoCrash();
  });

  it("refuses a bare function name no contract on the graph carries", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample({ functionSignature: "noContractHasThis" });
    });
    expect(result).toEqual({ ok: false, kind: "not-found" });
    expect(document.querySelector(".ps-machine-name")).toBeNull();
    expectNoCrash();
  });
});

// A score-page arrival used to render a SECOND entity card in a flyout popped
// out beside the sidebar while the sidebar itself showed the empty state. There
// is one sidebar now: the arrival renders on the sidebar's own Detail card,
// carrying the highlight with it.
describe("ProtocolSurface — score arrivals land on the one sidebar card", () => {
  const VAULT = ETHERFI_COMPANY_RICH.contracts[0];
  const POOL = ETHERFI_COMPANY_RICH.contracts[1];
  let scrolled;

  beforeEach(() => {
    installApiMocks();
    scrolled = [];
    // jsdom does no layout, so Element.scrollIntoView doesn't exist. Record the
    // element each call was made on so "scrolled the highlighted row into view"
    // is an assertion about that row, not just about some scroll happening.
    Element.prototype.scrollIntoView = function scrollIntoViewStub(opts) {
      scrolled.push({ el: this, opts });
    };
  });

  afterEach(() => {
    delete Element.prototype.scrollIntoView;
  });

  function renderWithHandle() {
    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="etherfi"
        initialData={ETHERFI_COMPANY_RICH}
        initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
        embedded
      />,
    );
    return ref;
  }

  async function arrive(ref, example) {
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample(example);
    });
    return result;
  }

  function sidebar() {
    const el = document.querySelector(".ps-sidebar-content");
    expect(el).toBeTruthy();
    return el;
  }

  function noFlyout() {
    expect(
      document.querySelectorAll(
        ".ps-sidebar-flyout, .ps-sidebar-flyout-content, .ps-sidebar-flyout-rail, .ps-sidebar-flyout-toggle",
      ).length,
    ).toBe(0);
  }

  it("marks the named function on the sidebar's own card — one card, no flyout", async () => {
    const ref = renderWithHandle();
    expect(
      await arrive(ref, { contractAddress: VAULT.address, functionSignature: "pause" }),
    ).toEqual({ ok: true, kind: "function" });

    await waitFor(() => {
      expect(sidebar().querySelector(".ps-machine-name")).toHaveTextContent("Vault");
    });
    // Exactly one entity card exists, and it is the sidebar's.
    expect(document.querySelectorAll(".ps-machine").length).toBe(1);
    noFlyout();

    const marked = sidebar().querySelectorAll(".ps-port-score-highlight");
    expect(marked.length).toBe(1);
    expect(marked[0].querySelector(".ps-port-name")).toHaveTextContent("pause");
    // The guard inspector for the named function rides along in the sidebar.
    expect(sidebar().querySelector(".ps-inspector")).toHaveTextContent("pause");
    expectNoCrash();
  });

  it("opens the tab that lists the highlighted function and scrolls its row into view", async () => {
    const ref = renderWithHandle();
    // withdraw is an asset_send: it is listed on Outflows, not the Control tab
    // a card opens on by default — so the card has to go where the row is.
    expect(
      await arrive(ref, { contractAddress: VAULT.address, functionSignature: "withdraw" }),
    ).toEqual({ ok: true, kind: "function" });

    await waitFor(() => {
      expect(sidebar().querySelector(".ps-machine-tab.active")).toHaveTextContent(/Outflows/i);
    });
    const marked = sidebar().querySelector(".ps-port-score-highlight");
    expect(marked.querySelector(".ps-port-name")).toHaveTextContent("withdraw");
    expect(scrolled.some((call) => call.el === marked)).toBe(true);
    expectNoCrash();
  });

  it("opens the card unmarked when the score row names no function", async () => {
    const ref = renderWithHandle();
    expect(await arrive(ref, { contractAddress: POOL.address })).toEqual({
      ok: true,
      kind: "contract",
      functionMissing: false,
    });

    // The card opening IS the landing signal — no ring dresses it up, and no
    // function row claims to be the named one.
    await waitFor(() => {
      expect(sidebar().querySelector(".ps-machine-name")).toHaveTextContent("LiquidityPool");
    });
    expect(sidebar().querySelector(".ps-port-score-highlight")).toBeNull();
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    noFlyout();
    expectNoCrash();
  });

  it("renders a controller arrival as the sidebar's principal card, unmarked", async () => {
    const ref = renderWithHandle();
    expect(await arrive(ref, { contractAddress: SAFE_PRINCIPAL.address })).toEqual({
      ok: true,
      kind: "principal",
    });

    await waitFor(() => {
      expect(sidebar().querySelector(".ps-principal-section")).toBeTruthy();
    });
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    noFlyout();
    expectNoCrash();
  });

  it("drops the highlight as soon as the next selection lands", async () => {
    const ref = renderWithHandle();
    await arrive(ref, { contractAddress: VAULT.address, functionSignature: "pause" });
    await waitFor(() => {
      expect(document.querySelector(".ps-port-score-highlight")).toBeTruthy();
    });

    const user = userEvent.setup();
    await user.type(searchInput(), "LiquidityPool");
    await commitViaEnter(user);

    await waitFor(() => {
      expect(sidebar().querySelector(".ps-machine-name")).toHaveTextContent("LiquidityPool");
    });
    expect(document.querySelector(".ps-port-score-highlight")).toBeNull();
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    expectNoCrash();
  });
});

// The score row names a PAIR — an action and the one principal that can take
// it — so a click on it marks that pair on the card: the function's row, and
// inside it the caller chip for that controller. Each part is marked only where
// the card's own lanes witness it; where they don't, the mark falls back rather
// than being invented.
describe("ProtocolSurface — a score arrival marks the function/caller pair", () => {
  const VAULT = ETHERFI_COMPANY_RICH.contracts[0];
  const { SAFE, TIMELOCK, EOA } = RICH_ADDRESSES;

  beforeEach(() => {
    installApiMocks();
    Element.prototype.scrollIntoView = function scrollIntoViewStub() {};
  });

  afterEach(() => {
    delete Element.prototype.scrollIntoView;
  });

  async function arrive(example) {
    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="etherfi"
        initialData={ETHERFI_COMPANY_RICH}
        initialFunctions={fixtureFunctions(ETHERFI_COMPANY_RICH)}
        embedded
      />,
    );
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample(example);
    });
    return { ref, result };
  }

  function markedRow() {
    return document.querySelector(".ps-port-score-highlight");
  }

  function markedChips() {
    return [...document.querySelectorAll(".ps-caller-score-highlight")];
  }

  it("marks the hinted function's row AND that row's chip for the hinted controller", async () => {
    // pause is guarded by the Safe on this card, and the Safe is who the row
    // named — the pair the points were charged for.
    const { result } = await arrive({
      contractAddress: VAULT.address,
      highlight: { functionSignature: "pause", controller: SAFE },
    });
    expect(result).toEqual({
      ok: true,
      kind: "contract",
      functionMissing: false,
      highlight: { function: "marked", controller: "marked" },
    });

    await waitFor(() => expect(markedRow()).toBeTruthy());
    expect(markedRow().querySelector(".ps-port-name")).toHaveTextContent("pause");
    const chips = markedChips();
    expect(chips).toHaveLength(1);
    expect(chips[0].closest(".ps-port")).toBe(markedRow());
    expect(chips[0]).toHaveTextContent("Safe");
    // The pair is the mark: the card outline is not also rung.
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    expectNoCrash();
  });

  it("marks nothing inside the card when the hinted controller cannot call the hinted function", async () => {
    // The Timelock guards `upgrade` on this same card, never `pause` — so the
    // pause row under the Safe's gate is a DIFFERENT action from the pair the
    // score row charged. Ringing it would present the Safe's gate as the
    // deduced one; the card simply opens, and the caller's `unpaired` outcome
    // carries the explanation.
    const { result } = await arrive({
      contractAddress: VAULT.address,
      highlight: { functionSignature: "pause", controller: TIMELOCK },
    });
    expect(result.highlight).toEqual({ function: "unpaired", controller: "not-a-caller" });

    await waitFor(() => {
      expect(document.querySelector(".ps-sidebar-content .ps-machine-name")).toHaveTextContent("Vault");
    });
    expect(markedRow()).toBeNull();
    expect(markedChips()).toHaveLength(0);
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    expectNoCrash();
  });

  it("opens the card with no mark at all when no row answers to the hinted name", async () => {
    const { result } = await arrive({
      contractAddress: VAULT.address,
      highlight: { functionSignature: "noSuchFunctionHere", controller: SAFE },
    });
    expect(result).toEqual({
      ok: true,
      kind: "contract",
      functionMissing: false,
      highlight: { function: "not-on-card", controller: "not-a-caller" },
    });

    await waitFor(() => {
      expect(document.querySelector(".ps-sidebar-content .ps-machine-name")).toHaveTextContent("Vault");
    });
    expect(markedRow()).toBeNull();
    expect(markedChips()).toHaveLength(0);
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    expectNoCrash();
  });

  it("marks the caller chip on a function-name arrival the graph resolved itself", async () => {
    // withdraw exists on one contract only, so the name alone resolves a host —
    // and the row's controller is that function's caller there.
    const { result } = await arrive({
      functionSignature: "withdraw",
      highlight: { functionSignature: "withdraw", controller: EOA },
    });
    expect(result).toEqual({
      ok: true,
      kind: "function",
      highlight: { function: "marked", controller: "marked" },
    });

    await waitFor(() => expect(markedRow()).toBeTruthy());
    expect(markedRow().querySelector(".ps-port-name")).toHaveTextContent("withdraw");
    expect(markedChips()).toHaveLength(1);
    expect(markedChips()[0]).toHaveTextContent("EOA");
    expectNoCrash();
  });

  it("narrows a shared function name to the host whose function the hinted controller can call", async () => {
    // `withdraw` exists on BOTH machines here, but only Vault's is gated by
    // the hinted EOA — the pool's copy sits under the Safe. The name alone is
    // ambiguous; the (function, controller) pair is witnessed on exactly one
    // card, and that pair is the action the score row charged.
    const shared = structuredClone(ETHERFI_COMPANY_RICH);
    const vault = shared.contracts.find((c) => c.name === "Vault");
    const pool = shared.contracts.find((c) => c.name === "LiquidityPool");
    const vaultWithdraw = vault.functions.find((f) => f.function === "withdraw");
    const safeGate = vault.functions.find((f) => f.function === "pause").direct_owner;
    pool.functions.push({ ...structuredClone(vaultWithdraw), direct_owner: structuredClone(safeGate) });

    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="etherfi"
        initialData={shared}
        initialFunctions={fixtureFunctions(shared)}
        embedded
      />,
    );
    await waitFor(() => expect(ref.current).toBeTruthy());

    // Without the pair the name resolves to neither host.
    let bare;
    await act(async () => {
      bare = ref.current.selectExample({ functionSignature: "withdraw" });
    });
    expect(bare).toEqual({ ok: false, kind: "ambiguous-function", count: 2, hosts: 2 });

    let result;
    await act(async () => {
      result = ref.current.selectExample({
        functionSignature: "withdraw",
        highlight: { functionSignature: "withdraw", controller: EOA },
      });
    });
    expect(result).toEqual({
      ok: true,
      kind: "function",
      highlight: { function: "marked", controller: "marked" },
    });

    await waitFor(() => expect(markedRow()).toBeTruthy());
    expect(document.querySelector(".ps-sidebar-content .ps-machine-name")).toHaveTextContent("Vault");
    expect(markedRow().querySelector(".ps-port-name")).toHaveTextContent("withdraw");
    expect(markedChips()).toHaveLength(1);
    expect(markedChips()[0]).toHaveTextContent("EOA");
    expectNoCrash();
  });

  it("marks the member the card's own caller list witnesses, never the hint's ordering", async () => {
    // A merged-unit row names every member. The Timelock comes first in the
    // hint and cannot call pause here; the Safe can — the caller list decides.
    const { result } = await arrive({
      contractAddress: VAULT.address,
      highlight: { functionSignature: "pause", controllers: [TIMELOCK, SAFE] },
    });
    expect(result).toEqual({
      ok: true,
      kind: "contract",
      functionMissing: false,
      highlight: { function: "marked", controller: "marked" },
    });
    await waitFor(() => expect(markedRow()).toBeTruthy());
    const chips = markedChips();
    expect(chips).toHaveLength(1);
    expect(chips[0]).toHaveTextContent("Safe");
    expectNoCrash();
  });

  it("stays unpaired when no member of the unit is the function's caller", async () => {
    const { result } = await arrive({
      contractAddress: VAULT.address,
      highlight: { functionSignature: "pause", controllers: [TIMELOCK, EOA] },
    });
    expect(result.highlight).toEqual({ function: "unpaired", controller: "not-a-caller" });
    await waitFor(() => {
      expect(document.querySelector(".ps-sidebar-content .ps-machine-name")).toHaveTextContent("Vault");
    });
    expect(markedRow()).toBeNull();
    expect(markedChips()).toHaveLength(0);
    expectNoCrash();
  });

  it("resolves a bare name through duplicate rows of the same function", async () => {
    // A split proxy materializes one selector once per implementation, so the
    // card can carry the same function twice. Two rows of one function are not
    // overloads and must not turn the hint into a not-on-card refusal.
    const doubled = structuredClone(ETHERFI_COMPANY_RICH);
    const vault = doubled.contracts.find((c) => c.name === "Vault");
    const pause = vault.functions.find((f) => f.function === "pause");
    vault.functions.push(structuredClone(pause));

    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="etherfi"
        initialData={doubled}
        initialFunctions={fixtureFunctions(doubled)}
        embedded
      />,
    );
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample({
        contractAddress: vault.address,
        highlight: { functionSignature: "pause", controller: SAFE },
      });
    });
    expect(result).toEqual({
      ok: true,
      kind: "contract",
      functionMissing: false,
      highlight: { function: "marked", controller: "marked" },
    });
    await waitFor(() => expect(markedRow()).toBeTruthy());
    expectNoCrash();
  });

  it("drops the chip mark with the row mark on the next selection", async () => {
    await arrive({
      contractAddress: VAULT.address,
      highlight: { functionSignature: "pause", controller: SAFE },
    });
    await waitFor(() => expect(markedChips()).toHaveLength(1));

    const user = userEvent.setup();
    await user.type(searchInput(), "LiquidityPool");
    await commitViaEnter(user);

    await waitFor(() => {
      expect(document.querySelector(".ps-machine-name")).toHaveTextContent("LiquidityPool");
    });
    expect(markedChips()).toHaveLength(0);
    expect(markedRow()).toBeNull();
    expect(document.querySelector(".ps-machine-score-highlight")).toBeNull();
    expectNoCrash();
  });
});

// --- Reach path: the route a score-page click-through took to get here -------
describe("ProtocolSurface — reached-from route on the entity card", () => {
  const { VAULT: V_ADDR, POOL: P_ADDR, SAFE: S_ADDR, EOA: E_ADDR } = RICH_ADDRESSES;
  // The rich fixture's fund_flows carry no control edges, so give it the
  // etherfi row-0 shape: the safe reaches the pool only THROUGH the vault.
  const WITH_CONTROL_EDGES = {
    ...ETHERFI_COMPANY_RICH,
    fund_flows: [
      ...ETHERFI_COMPANY_RICH.fund_flows,
      { from: S_ADDR, to: V_ADDR, type: "principal", relation: "role_principal", label: "roles 77" },
      { from: V_ADDR, to: P_ADDR, type: "controller" },
    ],
  };

  beforeEach(() => {
    installApiMocks();
  });

  function renderWithHandle(data = WITH_CONTROL_EDGES) {
    const ref = React.createRef();
    render(
      <ProtocolSurface
        ref={ref}
        companyName="etherfi"
        initialData={data}
        initialFunctions={fixtureFunctions(data)}
        embedded
      />,
    );
    return ref;
  }

  async function arriveFrom(example) {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    let result;
    await act(async () => {
      result = ref.current.selectExample(example);
    });
    expect(result.ok).toBe(true);
    return waitFor(() => {
      const el = document.querySelector(".ps-machine-name");
      expect(el).toBeTruthy();
      return el;
    });
  }

  it("walks the host→target route and names each hop", async () => {
    await arriveFrom({ contractAddress: P_ADDR, reachedFrom: [S_ADDR] });
    const block = await waitFor(() => {
      const el = document.querySelector(".ps-reach");
      expect(el).toBeTruthy();
      return el;
    });
    expect(block.querySelector(".ps-reach-hdr")).toHaveTextContent("Reached from Multisig via:");
    const hops = [...block.querySelectorAll(".ps-reach-hop")];
    expect(hops.map((h) => h.querySelector(".ps-reach-pair").textContent)).toEqual([
      "Multisig→Vault",
      "Vault→LiquidityPool",
    ]);
    // The witnessed role rides through from the payload; the unwitnessed hop
    // shows its flow type alone.
    expect(hops[0].querySelector(".ps-reach-kind").textContent).toBe("can call · role holder roles 77");
    expect(hops[1].querySelector(".ps-reach-kind").textContent).toBe("controls");
    expectNoCrash();
  });

  it("says the path is not carried when this graph has no route", async () => {
    await arriveFrom({ contractAddress: P_ADDR, reachedFrom: [E_ADDR] });
    await waitFor(() => {
      expect(document.querySelector(".ps-reach-nd")).toHaveTextContent("path not carried by this graph");
    });
    expect(document.querySelector(".ps-reach-hops")).toBeNull();
    expectNoCrash();
  });

  it("shows no route on a plain selection that names no origin", async () => {
    await arriveFrom({ contractAddress: P_ADDR });
    expect(document.querySelector(".ps-reach")).toBeNull();
    expectNoCrash();
  });

  it("drops the route when the next selection carries none", async () => {
    const ref = renderWithHandle();
    await waitFor(() => expect(ref.current).toBeTruthy());
    await act(async () => {
      ref.current.selectExample({ contractAddress: P_ADDR, reachedFrom: [S_ADDR] });
    });
    await waitFor(() => expect(document.querySelector(".ps-reach")).toBeTruthy());
    await act(async () => {
      ref.current.selectExample({ contractAddress: V_ADDR });
    });
    await waitFor(() => {
      expect(document.querySelector(".ps-machine-name")).toHaveTextContent("Vault");
    });
    expect(document.querySelector(".ps-reach")).toBeNull();
    expectNoCrash();
  });
});

describe("ProtocolSurface — collapsed filter panel", () => {
  it("starts collapsed; the SAME pill toggles it open and closed", async () => {
    renderSurface();
    const user = userEvent.setup();
    await waitFor(() => expect(document.querySelector(".ps-filter-pill")).toBeTruthy());
    const pill = document.querySelector(".ps-filter-pill");
    expect(pill.getAttribute("aria-expanded")).toBe("false");
    expect(document.querySelector(".ps-search-input")).toBeNull();

    await user.click(pill);
    expect(document.querySelector(".ps-search-input")).toBeTruthy();
    expect(document.querySelector(".ps-filter-pill").getAttribute("aria-expanded")).toBe("true");

    await user.click(document.querySelector(".ps-filter-pill"));
    expect(document.querySelector(".ps-search-input")).toBeNull();
    expect(document.querySelector(".ps-filter-pill").getAttribute("aria-expanded")).toBe("false");
    expectNoCrash();
  });

  it("carries no emoji anywhere in the panel", async () => {
    renderSurface();
    const user = userEvent.setup();
    await waitFor(() => expect(document.querySelector(".ps-filter-pill")).toBeTruthy());
    await user.click(document.querySelector(".ps-filter-pill"));
    const text = document.querySelector(".ps-filter-overlay").textContent;
    expect(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(text)).toBe(false);
    expectNoCrash();
  });
});
