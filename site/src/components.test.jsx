// Direct render tests for the default-exported page components in
// site/src/*.jsx. Each test renders the component in isolation with
// minimal-but-realistic props and asserts a stable landmark.
//
// These complement App.test.jsx: the App suite proves a route reaches
// the right component, this suite proves the component honors its
// public prop API. Together they catch (a) routing bugs, (b)
// prop-shape regressions, (c) closures or imports that broke during
// the upcoming file split.

import React, { Suspense } from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

import ProtocolSurface from "./ProtocolSurface.jsx";
import AddressesModal from "./AddressesModal.jsx";
import AuditsAdminModal from "./AuditsAdminModal.jsx";
import AddressLabelInline from "./AddressLabelInline.jsx";
import ProductHero from "./ProductHero.jsx";
import ProtocolLogo from "./ProtocolLogo.jsx";

import { setFetchHandler } from "./test/fetchMock.js";
import {
  ETHERFI_COMPANY,
  COVERAGE_FIXTURE,
  ADDRESS_LABELS,
} from "./test/fixtures.js";

function expectNoCrash() {
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
}

function installCommonApiMocks() {
  setFetchHandler(/^\/api\/address_labels$/, () => ADDRESS_LABELS);
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+$/.test(url.pathname),
    () => ETHERFI_COMPANY,
  );
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+\/audit_coverage$/.test(url.pathname),
    () => COVERAGE_FIXTURE,
  );
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+\/audits$/.test(url.pathname),
    () => ({ audit_count: 0, audits: [] }),
  );
  setFetchHandler(
    (url) => /^\/api\/contracts\/[^/]+\/audit_timeline$/.test(url.pathname),
    () => ({ current_status: "unknown", coverage: [] }),
  );
  setFetchHandler(/^\/api\/audits\/.*\/scope$/, () => ({ contracts: [] }));
  setFetchHandler(/^\/api\/audits\/.*\/text$/, () => "");
  setFetchHandler(/^\/api\/audits\/[0-9]+$/, () => ({ id: 1 }));
  setFetchHandler(/^\/api\/audits\/pipeline$/, () => ({ groups: [], recent_completed: [] }));
}

describe("ProtocolSurface", () => {
  beforeEach(() => {
    installCommonApiMocks();
  });

  it("renders embedded with initialData without firing /api/company", async () => {
    render(
      <ProtocolSurface
        companyName="etherfi"
        initialData={ETHERFI_COMPANY}
        embedded
      />,
    );
    await waitFor(() => {
      // .ps-surface is the outer wrapper; .react-flow is React Flow's
      // injected canvas. Either proves the component finished mounting.
      expect(document.querySelector(".ps-surface, .react-flow")).toBeInTheDocument();
    });
    expectNoCrash();
  });

  it("renders fullscreen at companyName without initialData", async () => {
    render(<ProtocolSurface companyName="etherfi" />);
    await waitFor(() => {
      // Loading state ("Loading surface...") or rendered state both
      // indicate the component is running and the route is correct.
      const text = document.body.textContent || "";
      const ready =
        document.querySelector(".ps-surface, .react-flow") ||
        /Loading surface/i.test(text);
      expect(ready).toBeTruthy();
    });
    expectNoCrash();
  });
});

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

describe("AuditsAdminModal", () => {
  beforeEach(() => {
    installCommonApiMocks();
  });

  it("renders for a company with onClose callback", async () => {
    render(<AuditsAdminModal companyName="etherfi" onClose={() => {}} />);
    await waitFor(() => {
      expect(document.body.textContent).toBeTruthy();
    });
    expectNoCrash();
  });
});

describe("AddressLabelInline", () => {
  it("renders an unlabeled address", () => {
    render(
      <AddressLabelInline
        address="0x1111111111111111111111111111111111111111"
        labels={new Map()}
        refreshAll={() => {}}
      />,
    );
    expectNoCrash();
  });

  it("renders a labeled address", () => {
    const labels = new Map([["0x1111111111111111111111111111111111111111", "Treasury"]]);
    render(
      <AddressLabelInline
        address="0x1111111111111111111111111111111111111111"
        labels={labels}
        refreshAll={() => {}}
      />,
    );
    expect(screen.getByText("Treasury")).toBeInTheDocument();
  });

  it("prefers a chain-qualified label over the global one (invariant 12)", () => {
    const addr = "0x1111111111111111111111111111111111111111";
    const maps = {
      global: new Map([[addr, "Global Name"]]),
      byChain: new Map([["base", new Map([[addr, "Base Name"]])]]),
    };
    render(
      <AddressLabelInline address={addr} labels={maps} chain="base" refreshAll={() => {}} />,
    );
    expect(screen.getByText("Base Name")).toBeInTheDocument();
    expect(screen.queryByText("Global Name")).not.toBeInTheDocument();
  });
});

describe("ProductHero", () => {
  it("renders the hero title", () => {
    render(<ProductHero />);
    expect(screen.getByText(/Detect every/i)).toBeInTheDocument();
    expectNoCrash();
  });
});

describe("ProtocolLogo", () => {
  it("renders with a name", () => {
    render(<ProtocolLogo name="etherfi" />);
    expectNoCrash();
  });
});
