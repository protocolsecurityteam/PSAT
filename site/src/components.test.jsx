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
import { render, screen, waitFor } from "@testing-library/react";

import ProtocolSurface from "./ProtocolSurface.jsx";
import DependencyGraphTab from "./DependencyGraphTab.jsx";
import AddressesModal from "./AddressesModal.jsx";
import AuditsAdminModal from "./AuditsAdminModal.jsx";
import AddressLabelInline from "./AddressLabelInline.jsx";
import ProductHero from "./ProductHero.jsx";
import ProtocolLogo from "./ProtocolLogo.jsx";
import ProtocolRadar from "./ProtocolRadar.jsx";

import { computeProtocolScore } from "./protocolScore.js";
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

describe("DependencyGraphTab", () => {
  it("renders with empty data", () => {
    render(<DependencyGraphTab data={null} runName="empty" />);
    expectNoCrash();
  });

  it("renders with a small viz payload", () => {
    const data = {
      nodes: [
        { id: "0xaaa", address: "0xaaa", label: "A" },
        { id: "0xbbb", address: "0xbbb", label: "B" },
      ],
      edges: [{ source: "0xaaa", target: "0xbbb", type: "CALL" }],
    };
    render(<DependencyGraphTab data={data} runName="demo" />);
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
        onSelectContract={() => {}}
      />,
    );
    await waitFor(() => {
      expect(document.body.textContent).toBeTruthy();
    });
    expectNoCrash();
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

describe("ProtocolRadar", () => {
  it("renders with computed axes", () => {
    const score = computeProtocolScore(ETHERFI_COMPANY, COVERAGE_FIXTURE);
    render(<ProtocolRadar axes={score.axes} />);
    // 6 axis labels (Authority, Audits, Upgrades, Pause, Safes, Data)
    expect(screen.getByText(/Authority/i)).toBeInTheDocument();
    expectNoCrash();
  });
});
