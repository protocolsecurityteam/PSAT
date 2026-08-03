// Clicking an entity on the score band drives the embedded surface's own
// selection handle and brings the surface into view. The surface is mocked
// down to that handle: what is under test is the wiring (which entity is
// asked for, that the band scrolls, that a miss is reported), not the
// surface's internal selection transition.

import React from "react";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CompanyOverview from "./CompanyOverview.jsx";
import { setFetchHandler } from "../test/fetchMock.js";
import SCORE_ETHERFI from "../test/fixtures/score_etherfi.json";

const { selectExample } = vi.hoisted(() => ({ selectExample: vi.fn() }));

vi.mock("../ProtocolSurface.jsx", () => ({
  default: React.forwardRef(function MockSurface(props, ref) {
    React.useImperativeHandle(ref, () => ({ selectExample }), []);
    return <div data-testid="mock-surface" />;
  }),
}));

const FIRST_TARGET = "0x352180974c71f84a934953cf49c4e538a6f9c997";
const CONTROLLER = "0x2322ba43eff1542b6a7baed35e66099ea0d12bd1";

function installMocks() {
  setFetchHandler(
    (url) => url.pathname === "/api/company/etherfi",
    () => ({
      protocol_id: 1,
      contracts: [
        {
          address: FIRST_TARGET,
          chain: "ethereum",
          name: "BoringVault",
          role: "value_handler",
          is_proxy: false,
          functions: [],
        },
      ],
      principals: [],
      fund_flows: [],
      ownership_hierarchy: [],
    }),
  );
  setFetchHandler((url) => url.pathname === "/api/company/etherfi/audit_coverage", () => ({
    audit_count: 64,
    coverage: [],
  }));
  setFetchHandler((url) => url.pathname === "/api/company/etherfi/functions", () => ({ functions: {} }));
  setFetchHandler((url) => url.pathname === "/api/company/etherfi/score", () => SCORE_ETHERFI);
}

async function openBreakdown(user) {
  await screen.findByTestId("mock-surface");
  await user.click(await screen.findByRole("button", { name: /Full score breakdown/i }));
}

function firstRow() {
  return document.querySelector(".sc-frow");
}

describe("CompanyOverview — score entities select on the embedded surface", () => {
  let scrollIntoView;

  beforeEach(() => {
    installMocks();
    selectExample.mockReset();
    selectExample.mockReturnValue(true);
    scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
  });

  it("asks the surface for the contract a function was witnessed on, then scrolls to it", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: FIRST_TARGET,
      functionSignature: "setAuthority",
    });
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
    expect(scrollIntoView.mock.instances[0]).toBe(document.querySelector(".company-surface-band"));
  });

  it("asks for the controller's own node, with no function", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: /0x2322…2bd1/ }));
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: CONTROLLER,
      functionSignature: "",
    });
  });

  it("asks for a target contract, with no function", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    const targets = firstRow().querySelector(".sc-targets");
    await user.click(within(targets).getByRole("button", { name: /BoringVault/ }));
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: FIRST_TARGET,
      functionSignature: "",
    });
  });

  it("reports an entity the graph does not carry instead of scrolling to nothing", async () => {
    selectExample.mockReturnValue(false);
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "setAuthority is not on the control surface.",
    );
    expect(scrollIntoView).not.toHaveBeenCalled();
  });
});
