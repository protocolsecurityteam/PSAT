// Clicking an entity on the score band drives the embedded surface's own
// selection handle and brings the surface into view. The surface is mocked
// down to that handle: what is under test is the wiring (which entity is
// asked for, that the band scrolls, and that each way the surface can refuse
// is reported as the fact it is), not the surface's internal transition.

import React from "react";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, within, act, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CompanyOverview from "./CompanyOverview.jsx";
import { setFetchHandler } from "../test/fetchMock.js";
import SCORE_ETHERFI from "../test/fixtures/score_etherfi.json";

const { selectExample, mountSurface } = vi.hoisted(() => ({
  selectExample: vi.fn(),
  mountSurface: { current: true },
}));

vi.mock("../ProtocolSurface.jsx", () => ({
  default: React.forwardRef(function MockSurface(props, ref) {
    // The real surface is a lazy chunk; `mountSurface` lets a test render the
    // band with no handle attached yet, which is the loading race.
    React.useImperativeHandle(ref, () => (mountSurface.current ? { selectExample } : null), []);
    return <div data-testid="mock-surface" />;
  }),
}));

const FIRST_TARGET = "0x352180974c71f84a934953cf49c4e538a6f9c997";
const SECOND_TARGET = "0x917cee801a67f933f2e6b33fc0cd1ed2d5909d88";
const CONTROLLER = "0x2322ba43eff1542b6a7baed35e66099ea0d12bd1";

// Row 0's example function is `setAuthority`, and its capability reaches
// SEVEN contracts. Two of them carry contract rows here, so "the page asked
// for the first reached contract as the function's host" is a distinguishable
// wrong answer rather than the only answer the fixture can express.
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
        {
          address: SECOND_TARGET,
          chain: "ethereum",
          name: "OtherReachedContract",
          role: "utility",
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
    mountSurface.current = true;
    selectExample.mockReset();
    selectExample.mockReturnValue({ ok: true, kind: "function" });
    scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
  });

  it("asks for the example function by name and lets the graph find its host", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    // No contractAddress: the score document publishes no host for the
    // function, and the first reached contract is not one.
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: "",
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
    selectExample.mockReturnValue({ ok: false, kind: "not-found" });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "setAuthority is not on the control surface.",
    );
    expect(scrollIntoView).not.toHaveBeenCalled();
  });

  it("says a name several contracts answer to is ambiguous, and does not navigate", async () => {
    selectExample.mockReturnValue({ ok: false, kind: "ambiguous-function", count: 3, hosts: 3 });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "setAuthority is on 3 contracts here — select a contract first, then the function.",
    );
    expect(scrollIntoView).not.toHaveBeenCalled();
  });

  it("tells overloads on one contract apart from a name on several", async () => {
    selectExample.mockReturnValue({ ok: false, kind: "ambiguous-function", count: 2, hosts: 1 });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "setAuthority has 2 overloads on its contract — open the contract and pick one.",
    );
  });

  it("tells another chain's entity apart from an absent one", async () => {
    selectExample.mockReturnValue({ ok: false, kind: "chain-mismatch" });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    const targets = firstRow().querySelector(".sc-targets");
    await user.click(within(targets).getByRole("button", { name: /BoringVault/ }));
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(
      "BoringVault is on another chain; the control surface shows one chain at a time.",
    );
    expect(status.textContent).not.toContain("not on the control surface");
  });

  it("says so when the contract landed but its named function did not", async () => {
    selectExample.mockReturnValue({ ok: true, kind: "contract", functionMissing: true });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "setAuthority is not among that contract's functions on the surface — the contract is selected instead.",
    );
    // A partial landing is still a landing: the user is taken there.
    expect(scrollIntoView).toHaveBeenCalled();
  });

  it("tells a surface that has not mounted yet apart from one that said no", async () => {
    mountSurface.current = false;
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "The control surface is still loading — try that again in a moment.",
    );
    // Nothing was asked of a surface that could not answer, and nothing was
    // claimed about whether the entity is on it.
    expect(selectExample).not.toHaveBeenCalled();
    expect(screen.getByRole("status").textContent).not.toContain("not on the control surface");
  });
});

describe("CompanyOverview — a repeated miss re-shows and re-announces", () => {
  beforeEach(() => {
    installMocks();
    mountSurface.current = true;
    selectExample.mockReset();
    selectExample.mockReturnValue({ ok: false, kind: "not-found" });
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("restarts the dismiss timer and replaces the announced node on an identical miss", async () => {
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    // The page's own fetches settle on real timers; only the notice lifetime
    // is put under fake ones.
    await openBreakdown(userEvent.setup());
    const button = within(firstRow()).getByRole("button", { name: "setAuthority" });

    vi.useFakeTimers();
    fireEvent.click(button);
    const first = screen.getByRole("status").firstElementChild;
    expect(first).toHaveTextContent("setAuthority is not on the control surface.");

    // Just before the first notice would be dismissed, click the same entity
    // again. The message is character-identical — the retrigger must not depend
    // on the string changing.
    await act(async () => { await vi.advanceTimersByTimeAsync(3900); });
    fireEvent.click(button);
    const second = screen.getByRole("status").firstElementChild;
    expect(second).not.toBe(first);
    expect(second).toHaveTextContent("setAuthority is not on the control surface.");

    // The old timer must not carry over and kill the new notice.
    await act(async () => { await vi.advanceTimersByTimeAsync(200); });
    expect(screen.getByRole("status")).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(4000); });
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
