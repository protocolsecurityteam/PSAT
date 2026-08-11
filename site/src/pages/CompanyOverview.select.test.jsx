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
const CONTROLLER = "0xf8553c8552f906c19286f21711721e206ee4909e";
// The row's single host — the contract the capability's function actually
// lives on, and NOT the first contract its reach lands on.
const HOST = "0x989468982b08aefa46e37cd0086142a86fa466d7";

// The row's example function is `setAuthority`, and its capability reaches
// TWELVE contracts. Two of them carry contract rows here, so "the page asked
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

// The row these cases need has ONE host and a wider reach set, so a target
// click has a route to carry. It is row 6 of the published ranking; the pin
// below fails loudly if the ranking moves it rather than silently testing some
// other row's shape.
const ROW = 6;

function firstRow() {
  return document.querySelectorAll(".sc-frow")[ROW];
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

  it("asks for the example function on the host the document publishes", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: "setAuthority" }));
    // host_entities names the function's own contract — the request selects it
    // directly instead of asking the graph to resolve the bare name.
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: HOST,
      functionSignature: "setAuthority",
      highlight: { functionSignature: "setAuthority", controller: CONTROLLER },
    });
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
    expect(scrollIntoView.mock.instances[0]).toBe(document.querySelector(".company-surface-band"));
  });

  it("asks for the controller's own node, with no function", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: /0xf855…909e/ }));
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: CONTROLLER,
      functionSignature: "",
    });
  });

  it("asks for a target contract, with no function, carrying the pair to mark", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    const targets = firstRow().querySelector(".sc-targets");
    await user.click(within(targets).getByRole("button", { name: /BoringVault/ }));
    // The contract is the request; the row's example function + controller
    // travel beside it as the hint, never as a second entity to resolve.
    expect(selectExample).toHaveBeenCalledWith({
      chain: "ethereum",
      contractAddress: FIRST_TARGET,
      functionSignature: "",
      highlight: { functionSignature: "setAuthority", controller: CONTROLLER },
      // A transitive target also names where the reach started, so the surface
      // can walk (and show) the route the deduction only implies.
      reachedFrom: [HOST],
    });
  });

  it("keeps the controller's own click free of a highlight hint", async () => {
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    await user.click(within(firstRow()).getByRole("button", { name: /0xf855…909e/ }));
    // The principal card is the whole answer to "who is this" — there is no
    // function row on it to pair with.
    expect(selectExample.mock.calls[0][0]).not.toHaveProperty("highlight");
  });

  it("says nothing when the card could not carry the hinted pair", async () => {
    // The hint is an extra, not the request: a click that landed on the
    // contract the user asked for is a clean landing even when nothing inside
    // it could be marked, and a notice would report a miss that did not happen.
    selectExample.mockReturnValue({
      ok: true,
      kind: "contract",
      functionMissing: false,
      highlight: { function: "not-on-card", controller: "not-a-caller" },
    });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    const targets = firstRow().querySelector(".sc-targets");
    await user.click(within(targets).getByRole("button", { name: /BoringVault/ }));
    expect(screen.queryByRole("status")).toBeNull();
    expect(scrollIntoView).toHaveBeenCalled();
  });

  it("explains an unpaired hint: same name on the card, someone else's gate", async () => {
    // Unlike an absent name, an unpaired one invites a wrong reading — the
    // card shows a setAuthority row and nothing marks it, which looks broken
    // unless the refusal is said out loud.
    selectExample.mockReturnValue({
      ok: true,
      kind: "contract",
      functionMissing: false,
      highlight: { function: "unpaired", controller: "not-a-caller" },
    });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    const targets = firstRow().querySelector(".sc-targets");
    await user.click(within(targets).getByRole("button", { name: /BoringVault/ }));
    expect(screen.getByRole("status")).toHaveTextContent(
      "setAuthority on this contract is gated by a different controller than the deduction names",
    );
    expect(scrollIntoView).toHaveBeenCalled();
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

  it("announces a chain switch when the surface re-scoped to reach the entity", async () => {
    selectExample.mockReturnValue({ ok: true, kind: "chain-switch", chain: "base" });
    const user = userEvent.setup();
    render(<CompanyOverview companyName="etherfi" onNavigateToSurface={() => {}} />);
    await openBreakdown(user);
    const targets = firstRow().querySelector(".sc-targets");
    await user.click(within(targets).getByRole("button", { name: /BoringVault/ }));
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(
      "Switched the control surface to Base — BoringVault is on that chain.",
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
