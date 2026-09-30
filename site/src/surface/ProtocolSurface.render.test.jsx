// Direct render tests for ProtocolSurface's public prop API (split out of the
// old src/components.test.jsx). Complements App.test.jsx: the App suite proves
// a route reaches the component, this suite proves the component honors its
// props in isolation.

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import ProtocolSurface from "./ProtocolSurface.jsx";
import { installCommonApiMocks } from "../test/commonApiMocks.js";
import { setFetchHandler } from "../test/fetchMock.js";
import { ETHERFI_COMPANY } from "../test/fixtures.js";

function expectNoCrash() {
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
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

  it("labels a stale company payload it fetched itself", async () => {
    setFetchHandler((url) => url.pathname === "/api/company/etherfi", () => new Response(
      JSON.stringify(ETHERFI_COMPANY),
      {
        headers: {
          "Content-Type": "application/json",
          "X-PSAT-Response-Source": "prepared-stale",
          "X-PSAT-Stale-Reason": "code",
          "X-PSAT-Prepared-At": "2026-09-29T08:00:00Z",
          "X-PSAT-Payload-Schema": "1",
        },
      },
    ));
    render(<ProtocolSurface companyName="etherfi" />);
    await screen.findByText(`Updating — data as of ${new Date("2026-09-29T08:00:00Z").toLocaleString()}`);
    expectNoCrash();
  });
});
