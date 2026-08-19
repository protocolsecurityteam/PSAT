// Direct render test for AuditsAdminModal's public prop API (split out of the
// old src/components.test.jsx). Link-safety behavior is covered separately in
// auditLinkSafety.test.jsx.

import React from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import AuditsAdminModal from "./AuditsAdminModal.jsx";
import { installCommonApiMocks } from "../test/commonApiMocks.js";

function expectNoCrash() {
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
}

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
