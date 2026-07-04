import React from "react";
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";

import PermissionsTab from "./PermissionsTab.jsx";

function detailWith(fn) {
  return { effective_permissions: { functions: [fn] } };
}

describe("PermissionsTab claim chip", () => {
  it("renders claim sentences + provenance tier when the function carries claims", () => {
    const { getByText } = render(
      <PermissionsTab
        detail={detailWith({
          selector: "0x11111111",
          function: "transferOwnership(address)",
          effect_labels: ["hook_update"],
          claims: [{ claim_id: "ownership.transfer", tier: "standard_exact", witness: {} }],
          action_summary: "changes owner",
        })}
      />,
    );
    expect(getByText("changes owner · standard")).toBeInTheDocument();
  });

  it("falls back to the legacy effect_labels join for claim-less rows", () => {
    const { getByText } = render(
      <PermissionsTab
        detail={detailWith({
          selector: "0x22222222",
          function: "pause()",
          effect_labels: ["pause_toggle"],
          action_summary: "pause control",
        })}
      />,
    );
    expect(getByText("pause_toggle")).toBeInTheDocument();
  });
});
