import React from "react";
import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";

import { SearchNavigator } from "./SearchNavigator.jsx";

const preview = (machines, principals, mode) =>
  render(<SearchNavigator machines={machines} principals={principals} mode={mode} onPreview={vi.fn()} onCommit={vi.fn()} />)
    .container.querySelector(".ps-search-preview");

describe("SearchNavigator — Safe threshold", () => {
  it("shows a missing threshold as not determined, never owners/owners", () => {
    const el = preview([], [{ address: "0xs", type: "safe", label: "s", controls: [], details: { owners: ["0xa", "0xb", "0xc"] } }], "safe");
    expect(el).toHaveTextContent("3 signers · threshold not determined");
    expect(el).not.toHaveTextContent("3/3");
  });

  it("shows a published threshold over its owners", () => {
    const el = preview([], [{ address: "0xs", type: "safe", label: "s", controls: [], details: { owners: ["0xa", "0xb", "0xc"], threshold: 2 } }], "safe");
    expect(el).toHaveTextContent("2/3 signers");
  });
});

describe("SearchNavigator — USD lower bound", () => {
  it("renders a value summed over unvalued holdings as a lower bound", () => {
    const m = { address: "0xa", name: "A", total_usd: 2_500_000, holdings_coverage: { unvalued_rows: 1 }, totalFunctions: 1 };
    expect(preview([m], [], "contracts")).toHaveTextContent("≥ $2.5M");
    const exact = { ...m, holdings_coverage: { unvalued_rows: 0 } };
    expect(preview([exact], [], "contracts").textContent).not.toContain("≥");
  });
});
