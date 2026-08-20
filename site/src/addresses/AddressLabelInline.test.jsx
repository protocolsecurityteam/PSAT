// Direct render tests for AddressLabelInline's public prop API (split out of
// the old src/components.test.jsx).

import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import AddressLabelInline from "./AddressLabelInline.jsx";

function expectNoCrash() {
  expect(screen.queryByText(/Something went wrong/i)).not.toBeInTheDocument();
}

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
