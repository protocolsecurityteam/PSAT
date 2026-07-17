import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@testing-library/react";

import { ChainSwitcher } from "./ChainSwitcher.jsx";

describe("ChainSwitcher", () => {
  it("renders nothing for a single-chain protocol (unobtrusive)", () => {
    const { container } = render(
      <ChainSwitcher chains={[{ name: "ethereum", count: 12 }]} active="ethereum" onSelect={() => {}} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when there are no chains", () => {
    const { container } = render(<ChainSwitcher chains={[]} active={undefined} onSelect={() => {}} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders one pill per chain with counts for a multi-chain protocol", () => {
    const { getByText } = render(
      <ChainSwitcher
        chains={[
          { name: "ethereum", count: 24 },
          { name: "base", count: 6 },
        ]}
        active="ethereum"
        onSelect={() => {}}
      />,
    );
    expect(getByText("Ethereum")).toBeTruthy();
    expect(getByText("Base")).toBeTruthy();
    expect(getByText("24")).toBeTruthy();
    expect(getByText("6")).toBeTruthy();
  });

  it("marks the active chain pressed and fires onSelect for another", () => {
    const onSelect = vi.fn();
    const { getByText } = render(
      <ChainSwitcher
        chains={[
          { name: "ethereum", count: 24 },
          { name: "base", count: 6 },
        ]}
        active="ethereum"
        onSelect={onSelect}
      />,
    );
    const eth = getByText("Ethereum").closest("button");
    const base = getByText("Base").closest("button");
    expect(eth.getAttribute("aria-pressed")).toBe("true");
    expect(base.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(base);
    expect(onSelect).toHaveBeenCalledWith("base");
  });
});
