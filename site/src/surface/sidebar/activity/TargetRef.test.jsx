import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TargetRef } from "./TargetRef.jsx";

const ADDR = "0x0d05f2465c45a1e0f9dbd7d51c3f2b3ce7778198";

describe("TargetRef", () => {
  it("clicking the name previews — it never commits", () => {
    const onPreview = vi.fn();
    const onNavigate = vi.fn();
    render(
      <TargetRef
        target={{ address: ADDR, label: "Accountant", prep: "on", onGraph: true }}
        onPreview={onPreview}
        onNavigate={onNavigate}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Accountant" }));
    expect(onPreview).toHaveBeenCalledWith(ADDR);
    expect(onNavigate).not.toHaveBeenCalled();
  });

  it("the → arrow is the commit path", () => {
    const onPreview = vi.fn();
    const onNavigate = vi.fn();
    render(
      <TargetRef
        target={{ address: ADDR, label: "Accountant", prep: "on", onGraph: true }}
        onPreview={onPreview}
        onNavigate={onNavigate}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Go to Accountant" }));
    expect(onNavigate).toHaveBeenCalledWith({ type: "contract", address: ADDR, label: "Accountant" });
    expect(onPreview).not.toHaveBeenCalled();
  });

  it("an off-graph target states the gap with its FULL address and offers no selection", () => {
    render(
      <TargetRef
        target={{ address: ADDR, label: null, prep: "on", onGraph: false }}
        onPreview={vi.fn()}
        onNavigate={vi.fn()}
      />,
    );
    expect(screen.getByText(ADDR)).toBeInTheDocument();
    expect(screen.getByText(/not on this protocol's graph/)).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("an unresolved target with no resolver claims nothing about the graph", () => {
    render(<TargetRef target={{ address: ADDR, label: null, prep: "on", onGraph: null }} />);
    expect(screen.getByText(ADDR)).toBeInTheDocument();
    expect(screen.queryByText(/not on this protocol's graph/)).toBeNull();
  });
});
