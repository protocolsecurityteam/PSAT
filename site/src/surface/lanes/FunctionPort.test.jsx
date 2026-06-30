// Render + interaction tests for FunctionPort: one button per direct caller,
// the no-caller status pill, and the navigate/select click wiring.

import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@testing-library/react";

import { FunctionPort } from "./FunctionPort.jsx";

function caller({ address, resolvedType, name, kind = resolvedType, sub = null, accent = "#6a9e94", label = null, details = {} }) {
  return {
    address,
    resolvedType,
    label,
    details,
    display: { kind, name, sub, accent },
  };
}

function fnViewWith(principals, extra = {}) {
  return {
    name: "pause",
    action: "pause control",
    tone: "#998a6a",
    guard: { kind: "many", label: "MULTI", sublabel: "mixed", accent: "#8a80a0", principals },
    ...extra,
  };
}

describe("FunctionPort", () => {
  it("renders one .ps-caller-btn per caller with the right names", () => {
    const principals = [
      caller({ address: "0xaaa", resolvedType: "safe", name: "Safe", sub: "2/3" }),
      caller({ address: "0xbbb", resolvedType: "timelock", name: "Timelock", sub: "2d" }),
    ];
    const { container, getByText } = render(
      <FunctionPort fnView={fnViewWith(principals)} onSelect={vi.fn()} onNavigate={vi.fn()} orientation="top" />,
    );
    expect(container.querySelectorAll(".ps-caller-btn")).toHaveLength(2);
    expect(getByText("Safe")).toBeInTheDocument();
    expect(getByText("Timelock")).toBeInTheDocument();
    expect(container.querySelector(".ps-callers-label")).toHaveTextContent("callable by");
  });

  it("renders exactly one .ps-caller-btn and no 'callable by' label for a single caller", () => {
    const principals = [caller({ address: "0xaaa", resolvedType: "eoa", name: "EOA", sub: "0xaaa..aaaa" })];
    const { container } = render(
      <FunctionPort fnView={fnViewWith(principals)} onSelect={vi.fn()} onNavigate={vi.fn()} orientation="ops" />,
    );
    expect(container.querySelectorAll(".ps-caller-btn")).toHaveLength(1);
    expect(container.querySelector(".ps-callers-label")).toBeNull();
  });

  it("renders a .ps-caller-status pill (no .ps-caller-btn) when guard.principals is empty", () => {
    const fnView = {
      name: "recover",
      action: "",
      tone: "#64748b",
      guard: { kind: "resolved_empty", label: "NONE", sublabel: "no active principal", accent: "#64748b", principals: [] },
    };
    const { container, getByText } = render(
      <FunctionPort fnView={fnView} onSelect={vi.fn()} onNavigate={vi.fn()} orientation="top" />,
    );
    expect(container.querySelector(".ps-caller-status")).toBeInTheDocument();
    expect(container.querySelectorAll(".ps-caller-btn")).toHaveLength(0);
    expect(getByText("NONE")).toBeInTheDocument();
  });

  it("calls onNavigate with the caller's {type,address,...} when a caller button is clicked", () => {
    const onNavigate = vi.fn();
    const principals = [
      caller({ address: "0xaaa", resolvedType: "safe", name: "Safe", sub: "2/3", label: "Treasury" }),
      caller({ address: "0xbbb", resolvedType: "timelock", name: "Timelock", sub: "2d" }),
    ];
    const { container } = render(
      <FunctionPort fnView={fnViewWith(principals)} onSelect={vi.fn()} onNavigate={onNavigate} orientation="top" />,
    );
    fireEvent.click(container.querySelectorAll(".ps-caller-btn")[1]);
    expect(onNavigate).toHaveBeenCalledTimes(1);
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({ type: "timelock", address: "0xbbb" }),
    );
  });

  it("calls onSelect when the .ps-port-copy region is clicked", () => {
    const onSelect = vi.fn();
    const fnView = fnViewWith([caller({ address: "0xaaa", resolvedType: "safe", name: "Safe", sub: "2/3" })]);
    const { container } = render(
      <FunctionPort fnView={fnView} onSelect={onSelect} onNavigate={vi.fn()} orientation="top" />,
    );
    fireEvent.click(container.querySelector(".ps-port-copy"));
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith(fnView);
  });
});
