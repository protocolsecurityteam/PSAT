// Selecting a principal must claim authority ONLY over contracts it can
// actually act on. A grouped_with machinery contract lives inside the box
// because of what IT operates (operand-unit placement), not because the box
// owner controls it — so the principal click leaves it unchipped and dimmed.

import React from "react";
import { render, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { SurfaceCanvas } from "./SurfaceCanvas.jsx";

const captured = { nodes: null };

vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    ReactFlow: (props) => {
      captured.nodes = props.nodes;
      return <div className="react-flow" />;
    },
  };
});

const EOA = "0x" + "1a".repeat(20); // selected principal
const OWNED = "0x" + "2b".repeat(20); // in EOA's primary_for
const PLACED = "0x" + "3c".repeat(20); // grouped_with EOA's box, no authority
const OUTSIDE = "0x" + "4d".repeat(20); // unrelated

function machine(address, name, extra = {}) {
  return { address, name, is_proxy: false, totalFunctions: 2, total_usd: 0, functions: [], ...extra };
}

const MACHINES = [
  machine(OWNED, "Solver"),
  machine(PLACED, "AtomicQueue", { grouped_with: EOA }),
  machine(OUTSIDE, "Unrelated"),
];

const PRINCIPALS = [
  {
    address: EOA,
    type: "eoa",
    primary_for: [OWNED],
    controls: [OWNED],
    co_controls: [],
    controls_detail: [{ address: OWNED, chain: "ethereum", functions: ["solve"], capabilities: [] }],
  },
];

function nodeFor(addr) {
  return (captured.nodes || []).find((n) => n.id?.toLowerCase() === addr.toLowerCase());
}

describe("SurfaceCanvas — principal selection claims only real authority", () => {
  beforeEach(() => {
    captured.nodes = null;
  });

  it("chips the owned child but leaves a placement-only (grouped_with) member unchipped and dimmed", async () => {
    render(
      <SurfaceCanvas
        machines={MACHINES}
        fundFlows={[]}
        principals={PRINCIPALS}
        chain="ethereum"
        selectedAddress={EOA}
        onSelectMachine={() => {}}
        onSelectPrincipal={() => {}}
      />,
    );
    await waitFor(() => expect(nodeFor(OWNED)).toBeTruthy());

    const owned = nodeFor(OWNED);
    expect(owned.data.selectionChip?.out).toBeTruthy();
    expect(owned.style?.opacity).not.toBe(0.2);

    // Both live in the EOA's box…
    const placed = nodeFor(PLACED);
    expect(placed.parentId?.toLowerCase()).toBe(EOA.toLowerCase());
    expect(owned.parentId?.toLowerCase()).toBe(EOA.toLowerCase());
    // …but the placement-only member gets no authority claim: no chip, dimmed
    // exactly like the unrelated node.
    expect(placed.data.selectionChip).toBeNull();
    expect(placed.style?.opacity).toBe(0.2);
    expect(nodeFor(OUTSIDE).style?.opacity).toBe(0.2);
  });
});
