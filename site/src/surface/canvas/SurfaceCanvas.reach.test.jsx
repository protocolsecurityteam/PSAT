// Reach-route edge highlighting on the canvas. The reach overlay chips every
// transitively-reached contract with its hop count; these tests cover the lines
// that make those counts checkable — the drawn edges along the BFS-tree routes
// from the selection to each chipped node.
//
// ReactFlow itself is stubbed out (jsdom measures nothing, so it draws no edge
// paths); everything up to it — elkLayout, the aggregation, the selection pass —
// is the real code, and we assert on the edge list handed to it.

import React from "react";
import { render, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { SurfaceCanvas, edgeOnReachPath } from "./SurfaceCanvas.jsx";

const captured = { edges: null, nodes: null };

vi.mock("@xyflow/react", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    ReactFlow: (props) => {
      captured.edges = props.edges;
      captured.nodes = props.nodes;
      return <div className="react-flow" />;
    },
  };
});

const A = "0x" + "a1".repeat(20); // selected
const B = "0x" + "b2".repeat(20); // hop 1
const C = "0x" + "c3".repeat(20); // hop 2
const D = "0x" + "d4".repeat(20); // frontier destination / off the walk
const E = "0x" + "e5".repeat(20); // off the walk

const REACH_VIOLET = "#a78bfa";
const RESTING_GREY = "#94a3b8";

function machine(address, name) {
  return { address, name, is_proxy: false, totalFunctions: 3, total_usd: 0, functions: [] };
}

const MACHINES = [
  machine(A, "AtomicQueue"),
  machine(B, "Solver"),
  machine(C, "Vault"),
  machine(D, "Unrelated"),
  machine(E, "AlsoUnrelated"),
];

// A→B→C is the spine; C→D is the refused continuation; D→E shares nothing
// with the walk.
const FLOWS = [
  { from: A, to: B, type: "controls" },
  { from: B, to: C, type: "controls" },
  { from: C, to: D, type: "controls" },
  { from: D, to: E, type: "controls" },
];

const REACH_DISTANCES = new Map([
  [B.toLowerCase(), 1],
  [C.toLowerCase(), 2],
]);
const PATH_EDGES = new Set([
  `${A.toLowerCase()}>${B.toLowerCase()}`,
  `${B.toLowerCase()}>${C.toLowerCase()}`,
]);

function renderCanvas(props) {
  return render(
    <SurfaceCanvas
      machines={MACHINES}
      fundFlows={FLOWS}
      principals={[]}
      chain="ethereum"
      onSelectMachine={() => {}}
      onSelectPrincipal={() => {}}
      {...props}
    />,
  );
}

// The drawn edge for a contract pair, whatever id the layout gave it.
function edgeFor(from, to) {
  return (captured.edges || []).find(
    (e) =>
      e.source?.toLowerCase() === from.toLowerCase() &&
      e.target?.toLowerCase() === to.toLowerCase(),
  );
}

function nodeFor(addr) {
  return (captured.nodes || []).find((n) => n.id?.toLowerCase() === addr.toLowerCase());
}

async function settle() {
  await waitFor(() => expect(edgeFor(B, C)).toBeTruthy());
}

describe("SurfaceCanvas — reach-route edges", () => {
  beforeEach(() => {
    captured.edges = null;
    captured.nodes = null;
  });

  it("paints an in-between hop violet and leaves an unrelated edge grey + dimmed", async () => {
    renderCanvas({
      selectedAddress: A,
      reachDistances: REACH_DISTANCES,
      reachPathEdges: PATH_EDGES,
    });
    await settle();

    // Hop 2 of the route: the segment the "reach · 2 hops" chip is claiming.
    const hop = edgeFor(B, C);
    expect(hop.style.stroke).toBe(REACH_VIOLET);
    expect(hop.style.strokeWidth).toBeGreaterThanOrEqual(2.5);
    expect(hop.style.opacity).toBe(1);

    // Touches nothing on the route — stays resting grey and dimmed out.
    const other = edgeFor(D, E);
    expect(other.style.stroke).toBe(RESTING_GREY);
    expect(other.style.opacity).toBe(0.08);
  });

  it("leaves the directly-connected hop-1 edge on its existing selection styling", async () => {
    renderCanvas({
      selectedAddress: A,
      reachDistances: REACH_DISTANCES,
      reachPathEdges: PATH_EDGES,
    });
    await settle();

    // The acts-on chips already state this relationship concretely; restyling it
    // violet would demote the stronger claim to the weaker one.
    const direct = edgeFor(A, B);
    expect(direct.style.stroke).toBe(RESTING_GREY);
    expect(direct.style.strokeWidth).toBe(2);
    expect(direct.style.opacity).toBe(1);
  });

  it("drops the route styling on deselect, exactly when the chips drop", async () => {
    const { rerender } = renderCanvas({
      selectedAddress: A,
      reachDistances: REACH_DISTANCES,
      reachPathEdges: PATH_EDGES,
    });
    await settle();
    expect(edgeFor(B, C).style.stroke).toBe(REACH_VIOLET);

    rerender(
      <SurfaceCanvas
        machines={MACHINES}
        fundFlows={FLOWS}
        principals={[]}
        chain="ethereum"
        onSelectMachine={() => {}}
        onSelectPrincipal={() => {}}
        selectedAddress={null}
        reachDistances={null}
        reachPathEdges={null}
      />,
    );

    await waitFor(() => expect(edgeFor(B, C).style.stroke).toBe(RESTING_GREY));
    const cleared = edgeFor(B, C);
    expect(cleared.style.strokeWidth).toBe(1);
    expect(cleared.style.opacity).toBe(1);
    // No node wears a reach chip — walked or unconfirmed — any more either.
    expect((captured.nodes || []).every((n) => !n.data.reachChip && !n.data.reachNdChip)).toBe(true);
  });

  it("suppresses the route styling under an audit/agent highlight overlay", async () => {
    // That set answers a different question and already owns the dim.
    renderCanvas({
      selectedAddress: A,
      reachDistances: REACH_DISTANCES,
      reachPathEdges: PATH_EDGES,
      highlightedAddresses: new Set([A.toLowerCase(), D.toLowerCase()]),
    });
    await settle();
    expect(edgeFor(B, C).style.stroke).toBe(RESTING_GREY);
  });
});

describe("SurfaceCanvas — not_determined frontier is not drawn (owner ruling 2026-08-12)", () => {
  beforeEach(() => {
    captured.edges = null;
    captured.nodes = null;
  });

  it("renders a frontier destination exactly like an unreached node — dim, no chip, grey edge", async () => {
    // The canvas shows proven reach only; the unknowns' home is the score
    // page's confidence zone and the Governs tab's count line. D (the refused
    // hop's destination) must be indistinguishable from E (never named).
    renderCanvas({
      selectedAddress: A,
      reachDistances: REACH_DISTANCES,
      reachPathEdges: PATH_EDGES,
    });
    await settle();

    for (const addr of [D, E]) {
      const node = nodeFor(addr);
      expect(node.data.reachChip).toBeNull();
      expect(node.data.reachNdChip).toBeUndefined();
      expect(node.style.opacity).toBe(0.2);
    }
    const walked = nodeFor(C);
    expect(walked.data.reachChip).toBe("reach · 2 hops");
    expect(walked.style.opacity).toBeUndefined();

    const refused = edgeFor(C, D);
    expect(refused.style.stroke).toBe(RESTING_GREY);
    expect(refused.style.strokeDasharray).toBeUndefined();
    expect(refused.style.opacity).toBe(0.08);
  });
});

describe("edgeOnReachPath", () => {
  const pair = (from, to) => `${from.toLowerCase()}>${to.toLowerCase()}`;
  const pathEdges = new Set([pair(B, C)]);

  it("matches a plain edge on its own endpoints", () => {
    expect(edgeOnReachPath({ source: B, target: C }, pathEdges)).toBe(true);
    expect(edgeOnReachPath({ source: C, target: B }, pathEdges)).toBe(false);
  });

  it("matches an aggregated bundle when ANY sample is a route pair", () => {
    // Cross-group bundles terminate at group boxes; only data.samples says what
    // they actually carry — the same rule that decides connection chips.
    const bundle = {
      source: D,
      target: E,
      data: { samples: [{ from: A, to: E }, { from: B, to: C }] },
    };
    expect(edgeOnReachPath(bundle, pathEdges)).toBe(true);
  });

  it("leaves a bundle carrying nothing on the route alone", () => {
    const bundle = { source: D, target: E, data: { samples: [{ from: A, to: E }] } };
    expect(edgeOnReachPath(bundle, pathEdges)).toBe(false);
  });

  it("is false without a path set", () => {
    expect(edgeOnReachPath({ source: B, target: C }, null)).toBe(false);
    expect(edgeOnReachPath({ source: B, target: C }, new Set())).toBe(false);
  });
});
