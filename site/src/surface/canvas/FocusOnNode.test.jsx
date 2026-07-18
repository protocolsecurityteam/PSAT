import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, act } from "@testing-library/react";

const fitBounds = vi.fn();
const CHECKSUM_ID = "0x04C0599Ae5A44757c0af6F9eC3b93da8976c150A";

// A grouped card: the PUBLIC node only knows its group-relative position; the
// absolute position lives on the internal-node representation, keyed by the
// node's exact (checksummed) id.
const publicNode = {
  id: CHECKSUM_ID,
  parentId: "0xgroup",
  position: { x: 40, y: 60 },
  measured: { width: 220, height: 120 },
};
const internalNode = {
  internals: { positionAbsolute: { x: 5000, y: 300 } },
  measured: { width: 220, height: 120 },
};

vi.mock("@xyflow/react", () => ({
  useReactFlow: () => ({
    fitBounds,
    getInternalNode: (id) => (id === CHECKSUM_ID ? internalNode : undefined),
    getNodes: () => [publicNode],
  }),
  useStoreApi: () => ({ getState: () => ({ width: 1200, height: 800 }) }),
}));

import { FocusOnNode } from "./FocusOnNode.jsx";

describe("FocusOnNode — case-insensitive absolute positioning", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    fitBounds.mockClear();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("focuses a checksummed-id node at its ABSOLUTE position from a lowercase address", () => {
    render(<FocusOnNode address={CHECKSUM_ID.toLowerCase()} focusKey={1} principals={[]} />);
    act(() => {
      vi.advanceTimersByTime(150);
    });
    expect(fitBounds).toHaveBeenCalledTimes(1);
    const bounds = fitBounds.mock.calls[0][0];
    // Camera centers on the absolute x=5000, not the group-relative x=40.
    expect(bounds.x + bounds.width / 2).toBeCloseTo(5000 + 110);
    expect(bounds.y + bounds.height / 2).toBeCloseTo(300 + 60);
  });
});
