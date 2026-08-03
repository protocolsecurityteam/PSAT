import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SelectionLegend, buildControlsDetailMap, reachChipText } from "./SurfaceCanvas.jsx";
import { entityKey } from "../entityKey.js";

const ADDR = "0x" + "ab".repeat(20);

describe("buildControlsDetailMap — controls_detail chain keying (inv. 13)", () => {
  it("keys twin rows by their own chain so the active chain's row wins", () => {
    const rows = [
      { address: ADDR, chain: "base", functions: ["pauseOnBase"] },
      { address: ADDR, chain: "ethereum", functions: ["pauseOnEth"] },
    ];
    const map = buildControlsDetailMap(rows, "base");
    expect(map.get(entityKey("base", ADDR)).functions).toEqual(["pauseOnBase"]);
    expect(map.get(entityKey("ethereum", ADDR)).functions).toEqual(["pauseOnEth"]);
  });

  it("keys a chain-less legacy row to the active chain", () => {
    const rows = [{ address: ADDR, functions: ["pause"] }];
    const map = buildControlsDetailMap(rows, "base");
    expect(map.get(entityKey("base", ADDR)).functions).toEqual(["pause"]);
  });

  it("tolerates null/short rows", () => {
    expect(buildControlsDetailMap(null, "ethereum").size).toBe(0);
    expect(buildControlsDetailMap([{}, { address: "" }], "ethereum").size).toBe(0);
  });
});


describe("reachChipText — hop distance → chip label", () => {
  it("gives the directly-connected node no reach chip of its own", () => {
    // Hop 1 already wears the acts-on chip naming the concrete capability;
    // a reach chip beside it would restate the relationship, more weakly.
    expect(reachChipText(1)).toBeNull();
  });

  it("names the exact hop count at every distance", () => {
    expect(reachChipText(2)).toBe("reach · 2 hops");
    expect(reachChipText(3)).toBe("reach · 3 hops");
    expect(reachChipText(4)).toBe("reach · 4 hops");
    // Far hops keep counting rather than collapsing into a capped tier.
    expect(reachChipText(9)).toBe("reach · 9 hops");
  });

  it("treats a non-reached node as no chip", () => {
    expect(reachChipText(0)).toBeNull();
    expect(reachChipText(undefined)).toBeNull();
  });
});

describe("SelectionLegend", () => {
  it("names the reach chip when the selection has transitive reach", () => {
    const { container } = render(<SelectionLegend onClear={() => {}} hasReach />);
    expect(screen.getByText("selected reaches this contract")).toBeInTheDocument();
    expect(container.querySelector(".ps-selection-legend-swatch--reach")).not.toBeNull();
  });

  it("omits the reach row when nothing on the canvas is chipped", () => {
    const { container } = render(<SelectionLegend onClear={() => {}} />);
    expect(screen.queryByText("selected reaches this contract")).toBeNull();
    expect(container.querySelector(".ps-selection-legend-swatch--reach")).toBeNull();
    // The two direction rows are untouched.
    expect(screen.getByText("selected acts on this contract")).toBeInTheDocument();
    expect(screen.getByText("this contract acts on selected")).toBeInTheDocument();
  });
});
