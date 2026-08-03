import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { REACH_TIERS, SelectionLegend, buildControlsDetailMap, reachTier } from "./SurfaceCanvas.jsx";
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


describe("reachTier — hop distance → wash intensity", () => {
  it("gives the directly-connected node no wash of its own", () => {
    // Hop 1 already wears the stronger acts-on treatment; washing it too would
    // erase the one-hop / transitive distinction the overlay exists to draw.
    expect(reachTier(1)).toBe(0);
  });

  it("fades with distance, one tier per hop", () => {
    expect(reachTier(2)).toBe(2);
    expect(reachTier(3)).toBe(3);
    expect(reachTier(4)).toBe(4);
  });

  it("caps far hops at the faintest tier rather than dropping them", () => {
    expect(reachTier(5)).toBe(REACH_TIERS);
    expect(reachTier(40)).toBe(REACH_TIERS);
  });

  it("treats a non-reached node as no tier", () => {
    expect(reachTier(0)).toBe(0);
    expect(reachTier(undefined)).toBe(0);
  });
});

describe("SelectionLegend", () => {
  it("names the reach wash when the selection has transitive reach", () => {
    const { container } = render(<SelectionLegend onClear={() => {}} hasReach />);
    expect(screen.getByText("reachable through the control graph")).toBeInTheDocument();
    expect(container.querySelector(".ps-selection-legend-swatch--reach")).not.toBeNull();
  });

  it("omits the reach row when nothing on the canvas is washed", () => {
    const { container } = render(<SelectionLegend onClear={() => {}} />);
    expect(screen.queryByText("reachable through the control graph")).toBeNull();
    expect(container.querySelector(".ps-selection-legend-swatch--reach")).toBeNull();
    // The two direction rows are untouched.
    expect(screen.getByText("selected acts on this contract")).toBeInTheDocument();
    expect(screen.getByText("this contract acts on selected")).toBeInTheDocument();
  });
});
