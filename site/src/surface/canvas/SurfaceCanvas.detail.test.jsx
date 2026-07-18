import { describe, expect, it } from "vitest";

import { buildControlsDetailMap } from "./SurfaceCanvas.jsx";
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
