import { describe, it, expect } from "vitest";

import { findFunctionView } from "./lane.js";

function machineWith(fns) {
  return { lanes: { top: fns, ops: [], left: [], right: [] } };
}

const PAUSE = { key: "0xabc:0x11111111", name: "pause", signature: "pause(bool)" };
const PAUSE_NO_ARGS = { key: "0xabc:0x22222222", name: "pause", signature: "pause()" };
const SWEEP = { key: "0xabc:0x5b116ab8", name: "sweepETH", signature: "sweepETH(address,uint256)" };

describe("findFunctionView", () => {
  it("matches a full signature and a selector", () => {
    const machine = machineWith([PAUSE, SWEEP]);
    expect(findFunctionView(machine, { functionSignature: "sweepETH(address,uint256)" })).toBe(SWEEP);
    expect(findFunctionView(machine, { selector: "0x5b116ab8" })).toBe(SWEEP);
  });

  it("resolves a bare function name — what the scorer's example functions carry", () => {
    expect(findFunctionView(machineWith([PAUSE, SWEEP]), { functionSignature: "sweepETH" })).toBe(SWEEP);
  });

  it("refuses a bare name that two overloads answer to", () => {
    // Selecting one of them would point at a call site the caller never named.
    expect(findFunctionView(machineWith([PAUSE, PAUSE_NO_ARGS]), { functionSignature: "pause" })).toBeNull();
  });

  it("returns null for an unknown name and for an empty target", () => {
    const machine = machineWith([PAUSE, SWEEP]);
    expect(findFunctionView(machine, { functionSignature: "mint" })).toBeNull();
    expect(findFunctionView(machine, {})).toBeNull();
  });
});
