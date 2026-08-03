import { describe, it, expect } from "vitest";

import { findFunctionMatches, findFunctionView } from "./lane.js";

function machineWith(fns, address = "0xabc") {
  return { address, lanes: { top: fns, ops: [], left: [], right: [] } };
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

describe("findFunctionMatches — graph-wide resolution of a bare name", () => {
  // The scorer names an example function by bare name and publishes no host
  // contract for it, so these matches are the ONLY witness to where the name
  // lives on this graph.
  const OTHER_SWEEP = { key: "0xdef:0x5b116ab8", name: "sweepETH", signature: "sweepETH(address,uint256)" };
  const MINT = { key: "0xdef:0x33333333", name: "mint", signature: "mint(address,uint256)" };

  it("finds the one machine a name lives on", () => {
    const machines = [machineWith([PAUSE, SWEEP]), machineWith([MINT], "0xdef")];
    const matches = findFunctionMatches(machines, { functionSignature: "mint" });
    expect(matches).toHaveLength(1);
    expect(matches[0].machine.address).toBe("0xdef");
    expect(matches[0].fnView).toBe(MINT);
  });

  it("returns every host when two machines answer to the same name", () => {
    const machines = [machineWith([PAUSE, SWEEP]), machineWith([OTHER_SWEEP], "0xdef")];
    const matches = findFunctionMatches(machines, { functionSignature: "sweepETH" });
    expect(matches.map((m) => m.machine.address)).toEqual(["0xabc", "0xdef"]);
  });

  it("returns every overload on one machine, so a caller can refuse it too", () => {
    const matches = findFunctionMatches([machineWith([PAUSE, PAUSE_NO_ARGS])], {
      functionSignature: "pause",
    });
    expect(matches).toHaveLength(2);
    expect(new Set(matches.map((m) => m.machine.address)).size).toBe(1);
  });

  it("returns nothing for a name no machine carries, and for an empty target", () => {
    const machines = [machineWith([PAUSE, SWEEP]), machineWith([MINT], "0xdef")];
    expect(findFunctionMatches(machines, { functionSignature: "burn" })).toEqual([]);
    expect(findFunctionMatches(machines, {})).toEqual([]);
    expect(findFunctionMatches(null, { functionSignature: "mint" })).toEqual([]);
  });

  it("lets an exact signature shadow bare-name matches elsewhere", () => {
    // A caller that knows the signature has already resolved the ambiguity a
    // bare name would raise; it must not be dragged back into one.
    const machines = [machineWith([PAUSE, PAUSE_NO_ARGS]), machineWith([MINT], "0xdef")];
    const matches = findFunctionMatches(machines, { functionSignature: "pause(bool)" });
    expect(matches).toHaveLength(1);
    expect(matches[0].fnView).toBe(PAUSE);
  });
});
