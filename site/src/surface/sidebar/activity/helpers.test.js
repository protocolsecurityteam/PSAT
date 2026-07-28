import { describe, expect, it } from "vitest";

import { contractTypeForMachine } from "./helpers.js";

// The three states of `is_pausable`, kept apart at the badge. The pair that
// matters is the last two: before this split a null and a proven `false` both
// produced "regular", so a contract nobody had classified was badged as
// classified-and-plain.
describe("contractTypeForMachine — the pause flag is three-state", () => {
  it("badges a PROVEN pausable contract pausable", () => {
    expect(contractTypeForMachine({ is_pausable: true })).toBe("pausable");
  });

  it("badges a PROVEN non-pausable plain contract regular", () => {
    // POSITIVE CONTROL for the hedge below: hedging on every falsy flag would
    // erase the case where "regular" is the answer the analysis produced.
    expect(contractTypeForMachine({ is_pausable: false })).toBe("regular");
  });

  it("badges a NOT-DETERMINED pause flag unclassified, not regular", () => {
    expect(contractTypeForMachine({ is_pausable: null })).toBe("unclassified");
  });

  it("treats an absent pause key (a pre-fix payload) as not determined", () => {
    expect(contractTypeForMachine({})).toBe("unclassified");
    expect(contractTypeForMachine(undefined)).toBe("unclassified");
  });

  it("keeps every positive signal ahead of the hedge", () => {
    // A null pause flag must not out-rank a fact: proxyhood, an observed pause
    // capability, and a governance role are all determined answers.
    expect(contractTypeForMachine({ is_proxy: true, is_pausable: null })).toBe("proxy");
    expect(contractTypeForMachine({ is_pausable: null, capabilities: ["pause"] })).toBe("pausable");
    expect(contractTypeForMachine({ is_pausable: null, role: "governance" })).toBe("governance");
  });
});
