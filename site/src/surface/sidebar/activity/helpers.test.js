import { describe, expect, it } from "vitest";

import { contractTypeForMachine, proxyState } from "./helpers.js";

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

// `Boolean(is_proxy)` is a two-state read of a payload that carries two proxy
// signals which can disagree — and one real row does.
describe("proxyState — proxyhood is three-state", () => {
  it("answers proxy on the flag", () => {
    expect(proxyState({ is_proxy: true })).toBe("proxy");
  });

  it("answers not_proxy only when NO proxy signal is present", () => {
    // POSITIVE CONTROL for the hedge below: without this, every Safe and EOA in
    // the protocol would read as a maybe-proxy.
    expect(proxyState({ is_proxy: false })).toBe("not_proxy");
    expect(proxyState({})).toBe("not_proxy");
    expect(proxyState(undefined)).toBe("not_proxy");
  });

  it("answers not_determined when the two signals contradict each other", () => {
    // The real row: 0x3c55986c… is_proxy=false, proxy_type='beacon', 14
    // `Upgraded(address)` logs at or before block 25619159.
    expect(proxyState({ is_proxy: false, proxy_type: "beacon" })).toBe("not_determined");
    expect(proxyState({ is_proxy: false, implementation: "0xabc" })).toBe("not_determined");
  });
});
