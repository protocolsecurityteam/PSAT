import { describe, expect, it } from "vitest";

import {
  contractTypeForMachine,
  eventTypesFromGroupKeys,
  groupKeysFromConfig,
  proxyState,
} from "./helpers.js";

// The event types the `signers` group carried before `safe_exec` was split out
// of it — pinned literally, so the split is measured against what a Safe
// actually subscribed to rather than against the current table.
const PRE_SPLIT_SIGNERS_TYPES = [
  "signer_added",
  "signer_removed",
  "threshold_changed",
  "safe_tx_executed",
  "safe_tx_failed",
  "safe_module_executed",
  "safe_module_failed",
];

describe("safe_exec split out of the signers group", () => {
  it("offers both groups on the flag that gates both", () => {
    // `_should_watch` gates owners/threshold AND _safe_op/_safe_module_op on
    // `watch_safe_signers`, so the split withdraws nothing a Safe is watched for.
    expect(groupKeysFromConfig({ watch_safe_signers: true })).toEqual(["signers", "safe_exec"]);
    expect(groupKeysFromConfig({ watch_signers: true })).toEqual(["signers", "safe_exec"]);
  });

  it("subscribes a Safe to exactly what it subscribed to before the split", () => {
    // Invariant 7, the force-subscribe direction: a webhook attached today gets
    // the same set as one attached before the split — no type added, none lost.
    const derived = eventTypesFromGroupKeys(groupKeysFromConfig({ watch_safe_signers: true }));
    expect(new Set(derived)).toEqual(new Set(PRE_SPLIT_SIGNERS_TYPES));
  });

  it("lets each group be asked for on its own", () => {
    // The point of the split: "tell me when the owner set changes" no longer
    // means "tell me about every transaction this Safe runs".
    expect(eventTypesFromGroupKeys(["signers"])).toEqual([
      "signer_added",
      "signer_removed",
      "threshold_changed",
    ]);
    expect(eventTypesFromGroupKeys(["safe_exec"])).toEqual([
      "safe_tx_executed",
      "safe_tx_failed",
      "safe_module_executed",
      "safe_module_failed",
    ]);
  });
});

describe("the state-polling group is offered on a witness contracts carry", () => {
  it("offers it to a contract with a polling plan", () => {
    const keys = groupKeysFromConfig({ polling_plan: [{ kind: "getter_call", field: "isPaused" }] });
    expect(keys).toContain("state");
    expect(eventTypesFromGroupKeys(keys)).toContain("state_changed_poll");
  });

  it("does not offer it on an empty plan", () => {
    // `[]` is enrollment's witnessed "the plan was read and named nothing" —
    // there is no polled field to hear about. (`Boolean([])` is `true`, so this
    // is the case a truthiness check would get wrong.)
    expect(groupKeysFromConfig({ polling_plan: [] })).not.toContain("state");
  });

  it("does not offer it on a config that says nothing about polling", () => {
    // POSITIVE CONTROL: the group must stay unofferable where it is unearned,
    // or it would appear on every contract and the fix would be a default.
    expect(groupKeysFromConfig({ watch_ownership: true })).not.toContain("state");
    expect(groupKeysFromConfig({ polling_plan: "yes" })).not.toContain("state");
    expect(groupKeysFromConfig({})).not.toContain("state");
  });

  it("still honours the flag itself where a config carries it", () => {
    expect(groupKeysFromConfig({ watch_state: true })).toContain("state");
  });

  it("offers nothing else on a plan alone", () => {
    // A polling plan is a witness about polling and nothing more.
    expect(groupKeysFromConfig({ polling_plan: [{ kind: "storage_slot" }] })).toEqual(["state"]);
  });
});

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
