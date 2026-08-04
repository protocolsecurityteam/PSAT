import { describe, it, expect } from "vitest";
import { decodeEvent, eventKind, eventKindLabel, eventSalience, eventSeverity, salienceAllows } from "./format.js";
import { shortenAddress } from "../graph.js";

const ADDR_A = "0x1111111111111111111111111111111111111111";
const ADDR_B = "0x2222222222222222222222222222222222222222";
const ZERO = "0x0000000000000000000000000000000000000000";

function evt(event_type, data) {
  return { event_type, data };
}

// ---------------------------------------------------------------------------
// decodeEvent — one assertion per old switch case so regressions in the
// tag-driven dispatch surface as a single failing assertion per case.
// ---------------------------------------------------------------------------

describe("decodeEvent — ownership", () => {
  it("renders ownership_transferred with arrow sub", () => {
    const result = decodeEvent(
      evt("ownership_transferred", {
        old_owner: ADDR_A,
        new_owner: ADDR_B,
        effect_tags: { writes: ["owner"] },
      }),
    );
    expect(result.title).toBe("Ownership transferred");
    expect(result.sub).toContain("→");
  });

  it("renders renounced ownership when new_owner is zero address", () => {
    const result = decodeEvent(
      evt("ownership_transferred", {
        old_owner: ADDR_A,
        new_owner: ZERO,
        effect_tags: { writes: ["owner"] },
      }),
    );
    expect(result.title).toBe("Ownership renounced");
  });

  it("renders ownership_transfer_started via pendingOwner write", () => {
    const result = decodeEvent(
      evt("ownership_transfer_started", {
        old_owner: ADDR_A,
        new_owner: ADDR_B,
        effect_tags: { writes: ["pendingOwner"] },
      }),
    );
    expect(result.title).toBe("Ownership transfer initiated");
  });

  it("renders authority_updated", () => {
    const result = decodeEvent(
      evt("authority_updated", {
        old_authority: ADDR_A,
        new_authority: ADDR_B,
        effect_tags: { writes: ["authority"] },
      }),
    );
    expect(result.title).toBe("Authority updated");
    expect(result.sub).toContain("→");
  });
});

describe("decodeEvent — pause", () => {
  it("renders paused with account", () => {
    const result = decodeEvent(
      evt("paused", { account: ADDR_A, effect_tags: { writes: ["paused"] } }),
    );
    expect(result.title).toBe("Contract paused");
    expect(result.sub).toContain("paused by");
  });

  it("renders unpaused with account — same writes but different verb", () => {
    const result = decodeEvent(
      evt("unpaused", { account: ADDR_A, effect_tags: { writes: ["paused"] } }),
    );
    expect(result.title).toBe("Contract unpaused");
    expect(result.sub).toContain("unpaused by");
  });
});

describe("decodeEvent — upgrades", () => {
  it("renders upgraded", () => {
    const result = decodeEvent(
      evt("upgraded", {
        implementation: ADDR_A,
        effect_tags: { writes: ["implementation"], delegates: true },
      }),
    );
    expect(result.title).toBe("Implementation upgraded");
    expect(result.sub).toContain("→");
  });

  it("renders new_implementation as the same title (shared write target)", () => {
    const result = decodeEvent(
      evt("new_implementation", {
        implementation: ADDR_A,
        effect_tags: { writes: ["implementation"], delegates: true },
      }),
    );
    expect(result.title).toBe("Implementation upgraded");
  });

  it("renders target_updated and upgraded_revision as upgrades", () => {
    for (const type of ["target_updated", "upgraded_revision"]) {
      const result = decodeEvent(
        evt(type, {
          implementation: ADDR_A,
          effect_tags: { writes: ["implementation"], delegates: true },
        }),
      );
      expect(result.title).toBe("Implementation upgraded");
    }
  });

  it("renders new_pending_implementation distinctly via pendingImplementation write", () => {
    const result = decodeEvent(
      evt("new_pending_implementation", {
        implementation: ADDR_A,
        effect_tags: { writes: ["pendingImplementation"] },
      }),
    );
    expect(result.title).toBe("Pending implementation queued");
  });

  it("renders changed_master_copy via title override", () => {
    const result = decodeEvent(
      evt("changed_master_copy", {
        implementation: ADDR_A,
        effect_tags: { writes: ["implementation"], delegates: true },
      }),
    );
    expect(result.title).toBe("Safe singleton (mastercopy) swapped");
  });

  it("renders admin_changed", () => {
    const result = decodeEvent(
      evt("admin_changed", {
        previous_admin: ADDR_A,
        new_admin: ADDR_B,
        effect_tags: { writes: ["admin"] },
      }),
    );
    expect(result.title).toBe("Proxy admin changed");
    expect(result.sub).toContain("new admin");
  });

  it("renders beacon_upgraded", () => {
    const result = decodeEvent(
      evt("beacon_upgraded", {
        beacon: ADDR_A,
        effect_tags: { writes: ["beacon"], delegates: true },
      }),
    );
    expect(result.title).toBe("Beacon upgraded");
    expect(result.sub).toContain("beacon");
  });

  it("renders diamond_cut", () => {
    const result = decodeEvent(
      evt("diamond_cut", {
        facets: [ADDR_A],
        effect_tags: { writes: ["facets"], delegates: true },
      }),
    );
    expect(result.title).toBe("Diamond cut (facets changed)");
    expect(result.sub).toBeNull();
  });
});

describe("decodeEvent — roles", () => {
  it("renders role_granted", () => {
    const result = decodeEvent(
      evt("role_granted", {
        account: ADDR_A,
        sender: ADDR_B,
        effect_tags: { writes: ["_roles"] },
      }),
    );
    expect(result.title).toBe("Role granted");
    expect(result.sub).toContain("to");
    expect(result.sub).toContain("by");
  });

  it("renders role_revoked", () => {
    const result = decodeEvent(
      evt("role_revoked", {
        account: ADDR_A,
        sender: ADDR_B,
        effect_tags: { writes: ["_roles"] },
      }),
    );
    expect(result.title).toBe("Role revoked");
    expect(result.sub).toContain("from");
  });
});

describe("decodeEvent — signers", () => {
  it("renders signer_added", () => {
    const result = decodeEvent(
      evt("signer_added", { owner: ADDR_A, effect_tags: { writes: ["owners"] } }),
    );
    expect(result.title).toBe("Safe signer added");
  });

  it("renders signer_removed", () => {
    const result = decodeEvent(
      evt("signer_removed", { owner: ADDR_A, effect_tags: { writes: ["owners"] } }),
    );
    expect(result.title).toBe("Safe signer removed");
  });

  it("renders threshold_changed", () => {
    const result = decodeEvent(
      evt("threshold_changed", { threshold: 3, effect_tags: { writes: ["threshold"] } }),
    );
    expect(result.title).toBe("Safe threshold changed");
    expect(result.sub).toContain("3");
  });
});

describe("decodeEvent — Safe activity", () => {
  it("renders safe_tx_executed with success verb", () => {
    const result = decodeEvent(
      evt("safe_tx_executed", {
        safe_tx_hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        payment: 0,
        effect_tags: { writes: ["_safe_op"] },
      }),
    );
    expect(result.title).toBe("Safe transaction executed");
  });

  it("renders safe_tx_failed with reverted verb — same writes", () => {
    const result = decodeEvent(
      evt("safe_tx_failed", {
        safe_tx_hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        effect_tags: { writes: ["_safe_op"] },
      }),
    );
    expect(result.title).toBe("Safe transaction reverted");
  });

  it("renders safe_module_executed", () => {
    const result = decodeEvent(
      evt("safe_module_executed", {
        module: ADDR_A,
        effect_tags: { writes: ["_safe_module_op"] },
      }),
    );
    expect(result.title).toBe("Safe module executed");
  });

  it("renders safe_module_failed with reverted verb", () => {
    const result = decodeEvent(
      evt("safe_module_failed", {
        module: ADDR_A,
        effect_tags: { writes: ["_safe_module_op"] },
      }),
    );
    expect(result.title).toBe("Safe module reverted");
  });
});

// ---------------------------------------------------------------------------
// The enriched Safe execution (§5c). The renderer reads what the backend
// decoded and NEVER re-derives it: a mirrored decode would drift, and a
// drifted mirror that renders the wrong call is worse than a bare hash.
// ---------------------------------------------------------------------------

describe("decodeEvent — enriched Safe executions", () => {
  const safeOp = (data) => decodeEvent(evt("safe_tx_executed", { effect_tags: { writes: ["_safe_op"] }, ...data }));

  it("names the resolved function, the target and the operation", () => {
    const result = safeOp({
      safe_exec: {
        status: "decoded",
        to: ADDR_A,
        selector: "0x69fe0e2d",
        operation: 0,
        operation_label: "call",
        target_function: { selector: "0x69fe0e2d", signature: "setFee(uint256)", source: "effective_functions" },
      },
    });
    expect(result.title).toBe("Safe executed setFee(uint256)");
    expect(result.sub).toBe(`${shortenAddress(ADDR_A)} · call`);
  });

  it("falls back to the raw selector when no signature resolved", () => {
    const result = safeOp({
      safe_exec: {
        status: "decoded",
        to: ADDR_A,
        selector: "0x8456cb59",
        operation: 0,
        operation_label: "call",
        target_function: { selector: "0x8456cb59", signature: null },
      },
    });
    expect(result.title).toBe("Safe executed 0x8456cb59");
  });

  it("summarizes a MultiSend batch from its first call", () => {
    const result = safeOp({
      safe_exec: {
        status: "decoded",
        to: ADDR_B,
        operation: 1,
        operation_label: "delegatecall",
        multisend_recognized: true,
        batch: [
          { operation: 0, operation_label: "call", to: ADDR_A, selector: "0x69fe0e2d", signature: "setFee(uint256)" },
          { operation: 0, operation_label: "call", to: ADDR_B, selector: "0x8456cb59", signature: null },
          { operation: 0, operation_label: "call", to: ADDR_B, selector: "0x8456cb59", signature: null },
        ],
      },
    });
    expect(result.title).toBe("Safe executed setFee(uint256)");
    expect(result.sub).toBe(`${shortenAddress(ADDR_A)} · call · +2 more in batch`);
  });

  it("says an undecodable batch did not decode rather than listing part of it", () => {
    const result = safeOp({
      safe_exec: {
        status: "decoded",
        to: ADDR_B,
        operation: 1,
        operation_label: "delegatecall",
        multisend_recognized: true,
        batch_status: "undecodable",
      },
    });
    expect(result.title).toBe("Safe executed a MultiSend batch that did not decode");
    expect(result.sub).toBe(`${shortenAddress(ADDR_B)} · delegatecall`);
  });

  it("renders an unrecognized delegatecall as the delegatecall it is", () => {
    const result = safeOp({
      safe_exec: {
        status: "decoded",
        to: ADDR_B,
        selector: "0x69fe0e2d",
        operation: 1,
        operation_label: "delegatecall",
        multisend_recognized: false,
        target_function: { selector: "0x69fe0e2d", signature: null },
      },
    });
    expect(result.title).toBe("Safe executed 0x69fe0e2d");
    expect(result.sub).toBe(`${shortenAddress(ADDR_B)} · delegatecall`);
  });

  it("renders each undecoded status as its own stated reason", () => {
    const cases = {
      not_top_level_call: "not a direct execTransaction",
      over_budget: "transaction budget",
      args_undecodable: "did not decode",
      something_new: "not decoded (something_new)",
    };
    for (const [status, fragment] of Object.entries(cases)) {
      const result = safeOp({ safe_tx_hash: "0x" + "ab".repeat(32), safe_exec: { status } });
      expect(result.title).toBe("Safe transaction executed");
      expect(result.sub).toContain(fragment);
    }
  });

  it("keeps the pre-enrichment rendering when no safe_exec block exists", () => {
    const result = safeOp({ safe_tx_hash: "0x" + "ab".repeat(32), payment: 0 });
    expect(result.title).toBe("Safe transaction executed");
    expect(result.sub).toContain("safeTxHash");
  });

  it("uses the reverted verb on a decoded failure", () => {
    const result = decodeEvent(
      evt("safe_tx_failed", {
        effect_tags: { writes: ["_safe_op"] },
        safe_exec: { status: "decoded", to: ADDR_A, selector: "0x69fe0e2d", operation: 0, operation_label: "call" },
      }),
    );
    expect(result.title).toBe("Safe execution reverted 0x69fe0e2d");
  });
});

describe("decodeEvent — timelock name resolution", () => {
  it("shows the backend-resolved signature in place of the raw selector", () => {
    const result = decodeEvent(
      evt("timelock_scheduled", {
        target: ADDR_A,
        selector: "0x69fe0e2d",
        delay: 86400,
        target_function: { selector: "0x69fe0e2d", signature: "setFee(uint256)", source: "effective_functions" },
        effect_tags: { writes: ["_timelock_op"] },
      }),
    );
    expect(result.sub).toContain("setFee(uint256)");
    expect(result.sub).not.toContain("sel 0x69fe0e2d");
  });

  it("keeps the raw selector when nothing resolved it", () => {
    const result = decodeEvent(
      evt("timelock_scheduled", {
        target: ADDR_A,
        selector: "0x69fe0e2d",
        target_function: { selector: "0x69fe0e2d", signature: null },
        effect_tags: { writes: ["_timelock_op"] },
      }),
    );
    expect(result.sub).toContain("sel 0x69fe0e2d");
  });
});

describe("decodeEvent — timelock", () => {
  it("renders timelock_scheduled with target, selector, delay", () => {
    const result = decodeEvent(
      evt("timelock_scheduled", {
        target: ADDR_A,
        selector: "0xdeadbeef",
        delay: 86400,
        effect_tags: { writes: ["_timelock_op"] },
      }),
    );
    expect(result.title).toBe("Timelock operation scheduled");
    expect(result.sub).toContain("target");
    expect(result.sub).toContain("sel");
    expect(result.sub).toContain("delay");
  });

  it("renders timelock_executed without delay", () => {
    const result = decodeEvent(
      evt("timelock_executed", {
        target: ADDR_A,
        selector: "0xdeadbeef",
        effect_tags: { writes: ["_timelock_op"] },
      }),
    );
    expect(result.title).toBe("Timelock operation executed");
    expect(result.sub).toContain("target");
    expect(result.sub).not.toContain("delay");
  });

  it("renders delay_changed with formatted seconds", () => {
    const result = decodeEvent(
      evt("delay_changed", {
        old_delay: 3600,
        new_delay: 7200,
        effect_tags: { writes: ["min_delay"] },
      }),
    );
    expect(result.title).toBe("Timelock delay changed");
    expect(result.sub).toContain("→");
  });
});

describe("decodeEvent — state poll", () => {
  it("renders state_changed_poll as a synthetic event (no tags)", () => {
    const result = decodeEvent(
      evt("state_changed_poll", { field: "owner", old: ADDR_A, new: ADDR_B }),
    );
    expect(result.title).toBe("owner changed (polled)");
    expect(result.sub).toContain("→");
  });

  it("compacts wei-scale integers and appends the relative delta", () => {
    // The poller's real shape: old_value/new_value, unbounded uint256 strings.
    // No decimals are known, so no unit is assumed — scientific notation plus
    // a delta derivable from the pair alone.
    const result = decodeEvent(
      evt("state_changed_poll", {
        field: "_totalSupply",
        old_value: "91887099948048325164605122",
        new_value: "91953892477145219780348471",
      }),
    );
    expect(result.sub).toBe("9.1887e25 → 9.1953e25 (+0.072%)");
  });

  it("leaves small numeric values verbatim with no delta", () => {
    const result = decodeEvent(
      evt("state_changed_poll", { field: "threshold", old_value: "2", new_value: "3" }),
    );
    expect(result.sub).toBe("2 → 3");
  });

  it("marks a change too small for three decimals as sub-threshold, not zero", () => {
    const result = decodeEvent(
      evt("state_changed_poll", {
        field: "_totalSupply",
        old_value: "1000000000000000000000000000",
        new_value: "1000000000000000000000000001",
      }),
    );
    expect(result.sub).toContain("(+<0.001%)");
  });

  it("shortens polled address values like the verified renderer does", () => {
    const result = decodeEvent(
      evt("state_changed_poll", { field: "owner", old: ADDR_A, new: ADDR_B }),
    );
    expect(result.sub.length).toBeLessThan(ADDR_A.length + ADDR_B.length);
  });
});

describe("decodeEvent — value_changed numeric compaction", () => {
  it("compacts a verified wei-scale diff the same way", () => {
    const result = decodeEvent(
      evt("value_changed:state_variable:cap", {
        old: "5000000000000000000000000",
        new: "6000000000000000000000000",
      }),
    );
    expect(result.title).toBe("cap changed (verified)");
    expect(result.sub).toBe("5.0000e24 → 6.0000e24 (+20.000%)");
  });
});

// ---------------------------------------------------------------------------
// Tag-driven fallback paths
// ---------------------------------------------------------------------------

describe("decodeEvent — fallback paths", () => {
  it("renders legacy event with no effect_tags via synthesis fallback", () => {
    // Hand-rolled event from before tag synthesis landed — no
    // effect_tags in data, but event_type is canonical so synthesis
    // map produces writes=["owner"].
    const result = decodeEvent(
      evt("ownership_transferred", { old_owner: ADDR_A, new_owner: ADDR_B }),
    );
    expect(result.title).toBe("Ownership transferred");
  });

  it("falls back to humanized event_type for completely unknown events", () => {
    const result = decodeEvent(
      evt("totally_unknown_event_type", { some_arg: "value" }),
    );
    expect(result.title).toBe("totally unknown event type");
    expect(result.sub).toContain("some_arg");
  });

  it("excludes effect_tags from the fallback sub render", () => {
    const result = decodeEvent(
      evt("unknown_with_tags", {
        some_arg: "value",
        effect_tags: { writes: ["unknown_target"] },
      }),
    );
    // effect_tags shouldn't leak into the prose subtitle.
    expect(result.sub).not.toContain("effect_tags");
  });
});

// ---------------------------------------------------------------------------
// eventKind — tag-driven kind classification
// ---------------------------------------------------------------------------

describe("eventKind", () => {
  it("classifies by tag write target", () => {
    expect(eventKind({ event_type: "ownership_transferred", data: { effect_tags: { writes: ["owner"] } } })).toBe("owner");
    expect(eventKind({ event_type: "upgraded", data: { effect_tags: { writes: ["implementation"] } } })).toBe("upgrade");
    expect(eventKind({ event_type: "paused", data: { effect_tags: { writes: ["paused"] } } })).toBe("pause");
    expect(eventKind({ event_type: "role_granted", data: { effect_tags: { writes: ["_roles"] } } })).toBe("role");
    expect(eventKind({ event_type: "signer_added", data: { effect_tags: { writes: ["owners"] } } })).toBe("signer");
    expect(eventKind({ event_type: "safe_tx_executed", data: { effect_tags: { writes: ["_safe_op"] } } })).toBe("safe");
    expect(eventKind({ event_type: "timelock_scheduled", data: { effect_tags: { writes: ["_timelock_op"] } } })).toBe("timelock");
  });

  it("treats state_changed_poll as the state kind", () => {
    expect(eventKind({ event_type: "state_changed_poll", data: {} })).toBe("state");
  });

  it("supports legacy string-only API for back-compat", () => {
    // Old callers passed e.event_type (a string) directly.
    expect(eventKind("ownership_transferred")).toBe("owner");
    expect(eventKind("upgraded")).toBe("upgrade");
    expect(eventKind("paused")).toBe("pause");
  });

  it("falls back to 'other' for unknown writes and event_type", () => {
    expect(eventKind({ event_type: "unknown", data: { effect_tags: { writes: ["custom"] } } })).toBe("other");
    expect(eventKind("totally_unknown")).toBe("other");
  });

  it("authority writes classify as owner-equivalent", () => {
    expect(
      eventKind({
        event_type: "authority_updated",
        data: { effect_tags: { writes: ["authority"] } },
      }),
    ).toBe("owner");
  });
});

// ---------------------------------------------------------------------------
// eventKindLabel + eventSeverity
// ---------------------------------------------------------------------------

describe("eventKindLabel", () => {
  it("returns the human label for each kind", () => {
    expect(eventKindLabel("upgraded")).toBe("Upgrade");
    expect(eventKindLabel("ownership_transferred")).toBe("Ownership");
    expect(eventKindLabel("paused")).toBe("Pause");
    expect(eventKindLabel("role_granted")).toBe("Role");
    expect(eventKindLabel("signer_added")).toBe("Signer");
    expect(eventKindLabel("safe_tx_executed")).toBe("Safe tx");
    expect(eventKindLabel("timelock_scheduled")).toBe("Timelock");
    expect(eventKindLabel("state_changed_poll")).toBe("State change");
  });
});

describe("eventSeverity", () => {
  it("critical for owner/pause/upgrade kinds", () => {
    expect(eventSeverity("ownership_transferred")).toBe("critical");
    expect(eventSeverity("paused")).toBe("critical");
    expect(eventSeverity("upgraded")).toBe("critical");
  });

  it("major for role/signer/timelock", () => {
    expect(eventSeverity("role_granted")).toBe("major");
    expect(eventSeverity("signer_added")).toBe("major");
    expect(eventSeverity("timelock_scheduled")).toBe("major");
  });

  it("routine for safe activity and state polls", () => {
    expect(eventSeverity("safe_tx_executed")).toBe("routine");
    expect(eventSeverity("state_changed_poll")).toBe("routine");
  });
});

// ---------------------------------------------------------------------------
// Custom slot end-to-end via the generic rendering path
// ---------------------------------------------------------------------------

describe("custom-named slots", () => {
  it("classifies a custom slot via tag writes — example: protocolAdmin → upgrade", () => {
    // A fork that named its admin field 'protocolAdmin' but the static
    // analyzer tagged its setter event as writing 'admin' (the canonical
    // slot semantics) flows through eventKind correctly.
    expect(
      eventKind({
        event_type: "controller_changed:state_variable:protocolAdmin",
        data: { effect_tags: { writes: ["admin"] } },
      }),
    ).toBe("upgrade");
  });

  it("renders an unknown custom slot via the fallback prose path", () => {
    // No renderer for a slot named 'guardian' → falls through to the
    // terminal-form fallback. The producer only mints this stem when the
    // tracking plan proved the slot gates callers, so the control wording
    // is earned here.
    const result = decodeEvent(
      evt("controller_changed:state_variable:guardian", {
        guardian: ADDR_A,
        effect_tags: { writes: ["guardian"] },
      }),
    );
    expect(result.title).toBe("Controller changed: guardian");
    expect(result.sub).toContain("guardian");
  });
});

// ---------------------------------------------------------------------------
// Neutral terminal type — the producer's unproven-target fallback
// ---------------------------------------------------------------------------

describe("state_changed:<controller_id>", () => {
  // Verbatim shape of a served row: an ordinary ERC-20 transfer on an
  // enrolled governance token, whose _balances slot the tracking plan
  // never proved to gate anything.
  const transferRow = {
    event_type: "state_changed:state_variable:_balances",
    data: {
      to: "0x951af4267c8fbcd1c5a8c38e15b122768e44559a",
      from: "0x0000000000000000000000000000000000000000",
      value: 22661724000000000000,
      effect_tags: { writes: ["_allowances", "_balances", "_totalSupply"] },
    },
  };

  it("never renders a control claim in the timeline title", () => {
    const result = decodeEvent(transferRow);
    expect(result.title).toBe("State changed: _balances");
    expect(result.title.toLowerCase()).not.toContain("controller");
    expect(result.sub).toContain("to: 0x951a");
  });

  it("is a state event, not an ownership/role/upgrade one", () => {
    expect(eventKind(transferRow)).toBe("state");
    expect(eventKindLabel(transferRow)).toBe("State change");
    expect(eventSeverity(transferRow)).toBe("routine");
  });

  it("still reports what the emitter wrote when tags name a known slot", () => {
    // A neutral type does not suppress a renderer the tags do earn.
    const result = decodeEvent({
      event_type: "state_changed:state_variable:custom",
      data: { old_owner: ADDR_A, new_owner: ADDR_B, effect_tags: { writes: ["owner"] } },
    });
    expect(result.title).toBe("Ownership transferred");
  });
});

// ---------------------------------------------------------------------------
// Witnessed vocabulary — the types the taxonomy mints once a change is proven
// ---------------------------------------------------------------------------

describe("value_changed:<controller_id>", () => {
  const ownerRow = {
    event_type: "value_changed:state_variable:owner",
    data: { field: "owner", controller_id: "state_variable:owner", old: ADDR_A, new: ADDR_B, witness: "read_verified" },
  };

  it("renders the read-verified diff, not the emitter's write set", () => {
    const result = decodeEvent(ownerRow);
    expect(result.title).toBe("owner changed (verified)");
    expect(result.sub).toBe("0x1111...1111 → 0x2222...2222");
  });

  it("takes its kind from the slot the read proved moved", () => {
    expect(eventKind(ownerRow)).toBe("owner");
    expect(eventKindLabel(ownerRow)).toBe("Ownership");
    expect(eventSeverity(ownerRow)).toBe("critical");
  });

  it("falls back to the state kind for a slot with no mapping", () => {
    const row = { event_type: "value_changed:state_variable:feeBps", data: { old: 30, new: 50 } };
    expect(eventKind(row)).toBe("state");
    expect(decodeEvent(row).sub).toBe("30 → 50");
  });

  it("is not re-titled by a donated write set", () => {
    // The emitter that hinted at this read wrote several slots; only the
    // read's own field is the claim.
    const row = {
      event_type: "value_changed:state_variable:feeBps",
      data: { field: "feeBps", old: 30, new: 50, effect_tags: { writes: ["owner", "feeBps"] } },
    };
    expect(decodeEvent(row).title).toBe("feeBps changed (verified)");
  });
});

describe("member_changed:<mapping_var>", () => {
  it("renders the key/value/direction from data, never from the type", () => {
    const row = {
      event_type: "member_changed:fromDenyList",
      data: { key: ADDR_A, value: true, direction: "add" },
    };
    const result = decodeEvent(row);
    expect(result.title).toBe("fromDenyList entry added");
    expect(result.sub).toBe("0x1111...1111 = true");
    expect(row.event_type).not.toContain(ADDR_A);
  });

  it("names no verb when the event stated no direction", () => {
    const result = decodeEvent({ event_type: "member_changed:peers", data: { key: "42" } });
    expect(result.title).toBe("peers entry changed");
  });
});

describe("state_changed_poll old/new key aliases", () => {
  it("renders the poller's own old_value/new_value shape", () => {
    const result = decodeEvent(
      evt("state_changed_poll", { field: "owner", old_value: ADDR_A, new_value: ADDR_B }),
    );
    // addresses shorten like every other renderer; the aliases are what this pins
    expect(result.sub).toBe(`${shortenAddress(ADDR_A)} → ${shortenAddress(ADDR_B)}`);
  });
});

// ---------------------------------------------------------------------------
// Salience — the vocabulary mirror. The backend owns the classification; these
// tests pin that this file reads it and never re-derives it.
// ---------------------------------------------------------------------------

describe("eventSalience", () => {
  it("reads the level the backend published", () => {
    for (const level of ["alert", "notable", "routine", "not_determined"]) {
      expect(eventSalience(evt("safe_tx_executed", { salience: level }))).toBe(level);
    }
  });

  it("reads an absent or unknown level as not_determined, never as routine", () => {
    expect(eventSalience(evt("safe_tx_executed", {}))).toBe("not_determined");
    expect(eventSalience(evt("safe_tx_executed", { salience: "quiet" }))).toBe("not_determined");
    expect(eventSalience(evt("safe_tx_executed", null))).toBe("not_determined");
    expect(eventSalience(undefined)).toBe("not_determined");
  });

  it("does not re-derive a level from the event type", () => {
    // A canonical config family with NO backend level stays unrated here even
    // though the backend rule would call it alert — a mirrored ruleset drifts,
    // and a drifted mirror that hides rows is a silent-suppression bug.
    expect(eventSalience(evt("ownership_transferred", {}))).toBe("not_determined");
  });
});

describe("salienceAllows", () => {
  it("sorts not_determined with notable, never with routine", () => {
    expect(salienceAllows("not_determined", "notable")).toBe(true);
    expect(salienceAllows("notable", "notable")).toBe(true);
    expect(salienceAllows("routine", "notable")).toBe(false);
    expect(salienceAllows("alert", "notable")).toBe(true);
  });

  it("admits only proven alerts at the alert threshold", () => {
    expect(salienceAllows("alert", "alert")).toBe(true);
    expect(salienceAllows("not_determined", "alert")).toBe(false);
    expect(salienceAllows("notable", "alert")).toBe(false);
  });

  it("admits everything at the routine threshold and for an unreadable one", () => {
    for (const level of ["alert", "notable", "routine", "not_determined"]) {
      expect(salienceAllows(level, "routine")).toBe(true);
      expect(salienceAllows(level, "nonsense")).toBe(true);
      expect(salienceAllows(level, undefined)).toBe(true);
    }
  });

  it("measures an unrated level at the not_determined rank", () => {
    expect(salienceAllows(undefined, "notable")).toBe(true);
    expect(salienceAllows(undefined, "alert")).toBe(false);
  });
});

describe("eventSeverity — rebased on salience", () => {
  it("takes the backend level over the kind-derived table", () => {
    // The old table hardcoded every safe and state event to routine.
    expect(eventSeverity(evt("safe_tx_executed", { salience: "alert" }))).toBe("critical");
    expect(eventSeverity(evt("state_changed_poll", { salience: "notable" }))).toBe("major");
    expect(eventSeverity(evt("safe_tx_executed", { salience: "routine" }))).toBe("routine");
  });

  it("renders not_determined at notable prominence", () => {
    expect(eventSeverity(evt("safe_tx_executed", { salience: "not_determined" }))).toBe("major");
  });

  it("demotes a canonical family the backend proved routine", () => {
    expect(eventSeverity(evt("ownership_transferred", { salience: "routine" }))).toBe("routine");
  });

  it("falls back to the kind table for rows written before salience landed", () => {
    expect(eventSeverity(evt("ownership_transferred", {}))).toBe("critical");
    expect(eventSeverity(evt("safe_tx_executed", {}))).toBe("routine");
  });
});
