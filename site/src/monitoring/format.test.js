import { describe, it, expect } from "vitest";
import { decodeEvent, eventKind, eventKindLabel, eventSeverity } from "./format.js";

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
    // raw key-value fallback.
    const result = decodeEvent(
      evt("controller_changed:state_variable:guardian", {
        guardian: ADDR_A,
        effect_tags: { writes: ["guardian"] },
      }),
    );
    expect(result.title).toBe("controller changed:state variable:guardian");
    expect(result.sub).toContain("guardian");
  });
});
