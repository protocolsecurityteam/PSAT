import { describe, it, expect } from "vitest";

import {
  CLAIM_VOCAB,
  claimSummaryLine,
  claimWitnessFacts,
  claimsOf,
  hasClaims,
  laneForClaims,
  primaryClaim,
  priorityForClaims,
  qualifierForClaims,
  scoreForClaims,
  sentenceForClaims,
  signerOverlapNote,
  terminalControllerNote,
  toneForClaims,
} from "./claimsVocab.js";
import {
  compactActionSummary,
  laneForFunction,
  lanePriority,
  toneForFunction,
} from "./surface/lane.js";
import { buildMachines } from "./surface/layout/buildMachines.js";
import { entityKey } from "./surface/entityKey.js";
import { ETHERFI_COMPANY_RICH } from "./test/fixtures.js";

const VALID_LANES = new Set(["top", "left", "right", "ops"]);
const VALID_FAMILIES = new Set(["control_plane", "flow", "exec", "user_plane"]);
const VALID_KINDS = new Set([
  "upgrade", "execution", "admin", "config", "pause", "unpause", "timelock", "asset_out", "asset_in",
]);

function claim(claim_id, tier = "standard_exact") {
  return { claim_id, tier, witness: {} };
}

// Every registered backend claim_id the frontend renders. A new backend claim
// that lands without a vocab entry is caught here — the JS half of the
// consumer-coverage invariant (spec §6.5).
const EXPECTED_CLAIM_IDS = [
  "authority.grant",
  "authority.replace",
  "authorized_caller.rotate",
  "callee_pointer.rotate",
  "contract_deployment",
  "erc20.approve",
  "erc20.transfer",
  "erc20.transfer_from",
  "exec.arbitrary",
  "flow.in",
  "flow.out",
  "gov.delegate",
  "lz_oapp.set_delegate",
  "lz_oapp.set_peer",
  "ownership.accept",
  "ownership.renounce",
  "ownership.transfer",
  "pause.set",
  "pause.unset",
  "proxy.admin_change",
  "roles.configure",
  "roles.grant",
  "roles.revoke",
  "safe.module_mgmt",
  "safe.set_guard",
  "safe.signer_mgmt",
  "supply.burn",
  "supply.mint",
  "timelock.cancel",
  "timelock.execute",
  "timelock.schedule",
  "timelock.set_delay",
  "upgrade.implementation",
  "weth.deposit",
  "weth.withdraw",
];

describe("CLAIM_VOCAB shape invariants", () => {
  it("covers exactly the registered backend claim ids", () => {
    expect(Object.keys(CLAIM_VOCAB).sort()).toEqual(EXPECTED_CLAIM_IDS);
  });

  it("gives every entry a valid family, lane, sentence, and numeric priority", () => {
    for (const [id, entry] of Object.entries(CLAIM_VOCAB)) {
      expect(VALID_FAMILIES.has(entry.family), `${id} family`).toBe(true);
      expect(VALID_LANES.has(entry.lane), `${id} lane`).toBe(true);
      expect(typeof entry.sentence === "string" && entry.sentence.length > 0, `${id} sentence`).toBe(true);
      expect(Number.isFinite(entry.priority), `${id} priority`).toBe(true);
      if (entry.score) {
        expect(VALID_KINDS.has(entry.score.kind), `${id} score.kind`).toBe(true);
        expect(entry.score.severity, `${id} severity`).toBeGreaterThan(0);
      }
    }
  });

  it("never puts a user_plane claim in the control lane", () => {
    for (const [id, entry] of Object.entries(CLAIM_VOCAB)) {
      if (entry.family === "user_plane") expect(entry.lane, `${id}`).not.toBe("top");
    }
  });

  it("lanes every control_plane and exec claim to the top", () => {
    for (const [id, entry] of Object.entries(CLAIM_VOCAB)) {
      if (entry.family === "control_plane" || entry.family === "exec") {
        expect(entry.lane, `${id}`).toBe("top");
      }
    }
  });
});

describe("claim helpers", () => {
  it("drops unknown/malformed claim ids (fail-closed)", () => {
    const fn = { claims: [claim("ownership.transfer"), { claim_id: "not.a.claim" }, null, { tier: "x" }] };
    expect(claimsOf(fn).map((c) => c.claim_id)).toEqual(["ownership.transfer"]);
    expect(hasClaims(fn)).toBe(true);
    expect(hasClaims({ claims: [] })).toBe(false);
    expect(hasClaims({})).toBe(false);
  });

  it("picks the lowest-priority claim as the primary", () => {
    const fn = { claims: [claim("flow.out"), claim("ownership.transfer"), claim("pause.set")] };
    expect(primaryClaim(fn).claim_id).toBe("ownership.transfer");
    expect(toneForClaims(fn)).toBe("#9e8a8d");
    expect(sentenceForClaims(fn)).toBe("changes owner");
    expect(priorityForClaims(fn)).toBe(2);
  });

  it("breaks equal-priority ties deterministically by claim_id", () => {
    // roles.grant and authority.replace share priority 3; the id-sorted winner
    // is stable regardless of input order.
    const a = { claims: [claim("roles.grant"), claim("authority.replace")] };
    const b = { claims: [claim("authority.replace"), claim("roles.grant")] };
    expect(primaryClaim(a).claim_id).toBe("authority.replace");
    expect(primaryClaim(b).claim_id).toBe("authority.replace");
  });

  it("returns null for every derived field when no registered claims exist", () => {
    const fn = { claims: [] };
    expect(primaryClaim(fn)).toBeNull();
    expect(laneForClaims(fn)).toBeNull();
    expect(toneForClaims(fn)).toBeNull();
    expect(sentenceForClaims(fn)).toBeNull();
    expect(priorityForClaims(fn)).toBeNull();
    expect(scoreForClaims(fn)).toBeNull();
    expect(claimSummaryLine(fn)).toBeNull();
  });
});

describe("laneForClaims — family → lane", () => {
  it("routes control/exec claims to the top lane", () => {
    for (const id of ["upgrade.implementation", "roles.grant", "timelock.execute", "exec.arbitrary"]) {
      expect(laneForClaims({ claims: [claim(id)] })).toBe("top");
    }
  });

  it("routes flow claims to inflow/outflow by direction", () => {
    expect(laneForClaims({ claims: [claim("flow.in")] })).toBe("left");
    expect(laneForClaims({ claims: [claim("supply.mint")] })).toBe("left");
    expect(laneForClaims({ claims: [claim("flow.out")] })).toBe("right");
    expect(laneForClaims({ claims: [claim("supply.burn")] })).toBe("right");
  });

  it("lets an outflow win when a function both pulls and sends (legacy merge)", () => {
    expect(laneForClaims({ claims: [claim("flow.in"), claim("flow.out")] })).toBe("right");
  });

  it("keeps user-plane operations out of the control lane", () => {
    expect(laneForClaims({ claims: [claim("gov.delegate")] })).toBe("ops");
    expect(laneForClaims({ claims: [claim("erc20.approve")] })).toBe("ops");
    expect(laneForClaims({ claims: [claim("weth.deposit")] })).toBe("left");
    expect(laneForClaims({ claims: [claim("erc20.transfer")] })).toBe("right");
  });

  it("prefers a control claim over a co-occurring flow claim", () => {
    expect(laneForClaims({ claims: [claim("flow.out"), claim("ownership.transfer")] })).toBe("top");
  });
});

describe("scoreForClaims — protocolScore kinds", () => {
  it("maps the spec severity tiers", () => {
    expect(scoreForClaims({ claims: [claim("upgrade.implementation")] })).toEqual({ kind: "upgrade", severity: 1 });
    expect(scoreForClaims({ claims: [claim("exec.arbitrary")] })).toEqual({ kind: "execution", severity: 0.95 });
    expect(scoreForClaims({ claims: [claim("ownership.transfer")] })).toEqual({ kind: "admin", severity: 0.88 });
    expect(scoreForClaims({ claims: [claim("proxy.admin_change")] })).toEqual({ kind: "admin", severity: 0.88 });
    expect(scoreForClaims({ claims: [claim("safe.signer_mgmt")] })).toEqual({ kind: "admin", severity: 0.88 });
    expect(scoreForClaims({ claims: [claim("callee_pointer.rotate")] })).toEqual({ kind: "config", severity: 0.78 });
    expect(scoreForClaims({ claims: [claim("pause.set")] })).toEqual({ kind: "pause", severity: 0.25 });
    expect(scoreForClaims({ claims: [claim("pause.unset")] })).toEqual({ kind: "unpause", severity: 0.68 });
    expect(scoreForClaims({ claims: [claim("timelock.schedule")] })).toEqual({ kind: "timelock", severity: 0.62 });
    expect(scoreForClaims({ claims: [claim("flow.out")] })).toEqual({ kind: "asset_out", severity: 0.78 });
    expect(scoreForClaims({ claims: [claim("flow.in")] })).toEqual({ kind: "asset_in", severity: 0.5 });
  });

  it("takes the strongest severity across several claims", () => {
    expect(scoreForClaims({ claims: [claim("flow.out"), claim("upgrade.implementation")] }))
      .toEqual({ kind: "upgrade", severity: 1 });
  });

  it("returns null for non-scoreable (user-plane / deployment) claims", () => {
    expect(scoreForClaims({ claims: [claim("erc20.transfer")] })).toBeNull();
    expect(scoreForClaims({ claims: [claim("contract_deployment")] })).toBeNull();
  });
});

describe("claimSummaryLine — chip line + provenance tier", () => {
  it("joins sentences in priority order and appends the strongest tier", () => {
    const fn = { claims: [claim("flow.out", "policy_derived"), claim("ownership.transfer", "standard_exact")] };
    const line = claimSummaryLine(fn);
    expect(line.text).toBe("changes owner · moves value out");
    expect(line.tier).toBe("standard_exact");
    expect(line.label).toBe("changes owner · moves value out · standard");
  });

  it("deduplicates repeated phrases from distinct claim ids", () => {
    // erc20.transfer and erc20.transfer_from both render "transfers tokens".
    const line = claimSummaryLine({ claims: [claim("erc20.transfer"), claim("erc20.transfer_from")] });
    expect(line.text).toBe("transfers tokens");
  });

  it("renders the behavioral_observed tier as the strongest provenance", () => {
    // The effects bridge mints at behavioral_observed (rank 4) — it outranks a
    // static standard_exact claim of a different id and labels as "observed".
    const fn = {
      claims: [claim("upgrade.implementation", "standard_exact"), claim("flow.out", "behavioral_observed")],
    };
    const line = claimSummaryLine(fn);
    expect(line.tier).toBe("behavioral_observed");
    expect(line.label.endsWith("· observed")).toBe(true);
  });

  it("renders the bridge-only authority.grant claim", () => {
    const line = claimSummaryLine({ claims: [claim("authority.grant", "behavioral_observed")] });
    expect(line.text).toBe("opens a gate");
    expect(line.label).toBe("opens a gate · observed");
  });
});

// ── SCORING plan §7: witness qualifiers (the honesty rule) ───────────────────

// A static flow.out claim carrying a target_kind / amount_kind on one flow entry.
function flowOut(targetKind, { amountKind = null, tier = "standard_exact" } = {}) {
  const flow = { kind: "low_level_value_call", selector: null, from_is_self: true };
  if (targetKind) flow.target_kind = targetKind;
  if (amountKind) flow.amount_kind = amountKind;
  return {
    claim_id: "flow.out",
    tier,
    witness: { kind: "value_flow", direction: "out", flows: [flow], sink_ids: [] },
  };
}

// A behavioral (fork-observed) claim with an `observed` summary.
function observedClaim(claim_id, observed) {
  return {
    claim_id,
    tier: "behavioral_observed",
    witness: { effect_verdict_id: 1, effect_class: "x", observed },
  };
}

describe("qualifierForClaims — flow.out destination (theft vs routing)", () => {
  it("renders (fixed destination) only for a proven immutable/constant/no-setter target", () => {
    expect(qualifierForClaims({ claims: [flowOut({ kind: "immutable", tier: "dispositive_ast" })] }))
      .toBe("(fixed destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "constant", tier: "dispositive_ast" })] }))
      .toBe("(fixed destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "storage_no_setter", tier: "static_trace" })] }))
      .toBe("(fixed destination)");
  });

  it("renders (caller-chosen destination) for param / msg_sender", () => {
    expect(qualifierForClaims({ claims: [flowOut({ kind: "param", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "msg_sender", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
  });

  it("treats storage_setter as admin-redirectable, NOT fixed", () => {
    expect(qualifierForClaims({ claims: [flowOut({ kind: "storage_setter", tier: "static_trace" })] }))
      .toBe("(admin-settable destination)");
  });

  it("suppresses the qualifier for indeterminate / self / absent target_kind", () => {
    expect(qualifierForClaims({ claims: [flowOut({ kind: "indeterminate", tier: "static_trace" })] })).toBeNull();
    expect(qualifierForClaims({ claims: [flowOut({ kind: "self", tier: "dispositive_ast" })] })).toBeNull();
    expect(qualifierForClaims({ claims: [flowOut(null)] })).toBeNull();
  });

  it("shows the worst path in a multi-flow function (caller-chosen dominates fixed)", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [
            { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
            { kind: "y", target_kind: { kind: "param", tier: "dispositive_ast" } },
          ],
          sink_ids: [],
        },
      }],
    };
    expect(qualifierForClaims(fn)).toBe("(caller-chosen destination)");
  });

  it("does NOT claim fixed when one out-flow is unclassified (no false negative laundering)", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [
            { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
            { kind: "y" }, // no target_kind → unclassified, blocks a "fixed" claim
          ],
          sink_ids: [],
        },
      }],
    };
    expect(qualifierForClaims(fn)).toBeNull();
  });
});

describe("qualifierForClaims — pause freeze specifics", () => {
  it("renders (auto-expires ~Nd) only when auto_expiry true AND a duration bound is read", () => {
    const fn = { claims: [observedClaim("pause.set", { auto_expiry: true, duration_bound_seconds: 30 * 86400 })] };
    expect(qualifierForClaims(fn)).toBe("(auto-expires ~30d)");
  });

  it("renders hours when the bound is under a day", () => {
    const fn = { claims: [observedClaim("pause.set", { auto_expiry: true, duration_bound_seconds: 8 * 3600 })] };
    expect(qualifierForClaims(fn)).toBe("(auto-expires ~8h)");
  });

  it("renders (indefinite) for the null/null latch on a present behavioral witness", () => {
    const fn = { claims: [observedClaim("pause.set", { auto_expiry: null, duration_bound_seconds: null })] };
    expect(qualifierForClaims(fn)).toBe("(indefinite)");
  });

  it("suppresses when auto_expiry is false (fork contradicted the static bound)", () => {
    const fn = { claims: [observedClaim("pause.set", { auto_expiry: false, duration_bound_seconds: 30 * 86400 })] };
    expect(qualifierForClaims(fn)).toBeNull();
  });

  it("suppresses on a static-only pause.set (no observed witness = unknown)", () => {
    expect(qualifierForClaims({ claims: [claim("pause.set", "idiom_structural")] })).toBeNull();
    // present observed but no freeze fields → unknown, not indefinite
    expect(qualifierForClaims({ claims: [observedClaim("pause.set", { gate_mutation: "x" })] })).toBeNull();
  });
});

describe("qualifierForClaims — mint backing", () => {
  it("renders (backed) only for inflow_observed === true", () => {
    const fn = { claims: [observedClaim("supply.mint", { backing: { inflow_observed: true, minted: true } })] };
    expect(qualifierForClaims(fn)).toBe("(backed)");
  });

  it("renders (unbacked) for a witnessed dilution (inflow_observed === false)", () => {
    const fn = { claims: [observedClaim("supply.mint", { backing: { inflow_observed: false, minted: true } })] };
    expect(qualifierForClaims(fn)).toBe("(unbacked)");
  });

  it("suppresses when backing is absent (unknown, never 'backed' from absence)", () => {
    expect(qualifierForClaims({ claims: [claim("supply.mint")] })).toBeNull();
    expect(qualifierForClaims({ claims: [observedClaim("supply.mint", {})] })).toBeNull();
  });
});

describe("qualifierForClaims — non-target claims and empties", () => {
  it("returns null for a primary claim with no qualifier concept", () => {
    expect(qualifierForClaims({ claims: [claim("ownership.transfer")] })).toBeNull();
    expect(qualifierForClaims({ claims: [] })).toBeNull();
    expect(qualifierForClaims({})).toBeNull();
  });
});

describe("compactActionSummary appends the witness qualifier", () => {
  it("appends the destination qualifier to the flow.out chip", () => {
    expect(compactActionSummary({ claims: [flowOut({ kind: "immutable", tier: "dispositive_ast" })] }))
      .toBe("moves value out (fixed destination)");
    expect(compactActionSummary({ claims: [flowOut({ kind: "param", tier: "dispositive_ast" })] }))
      .toBe("moves value out (caller-chosen destination)");
  });

  it("leaves the plain phrase when the witness is indeterminate/absent", () => {
    expect(compactActionSummary({ claims: [flowOut({ kind: "indeterminate", tier: "static_trace" })] }))
      .toBe("moves value out");
    expect(compactActionSummary({ claims: [claim("flow.out")] })).toBe("moves value out");
  });
});

describe("claimSummaryLine appends the qualifier to the primary phrase", () => {
  it("qualifies the pause phrase in the joined line + label", () => {
    const fn = { claims: [observedClaim("pause.set", { auto_expiry: true, duration_bound_seconds: 30 * 86400 })] };
    const line = claimSummaryLine(fn);
    expect(line.text).toBe("pauses (auto-expires ~30d)");
    expect(line.label).toBe("pauses (auto-expires ~30d) · observed");
  });

  it("leaves the plain phrase when there is no at-bar witness", () => {
    const line = claimSummaryLine({ claims: [claim("pause.set")] });
    expect(line.text).toBe("pauses");
  });

  it("lands on the primary claim's phrase on a priority tie, not the array-first sibling", () => {
    // supply.burn and flow.out share priority 7; primaryClaim tie-breaks by
    // claim_id to flow.out. With supply.burn first in the array, the stable sort
    // puts "burns supply" at index 0 — the destination qualifier must still
    // attach to "moves value out", never the tied sibling's phrase.
    const flowOut = {
      claim_id: "flow.out",
      tier: "idiom_structural",
      witness: {
        kind: "value_flow",
        direction: "out",
        flows: [{ kind: "low_level_value_call", selector: null, from_is_self: true, target_kind: { kind: "param", tier: "dispositive_ast" } }],
      },
    };
    const line = claimSummaryLine({ claims: [claim("supply.burn"), flowOut] });
    expect(line.text).toBe("burns supply · moves value out (caller-chosen destination)");
  });
});

describe("claimWitnessFacts — inspector verbose rows", () => {
  it("emits destination + amount rows with their tier labels", () => {
    const fn = {
      claims: [flowOut(
        { kind: "immutable", tier: "dispositive_ast" },
        { amountKind: { kind: "param", tier: "static_trace" } },
      )],
    };
    const facts = claimWitnessFacts(fn);
    expect(facts).toContainEqual({ label: "Destination", value: "immutable address · dispositive AST" });
    expect(facts).toContainEqual({ label: "Amount", value: "caller-supplied argument · static trace" });
  });

  it("emits freeze scope + auto-expiry rows for a fork-observed pause", () => {
    const fn = {
      claims: [observedClaim("pause.set", {
        observed_blast_radius: ["pauseUntil(uint256)", "blacklist(address)"],
        auto_expiry: true,
        duration_bound_seconds: 30 * 86400,
      })],
    };
    const facts = claimWitnessFacts(fn);
    expect(facts.find((f) => f.label === "Freeze scope").value).toContain("2 entry point(s)");
    expect(facts).toContainEqual({ label: "Auto-expiry", value: "self-recovers after ~30d" });
  });

  it("labels an indefinite latch honestly", () => {
    const facts = claimWitnessFacts({
      claims: [observedClaim("pause.set", { auto_expiry: null, duration_bound_seconds: null })],
    });
    expect(facts).toContainEqual({ label: "Auto-expiry", value: "indefinite latch (no self-recovery bound)" });
  });

  it("emits backing rows for both witnessed directions", () => {
    expect(claimWitnessFacts({ claims: [observedClaim("supply.mint", { backing: { inflow_observed: true } })] }))
      .toContainEqual({ label: "Backing", value: "matching asset inflow observed (backed)" });
    expect(claimWitnessFacts({ claims: [observedClaim("supply.mint", { backing: { inflow_observed: false } })] }))
      .toContainEqual({ label: "Backing", value: "no matching inflow — supply rose alone (dilution)" });
  });

  it("renders reach as an explicit UPPER BOUND, never exact", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: { effect_verdict_id: 1, observed: { observed_reach_value_usd: 55_200_000 } },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({ label: "Reach (upper bound)", value: "up to ~$55.2M" });
  });

  it("floors reach to own balance when fork-observed indeterminate", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: { effect_verdict_id: 1, observed: { reach_indeterminate: true, observed_reach_value_usd: 999 } },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({ label: "Reach", value: "floored to own balance (reach indeterminate)" });
  });

  it("emits no rows when no witness facts are present (silence, not defaults)", () => {
    expect(claimWitnessFacts({ claims: [claim("flow.out")] })).toEqual([]);
    expect(claimWitnessFacts({ claims: [claim("ownership.transfer")] })).toEqual([]);
    expect(claimWitnessFacts({})).toEqual([]);
  });
});

describe("terminalControllerNote — non-terminal way-points never read as settled keys", () => {
  it("returns null for a principal that is itself a settled key", () => {
    expect(terminalControllerNote({ resolvedType: "safe", details: { terminal: true } })).toBeNull();
    expect(terminalControllerNote({ resolvedType: "eoa", details: { terminal: true } })).toBeNull();
  });

  it("flags a bare contract way-point (no terminal walk) as unresolved", () => {
    const note = terminalControllerNote({ resolvedType: "contract", details: { terminal: false } });
    expect(note).toEqual({ kind: "unresolved", status: "unknown_unfetched" });
  });

  it("surfaces a terminated walk's ultimate key", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: true, resolved_type: "safe", address: "0xabc", chain: ["0x1", "0xabc"], status: "terminated" },
      },
    });
    expect(note).toEqual({ kind: "terminated", address: "0xabc", resolvedType: "safe" });
  });

  it("shows multiple control planes for ambiguous_controllers, never one key", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "ambiguous_controllers", controllers: ["0x1", "0x2"] },
      },
    });
    expect(note.kind).toBe("ambiguous");
    expect(note.planes).toEqual(["0x1", "0x2"]);
  });

  it("treats cycle / depth_exceeded / unfetched as honestly unresolved", () => {
    for (const status of ["cycle", "depth_exceeded", "unknown_unfetched"]) {
      const note = terminalControllerNote({
        resolvedType: "contract",
        details: { terminal: false, terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status } },
      });
      expect(note).toEqual({ kind: "unresolved", status });
    }
  });
});

describe("signerOverlapNote — attribution context, not org identity", () => {
  it("surfaces the strongest subset relation", () => {
    const principal = {
      resolvedType: "safe",
      details: {
        signer_overlap: {
          provenance: "onchain_owner_read",
          self_owner_count: 5,
          overlaps: [
            { address: "0x2aca", other_owner_count: 7, shared_count: 5, shared_owners: [], subset: true, superset: false, equal: false, jaccard: 0.71 },
            { address: "0xdead", other_owner_count: 3, shared_count: 1, shared_owners: [], subset: false, superset: false, equal: false, jaccard: 0.14 },
          ],
        },
      },
    };
    const note = signerOverlapNote(principal);
    expect(note.selfOwnerCount).toBe(5);
    expect(note.strongest.address).toBe("0x2aca");
    expect(note.strongest.subset).toBe(true);
  });

  it("emits null when the fact is absent or has no shared signers", () => {
    expect(signerOverlapNote({ resolvedType: "safe", details: {} })).toBeNull();
    const disjoint = {
      resolvedType: "safe",
      details: { signer_overlap: { self_owner_count: 3, overlaps: [{ address: "0x1", shared_count: 0, jaccard: 0 }] } },
    };
    expect(signerOverlapNote(disjoint)).toEqual({ selfOwnerCount: 3, strongest: null });
  });
});

describe("lane.js consumers prefer claims over legacy effect_labels", () => {
  it("laneForFunction uses the claim lane, overriding a legacy label and name-hint", () => {
    // Legacy label + name both say inflow/control; the claim says outflow.
    const fn = { function: "deposit", effect_labels: ["hook_update"], claims: [claim("flow.out")] };
    expect(laneForFunction(fn)).toBe("right");
  });

  it("laneForFunction falls back to legacy effect_labels when claims are absent", () => {
    expect(laneForFunction({ function: "x", effect_labels: ["pause_toggle"] })).toBe("top");
    expect(laneForFunction({ function: "x", effect_labels: ["asset_send"] })).toBe("right");
  });

  it("toneForFunction uses the claim tone, and the lane tone for a tone-less claim", () => {
    expect(toneForFunction({ effect_labels: [], claims: [claim("ownership.transfer")] }, "top")).toBe("#9e8a8d");
    // approve has no tone of its own → lane tone, never a legacy effect tone.
    expect(toneForFunction({ effect_labels: ["ownership_transfer"], claims: [claim("erc20.approve")] }, "ops"))
      .toBe("#6b7590");
  });

  it("compactActionSummary renders the claim sentence, not the legacy phrase", () => {
    expect(compactActionSummary({ effect_labels: ["hook_update"], claims: [claim("pause.unset")] })).toBe("unpauses");
    // claim-less falls back to the legacy phrase.
    expect(compactActionSummary({ effect_labels: ["implementation_update"] })).toBe("changes logic");
  });

  it("lanePriority uses the claim priority when present", () => {
    expect(lanePriority({ effect_labels: [], claims: [claim("upgrade.implementation")] })).toBe(0);
    expect(lanePriority({ effect_labels: [], claims: [claim("flow.out"), claim("ownership.transfer")] })).toBe(2);
    // claim-less path unchanged.
    expect(lanePriority({ effect_labels: ["timelock_operation"] })).toBe(4);
  });
});

describe("buildMachines carries claims into lane placement + ordering", () => {
  it("places a claim-bearing function by its claim, overriding the legacy label", () => {
    const company = structuredClone(ETHERFI_COMPANY_RICH);
    const vault = company.contracts[0];
    // deposit is legacy asset_pull (inflow); a flow.out claim must move it to outflow.
    const deposit = vault.functions.find((f) => f.function === "deposit");
    deposit.claims = [claim("flow.out")];
    const functionData = Object.fromEntries(company.contracts.map((c) => [entityKey(c.chain, c.address), c.functions]));

    const machines = buildMachines(company, functionData);
    const machine = machines.find((m) => m.address === vault.address);
    const right = machine.lanes.right.map((f) => f.name);
    expect(right).toContain("deposit");
    expect(machine.lanes.left.map((f) => f.name)).not.toContain("deposit");
    const view = machine.lanes.right.find((f) => f.name === "deposit");
    expect(view.action).toBe("moves value out");
    expect(view.tone).toBe("#9a8a6e");
  });
});
