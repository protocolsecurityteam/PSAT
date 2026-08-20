import { describe, it, expect } from "vitest";

import { CLAIM_VOCAB } from "./claimVocab.data.js";
import {
  claimSummaryLine,
  claimsOf,
  hasClaims,
  laneForClaims,
  primaryClaim,
  priorityForClaims,
  sentenceForClaims,
  toneForClaims,
} from "./claimProjection.js";
import { claim, flowOut, observedClaim } from "./testSupport.js";

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

describe("claimSummaryLine — chip line + provenance tier", () => {
  it("names BOTH tiers when the weakest differs from the strongest", () => {
    // INVERTED. This asserted `label` ended at "· standard": the
    // headline tier hid the policy_derived claim on the same line, and
    // policy_derived is defined as having no single-contract evidence at all.
    // Surfacing only the strongest tier is what made the provenance disappear
    // from every surface reading this line.
    const fn = { claims: [claim("flow.out", "policy_derived"), claim("ownership.transfer", "standard_exact")] };
    const line = claimSummaryLine(fn);
    expect(line.text).toBe("changes owner · moves value out");
    expect(line.tier).toBe("standard_exact");
    expect(line.weakestTier).toBe("policy_derived");
    expect(line.label).toBe("changes owner · moves value out · standard + policy");
  });

  it("names one tier when every claim shares it", () => {
    // NEGATIVE CONTROL: the double label is not unconditional decoration.
    const fn = { claims: [claim("flow.out"), claim("ownership.transfer")] };
    const line = claimSummaryLine(fn);
    expect(line.tier).toBe("standard_exact");
    expect(line.weakestTier).toBe("standard_exact");
    expect(line.label.endsWith("· standard")).toBe(true);
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
    // The weakest tier on the line is named too — the observed claim outranks the
    // static one, and hiding the static one is the same collapse.
    expect(line.weakestTier).toBe("standard_exact");
    expect(line.label.endsWith("· observed + standard")).toBe(true);
  });

  it("renders the bridge-only authority.grant claim", () => {
    const line = claimSummaryLine({ claims: [claim("authority.grant", "behavioral_observed")] });
    expect(line.text).toBe("opens a gate");
    expect(line.label).toBe("opens a gate · observed");
  });
});

// ── Witness qualifiers (the honesty rule) ────────────────────────────────────

// A static flow.out claim carrying a target_kind / amount_kind on one flow entry.
// `constraint` is the destination verdict the producer attaches to every
// `param` destination. It defaults to the proven-free state so the existing
// caller-chosen assertions keep testing what they were written to test — the
// constrained and not-determined arms get their own cases below.

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
        flows: [{ kind: "low_level_value_call", selector: null, from_is_self: true, target_kind: { kind: "param", tier: "dispositive_ast" }, target_constraint: { state: "unconstrained_proven" } }],
      },
    };
    const line = claimSummaryLine({ claims: [claim("supply.burn"), flowOut] });
    expect(line.text).toBe("burns supply · moves value out (caller-chosen destination)");
  });
});

describe("toneForClaims — hazard/calm tinting (proven positives vs negatives)", () => {
  const flowOutTone = (targetKind) => toneForClaims({ claims: [flowOut({ kind: targetKind, tier: "dispositive_ast" })] });

  it("tints a caller-chosen out-flow more hazardous than a proven-fixed one", () => {
    const caller = flowOutTone("param");
    const callerOrigin = flowOutTone("caller_controlled");
    const fixed = flowOutTone("immutable");
    expect(caller).toBe("#a8746a");
    expect(callerOrigin).toBe("#a8746a");
    expect(fixed).toBe("#8f947a");
    expect(caller).not.toBe(fixed);
    // both differ from the neutral base tone.
    expect(caller).not.toBe(CLAIM_VOCAB["flow.out"].tone);
    expect(fixed).not.toBe(CLAIM_VOCAB["flow.out"].tone);
  });

  it("keeps the neutral base tone for an admin-settable / indeterminate / absent destination", () => {
    const base = CLAIM_VOCAB["flow.out"].tone;
    expect(flowOutTone("storage_setter")).toBe(base);
    expect(flowOutTone("indeterminate")).toBe(base);
    expect(toneForClaims({ claims: [claim("flow.out")] })).toBe(base);
  });

  it("does not calm-tint a mixed out-flow where one path is caller-chosen", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow", direction: "out",
          flows: [
            { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
            {
              kind: "y",
              target_kind: { kind: "param", tier: "dispositive_ast" },
              target_constraint: { state: "unconstrained_proven" },
            },
          ],
        },
      }],
    };
    expect(toneForClaims(fn)).toBe("#a8746a");
  });

  it("tints an unbacked mint hazardous and leaves a backed/unknown mint neutral", () => {
    const base = CLAIM_VOCAB["supply.mint"].tone;
    expect(toneForClaims({ claims: [observedClaim("supply.mint", { backing: { inflow_observed: false } })] }))
      .toBe("#9e8a6a");
    expect(toneForClaims({ claims: [observedClaim("supply.mint", { backing: { inflow_observed: true } })] }))
      .toBe(base);
    expect(toneForClaims({ claims: [claim("supply.mint")] })).toBe(base);
  });

  it("reflects an unbacked co-mint on a wrap's value-in tone", () => {
    const base = CLAIM_VOCAB["flow.in"].tone;
    const unbacked = { claims: [claim("flow.in"), observedClaim("supply.mint", { backing: { inflow_observed: false } })] };
    const backed = { claims: [claim("flow.in"), observedClaim("supply.mint", { backing: { inflow_observed: true } })] };
    expect(toneForClaims(unbacked)).toBe("#9e8a6a");
    expect(toneForClaims(backed)).toBe(base);
  });

  it("leaves non-flow claims on their vocabulary tone", () => {
    expect(toneForClaims({ claims: [claim("ownership.transfer")] })).toBe(CLAIM_VOCAB["ownership.transfer"].tone);
    expect(toneForClaims({ claims: [] })).toBeNull();
  });
});

describe("rate_limit.consume — a fact at zero severity weight", () => {
  const limiterClaim = {
    claim_id: "rate_limit.consume",
    tier: "idiom_structural",
    witness: {
      kind: "limiter_consume",
      sink_ids: ["s0"],
      mandatory: { state: "proven" },
      capacity: { state: "not_determined", source: "chain_state" },
      refill_rate: { state: "not_determined", source: "chain_state" },
      bounds_total_extraction: { state: "not_determined", source: "chain_state" },
      severity_weight: 0,
    },
  };

  it("is rendered rather than dropped — the vocab knows the id", () => {
    // claimsOf is fail-closed: an id the vocab does not carry is treated as
    // absent, which would silently discard the fact the producer went out of its
    // way to publish.
    expect(claimsOf({ claims: [limiterClaim] })).toHaveLength(1);
  });

  it("never displaces the lane of the value move it sits beside", () => {
    expect(laneForClaims({ claims: [limiterClaim, flowOut({ kind: "param", tier: "dispositive_ast" })] })).toBe("right");
    expect(laneForClaims({ claims: [limiterClaim] })).toBe("ops");
  });

  it("never becomes the primary claim over the move it limits", () => {
    const fn = { claims: [limiterClaim, flowOut({ kind: "param", tier: "dispositive_ast" })] };
    expect(primaryClaim(fn).claim_id).toBe("flow.out");
  });
});
