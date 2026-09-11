import { describe, it, expect } from "vitest";

import { CLAIM_VOCAB } from "./claimVocab.data.js";
import { laneForClaims, primaryClaim, toneForClaims } from "./claimProjection.js";
import { claimWitnessFacts } from "./witnessFacts.js";
import { qualifierForClaims } from "./claimQualifiers.js";
import { compactActionSummary } from "../surface/lane.js";
import { claim, flowOut, observedClaim } from "./testSupport.js";

describe("qualifierForClaims — flow.out destination (theft vs routing)", () => {
  it("renders (fixed destination) only for a proven immutable/constant/no-setter target", () => {
    expect(qualifierForClaims({ claims: [flowOut({ kind: "immutable", tier: "dispositive_ast" })] }))
      .toBe("(fixed destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "constant", tier: "dispositive_ast" })] }))
      .toBe("(fixed destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "storage_no_setter", tier: "static_trace" })] }))
      .toBe("(fixed destination)");
  });

  it("renders (caller-chosen destination) for param / msg_sender / caller_controlled", () => {
    expect(qualifierForClaims({ claims: [flowOut({ kind: "param", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "msg_sender", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
    // caller_controlled = tx.origin — a distinct EOA fact, same theft-shaped class.
    expect(qualifierForClaims({ claims: [flowOut({ kind: "caller_controlled", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
  });

  it("lets caller_controlled dominate a fixed path in the worst case (never reads fixed)", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [
            { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
            { kind: "y", target_kind: { kind: "caller_controlled", tier: "dispositive_ast" } },
          ],
          sink_ids: [],
        },
      }],
    };
    expect(qualifierForClaims(fn)).toBe("(caller-chosen destination)");
  });

  it("reads a several fold through its members, worst case first", () => {
    // splitPay() (AssetRecovery, corpus golden): one send to a caller argument,
    // one to an admin-settable storage slot. Both members are resolved, so the
    // fold is several — and the caller-chosen member has to dominate over the
    // setter. This is the MINTABLE shape: the producer never attaches
    // `target_constraint` to a fold, so the param member reads as
    // caller-chosen with the gate question noted, never demoted below the
    // admin-settable member.
    const oneOf = flowOut(
      { kind: "several", tier: "dispositive_ast" },
      {
        targetKinds: [
          { kind: "param", tier: "dispositive_ast" },
          { kind: "storage_setter", tier: "dispositive_ast" },
        ],
      },
    );
    expect(oneOf.witness.flows[0].target_constraint).toBeUndefined();
    expect(qualifierForClaims({ claims: [oneOf] }))
      .toBe("(caller-chosen destination; gate not analysed)");
    expect(toneForClaims({ claims: [oneOf] })).toBe("#a8746a");
  });

  it("keeps the hazard tint and reading for a param member of a several fold (the persisted shape)", () => {
    // PriorityWithdrawalQueue.claimWithdraw / batchClaimWithdraw: real local
    // rows, `target_kinds=[param, immutable]`, `target_param_index=None`, NO
    // `target_constraint` — the producer cannot mint one for a fold. The param
    // member is a PROVEN fact (the caller names one of the destinations); the
    // missing verdict answers only a secondary question, so it must render the
    // same tone chip as before the verdict field existed, never slide below
    // the tint threshold — knowing strictly less must not read strictly safer.
    const fold = flowOut(
      { kind: "several", tier: "static_trace" },
      {
        targetKinds: [
          { kind: "param", tier: "static_trace" },
          { kind: "immutable", tier: "static_trace" },
        ],
      },
    );
    expect(qualifierForClaims({ claims: [fold] }))
      .toBe("(caller-chosen destination; gate not analysed)");
    expect(toneForClaims({ claims: [fold] })).toBe("#a8746a");
  });

  it("stops calling a GATED param destination caller-chosen, and names the guard", () => {
    // The gate narrowing. `param` still means the caller NAMES the destination —
    // what changed is that a mandatory revert gate pinning that parameter is now
    // published, and the theft-shaped wording is reserved for the case where no
    // such gate exists. This is not reassurance: the qualifier says a guard was
    // proven, never that the destination is safe or fixed.
    const gated = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "constrained", guard: "mapping_allowlist", pins: true } },
    );
    expect(qualifierForClaims({ claims: [gated] })).toBe("(destination gated by a guard)");
  });

  it("keeps the caller-chosen reading when the constraint was not determined, noting the open gate", () => {
    // Only a PRESENT `constrained` verdict may soften the reading. An explicit
    // `not_determined` proves nothing in either direction, and the param fact —
    // the caller names the destination — is already proven, so the hazard
    // reading stays, with the unanswered question spelled out.
    const open = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "not_determined" } },
    );
    expect(qualifierForClaims({ claims: [open] }))
      .toBe("(caller-chosen destination; gate not analysed)");
    expect(toneForClaims({ claims: [open] })).toBe("#a8746a");
  });

  it("renders a legacy claim (no target_constraint key) with the pre-verdict tone chip", () => {
    // Regression pin. 82/82 persisted param flow destinations carry
    // no `target_constraint` today; before the verdict field existed (bf240fe9)
    // every one of them read "(caller-chosen destination)" with the hazard tint
    // #a8746a. The absent field must keep exactly that tone path — a payload
    // minted before the producer answered the question must not read SAFER than
    // it did before the question existed. Wording may note the open gate;
    // the tone chip may not move.
    const legacy = flowOut({ kind: "param", tier: "dispositive_ast" }, { constraint: null });
    expect(legacy.witness.flows[0].target_constraint).toBeUndefined();
    expect(toneForClaims({ claims: [legacy] })).toBe("#a8746a");
    expect(qualifierForClaims({ claims: [legacy] }))
      .toBe("(caller-chosen destination; gate not analysed)");
  });

  it("keeps msg_sender / caller_controlled unconditional — they ask no such question", () => {
    // The destination IS the caller, provably. There is no parameter for a gate
    // to pin, so no verdict is attached and none is required.
    expect(qualifierForClaims({ claims: [flowOut({ kind: "msg_sender", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
    expect(qualifierForClaims({ claims: [flowOut({ kind: "caller_controlled", tier: "dispositive_ast" })] }))
      .toBe("(caller-chosen destination)");
  });

  it("never reads a gated or undetermined param path as (fixed destination)", () => {
    for (const constraint of [{ state: "constrained", guard: "hash_commitment", pins: true }, { state: "not_determined" }]) {
      const fn = {
        claims: [{
          claim_id: "flow.out",
          tier: "standard_exact",
          witness: {
            kind: "value_flow",
            direction: "out",
            flows: [
              { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
              { kind: "y", target_kind: { kind: "param", tier: "dispositive_ast" }, target_constraint: constraint },
            ],
            sink_ids: [],
          },
        }],
      };
      expect(qualifierForClaims(fn)).not.toBe("(fixed destination)");
    }
  });

  it("drops the hazard tint only for a PROVEN pinning guard — an undetermined one keeps it", () => {
    // The one state that softens: a present `constrained` verdict whose guard
    // provably pins. `not_determined` proves nothing and keeps the hazard tint
    // — the calm tint stays off in both cases: neither is
    // proven-fixed.
    const base = CLAIM_VOCAB["flow.out"].tone;
    const gated = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "constrained", guard: "equality_vs_storage", pins: true } },
    );
    const open = flowOut({ kind: "param", tier: "dispositive_ast" }, { constraint: { state: "not_determined" } });
    expect(toneForClaims({ claims: [gated] })).toBe(base);
    expect(toneForClaims({ claims: [open] })).toBe("#a8746a");
    expect(toneForClaims({ claims: [gated] })).not.toBe("#8f947a");
    expect(toneForClaims({ claims: [open] })).not.toBe("#8f947a");
  });

  it("keeps the caller-chosen wording AND the hazard tint for a proven non-pinning guard (denylist)", () => {
    // The producer proved a guard exists and proved it does NOT
    // pin (pins: false): the destination is freely chosen outside an excluded
    // set. That IS the theft-shaped fact — the chip and the tint must read
    // exactly like the unguarded case, with the guard spelled out in the
    // inspector row, not laundered into "(destination gated by a guard)".
    const denied = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "constrained", guard: "denylist", pins: false, binding: "operand" } },
    );
    expect(qualifierForClaims({ claims: [denied] })).toBe("(caller-chosen destination)");
    expect(toneForClaims({ claims: [denied] })).toBe("#a8746a");
  });

  it("keeps the hazard tint when the guard's pinning is NOT proven (the 4 real external_call_revert rows)", () => {
    // EtherFiRedemptionManager.redeem*: receiver is gated by an external
    // nonBlacklisted(address) view call — a blacklist, structurally identical
    // here to an allowlist. pins is null: not proven either way. Absence of a
    // pinning proof must not soften the reading (the governing rule), so the
    // tint stays at the hazard end and the wording claims only what was proven.
    const checked = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "constrained", guard: "external_call_revert", pins: null, binding: "operand", leaf_path: [28] } },
    );
    expect(qualifierForClaims({ claims: [checked] })).toBe("(destination checked; pinning not proven)");
    expect(toneForClaims({ claims: [checked] })).toBe("#a8746a");
    // A legacy constrained verdict with NO pins key reads the same way.
    const legacy = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "constrained", guard: "external_call_revert", binding: "operand" } },
    );
    expect(qualifierForClaims({ claims: [legacy] })).toBe("(destination checked; pinning not proven)");
    expect(toneForClaims({ claims: [legacy] })).toBe("#a8746a");
  });

  it("keeps the hazard tint for a guard bound through flow-insensitive provenance (derived_from)", () => {
    // `derived_from` is a union over branches — `address t =
    // defaultTo; if (cond) t = to;` binds `to` on one branch only, and the
    // artifact cannot tell the branches apart. The producer therefore mints
    // pins: null on every derived_from binding, and the chip must read
    // "checked", never "gated", with the tint at the hazard end.
    const committed = flowOut(
      { kind: "param", tier: "dispositive_ast" },
      { constraint: { state: "constrained", guard: "hash_commitment", pins: null, binding: "derived_from", leaf_path: [0] } },
    );
    expect(qualifierForClaims({ claims: [committed] })).toBe("(destination checked; pinning not proven)");
    expect(toneForClaims({ claims: [committed] })).toBe("#a8746a");
  });

  it("does not let a several fold promote a GATED param member to caller-chosen", () => {
    // Same fold, one verdict: the flow's destination parameter is pinned by a
    // mandatory gate. The admin-settable member is then the worst thing left,
    // and it must win — reading the param member as caller-chosen would restate
    // the exact over-claim the constraint verdict exists to remove.
    // DEFENSIVE ARM: the verdict is injected explicitly — today's producer
    // never mints one on a fold (the mintable no-verdict fold is pinned
    // above); this pins the softening path should a fold ever carry one.
    const oneOf = flowOut(
      { kind: "several", tier: "dispositive_ast" },
      {
        targetKinds: [
          { kind: "param", tier: "dispositive_ast" },
          { kind: "storage_setter", tier: "dispositive_ast" },
        ],
        constraint: { state: "constrained", guard: "mapping_allowlist", pins: true },
      },
    );
    expect(qualifierForClaims({ claims: [oneOf] })).toBe("(admin-settable destination)");
  });

  it("reads a several of admin-settable and fixed members as admin-settable", () => {
    const oneOf = flowOut(
      { kind: "several", tier: "dispositive_ast" },
      {
        targetKinds: [
          { kind: "immutable", tier: "dispositive_ast" },
          { kind: "storage_setter", tier: "dispositive_ast" },
        ],
      },
    );
    expect(qualifierForClaims({ claims: [oneOf] })).toBe("(admin-settable destination)");
  });

  it("never reads a several as fixed when its members are not readable", () => {
    // A several with no member list is an artifact we cannot interpret; it must
    // block a "fixed" claim rather than disappear from the tally.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [
            { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
            { kind: "y", target_kind: { kind: "several", tier: "dispositive_ast" } },
          ],
          sink_ids: [],
        },
      }],
    };
    expect(qualifierForClaims(fn)).toBeNull();
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

  it("reads token_owner as neither caller-chosen nor fixed", () => {
    // The caller names the token id, not the payee, so it is not theft-shaped —
    // but an NFT transfer repoints it, so it is not a proven-fixed destination
    // either. It must also block a sibling fixed flow from claiming "fixed".
    expect(qualifierForClaims({ claims: [flowOut({ kind: "token_owner", tier: "static_trace" })] })).toBeNull();
    const mixed = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [
            { kind: "x", target_kind: { kind: "immutable", tier: "dispositive_ast" } },
            { kind: "y", target_kind: { kind: "token_owner", tier: "static_trace" } },
          ],
          sink_ids: [],
        },
      }],
    };
    expect(qualifierForClaims(mixed)).toBeNull();
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
            {
              kind: "y",
              target_kind: { kind: "param", tier: "dispositive_ast" },
              target_constraint: { state: "unconstrained_proven" },
            },
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

  it("renders (indefinite) only when static PROVED the latch reads no clock", () => {
    // INVERTED. This used to assert "(indefinite)" for null/null alone, which
    // made the most severe freeze statement the DEFAULT for an unread window. All
    // four proven freeze_pause verdicts in production are `pauseUntil` — a latch
    // that expires — and every one of them rendered "(indefinite)".
    const proven = {
      claims: [observedClaim("pause.set", {
        auto_expiry: null,
        duration_bound_seconds: null,
        duration_bound_source: "no_time_reference",
      })],
    };
    expect(qualifierForClaims(proven)).toBe("(indefinite)");
  });

  it("suppresses (indefinite) when the freeze window was merely not determined", () => {
    const notDetermined = {
      claims: [observedClaim("pause.set", {
        auto_expiry: null,
        duration_bound_seconds: null,
        duration_bound_source: "not_determined",
      })],
    };
    expect(qualifierForClaims(notDetermined)).toBeNull();
    // ...and the same for an older verdict, whose witness carries no source at all.
    const legacy = {
      claims: [observedClaim("pause.set", { auto_expiry: null, duration_bound_seconds: null })],
    };
    expect(qualifierForClaims(legacy)).toBeNull();
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

  // CONTAINMENT PIN, prose half. `duration_bound_seconds` is a STATIC read of a
  // guard constant, and the harvest that produced it was once side- and
  // operator-blind: `require(block.timestamp + 3600 < pausedUntil)` published 3600 —
  // a lead time — as the freeze window. What kept that number off every rendered
  // surface is the fork cross-check: BOTH prose copies show a bound only when
  // `auto_expiry === true`. That containment is load-bearing, so it is pinned
  // exhaustively over the qualifier's states rather than by one example — a future
  // edit that renders a bound on `auto_expiry` false/null/absent re-opens it.
  const NON_AFFIRMED = [
    ["false — the fork contradicted the bound", false],
    ["null — the probe did not run", null],
    ["absent — a witness with no qualifier at all", undefined],
  ];

  it.each(NON_AFFIRMED)("shows no bound in the pause QUALIFIER when auto_expiry is %s", (_label, expiry) => {
    const observed = { duration_bound_seconds: 3600, duration_bound_source: "guard_constant" };
    if (expiry !== undefined) observed.auto_expiry = expiry;
    const rendered = qualifierForClaims({ claims: [observedClaim("pause.set", observed)] });
    expect(rendered === null || !/3600|1h|auto-expires/.test(rendered)).toBe(true);
  });

  it.each(NON_AFFIRMED)("shows no bound in the INSPECTOR facts when auto_expiry is %s", (_label, expiry) => {
    const observed = { duration_bound_seconds: 3600, duration_bound_source: "guard_constant" };
    if (expiry !== undefined) observed.auto_expiry = expiry;
    const facts = claimWitnessFacts({ claims: [observedClaim("pause.set", observed)] });
    const expiryFacts = facts.filter((f) => f.label === "Auto-expiry");
    for (const fact of expiryFacts) expect(fact.value).not.toMatch(/self-recovers|1h|3600/);
    // The proven-indefinite sentence is the most severe statement here and must not be
    // borrowed either: a bound WAS read, so the latch is not proven indefinite.
    for (const fact of expiryFacts) expect(fact.value).not.toContain("indefinite latch");
  });

  it("still shows the bound in both copies once the fork affirms it", () => {
    // POSITIVE CONTROL for the two pins above: the containment is a discrimination,
    // not a blanket refusal.
    const observed = { auto_expiry: true, duration_bound_seconds: 3600, duration_bound_source: "guard_constant" };
    const fn = { claims: [observedClaim("pause.set", observed)] };
    expect(qualifierForClaims(fn)).toBe("(auto-expires ~1h)");
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Auto-expiry",
      value: "self-recovers after ~1h",
    });
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

describe("qualifierForClaims — wrap-shape backing on the chip (register #10)", () => {
  // A wrap carries flow.in + supply.mint (both priority 6); primaryClaim
  // tie-breaks to flow.in, so the backing witness must be promoted onto the
  // value-in chip or it would only ever show in the inspector.
  const wrap = (observed) => ({
    claims: [claim("flow.in"), observedClaim("supply.mint", observed)],
  });

  it("promotes (backed) onto the value-in chip when the co-mint is backed", () => {
    const fn = wrap({ backing: { inflow_observed: true, minted: true } });
    expect(primaryClaim(fn).claim_id).toBe("flow.in");
    expect(qualifierForClaims(fn)).toBe("(backed)");
    expect(compactActionSummary(fn)).toBe("moves value in (backed)");
  });

  it("promotes (unbacked) onto the value-in chip for a witnessed dilution", () => {
    const fn = wrap({ backing: { inflow_observed: false, minted: true } });
    expect(qualifierForClaims(fn)).toBe("(unbacked)");
    expect(compactActionSummary(fn)).toBe("moves value in (unbacked)");
  });

  it("suppresses when the co-mint carries no backing witness (unknown, not backed)", () => {
    expect(qualifierForClaims(wrap({}))).toBeNull();
    expect(compactActionSummary(wrap({}))).toBe("moves value in");
  });

  it("leaves a plain inflow (no mint) unqualified", () => {
    expect(qualifierForClaims({ claims: [claim("flow.in")] })).toBeNull();
    expect(compactActionSummary({ claims: [claim("flow.in")] })).toBe("moves value in");
  });

  it("does not change pure-mint-primary behavior (no flow.in present)", () => {
    const fn = { claims: [observedClaim("supply.mint", { backing: { inflow_observed: true } })] };
    expect(primaryClaim(fn).claim_id).toBe("supply.mint");
    expect(qualifierForClaims(fn)).toBe("(backed)");
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

describe("qualifierForClaims — exec.arbitrary target constraint", () => {
  const execArb = (destination_constraint) => ({
    claim_id: "exec.arbitrary",
    tier: "idiom_structural",
    witness: {
      kind: "param_taint",
      sink_ids: ["s0"],
      destination_param: "target",
      destination_kind: "param",
      ...(destination_constraint ? { destination_constraint } : {}),
    },
  });

  it("leaves the sentence alone when the target is provably unconstrained", () => {
    // The 11 of 20 production rows the audit found genuinely arbitrary: the
    // claim already says it, and a qualifier would be noise.
    expect(qualifierForClaims({ claims: [execArb({ state: "unconstrained_proven" })] })).toBeNull();
  });

  it("names the guard when a mandatory gate pins the target", () => {
    // EtherFiNodesManager.forwardExternalCall: a three-level allowlist keyed on
    // (msg.sender, selector, target). The claim still fires — a forwarded call
    // IS happening — but "arbitrary" overstates it, and this is where the
    // qualification is visible.
    expect(qualifierForClaims({ claims: [execArb({ state: "constrained", guard: "mapping_allowlist", pins: true })] }))
      .toBe("(target gated by mapping_allowlist)");
  });

  it("leaves the arbitrary sentence standing for a proven non-pinning target guard", () => {
    // pins: false (a denylist) proves the target is freely chosen outside an
    // excluded set — the claim's own sentence is accurate as written, so no
    // softening qualifier appears; the inspector row carries the guard.
    expect(qualifierForClaims({ claims: [execArb({ state: "constrained", guard: "denylist", pins: false })] }))
      .toBeNull();
  });

  it("never reads an unproven-pinning target guard as gated", () => {
    // external_call_revert with pins null/absent (forwardExternalCall's
    // deployedEtherFiNodes check has this shape): a real guard, set semantics
    // unknown. "gated by" is reserved for a proven pin.
    expect(qualifierForClaims({ claims: [execArb({ state: "constrained", guard: "external_call_revert", pins: null })] }))
      .toBe("(target checked; pinning not proven)");
    expect(qualifierForClaims({ claims: [execArb({ state: "constrained", guard: "external_call_revert" })] }))
      .toBe("(target checked; pinning not proven)");
  });

  it("says not-determined for an open question and for an absent verdict", () => {
    expect(qualifierForClaims({ claims: [execArb({ state: "not_determined" })] }))
      .toBe("(target constraint not determined)");
    expect(qualifierForClaims({ claims: [execArb(null)] }))
      .toBe("(target constraint not determined)");
  });
});

describe("delegatecall.execute — where the foreign code comes from", () => {
  const dc = (destination) => ({
    claim_id: "delegatecall.execute",
    tier: "idiom_structural",
    witness: { kind: "delegatecall_sink", sink_ids: ["s0"], destination },
  });

  it("names an admin-settable destination as the capability it is", () => {
    expect(qualifierForClaims({ claims: [dc({ target_kind: "storage_setter", variable: "module" })] }))
      .toBe("(target is admin-settable storage)");
  });

  it("reads a multi-site union destination by its agreed kind", () => {
    // Two sites agreeing on storage_setter publish the union (plural
    // `variables`, merged writers, no singular `variable`); the qualifier binds
    // target_kind alone, so the union shape renders the same — and truthfully,
    // since the kind now holds across every site rather than the first seen.
    const union = {
      target_kind: "storage_setter",
      sites: 2,
      variables: ["module", "sideModule"],
      writer_signatures: ["setModule(address)", "setSideModule(address)"],
    };
    expect(qualifierForClaims({ claims: [dc(union)] })).toBe("(target is admin-settable storage)");
  });

  it("does not read a caller-keyed mapping element as settable OR as fixed", () => {
    const q = qualifierForClaims({ claims: [dc({ target_kind: "indeterminate", reason: "mapping_or_array_element" })] });
    expect(q).toBe("(target not determined)");
    expect(q).not.toContain("settable");
    expect(q).not.toContain("immutable");
  });

});
