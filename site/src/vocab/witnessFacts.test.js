import { describe, it, expect } from "vitest";

import { claimSummaryLine, toneForClaims } from "./claimProjection.js";
import { qualifierForClaims } from "./claimQualifiers.js";
import { claimWitnessFacts } from "./witnessFacts.js";
import { compactActionSummary } from "../surface/lane.js";
import { claim, flowOut, observedClaim } from "./testSupport.js";

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

  it("labels a caller_controlled destination honestly as caller (tx.origin)", () => {
    const fn = { claims: [flowOut({ kind: "caller_controlled", tier: "dispositive_ast" })] };
    expect(claimWitnessFacts(fn)).toContainEqual({ label: "Destination", value: "caller (tx.origin) · dispositive AST" });
  });

  it("words a token_owner destination and a balance_delta amount", () => {
    const fn = {
      claims: [flowOut(
        { kind: "token_owner", tier: "static_trace" },
        { amountKind: { kind: "balance_delta", tier: "static_trace" } },
      )],
    };
    const facts = claimWitnessFacts(fn);
    // Both must render as prose, not leak the raw enum through the fallback.
    expect(facts).toContainEqual({ label: "Destination", value: "the token's current owner · static trace" });
    expect(facts).toContainEqual({ label: "Amount", value: "a balance delta · static trace" });
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

  it("labels a PROVEN indefinite latch honestly", () => {
    const facts = claimWitnessFacts({
      claims: [observedClaim("pause.set", {
        auto_expiry: null,
        duration_bound_seconds: null,
        duration_bound_source: "no_time_reference",
      })],
    });
    expect(facts).toContainEqual({ label: "Auto-expiry", value: "indefinite latch (no self-recovery bound)" });
  });

  it("labels an unread freeze window as not determined, not as indefinite", () => {
    // INVERTED: the sentence above is the most severe statement this inspector
    // makes and it was being produced from an extraction failure. The etherfi shape
    // (a timestamp latch whose window is a storage value) is this case.
    for (const observed of [
      { auto_expiry: null, duration_bound_seconds: null, duration_bound_source: "not_determined" },
      { auto_expiry: null, duration_bound_seconds: null }, // older verdict: no source key
    ]) {
      const facts = claimWitnessFacts({ claims: [observedClaim("pause.set", observed)] });
      expect(facts).toContainEqual({ label: "Auto-expiry", value: "window not determined" });
      expect(facts).not.toContainEqual({
        label: "Auto-expiry",
        value: "indefinite latch (no self-recovery bound)",
      });
    }
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

  it("names an unmeasured reach as not determined and the balance as a floor", () => {
    // INVERTED. The producer used to publish the acting contract's own balance
    // as `observed_reach_value_usd` on this branch, so the row read as a measured
    // reach with a flag beside it; on a zero-balance router that is "$0 reach" for a
    // function that may move millions. The number now arrives as a FLOOR under its
    // own key, and the row says it was not determined.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: {
            reach_indeterminate: true,
            reach_determined: false,
            observed_reach_floor_usd: 999,
          },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "not determined (own balance floor up to ~$999)",
    });
  });

  it("states the destination even when the static matcher produced no flows", () => {
    // The approve-then-pull shape: reach renders, `flows` is empty, and the inspector
    // used to say NOTHING about the destination — the worst combination available
    // beside a $472M figure.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 170,
          observed: {
            observed_reach_value_usd: 472_190_234.24,
            reach_determined: true,
            destination_shape: "unknown",
            shape_proved_by: "none",
          },
        },
      }],
    };
    const facts = claimWitnessFacts(fn);
    expect(facts).toContainEqual({
      label: "Destination",
      value: "not determined (no static classification, no sentinel landed)",
    });
    expect(facts).toContainEqual({ label: "Reach (upper bound)", value: "up to ~$472.2M" });
  });

  it("renders a fork-proven caller-chosen destination on the chip and in the facts", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: { destination_shape: "caller_arbitrary", shape_proved_by: "simulation" },
        },
      }],
    };
    expect(qualifierForClaims(fn)).toBe("(caller-chosen destination)");
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Destination",
      value: "caller-chosen (a sentinel address received the outflow)",
    });
  });

  it("keeps the static lattice in charge when it has an answer", () => {
    // The observed shape must not override a static destination row: the static
    // lattice is a universal about the code and the observation is one execution.
    const fn = {
      claims: [
        flowOut({ kind: "immutable", tier: "dispositive_ast" }),
        {
          claim_id: "flow.out",
          tier: "behavioral_observed",
          witness: { effect_verdict_id: 1, observed: { destination_shape: "unknown", shape_proved_by: "none" } },
        },
      ],
    };
    const dest = claimWitnessFacts(fn).filter((f) => f.label === "Destination");
    expect(dest).toHaveLength(1);
    expect(dest[0].value).toContain("immutable");
  });

  it("shows a TVL-refused reach as refused, never as the number", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: {
            reach_determined: false,
            reach_tvl_check: "exceeds_protocol_tvl",
            observed_reach_rejected_usd: 3_488_955_156.06,
            protocol_tvl_usd: 3_297_344_734,
          },
        },
      }],
    };
    const facts = claimWitnessFacts(fn);
    expect(facts).toContainEqual({
      label: "Reach",
      value: "not determined (measured figure exceeded protocol TVL and was refused)",
    });
    // The rejected figure must not also render as a reach.
    expect(JSON.stringify(facts)).not.toContain("3.5B");
  });

  it("keeps the unvalued-asset disclosure when the ceiling refuses the priced floor", () => {
    // The producer now applies the ceiling to the PARTIAL-FLOOR branch, so a row
    // can carry both facts at once — assets moved whose value is unknown, AND a
    // priced part the protocol's own TVL contradicts. They are independent, and
    // the refusal must not swallow the disclosure.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: {
            reach_determined: false,
            observed_reach_unvalued_pairs: [
              { holder: "0x" + "c0".repeat(20), asset: "0x" + "ee".repeat(20), reason: "asset_not_in_recorded_holdings" },
            ],
            observed_reach_unvalued_assets: ["0x" + "ee".repeat(20)],
            observed_reach_unvalued_reasons: ["asset_not_in_recorded_holdings"],
            reach_tvl_check: "exceeds_protocol_tvl",
            observed_reach_rejected_usd: 3_488_955_156.06,
            observed_reach_priced_holders: ["0x" + "c0".repeat(20)],
            protocol_tvl_usd: 3_297_344_734,
          },
        },
      }],
    };
    const reach = claimWitnessFacts(fn).filter((f) => f.label === "Reach");
    expect(reach).toHaveLength(1);
    expect(reach[0].value).toContain("1 holder/asset pair(s) of unknown value");
    expect(reach[0].value).toContain("refused");
    // Still never the number.
    expect(reach[0].value).not.toContain("3.5B");
  });

  it("names a witnessed-but-unvalued reach as its own state", () => {
    // Value WAS observed leaving a holder, in an asset whose USD we do not have —
    // the weETH recoverETH shape (a synthetic native move out of a deployment with
    // no native balance row). Neither a reach figure nor a floor on own balance:
    // this row used to publish the holder's whole sheet, $3.489B, as the reach.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: {
            reach_determined: false,
            observed_reach_holders: ["0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee"],
            observed_reach_assets: ["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],
            observed_reach_unvalued_pairs: [
              {
                holder: "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee",
                asset: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                reason: "asset_not_in_recorded_holdings",
              },
            ],
            observed_reach_unvalued_assets: ["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],
          },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "value not determined — 1 holder/asset pair(s) of unknown value",
    });
  });

  it("shows the priced part of an unvalued reach as a partial floor, with its holders", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: {
            reach_determined: false,
            observed_reach_unvalued_pairs: [
              { holder: "0x" + "c0".repeat(20), asset: "0x" + "9d".repeat(20), reason: "unpriced_holding" },
            ],
            observed_reach_unvalued_assets: ["0x" + "9d".repeat(20)],
            observed_reach_priced_usd: 759.15,
            observed_reach_priced_holders: ["0x" + "c0".repeat(20)],
          },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "value not determined — 1 holder/asset pair(s) of unknown value, priced part up to ~$759 across 1 holder(s)",
    });
  });

  it("does not present a priced part as if it covered the assets it names", () => {
    // PR-161 verdict 198 (PriorityWithdrawalQueue.requestWithdrawWithWeETH): weETH
    // left TWO holders, only the BoringVault has a weETH balance row. The producer
    // published weETH as the ONLY asset that moved AND the ONLY asset that could not
    // be valued, beside observed_reach_priced_usd: 8,471,736.29 — the vault's row.
    // This renderer read the asset-keyed set at face value and printed "1 asset(s) of
    // unknown value, priced part up to ~$8.5M", i.e. a second priced asset that does
    // not exist. Keyed per pair, the sentence is about the pair that is unknown and
    // the holder the figure came from.
    const queue = "0x35e7d6fef6f72add3c3e39dec6d9ccc29e3345fa";
    const vault = "0xf0bb20865277abd641a307ece5ee04e79073416c";
    const weeth = "0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee";
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 198,
          observed: {
            reach_determined: false,
            observed_reach_holders: [queue, vault],
            observed_reach_assets: [weeth],
            observed_reach_unvalued_pairs: [
              { holder: queue, asset: weeth, reason: "asset_not_in_recorded_holdings" },
            ],
            // Earned empty: weETH IS priced, for the vault.
            observed_reach_unvalued_assets: [],
            observed_reach_priced_usd: 8_471_736.29,
            observed_reach_priced_holders: [vault],
            reach_tvl_check: "within_protocol_tvl",
          },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "value not determined — 1 holder/asset pair(s) of unknown value, priced part up to ~$8.5M across 1 holder(s)",
    });
  });

  it("shows a pre-fix asset-keyed payload's priced part as unattributed", () => {
    // Rows written before the pair keying carry only the asset-level set, and their
    // figure cannot be tied to any holder — the renderer says so instead of implying
    // the named assets are what was priced.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: {
            reach_determined: false,
            observed_reach_unvalued_assets: ["0x" + "9d".repeat(20)],
            observed_reach_priced_usd: 759.15,
          },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "value not determined — 1 asset(s) of unknown value, priced part up to ~$759 (holder attribution not recorded)",
    });
  });

  it("says not determined with no number when the floor itself is zero", () => {
    // The zero-balance router: the floor is a real 0 and must not be dressed up as
    // a reach figure, nor suppressed into silence that reads as "no reach".
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: { reach_indeterminate: true, reach_determined: false, observed_reach_floor_usd: 0 },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "not determined (no downstream holder observed)",
    });
  });

  it("renders a MEASURED $0 reach as a measured zero, not as silence", () => {
    // `formatUsdUpperBound(0)` is falsy, so a reach measured at exactly $0
    // — every asset that moved had a priced holding and the total came out at
    // nothing — emitted no Reach row at all, which is what a never-attempted reach
    // emits. The backend payload is already pinned correct by
    // test_zero_reach_without_the_flag_is_a_measured_zero_not_a_floor.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: { reach_determined: true, observed_reach_value_usd: 0 },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach",
      value: "$0 — measured, no priced value reachable",
    });
  });

  it("keeps a measured non-zero reach as the upper-bound row", () => {
    // POSITIVE CONTROL: the measured branch must not have changed the wording of
    // every real figure.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          observed: { reach_determined: true, observed_reach_value_usd: 55_200_000 },
        },
      }],
    };
    expect(claimWitnessFacts(fn)).toContainEqual({ label: "Reach (upper bound)", value: "up to ~$55.2M" });
  });

  it("stays silent on an OLDER payload whose reach figure is zero", () => {
    // NEGATIVE CONTROL. Without `reach_determined` a 0 may be the acting
    // deployment's own (zero) balance published as the reach — the exact
    // "$0 reach for a function that may move millions" sentence the floor key
    // removed — so
    // this renderer must not assert a measurement it cannot see.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: { effect_verdict_id: 1, observed: { observed_reach_value_usd: 0 } },
      }],
    };
    expect(claimWitnessFacts(fn).some((f) => String(f.label).startsWith("Reach"))).toBe(false);
  });

  it("emits no rows when no witness facts are present (silence, not defaults)", () => {
    expect(claimWitnessFacts({ claims: [claim("flow.out")] })).toEqual([]);
    expect(claimWitnessFacts({ claims: [claim("ownership.transfer")] })).toEqual([]);
    expect(claimWitnessFacts({})).toEqual([]);
  });

  // The per-site breakdown: a fold that reads "indeterminate" only because its
  // sites disagreed must show what those sites actually were.
  it("names both destinations instead of the fold when the sites disagreed", () => {
    const fn = {
      claims: [flowOut({ kind: "indeterminate", tier: "static_trace" }, {
        targetKinds: [
          { kind: "token_owner", tier: "static_trace" },
          { kind: "immutable", tier: "dispositive_ast" },
        ],
        amountKind: { kind: "indeterminate", tier: "static_trace" },
        amountKinds: [
          { kind: "indeterminate", tier: "static_trace" },
          { kind: "balance_delta", tier: "static_trace" },
        ],
      })],
    };
    const facts = claimWitnessFacts(fn);
    expect(facts).toContainEqual({
      label: "Destination",
      value: "2 sites: the token's current owner · static trace / immutable address · dispositive AST",
    });
    // An unresolved site stays visible as unresolved — the row explains the
    // fold, it never launders it into something more settled.
    expect(facts).toContainEqual({
      label: "Amount",
      value: "2 sites: indeterminate · static trace / a balance delta · static trace",
    });
  });

  it("keeps the folded row when there is no breakdown", () => {
    const fn = { claims: [flowOut({ kind: "indeterminate", tier: "static_trace" })] };
    expect(claimWitnessFacts(fn)).toContainEqual({ label: "Destination", value: "indeterminate · static trace" });
  });

  it("caps a pathological site list and still states the true total", () => {
    const sites = ["immutable", "param", "msg_sender", "storage_setter", "self", "token_owner"].map((kind) => ({
      kind,
      tier: "static_trace",
    }));
    const fn = {
      claims: [flowOut({ kind: "indeterminate", tier: "static_trace" }, { targetKinds: sites })],
    };
    const value = claimWitnessFacts(fn).find((f) => f.label === "Destination").value;
    expect(value).toMatch(/^6 sites: /);
    expect(value).toContain("+2 more");
    expect(value).not.toContain("the token's current owner");
  });

  it("leaves the chip and the tone on the FOLD, never a single site", () => {
    // A caller-supplied site inside a disagreeing fold must not promote the chip
    // to "(caller-chosen destination)" — the fold never reached that verdict.
    const fn = {
      claims: [flowOut({ kind: "indeterminate", tier: "static_trace" }, {
        targetKinds: [
          { kind: "param", tier: "dispositive_ast" },
          { kind: "immutable", tier: "static_trace" },
        ],
      })],
    };
    expect(qualifierForClaims(fn)).toBeNull();
    expect(toneForClaims(fn)).toBe(toneForClaims({ claims: [claim("flow.out")] }));
  });
});

describe("claimWitnessFacts — destination constraint row", () => {
  it("spells out the guard, and marks a flow-insensitive binding as one", () => {
    // The producer never mints `pins: true` on a `derived_from` binding — the
    // provenance is flow-insensitive, so the guard is real but whether it
    // confines THIS parameter is not proven. The row must carry both the
    // binding and the not-proven caveat, and never read as "gated by".
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [{
            kind: "callee_erc20_selector",
            target_kind: { kind: "param", tier: "dispositive_ast" },
            target_constraint: { state: "constrained", guard: "hash_commitment", pins: null, binding: "derived_from" },
          }],
          sink_ids: [],
        },
      }],
    };
    const row = claimWitnessFacts(fn).find((f) => f.label === "Destination constraint");
    expect(row.value).toContain("a hash commitment in storage");
    expect(row.value).toContain("argument provenance");
    expect(row.value).toContain("whether it pins the destination is not proven");
    expect(row.value).not.toContain("gated by");
  });

  it("renders a denylist as one that pins nothing", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [{
            kind: "x",
            target_kind: { kind: "param", tier: "dispositive_ast" },
            target_constraint: { state: "constrained", guard: "denylist", pins: false, binding: "operand" },
          }],
          sink_ids: [],
        },
      }],
    };
    const row = claimWitnessFacts(fn).find((f) => f.label === "Destination constraint");
    expect(row.value).toContain("checked by a denylist");
    expect(row.value).toContain("does NOT pin the destination");
  });

  it("never renders 'gated by' for a constrained verdict whose pins is absent", () => {
    // A payload minted before `pins` existed carries a real guard whose set
    // semantics are unknown here. Absence of the pinning proof must not become
    // the proof: the row reads "checked by", with the caveat.
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: {
          kind: "value_flow",
          direction: "out",
          flows: [{
            kind: "x",
            target_kind: { kind: "param", tier: "dispositive_ast" },
            target_constraint: { state: "constrained", guard: "external_call_revert", binding: "operand" },
          }],
          sink_ids: [],
        },
      }],
    };
    const row = claimWitnessFacts(fn).find((f) => f.label === "Destination constraint");
    expect(row.value).toContain("checked by another contract's revert surface");
    expect(row.value).toContain("whether it pins the destination is not proven");
    expect(row.value).not.toContain("gated by");
  });

  it("emits NO row when the verdict is absent (says nothing rather than implying a proof)", () => {
    const fn = { claims: [{
      claim_id: "flow.out",
      tier: "standard_exact",
      witness: {
        kind: "value_flow",
        direction: "out",
        flows: [{ kind: "x", target_kind: { kind: "param", tier: "dispositive_ast" } }],
        sink_ids: [],
      },
    }] };
    expect(claimWitnessFacts(fn).find((f) => f.label === "Destination constraint")).toBeUndefined();
  });
});

describe("synthesis qualifiers — a seeded verdict never renders as a live one", () => {
  // `input_seeded` / `contract_balance_seeded` travel on the behavioral witness
  // and both weaken it (services/effects/recipes.py `value_out`). Before this the
  // renderer received them and said nothing: 13 verdicts in the PR-161 corpus
  // showed a measured "Reach (upper bound)" figure, and 2 showed a proven outflow
  // whose payout only executed once the contract's own balance was overridden,
  // with the same sentence and the same "observed" provenance word as a verdict
  // witnessed in live state.
  function outflow(observed, extra = {}) {
    return {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: {
          effect_verdict_id: 1,
          direction: "out",
          flows: [{ target_kind: { kind: "msg_sender" } }],
          observed: { reach_determined: true, observed_reach_value_usd: 55_200_000, ...observed },
          ...extra,
        },
      }],
    };
  }

  // The exact rendering of the SAME payload with no qualifier — the byte-identical
  // control every arm below is diffed against.
  const UNSEEDED_FACTS = [
    { label: "Destination", value: "msg.sender (the caller)" },
    { label: "Reach (upper bound)", value: "up to ~$55.2M" },
  ];
  const UNSEEDED_ACTION = "moves value out (caller-chosen destination)";
  const UNSEEDED_LABEL = "moves value out (caller-chosen destination) · observed";

  it("cross-claim dominance: the funded-only clause wins over a sibling's seeded-inputs clause in either order", () => {
    // Two sibling outflow claims seeded differently: one input_seeded-only, one
    // contract_balance_seeded. The fact line built across both must carry the
    // strictly weaker "only if the contract were funded" clause regardless of
    // claim order — the short-circuit in seedClauseForClaims must key on the
    // CONTRACT_BALANCE clause, not merely on the first clause found.
    const inputOnly = outflow({ input_seeded: true }).claims[0];
    const funded = outflow({ contract_balance_seeded: true }).claims[0];
    for (const claims of [[inputOnly, funded], [funded, inputOnly]]) {
      const facts = claimWitnessFacts({ claims });
      const reach = facts.find((f) => f.label.startsWith("Reach"));
      expect(reach.value).toContain("only if the contract were funded");
      expect(reach.value).not.toContain("with seeded inputs");
    }
  });

  it("renders an unseeded verdict exactly as before — absent AND explicitly false", () => {
    // Absence is contractually "no seeding was needed" (claims_bridge.py), and an
    // explicit `false` is the same statement said out loud. Neither may produce a
    // clause, so both must be byte-identical to the pre-change rendering.
    for (const observed of [{}, { input_seeded: false, contract_balance_seeded: false }]) {
      const fn = outflow(observed);
      expect(claimWitnessFacts(fn)).toEqual(UNSEEDED_FACTS);
      expect(compactActionSummary(fn)).toBe(UNSEEDED_ACTION);
      expect(claimSummaryLine(fn).label).toBe(UNSEEDED_LABEL);
    }
  });

  it("discloses seeded inputs on the reach line, the sentence and the tier word", () => {
    const fn = outflow({ input_seeded: true });
    expect(claimWitnessFacts(fn)).toEqual([
      { label: "Destination", value: "msg.sender (the caller)" },
      { label: "Reach (upper bound)", value: "up to ~$55.2M; with seeded inputs" },
    ]);
    expect(compactActionSummary(fn)).toBe(
      "moves value out (caller-chosen destination; with seeded inputs)",
    );
    expect(claimSummaryLine(fn).label).toBe(
      "moves value out (caller-chosen destination; with seeded inputs) · observed (seeded)",
    );
  });

  it("gives contract_balance_seeded its own capability wording, and lets it dominate", () => {
    // The producer's semantics differ in kind: this verdict means "would move
    // value IF THE CONTRACT WERE FUNDED", not "moves value in current state", so
    // it must not share the input-seeding phrase. Both flags together is the
    // corpus shape (verdicts 180 / 242) and the weaker reading wins.
    const only = outflow({ contract_balance_seeded: true });
    const both = outflow({ input_seeded: true, contract_balance_seeded: true });
    for (const fn of [only, both]) {
      expect(claimWitnessFacts(fn)).toContainEqual({
        label: "Reach (upper bound)",
        value: "up to ~$55.2M; only if the contract were funded",
      });
      expect(compactActionSummary(fn)).toBe(
        "moves value out (caller-chosen destination; only if the contract were funded)",
      );
      expect(claimSummaryLine(fn).label).toBe(
        "moves value out (caller-chosen destination; only if the contract were funded) · observed (seeded)",
      );
    }
  });

  it("qualifies a reach line that carries no figure, and one with no other qualifier", () => {
    // The corpus's two contract-balance-seeded rows (recoverETH) land on the
    // unvalued branch, so the clause has to reach every reach branch — not only
    // the measured one.
    const unvalued = outflow({
      reach_determined: false,
      observed_reach_value_usd: undefined,
      observed_reach_unvalued_assets: ["0xeee"],
      contract_balance_seeded: true,
    });
    expect(claimWitnessFacts(unvalued)).toContainEqual({
      label: "Reach",
      value: "value not determined — 1 asset(s) of unknown value; only if the contract were funded",
    });
    // No destination lattice at all: the clause stands as the whole parenthetical
    // rather than being dropped for want of something to append to.
    const bare = {
      claims: [{
        claim_id: "flow.out",
        tier: "behavioral_observed",
        witness: { effect_verdict_id: 1, observed: { input_seeded: true } },
      }],
    };
    expect(compactActionSummary(bare)).toBe("moves value out (with seeded inputs)");
  });

  it("does not let a seeded mint's backing read as backing observed in live state", () => {
    // A supply verdict carries the flags top-level AND inside `backing`; a payload
    // written before the producer mirrored them onto `details` has only the latter.
    const mint = (backing, observed = {}) => ({
      claims: [
        { claim_id: "flow.in", tier: "behavioral_observed", witness: { effect_verdict_id: 2, observed: {} } },
        {
          claim_id: "supply.mint",
          tier: "behavioral_observed",
          witness: { effect_verdict_id: 2, observed: { backing, ...observed } },
        },
      ],
    });
    const seeded = mint({ inflow_observed: true, input_seeded: true });
    expect(claimWitnessFacts(seeded)).toContainEqual({
      label: "Backing",
      value: "matching asset inflow observed (backed); with seeded inputs",
    });
    expect(compactActionSummary(seeded)).toBe("moves value in (backed; with seeded inputs)");

    // CONTROL: the same shape with the flags explicitly false renders unchanged.
    const plain = mint({ inflow_observed: true, input_seeded: false, contract_balance_seeded: false });
    expect(claimWitnessFacts(plain)).toEqual([
      { label: "Backing", value: "matching asset inflow observed (backed)" },
    ]);
    expect(compactActionSummary(plain)).toBe("moves value in (backed)");
  });

  it("attributes the clause to the seeded claim, never to an unseeded sibling", () => {
    // Corpus function 1820: a STATIC flow.in is the primary claim (priority 6) and
    // the seeded verdict is the behavioral flow.out. The inflow sentence is not a
    // seeded observation and must stay unqualified; the reach row and the
    // provenance word, which do come from the seeded claim, carry the disclosure.
    const fn = {
      claims: [
        { claim_id: "flow.in", tier: "standard_exact", witness: {} },
        {
          claim_id: "flow.out",
          tier: "behavioral_observed",
          witness: {
            effect_verdict_id: 3,
            observed: { reach_determined: true, observed_reach_value_usd: 8_471_736.29, input_seeded: true },
          },
        },
      ],
    };
    expect(compactActionSummary(fn)).toBe("moves value in");
    expect(claimWitnessFacts(fn)).toContainEqual({
      label: "Reach (upper bound)",
      value: "up to ~$8.5M; with seeded inputs",
    });
    expect(claimSummaryLine(fn).label).toBe(
      "moves value in · moves value out · observed (seeded) + standard",
    );
  });

  it("never qualifies a static tier word — only an observation can be seeded", () => {
    const fn = {
      claims: [{
        claim_id: "flow.out",
        tier: "standard_exact",
        witness: { direction: "out", flows: [{ target_kind: { kind: "msg_sender" } }], observed: { input_seeded: true } },
      }],
    };
    expect(claimSummaryLine(fn).label).toBe(
      "moves value out (caller-chosen destination; with seeded inputs) · standard",
    );
  });
});
