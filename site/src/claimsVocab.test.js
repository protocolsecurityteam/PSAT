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
  sharedDeployerNote,
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
// "fact" is the backend's own family for a claim that carries no semantic
// weight (services/static/claims/types.py). Its presence here is structural, not
// cosmetic: it is what makes "contributes nothing to severity" a property of the
// vocabulary rather than a convention a future entry could quietly break.
const VALID_FAMILIES = new Set(["control_plane", "flow", "exec", "user_plane", "fact"]);
const VALID_KINDS = new Set([
  "upgrade", "execution", "admin", "config", "pause", "unpause", "timelock", "asset_out", "asset_in",
]);

function claim(claim_id, tier = "standard_exact") {
  return { claim_id, tier, witness: {} };
}

// Every registered backend claim_id the frontend renders. A new backend claim
// that lands without a vocab entry is caught here — the JS half of the
// consumer-coverage invariant.
const EXPECTED_CLAIM_IDS = [
  "authority.grant",
  "authority.replace",
  "authorized_caller.rotate",
  "callee_pointer.rotate",
  "contract_deployment",
  "delegatecall.execute",
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
  "rate_limit.consume",
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
  "value_router",
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

  it("never scores a fact-family claim and never lanes it to control", () => {
    for (const [id, entry] of Object.entries(CLAIM_VOCAB)) {
      if (entry.family !== "fact") continue;
      expect(entry.score, `${id} score`).toBeNull();
      expect(entry.lane, `${id} lane`).toBe("ops");
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

  it("scores a routed INFLOW as an inflow, not as an asset outflow", () => {
    // The same value_router claim covers both directions. A pull the entry only
    // caused between two other parties sends none of this unit's assets
    // anywhere, so filing it as a high-risk asset_out would raise the protocol
    // score off a move the contract never made.
    const inbound = {
      claims: [
        {
          claim_id: "value_router",
          tier: "standard_exact",
          witness: { flows: [{ from_is_self: false, target_kind: { kind: "immutable" } }] },
        },
      ],
    };
    expect(scoreForClaims(inbound)).toEqual({ kind: "asset_in", severity: 0.5 });

    const outbound = {
      claims: [
        {
          claim_id: "value_router",
          tier: "standard_exact",
          witness: { flows: [{ from_is_self: true, target_kind: { kind: "param" } }] },
        },
      ],
    };
    expect(scoreForClaims(outbound)).toEqual({ kind: "asset_out", severity: 0.78 });
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

// The score path is the one place provenance strength decides something, and it
// was the one place the tier lattice was discarded: everything except the observed
// tier fell through untouched, so a cross-contract inference with NO
// single-contract evidence entered at the weight of an exact ABI-selector match.
describe("scoreForClaims — the tier lattice reaches the score", () => {
  it("scores a policy_derived claim below the identical standard_exact claim", () => {
    const exact = scoreForClaims({ claims: [claim("upgrade.implementation", "standard_exact")] });
    const policy = scoreForClaims({ claims: [claim("upgrade.implementation", "policy_derived")] });
    expect(exact.severity).toBe(1);
    expect(policy.severity).toBeLessThan(exact.severity);
    // The factor is read off TIER_RANK (1 of 3), not invented at the call site.
    expect(policy.severity).toBeCloseTo(1 / 3, 10);
    expect(policy.kind).toBe("upgrade");
    // Named, so the score's prose can say WHY the number is smaller.
    expect(policy.provenance_tier).toBe("policy_derived");
  });

  it("keeps the policy claim IN the candidate set", () => {
    // Stripping it (the observed tier's treatment) would drop the action from
    // protocolScore's candidate set entirely and make the protocol read SAFER for
    // a risk nobody disproved — the adverse direction.
    const policy = scoreForClaims({ claims: [claim("flow.out", "policy_derived")] });
    expect(policy).not.toBeNull();
    expect(policy.severity).toBeGreaterThan(0);
  });

  it("leaves idiom_structural and standard_exact at full weight", () => {
    // NEGATIVE CONTROL: the attenuation is scoped to the tier that has no
    // single-contract evidence. `idiom_structural` is a structural idiom in this
    // contract's OWN code, and re-weighting it would move 123 real corpus claims.
    expect(scoreForClaims({ claims: [claim("flow.out", "idiom_structural")] }).severity).toBe(0.78);
    expect(scoreForClaims({ claims: [claim("flow.out", "standard_exact")] }).severity).toBe(0.78);
    expect(scoreForClaims({ claims: [claim("flow.out")] }).provenance_tier).toBeUndefined();
  });

  it("attenuates the golden fixture-10 row's own claim shape", () => {
    // The corpus gate for this defect: `policy_derived` is 0 of 679 real claims, so
    // no corpus row could catch a consumer that mishandles the weakest tier —
    // fixture 10 exists to be that row. This is its claim verbatim from
    // tests/fixtures/label_corpus/golden.json (contract 0x…0100, depositTo).
    const golden = {
      claim_id: "flow.in",
      tier: "policy_derived",
      witness: {
        callee: "0x00000000000000000000000000000000000000a0",
        kind: "cross_contract_join",
        selector: "0xb6b55f25",
        sink_id: "depositTo(uint256):sink0:external_call:vault.deposit",
        source_tier: "standard_exact",
      },
    };
    const scored = scoreForClaims({ claims: [golden] });
    const asExact = scoreForClaims({ claims: [{ ...golden, tier: "standard_exact" }] });
    expect(scored.kind).toBe(asExact.kind);
    expect(scored.severity).toBeLessThan(asExact.severity);
    expect(scored.provenance_tier).toBe("policy_derived");
  });

  it("still takes the strongest severity when a policy claim sits beside a stronger one", () => {
    const both = scoreForClaims({
      claims: [claim("upgrade.implementation", "policy_derived"), claim("flow.out", "standard_exact")],
    });
    expect(both.kind).toBe("asset_out");
    expect(both.severity).toBe(0.78);
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
const FREE = { state: "unconstrained_proven" };

function flowOut(
  targetKind,
  { amountKind = null, tier = "standard_exact", targetKinds = null, amountKinds = null, constraint } = {},
) {
  const flow = { kind: "low_level_value_call", selector: null, from_is_self: true };
  if (targetKind) flow.target_kind = targetKind;
  // The producer (`flows.py:_flow_entry`) attaches a verdict only to a SCALAR
  // `param` destination — a `several` fold NEVER carries one. The helper
  // mirrors that: the proven-free default applies to scalar params only, so a
  // fold payload is the mintable no-verdict shape unless a test explicitly
  // injects a verdict (the defensive fold arms below say so when they do).
  const scalarParam = targetKind?.kind === "param";
  const foldParam = Array.isArray(targetKinds) && targetKinds.some((k) => k?.kind === "param");
  const verdict = constraint === undefined ? (scalarParam ? FREE : null) : constraint;
  if ((scalarParam || foldParam) && verdict) flow.target_constraint = verdict;
  if (amountKind) flow.amount_kind = amountKind;
  if (targetKinds) flow.target_kinds = targetKinds;
  if (amountKinds) flow.amount_kinds = amountKinds;
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
      expect(facts).toContainEqual({ label: "Auto-expiry", value: "not determined (no freeze window read)" });
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

  it("renders each plane's own terminal outcome for a multi_plane walk, never one key", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: {
          terminal: false,
          resolved_type: "unknown",
          address: null,
          status: "multi_plane",
          controllers: ["0x1", "0x2"],
          planes: [
            { controller: "0x1", terminal_record: { terminal: true, resolved_type: "safe", address: "0xsafe", status: "terminated" } },
            { controller: "0x2", terminal_record: { terminal: false, resolved_type: "unknown", address: null, status: "unknown_unfetched" } },
          ],
        },
      },
    });
    expect(note.kind).toBe("multi_plane");
    expect(note.planes).toEqual([
      { controller: "0x1", outcome: { resolved: true, address: "0xsafe", resolvedType: "safe" } },
      { controller: "0x2", outcome: { resolved: false, status: "unknown_unfetched" } },
    ]);
  });

  it("degrades a multi_plane record with no usable planes array to the flat ambiguous render", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: {
          terminal: false, resolved_type: "unknown", address: null,
          status: "multi_plane", controllers: ["0x1", "0x2"],
        },
      },
    });
    expect(note.kind).toBe("ambiguous");
    expect(note.planes).toEqual(["0x1", "0x2"]);
  });

  it("renders a nested ambiguous_controllers fork as the flat 'no single settled key'", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "ambiguous_controllers", controllers: ["0x1", "0x2", "0x3"] },
      },
    });
    expect(note.kind).toBe("ambiguous");
    expect(note.planes).toEqual(["0x1", "0x2", "0x3"]);
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

  it("renders canonical-getter silence as unresolved with the true status carried", () => {
    // controllers_not_determined = the probes were silent, NOT "no controller
    // exists". The payload carries the basis (probes_silent / undetermined_at)
    // and the note must keep the state distinguishable, never fold it into a
    // settled key or a proven absence.
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: {
          terminal: false,
          resolved_type: "unknown",
          address: null,
          status: "controllers_not_determined",
          probes_silent: ["owner", "authority", "admin"],
          undetermined_at: "0x" + "ec".repeat(20),
          chain: ["0x" + "dc".repeat(20), "0x" + "ec".repeat(20)],
        },
      },
    });
    expect(note).toEqual({ kind: "unresolved", status: "controllers_not_determined" });
  });

  it("keeps legacy persisted no_controller rows unresolved (never a settled key)", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "no_controller" },
      },
    });
    expect(note).toEqual({ kind: "unresolved", status: "no_controller" });
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

describe("sharedDeployerNote — heuristic hint, never an org-identity claim", () => {
  it("counts the OTHER addresses in the deployer group and carries the heuristic hedge", () => {
    const note = sharedDeployerNote({
      address: "0xself",
      details: {
        shared_deployer: {
          provenance: "deployer_read", heuristic: true, deployer: "0xdep",
          addresses: ["0xself", "0xaaa", "0xbbb"],
        },
      },
    });
    expect(note).toEqual({ deployer: "0xdep", otherCount: 2, heuristic: true });
  });

  it("counts case-insensitively and excludes the principal itself", () => {
    const note = sharedDeployerNote({
      address: "0xSELF",
      details: { shared_deployer: { deployer: "0xdep", addresses: ["0xself", "0xaaa"] } },
    });
    expect(note.otherCount).toBe(1);
  });

  it("emits null when the fact is absent (no hint from absence)", () => {
    expect(sharedDeployerNote({ address: "0xself", details: {} })).toBeNull();
    expect(sharedDeployerNote({ details: {} })).toBeNull();
    expect(sharedDeployerNote({})).toBeNull();
  });

  it("emits null for a singleton group (no OTHER address to share with)", () => {
    const note = sharedDeployerNote({
      address: "0xself",
      details: { shared_deployer: { deployer: "0xdep", addresses: ["0xself"] } },
    });
    expect(note).toBeNull();
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

  it("contributes nothing to the score, alone or beside a real outflow", () => {
    expect(scoreForClaims({ claims: [limiterClaim] })).toBeNull();
    const withFlow = { claims: [limiterClaim, flowOut({ kind: "param", tier: "dispositive_ast" })] };
    // The flow's own severity is the whole score; the limiter neither raises nor
    // discounts it. A refilling bucket bounds throughput per window, not total
    // loss, so a discount here would be an invented ceiling.
    expect(scoreForClaims(withFlow)).toEqual(scoreForClaims({ claims: [flowOut({ kind: "param", tier: "dispositive_ast" })] }));
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

  it("scores at the execution severity and lanes to control", () => {
    // Foreign code in this contract's storage is the same severity class as an
    // arbitrary external call; what it must NOT do is join the
    // upgrade.implementation population and move that claim's statistics.
    expect(scoreForClaims({ claims: [dc({ target_kind: "storage_setter" })] }))
      .toEqual({ kind: "execution", severity: 0.95 });
    expect(laneForClaims({ claims: [dc({ target_kind: "storage_setter" })] })).toBe("top");
    expect(CLAIM_VOCAB["delegatecall.execute"].legacy).toBe("delegatecall_execution");
    expect(CLAIM_VOCAB["delegatecall.execute"].legacy).not.toBe(CLAIM_VOCAB["upgrade.implementation"].legacy);
  });
});
