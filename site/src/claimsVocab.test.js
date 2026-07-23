import { describe, it, expect } from "vitest";

import {
  CLAIM_VOCAB,
  claimSummaryLine,
  claimsOf,
  hasClaims,
  laneForClaims,
  primaryClaim,
  priorityForClaims,
  scoreForClaims,
  sentenceForClaims,
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
