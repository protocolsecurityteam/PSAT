import { describe, it, expect } from "vitest";

import {
  compactActionSummary,
  laneForFunction,
  lanePriority,
  toneForFunction,
} from "./lane.js";
import { buildMachines } from "./layout/buildMachines.js";
import { entityKey } from "./entityKey.js";
import { ETHERFI_COMPANY_RICH } from "../test/fixtures.js";
import { claim } from "../vocab/testSupport.js";

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
