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

describe("lane.js claim consumers", () => {
  it("laneForFunction uses the claim lane", () => {
    const fn = { function: "deposit", claims: [claim("flow.out")] };
    expect(laneForFunction(fn)).toBe("right");
  });

  it("places an unsupported function in ops", () => {
    expect(laneForFunction({ function: "x", claims: [] })).toBe("ops");
  });

  it("toneForFunction uses the claim tone, and the lane tone for a tone-less claim", () => {
    expect(toneForFunction({ claims: [claim("ownership.transfer")] }, "top")).toBe("#9e8a8d");
    expect(toneForFunction({ claims: [claim("erc20.approve")] }, "ops"))
      .toBe("#6b7590");
  });

  it("compactActionSummary renders the claim sentence", () => {
    expect(compactActionSummary({ claims: [claim("pause.unset")] })).toBe("unpauses");
    expect(compactActionSummary({ claims: [] })).toBe("");
  });

  it("lanePriority uses the claim priority when present", () => {
    expect(lanePriority({ claims: [claim("upgrade.implementation")] })).toBe(0);
    expect(lanePriority({ claims: [claim("flow.out"), claim("ownership.transfer")] })).toBe(2);
    expect(lanePriority({ claims: [] })).toBe(9);
  });
});

describe("buildMachines carries claims into lane placement + ordering", () => {
  it("places a claim-bearing function by its claim", () => {
    const company = structuredClone(ETHERFI_COMPANY_RICH);
    const vault = company.contracts[0];
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
