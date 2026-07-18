import { describe, it, expect } from "vitest";

import { buildGovernsIndex } from "./governsIndex.js";
import { entityKey } from "../entityKey.js";

// functionData is keyed by the composite (chain, address) token; MACHINES carry
// no chain, so they resolve to the "ethereum" default (NULL≡ethereum).
const k = (addr) => entityKey("ethereum", addr);

const TIMELOCK = "0x9f26d4c958fd811a1f59b01b86be7dffc9d20761"; // no principal entry
const SAFE = "0x2222222222222222222222222222222222222222";
const POOL = "0x3333333333333333333333333333333333333333";
const VAULT = "0x4444444444444444444444444444444444444444";

const MACHINES = [
  { address: POOL, name: "LiquidityPool" },
  { address: VAULT, name: "Vault" },
];

function fn(signature, { owner, roles = [], controllers = [] } = {}) {
  return {
    function: signature,
    direct_owner: owner ? { address: owner, resolved_type: "timelock" } : null,
    authority_roles: roles,
    controllers,
  };
}

describe("buildGovernsIndex", () => {
  it("resolves the governed set for an authority with NO principal entry", () => {
    // The motivating case: EtherFiTimelock owns functions but has no entry in
    // the principals list. The client-side inversion must still surface it.
    const idx = buildGovernsIndex(MACHINES, {
      [k(POOL)]: [fn("upgradeTo(address)", { owner: TIMELOCK })],
    });
    const rows = idx.get(TIMELOCK);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      contractAddress: POOL,
      contractName: "LiquidityPool",
      functions: ["upgradeTo"],
    });
  });

  it("collects every authority on a function (owner + role + controller)", () => {
    const idx = buildGovernsIndex(MACHINES, {
      [k(POOL)]: [
        fn("pause()", {
          owner: TIMELOCK,
          roles: [{ role: "PAUSER", principals: [{ address: SAFE, resolved_type: "safe" }] }],
        }),
      ],
    });
    expect(idx.get(TIMELOCK).map((r) => r.functions)).toEqual([["pause"]]);
    expect(idx.get(SAFE).map((r) => r.functions)).toEqual([["pause"]]);
  });

  it("groups multiple functions per governed contract and sorts them", () => {
    const idx = buildGovernsIndex(MACHINES, {
      [k(POOL)]: [fn("setFee(uint256)", { owner: TIMELOCK }), fn("addToken(address)", { owner: TIMELOCK })],
      [k(VAULT)]: [fn("sweep(address)", { owner: TIMELOCK })],
    });
    const rows = idx.get(TIMELOCK);
    // Sorted by contract name asc: LiquidityPool before Vault.
    expect(rows.map((r) => r.contractName)).toEqual(["LiquidityPool", "Vault"]);
    expect(rows[0].functions).toEqual(["addToken", "setFee"]);
  });

  it("excludes a contract governing its own functions (that is Control's job)", () => {
    const idx = buildGovernsIndex(MACHINES, {
      [k(POOL)]: [fn("setFee(uint256)", { owner: POOL })],
    });
    expect(idx.get(POOL)).toBeUndefined();
  });

  it("skips role-constant pseudo-functions and returns empty for no authority", () => {
    const idx = buildGovernsIndex(MACHINES, {
      [k(POOL)]: [fn("PAUSER_ROLE", { owner: TIMELOCK }), fn("openMint()", {})],
    });
    expect(idx.size).toBe(0);
  });

  it("dedupes a function reached via both direct_owner and a controller", () => {
    const idx = buildGovernsIndex(MACHINES, {
      [k(POOL)]: [
        fn("upgradeTo(address)", {
          owner: TIMELOCK,
          controllers: [{ label: "admin", principals: [{ address: TIMELOCK, resolved_type: "timelock" }] }],
        }),
      ],
    });
    expect(idx.get(TIMELOCK)).toHaveLength(1);
    expect(idx.get(TIMELOCK)[0].functions).toEqual(["upgradeTo"]);
  });
});
