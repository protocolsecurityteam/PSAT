import { describe, it, expect } from "vitest";

import { CLAIM_VOCAB } from "./claimVocab.data.js";

const VALID_LANES = new Set(["top", "left", "right", "ops"]);
// "fact" is the backend's own family for a claim that carries no semantic
// weight (services/static/claims/types.py). Its presence here is structural, not
// cosmetic: it is what makes "contributes nothing to severity" a property of the
// vocabulary rather than a convention a future entry could quietly break.
const VALID_FAMILIES = new Set(["control_plane", "flow", "exec", "user_plane", "fact"]);

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
  "transfer_policy.configure",
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
    }
  });

  it("never lanes a fact-family claim to control", () => {
    for (const [id, entry] of Object.entries(CLAIM_VOCAB)) {
      if (entry.family !== "fact") continue;
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
