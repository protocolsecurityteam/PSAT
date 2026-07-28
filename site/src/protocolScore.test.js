import { describe, expect, it } from "vitest";

import { computeProtocolScore } from "./protocolScore.js";
import { entityKey } from "./surface/entityKey.js";

const SAFE_4_OF_7 = {
  address: "0xsafe",
  resolved_type: "safe",
  details: {
    threshold: 4,
    owners: ["0x1", "0x2", "0x3", "0x4", "0x5", "0x6", "0x7"],
  },
};

const EOA = {
  address: "0xeoa",
  resolved_type: "eoa",
  details: {},
};

function contractWithUnpause(principal) {
  return {
    address: "0xcontract",
    name: "Vault",
    source_verified: true,
    is_proxy: false,
    role: "value_handler",
    total_usd: 100_000_000,
    risk_level: "high",
    functions: [
      {
        function: "pause()",
        effect_labels: ["pause_toggle"],
        controllers: [{ principals: [EOA] }],
      },
      {
        function: "unpause()",
        effect_labels: ["pause_toggle"],
        controllers: [{ principals: [principal] }],
      },
    ],
  };
}

function axis(score, key) {
  return score.axes.find((entry) => entry.key === key)?.value;
}

describe("computeProtocolScore", () => {
  it("scores pause authority differently from unpause authority", () => {
    const safeUnpause = computeProtocolScore({ contracts: [contractWithUnpause(SAFE_4_OF_7)] }, null);
    const eoaUnpause = computeProtocolScore({ contracts: [contractWithUnpause(EOA)] }, null);

    expect(axis(safeUnpause, "pause")).toBeGreaterThan(axis(eoaUnpause, "pause"));
  });

  it("does not use Slither risk_level as a scoring axis", () => {
    const highRisk = computeProtocolScore({ contracts: [contractWithUnpause(SAFE_4_OF_7)] }, null);
    const lowRiskContract = { ...contractWithUnpause(SAFE_4_OF_7), risk_level: "low" };
    const lowRisk = computeProtocolScore({ contracts: [lowRiskContract] }, null);

    expect(highRisk.composite).toBe(lowRisk.composite);
    expect(highRisk.axes.some((entry) => entry.key === "risk")).toBe(false);
  });

  it("only credits bytecode-verified audit coverage", () => {
    const contract = { ...contractWithUnpause(SAFE_4_OF_7), address: "0xabc" };
    const heuristicCoverage = {
      coverage: [
        {
          address: "0xabc",
          audit_count: 1,
          audits: [
            {
              audit_id: 1,
              match_type: "impl_era",
              match_confidence: "high",
              equivalence_status: "no_source_repo",
            },
          ],
        },
      ],
    };
    const verifiedCoverage = {
      coverage: [
        {
          address: "0xabc",
          audit_count: 1,
          audits: [
            {
              audit_id: 1,
              match_type: "reviewed_commit",
              match_confidence: "high",
              equivalence_status: "proven",
              proof_kind: "clean",
            },
          ],
        },
      ],
    };

    expect(axis(computeProtocolScore([contract], [], heuristicCoverage), "audits")).toBe(0);
    expect(axis(computeProtocolScore([contract], [], verifiedCoverage), "audits")).toBe(1);
  });

  it("labels the strict audit axis as audit", () => {
    const score = computeProtocolScore({ contracts: [contractWithUnpause(SAFE_4_OF_7)] }, null);
    const auditAxis = score.axes.find((entry) => entry.key === "audits");

    expect(auditAxis.label).toBe("Audit");
  });

  it("adds detail copy with positive notes and concrete negative examples", () => {
    const score = computeProtocolScore({ contracts: [contractWithUnpause(EOA)] }, null);
    const pauseAxis = score.axes.find((entry) => entry.key === "pause");

    expect(pauseAxis.tooltip.description).toContain("emergency stops");
    expect(pauseAxis.tooltip.positive).toContain("pause");
    expect(pauseAxis.tooltip.negative).toContain("unpause");
    expect(pauseAxis.tooltip.negativeExamples).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: expect.stringContaining("unpause"),
          detail: expect.stringContaining("EOA-controlled"),
          contractAddress: "0xcontract",
          functionSignature: "unpause()",
        }),
      ]),
    );
  });

  it("does not classify exact empty principal sets as unresolved controllers", () => {
    const contract = {
      address: "0xcontract",
      name: "Vault",
      source_verified: true,
      role: "value_handler",
      total_usd: 100_000_000,
      functions: [
        {
          function: "recover(address)",
          effect_labels: ["asset_send"],
          status: "resolved_empty",
          capability_expr: {
            kind: "finite_set",
            members: [],
            membership_quality: "exact",
            confidence: "enumerable",
          },
          controllers: [],
        },
      ],
    };

    const score = computeProtocolScore({ contracts: [contract] }, null);
    const authorityAxis = score.axes.find((entry) => entry.key === "authority");

    expect(axis(score, "authority")).toBeGreaterThan(0.9);
    expect(authorityAxis.tooltip.negative).not.toContain("unresolved controllers");
    expect(JSON.stringify(authorityAxis.tooltip.negativeExamples)).not.toContain("controller unresolved");
  });

  function contractWithAction(fn) {
    return {
      address: "0xcontract",
      name: "Vault",
      source_verified: true,
      role: "value_handler",
      total_usd: 100_000_000,
      functions: [fn],
    };
  }

  function authorityTooltip(fn) {
    const score = computeProtocolScore({ contracts: [contractWithAction(fn)] }, null);
    return score.axes.find((entry) => entry.key === "authority").tooltip;
  }

  it("describes a permissionless high-risk action as permissionless, not an unresolved controller", () => {
    const tooltip = authorityTooltip({
      function: "sweep(address)",
      effect_labels: ["asset_send"], // asset_out, high-risk
      authority_public: true,
      controllers: [],
    });
    const json = JSON.stringify(tooltip.negativeExamples);
    expect(json).toContain("permissionless");
    expect(json).not.toContain("No resolved controller was found");
    expect(json).not.toContain("controller unresolved");
    expect(tooltip.negative).not.toContain("unresolved controllers");
  });

  it("still flags a genuinely unresolved (non-public) controller as such", () => {
    const tooltip = authorityTooltip({
      function: "sweep(address)",
      effect_labels: ["asset_send"],
      authority_public: false,
      controllers: [],
    });
    const json = JSON.stringify(tooltip.negativeExamples);
    expect(json).toContain("No resolved controller was found");
    expect(json).not.toContain("permissionless");
  });

  it("does not surface a consumed one-shot initializer as a negative example", () => {
    const score = computeProtocolScore(
      {
        contracts: [
          contractWithAction({
            function: "initialize(address)",
            effect_labels: ["authority_update"], // admin, high-risk
            authority_public: true,
            conditions: [{ kind: "one_shot", latch_state: "consumed" }],
            controllers: [],
          }),
        ],
      },
      null,
    );
    const tooltip = score.axes.find((entry) => entry.key === "authority").tooltip;
    const json = JSON.stringify(tooltip.negativeExamples);
    expect(json).not.toContain("initialize");
    expect(json).not.toContain("permissionless");
    expect(json).not.toContain("No resolved controller was found");
    // a spent initializer is inert, so the authority axis reads it as protected
    expect(axis(score, "authority")).toBeGreaterThan(0.9);
  });

  it("describes a live one-shot initializer accurately rather than as an unresolved controller", () => {
    const tooltip = authorityTooltip({
      function: "initialize(address)",
      effect_labels: ["authority_update"],
      authority_public: true,
      conditions: [{ kind: "one_shot", latch_state: "live" }],
      controllers: [],
    });
    const json = JSON.stringify(tooltip.negativeExamples);
    expect(json).toContain("live one-shot");
    expect(json).not.toContain("No resolved controller was found");
  });

  function claim(claim_id, tier = "standard_exact") {
    return { claim_id, tier, witness: {} };
  }

  describe("classifyAction — claims drive severity, legacy is the fallback", () => {
    it("keys the action kind on the claim, overriding a conflicting legacy label", () => {
      const claimTip = authorityTooltip({
        function: "poke",
        effect_labels: ["hook_update"], // legacy → config 0.78
        claims: [claim("ownership.transfer")], // claim → admin 0.88
        authority_public: true,
        controllers: [],
      });
      const legacyTip = authorityTooltip({
        function: "poke",
        effect_labels: ["hook_update"],
        authority_public: true,
        controllers: [],
      });
      expect(JSON.stringify(claimTip.negativeExamples)).toContain("admin");
      expect(JSON.stringify(claimTip.negativeExamples)).not.toContain("config");
      expect(JSON.stringify(legacyTip.negativeExamples)).toContain("config");
    });

    it("classifies exec.arbitrary as a high-risk execution action", () => {
      const tip = authorityTooltip({
        function: "run",
        effect_labels: [],
        claims: [claim("exec.arbitrary")],
        authority_public: true,
        controllers: [],
      });
      expect(JSON.stringify(tip.negativeExamples)).toContain("execution");
    });

    it("treats an upgrade claim as an upgrade action even when the name isn't 'upgrade'", () => {
      const contract = {
        address: "0xc",
        name: "Vault",
        source_verified: true,
        role: "value_handler",
        total_usd: 1e8,
        is_proxy: true,
        functions: [
          {
            function: "migrateCode(address)",
            claims: [claim("upgrade.implementation")],
            authority_public: true,
            controllers: [],
          },
        ],
      };
      const upgradesTip = computeProtocolScore({ contracts: [contract] }, null)
        .axes.find((a) => a.key === "upgrades").tooltip;
      expect(JSON.stringify(upgradesTip.negativeExamples)).toContain("migrateCode");
    });

    it("splits unpause severity from a claim, independent of the function name", () => {
      const contract = {
        address: "0xc",
        name: "Vault",
        source_verified: true,
        role: "value_handler",
        total_usd: 1e8,
        functions: [
          { function: "liftHalt()", claims: [claim("pause.unset")], controllers: [{ principals: [EOA] }] },
        ],
      };
      const pauseTip = computeProtocolScore({ contracts: [contract] }, null)
        .axes.find((a) => a.key === "pause").tooltip;
      expect(pauseTip.negative).toContain("unpause");
    });

    it("does not treat a user-plane transfer as a sensitive authority action", () => {
      // Legacy asset_send would make this a high-risk asset_out; the user-plane
      // claim keeps it out of the sensitive set entirely.
      const tip = authorityTooltip({
        function: "transfer(address,uint256)",
        effect_labels: ["asset_send"],
        claims: [claim("erc20.transfer")],
        authority_public: true,
        controllers: [],
      });
      expect(tip.positive).toBe("No sensitive function-level authority was detected.");
      expect(tip.negativeExamples).toHaveLength(0);
    });
  });

  // The effects bridge mints observable labels at the behavioral_observed tier,
  // but the score must NOT consume verdicts while their consumption stays
  // unspecified. The score of any input is byte-identical
  // whether or not behavioral_observed claims (and their re-projected labels) are
  // present.
  describe("behavioral_observed claims are score-inert (scoring deferred)", () => {
    function observed(claim_id) {
      return { claim_id, tier: "behavioral_observed", witness: {} };
    }
    function scoreOf(contracts) {
      return JSON.stringify(computeProtocolScore({ contracts }, null));
    }

    it("adding an observed claim to a claimed function does not move the score", () => {
      const base = {
        function: "migrateCode(address)",
        claims: [claim("upgrade.implementation", "idiom_structural")],
        effect_labels: ["implementation_update"],
        authority_public: true,
        controllers: [],
      };
      const withObserved = {
        ...base,
        claims: [...base.claims, observed("upgrade.implementation")],
      };
      expect(scoreOf([contractWithAction(withObserved)])).toBe(scoreOf([contractWithAction(base)]));
    });

    it("labeling a previously-blank money function does not move the score", () => {
      // The core case: a blank outflow function gains flow.out + its
      // re-projected "asset_send" label. The score must not start counting it.
      const blank = { function: "sweep()", effect_labels: [], claims: [], controllers: [] };
      const labeled = {
        function: "sweep()",
        claims: [observed("flow.out")],
        effect_labels: ["asset_send"], // re-projected legacy label from the observed claim
        controllers: [],
      };
      expect(scoreOf([contractWithAction(labeled)])).toBe(scoreOf([contractWithAction(blank)]));
    });

    it("an observed claim never diverts a name-fallback row's score", () => {
      // A stale claim-less "upgradeTo" row scores via the name fallback; gaining
      // an observed upgrade claim must not flip it to the claims branch and drop it.
      const stale = { function: "upgradeTo(address)", effect_labels: [], claims: [], controllers: [] };
      const withObserved = {
        function: "upgradeTo(address)",
        claims: [observed("upgrade.implementation")],
        effect_labels: ["implementation_update"],
        controllers: [],
      };
      expect(scoreOf([contractWithAction(withObserved)])).toBe(scoreOf([contractWithAction(stale)]));
    });
  });
});

// A CREATE2 twin — the same address deployed on two of a protocol's chains — is
// two distinct entities, not one (identity is (chain, address)). The
// stats-plane reductions used to key by bare address while iterating the
// all-chains contract array, so a twin's per-chain actions/coverage collapsed
// together. These assert the invariant directly: a same-address-two-chains
// fixture must score identically to a two-distinct-addresses fixture, because
// both describe two separate entities. Bare-address keying diverges (and the
// per-chain analyses below are deliberately different so the collapse is
// observable rather than a no-op).
describe("computeProtocolScore — cross-chain same-address twins", () => {
  const ADDR = "0x1111111111111111111111111111111111111111";
  const ADDR2 = "0x2222222222222222222222222222222222222222";

  const EOA = { address: "0xeoa", resolved_type: "eoa", details: {} };

  function axisValue(score, key) {
    return score.axes.find((entry) => entry.key === key)?.value;
  }

  it("keeps each chain's pause posture separate (pause axis)", () => {
    // eth twin has only a pause(); base twin has only an unpause(). Bare keying
    // merges both into both contracts, so each looks like it has fast pause AND
    // a weak EOA unpause — flattering the base entity and penalizing the eth one.
    const ethPause = (addr) => ({
      address: addr,
      chain: "ethereum",
      name: "EthVault",
      is_proxy: true,
      source_verified: true,
      functions: [{ function: "pause()", controllers: [{ principals: [EOA] }] }],
    });
    const baseUnpause = (addr) => ({
      address: addr,
      chain: "base",
      name: "BaseVault",
      is_proxy: true,
      source_verified: true,
      functions: [{ function: "unpause()", controllers: [{ principals: [EOA] }] }],
    });

    const twin = computeProtocolScore({ contracts: [ethPause(ADDR), baseUnpause(ADDR)] }, null);
    const distinct = computeProtocolScore({ contracts: [ethPause(ADDR), baseUnpause(ADDR2)] }, null);

    expect(axisValue(twin, "pause")).toBeCloseTo(axisValue(distinct, "pause"), 10);
    expect(axisValue(distinct, "pause")).toBeCloseTo(0.495, 4);
  });

  it("does not tag a standalone twin as upgradeable from its cross-chain proxy (upgrades axis)", () => {
    // eth twin is an upgradeable proxy; base twin is a plain non-proxy with no
    // upgrade function. Bare keying hands the base contract the eth proxy's
    // upgrade action, flipping it to "upgradeable" and tanking the axis.
    const ethProxy = (addr) => ({
      address: addr,
      chain: "ethereum",
      name: "EthProxy",
      is_proxy: true,
      source_verified: true,
      implementation: "0ximpl",
      upgrade_count: 2,
      functions: [{ function: "upgradeTo(address)", controllers: [{ principals: [EOA] }] }],
    });
    const baseStandalone = (addr) => ({
      address: addr,
      chain: "base",
      name: "BaseToken",
      is_proxy: false,
      source_verified: true,
      functions: [],
    });

    const twin = computeProtocolScore({ contracts: [ethProxy(ADDR), baseStandalone(ADDR)] }, null);
    const distinct = computeProtocolScore({ contracts: [ethProxy(ADDR), baseStandalone(ADDR2)] }, null);

    expect(axisValue(twin, "upgrades")).toBeCloseTo(axisValue(distinct, "upgrades"), 10);
  });

  it("attributes audit coverage to the covered chain only (audit axis)", () => {
    // The verified coverage row is for the eth twin. Bare keying lets the base
    // twin's empty coverage row overwrite it (last-wins), stripping the eth
    // entity's audit credit.
    const bareContract = (addr, chain, name) => ({
      address: addr,
      chain,
      name,
      is_proxy: false,
      source_verified: true,
      functions: [],
    });
    const verifiedAudit = {
      audit_id: 1,
      match_type: "reviewed_commit",
      match_confidence: "high",
      equivalence_status: "proven",
      proof_kind: "clean",
    };
    const coverageFor = (baseAddr) => ({
      coverage: [
        { address: ADDR, chain: "ethereum", audits: [verifiedAudit] },
        { address: baseAddr, chain: "base", audits: [] },
      ],
    });

    const twin = computeProtocolScore(
      { contracts: [bareContract(ADDR, "ethereum", "EthC"), bareContract(ADDR, "base", "BaseC")] },
      coverageFor(ADDR),
    );
    const distinct = computeProtocolScore(
      { contracts: [bareContract(ADDR, "ethereum", "EthC"), bareContract(ADDR2, "base", "BaseC")] },
      coverageFor(ADDR2),
    );

    expect(axisValue(twin, "audits")).toBeCloseTo(axisValue(distinct, "audits"), 10);
    expect(axisValue(distinct, "audits")).toBeCloseTo(0.5, 4);
  });

  it("keys twins distinctly (entityKey convention sanity)", () => {
    expect(entityKey("ethereum", ADDR)).not.toBe(entityKey("base", ADDR));
  });
});
