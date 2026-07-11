// Shared API response fixtures for vitest render tests. Shapes mirror
// what api.py returns and what the e2e specs in site/e2e/*.spec.js use,
// so tests stay self-consistent with the real frontend contracts.

export const ANALYSIS_LIST = [
  {
    job_id: "a",
    company: "etherfi",
    address: "0x1111111111111111111111111111111111111111",
    contract_name: "Weeth",
    risk_level: "low",
    is_proxy: true,
    upgrade_count: 2,
  },
  {
    job_id: "b",
    company: "etherfi",
    address: "0x2222222222222222222222222222222222222222",
    contract_name: "LiquidityPool",
    risk_level: "medium",
    upgrade_count: 0,
  },
  {
    job_id: "c",
    company: "lido",
    address: "0x3333333333333333333333333333333333333333",
    contract_name: "stETH",
    risk_level: "low",
  },
];

export const ETHERFI_COMPANY = {
  contracts: [
    {
      address: "0x1111111111111111111111111111111111111111",
      name: "Weeth",
      risk_level: "low",
      is_proxy: true,
      proxy_type: "ERC1967",
      upgrade_count: 2,
      control_model: "timelock",
      controllers: { owner: "0xMultiSig" },
      functions: [],
    },
    {
      address: "0x2222222222222222222222222222222222222222",
      name: "LiquidityPool",
      risk_level: "medium",
      upgrade_count: 0,
      controllers: {},
      functions: [],
    },
  ],
  ownership_hierarchy: [
    {
      owner: "0x9999999999999999999999999999999999999999",
      owner_name: "Treasury",
      owner_is_contract: true,
      contracts: [
        { address: "0x1111111111111111111111111111111111111111", name: "Weeth" },
        { address: "0x2222222222222222222222222222222222222222", name: "LiquidityPool" },
      ],
    },
  ],
  all_addresses_count: 0,
};

export const COVERAGE_FIXTURE = {
  audit_count: 3,
  coverage: [
    {
      address: "0x1111111111111111111111111111111111111111",
      audit_count: 2,
      audits: [],
      last_audit: { auditor: "ABC", date: "2024-06" },
    },
    {
      address: "0x2222222222222222222222222222222222222222",
      audit_count: 0,
      audits: [],
    },
  ],
};

export const PIPELINE_FIXTURE = {
  groups: [],
  recent_completed: [],
};

export const ADDRESS_LABELS = { labels: {} };

// Rich ProtocolSurface fixture — contracts with functions that exercise
// every lane (control / ops / inflow / outflow), guard kind (safe / timelock
// / eoa / unknown / open), and the cross-contract principal walk that drives
// `collectPrincipals` + `guardSummary` + lane categorization. Used by the
// state-variant tests in src/ProtocolSurface.test.jsx.
const SAFE_ADDR = "0xaaaa000000000000000000000000000000000aaa";
const TIMELOCK_ADDR = "0xbbbb000000000000000000000000000000000bbb";
const EOA_ADDR = "0xcccc000000000000000000000000000000000ccc";
const VAULT_ADDR = "0x1111111111111111111111111111111111111111";
const POOL_ADDR = "0x2222222222222222222222222222222222222222";

function fn(name, effectLabels, principals = [], extra = {}) {
  return {
    function: name,
    selector: `0x${name.slice(0, 8).padEnd(8, "0")}`,
    abi_signature: name,
    effect_labels: effectLabels,
    action_summary: `${name} action`,
    authority_public: extra.public ?? false,
    direct_owner: principals[0] || null,
    authority_roles: extra.roles || [],
    controllers: extra.controllers || [],
    effect_targets: extra.targets || [],
    ...extra.fields,
  };
}

function principal(address, resolvedType, details = {}, label = null) {
  return {
    address,
    resolved_type: resolvedType,
    label,
    details,
    source_contract: null,
    source_controller_id: null,
  };
}

export const ETHERFI_COMPANY_RICH = {
  contracts: [
    {
      address: VAULT_ADDR,
      name: "Vault",
      risk_level: "low",
      is_proxy: true,
      proxy_type: "ERC1967",
      upgrade_count: 2,
      control_model: "timelock",
      controllers: { owner: SAFE_ADDR },
      job_id: "vault-job",
      functions: [
        fn("upgrade", ["upgrade"], [principal(TIMELOCK_ADDR, "timelock", { delay: 86400 })]),
        fn("pause", ["pause"], [principal(SAFE_ADDR, "safe", { owners: ["0x1", "0x2", "0x3"], threshold: 2 })]),
        fn("unpause", ["unpause"], [principal(SAFE_ADDR, "safe", { owners: ["0x1", "0x2", "0x3"], threshold: 2 })]),
        fn("deposit", ["asset_pull"], [], { public: true }),
        fn("withdraw", ["asset_send"], [principal(EOA_ADDR, "eoa")]),
        fn("setFee", ["config"], [principal(SAFE_ADDR, "safe", { owners: ["0x1", "0x2", "0x3"], threshold: 2 })]),
      ],
    },
    {
      address: POOL_ADDR,
      name: "LiquidityPool",
      risk_level: "medium",
      is_proxy: false,
      upgrade_count: 0,
      controllers: {},
      job_id: "pool-job",
      functions: [
        fn("rebalance", ["asset_send"], [principal(VAULT_ADDR, "contract", {}, "Vault")]),
        fn("setOracle", ["config"], [], {}), // no principals → unknown guard
        fn("addLiquidity", ["asset_pull"], [], { public: true }),
      ],
    },
  ],
  ownership_hierarchy: [
    {
      owner: SAFE_ADDR,
      owner_name: "Multisig",
      owner_is_contract: true,
      contracts: [
        { address: VAULT_ADDR, name: "Vault" },
        { address: POOL_ADDR, name: "LiquidityPool" },
      ],
    },
  ],
  all_addresses_count: 5,
  fund_flows: [
    { from: VAULT_ADDR, to: POOL_ADDR, label: "rebalance", usd: 1000000 },
  ],
  resolved_principals: [
    {
      address: SAFE_ADDR,
      resolved_type: "safe",
      display_name: "Multisig",
      labels: ["governance"],
      details: { owners: ["0x1", "0x2", "0x3"], threshold: 2 },
    },
    {
      address: TIMELOCK_ADDR,
      resolved_type: "timelock",
      display_name: "Timelock",
      labels: ["governance"],
      details: { delay: 86400 },
    },
  ],
};

export const RICH_COVERAGE = {
  audit_count: 2,
  coverage: [
    {
      address: VAULT_ADDR,
      audit_count: 1,
      // isBytecodeVerifiedAudit needs equivalence_status="proven",
      // match_type="reviewed_commit", proof_kind!="cited_only",
      // bytecode_drift!=true. These shapes mirror what api.py returns.
      audits: [
        {
          audit_id: 1,
          auditor: "Trail of Bits",
          date: "2024-03-15",
          title: "V2 Audit",
          match_type: "reviewed_commit",
          equivalence_status: "proven",
          proof_kind: "clean",
          bytecode_drift: false,
        },
      ],
      last_audit: { auditor: "Trail of Bits", date: "2024-03-15" },
    },
    {
      address: POOL_ADDR,
      audit_count: 0,
      audits: [],
    },
  ],
};

export const RICH_ADDRESSES = { VAULT: VAULT_ADDR, POOL: POOL_ADDR, SAFE: SAFE_ADDR, TIMELOCK: TIMELOCK_ADDR, EOA: EOA_ADDR };
