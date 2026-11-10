// Shared API response fixtures for vitest render tests. Shapes mirror
// what api.py returns and what the e2e specs in site/e2e/*.spec.js use,
// so tests stay self-consistent with the real frontend contracts.

export const ANALYSIS_LIST = [
  {
    job_id: "a",
    company: "etherfi",
    address: "0x1111111111111111111111111111111111111111",
    contract_name: "Weeth",
    is_proxy: true,
    upgrade_count: 2,
  },
  {
    job_id: "b",
    company: "etherfi",
    address: "0x2222222222222222222222222222222222222222",
    contract_name: "LiquidityPool",
  },
  {
    job_id: "c",
    company: "lido",
    address: "0x3333333333333333333333333333333333333333",
    contract_name: "stETH",
  },
];

export const ETHERFI_COMPANY = {
  contracts: [
    {
      address: "0x1111111111111111111111111111111111111111",
      name: "Weeth",
      is_proxy: true,
      proxy_type: "ERC1967",
      upgrade_count: 2,
      upgrade_count_basis: { history_fetch_status: "complete", events_total: 3, events_unlinked: 0, events_without_tx_hash: 0, deployments_excluded: 1, recorded_count_relation: "exact" },
      control_model: "timelock",
      controllers: { owner: "0xMultiSig" },
      functions: [],
    },
    {
      address: "0x2222222222222222222222222222222222222222",
      name: "LiquidityPool",
      upgrade_count: null,
      upgrade_count_basis: null,
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

export const ADDRESS_LABELS = { labels: {} };

// Rich ProtocolSurface fixture — contracts with functions that exercise
// every lane (control / ops / inflow / outflow), guard kind (safe / timelock
// / eoa / unknown / open), and the cross-contract caller walk that drives
// `collectDirectCallers` + `guardSummary` + lane categorization. Used by the
// state-variant tests in src/surface/ProtocolSurface.test.jsx.
const SAFE_ADDR = "0xaaaa000000000000000000000000000000000aaa";
const TIMELOCK_ADDR = "0xbbbb000000000000000000000000000000000bbb";
const EOA_ADDR = "0xcccc000000000000000000000000000000000ccc";
const VAULT_ADDR = "0x1111111111111111111111111111111111111111";
const POOL_ADDR = "0x2222222222222222222222222222222222222222";
// Safe signer addresses — real /api/company puts full 40-hex owners in
// principal.details.owners; the entity card renders one row each + the
// "threshold/owners" badge, so the count is load-bearing (2/3).
const OWNER_1 = "0xd111000000000000000000000000000000000111";
const OWNER_2 = "0xd222000000000000000000000000000000000222";
const OWNER_3 = "0xd333000000000000000000000000000000000333";

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

function principal(address, resolvedType, details = {}, label = null, sourceControllerId = null) {
  return {
    address,
    resolved_type: resolvedType,
    label,
    details,
    source_contract: null,
    source_controller_id: sourceControllerId,
  };
}

// Overview `analysis_provenance.job` as build_company_overview publishes it.
function provenanceJob(jobId, over = {}) {
  return {
    job_id: jobId,
    state: "current_analyzer",
    static_analyzer_version: 12,
    static_reused_from_job_id: null,
    started_at: "2026-07-12T08:00:00+00:00",
    last_pipeline_pass_at: "2026-07-12T09:30:00+00:00",
    ...over,
  };
}

export const ETHERFI_COMPANY_RICH = {
  // Monitoring id — present so the Surface Monitor tab reaches its real
  // render path (contract alerts / global list / principal hint) instead of
  // the "no monitoring id" early return.
  protocol_id: 1,
  contracts: [
    {
      address: VAULT_ADDR,
      name: "Vault",
      is_proxy: true,
      proxy_type: "ERC1967",
      upgrade_count: 2,
      upgrade_count_basis: { history_fetch_status: "complete", events_total: 3, events_unlinked: 0, events_without_tx_hash: 0, deployments_excluded: 1, recorded_count_relation: "exact" },
      control_model: "timelock",
      controllers: { owner: SAFE_ADDR },
      controller_reads: {
        owner: { value: SAFE_ADDR, block_number: 21000000, block_basis: "head_before_read", observed_via: "eth_call" },
      },
      controller_values_state: null,
      last_upgrade_block: 20990000,
      last_upgrade_timestamp: "2026-07-10T16:20:00+00:00",
      last_upgrade_state: "established",
      role: "utility",
      role_evidence: "witnessed",
      job_id: "vault-job",
      impl_job_id: "vault-impl-job",
      analysis_provenance: {
        job: provenanceJob("vault-job"),
        impl_job: provenanceJob("vault-impl-job", { static_reused_from_job_id: "donor-job-0001" }),
      },
      functions: [
        fn("upgrade", ["upgrade"], [principal(TIMELOCK_ADDR, "timelock", { delay: 86400 })]),
        fn("pause", ["pause"], [principal(SAFE_ADDR, "safe", { owners: ["0x1", "0x2", "0x3"], threshold: 2 }, null, "owner")]),
        fn("unpause", ["unpause"], [principal(SAFE_ADDR, "safe", { owners: ["0x1", "0x2", "0x3"], threshold: 2 }, null, "owner")]),
        fn("deposit", ["asset_pull"], [], { public: true }),
        fn("withdraw", ["asset_send"], [principal(EOA_ADDR, "eoa")]),
        fn("setFee", ["config"], [principal(SAFE_ADDR, "safe", { owners: ["0x1", "0x2", "0x3"], threshold: 2 })]),
      ],
    },
    {
      address: POOL_ADDR,
      name: "LiquidityPool",
      is_proxy: false,
      upgrade_count: null,
      upgrade_count_basis: null,
      controllers: {},
      controller_reads: {},
      controller_values_state: null,
      last_upgrade_block: null,
      last_upgrade_timestamp: null,
      last_upgrade_state: null,
      // The fall-through role with every input unread.
      role: "utility",
      role_evidence: "not_determined",
      job_id: "pool-job",
      analysis_provenance: {
        job: provenanceJob("pool-job", { state: "older_analyzer", static_analyzer_version: 11 }),
        impl_job: null,
      },
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
  member_analysis: {
    members: 2,
    analyzed: 2,
    not_determined: 0,
    by_state: { analysis_failed: 0, analysis_not_completed: 0 },
    not_analyzed: [],
    analyzed_at_older_version: [
      {
        contract_id: 2,
        address: POOL_ADDR,
        chain: "ethereum",
        name: "LiquidityPool",
        stale_analysis_job_id: "pool-job",
        stale_analysis_version: 11,
      },
    ],
  },
  // Top-level governance principals — the exact shape /api/company emits
  // (services/aggregations/company_overview/governance_view.py builds
  // `principals` with type/label/details/controls
  // /primary_for/co_controls/controls_detail). ProtocolSurface reads
  // companyData.principals directly (visiblePrincipals filter → SearchNavigator
  // + EntityCard + SurfaceCanvas), so these fields drive the safe/timelock
  // search-and-select flow the stage-1 tests exercise.
  principals: [
    {
      address: SAFE_ADDR,
      type: "safe",
      label: "Multisig",
      details: { address: SAFE_ADDR, owners: [OWNER_1, OWNER_2, OWNER_3], threshold: 2 },
      // Controls both contracts that exist in this fixture — the leak in the
      // original bug picked controls[0] (Vault) and smuggled it into every tab.
      controls: [VAULT_ADDR, POOL_ADDR],
      primary_for: [VAULT_ADDR],
      co_controls: [POOL_ADDR],
      controls_detail: [
        { address: VAULT_ADDR, functions: ["pause", "unpause", "setFee"], capabilities: ["pause", "config"] },
        { address: POOL_ADDR, functions: ["setOracle"], capabilities: ["config"] },
      ],
    },
    {
      address: TIMELOCK_ADDR,
      type: "timelock",
      label: "Timelock",
      details: { address: TIMELOCK_ADDR, delay: 86400 },
      controls: [VAULT_ADDR],
      // Empty: the server assigns each contract to exactly ONE principal's
      // primary_for, and the safe above already primary-owns VAULT_ADDR. The
      // timelock is a co-controller of the upgrade path, not its primary.
      primary_for: [],
      co_controls: [VAULT_ADDR],
      controls_detail: [
        { address: VAULT_ADDR, functions: ["upgrade"], capabilities: ["upgrade"] },
      ],
    },
  ],
  fund_flows: [
    { from: VAULT_ADDR, to: POOL_ADDR, label: "rebalance", usd: 1000000 },
  ],
  // Server-computed reach:
  // the safe's walk reaches the Vault at hop 1 and the LiquidityPool at hop 2
  // through it, and was refused continuing from the pool to the EOA — a
  // not_determined frontier entry, distinct from both reached and absent.
  // Entities without a record here (the timelock, every contract) get NO
  // overlay: absence of the witness is not reach.
  reach: {
    model: "scorer_closure_v1",
    entities: {
      [`ethereum::${SAFE_ADDR}`]: {
        reached: {
          [`ethereum::${VAULT_ADDR}`]: { hop: 1, basis: "signal_seed" },
          [`ethereum::${POOL_ADDR}`]: { hop: 2, basis: "walked_hop" },
        },
        parents: {
          [`ethereum::${VAULT_ADDR}`]: `ethereum::${SAFE_ADDR}`,
          [`ethereum::${POOL_ADDR}`]: `ethereum::${VAULT_ADDR}`,
        },
        frontier: [
          {
            from: `ethereum::${POOL_ADDR}`,
            to: `ethereum::${EOA_ADDR}`,
            reason: "gate_does_not_confer_this_scope",
            basis: "conferral",
          },
        ],
      },
    },
  },
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
