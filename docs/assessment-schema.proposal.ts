/**
 * COMPLETE LOGICAL DECLARATION — implemented by the temporal Assessment store.
 *
 * Four canonical record families: Subject, Evidence, Claim, Analysis.
 * Other types below are embedded shapes, query metadata, or raw payload storage.
 * Records are rows with explicit IDs; query bundles contain row arrays.
 * Runtime invariants are specified in ASSESSMENT_SCHEMA_PROPOSAL.md.
 */

export type Key = string;
export type Instant = string; // ISO-8601 UTC timestamp
export type UInt = string; // canonical unsigned decimal integer; no precision loss
export type Int = string; // canonical signed decimal integer
export type Index = number; // non-negative safe integer
export type ChainId = number; // positive safe integer from the supported chain registry
export type Address = string; // normalized lower-case 20-byte hex address
export type Hash = string; // 32-byte hex digest; algorithm defined by the field
export type Selector = string; // 4-byte hex selector
export type Hex = string; // even-length hexadecimal byte string

// Immutable row identity and recording time; no per-record schema-version tag.
export type Recorded = {
  id: Key;
  recorded_at: Instant;
};

export type ChainPoint = {
  chain_id: ChainId;
  block_number: UInt;
  block_hash: Hash;
};

export type ChainScope =
  | { kind: ScopeKind.Point; at: ChainPoint }
  | { kind: ScopeKind.Interval; from: ChainPoint; through: ChainPoint };

export type ClaimScope =
  | { kind: ScopeKind.Code; code: Key }
  | ChainScope
  | { kind: ScopeKind.Scenario; context: Key; step: Index };

// "Current" resolves to a concrete point; history is a range over the same model.
export type AssessmentView =
  | { kind: ViewKind.Code; code: Key; known_at: Instant }
  | { kind: ViewKind.Chain; scope: ChainScope; known_at: Instant }
  | { kind: ViewKind.Scenario; context: Key; step: Index; known_at: Instant };

export type Assessment = {
  view: AssessmentView;
  subjects: Subject[];
  evidence: Evidence[];
  claims: Claim[];
  analyses: Analysis[];
  contexts: AnalysisContext[];
  implementations: Implementation[];
  payloads: PayloadMetadata[];
  corrections: Correction[];
};

// ---------- Stable identities ----------

export type Subject = Recorded & (
  | { kind: SubjectKind.Address; chain_id: ChainId; address: Address }
  | { kind: SubjectKind.Code; runtime_code_hash: Hash }
  | { kind: SubjectKind.Function; code: Key; identity: FunctionIdentity }
  | { kind: SubjectKind.Controller; deployment: Key; code: Key; controller_key: string }
  | { kind: SubjectKind.Role; authority: Key; identity: RoleIdentity }
  | { kind: SubjectKind.Proposal; governor: Key; proposal_id: string }
  | { kind: SubjectKind.Operation; timelock: Key; operation_id: string }
);

export type FunctionIdentity =
  | { kind: FunctionIdentityKind.Abi; signature: string; selector: Selector }
  | { kind: FunctionIdentityKind.Fallback }
  | { kind: FunctionIdentityKind.Receive }
  | { kind: FunctionIdentityKind.Source; signature: string; locator: Locator };

export type RoleIdentity =
  | { kind: RoleIdentityKind.Integer; value: UInt }
  | { kind: RoleIdentityKind.Bytes32; value: Hash };

export type Locator =
  | { kind: LocatorKind.Whole }
  | { kind: LocatorKind.JsonPointer; pointer: string }
  | { kind: LocatorKind.Source; path: string; start_line: Index; end_line: Index }
  | { kind: LocatorKind.Bytecode; start_pc: Index; end_pc: Index };

// ---------- Immutable observations ----------

export type Evidence = Recorded & {
  subject: Key;
  source: EvidenceSource;
  payload: Key; // content-store key for original bytes
  obtained_at: Instant;
};

export type EvidenceSource =
  | { kind: EvidenceKind.ChainRead; at: ChainPoint; request: Key }
  | {
      kind: EvidenceKind.ChainEvent;
      at: ChainPoint;
      transaction_hash: Hash;
      transaction_index: Index;
      log_index: Index;
      request: Key;
    }
  | { kind: EvidenceKind.Artifact; locator: Locator }
  | ExecutionSource
  | { kind: EvidenceKind.External; source: string; request: Key };

export type ExecutionSource =
  | { kind: EvidenceKind.Execution; environment: ExecutionEnvironment.Chain; at: ChainPoint; transaction_hash: Hash; request: Key }
  | {
      kind: EvidenceKind.Execution;
      environment: ExecutionEnvironment.Fork | ExecutionEnvironment.Model;
      base: ChainPoint;
      request: Key;
      context: { kind: ExecutionContextKind.Baseline } | { kind: ExecutionContextKind.Scenario; context: Key; step: Index };
    };

// Content-addressed byte storage, fetched separately rather than copied into claims.
export type Payload = {
  media_type: string;
  byte_length: UInt;
  data_base64: string;
};

export type PayloadMetadata = Recorded & Omit<Payload, "data_base64">;

// ---------- Supported, scoped assertions ----------

export type Basis = {
  evidence: Key[];
  claims: Key[]; // exact prerequisite claim versions; all listed inputs are required
};

export type Claim = Recorded & {
  subject: Key;
  proposition: Proposition;
  scope: ClaimScope;
  basis: Basis;
  rule: DerivationRule;
};

export type Proposition =
  | { kind: ClaimKind.FunctionEffect; function: Key; effect: Effect }
  | { kind: ClaimKind.FunctionAuthority; function: Key; authority: Authority }
  | { kind: ClaimKind.AuthorityCapability; authority_claim: Key; effect_claim: Key }
  | { kind: ClaimKind.AuthorityRelationship; authority: Authority; target: Key; relationship: AuthorityRelationship }
  | { kind: ClaimKind.EntityClassification; classification: EntityClassification }
  | { kind: ClaimKind.DeploymentCode; code: Key }
  | { kind: ClaimKind.Implementation; implementation: Key; code: Key }
  | { kind: ClaimKind.RoleMembership; role: Key; principal: Key; present: boolean }
  | { kind: ClaimKind.Configuration; setting: Configuration }
  | { kind: ClaimKind.ProposalContents; contents: Key }
  | { kind: ClaimKind.ProposalState; state: ProposalState }
  | { kind: ClaimKind.ProposalTiming; field: ProposalTiming; value: ClockValue }
  | { kind: ClaimKind.ProposalQuorum; required: UInt; unit: VotingUnit; checkpoint: ClockValue }
  | { kind: ClaimKind.OperationState; state: OperationState }
  | { kind: ClaimKind.OperationTiming; field: OperationTiming; value: ClockValue }
  | { kind: ClaimKind.AppliedConfiguration; configuration_claim: Key; phase: BindingPhase }
  | { kind: ClaimKind.Dependency; dependency: DependencyKind; target: Operand };

// Claim references in propositions are implicit prerequisites, indexed once.
// Do not repeat authority_claim/effect_claim/configuration_claim in Basis.claims.

export enum EntityClassification {
  Zero = "zero",
  Eoa = "eoa",
  Contract = "contract",
  Safe = "safe",
  Timelock = "timelock",
  ProxyAdmin = "proxy_admin",
  OffChainWitness = "off_chain_witness",
  CrossChainAuthority = "cross_chain_authority",
}

export enum AuthorityRelationship {
  ControllerValue = "controller_value",
  SafeOwner = "safe_owner",
  TimelockOwner = "timelock_owner",
  ProxyAdminOwner = "proxy_admin_owner",
  RolePrincipal = "role_principal",
  MappingMember = "mapping_member",
  CapabilityPrincipal = "capability_principal",
}

export enum DependencyKind {
  Calls = "calls",
  Reads = "reads",
  Writes = "writes",
  DelegatesTo = "delegates_to",
}

// These describe supported authority conditions; they do not assert that an
// external-check contract or a signature witness is itself a permitted caller.
export type Authority =
  | { kind: AuthorityKind.Public }
  | { kind: AuthorityKind.Entity; entity: Key }
  | { kind: AuthorityKind.Controller; controller: Key }
  | { kind: AuthorityKind.Role; role: Key }
  | { kind: AuthorityKind.Any; children: Authority[] }
  | { kind: AuthorityKind.All; children: Authority[] }
  | { kind: AuthorityKind.Threshold; required: UInt; members: Key[] }
  | { kind: AuthorityKind.Conditional; authority: Authority; condition: Condition }
  | { kind: AuthorityKind.Expression; expression: CapabilityExpression };

export enum SetCompleteness {
  Exact = "exact",
  LowerBound = "lower_bound",
}

export type CapabilityExpression =
  | { kind: CapabilityKind.FiniteSet; members: Key[]; completeness: SetCompleteness }
  | { kind: CapabilityKind.ThresholdGroup; group: Key; required: UInt; members: Key[]; completeness: SetCompleteness }
  | { kind: CapabilityKind.CofiniteBlacklist; excluded: Key[]; completeness: SetCompleteness }
  | { kind: CapabilityKind.SignatureWitness; signers: Authority; scheme: SignatureScheme }
  | { kind: CapabilityKind.ConditionalUniversal; conditions: Condition[] }
  | { kind: CapabilityKind.ExternalCheckOnly; check: ExternalCheck }
  | { kind: CapabilityKind.And; children: CapabilityExpression[] }
  | { kind: CapabilityKind.Or; children: CapabilityExpression[] };

export type SignatureScheme =
  | { kind: SignatureSchemeKind.Ecrecover }
  | { kind: SignatureSchemeKind.Erc1271 }
  | { kind: SignatureSchemeKind.Custom; definition: Key }; // evidence of the scheme; no assumed meaning

export type Condition =
  | { kind: ConditionKind.Comparison; operator: Comparison; left: Operand; right: Operand }
  | { kind: ConditionKind.All; children: Condition[] }
  | { kind: ConditionKind.Any; children: Condition[] }
  | { kind: ConditionKind.Not; child: Condition }
  | { kind: ConditionKind.ExternalCheck; check: ExternalCheck }
  | { kind: ConditionKind.Signature; signers: Authority; scheme: SignatureScheme; message: Operand }
  | { kind: ConditionKind.Opaque; evidence: Key }; // guard exists; its meaning is unassessed

export enum Comparison {
  Eq = "eq",
  Ne = "ne",
  Lt = "lt",
  Le = "le",
  Gt = "gt",
  Ge = "ge",
}
export enum Arithmetic {
  Add = "add",
  Subtract = "subtract",
  Multiply = "multiply",
  Divide = "divide",
  Modulo = "modulo",
  Min = "min",
  Max = "max",
}

export type Operand =
  | { kind: OperandKind.Literal; value: LiteralValue }
  | { kind: OperandKind.Subject; subject: Key }
  | { kind: OperandKind.Parameter; index: Index }
  | { kind: OperandKind.Controller; controller: Key }
  | { kind: OperandKind.Storage; deployment: Key; slot: Hash; path: string[] }
  | { kind: OperandKind.Context; field: ContextField }
  | { kind: OperandKind.CallResult; call: ExternalCheck }
  | { kind: OperandKind.Arithmetic; operator: Arithmetic; operands: Operand[] };

export type LiteralValue =
  | { kind: LiteralKind.Boolean; value: boolean }
  | { kind: LiteralKind.Unsigned; value: UInt }
  | { kind: LiteralKind.Signed; value: Int }
  | { kind: LiteralKind.Bytes; value: Hex }
  | { kind: LiteralKind.String; value: string };

export enum ContextField {
  MsgSender = "msg_sender",
  MsgValue = "msg_value",
  MsgSig = "msg_sig",
  TxOrigin = "tx_origin",
  AddressThis = "address_this",
  BlockNumber = "block_number",
  BlockTimestamp = "block_timestamp",
}

export type ExternalCheck = {
  target: Operand;
  function: Key;
  arguments: Operand[];
  requirement: CallRequirement;
};

export type Effect = {
  kind: EffectKind;
  targets: Operand[];
  affected_functions: Key[];
  conditions: Condition[];
};

// Retain the existing effect vocabulary. Display families are derived from the
// versioned registry rather than independently copied onto each effect.
export enum EffectKind {
  AuthorityGrant = "authority.grant",
  AuthorityReplace = "authority.replace",
  AuthorizedCallerRotate = "authorized_caller.rotate",
  CalleePointerRotate = "callee_pointer.rotate",
  ContractDeployment = "contract_deployment",
  DelegatecallExecute = "delegatecall.execute",
  Erc20Approve = "erc20.approve",
  Erc20Transfer = "erc20.transfer",
  Erc20TransferFrom = "erc20.transfer_from",
  ExecArbitrary = "exec.arbitrary",
  FlowIn = "flow.in",
  FlowOut = "flow.out",
  GovDelegate = "gov.delegate",
  LzOappSetDelegate = "lz_oapp.set_delegate",
  LzOappSetPeer = "lz_oapp.set_peer",
  OwnershipAccept = "ownership.accept",
  OwnershipRenounce = "ownership.renounce",
  OwnershipTransfer = "ownership.transfer",
  PauseSet = "pause.set",
  PauseUnset = "pause.unset",
  ProxyAdminChange = "proxy.admin_change",
  RateLimitConsume = "rate_limit.consume",
  RolesConfigure = "roles.configure",
  RolesGrant = "roles.grant",
  RolesRevoke = "roles.revoke",
  SafeModuleMgmt = "safe.module_mgmt",
  SafeSetGuard = "safe.set_guard",
  SafeSignerMgmt = "safe.signer_mgmt",
  SupplyBurn = "supply.burn",
  SupplyMint = "supply.mint",
  TimelockCancel = "timelock.cancel",
  TimelockExecute = "timelock.execute",
  TimelockSchedule = "timelock.schedule",
  TimelockSetDelay = "timelock.set_delay",
  TransferPolicyConfigure = "transfer_policy.configure",
  UpgradeImplementation = "upgrade.implementation",
  ValueRouter = "value_router",
  WethDeposit = "weth.deposit",
  WethWithdraw = "weth.withdraw",
}

// ---------- Configuration and governance ----------

export type Configuration =
  | { parameter: ConfigurationParameter.Owner; owner: Key | null }
  | { parameter: ConfigurationParameter.PendingOwner; owner: Key | null }
  | { parameter: ConfigurationParameter.MinimumDelay; seconds: UInt }
  | { parameter: ConfigurationParameter.VotingDelay; duration: ClockDuration }
  | { parameter: ConfigurationParameter.VotingPeriod; duration: ClockDuration }
  | { parameter: ConfigurationParameter.ProposalThreshold; amount: UInt; unit: VotingUnit }
  | { parameter: ConfigurationParameter.QuorumRule; rule: QuorumRule }
  | { parameter: ConfigurationParameter.SafeSigners; members: Key[]; completeness: SetCompleteness }
  | { parameter: ConfigurationParameter.SafeThreshold; required: UInt }
  | { parameter: ConfigurationParameter.RoleAccess; role: Key; authority: Authority };


export type Clock =
  | { kind: ClockKind.BlockNumber; chain_id: ChainId }
  | { kind: ClockKind.Timestamp; chain_id: ChainId }
  | { kind: ClockKind.Custom; subject: Key; unit: string; definition: Key };

export type ClockValue = { clock: Clock; value: UInt };
export type ClockDuration = { clock: Clock; amount: UInt };

export type VotingUnit =
  | { kind: VotingUnitKind.Token; token: Key }
  | { kind: VotingUnitKind.Votes; source: Key }
  | { kind: VotingUnitKind.Members; group: Key };

export type QuorumRule =
  | { kind: QuorumRuleKind.Absolute; amount: UInt; unit: VotingUnit }
  | { kind: QuorumRuleKind.Fraction; numerator: UInt; denominator: UInt; supply_source: Key; checkpoint: BindingPhase }
  | { kind: QuorumRuleKind.Function; function: Key; unit: VotingUnit; checkpoint: BindingPhase };

export enum BindingPhase {
  Creation = "creation",
  Snapshot = "snapshot",
  Schedule = "schedule",
  Execution = "execution",
}
export enum ProposalState {
  Pending = "pending",
  Active = "active",
  Succeeded = "succeeded",
  Defeated = "defeated",
  Queued = "queued",
  Executed = "executed",
  Cancelled = "cancelled",
  Expired = "expired",
  Vetoed = "vetoed",
}
export enum ProposalTiming {
  Snapshot = "snapshot",
  VotingStart = "voting_start",
  VotingEnd = "voting_end",
}
export enum OperationState {
  Scheduled = "scheduled",
  Ready = "ready",
  Executed = "executed",
  Cancelled = "cancelled",
  Expired = "expired",
}
export enum OperationTiming {
  ScheduledAt = "scheduled_at",
  ReadyAt = "ready_at",
  ExpiresAt = "expires_at",
}

// contents payload for a proposal_contents claim; calls are not necessarily
// separate transactions. The governor/timelock determines execution semantics.
export type ProposalContents = {
  calls: ProposedCall[];
  description: Key | null; // original description payload
};

export type ProposedCall = {
  chain_id: ChainId;
  target: Key;
  calldata: Key;
  value_wei: UInt;
};

// ---------- Reproducible analyses and hypothetical changes ----------

export type Analysis = Recorded & {
  producer: AnalysisProducer;
  implementation: Key; // content-addressed analyzer build/config manifest
  started_at: Instant;
  finished_at: Instant;
  outcome: AnalysisOutcome;
  context: Key;
  inputs: Basis;
  outputs: Key[]; // analysis_outputs; the same claim may be output by many runs
  coverage: Coverage[];
  diagnostics: Diagnostic[];
  corrections: Correction[];
};

export type AnalysisContext = Recorded & (
  | { kind: AnalysisContextKind.Observed }
  | {
      kind: AnalysisContextKind.Scenario;
      base: ChainPoint;
      proposal: Key | null;
      actions: Action[];
      assumptions: Assumption[];
    }
);

export type Implementation = Recorded & {
  producer: AnalysisProducer;
  manifest: Record<string, unknown>;
};

// Each action is a top-level transaction. Inner-call atomicity follows the code.
export type Action =
  | { kind: ActionKind.Call; chain_id: ChainId; sender: Key; target: Key; calldata: Key; value_wei: UInt }
  | { kind: ActionKind.Deploy; chain_id: ChainId; sender: Key; init_code: Key; value_wei: UInt };

export type Assumption =
  | { kind: AssumptionKind.Fact; subject: Key; proposition: Proposition }
  | { kind: AssumptionKind.ExecutionTime; chain_id: ChainId; timestamp: UInt };

export type Coverage = {
  subject: Key;
  domain: CoverageDomain;
  scope: ClaimScope;
  completeness: CoverageCompleteness;
  evidence: Key[];
  omissions: Diagnostic[];
};

export type CoverageDomain =
  | { kind: CoverageKind.Code }
  | { kind: CoverageKind.StateReads }
  | { kind: CoverageKind.Events; topics: Hash[] }
  | { kind: CoverageKind.Authority }
  | { kind: CoverageKind.Effects; kinds: EffectKind[] }
  | { kind: CoverageKind.Configuration; parameters: ConfigurationParameter[] }
  | { kind: CoverageKind.ProposalLifecycle }
  | { kind: CoverageKind.OperationLifecycle }
  | { kind: CoverageKind.ScenarioActions; from_step: Index; through_step: Index };

export type Diagnostic = {
  severity: Severity;
  code: DiagnosticCode;
  message: string;
  subject: Key | null;
  scope: ClaimScope | null;
  details: Key | null; // raw diagnostic/trace payload, not a positive claim
};

export type Correction = {
  target: { kind: CorrectionTargetKind.Evidence; key: Key } | { kind: CorrectionTargetKind.Claim; key: Key };
  reason: CorrectionReason;
  justification: Key[];
};

// Controlled vocabularies. Values are explicit and stable for serialization.

export enum ScopeKind {
  Point = "point",
  Interval = "interval",
  Code = "code",
  Scenario = "scenario",
}

export enum ViewKind {
  Code = "code",
  Chain = "chain",
  Scenario = "scenario",
}

export enum SubjectKind {
  Address = "address",
  Code = "code",
  Function = "function",
  Controller = "controller",
  Role = "role",
  Proposal = "proposal",
  Operation = "operation",
}

export enum FunctionIdentityKind {
  Abi = "abi",
  Fallback = "fallback",
  Receive = "receive",
  Source = "source",
}

export enum RoleIdentityKind {
  Integer = "integer",
  Bytes32 = "bytes32",
}

export enum LocatorKind {
  Whole = "whole",
  JsonPointer = "json_pointer",
  Source = "source",
  Bytecode = "bytecode",
}

export enum EvidenceKind {
  ChainRead = "chain_read",
  ChainEvent = "chain_event",
  Artifact = "artifact",
  External = "external",
  Execution = "execution",
}

export enum ExecutionEnvironment {
  Chain = "chain",
  Fork = "fork",
  Model = "model",
}

export enum ExecutionContextKind {
  Baseline = "baseline",
  Scenario = "scenario",
}


export enum ClaimKind {
  FunctionEffect = "function_effect",
  FunctionAuthority = "function_authority",
  AuthorityCapability = "authority_capability",
  AuthorityRelationship = "authority_relationship",
  EntityClassification = "entity_classification",
  DeploymentCode = "deployment_code",
  Implementation = "implementation",
  RoleMembership = "role_membership",
  Configuration = "configuration",
  ProposalContents = "proposal_contents",
  ProposalState = "proposal_state",
  ProposalTiming = "proposal_timing",
  ProposalQuorum = "proposal_quorum",
  OperationState = "operation_state",
  OperationTiming = "operation_timing",
  AppliedConfiguration = "applied_configuration",
  Dependency = "dependency",
}

export enum AuthorityKind {
  Public = "public",
  Entity = "entity",
  Controller = "controller",
  Role = "role",
  Any = "any",
  All = "all",
  Threshold = "threshold",
  Conditional = "conditional",
  Expression = "expression",
}

export enum CapabilityKind {
  FiniteSet = "finite_set",
  ThresholdGroup = "threshold_group",
  CofiniteBlacklist = "cofinite_blacklist",
  SignatureWitness = "signature_witness",
  ConditionalUniversal = "conditional_universal",
  ExternalCheckOnly = "external_check_only",
  And = "AND",
  Or = "OR",
}

export enum SignatureSchemeKind {
  Ecrecover = "ecrecover",
  Erc1271 = "erc1271",
  Custom = "custom",
}

export enum ConditionKind {
  Comparison = "comparison",
  All = "all",
  Any = "any",
  Not = "not",
  ExternalCheck = "external_check",
  Signature = "signature",
  Opaque = "opaque",
}

export enum OperandKind {
  Literal = "literal",
  Subject = "subject",
  Parameter = "parameter",
  Controller = "controller",
  Storage = "storage",
  Context = "context",
  CallResult = "call_result",
  Arithmetic = "arithmetic",
}

export enum LiteralKind {
  Boolean = "boolean",
  Unsigned = "unsigned",
  Signed = "signed",
  Bytes = "bytes",
  String = "string",
}

export enum CallRequirement {
  ReturnsTrue = "returns_true",
  DoesNotRevert = "does_not_revert",
  ReturnsValue = "returns_value",
}

export enum ConfigurationParameter {
  Owner = "owner",
  PendingOwner = "pending_owner",
  MinimumDelay = "minimum_delay",
  VotingDelay = "voting_delay",
  VotingPeriod = "voting_period",
  ProposalThreshold = "proposal_threshold",
  QuorumRule = "quorum_rule",
  SafeSigners = "safe_signers",
  SafeThreshold = "safe_threshold",
  RoleAccess = "role_access",
}

export enum ClockKind {
  BlockNumber = "block_number",
  Timestamp = "timestamp",
  Custom = "custom",
}

export enum VotingUnitKind {
  Token = "token",
  Votes = "votes",
  Members = "members",
}

export enum QuorumRuleKind {
  Absolute = "absolute",
  Fraction = "fraction",
  Function = "function",
}

export enum AnalysisOutcome {
  Completed = "completed",
  Partial = "partial",
  Failed = "failed",
}

export enum AnalysisContextKind {
  Observed = "observed",
  Scenario = "scenario",
}

export enum ActionKind {
  Call = "call",
  Deploy = "deploy",
}

export enum AssumptionKind {
  Fact = "fact",
  ExecutionTime = "execution_time",
}

export enum CoverageCompleteness {
  Complete = "complete",
  Partial = "partial",
  Unknown = "unknown",
}

export enum CoverageKind {
  Code = "code",
  StateReads = "state_reads",
  Events = "events",
  Authority = "authority",
  Effects = "effects",
  Configuration = "configuration",
  ProposalLifecycle = "proposal_lifecycle",
  OperationLifecycle = "operation_lifecycle",
  ScenarioActions = "scenario_actions",
}

export enum Severity {
  Info = "info",
  Degraded = "degraded",
  Error = "error",
}

export enum CorrectionTargetKind {
  Evidence = "evidence",
  Claim = "claim",
}

export enum CorrectionReason {
  Reorg = "reorg",
  InvalidObservation = "invalid_observation",
  WrongSubject = "wrong_subject",
  RuleError = "rule_error",
  IncompleteBasis = "incomplete_basis",
}

export enum AnalysisProducer {
  Static = "static",
  Observation = "observation",
  Resolution = "resolution",
  Policy = "policy",
  Principal = "principal",
  Execution = "execution",
  Governance = "governance",
  Scenario = "scenario",
  Correction = "correction",
}

export enum DerivationRule {
  FunctionEffect = "function_effect",
  FunctionAuthority = "function_authority",
  AuthorityCapability = "authority_capability",
  AuthorityRelationship = "authority_relationship",
  EntityClassification = "entity_classification",
  DeploymentCode = "deployment_code",
  ImplementationBinding = "implementation_binding",
  RoleMembership = "role_membership",
  Configuration = "configuration",
  ProposalContents = "proposal_contents",
  ProposalState = "proposal_state",
  ProposalTiming = "proposal_timing",
  ProposalQuorum = "proposal_quorum",
  OperationState = "operation_state",
  OperationTiming = "operation_timing",
  AppliedConfiguration = "applied_configuration",
  Dependency = "dependency",
  HistoricalInterval = "historical_interval",
  ScenarioTransition = "scenario_transition",
}

export enum DiagnosticCode {
  InvalidInput = "invalid_input",
  MissingEvidence = "missing_evidence",
  UnsupportedCode = "unsupported_code",
  UnsupportedParameter = "unsupported_parameter",
  UnsupportedClock = "unsupported_clock",
  UnresolvedIdentity = "unresolved_identity",
  UnresolvedAuthority = "unresolved_authority",
  UnresolvedTarget = "unresolved_target",
  IncompleteCoverage = "incomplete_coverage",
  ConflictingEvidence = "conflicting_evidence",
  RpcFailure = "rpc_failure",
  SourceUnavailable = "source_unavailable",
  ExecutionFailure = "execution_failure",
  AnalysisFailure = "analysis_failure",
  ScopeMismatch = "scope_mismatch",
  StaleBaseline = "stale_baseline",
  OrphanedBlock = "orphaned_block",
}
