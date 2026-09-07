# Assessment schema proposal — table-first

Status: implemented storage contract. Collection adapters and product views are
tracked separately in the [implementation plan](ASSESSMENT_IMPLEMENTATION_PLAN.md).

Claims are reused through `analysis_outputs`; they are not owned by one run.
Scenario scope references a reusable content-addressed context and a step.

The [complete logical declaration](assessment-schema.proposal.ts) now uses rows
with explicit IDs and actual enums for controlled vocabularies. It contains no
per-document schema version, per-record revision counter, or separate analyzer
version string. Production schema changes belong to database migrations.

An analyzer-build reference remains because it identifies the implementation
and configuration that produced an answer. Code hashes and recording times also
remain: they describe evidence and historical meaning.

## Decision summary

Use four canonical record families: **Subject, Evidence, Claim, Analysis**.
History and current state query the same retained rows. Scenarios are analysis
contexts, with no copied baseline or separate historical model.

| Table | Owns |
| --- | --- |
| subjects | Stable identities |
| evidence | Immutable observations and provenance |
| claims | Scoped, supported assertions and their derivations |
| analyses | Reproducible runs, coverage, diagnostics, and corrections |

Every row has an explicit primary key, `id`, and an immutable `recorded_at`.
A query bundle returns arrays of rows rather than `Record<Key, T>` mappings.

References identify rows or shared payloads. Variable-length relationships such
as claim prerequisites can use join tables and appear as arrays in API views.
Do not independently store both representations of a relationship. This is a
logical table-first proposal, not a decision to split every nested expression
into a separate physical table.

Preserve existing features, including historical permissions. Remove old
implementations only after equivalent behavior is verified.

## Common field types

| Type | Meaning |
| --- | --- |
| Key | Row or content-store identifier; open-ended data, not an enum |
| Instant | UTC timestamp |
| UInt / Int | Lossless decimal integer strings |
| Address | Normalized 20-byte chain address |
| Hash | 32-byte digest |
| Selector | Four-byte ABI selector |
| Index | Non-negative safe integer |
| ChainId | Supported positive chain identifier |

Controlled categories use enums. IDs, addresses, amounts, timestamps, source
paths, and human-readable messages remain data values.

Enum members have explicit stable serialized values. For example,
`ScopeKind.Point` serializes as `point`; this is a validated enum value, not an
arbitrary string or an unstable implicit ordinal.
Existing enum values must not be reassigned different meanings. Additions and
schema migrations must preserve historical values, evidence, and references.

## 1. Subjects

| Column | Type | Purpose |
| --- | --- | --- |
| id | Key | Primary key |
| recorded_at | Instant | When the identity was recorded |
| kind | SubjectKind | Address, Code, Function, Controller, Role, Proposal, Operation |
| identity fields | Typed by kind | The stable identifying fields below |

| SubjectKind | Identity fields |
| --- | --- |
| Address | chain_id, address |
| Code | runtime_code_hash |
| Function | code reference, FunctionIdentity |
| Controller | deployment reference, code reference, controller_key |
| Role | authority reference, RoleIdentity |
| Proposal | governor reference, on-chain proposal_id |
| Operation | timelock reference, on-chain operation_id |

A subject does not independently store its owner, delay, implementation, or
current status. Those are changing claims. Address classification is also a
claim, since the address's behavior can change.

`FunctionIdentityKind` distinguishes ABI, Fallback, Receive, and Source.
Known ABI identities include a canonical signature and matching selector.
Source-only identities retain their location without acquiring a guessed
dispatch. `RoleIdentityKind` distinguishes integer and bytes32 identifiers.

## 2. Evidence

| Column | Type | Purpose |
| --- | --- | --- |
| id | Key | Primary key |
| recorded_at | Instant | When the observation became durable |
| subject | Key | What was observed |
| source | EvidenceSource | Typed acquisition and chain provenance |
| payload | Key | Original bytes in the shared content store |
| obtained_at | Instant | When the observation was acquired |

| EvidenceKind | Additional source fields |
| --- | --- |
| ChainRead | ChainPoint and original request |
| ChainEvent | ChainPoint, transaction hash/index, log index, original request |
| Artifact | Typed locator within the payload |
| Execution | ExecutionEnvironment and the appropriate chain or simulation context |
| External | Source identifier and original request |

`ExecutionEnvironment` is Chain, Fork, or Model. Actual execution names a chain
transaction. A fork/model observation names its baseline and, when applicable,
the scenario analysis and step.

Payload bytes are content-addressed and stored once. Distinct observations
retain their provenance even when their payloads match. Evidence is retained
even when analysis produces no supported claim.

The initial state-query boundary is block end. Event ordering remains available
for reconstruction and timelines. Intra-transaction state assertions require
additional position semantics and proof.

## 3. Claims

| Column | Type | Purpose |
| --- | --- | --- |
| id | Key | Immutable assertion/derivation identity |
| recorded_at | Instant | When the supported assertion became durable |
| subject | Key | What the assertion describes |
| proposition | Proposition | Typed statement, discriminated by ClaimKind |
| scope | ClaimScope | Code, point, verified interval, or scenario step |
| basis | Basis | Evidence and exact prerequisite claim IDs |
| rule | DerivationRule | Controlled derivation category within the referenced implementation |

There is no separate Support record and no current/history flag.

| ScopeKind | Fields | Meaning |
| --- | --- | --- |
| Code | code reference | Property of an immutable code version |
| Point | at: ChainPoint | Supported at one block-end state |
| Interval | from, through: ChainPoint | Supported throughout a bounded inclusive period |
| Scenario | context, step | Conditional state within a reusable scenario context |

`ChainPoint` contains chain_id, block_number, and block_hash. An interval must
be ordered, on one canonical branch, and justified by continuity evidence.
Matching polling observations do not prove the interval between them.

Example view of the same claim table:

| id | subject | statement | scope | basis |
| --- | --- | --- | --- | --- |
| c1 | Timelock T | minimum_delay = 48 hours | Point: block 100 | read e1 |
| c2 | Timelock T | minimum_delay = 6 hours | Point: block 200 | read e2 |
| c3 | Timelock T | minimum_delay = 6 hours | Scenario: step 1 | proposal/code evidence and explicit assumptions |

These rows do not imply that the value was continuously 48 hours between blocks
100 and 200. Additional coverage can justify a new interval assertion.

### Claim vocabulary

`ClaimKind` covers function effects, function authority, authority capabilities,
authority relationships, entity classification, deployment code, implementation
bindings, role membership, configuration, proposal contents/state/timing/quorum,
operation state/timing, applied configuration, and dependencies.

Authority-capability and applied-configuration propositions reference their
prerequisite claims instead of copying those assertions. Those typed references
are implicit dependency edges; they need not be repeated in `basis.claims`.

All prerequisites in a derivation are required. Alternative proofs can coexist
as separate claim rows. Views group equivalent conclusions while preserving
their distinct explanations and conflicts.

### Configuration and authority

| Enum | Controlled values |
| --- | --- |
| ConfigurationParameter | Owner, PendingOwner, MinimumDelay, VotingDelay, VotingPeriod, ProposalThreshold, QuorumRule, SafeSigners, SafeThreshold, RoleAccess |
| ClockKind | BlockNumber, Timestamp, Custom |
| QuorumRuleKind | Absolute, Fraction, Function |
| BindingPhase | Creation, Snapshot, Schedule, Execution |
| ProposalState | Pending, Active, Succeeded, Defeated, Queued, Executed, Cancelled, Expired, Vetoed |
| OperationState | Scheduled, Ready, Executed, Cancelled, Expired |
| SetCompleteness | Exact, LowerBound |

Amounts retain explicit units. A custom clock requires its definition and
cannot silently become wall-clock time. Unsupported parameters remain evidence
plus coverage omissions.

Authority expressions preserve public/entity/controller/role access, any/all
combinations, thresholds, conditional access, finite sets, exclusions, signatures,
and external checks. Conditions and operands use enums for their kinds and
operators. Opaque guards do not establish satisfied conditions or permitted
callers. All 39 existing EffectKind values are retained; display families are
derived from their registry rather than copied onto each record.

## 4. Analyses

| Column | Type | Purpose |
| --- | --- | --- |
| id | Key | Primary key |
| recorded_at | Instant | Publication time |
| producer | AnalysisProducer | Static, Observation, Resolution, Policy, Principal, Execution, Governance, Scenario, Correction |
| implementation | Key | Analyzer build/configuration manifest |
| started_at / finished_at | Instant | Actual run timing |
| outcome | AnalysisOutcome | Completed, Partial, Failed |
| context | AnalysisContext | Observed or explicit scenario inputs |
| inputs | Basis | Exact observations and claims considered |
| coverage | Coverage[] | Scope examined and its completeness |
| diagnostics | Diagnostic[] | Typed limitations and failures |
| corrections | Correction[] | Justified invalidation of prior evidence or claims |

No independent `version` field is stored alongside the implementation
reference. No schema-version tag is stored on analytical records or bundles.

| Supporting shape | Fields |
| --- | --- |
| Coverage | subject, CoverageDomain, scope, CoverageCompleteness, evidence, omissions |
| Diagnostic | Severity, DiagnosticCode, message, subject/scope, raw details reference |
| Correction | CorrectionTargetKind and key, CorrectionReason, justification evidence |

Original exception names, responses, and traces remain in raw details. The
controlled diagnostic category is an enum.

### Scenario context

| Field | Purpose |
| --- | --- |
| kind | AnalysisContextKind.Scenario |
| base | Concrete ChainPoint |
| known_at | Knowledge-time cutoff; exact input IDs pin reproducibility |
| proposal | Optional proposal subject |
| actions | Ordered top-level transactions |
| assumptions | Explicit hypothetical premises |

An Action has ActionKind.Call or ActionKind.Deploy, a chain, sender, calldata or
init-code payload, target where applicable, and value. Step zero is the baseline;
step N follows the first N actions.

Evaluate atomic governance batches through their real entry points. Their
internal calls and rollback behavior follow the code. Separate transactions can
leave earlier changes committed after a later failure. Contract impersonation
does not prove that a governance execution path is reachable.

Scenario conclusions cannot satisfy observed-state queries. A simulated
execution does not prove an operation happened on-chain. Code-behavior claims
using controlled execution need an appropriate validated derivation rule.

The first scenario implementation handles one chain's ordered actions.
Cross-chain payloads remain retained, but end-to-end conclusions require modeled
delivery, ordering, and finality. Predicted deployment addresses require enough
nonce/creation evidence.

Finalized failures and available evidence are retained. In-progress worker
status and transport failures remain operational records that can exist before
any analytical result is publishable.


## 5. Updates, corrections, and queries

| Event | Required behavior |
| --- | --- |
| Alice is replaced by Bob | Append new observations and scoped claims; keep Alice's valid historical assertions. |
| Observation at block 200 fails | Keep the block-100 observation. Report current knowledge as stale/unknown unless continuity is otherwise proven. |
| An analyzer was wrong | Append a correction and corrected derivations. Exclude invalid dependent proofs from best-known views, retaining the audit trail. |
| A chain reorg occurs | Retain orphaned observations; invalidate canonical-chain derivations that require them and analyze the replacement branch. |
| A proposal is evaluated | Pin its baseline, ordered actions, and assumptions. Produce conditional, scenario-scoped claims. |
| A proposal executes | Ingest actual execution evidence and derive real-state claims; compare with the scenario without promoting predictions into facts. |

Queries use a chain/code/scenario scope and optionally a knowledge-time cutoff.
"Current" resolves to a concrete chain point and reports coverage and last-known
observations where that point cannot be established. History queries use the
same records over a range. Later discoveries may improve an old block's answer;
`known_at` allows inspection of the earlier published understanding.

A scope change is not a correction. Correctly knowing Alice was owner at block
100 remains useful after Bob is owner at block 200. A late-discovered intervening
change can, however, disprove a previously inferred broad interval, requiring a
correction to that interval assertion rather than to the valid point observation.

## 6. Governance and downstream effects

For each proposal/operation, preserve the configuration actually consulted at
creation, snapshot, scheduling, or execution as established by that implementation.
The model does not assume all governance systems freeze settings at the same step.

An applied-configuration claim cites both the configuration assertion and the
evidence/rule establishing its binding to that proposal or operation. Thus an
old queued operation can retain its recorded ready time when the global minimum
delay changes, when that is how the contract works.

Downstream answers are derived from prerequisites and typed authority/effect
relationships. Present direct changes, consequential capability changes, and
unassessed areas separately. Ability to move assets is distinct from an actual
asset movement. Unsupported upgrade code or unresolved call targets limit the
impact assessment; they never imply "no downstream effects."

When a baseline advances, retain the old scenario result and mark its applicability
to the current decision as stale. Reevaluate affected dependencies for a new
analysis. Corrections to its premises can invalidate its conclusions even for the
old baseline; ordinary later chain changes do not rewrite the old hypothetical.

## 7. Storage and cutover acceptance

Canonical records are immutable rows or immutable artifacts. Large
payloads are stored once by content hash. Current indexes, timelines, labels,
and graph layouts are rebuildable projections. A mutable pointer to the latest
view is permitted; overwriting the sole copy of historical evidence is not.

Publishing a completed analysis and its claims has one atomic visibility boundary.
Corrections and dependency eligibility must also be applied coherently in views.
Readers never interpret a partially updated collection of indexes as a new truth.

"Store everything" means all evidence actually collected within the configured
analysis scope, all finalized outcomes, and their provenance. It does not assert
that PSAT fetched the entire chain or that a partial scan has complete history.

Required before the big-bang cutover:

1. Feature-parity mapping for every existing analytical and public API capability,
   including principal-history intervals; no unapproved feature retirement.
2. Current and historical permission tests, including gaps and changes within a block.
3. Rebuild analytical indexes without fresh RPC, classification, or graph discovery.
4. Dependency correction tests: invalidate one proof while preserving an independent valid proof.
5. Proposal configuration-binding and ordered-action tests, including already queued operations.
6. Scenario isolation, stale-baseline, and execution-versus-prediction tests.
7. Reorg and late-discovery tests across both chain scope and knowledge time.
8. Persistence tests proving completed updates and corrections do not erase earlier records.

Old implementations can be deleted in the same release once their replacements
pass parity tests. The current deletion of principal history has no temporal
replacement yet and therefore cannot be treated as accepted consolidation.

## Review decisions

Recommended defaults for this proposal:

- Keep scope and provenance on each immutable Claim; defer a separate Support type.
- Put scenario context on Analysis; introduce a reusable Scenario object only if
  repeated evaluations demonstrate a concrete need beyond shared action payloads.
- Begin with block-end state queries and preserved event ordering.
- Require bounded, evidence-backed intervals; never infer uninterrupted history
  from polling alone.
- Make feature parity and offline projection rebuilding release requirements.

## Expanded declaration: validation rules

The logical TypeScript alone cannot enforce these invariants. They are required
of production validators and derivation rules:

1. **Reference kinds:** each key resolves to its expected record/payload kind.
   For example, `configuration_claim` names a configuration Claim; `role` names
   a role Subject; a function Subject's `code` names a code Subject. A response
   may be paginated, but the canonical store must resolve its references.
2. **Identity:** chain IDs are registered positive safe integers; addresses and
   digests have their declared widths. ABI signatures are canonical and hash to
   their selectors. Source-only identities cannot be used as known dispatches.
3. **Record metadata:** subjects use identity-derived keys; analytical records
   have immutable row IDs. `recorded_at` describes publication time. Knowledge-time
   queries must resolve to complete publications; internal commit ordering belongs
   to storage, not a repeated domain revision field. No completed update overwrites its predecessor.
4. **Claim subject:** each proposition family specifies its legal subject kind.
   Deployment-specific function authority names the deployment as subject and a
   code-version function in its proposition; a code-only effect may name that
   function directly. Configuration and lifecycle facts target the appropriate
   address, proposal, or operation.
5. **Scope and dependencies:** chain intervals are bounded, ordered, and on one
   branch. Their bases include continuity evidence. Dependencies use exact claim
   versions. Historical configuration bindings are checked by their binding rule,
   not by blindly requiring all prerequisites to describe the same block.
6. **Implicit prerequisites:** typed proposition fields that reference claims
   are part of the dependency graph automatically. An authority-capability claim
   points to authority and effect claims rather than copying their content. The
   same references need not be repeated in `basis.claims`.
7. **No circular proof:** the combined explicit and implicit prerequisite graph
   is acyclic. Claim-free failures remain analysis records and diagnostics.
8. **Negative answers:** an absent role member or excluded principal requires
   adequate evidence. A lower-bound exclusion list cannot establish the entire
   allowed caller set. `opaque` conditions preserve an observed guard, not a
   proven permission or a satisfied condition.
9. **Units and ranges:** amounts remain lossless integers; quorum denominators
   are positive; thresholds are consistent with the verified group semantics.
   A block clock is never silently converted into seconds, and an unsupported
   custom clock has no inferred wall-clock deadline.
10. **Scenario isolation:** scenario claims reference their producing scenario
    Analysis and valid steps. Actual-state claims cannot depend on hypothetical
    premises. Simulation evidence is explicitly marked; it cannot establish that
    an operation actually executed on-chain.
11. **Uncertainty and conflict:** unresolved meaning stays in evidence/coverage.
    Views distinguish supported, conflicting, unknown, and last-known answers.
    They do not silently resolve incompatible proofs by choosing the latest row.
12. **Corrections:** invalidation propagates through both kinds of dependency
    edge. Unaffected alternative proofs remain eligible. Corrections are applied
    at the selected knowledge boundary and never masquerade as ordinary on-chain
    configuration changes.

`Recorded`, `ChainPoint`, `Authority`, `Configuration`, and the other helper
types are embedded shapes, not requirements for separate databases or copies of
history. `Payload` describes shared raw-byte storage outside the four analytical
record tables. Registered enum vocabularies can be extended through reviewed schema and
adapter changes; raw evidence is retained while a meaning remains unsupported.
