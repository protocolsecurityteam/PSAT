# Assessment temporal cutover — implementation plan

Status: implementation in progress on the cutover branch. Core temporal rows,
publication/deduplication, correction selection, legacy import, principal
history, graph projection ownership, typed governance bindings, reusable
scenario contexts, row-shaped API transport, initial OpenZeppelin Governor/
Timelock and Safe getter collectors, proposal-impact UI, and restored-copy
rehearsal tooling are implemented. Broader custom-governor adapters and live
preview verification remain release gates. This plan does not authorize a live
migration or deployment.

## Objective

Replace mutable per-job analytical documents with one canonical, temporal,
evidence-backed model. Preserve existing features while making current answers,
historical answers, and hypothetical proposal effects reproducible views.

Develop in reviewable stages inside the big-bang branch. Production makes one
coordinated transition after all gates pass; do not introduce a long-lived dual
writer or a second authoritative analytical model.

## Fixed requirements

- Four core record families: Subject, Evidence, Claim, Analysis. Supporting
  relationship/context/payload tables are storage structure, not rival models.
- Table/row representations, explicit IDs, and enums for controlled vocabularies.
- No schema-version fields on analytical rows or Assessment responses. Database
  migration bookkeeping remains operational infrastructure.
- Retain the exact analyzer implementation/configuration reference, code hashes,
  and meaningful observation/publication times.
- No separate current/history model. Preserve collected evidence and prior
  assertions rather than overwriting them.
- Reuse identical claims across runs with an `analysis_outputs` relationship.
- Preserve principal history, classification, controller walks, graph coverage,
  permission behavior, and the existing public analytical capabilities.
- Failures and omissions remain analysis outcomes; they do not become claims.
- Preserve the cache speed assertion and the cache-reuse/source assertions.
- Automatic PR live-database resets remain deferred and outside this PR.
- Preserve unrelated dirty/untracked workspace contents.

## Current starting point

The working tree contains unpublished fixes and partial consolidation of the
existing snapshot model. Reuse that work where it meets the new invariants.
Do not assume the previous passing test suite proves temporal correctness.

Known unresolved architecture gaps:

1. Replacing controller observations can leave an old caller claim and a
   `completed` policy receipt eligible. Dependencies are incompletely recorded.
2. `write_permission_rows` still performs live principal classification.
3. Function-principal graph nodes can be materialized only into relational
   tables and a separate summary, outside canonical analytical derivations.
4. Principal-history behavior was removed without its temporal replacement.
5. `store_artifact` overwrites the Assessment body for a job/name.

The schema draft also predates the latest accepted `analysis_outputs` change:
it still has `Claim.analysis` and ties scenario scope to the producing run.
Phase 0 must reconcile those fields before implementation.

## Execution map

| Phase | Deliverable | Depends on | Exit gate |
| --- | --- | --- | --- |
| 0 | Frozen identities, relationships, and temporal semantics | None | Schema/ADR review accepted |
| 1 | Feature-parity inventory and reference corpus | 0 | Every retained behavior mapped |
| 2 | Tables, enums, content store, canonical repository | 0 | Integrity and dedup tests pass |
| 3 | Atomic publication, corrections, temporal eligibility | 2 | Concurrency and history tests pass |
| 4 | Current pipeline writes the canonical model | 1–3 | No independent analytical writers |
| 5 | Historical permissions reconstructed through the model | 1–4 | Principal-history parity verified |
| 6 | Governance/timelock history and configuration bindings | 3–5 | Historical binding tests pass |
| 7 | Scenario execution and downstream impact derivation | 4, 6 | Isolation and execution semantics pass |
| 8 | Unified API and product views | 3–7 | API/UI parity and explainability pass |
| 9 | Loss-preserving import and projection rebuild | Starts after 2; completes after 4–8 | Data reconciliation and restore drill pass |
| 10 | Cutover rehearsal, deletion, and merge/release gates | All above | Reviewed release candidate ready |

The import tooling starts early against copies; it must not be left until the
end. Phases describe dependencies, not permission to deploy intermediate states.

## Phase 0 — Freeze the actual model

### 0.1 Establish a reproducible development baseline

- Record local HEAD, hosted PR head, tracked modifications, and task-owned new
  files. Checkpoint the task changes without absorbing unrelated research files.
- Reconcile the upstream merge carefully before publication. Do not discard the
  existing dirty worktree or use broad reset/checkout operations.
- Pin the pre-cutover implementation and fixture corpus used for parity checks.

### 0.2 Resolve identities and deduplication

Recommended identity rules:

| Record | Identity/dedup basis |
| --- | --- |
| Subject | Stable semantic identity: chain/address, code/function, authority/role, governor/proposal, timelock/operation |
| Payload | Content digest of the original bytes |
| Evidence | A distinct observation occurrence, source/anchor, and payload; identical retry deliveries may be idempotent |
| Claim | Subject + typed proposition + scope + exact proof inputs + rule implementation; exclude run ID and publication timestamp |
| Analysis | One actual attempt; retain separate attempts even when outputs are reused |
| Analysis output | Unique pair `(analysis_id, claim_id)` |

- Define canonical serialization before hashing: enums, integer encoding,
  ordering of mathematical sets, ordered transactions, normalized addresses,
  and distinction between missing and known-empty values.
- Different proofs, blocks, contexts, or actual observations are not accidental
  duplicates. Replaying identical inputs under the same rule can reuse a claim.
- Same hash with different canonical content is an error, never an overwrite.

### 0.3 Remove run ownership from claims

- Replace `Claim.analysis` with `analysis_outputs`.
- Give the claim a rule-implementation reference sufficient to identify its
  proof independently of any one producing run. Analyses reference the same
  implementation manifest; do not copy the manifest into claims.
- Record all producing runs through output links. Partially successful runs may
  publish their supported outputs alongside diagnostics.
- Do not derive claim identity from `recorded_at` or the execution attempt ID.

### 0.4 Make scenario identity reusable

Use a small immutable, content-addressed analysis-context record referenced by
analyses and scenario-scoped claims. This is a reusable input description, not
a new history model or a separate Support system.

- Context identity includes baseline chain point, ordered transactions,
  subject bindings, and explicit assumptions/execution parameters.
- Exclude run ID, wall-clock publication time, and analyzer implementation from
  context identity. Different engines can analyze the same hypothetical world.
- Knowledge-time selection belongs to the run/view; exact selected input IDs
  pin its reproducibility. A later cutoff with identical inputs need not create
  a new hypothetical world.
- Scenario scope identifies `(context_id, step)`. It no longer implicitly means
  "whatever scenario this one analysis happened to run."

### 0.5 Freeze temporal and proof semantics

- Ordinary world changes preserve valid historical claims.
- Corrections invalidate particular evidence/proofs; they do not erase records.
- Explicit and proposition-implied prerequisite edges form one dependency graph.
  Store each relationship once and enforce acyclicity.
- A proof requires all its declared prerequisites. Alternative proofs are
  separate claim rows that views can group.
- Point observations alone do not establish continuity. Intervals require
  bounded, applicable coverage and verified state-transition semantics.
- Configuration bindings may correctly reference an older snapshot; validate
  them by their binding rule, not by requiring every premise at the same block.
- Initial state views are block-end views with full event ordering retained.
  Confirm the baseline principal-history API's granularity. If parity requires
  finer positions, extend the position type now rather than silently dropping it.
- Specify supported/conflicting/unknown/last-known answers and freshness.

**Deliverables:** update both schema proposal files, enum catalog, identity rules,
dependency rules, and a short ADR recording these decisions.

**Gate:** no open ambiguity about claim reuse, scenario identity, interval meaning,
or what qualifies as an observed versus hypothetical conclusion.

## Phase 1 — Establish feature parity before deleting anything

Create a parity matrix from the pre-cutover code, public routes, UI consumers,
tests, and available representative artifacts. Mark each behavior as retained,
corrected with explicit evidence, or a newly proposed capability.

| Capability | Required replacement |
| --- | --- |
| Function inventory and canonical identity | Code/function subjects and deployment bindings |
| Function effects, including pause.set/pause.unset | Scoped effect claims with existing semantics |
| Caller authority, roles, thresholds, signatures, conditions | Exact structured authority claims |
| Principal classification and terminal-controller walks | Evidence and claims consumed by pure projections |
| Graph refresh and function-principal materialization | Canonical relationships with correct derivation provenance |
| Principal-history intervals | Event/observation-backed historical permission views |
| Proxy/shared-implementation scoping | Explicit code and deployment bindings |
| Execution verdicts and cross-contract effects | Retained evidence and scoped derivations |
| Coverage, omissions, partial results, failure receipts | Typed Analysis outcomes |
| Cache reuse and speedup | Reusable canonical inputs/outputs, with equivalent behavior |
| Current public detail/functions/capabilities views | Projections of the canonical model |

- Recover principal-history implementation/tests from the pre-cutover baseline
  for reference. Its earlier deletion is not evidence that the feature is unused.
- Freeze representative cases: owner rotation, role grants/revocations, public
  capability changes, Safe thresholds, shared implementations, guarded callers,
  independent proofs, and missing/partial evidence.
- Add governance/proposal examples to the same corpus rather than creating a
  disconnected test model.
- Preserve input payloads and expected behavior. A demonstrated correction to an
  old false answer must be documented and reviewed, not disguised as parity.

**Gate:** every existing feature has a named replacement and tests. No accepted
feature is removed merely because its current implementation uses an old artifact.

## Phase 2 — Build canonical persistence and enums

Suggested locations: `schemas/assessment.py`, `db/models/assessment.py`, a new
canonical repository module, and explicit Alembic migrations.

| Logical table/group | Responsibility |
| --- | --- |
| subjects | Typed stable identities with natural uniqueness constraints |
| payloads | Content-addressed raw bytes and retrieval metadata |
| evidence | Immutable observations and exact provenance |
| claims | Typed propositions, scope, and proof/rule identity |
| analyses | Actual attempts, implementation reference, context, outcome |
| analysis_outputs | Many-to-many run/output association |
| claim_evidence / claim_dependencies | Canonical proof edges |
| analysis input relationships | Exact inputs consumed, including failed runs |
| analysis_contexts / implementation manifests | Reusable immutable inputs and rule-build provenance |
| coverage, diagnostics, corrections | Typed supporting records/relations owned by analyses |

Tasks:

- Share enum definitions across validation, persistence, and transport. Use
  constrained enum columns; do not reuse an enum value for a different meaning.
- Put searchable scalar identity/time/discriminator fields into columns. Use
  typed variant payloads for genuinely nested expressions. Add subtype tables or
  indexes where the query contract requires them; avoid untyped arbitrary bags.
- Use exact integer storage and lossless wire encoding for EVM amounts.
- Implement strict reference-kind, subject-kind, selector, scope, and unit validation.
- Add indexes for subject/scope lookup, dependency traversal, output reuse,
  analysis attempts, and event occurrence identity.
- Add canonical repository operations for interning identities/payloads,
  appending evidence, preparing outputs, and querying published records.
- Retain raw evidence that cannot yet be interpreted; do not force it into a claim.

**Gate tests:** duplicate ingestion, repeated analysis, distinct proofs, distinct
observations sharing bytes, invalid enum values, wrong reference kinds, malformed
scope/ABI identity, and exact integer round-trips.

## Phase 3 — Publication, corrections, and temporal queries

### Atomic publication

- Stage large immutable payloads before the database publication transaction.
- Publish the analysis, new claims, proof links, and output associations at one
  atomic visibility boundary. Deduplication races must not lose output links.
- Preserve already durable evidence if analysis crashes. Preserve failed attempts
  independently of their ability to produce claims.
- Keep publication ordering internal to storage. Use a short commit-ordered
  publication mechanism so knowledge-time cutoffs cannot later acquire an
  allegedly older, previously uncommitted result. Do not expose a schema-version
  or revision counter on every analytical row.
- Make projection recovery idempotent: an interrupted index rebuild must be
  repairable entirely from published canonical records.

### Eligibility and history

- Implement code, chain-point, interval, and scenario-step selection.
- Apply corrections at the requested knowledge boundary; traverse explicit and
  implicit dependencies to determine eligible proofs.
- Detect conflicting eligible answers. Never silently choose an arbitrary row
  or treat the newest observation as proof of an unobserved interval.
- Preserve last-known values with their actual scope and freshness.
- Keep code claims reusable while requiring valid deployment/code bindings for
  deployment-specific answers.

**Gate tests:** Alice→Bob rotation; failed refresh; A→B→A; same-block multiple
events; independent alternate proof survives correction; correction of an
overbroad interval; late discovery; reorg; concurrent publication; rollback after
payload upload; readers never observe a partially published answer.

## Phase 4 — Move the current pipeline onto the repository

Primary entry points:

- `services/assessment/{static,observations,resolution,policy,effects,principals}.py`
- `workers/{static_worker,resolution_worker,policy_worker,effects_worker}.py`
- `services/resolution/capability_resolver.py` and nested predicate evaluation
- `services/policy/{observations,principal_index,permission_index_writer}.py`
- `services/governance/control_graph_types.py`
- `db/queue/{typed,artifacts,static_cache}.py`

Tasks:

1. Replace document-replacement operations with canonical evidence ingestion and
   scoped output publication. Stop using `remove_analysis_slice` as deletion of history.
2. Record the complete proof inputs of policy conclusions, especially controller
   observations, code bindings, role membership, and configuration dependencies.
3. Make both direct and nested capability evaluation consume a selected canonical
   context. No controller-index fallback may independently determine authority.
4. Remove the classification callback from permission-row materialization. Observe
   classification/controller facts first, then project FunctionPrincipal rows.
5. Bring function-principal graph nodes under canonical derivation ownership.
   Preserve their behavior without falsely attributing derived nodes to a walk
   that did not observe them.
6. Keep cross-contract enrichment as derivation only; eliminate all direct
   analytical row patches outside the canonical projection path.
7. Route execution verdict evidence into the ledger before projecting effect claims.
8. Make labels, graphs, function rows, and permission views reproducible without
   RPC, reclassification, fresh graph discovery, or a second resolver output.
9. Replace cache schema-counter invalidation with exact analyzer/configuration
   and code-input identity. Reuse code facts safely across deployments; never
   carry runtime state or authority across deployments through static caching.

**Gate:** the stale-owner reproduction no longer publishes A as current after
B's supported state is selected; A's historical claims remain queryable. A full
projection rebuild matches incremental output while all observation interfaces
are disabled. Retained pipeline/parity tests pass.

## Phase 5 — Restore principal history through the temporal model

- Ingest role membership, function-to-role/public-capability changes, ownership,
  signer/threshold changes, and relevant controller events for supported patterns.
- Preserve chain/block/transaction/log identities, initial-state evidence,
  coverage ranges, source limitations, and code/implementation changes.
- Reconstruct bounded intervals only where the event/state model establishes
  them. Keep gaps and incomplete enumeration explicit.
- Derive historical function permissions from the applicable role/controller
  facts and code at the requested position.
- Implement the historical API/consumer behavior currently missing from the
  Assessment cutover. Avoid rebuilding a separate principal-history truth store.
- Retain old reports as evidence where their original derivation cannot be
  reconstructed; distinguish previously reported data from newly verified claims.

**Gate:** supported pre-cutover principal-history cases retain their behavior and
granularity. Unknown ranges remain visible. Current/historical views share one
query/derivation path. No parity gap is dismissed as a legacy feature.

## Phase 6 — Governance and timelock configuration history

- Add typed adapters for the initially supported governance/timelock families.
  Declare their coverage explicitly; unknown/custom semantics remain unassessed.
- Collect configuration getters/events, proposal contents, lifecycle transitions,
  clocks, queue entries, ready times, execution/cancellation, and implementation changes.
- Support minimum delay, voting delay/period, proposal threshold, quorum rules,
  role access, and Safe configuration using explicit units and clocks.
- Record which configuration a proposal/operation actually consults at creation,
  snapshot, scheduling, or execution. Preserve the exact prerequisite claims.
- Separate quorum rules from quorum computed for a particular snapshot.
- Preserve proposal contents as observed input. A proposed setting is not an
  effective setting until the relevant execution/state evidence supports it.

**Gate tests:** global configuration change during voting; frozen versus dynamic
configuration; queued operation after delay change; cancelled operations;
public executors versus authorized proposers; custom clocks; upgrade changes
governance semantics; unknown configuration must not yield invented deadlines.

## Phase 7 — Scenarios and downstream impact

- Persist reusable context descriptions and separate actual evaluation attempts.
- Pin baseline chain state, knowledge inputs, callers, transactions, and assumptions.
- Evaluate supported transactions through the actual execution entry point or a
  validated model. Use local, non-broadcast execution for concrete simulation.
- Preserve atomicity within a transaction and persistence across separate
  transactions. Do not flatten a governance batch into independent calls.
- Record execution evidence and derive scenario-scoped claims by step.
- Compute direct changes, consequential authority/behavior changes, and affected
  contracts/assets through the dependency graph.
- Keep reachability/authorization conditions explicit. A forced or assumed
  execution path does not prove that a real proposal can reach that path.
- Represent unsupported calls, opaque upgrades, unresolved targets, and incomplete
  coverage as unassessed areas rather than no-op outcomes.
- Mark old contexts stale for current decisions when baselines advance. Recompute
  affected dependencies in a new run while retaining the earlier analysis.
- On actual execution, ingest real evidence and compare observed results with the
  earlier scenario. Never automatically promote a prediction into a fact.

**Gate tests:** role transfer; timelock/configuration change; contract upgrade;
multiple ordered actions; inner-call revert; later-transaction failure; explicit
sender; stale baseline; correction to a premise; hypothetical results cannot
enter current indexes; expected-versus-observed execution comparison.

## Phase 8 — Unified API and intuitive product views

Inspect and migrate current consumers, particularly:

- `routers/analyses.py`, `routers/predicate_capabilities.py`, and `routers/company.py`
- `services/aggregations/` and governance/principal projections
- `site/src/surface/` principal, function, graph, and activity consumers

Tasks:

- Return row-shaped records with explicit IDs and enum values. Keep filtering,
  pagination, and evidence retrieval separate from raw payload duplication.
- Preserve existing API behaviors through canonical projections, allowing a
  coordinated API/UI cutover rather than maintaining competing answer models.
- Provide one view with time/scenario selection. Historical navigation must not
  use an independently maintained data path.
- Show current/as-of values, last-known scope, conflicts, and coverage limitations.
- Show proposal differences in tables: what changes, who gains/loses capabilities,
  affected contracts/assets, timing/conditions, and evidence links.
- Make a downstream conclusion expandable into its prerequisite path. Keep
  implementation diagnostics in appropriate detail views, not unexplained UI labels.
- Preserve the permission, principal, graph, and historical views that users
  already rely on. Add regression tests through their real endpoints.

**Gate:** current UI/API parity; historical values reproduce the requested scope;
scenario indicators cannot be confused with observed state; unsupported scope is
explicit; all presented answers have an inspectable derivation.

## Phase 9 — Preserve and migrate existing data

Start this work after Phase 2 against isolated copies. Final reconciliation
requires the complete projection and historical behavior from Phases 4–8.

### Inventory and archive

- Inventory job artifacts, inline bodies, object-store keys, materializations,
  principal-history reports, controller observations, event logs/cursors,
  execution transcripts/verdicts, and relevant configuration/history sources.
- Export an immutable source manifest with IDs, counts, checksums, source dates,
  and retrieval status. Preserve all available source bytes before contraction.
- Identify already missing or overwritten history. Do not imply that reanalysis
  of current state can recover it. Record recoverable backfill and irrecoverable
  gaps explicitly.

### Idempotent conversion

- Build a migration-only reader for old formats. It is not a permanent runtime
  compatibility layer or an alternative analytical writer.
- Import identities, payloads, observations, and proven historical provenance.
- Re-derive scoped claims where evidence supports them. Preserve old reports
  without laundering unsupported assertions into new canonical facts.
- Preserve proven original observation dates. Do not invent historical knowledge
  timestamps for conclusions derived during migration.
- Reuse exact duplicate canonical records and link every relevant run/report.
- Rebuild indexes from the imported ledger. Reconcile per-feature results and
  trace every missing/changed answer to an approved correction or explicit gap.

### Release gates

- Dry-run manifests reconcile all available source records and payloads.
- Running the import twice is idempotent.
- A crash/resume does not duplicate facts, lose evidence, or publish partial runs.
- Retained original reports remain inspectable.
- Historical permission/configuration parity passes on the reference corpus.
- Backup restoration has been rehearsed before destructive changes are eligible.

A production database reset is not a migration strategy for this cutover.

## Phase 10 — Delete replaced paths and rehearse one release

- Remove obsolete snapshot writers, duplicate serializers, live classification in
  projections, and independent graph/permission updates after their parity gates pass.
- Retain operational job/queue/monitoring state and raw input storage where they
  are still required. Do not delete a table merely because it is not a Claim.
- Revise the earlier `d58b239c7e10` contraction and maintenance workflow around
  the actual import/rebuild sequence; the old guide is not a ready release plan.
- Rehearse against a representative restored copy with old writers stopped,
  source archive complete, import/rebuild finished, and only the new runtime active.
- Run fresh migrations/schema comparison, backend/enum/storage tests, full type
  and formatting checks, frontend tests/build, API integration, and approved live
  verification of the exact release candidate.
- Keep cache timing and discovery-to-guarded-descendant tests. Do not weaken
  behavior assertions merely to obtain a green run.
- Keep automatic PR test-database resetting out of this work. Arrange the
  explicitly scoped test environment using the existing approved workflow.
- Update PR title/body, architecture docs, data-migration instructions, and known
  limitations around the final retained behavior and measured validation.
- Obtain independent review, including the temporal/dependency invariants and
  migration reconciliation. Green CI alone does not establish feature parity.

The coordinated maintenance release, after operational approval, must stop all
old writers, preserve source data, import/rebuild and verify, then start only
the new runtime. If validation fails, do not mix old binaries with contracted
schemas. Restore the verified backup before restoring old code, or fix forward
within the rehearsed procedure.

## Required acceptance scenarios

| Scenario | Must establish |
| --- | --- |
| Identical rerun | New analysis attempt, same claim row, additional output link |
| Same conclusion, independent proof | Distinct proof preserved; one correction does not erase the other |
| Same payload, different observation | Shared bytes, distinct acquisition/provenance |
| Owner A→B | A retained historically; B supported at its scope; no stale current A |
| Owner A→B→A | Both A periods/events retained; no invented continuous A interval |
| Polling gap | Known endpoints; intervening state stays unknown |
| Failed refresh | Earlier observation retained and marked last-known, not silently current |
| Reorg | Orphan preserved; canonical eligibility and dependent results corrected |
| Late discovery | Past answer improves without fabricating what was known earlier |
| Missing classification | No fabricated EOA/Safe/terminal conclusion |
| Graph materialization | All nodes reproducible with proper provenance and no discovery during projection |
| Delay/configuration change | Existing operation/proposal uses the configuration its code actually binds |
| Proposal execution | Predicted and actual effects remain distinguishable and comparable |
| Scenario rerun | Reusable context and claims where identical; all attempts retained |
| Atomic batch revert | No surviving effects from that transaction |
| Sequential transaction failure | Earlier committed steps remain represented |
| Cross-chain unsupported path | Payload retained; effect assessment explicitly partial |
| Projection rebuild | Same answers with RPC/classification/discovery interfaces disabled |
| Migration replay | No new duplication or loss; source manifests reconcile |

## Definition of done

The cutover is ready only when:

1. The reviewed schema matches the implemented relational identity/proof model.
2. Every retained feature has passing parity tests and a canonical data path.
3. Current, historical, and scenario answers use explicit scope and coverage.
4. Indexes and UI views rebuild from canonical records without observations.
5. Duplicate runs reuse claims while preserving all run associations.
6. Corrections and reorgs preserve history and invalidate only dependent proofs.
7. Existing data is preserved/imported with reconciled manifests and a tested restore path.
8. Fresh checks and live verification apply to the exact published candidate.
9. The final implementation and release procedure have been reviewed.

## Recommended first implementation slice

After Phase 0 approval, implement one end-to-end owner-rotation slice:
persist two scoped observations, derive immutable ownership claims, link two
identical analysis runs to one claim, query both historical states, fail a refresh,
correct one proof, and rebuild the resulting view offline. This proves the core
storage and temporal semantics before moving the large pipeline onto them.
