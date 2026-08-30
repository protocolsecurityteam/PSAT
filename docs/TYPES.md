# PSAT Type Reference

The canonical assessment vocabulary, followed by the compatibility schemas that
carry low-level facts and derived views during the cutover.

**How the type system works here**

- Wire documents are `typing_extensions.TypedDict` values, checked by pyright and
  validated with pydantic `TypeAdapter` at artifact ingress.
- A `Claim` contains only a supported proposition. It never represents a
  rejection, missing input, or failure.
- `Evidence` records what PSAT observed. `Basis` names the rule and evidence (or
  prior claims) supporting a claim.
- `Analysis` records completion, coverage, omissions, and diagnostics. The
  absence of a claim means false only when the relevant analysis receipt says its
  coverage completed; otherwise the projection is not determined.
- Relationships use stable ids. The vocabulary uses domain names (`Contract`,
  `Function`, `Controller`) rather than transport-oriented `*Ref` / `*Model`
  names.

## Canonical assessment (`schemas/assessment.py`)

```text
Account  Contract  Function  Controller  Entity
Guard    Authority Effect
Evidence Basis     Claim
Analysis Coverage  Omission Diagnostic
Assessment
```

`Assessment` is the durable analytical result:

```python
Assessment(
    accounts=...,
    contract=...,
    functions=...,
    controllers=...,
    entities=...,
    authority_edges=...,
    dependency_edges=...,
    claims=...,
    evidence=...,
    analyses=...,
)
```

### Claim, evidence, and failure boundary

```text
Evidence: pause() writes paused = true
Evidence: withdraw() necessarily reverts when paused = true
Basis:    pause-latch rule over those evidence ids
Claim:    pause() causes pause.set and affects withdraw()
```

A predicate-lowering failure creates an `Analysis` diagnostic and omission. It
does not create a failure-shaped claim. A public pause writer still creates the
effect claim; authority is a separate `PublicAuthority` capability claim.

### Derived three-state views

The canonical document does not store `Determination[T]`. For a view such as
`is_pausable`:

```text
pause.set claim exists                         -> true
no claim + pause.set analysis fully completed -> false
no claim + partial/failed/missing analysis     -> null
```

`services.assessment.views` owns these projections. The relational
`ContractSummary.is_pausable` column and legacy permission claim lists are
written from the assessment, so they are indexes/views rather than parallel
truth.

---

## Compatibility vocabulary (`schemas/core.py`)

The schemas below remain as low-level analyzer fact shards, legacy-ingress
adapters, and API/database projections while stored historical jobs are read.
They are not the canonical claim ledger.

The shapes every stage shares. Defined once, specialized everywhere.

### `Principal`

One resolved authority: an address, what kind of principal it is, what's known.
Extended by `ResolvedPrincipal` (policy stage, adds witness provenance) and
`PrincipalProfile` (labeling, adds display enrichment).

| field | type | meaning |
|---|---|---|
| `address` | `str` | 0x-address, lowercase by convention |
| `resolved_type` | `ResolvedControllerType` | vocabulary below; undetermined = `"unknown"`, never a fabricated token |
| `details` | `dict[str, object]` | open: owners, threshold, delay, signers — whatever the classifier proved |

A display name is enrichment added downstream (`PrincipalProfile`), not part of identity.

### `ArtifactEnvelope`

Header of every stage document minted with a flat identity. Extended by
`ControlTrackingPlan`, `ControlSnapshot`, `EffectivePermissions`, `PrincipalLabels`.

| field | type |
|---|---|
| `schema_version` | `str` |
| `contract_address` | `str` |
| `contract_name` | `str` |

Documents whose identity is **nested** (`ContractAnalysis.subject`) or
**differently named** (`ResolvedControlGraph.root_contract_address`,
`UpgradeHistoryOutput.target_address`) deliberately do NOT extend it.

### `ResolvedControllerType` (vocabulary, 9 members)

```
zero  eoa  safe  timelock  proxy_admin  contract  unknown
off_chain_witness  cross_chain_authority
```

- `unknown` — the not-determined arm; `coerce_resolved_controller_type()` maps
  `None`, the literal string `"None"`, and any out-of-vocabulary token here.
- `off_chain_witness` — signature/Merkle-gated functions: no finite on-chain
  principal set.
- `cross_chain_authority` — aliased L1 owner / OP-stack bridge predeploy: a label,
  not a control edge.

Re-exported from `schemas.control_tracking` so historical import sites are unchanged.

---

## Layer 1 — Stage documents

The pipeline: `static → resolution → policy`, with `coverage`/`effects` consuming
static output. Each stage writes named JSON artifacts (`store_artifact`); the next
stage reads them back validated ([typed loaders](#the-typed-wire)).

```
static writes:     contract_analysis, predicate_trees, effects, claims,
                   control_tracking_plan, upgrade_history, dependencies
resolution writes: control_snapshot, resolved_control_graph (+ nested bundles)
policy writes:     effective_permissions, principal_labels, principal_history
```

### Static stage — the dossier (`schemas/contract_analysis.py`)

#### `ContractAnalysis` (artifact `contract_analysis`) — 13 sections

The static stage's whole answer about one contract. Validated by
`load_contract_analysis`. Consumed by resolution (recursive BFS), policy
(permission building), and the API detail page.

| field | type | meaning |
|---|---|---|
| `schema_version` | `str` | era gate: materialization cache keys on it |
| `subject` | `Subject` | identity of the analyzed contract |
| `analysis_status` | `AnalysisStatus` | whether IR analysis completed + errors |
| `summary` | `Summary` | one-line verdicts (upgradeable, pausable, timelock…) |
| `contract_classification` | `ContractClassification` | ERC standards, factory/NFT flags |
| `semantic_control` | `SemanticControlAnalysis` | control-model pattern + per-function guard summaries |
| `upgradeability` | `UpgradeabilityAnalysis` | proxy pattern, slots, admin paths |
| `pausability` | `PausabilityAnalysis` | pause/unpause functions, latch vars |
| `timelock` | `TimelockAnalysis` | timelock pattern + delay variables |
| `audit_alignment` | `AuditAlignment` | bytecode-match status vs known audits |
| `tracking_hints` | `list[TrackingHint]` | suggested controllers to watch |
| `controller_tracking` | `list[ControllerTrackingTarget]` | the controller observation records → feeds the tracking plan |
| `secondary_impl_pointers` | `NotRequired[list[SecondaryImplPointer]]` | split-proxy admin-impl slots (rare) |

Key sub-shapes:

- **`Subject`** — `address`, `name`, `compiler_version`, `source_verified`
  (three-state: `True`/`False` = fetch answered; `None` = the fetch fact never
  reached this run).
- **`Summary`** — `control_model` (`ownable|role_control|auth|governance|custom|unknown`),
  `is_upgradeable`, plus nullable `is_pausable`/`has_timelock` (null = detector
  didn't run; `False` = ran and proved none). `standards`/`is_factory`/`is_nft`
  follow the same rule.
- **`SemanticFunctionSummary`** — per-function: guards (`list[str]` +
  `guard_kinds: list[GuardKind]`), `controller_refs`, `sink_ids`, `effects`,
  `effect_labels`, `action_summary`. This is what the API "permissions" tab renders.
- **`AssociatedEvent`** — one event a writer function emits. Required core:
  `name`, `signature`, `topic0`, `inputs` (`list[AssociatedEventInput]`);
  optional: `effect_tags` (`writes`/`delegates`/`is_initializer` for watcher
  classification), `member_witness` + `writer_openness` (F3 qualification —
  present only when PROVEN; absent ≠ false).
- **`ControllerSpec`** — the controller identity kernel (see resolution stage);
  `ControllerTrackingTarget` extends it with `confidence`, `writer_functions`,
  `associated_events`, `polling_sources`.
- **`ControllerReadSpec`** (`total=False` with `Required` core) — how the
  controller's value is read: `strategy` (getter_call/storage_slot/mapping_lookup/
  event_reconstruction), `target`, plus type-shape fields.
- **`PausabilityAnalysis` / `TimelockAnalysis`** — the null-vs-false discipline
  is load-bearing: `None` = "claims plane didn't run / no IR", never render as
  `False`. Timelock `delay` is ALWAYS `None` with `delay_source: "not_read"`
  until a chain read is threaded — a defaulted delay would fabricate a protective
  credit.

#### Control vocabulary literals (contract_analysis.py)

| type | members |
|---|---|
| `ControlModel` | ownable, role_control, auth, governance, custom, unknown |
| `UpgradeabilityPattern` | uups, transparent, beacon, custom, none, unknown |
| `TimelockPattern` | oz_timelock, governor_timelock, custom, none, unknown |
| `ControllerKind` | state_variable, mapping_membership, external_contract, role_identifier, singleton_slot, external_policy, computed, unknown |
| `ControllerProvenance` | caller_gate, call_target — *proven* facts; absent = not computed. Two different claims: "caller is checked against this" vs "this gets called" |
| `GuardKind` | caller_equals_storage, caller_in_mapping, external_authority_check, role_membership_check, caller_via_helper_function, unknown |
| `SinkKind` | state_write, contract_creation, external_call, delegatecall, selfdestruct |
| `ControllerReadStrategy` | getter_call, storage_slot, mapping_lookup, event_reconstruction, unknown |
| `ControllerConfidence` | exact, high, medium, low, unknown |
| `ControllerTrackingMode` | event_plus_state, state_only, manual_review |

#### Guard grammar (`services/static/contract_analysis_pipeline/predicate_types.py`)

The IR of "who may call this function" — artifact `predicate_trees`.

- **`PredicateTree`** (`total=False`) — recursive: `op` (`and|or|not`),
  `children: list[PredicateTree]`, `leaf: LeafPredicate | None`. The
  `predicate_trees` artifact is `{schema_version, contract_name, trees:
  {function_full_name: PredicateTree}, check_trees?, canonical_signatures?,
  guard_extraction_uncertain?}`.
- **`LeafPredicate`** — one atomic gate: `kind` (`equality|membership|comparison|
  signature|authority_delegation|truthiness`), `operator`, `authority_role`
  (`owner|admin|operator|caller_authority|delegated_authority|role_identifier|unknown`),
  `operands: list[Operand]`, `set_descriptor`, `value_predicate`, `confidence`,
  `authority_contract`, `role_domain`, `selector_context`, `callee_*` fields.
- **`Operand`** — where a gate value comes from: `source` (12-member vocabulary:
  `msg_sender, tx_origin, parameter, state_variable, constant, computed,
  view_call, external_call, signature_recovery, block_context, self_address, top`),
  plus per-source detail (`state_variable_name`, `parameter_index`, `callee_signature`,
  `storage_slot`, `member_path`, `derived_from` for taint chains…).
- **`SetDescriptor`** — the membership structure checked: `kind`
  (`state_set|mapping_membership|external_set|role_registry|solmate_authority`),
  `key_sources` (how the key is derived), `authority_contract`, `enumeration_hint`
  (`EventHint`: event address, topic0, direction → lets the resolution stage
  enumerate members).
- **`ValuePredicate`** — filter on the *value* a mapping read returns
  (`op`, `rhs_values`, `value_type`) — collapses `map[k] == const` shapes.
- **`AuthorityContract` / `RoleDomain` / `SelectorContext` / `EventHint`** — the
  cross-contract delegation facts a leaf can name.

Consumers: policy (`build_effective_permissions` → canonical signatures, guard
uncertainty), the capability resolver (`evaluate_tree` → `CapabilityExpr`),
effects calldata planning, the live probe endpoints
(`POST /api/contract/{addr}/probe/*`).

#### Effects vocabulary (`.../effects/types.py`, artifact `effects`)

What a function *does* to the world. `SCHEMA_VERSION = "semantic-3"`.

- **`EffectsArtifact`** — `{schema_version, contract_name, functions:
  dict[full_name, EffectInfo], token_slots?}`. Validated by loader? Not yet —
  read via `isinstance(dict)` in policy_worker.
- **`EffectInfo`** — per function: `selector`, `abi_signature`, `sinks:
  list[SinkRecord]`, `state_writes: list[StateWriteFact]`, `value_flows:
  list[ValueFlow]`, `effects` / `effect_labels` / `effect_targets`,
  `action_summary`, `writer_selectors`, `state_changing` (true for a
  selector-bearing external/public non-view entry point — lets policy surface
  an assembly-only writer as an honest unsupported row), `parameter_names`
  (positionally aligned with the ABI types), `payable`, `assembly_state_access`.
- **`SinkRecord`** — one reachable sink: `id` (stable cross-reference),
  `kind: SinkKind`, `function` = the *originating entry point* (not the unit
  holding the IR), `target`, `selector`, `origin` (`body|guard`), and
  `receiver: ReceiverDescriptor` **only** for resolved high-level/library calls —
  absent means never computed (low-level calls, non-call sinks), which fails
  downstream preconditions exactly like `not_determined`.
- **`StateWriteFact`** — a single state write, richer than a `state_write`
  sink: member granularity (`accountantState.isPaused` vs the whole struct)
  plus a hygiene class.
- **`KindTier`** — a lattice classification with its witness tier:
  `dispositive_ast` (scoring Tier 1 — SSA operand is directly a
  StateVariable/param/msg.sender/literal) vs `static_trace` (Tier 2 — recovered
  through SSA provenance). `indeterminate` always carries `static_trace`: an
  inference conclusion, never a dispositive fact.
- **`ValueFlow`** — one asset movement fact: `direction` (corrected for
  `from == address(this)`), `asset`, `amount_origin` (via `origins.py` —
  `ElementRecordSite` names the storage record an element read names).
- **`TokenSlotEntry`/`TokenSlots`** — storage base slots of token-precondition
  mappings, keyed to the VIEW getter reading them back; seeds anvil forks.

#### Claims (`services/static/claims/types.py`, artifact `claims`)

- **`ClaimProjection`** — compatibility shape `{claim_id, tier, witness}`;
  `tier` is `behavioral_observed | standard_exact | idiom_structural |
  policy_derived`. It is projected from the canonical `Claim` and its
  `Evidence`; it is not another claim source.
- **`ClaimsArtifact`** — `{schema_version, contract_name, functions:
  dict[full_name, list[ClaimProjection]], abi_selectors?, analyses?,
  diagnostics?}`. Matcher failures are recorded in the analysis receipts and
  diagnostics, never encoded as missing or failure-shaped claims.

#### Verdict containers (three-valued, purpose-built)

- **`VerifiedGuardVerdict`** (`reentrancy_pause.py`) — W2's reentrancy-guard
  satisfier for one function: `state: "proven" | "not_determined"` — **never
  proven-absent** (this arm cannot earn "needs no guard"). `basis` names which
  proof; `declaration` is the canonical body name (a signature alone doesn't
  name a body in an inheritance chain).
- **`OrderingWitness`** (`record_ordering.py`) — W2's clear-before-call proof
  for one (function, record): `state: "proven_ordering" | "not_determined"`,
  a refusal carries `reason`, a proof carries `w2_basis` + `record` +
  `clearing_shape` + optional `disclosures`. Rides on `ValueFlow.record_ordering`
  only where the amount NAMES a record — absence is "no question", not a refusal.
- **`PauseInfo`** (`reentrancy_pause.py`) — structural pausability export feeding
  `_detect_pausability`.
- **`WriterEventSpec`** (`mapping_events.py`) — one mapping-writer ↔ event
  correspondence (mapping_name, event signature/name, writer functions,
  arg-to-key mapping). Feeds the monitoring watcher's member-change detection.

#### Upgrade history (`schemas/upgrade_history.py`, artifact `upgrade_history`)

- **`UpgradeHistoryOutput`** — `{schema_version, target_address, proxies:
  dict[addr, ProxyUpgradeHistory], total_upgrades, synthesized?}`.
  Identity is `target_address` (not the envelope) — proxy-centric.
- **`ProxyUpgradeHistory`** — per proxy: type, current impl, upgrade count,
  first/last blocks, `implementations: list[ImplementationRecord]`,
  `events: list[UpgradeEventRecord]`.
- **`UpgradeEventRecord`** — one decoded upgrade log; `event_type` ∈ 9-member
  `UpgradeEventType` (upgraded, admin_changed, beacon_upgraded, diamond_cut, …);
  per-type fields (`implementation`, `previous_admin`, `beacon`, `facets`, …)
  appear only when that log carried them.
- **`ImplementationRecord`** (`total=False` + `Required[address]`) — one impl
  window: introduced/replaced blocks, tx hashes.

Producer: `workers/static_worker.py` (+ synthesis fallback from `upgrade_events`
rows for legacy jobs). Consumers: resolution (impl Contract row backfill),
audits coverage (impl windows), API upgrades tab.

### Resolution stage — live authority state (`schemas/control_tracking.py`, `resolved_control_graph.py`)

#### `ControlTrackingPlan` (artifact `control_tracking_plan`) — extends `ArtifactEnvelope`

The watch plan resolution executes. `tracking_strategy` is always
`"event_first_with_polling_fallback"`; `tracked_controllers: list[TrackedController]`
(required on fresh builds; legacy artifacts read as untyped JSONB).

- **`ControllerSpec` kernel** (defined in contract_analysis.py) — controller
  identity: `controller_id`, `label`, `source`, `kind`, `read_spec`,
  `tracking_mode`, `notes`, `authority_provenance?`.
- **`TrackedController`** extends the kernel with `event_watch: EventWatch | None`
  and `polling_fallback: PollingFallback`. The plan builder copies the kernel
  fields one-for-one from `ControllerTrackingTarget` — same fact, two stages.
- **`EventWatch`** — `transport` (`wss_logs`), contract address, events
  (`list[AssociatedEvent]`), writer functions.
- **`PollingFallback`** — polling sources, `cadence`
  (`realtime_confirm | periodic_reconciliation | state_only`), notes.

Producer: `build_control_tracking_plan` (static stage). Consumers: resolution
worker (`build_control_snapshot`), monitoring poller/watcher.

#### `ControlSnapshot` (artifact `control_snapshot`) — extends `ArtifactEnvelope`

What controllers hold RIGHT NOW (live RPC reads): `block_number` +
`controller_values: dict[controller_id, ControlSnapshotValue]`.

- **`ControlSnapshotValue`** — `source`, `value` (`str | None`; a reverting read
  is an `eth_call_error` NULL entry, not a resolved value), `block_number`,
  `observed_via`, `resolved_type`, `details`, `authority_provenance?`.

Producer: `build_control_snapshot` (resolution). Consumers: policy
(`build_effective_permissions`), the post-policy graph refresh.

#### `ResolvedControlGraph` (artifact `resolved_control_graph`)

The recursive BFS result — who controls whom, to the depth horizon.
Identity is `root_contract_address`.

- **`ResolvedGraphNode`** — `id`, `address`, `node_type` (`contract|principal`),
  `resolved_type`, `label`, `contract_name`, `depth`, `analyzed`,
  `analysis_state?` (4 members below), `details`, `artifacts`.
- **`ResolvedGraphEdge`** — `from_id`, `to_id`, `relation`, `label`,
  `source_controller_id`, `notes`.
- **`ResolvedAnalysisState`** — why a node is/isn't analyzed:
  `analyzed | not_analyzable | attempt_failed | beyond_depth_horizon`.
  `analyzed: false` alone collapses four populations; consumers needing the
  distinction read this field.
- **`ResolvedEdgeRelation`** — 9 members; the control relations
  (`controller_value, role_principal, capability_principal, safe_owner,
  timelock_owner, proxy_admin_owner, mapping_member`) vs the two that move NO
  authority: `external_call_target` (merely called) and
  `controller_value_unattributed` (provenance absent — published so the address
  stays visible).

Also here: **`LoadedArtifacts`** (`services/resolution/recursive.py`) — the
per-contract in-memory bundle `{analysis, tracking_plan, snapshot,
predicate_trees?, effective_permissions?}`. Fields are `Mapping[str, Any]`
(not strict TypedDicts) because bundles have two provenances: freshly built
root documents and nested bundles hydrated from persisted JSONB rows.

### Policy stage — the permission ledger (`schemas/effective_permissions.py`, `principal_labels.py`)

#### `EffectivePermissions` (artifact `effective_permissions`) — extends `ArtifactEnvelope`

The answer to "who can call what". Validated by `load_effective_permissions`.

| field | type | meaning |
|---|---|---|
| `authority_contract` | `str \| None` | nested authority joined, if any |
| `principal_resolution` | `PrincipalResolution` | how authority context was resolved |
| `artifacts` | `dict[str, str]` | names of the artifacts this build read |
| `functions` | `list[EffectiveFunctionPermission]` | the per-function rows |

- **`PrincipalResolution`** — `{status, reason}`; status ∈
  `complete | no_authority | no_authority_snapshot` (authority contract found
  but its snapshot artifact missing — a distinct degradation).
- **`EffectiveFunctionPermission`** — one function's permission record (21 fields):
  `function` (Slither full name), `abi_signature`, `selector` (`None` when the
  signature couldn't lower to elementary ABI types — a hash of a string still
  naming a user type is not a dispatch selector, and no answer beats a wrong one),
  `direct_owner: ResolvedPrincipal | None`, `authority_public`,
  `authority_openness?` (`open|restricted|not_determined`; absent = producer
  predates the distinction — a FOURTH state, don't fold into not_determined),
  `authority_roles: list[AuthorityRoleGrant] | None` (**three-state**: non-empty =
  witnessed role requirement; `None` = role-gated, role not determined; `[]` =
  proven not role-gated), `controllers: list[ResolvedControllerGrant]`,
  `effect_labels`, `claims?`, `signature_witnesses?`, plus the state-mutability
  quartet (`state_changing`, `state_writes`, `sinks`, `writer_selectors`) where
  `None` on any = NOT DETERMINED, distinct from `false`/`[]`.
- **`AuthorityRoleGrant`** — `{role: int, principals: list[ResolvedPrincipal]}`.
- **`ResolvedControllerGrant`** — one controller that gates the function:
  `controller_id`, `label`, `kind`, `principals`, `notes`.
- **`ResolvedPrincipal`** extends core `Principal` with `source_contract?`,
  `source_controller_id?`, `principal_type?` — where it was witnessed.

DB projection: `effective_functions` + `function_principals` tables
(`write_effective_function_rows`). The `authority_roles` column preserves the
JSON-scalar-null discipline: `null` = undetermined (379 rows locally),
`[]` = proven not role-gated — `WHERE authority_roles IS NULL` matches neither.

#### `PrincipalLabels` (artifact `principal_labels`) — extends `ArtifactEnvelope`

Frontend-facing principal cards: `principals: list[PrincipalProfile]`.

- **`PrincipalProfile`** extends core `Principal` (adding REQUIRED
  `display_name` — a labeled principal always has a name), `labels: list[str]`,
  `confidence: LabelConfidence` (`high|medium|low`), `graph_context`,
  `controller_context`, `permissions: list[PrincipalPermission]`
  (`{function, effect_labels, role, authority_public, controller?}`).

Producer: `build_principal_labels` (policy). Persisted to the `principal_labels`
table; consumed by the API principals tab and the company-overview terminal walk.

### Auxiliary vocabularies

- **`EnumerationResult` / `EnumeratedPrincipal`**
  (`services/resolution/mapping_enumerator.py`) — one mapping enumeration:
  `principals` + `status` (complete vs truncated — a silent `[]` would drop
  authorized addresses). Value-aware variant: `EnumerationValueResult` /
  `EnumeratedKeyValue` (latest observed value per key).
- **`PerimeterSpawnResult` / `FpMaterializationResult` / `OmissionRecord`**
  (`services/discovery/perimeter.py`) — the perimeter-walk ledgers: what was
  spawned/materialized, budget used, and every OMITTED candidate with its
  reason (omissions are records, never silent drops).

---

## Layer 2 — HTTP contracts

### Requests (`schemas/api_requests.py`, pydantic — validated by FastAPI)

| model | endpoint | notes |
|---|---|---|
| `AnalyzeRequest` | `POST /api/analyze` | `address`/`company`/`dapp_urls` modes; chain validation |
| `ProtocolSubscribeRequest` | `POST /api/protocols/{id}/subscribe` | Discord webhook + event filter |
| `UpsertMonitoredContractRequest` | `POST /api/monitored-contracts` | `contract_type` ∈ `MonitoredContractType` |
| `UpdateMonitoredContractRequest` | `PATCH /api/monitored-contracts/{id}` | partial update |
| `AddAuditRequest` | `POST /api/company/{name}/audits` | audit registration for extraction |
| `AddressLabelUpsert` | `PUT /api/address_labels/{addr}` | global or chain-qualified label |

### Responses (`schemas/api_responses.py`, TypedDict — **checking-only**)

These annotate handler RETURN TYPES so pyright verifies what a handler builds.
They are deliberately NOT wired as `response_model=` (that would prune
undeclared keys at runtime; the SPA reads payloads as-is), so every route
carries `response_model=None`. Interior payloads assembled dynamically stay
`dict[str, Any]` — depth is honest, not aspirational.

The meaningful ones:

- **`JobDict`** — `Job.to_dict()`; the `/api/jobs` row (17 fields incl.
  `status`, `stage`, `trace_id`, `retry_count`, `last_failure_kind`).
- **`CompanyOverviewResponse`** — top of `assemble_company_payload`; the four
  governance lists (`contracts`, `principals`, `ownership_hierarchy`,
  `fund_flows`) are `GovernanceView` aggregations, untyped inside by design.
  `tvl: TvlPoint | None`, `reach: ReachBlock`.
- **`CompanyScoreResponse`** — score-ledger passthrough; the `grade_*`/finding
  fields come verbatim from the persisted score document, consumed by branching
  on `grade_state`/`perimeter_state` only — no shape promise beyond presence.
- **`AuditReportDict` / `AuditBrief`** — serialized audit rows; `AuditBrief`'s
  match keys appear together iff a coverage row was supplied; the
  `coverage_source` trio is stamped only on inherited rows; `impl_address` +
  bytecode-drift fields only by the contract-audit-timeline aggregation.
- **`AuditCoverageEntry` / `CompanyAuditCoverageResponse`** — per-contract audit
  coverage incl. shared-dependency inheritance.
- **`MonitoredContractItem` / `MonitoredEventItem` / `EnrolledContractBrief` /
  `ReEnrollResponse` / `SubscriptionItem`** — monitoring plane serializations.
- **`TvlPoint` / `TvlCurrent` / `ProtocolTvlResponse`** — TVL current + history
  (`TvlPoint` serves both the company summary and history series — identical
  document, one name).
- **`FleetStatusResponse` / `PipelineStatsResponse`** — `/api/fleet`, `/api/stats`.
- **`AnalysisListEntry`** — `/api/analyses` rows after proxy/impl merge
  (`display_name` stamped on every entry; `proxy_*_display` only on merged rows).
- **`AddressLabelView` / `AddressLabelsResponse` / `AddressLabelUpsertResponse` /
  `AddressLabelDeleteResponse`** — the label plane (global + per-chain maps).
- **`AddressTouch` / `AddressTouchesResponse`** — the agent's
  "what does this address control" answer.
- Small mutation receipts: `QueuedJobRef`, `AnalyzeRemainingResponse`,
  `CancelQueuedJobsResponse`, `DeleteCompanyAddressResponse`,
  `RefreshCoverageResponse`, `ReextractScopeResponse`, `DeleteAuditResponse`,
  `AuditScopeResponse`.

### `StageError` / `StageErrors` (`schemas/stage_errors.py`, pydantic)

The sanitized per-stage failure ledger: `phase`, `message`, `severity`
(`error|warning`), exc type, context. Written by `BaseWorker` on every failure
path via a fresh session (survives a broken primary transaction); served at
`GET /api/jobs/{id}/errors`.

---

## The Typed Wire (`db/queue/typed.py`)

`get_artifact` returns `dict | list | str | None` — the type dies at
serialization. The loaders resurrect it, validating against the schema the
moment the artifact leaves storage. **Fail closed**: a shape violation raises
`ArtifactSchemaError` naming the artifact and each offending field; a missing
row stays `None`. Validation returns the ORIGINAL dict (unknown keys —
a future producer's additions — round-trip untouched).

| artifact | schema | loader | consumers |
|---|---|---|---|
| `contract_analysis` | `ContractAnalysis` | `load_contract_analysis` | resolution, policy, static materialization publish |
| `control_tracking_plan` | `ControlTrackingPlan` | `load_control_tracking_plan` | resolution (required), policy (degradable — `record_degraded` + `{}` fallback) |
| `control_snapshot` | `ControlSnapshot` | `load_control_snapshot` | policy |
| `resolved_control_graph` | `ResolvedControlGraph` | `load_resolved_control_graph` | policy (read still via `get_artifact` pending full migration) |
| `effective_permissions` | `EffectivePermissions` | `load_effective_permissions` | API, scoring |
| `principal_labels` | `PrincipalLabels` | `load_principal_labels` | API |

Not yet loaded through the typed path (still `get_artifact` + `isinstance`):
`predicate_trees`, `effects`, `claims`, `upgrade_history`, the nested
`recursive:*` bundles, `classified_addresses`. Each lands as its consumers migrate.

Contracts pinned by `tests/storage/test_typed_loaders.py`: round-trip, fail-closed
field naming, non-dict rejection, absent-is-None, unknown-key survival,
out-of-vocabulary `resolved_type` rejection.

---

## Appendix — inheritance map

```
ArtifactEnvelope
├── ControlTrackingPlan        (+ tracking_strategy, tracked_controllers)
├── ControlSnapshot            (+ block_number, controller_values)
├── EffectivePermissions       (+ authority_contract, principal_resolution, artifacts, functions)
└── PrincipalLabels            (+ principals)

Principal
├── ResolvedPrincipal          (+ source_contract?, source_controller_id?, principal_type?)
└── PrincipalProfile           (+ display_name!, labels, confidence, graph_context,
                                controller_context, permissions)

ControllerSpec
├── ControllerTrackingTarget   (+ confidence, writer_functions, associated_events, polling_sources)
└── TrackedController          (+ event_watch, polling_fallback)

AssociatedEvent  = total=False with Required core (name, signature, topic0, inputs)
ControllerReadSpec = total=False with Required core (strategy, target)
ImplementationRecord = total=False with Required address
```

Legend: `?` = `NotRequired`, `!` = required here though optional on the base.
