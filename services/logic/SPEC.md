# Formula, assessment and address expansion

Status: local implementation on `test/auth-fuzz-restructure`; no production rollout implied.
The complete predicate remains authoritative. No sampled caller proves unrestricted or complete access.

## Three explicit jobs

```sh
python -m scripts.logic generate "$ADDRESS" --chain-id 1 --rpc-url "$RPC_URL" --output formulas.json
python -m scripts.logic assess formulas.json --rpc-url "$RPC_URL" --cache .jev-cache --output assessment.json
python -m scripts.logic enumerate formulas.json --assessment assessment.json --rpc-url "$RPC_URL" --output addresses.json
# Optional narrowing of an assessed plan:
python -m scripts.logic enumerate formulas.json --assessment assessment.json --function 'setOwner(address)' --rpc-url "$RPC_URL" --output selected.json
# Explicit manual expansion without assessment:
python -m scripts.logic enumerate formulas.json --manual --effect 'setOwner(address):0' --rpc-url "$RPC_URL" --output manual.json
```

`generate` fetches verified compiler inputs, pins the current block (or `--block`), follows supported concrete
callees and saves formulas. It never enumerates keys or callers. The existing worker stores these as auxiliary
schema-2 artifacts; production principal rows and the UI remain unchanged. Proxy dispatch limitations below apply.

Generation now preserves interrupted expansion as `pending_functions` beside completed `functions`.
A pending entry is a typed compilation checkpoint, not a formula with an invented unknown post-state.
`status=incomplete` means at least one function remains pending. Completed siblings remain assessable;
assessment exposes pending function names/reasons and cannot report the whole generation assessed.

Resume through the same generate operation: `--resume previous.json --output continued.json`, or submit
`resume_job_id` to `POST /api/logic/generate` with the same address and chain. The saved block and scope are
retained; a changed block/scope is rejected. Increase `expansion_steps`, `loop_iterations`, `callee_depth`, or
`value_steps` as needed. Step budget buys new symbolic work; completed journal entries are reused. Loop/depth
limits bound total expansion rather than slicing away remaining executions. No subsequent pipeline stage is
automatically submitted. The CLI saves incomplete output and exits 3; API jobs finish with `result_state=incomplete`.

Checkpoints use a hierarchical, data-only journal of operations, input state and results. On resumption the
control-flow walker reconstructs its continuation while restoring completed semantic steps instead of lowering
them again. This is deterministic replay, not a serialized Python stack. Locals, ordered storage, memory aliases,
return-data state, frame identities, resolver memos and specialization evidence are retained. Stable references are checked against
matching verified compiler IR, runtime code and analysis bindings. Production checkpoints also pin the chain ID,
block hash and state root; a changed snapshot is rejected. Custom offline readers without `snapshot_identity()`
must supply immutable inputs at their declared block. The existing build resolver may rebuild frontend
IR to restore these references; checkpoints are not a standalone replacement for the verified compiler inputs.
Engine/toolchain changes reject old checkpoints rather than reuse results with changed semantics. No pickle or
executable object serialization is used.

Unresolved call execution is retained at the invocation boundary as `reason=call`, with a named
`blocker`. One record shape covers typed calls, raw/assembly calls, delegates and native send/transfer:
mode, address-normalized target, calldata or exact input-region expression, value/gas, original operands,
optional decoded ABI call, invoking frame and the complete pre-call State. The existing journal retains
the enclosing verified program and continuation. No assumed result or post-call havoc is substituted
before generation continues. Proxy-dispatch structural extraction remains separate from executing the
forwarded call. Native calls tag their source intrinsic; their 2300 field denotes the language stipend,
not a claim about a raw EVM gas operand.

The frame separates code address, storage address, sender, value, calldata and inherited static context.
Normal calls use the callee's storage; delegated contexts preserve the caller's storage/sender/value.
Typed Solidity bytes calls now execute known-target delegates through the same CallExecutor as ordinary calls.
The call mode is explicit. Delegated code uses caller storage, original sender/value and its own calldata/code;
nonpayable entries check inherited value. Fresh callee memory does not replace caller memory. The existing raw-call
resource outcome guards success and rolls back only this invocation's writes on failure. Source collection records
both storage and code addresses. Unavailable own code, unsupported ABI data or static effects remain retained blockers.
Assembly CALL/STATICCALL/DELEGATECALL use the same executor when memory bytes identify a verified static ABI entry.
Calls into known code now execute its native entry, fallback or receive body, selected by actual calldata.
The selected implementation is an inventory hint, not a substitute for the target's own dispatcher. Empty calldata
prefers receive; short/unknown selectors take fallback or the compiler's default revert. RETURN/STOP carry raw bytes
that bypass declared return encoding, and high-level callers decode those bytes using their own ABI coder.
Writes around a delegated call remain ordered and revert with the enclosing invocation when it fails.
This applies to calls executed inside an analyzed function. Top-level proxy entry generation still uses structural
dispatch certification and needs the same general execution routing. Dynamic ABI input layouts, symbolic targets,
unplaced memory and resource-dependent outcomes remain qualified. Build metadata pins compiler inputs and EVM target.

A loop cutoff retains a typed loop record: verified function/entry references, current State, iteration
count, region exit and execution frame. This is an exact retained loop program, not an inferred invariant
or closed-form solver relation. Existing expansion resumes it. Symbolic target resolution and general
input-length loop solving remain separate outstanding work; a larger budget alone need not unblock them.

Assessment reports `resolve_call` with the call blocker, rather than suggesting a budget-only retry.
Missing source can be supplied at the same snapshot and the saved program resumed. Existing bindings,
block, previously observed code, compiler inputs and scope cannot silently change. Unsupported semantics
require implementation work; retrying the same call with the same missing information makes no promise
of progress. Completed siblings remain assessable; no incomplete caller set is published as complete.

Budget-cut work can resume with further resources. Retained calls can instead need source, target resolution
or missing semantics; retrying those without new information does not complete them. Unsupported operations
outside the retained call boundary remain explicitly qualified. Symbolic loops need not become exact merely
by repeated resumption: they can keep reaching the loop bound, and a suitable summary may still be needed.
Checkpointing does not add a universal loop proof or certify a caller list.

Loop comparisons use complementary canonical bounds, so contradictory paths stop before spending further
iteration budget. Modeled storage bounds may be read at the pinned block after applying preceding tracked
writes; this records state specialization. Effectful loop conditions execute on the final test as well as
inside the loop. Unresolved calls, invalidated storage and caller-dependent bounds remain symbolic.
This does not infer a summary for arbitrary input-length loops or increase the configured limits.

`assess` runs deterministic effect-access analysis and requests **one grouped Jev batch per function**.
The batch contains distinct questions for every recorded effect, with the complete function source and
successful transitions shared as context. Each effect has its own impact estimate; a severe branch does
not assign its rating to another effect. Matching debits/funding, rollback and other writes on the same
transition remain visible. Ratings are advisory model estimates, not authorization or loss proofs.

`enumerate` explicitly expands recommended effect queries from the saved artifact. `--function` narrows recommendations.
`--manual` instead requires explicit `--function` (whole-call relation) or `--effect` selections. It cannot be combined
with `--assessment`. Neither generation nor assessment starts this job. Expansion never recompiles predicates; it may
load verified layouts to read storage. All reads use the saved block. Outputs cannot overwrite input artifacts.

Enumeration accepts `--storage-steps` in the CLI and `storage_steps` in the API (default 100,000; API maximum
10,000,000). This bounds local snapshot-accounting work per storage address per projected predicate, including
trace-enriched retries. It is separate from RPC, memory and solver budgets. Exhaustion retains a partial relation;
it never supplies an unproven zero default. The result records the requested limit and per-function
`storage_accounting`, keyed by `callers` or `effect:<index>`, with steps by operation/root, snapshot passes, and
accounted/unattributed occupied slots. Unattributed slots are not a count of missing callers. Counts are null if
the dump was never obtained. A projection proven without a dump has an empty accounting list.

Accounting normalizes candidate domains once per key type and indexes verified hash preimages by mapping base.
Fixed-byte candidates include canonical left-aligned ABI/event words. Every candidate still has its actual storage
location recomputed, and completeness still requires all occupied slots accounted for with no accounting issue.
Formula constants are collected before projection starts. A larger storage budget only permits more accounting;
it does not resolve unsupported semantics or guarantee the solver can prove a finite or cofinite caller set.

The old `logic_select`, `logic_impact` and `logic_expand` command wrappers have been removed; their useful operations
are in the three jobs above. The offline `logic_impact_evaluate` command compares function ratings with supplied labels.

## Asynchronous API

The same services are exposed through authenticated API jobs. Use the existing admin session or
`X-PSAT-Admin-Key` authentication. HTTP handlers submit work; they do not compile, call Jev or enumerate.

| Request | Body | Result |
| --- | --- | --- |
| `POST /api/logic/generate` | `address`, `chain_id`; optional `block`, `related_addresses`, `context_chars`, `resume_job_id`, expansion budgets | 202, generation job ID |
| `POST /api/logic/assess` | `formula_job_id`; optional `max_requests`, `cache_only`, direct-read/solver budgets | 202, assessment job ID |
| `POST /api/logic/enumerate` | `assessment_job_id`, explicit `functions`; optional `members`, `solver_ms`, `storage_steps` limits | 202, enumeration job ID |
| `GET /api/logic/jobs/{id}` | none | Execution status, operation, pinned block when available, result state, status/result URLs |
| `GET /api/logic/jobs/{id}/result` | none | Stored result after completion; 409 while not completed |

For example, after generation finishes, submit `{"formula_job_id":"<generation UUID>","max_requests":8}`.
Inspect the assessment's `suggested_expansions`, then explicitly submit
`{"assessment_job_id":"<assessment UUID>","functions":["setOwner(address)"]}` to enumerate.
No stage automatically submits the next. Inputs are completed server-owned jobs, not uploaded formulas,
caller-supplied RPC URLs, filesystem paths or API credentials. Pending/wrong-stage/stale inputs are rejected.
New submissions honor the existing chain allowlist; older results remain readable when a chain is disabled.

`status=completed` means the requested computation finished. `result_state=incomplete` still means required
assessment judgments are missing; `not_verified` is also retained. Operational failures use the existing
queued retry/backoff and `failed_terminal` states and produce no semantic result. Required RPC reads retry;
invalid inputs or changed artifacts fail. The ordinary `/api/jobs/{id}` diagnostics/retry routes also work.

Jobs reuse PostgreSQL `jobs`, the shared artifact store (`logic_result`), claims, leases, heartbeats and worker
recovery. A dedicated `logic` stage ends at `done` after one operation. These auxiliary jobs intentionally leave
`jobs.address` and `protocol_id` unset, storing target identity in the request, so they cannot displace production
address analyses or trigger grading/enrollment. Generation pins its block before compute; retries keep that block.
Input hashes are checked again in the worker and results are published under the current lease.

Jev uses server credentials and `PSAT_LOGIC_JEV_CACHE` (default `.cache/logic-jev`). Configure a persistent worker
path to retain cached judgments; cache sharing across machines depends on that storage. PostgreSQL tracks
`jev_requests_reserved` before inference so crashes and retries cannot reset a job's request cap. Reservations
may include a call that never reached the service; they are not a billing count. An incomplete assessment can be
resubmitted as a new explicit job with a new budget; successful cached answers are reused where available.

Apply migration `a38e901c6d72` before starting the updated API/workers. Rollback retires pending logic jobs
and retains the unused enum member to preserve existing stage-dependent triggers. Stop/drain logic workers first. `deploy/start_workers.sh` now launches
`workers.logic_worker`, and fleet wake/readiness includes its queue. Heavy work uses the existing isolated compute
budgets; `PSAT_LOGIC_JOB_CONCURRENCY` controls concurrent jobs. The API is implemented locally, not deployed by
this change. The CLI remains a direct development tool using the same engine/assessment services.

## Assessment boundary

`logic_selection` supplies per-effect access evidence, potential authority dependencies, structural attention and
storage-value bounds. It has no severity labels, expansion decisions or candidate enumeration. Optional direct reads
are bounded (`--direct-reads`); without `--rpc-url`, state-dependent access stays unresolved. Operational errors abort.
The full guard and joint caller/origin identities are retained. Source identifiers are not an authorization classifier.

`logic_impact.rate_effects` supplies ratings only. A pinned model, rubric, source context and full exact request key
the cache. Raw distributions are retained. Changed context/questions invalidate cached requests. Credentials are never
saved. `TYPESAFE_API_KEY` or `JEV_API_KEY` permits uncached requests by default; `--cache-only` forbids them.
`--max-requests` bounds wire attempts (default 8), including timeouts. Exact cache replay needs no credential.

`logic_assessment` contains the **only expansion-selection policy**: retain unrestricted effects visibly; retain
inactive, origin/signature-dependent, unsupported, unrated and uncertain cases for review; recommend supported caller
relations when any impact dimension assigns at least the policy threshold to medium-or-high impact.
Uncertainty between those two levels, or in other dimensions, does not erase that evidence. Exact severity may
remain unknown; insufficient context or conflicting scope still blocks selection. Probabilities across dimensions
are never summed or assumed independent. Missing only membership state can be resolved by expansion.
Low ratings never silently discard an effect. Each row's selection uses only its own effect rating and access
evidence. Publicly callable functions can still have restricted effects. No function-level severity is copied
onto effects, and no maximum-over-effect rating is computed.

Write occurrence is not uniform control of its results. For a write relation `R(c,a)` with target/value `O(c,a)`,
the additional power query is `R(c,a) AND EXISTS d: NOT EXISTS b: R(d,b) AND O(d,b)=O(c,a)`.
Both callers range over nonzero addresses; both input copies retain their type/ABI bounds and use the same pinned
state. Thus a public fixed-value write does not hide an owner's ability to choose arbitrary values. The query also
covers numeric limits without splitting branches. An identity-dependent expression alone does not prove unequal
power: different inputs can still give every caller the same outcome domain.

Assessment records occurrence access separately when it queries this relation. `outcome_access=uniform` means all
callers can attain the same target/value outcomes. `varies_by_caller` means some attainable outcomes are not common
to every caller; even all callers can have such outcomes, as with caller-keyed storage. `power_indices` pins which
selected write effects use this query. Enumeration verifies that scope against the assessment; manual occurrence
queries retain their previous meaning. Unknown state, unsupported coordinates, other identity dimensions and solver
timeouts do not establish uniformity or a complete set. This is **single-write control**, not a proof of independent
control over simultaneous writes; the complete transition remains the source of their correlation.

Assessment schema3 stores ratings at `assessment.functions[signature].effects[index]`, scoped by the group's
`formula_hash`. The effect-impact-v3 rubric generates exact effect-prefixed question IDs. Missing, extra or
legacy unscoped answers invalidate that function's batch; they are never copied across effects. Effects without
context, model budget or answers remain unknown. Functions without modeled effects remain visible for review
as no_modeled_effects with a review decision; they need no judgment, so they do not hold assessment incomplete.
Pending operations remain explicit. Neither receives a fabricated low rating.

The report holds each effect rating once. `rows` retain effect access evidence and decisions;
`suggested_expansions` is an execution plan, not an automatic job. `artifact_hash` binds the plan to all saved formulas
and their source bundle/context references. Enumeration rejects an old assessment after any of those inputs change. Old function-level schema2 reports
must be reassessed; they cannot authorize the new effect-specific selection. Rubric/questions/program/context
changes invalidate cached inference through the complete request key. Expansion remains an explicit job.

An exhausted budget, missing context/key or failed judgment saves partial results with status `incomplete` and exits 3.
Rerunning reuses the cache. A verified contract with no eligible functions finishes as `nothing_to_assess` (exit 0).
Unverified source is `not_verified` (exit 4), not a pending inference job. `judgments_complete` records receipt of
judgments, not confidence or correctness. The thresholds remain provisional and do not justify automatic low-impact deferral.

## Shared source bundle

Each formula artifact stores one `source_bundle`, deduplicated by file-content hash. It contains complete compiler
input files, including top-level constants, types, errors and helpers. Function contexts contain a formula hash,
bundle hash, source-file reference and UTF-8 byte span; they do not duplicate code or guess effect locations by variable name.
Deployments retain address, code-address hint, contract and source-file references, even when files are shared.

Source combines contracts followed across the selected entrypoints. `--related-address` adds explicitly supplied
associated deployments (up to 32); it does not change formulas or generate their function rows. This is not a complete
recursive or economic dependency graph: dynamic targets and wider dependencies can remain absent. Missing source is
reported. Contract boundaries are preserved rather than flattening separate deployed contracts into one storage context.

Source is stored in full and cut only for bounded model requests (`--context-chars`, default 48,000). The entry's file
comes first; cuts are explicit and prevent low-impact conclusions. `source_complete` describes the supplied source
scope, never the whole protocol. There is no new source fetching during assessment. Legacy schema-1 per-function
source snippets must be regenerated before assessment; their saved formulas remain usable for explicit manual expansion.

## Relations, not independent pieces

Inside generation, the compiler uses three pieces: `lower.py` handles language operations,
`linker.py` resolves code and read-only terms, and `calls.py` composes supported external calls.
`formula.py` assembles their output. A `CallRequest` contains the symbolic call, value/gas context,
and ordered shared-storage overlay. Its `CallResult` contains the normal-return condition,
decoded return values and resulting overlay. Caller locals and memory do not cross this interface;
arguments and returned memory values are copied through the ABI boundary. The lowerer retains
the caller's memory and intersects its path condition with the result. These are compiler interfaces,
not additional pipeline jobs, and they do not invoke Jev or enumerate addresses.

A function has a complete success predicate over caller, origin, arguments, value and the state at the block.
Each effect has its own guard. An early return may be callable by everyone while its write is owner-only.
A transition contains its successful exit guard and **all** final storage updates, including their values.

The display may highlight identity, argument and state dependencies. They are never solved independently:
`managers[id] == caller && id == 0` admits only the manager at zero. Disjunctions, shared variables and
conditions on recovered identities stay in the same predicate.

`msg.sender` and `tx.origin` are distinct variables. A projection onto the caller existentially quantifies
other inputs, including origin; it does not claim the caller can obtain a particular origin or anyone else's
signature. The original formula and projection identity are always retained. Generated formulas retain the full
160-bit EVM value domain. Caller projection explicitly conjoins `caller > 0` for controller reporting; it does not
remove zero from storage values, arguments, recovered signers, or other projected identities. The output predicate
includes this domain constraint even if enumeration is unfinished. Cofinite sets retain the full 160-bit universe,
so an unrestricted nonzero-caller set explicitly excludes zero. Key ownership and transaction-origin feasibility
are not inferred from membership. In multi-actor composition, earlier `step*.caller` arguments are not constrained
by this final-caller reporting convention; complete transaction-sequence feasibility is a separate question.
The relation describes EVM call-frame execution, not transaction admission (signatures, nonce, fees or funding).
A concrete balance read includes the call-entry value credit/debit; this does not assert an actor can fund that value.

## Projection and completeness

For identity `c`, a projection asks whether there exist values of the remaining inputs satisfying the **whole**
predicate at the pinned state. It returns one of:

- `finite`: exact listed members. After blocking them, the solver proved no other member exists.
- `cofinite`: exact excluded members. After blocking them, the solver proved no other exclusion exists.
- `symbolic`: retain the predicate and any proved members, without claiming a complete expansion.

Both positive and complement enumeration are bounded. Thus a blocklist can be represented as everyone except
its blocked entries without enumerating the address space. An arithmetic address predicate can remain symbolic.
An incomplete list is never confused with an empty set. A zero solver budget returns a budget qualification,
not an unlimited query or a proof that nobody passes.

A solver timeout/unknown, unsupported translation, incomplete storage attribution, or enumeration limit can
leave the projection symbolic. These are distinct from a node failure and from source not being verified.
Reducing a budget can lose evidence; it must not create a false complete set. It need not preserve a presentation
label, or the precise subset of witnesses a solver happens to find first.

## State inputs and enumeration

Production debug requests use `QUICK_NODE_ETH` on Ethereum, or the server override
`PSAT_DEBUG_RPC_URL_<chain_id>`. Ordinary reads and log scans remain on the normal RPC route. Debug and
primary provider identities are checked independently and cached separately. Storage dumps are accepted only
after their complete reconstructed trie matches an account proof anchored to the requested header's state root.
This detects incomplete pages and wrong transaction-state snapshots without trusting provider-specific index
semantics. Zero leaves, invalid slot preimages/cursors and invalid proofs are rejected. The dump word budget
bounds materialization. Other ordinary reads still use pinned block numbers and trust their configured provider.

Concrete reads use compiler-derived storage locations and packing. Symbolic reads use a complete snapshot
only after its occupied slots have been attributed to layout locations and verified keys. Candidate words may
come from constants, storage, events or traces; candidates do not establish membership by themselves.

When attribution leaves slots over, the provider finds a zero-to-nonzero boundary and reads the writing
transaction's opcode trace. KECCAK256 inputs are verified locally against their hashes. This search does not
claim to find the first-ever writer, and does not assume that storage changes monotonically.

Static composite keys, including the hash of two addresses, can be inverted through a known, verified ABI
preimage. A candidate with the right hash but the wrong ABI encoding does not justify a key match.
Mapping reconstruction explicitly records the usual cryptographic preimage/collision-resistance assumptions;
it is not a proof of mathematical injectivity of Keccak.

Unattributed storage slots are a diagnostic count, **not** a count of missing holders. Missing entries have
zero values, which can themselves satisfy an authorization condition (`!banned[caller]`). Full slot attribution
alone never establishes the caller set; the complete predicate still has to be solved.

Dumps and traces are expected provider capabilities. Failure to retrieve required data raises `ReadError` and
aborts acquisition; it must not become a semantic answer. A deliberate resource cutoff is `BudgetExceeded`
and remains visible as incomplete analysis. Input transport can be replaced without changing these semantics.
No spot-checked upload is accepted as a complete history or snapshot.

## Composition

Composition is a weakest-precondition calculation for a supplied sequence, outside the per-function engine.
It substitutes actual guarded updates into the following predicate, and requires each earlier call's guard.
Arguments and call values are namespaced per transaction. Actor equality is explicit; different earlier actors
are retained as separate dependencies. One actor's existence does not imply another actor controls it.

Examples tested against the local chain:

- Open `register()` writing `registered[caller] = true`, then a registered-only action, can admit everyone.
- A writer setting that entry to false cannot grant access.
- Unpause followed by withdrawal admits the owner only if the owner remains in place.
- Unpause that also clears ownership does not enable the previous owner.

The current composer handles local guarded updates at the pinned environment. External state transitions,
reentrancy, upgrades, and arbitrary future time changes are not assumed. It rejects unmodelled cross-contract
updates rather than silently substituting only the convenient writes. It does not search all possible transaction
sequences, establish cooperative actors, or claim an unbounded fixpoint from a cycle/depth cutoff.

## Unsupported behavior and operational status

Unknown or opaque reads retain their diagnostic identity but are not assumed to be identical values merely
because their labels match. Formula simplification and evaluation must not cancel such dependencies into a
confident answer. Unknowns on irrelevant, concretely unreachable paths may be ignored.

Verified read-only callees are followed in their own frames. Unverified callees are named `unverified:<address>`.
A finite following limit is a budget limitation, not evidence that the callee is source-unverified.
Known zero-value high-level calls can share ordered storage updates across separate frames, including
sequential calls, acyclic callbacks and rollback. Explicit gas caps, value transfer, try/catch, recursive
cycles, unresolved targets and unmodeled low-level effects remain qualified. A proxy call after a prior
storage/transient/action update remains unsupported: its dispatcher cannot be evaluated against the
unchanged block state. This first supported slice does not establish general cross-contract execution.
In one-shot/internal analysis, unknown actions still qualify state they may alter. Resumable generation
retains unresolved calls before such unknown effects are introduced. Raw/typed or incompatible namespace
aliases remain qualified when their overlap is not modeled.

Typed Solidity `.call` and `.staticcall` now use the same call executor for known zero-value targets.
They return a success flag and bytes; failure restores the pre-call world, including callback writes.
A distinct resource-outcome term qualifies each invocation: low-level failure is not inferred only from
logical reverts, because a callee can exhaust gas while its caller continues. Scalar success returndata
retains ABI types and can be decoded after requiring that very call's success. Static scalar and aggregate raw return bytes retain their declared layout. Revert bytes, dynamic raw returns,
explicit value/gas and unmodeled targets remain qualified. Trailing raw calldata is accepted where the actual ABI decoder permits it.

Explicit assembly writes preserve the 64-byte scratch region boundary. Writes to the allocator word
(64..95) make future allocation uncertain, without erasing objects already allocated above it. Writes
reaching the zero slot or heap, or an unplaced region, invalidate potentially aliased objects. Subsequent
explicit allocations and implicit event/call/precompile/return encodings under an uncertain allocator
also invalidate old objects they might overlap. Return encoding is handled after modifier epilogues.
Allocator uncertainty belongs to each path's heap state, including joins and checkpoint resumes; a
reverting branch cannot poison another path. The uncertainty travels with bytes through internal and
external helpers; encoded data is not reused after an unplaced mutation. Allocator restoration is not proven, so later allocations remain conservative.
Assembly calls decode the requested bytes through the callee's ABI version and types. Partial inputs fail decoding;
trailing bytes remain in the frame even when arguments do not read them. Static tuples/arrays share the typed ABI
layout, and short input fails before materializing a large declared array. Output copying preserves memory beyond
the actual reply and models unaligned byte ranges. Calldata size comes from the supplied frame bytes. Gas/resource
failure remains explicit. Unmodeled assembly calls retain their exact pointer and length; retaining these operands
does not prove the bytes or effects.

Concrete delegate targets are discovered from the proxy's verified fallback IR and storage at the analysis block.
Database implementation metadata is only a fallback discovery hint; it cannot certify proxy behavior at the block.
Generation retains native proxy entries as well as delegated implementation entries. Artifacts capture code locations
and each entry's code/layout; assessment and expansion reuse these locations without rerunning dispatch lowering.
The shared source bundle includes both the implementation and the native dispatcher.
A call reaches the hinted implementation only as the proxy's own verified code says at the block: its fallback
(the selector being no function of the proxy's own) forwards the whole calldata by `delegatecall`, writes
nothing else, forwards gas() rather than an unmodeled explicit gas cap, and the delegate target reads as that
implementation (an EIP-1967 slot, a beacon's answer). Every executed delegate is recorded, even when its result is
unused; memory copies invalidate the entire affected region, and return-data bounds constrain successful paths. Paths
on which the fallback returns without delegating stay qualified unless they evaluate false for the selector;
a callee behind a proxy additionally requires the delegate's return data returned unchanged. An unresolved dispatcher
prevents substituting implementation semantics entirely; it is not conjoined with the implementation's guard.

Values crossing a followed call are encoded by the sender and decoded by the receiver's own ABI coder: v2
rejects a word outside its type, v1 cleans it. Return/local decoding uses the executing statement's source scope,
including imported helpers and modifiers; an unresolvable decoder scope stays unsupported. Decoding constrains success
even when its return value is unused. Scalar decoding of a bytes parameter retains length and validation constraints
on that same parameter.

Concrete ecrecover inputs use actual recovery, including the zero result for invalid signatures. Symbolic
cryptographic feasibility is not replaced with an arbitrary freely chosen signer. Those predicates remain in
the formula, with an unsupported translation qualification when the projection cannot establish feasibility.
The folded assembly/typed-return lowering is not a claim that all ERC-1271 shapes are proved.

Other limitations include symbolic dynamic encodings, some raw/computed storage locations, compiler-rejected
constructs and unsupported mathematical operations. Named dispatch coverage is not a proof that every possible
combination of language features has correct semantics.

## Validation and migration

The executable differential tests retain arithmetic, conversions, loop control, modifiers, declaration scope
across compiler versions and Yul scope cases. New tests cover full-predicate projection, finite-domain truth,
blocklist complements, effect guards, composition, composite keys, transport failures and budget cuts.
`test_ir_coverage.py` checks construct classification only; it is not called a soundness proof.

111 Solidity source snippets from the pre-restructure suite are preserved in
`tests/logic/fixtures/regressions.json`, with original file and line provenance. These fixtures are material
for regression tests, not 111 automatically passing scenarios. The old sampled-open/arrangement assertions
and old fail-safe matrix no longer describe this API; their historical pass totals do not validate it.

No complete current corpus comparison or production rollout is implied by this restructure. Those measurements
must identify the schema, exact source revision, input block and any unresolved qualifications.

## Review fixes and validation (2026-10-29)

The five reproduced review issues have permanent coverage in `test_review_regressions.py`: production lazy-layout
providers, file-level declarations and UTF-8 source spans, different branches rated as one whole function, stale
source context rejected before expansion, and distinct empty/unverified outcomes. The Solidity reproduction is
retained in `tests/fixtures/contracts/logic_review_regressions.sol`.

901 related logic, workflow, vocabulary and logging checks pass. Changed runtime modules pass Ruff and Pyright.
The local-chain generation/assessment/expansion test still returns the independently known owner; its model response
is mocked. No new live Jev inference, metered chain RPC, full corpus run or deployment was performed. The earlier
`effect-impact-v2` recorded responses remain tests of distribution policy and historical evaluation data, not
validation of the new `function-impact-v1` prompt. Real-protocol impact accuracy remains to be measured.

## API validation (2026-10-29)

HTTP integration tests use the real PostgreSQL queue, claim leases and artifact persistence, with RPC, source
acquisition and Jev transport stubbed. They cover all three explicit operations, an exact finite expansion result,
admin authentication, unsupported chains, invalid input references, partial/unverified results, request budgets
across reclaim, stale lease publication, changed inputs, and operational retry with the original pinned block.
A broad backend run passed 1,487 checks; its route-inventory mismatch was corrected, then all 52 focused API,
boundary and metadata checks passed. The 33 job-monitor tests, changed-module typing/lint checks, shell syntax,
and a fresh-database migration upgrade/rollback/re-upgrade passed. No live inference/RPC spend or deployment
was needed for this integration. Existing production assessment/grade consumers are unchanged.

### Large assessment contexts

`generate.context_chars` accepts up to 1,000,000 source characters; omitted source remains an explicit context gap.
`assess.long_context` is false by default. Setting it enables TypeSafe's documented long-context header and raises the
client request byte cap from 100,000 to 1,000,000. It does not change the job's inference-request limit, authorization
proofs, impact thresholds, or retry policy. A provider `max_tokens_exceeded` response is a context budget failure, never
an accepted rating. See https://docs.typesafe.ai/models for the provider's per-question and per-request token limits.

Propositional authority-dependency checks retain the formula DAG. Each node has may-be-true/may-be-false projections;
unknown occurrences remain independent even when their containing nodes are shared. These checks do not enumerate callers.

## Bounded trace acquisition

Production hash-preimage acquisition parses `debug_traceTransaction` incrementally and retains only
KECCAK256/SHA3 input bytes. It consumes the response to EOF; RPC errors and truncated JSON abort the
read rather than publishing partial hints. The existing snapshot/key accounting still decides completeness.
The compact preimage cache and accumulated hints are bounded by the existing word budget; raw opcode
traces and block-diff responses are not retained in the request memo. Peak trace parsing memory depends
on the largest single instruction record, not the complete transaction trace. Custom in-memory readers
may still supply already-materialized traces for tests.

Canonical artifact hashes are fed incrementally to SHA256, preserving the previous JSON hash exactly
without constructing another complete serialized artifact in memory. Generation artifacts still contain
pending checkpoints; separating those payloads from assessment/enumeration manifests remains a further
memory improvement. This change does not promise that every computation fits a fixed memory budget.

### Solver word conversion

Integer-to-EVM-word conversion distributes over conditional values before bitwise operations:
`Int2BV(If(c, a, b)) = If(c, Int2BV(a), Int2BV(b))`. Conversion preserves shared subexpressions
and uses an iterative traversal. This lets the existing solver simplify concrete storage bitmasks
without changing the predicate, introducing a second enumerator, or changing completeness requirements.

### Source and ABI identity boundaries

An explicit source-client `VerifiedSourceUnavailable` result becomes missing-source status; acquisition and build
failures still propagate. Linked calls with empty runtime code stay explicitly unsupported, without guessing
ordinary-account or precompile outcomes, and do not trigger source fetches.

ABI names are built from declared types, with branch-local recursion detection so repeated sibling types stay
canonical. Contract types map to address in the contract ABI; library selectors retain Solidity's distinct internal
names and storage locations. Getter input keys, call frames, dispatch lookup and saved function identities use
the same conversion. Folded function/error/event selectors and interface IDs are resolved from their typed
declarations; an unresolved or ambiguous reference is an unsupported ABI identifier rather than a guessed literal.
Interface IDs include only functions declared by that interface. This changes ABI identity, not support for every
encoded value or external-call behavior. Old generation checkpoints are rejected by the existing engine fingerprint.

Proxy discovery retains a unique concrete delegate target as an inventory candidate even when another branch
has a symbolic target (for example a future upgrade target). Multiple concrete candidates remain ambiguous.
This does not establish complete proxy coverage: each generated implementation entry still requires the existing
selector-specific dispatch proof, including alternate targets and side effects. Failed reads are not omitted.

Nested forwarding reuses the same per-path dispatch validation at each code layer while storage remains at the
deployment address. Entry code locations select the layout used by saved-formula expansion. Visited code contexts
(including branch-specific intermediates) are retained in source bundles and restored on resume. Discovery walks
the concrete cycle-checked inventory before per-function proof-depth limits, so a depth cut leaves pending
functions instead of silently dropping them. Missing intermediate source remains explicit.

Named namespace types must identify one declaration (or equivalent declared types); ambiguous imported names
remain unsupported instead of choosing an arbitrary layout. Multi-transaction composition cannot establish
physical aliases from name-based updates across specialized code contexts, so it retains the existing context-
revalidation qualification in either ordering. This does not change single-function caller projection.

Implementation metadata is not used to import extra selectors when verified runtime source has no fallback.
A beacon's implementation getter does not make its implementation's methods callable at the beacon address.

## Generated getter entries

Physical location construction is shared by concrete state reads and `locate_symbolic`: mapping-key encoding,
array strides/packing, struct offsets and namespace roots use the same walk. Symbolic inputs remain in the slot
and byte-offset expressions. Locating an array element does not prove its index valid; bounds remain execution
conditions. Namespace roots and slot arithmetic have EVM word width. Concrete snapshot accounting does not
intern a formula node for each visited cell.

Persistent root packing uses compiler declaration order, excludes transient/constant/immutable declarations,
and honors the compilation unit's custom storage base. Function-type visibility comes from the compiler AST,
because the frontend's type object loses internal/external visibility. Missing or conflicting metadata is an
explicit unsupported layout, not an assumed width. Scalar aliases use the underlying ABI type for key encoding,
signed decoding and snapshot key normalization. This is storage placement, not function-pointer execution.

Scalar reads and writes now use physical address/slot/byte-range views, while retaining named provenance for
enumeration. Raw and typed writes share the same byte overlay; final effects reread the final aliased value.
Different code layouts use separate named snapshots at one storage address and share that address's accounting
budget. Aggregate views whose aliases cannot be placed remain qualified. General delegate execution is still pending.

Unmodeled location labels are not value identities: they cannot justify reflexivity or common-summand cancellation.
Separate writes through them retain occurrence identifiers instead of overwriting earlier possible writes in the
ordered store. Compiler assembly-reference metadata identifies `.slot` and `.offset` per operand; assigning a slot
to a storage pointer preserves the destination type.

Yul words and logical memory contents are separate. `memory_address` preserves a frame-local reference identity;
its numeric value is unresolved unless represented independently. Supported memory reads dereference current
contents only in the matching frame. Composition namespaces memory identities by transaction. Same-type Yul
reference assignments preserve aliases; incompatible or unplaced reference restoration is a retained `operation`
with `unsupported:memory_reference_cast`, including its state, value, destination and type information.

Free-memory regions use frame-local symbolic addresses and bounded relative offsets, never numeric sentinel
addresses. Byte fragments preserve partial-copy ownership; possible aliases invalidate affected knowledge.
Implicit compiler allocations require a valid allocator state; unplaced allocations remain qualified.
Return-data buffer identity and arity travel with each execution path, including internal calls and catch paths.
Static return words use typed ABI layout; dynamic layouts and revert bytes remain explicitly unsupported.

Write-power projection compares physical slots through the shared slot-equality relation, with explicit hash
collision-resistance assumptions. Physical metadata is not an extra output coordinate. The mapping-administrator
regression now preserves exact power projection. Complex quantified key comparisons may still time out and
remain symbolic. These improvements do not implement general delegate execution or joint multi-write control.

Public mappings and arrays ending in a scalar reuse the same getter execution and storage model.
Declared key types drive ABI encoding, including fixed bytes; each array layer retains its bounds check.
Reads observe preceding updates. Shadowed storage declarations have distinct compiler-derived names in
reads, writes, loop effects and snapshots; ambiguous legacy unqualified names are not guessed. Concrete
string/bytes keys use direct storage reads. Struct-returning getters remain retained call blockers.

Legacy enum widths use the required number of storage bytes, including one byte for a singleton enum.
The shared packer no longer depends on the frontend's zero-width enum layout. Aborted snapshot
acquisition/layout work cannot leave a cached complete empty result.

Short-circuit operators capture their left value before executing the right operand. Compiler RHS spans
identify assignment regions; values are not reread after RHS mutations. Unsupported interleaving is a named
unfollowed path, not guessed eager execution. Modeled caller-independent conditions can be folded using
tracked state before taking a branch, so known-dead calls do not block generation. Unknown-containing
conditions retain their evaluated identity, including a raw call's success flag.

## Effect-assessment migration (2026-11-03)

The effect-impact-v3 request contains a shared encoded program (parameters, whole-call success, every effect
and every successful transition), full function/source context, and separate distributions per effect index.
Requests remain grouped by function, so source is sent once. Wire request/byte limits apply to the whole batch;
there is no silent truncation or per-effect retry. Evaluation labels identify function, effect index and formula
hash, preventing a reordered effect list from being compared with stale labels.

This rates existing compiler effect records. It does not yet partition every value capability: an owner who
can set an arbitrary value and a public branch that can set only a fixed value may still be coalesced into one
write effect at the same location. That effect can have an unrestricted caller projection while the owner has
additional power. Such capability partitioning remains an explicit effect-extraction follow-up; the new rating
lookup alone does not resolve it. Existing event-only or other unmodeled behavior is not declared harmless.

Verified code contexts are retained separately from selected implementation views. Checkpoints record the exact
compiler declaration and restore code contexts before replayed results are consumed. Placed scalar reads use their
recorded physical slot, offset, width and type. Projected array/struct children are re-placed during linking against
the actual code source. Symbolic enumeration requires the source layout to agree with that physical cell family;
a mismatched plain mapping remains qualified. An unplaced load without an authoritative code context is not read
through a same-named variable from another layout.

Byte payloads preserve contiguous known word fragments and explicit unknown gaps, rather than expanding every
word into individual byte expressions. Boolean comparison with integer0/1 preserves EVM numeric equality; an
arbitrary nonzero integer does not equal true. ABI cleanup shortcuts only accept words with the required alignment,
including the different left alignment of fixed bytes.

Symbolic byte inputs use one consistent read-only stream per argument. A finite query introduces only the word
chunks it reads, with congruence constraints for equal indices. Overlapping reads, ABI words and byte-index operations
therefore share bytes; reads past the length are zero-padded without wrapping to the beginning. Concrete input bindings
remain concrete. This models byte semantics, not gas or transaction-size feasibility. Root routing still needs a raw
selector-input representation; a canonical ABI encoding must not stand in for arbitrary calldata before dispatch.

The external ABI decoder distinguishes pre-0.5 ABI v1 short-input padding from the checked decoder paths. Static-word
materialization is charged to the existing value budget before allocation. Caller return-size handling is separate:
legacy compilers and targets without RETURNDATASIZE may expose prior caller-memory bytes on short replies. Such replies
are retained as `unsupported:short_return_buffer` until the actual caller buffer is modeled; they are not treated as
zero-padded replies or guaranteed reverts. See the [Solidity0.5 changes](https://docs.soliditylang.org/en/v0.5.0/050-breaking-changes.html)
and [the compiler's external-call return path](https://github.com/ethereum/solidity/blob/v0.5.0/libsolidity/codegen/ExpressionCompiler.cpp#L1995).

Legacy assembly that Slither retains as text has no regex execution fallback. Its parsed straight-line operations use
the shared memory loads, stores, byte stores, copies, RETURN and STOP. Lexical blocks and declarations remain distinct;
compiler external-reference ids select the actual local/constant declaration, including inherited/shadowed bindings.
Unsupported syntax retains the original node and pre-block state. Allocator lower bounds distinguish older arenas that
can start at0x60 from modern arenas; no synthetic numeric pointer is introduced.

An allocation or ABI return encoding under an unplaced allocator is an unfinished operation. Generation retains its
state rather than introducing a narrow logical value under an unknown guard. This prevents a downstream comparison
from refuting an execution whose actual return bytes were never modeled. Diagnostic one-shot lowering halts unknown.


### Root runtime execution and raw input (2026-11-04)

Deployment generation executes the deployed runtime for each inventoried selector, including
native proxy entries. Inventory metadata does not select the executing body. The root frame
keeps the external sender, value, deployment storage, and actual code address; nested delegates
reuse the same call executor. There is no outer ABI return decoder for a root transaction.

A named-selector query carries a fixed four-byte prefix and an arbitrary `calldata_tail` byte
parameter. This includes short, dirty, and trailing input before the selected runtime decoder.
Concrete validation must bind that raw parameter; binding only the inventory function's old
named parameters is insufficient. Receive queries carry empty calldata. A fallback query uses
arbitrary calldata, excluding every native selector with at least four bytes and empty data when
receive exists. Delegated and called code dispatches these bytes again in its own runtime.
Dynamic input decoding and modified symbolic-length byte buffers remain unfinished operations
where unsupported.

Whole, unmodified calldata copying forwards the same byte value. Overwrites invalidate that
shortcut. Fixed-prefix reads share the existing stream's word congruence and padding semantics;
lengths cannot overflow, and adjacent fixed prefixes normalize before solving.

A root's successful early return and its writes have separate guards. Low-level call resource
uncertainty remains explicit; ample-gas test bindings are not production completeness proofs.
Unreachable qualified exits may be removed at a pinned snapshot, marking specialization.
Supported mutable guards remain symbolic so transition composition retains earlier writes.

Single-write power queries may quantify the length and finite chunk reads of caller-owned byte
inputs with their consistency constraints. These are not independent arbitrary words. Physical
target equalities that cannot be modeled still qualify the query. Joint multi-write power is not
implemented by this increment.


### Runtime domains and effect inventory (2026-11-04)

Runtime dispatch is a partition of verified entry signatures, receive and fallback domains.
Shorter-than-four-byte inputs cannot match a named selector, even selector zero. Invalid ABI
input to a matched named function reverts; it does not select fallback. If no matching entry
exists, the call reverts. The same call executor handles concrete and symbolic selector inputs;
raw byte producers no longer guess signatures or decode a second time.

Invoking path conditions travel with the call request and are captured with the caller's frame
before entering another function. The executor intersects them with each dispatch domain before
resolving a body or decoding arguments. Impossible branches do not demand unsupported decoders
or getter bodies. The ordinary Boolean simplifier handles contradictory flattened conjunctions;
this is not a protocol-specific selector shortcut.

Generation retains explicit view/pure functions. Their annotation cannot prove the effects of
the whole runtime route: old Solidity can accept a storage-writing constant function, and a proxy
can write before delegating to a pure implementation. Compiler-generated getter declarations
are still omitted as standalone bodies; their selectors participate in dispatch, and upstream
fallback formulas include routed getter cases. No-effect formulas are not automatically assigned
a harmless severity. Fresh full-scope cohort counts therefore include more explicit entries than
old reports which filtered view/pure annotations.


### Byte views, input decoding and operand types (2026-11-04)

A byte slice retains its source, start and length. A patched byte value retains its original
extent plus ordered placed writes. Reads share the source stream's chunk-congruence relation;
neither view invents independent input bytes. Copy reads pad beyond the source without wrapping
back to offset zero. Patches clip at the original extent, so writing a four-byte selector into
memory does not turn a zero/short call into a named call. Unknown placement still suspends
execution. A fixed window can be projected directly only when a structural minimum length
proves that the window exists; this preserves known selectors without guessing calldata size.

The Solidity0.8 ABI-coder-v2 profile decodes top-level bytes/string parameters, alongside static
parameters, to byte slices. Its path conditions retain head/offset/length checks and ordered
memory-allocation limits. Noncanonical offsets, aliases and unpadded tails are not rejected just
for differing from the canonical encoder. Memory parameters are separate objects even when
input offsets alias; bytes/string conversions of an existing memory object preserve its alias.
Missing data-location metadata and unsupported dynamic kinds/profiles remain retained work.
Dynamic arrays and tuples containing dynamic fields are not supported by this increment.

Binary operation width and implicit fixed-byte widening use the compiler AST common type,
indexed by exact source spans. The assigned temporary's width is not the operation width.
Legacy signed right shift follows SDIV by the wrapped EVM power of two, and signed negative
Solidity shift counts are rejected. Yul keeps its own EVM word semantics. These rules apply by
language/compiler semantics, not function or protocol names.

### Low-level call gas outcomes (2026-11-04)

Each low-level call keeps its resource-outcome term in the formula. Projection (`project`, selection access)
assumes that outcome succeeds only where the predicate needs the call to succeed: positively, including the
assembly word tests `ok != 0` / `ok == 1`. Raising such an outcome to TRUE can only admit more callers, and with
ample gas it is exact, so the result is complete and carries the assumption "low-level calls receive enough
gas to complete". An outcome that also appears negatively (a path that needs the call to fail, which a sender may
force with limited gas, subject to the 63/64 rule) or inside a word operation stays unknown, and that result
stays qualified. Formulas are unchanged; only their projection applies the assumption.
