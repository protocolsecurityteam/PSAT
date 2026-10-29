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

`assess` runs deterministic access analysis and requests **one Jev judgment per whole function**, using its source
span and associated source. A function with many effects does not make many model calls. Ratings concern the greatest
potential power through the function; they are model estimates, not authorization or financial-loss proofs.
Effect-specific access relations remain separate, and the rating is not claimed to describe each effect individually.

`enumerate` explicitly expands recommended effect guards from the saved artifact. `--function` narrows recommendations.
`--manual` instead requires explicit `--function` (whole-call relation) or `--effect` selections. It cannot be combined
with `--assessment`. Neither generation nor assessment starts this job. Expansion never recompiles predicates; it may
load verified layouts to read storage. All reads use the saved block. Outputs cannot overwrite input artifacts.

The old `logic_select`, `logic_impact` and `logic_expand` command wrappers have been removed; their useful operations
are in the three jobs above. The offline `logic_impact_evaluate` command compares function ratings with supplied labels.

## Asynchronous API

The same services are exposed through authenticated API jobs. Use the existing admin session or
`X-PSAT-Admin-Key` authentication. HTTP handlers submit work; they do not compile, call Jev or enumerate.

| Request | Body | Result |
| --- | --- | --- |
| `POST /api/logic/generate` | `address`, `chain_id`; optional `block`, `related_addresses`, `context_chars` | 202, generation job ID |
| `POST /api/logic/assess` | `formula_job_id`; optional `max_requests`, `cache_only`, direct-read/solver budgets | 202, assessment job ID |
| `POST /api/logic/enumerate` | `assessment_job_id`, explicit `functions`; optional member/solver limits | 202, enumeration job ID |
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

`logic_impact.rate_functions` supplies ratings only. A pinned model, rubric, source context and full exact request key
the cache. Raw distributions are retained. Changed context/questions invalidate cached requests. Credentials are never
saved. `TYPESAFE_API_KEY` or `JEV_API_KEY` permits uncached requests by default; `--cache-only` forbids them.
`--max-requests` bounds wire attempts (default 8), including timeouts. Exact cache replay needs no credential.

`logic_assessment` contains the **only expansion-selection policy**: retain unrestricted effects visibly; retain
inactive, origin/signature-dependent, unsupported, unrated and uncertain cases for review; recommend supported caller
relations when their function has a medium/high estimate. Missing only membership state can be resolved by expansion.
Low ratings never silently discard a function. A severe function can prioritize several effects conservatively; this
is not a claim that each of those effects has the function's severity. No maximum-over-effect rating is computed.

The report's `assessment.functions` holds each rating once. `rows` retain effect access evidence and decisions;
`suggested_expansions` is an execution plan, not an automatic job. `artifact_hash` binds the plan to all saved formulas
and their source bundle/context references. Enumeration rejects an old assessment after any of those inputs change.

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

A function has a complete success predicate over caller, origin, arguments, value and the state at the block.
Each effect has its own guard. An early return may be callable by everyone while its write is owner-only.
A transition contains its successful exit guard and **all** final storage updates, including their values.

The display may highlight identity, argument and state dependencies. They are never solved independently:
`managers[id] == caller && id == 0` admits only the manager at zero. Disjunctions, shared variables and
conditions on recovered identities stay in the same predicate.

`msg.sender` and `tx.origin` are distinct variables. A projection onto the caller existentially quantifies
other inputs, including origin; it does not claim the caller can obtain a particular origin or anyone else's
signature. The original formula and projection identity are always retained. The address domain is the full
160-bit word domain; key ownership and transaction-origin feasibility are not inferred from membership.
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
Stateful external-call transitions, downstream effects of external calls, and unresolved proxy dispatch
currently stay explicit unsupported terms.
Database implementation metadata is only a discovery hint; it cannot certify proxy behavior at the block.

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
