# Formula engine

Status: implemented on `test/auth-fuzz-restructure`; local validation only. Supersedes the earlier
formula/list/check proposal. The whole predicate is authoritative. No conjunction is discarded to
make a caller pass, and no caller sample proves an unrestricted or complete set.

## Boundary

The core accepts verified compiler inputs, deployment addresses, a pinned block and a read interface.
The default job emits function formulas, per-effect guards and guarded state updates only.
Address expansion is a separate, explicitly requested process over saved formulas.
It makes no `eth_call`, signs nothing, changes no chain state, and runs no fork or arranged transaction.

`clients/logic_reads.py` owns transport, retries, pagination, caching, read budgets and trace retrieval.
`resolution/logic_composition.py` composes explicitly supplied sequences of rows symbolically.
The test harness owns transactions, replays and differential checks. Presentation labels belong to consumers.
The existing opt-in resolution-worker integration stores schema-2 results as an auxiliary artifact; it does
not replace production principal rows or the UI. Its artifact now has `kind: formulas` and contains no caller lists.

`expansion.expand_formula` accepts a previously compiled `Formula`, a reader pinned to its block, and an explicit
selection. By default, an explicit expansion request expands that function's callers only; effects must be selected
by index. It never re-lowers the function. The deployment wrapper can load verified storage layouts as needed.
The old combined `analyze_function` production entry point has been removed.

Run the separate process against an exported formula artifact:

```sh
python -m scripts.logic_expand formulas.json --function 'setOwner(address)' --rpc-url "$RPC_URL" --output addresses.json
# Or expand only one effect, with no function-wide caller expansion:
python -m scripts.logic_expand formulas.json --effect 'setOwner(address):0' --rpc-url "$RPC_URL" --output addresses.json
```

The command requires a selection and writes a separate `address_expansions` artifact. It preserves the input
formula, chain, block and signature, and links each result to a hash of its saved formula. Missing or invalid
selections fail before reads. Expansion has its own materialisation/solver limits. A later run at another block
requires new formulas, rather than mixing old resolved callees with new state.

Formula generation makes only concrete reads needed for linking. It does not dump storage, scan candidate logs,
trace keys or query the solver for callers; symbolic callee targets remain unresolved instead of triggering enumeration.

## Selection reports (first pass)

`services.resolution.logic_selection` consumes saved formula artifacts and writes a separate
`expansion_selection` report. It never enumerates callers, executes a call, calls Jev, or schedules expansion.

```sh
python -m scripts.logic_select formulas.json --output selection.json
# Optional bounded direct state reads, at the formula artifact's original block:
python -m scripts.logic_select formulas.json --rpc-url "$RPC_URL" --direct-reads 64 --output selection.json
```

Offline mode requires no RPC or database. State-dependent access remains unresolved. With a provider, the service
permits bounded direct reads; symbolic membership lookups remain `state_required`. A hard provider boundary blocks
dumps, event scans and trace/preimage enumeration. Failed reads abort the report rather than become low priority.

For each effect it checks the complete guard. Ordinary arguments are existential choices; observed caller/origin
identity dimensions are considered jointly, so a privileged origin cannot be borrowed to prove unrestricted access.
Unmodelled signature feasibility remains unresolved. These are call-frame classifications, not proof of transaction
admission or control of someone else's key. The existing caller-only expansion API cannot enumerate origin/signing
authority, so those dimensions route to review. Inactive-at-block is separate from access and never means low severity.

Structural evidence links writes to guard reads within the supplied deployment. For a required identity equality or
Boolean identity lookup, a write at a potentially aliasing location is marked as a **potential** authority change.
Boolean implication covers the whole guard, including alternate paths; source identifiers are not a classifier.
Possible aliasing is not proof that the writer can establish a particular permission. Other guard dependencies stay
ordinary dependency evidence. External/unmodelled effects and raw storage writes receive high attention. Numeric
upper bounds, when proved under a reachable full guard, describe storage values only, not asset loss.

The deterministic pass deliberately leaves economic impact `unknown`. `high` attention is a transparent selection policy
applied to structural concerns, not a proven financial severity score. It does not claim transfers/deposits are benign,
and does not infer low impact from caller-keyed writes, small numbers, missing evidence or a function name.

Decisions are `expand` (recommendation only), `review`, `report_unrestricted` (keep visible without a holder list),
and `defer` for a formula with no successful path. Paused effects retain their attention and need enabling conditions
reviewed. High-attention restricted effects, or those missing only membership state, can recommend effect-level
expansion. Unknown code/semantics go to review. Every input function remains represented, including functions without
reported effects. Limits on queries, direct reads, assessed effects and dependency scans are recorded explicitly.

Reports retain chain, block, function, effect index, formula hash, policy version, evidence links, issues and decisions.
They include suggested expansion requests, but nothing consumes them automatically. A separate optional impact
pass can enrich this report. The earlier Jev pilot is not a labeled severity oracle.

## Optional impact assessment

`services.resolution.logic_impact` rates the potential power of each effect conditional on execution. It uses
version-pinned Jev judgments about assets/claims, authority/code, availability, scope and source sufficiency.
These are **model estimates**, never authority proofs, caller-set completeness or dollar-loss bounds.
The deterministic access result and original formula are preserved. The model sees source and structural facts,
not the preceding priority or decision. Missing knowledge remains visible.

Formula artifacts now include bounded source contexts captured from compiler inputs, including already-followed
callees. No additional RPC or model call is made by formula generation. Each context references its formula hash
and hashes its source units. Source truncation and missing callees are explicit. Effect locations use exact action
IR identities where available, or candidate write statements otherwise; they are presentation evidence, not proof
inputs. `source_complete` describes this captured scope, not the economic perimeter. Old artifacts without contexts
remain usable but receive `missing_context` in this pass; newly fetched source is never silently joined to them.

```sh
# Read cached judgments only; no API key or network request is needed:
python -m scripts.logic_impact formulas.json selection.json --cache .jev-cache --output impact.json
# Explicitly permit at most eight new requests (TYPESAFE_API_KEY or JEV_API_KEY in the environment):
python -m scripts.logic_impact formulas.json selection.json --cache .jev-cache --output impact.json --live --max-requests 8
# After reviewing the recommendations, explicitly run separate address expansion:
python -m scripts.logic_expand formulas.json --selection-report impact.json --rpc-url "$RPC_URL" --output addresses.json
```

The client pins `jev-1.14.0`, bounds request size and wire attempts, and does not retry or follow redirects.
The local cache retains exact model/rubric/context requests and raw distributions, without credentials.
Timeouts consume an attempt; failures and budget exhaustion do not change access or erase deterministic decisions.
Changing source, the questions, or the model invalidates the cache key. Cached outputs are revalidated before use.

Display/routing thresholds are provisional, not calibrated probabilities of correctness. A high estimate can
raise attention or recommend expansion when access analysis supports caller expansion. A low estimate only marks
a deferral candidate: it cannot discard a row or override structural high attention. Uncertain estimates abstain;
unrestricted high-impact effects remain visible without enumerating a universal set. Origin/signature identities,
inactive effects and unsupported access stay under review. No automatic scheduling or production grade changes exist.

`--selection-report` validates the saved chain, block, formula hash and selected effect indices before expansion.
It accepts either the deterministic report or its enriched copy and rejects stale or ambiguous selections.
This flag is an explicit execution request; generating either report alone never starts address expansion.

`scripts.logic_impact_evaluate` compares saved reports with supplied review labels offline. Abstentions are reported
separately from matches and errors. Historical pilot outputs without labels have no reported accuracy.

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

## Local validation (2026-10-27)

- Latest focused run: 809 passed, including the compiler, language, relation, composition, historical comparison
  and vocabulary checks. This includes the final discarded-call, call-entry-balance and composed-selector regressions.
- Broader offline run: 7,037 passed, 88 skipped, 105 deselected; its single failure was a solc 0.7.0 cache-path
  configuration issue. That compiler test passed when rerun using the already-installed home-directory compilers.
- Ruff checks/formatting pass. New runtime modules pass Pyright. The inherited lowerer/term/parser files still
  have baseline typing diagnostics; an older-tree check reproduced 27 diagnostics in those files.
- No metered RPC, new full-corpus comparison, deployment or production-pipeline replacement was performed.

## Separate expansion validation (2026-10-28)

823 logic, script and vocabulary checks pass. Changed runtime modules pass Pyright and Ruff. Tests verify
formula-only default jobs, no enumeration during linking, saved-formula round trips, explicit function/effect
selection, block matching, input preservation and expansion in a fresh Python process. No live corpus was run.

## Selection-report validation (2026-10-28)

849 logic, script and vocabulary/logging checks pass; Ruff and changed-module Pyright checks pass.
An independent local Anvil example selected owner reassignment and membership granting, kept a paused owner
change under review, and retained unrestricted owner reassignment as high attention without holder enumeration.
That fixture report used three distinct direct reads and eighteen solver queries; these are fixture measurements,
not corpus cost estimates. No Jev request, metered RPC, automatic expansion or live corpus run was performed.

## Impact-assessment validation (2026-10-28)

886 related logic, script and vocabulary/logging checks pass; changed runtime modules pass Pyright and Ruff.
The tests cover context/cache identity, request budgets, malformed responses, estimate abstentions, preservation
of access evidence, and explicit expansion from a matching report. Recorded live responses are policy regression
fixtures; they are not an oracle for general model correctness.

The small live evaluation used one synthetic native-asset vault with eight review-labeled operations and two
renamed/comment variants of that same vault. Rubric v2 accepted six estimates matching those labels and abstained
on four, with no accepted mismatch. All five high-power examples (including the renamed seizure variant) were
accepted high. The ordinary deposit, withdrawal and bounded-fee examples included abstentions. These results do
not establish corpus accuracy, calibrated confidence, or reliable automatic deferral. The v1 development pass
accepted one of eight and abstained on seven; v2 improved source locations and distinguished compiler limitations
from missing source, without lowering the acceptance thresholds.

`tests/fixtures/logic_impact/evaluation_2026_10_28.json` retains the case labels, raw ranking signals, uncertainty,
counts and historical pilot summary. The earlier 28 pilot records have no independent labels and use a different
model/rubric/context, so no accuracy comparison is claimed. Total live usage was 18 judgments plus one API smoke
request, reporting 54,580 input and 2,298 output tokens. Replaying all eight development judgments used eight cache
hits and zero wire requests. No metered chain RPC, corpus run, automatic address expansion or production change
was performed for this integration. The next evaluation needs independently reviewed real-protocol cases before
model-only low-impact deferral is considered.
