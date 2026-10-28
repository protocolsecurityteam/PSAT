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
