# Logic engine specification: formula, list, check

Status: draft for the restructure on branch `test/auth-fuzz-restructure`, 2026-10-27. Supersedes the decision
rules in `decide.py` and `holders.py` described in COVERAGE.md sections G4, G7, G11, G13 and the "Stated
assumptions" list. The lowering (`lower.py`, `terms.py`) and its coverage contract (COVERAGE.md, `test_ir_coverage`)
are unchanged by this specification.

## 1. Purpose

For every state-changing entry point of every contract, answer: who can call it, under what conditions, and how do
we know. The answer must be

* **generic** — derived from the language semantics and the chain alone; never from a protocol, a standard, a name
  or a code shape;
* **honest** — every statement is either proved from code and chain state, or carries a named gap saying exactly
  what is missing;
* **fail-safe** — no bug, failed read or exhausted budget can make a statement bolder than the truth: never a wider
  set of callers than the code admits, never a list called complete that is not. Budgets change how much is
  materialised, never what is claimed.

## 2. The three stages

### 2.1 Formula

The lowering turns a function's code, with every callee it can follow and every proxy it can resolve, into a term:
the condition under which a call from `caller` with arguments `args` succeeds at a block, over storage words. This
stage exists today and is governed by COVERAGE.md. It does not read the chain beyond what it needs to resolve code
(proxy targets, callee addresses held in storage, immutables).

A formula is reported for every function, always. It is the primary answer. Where the lowering cannot express a
construct, the formula contains a named `unknown` term from the coverage table; that term is reported, never
resolved by guessing.

### 2.2 List

The formula is split, syntactically, into three parts by what each conjunct mentions:

* **who** — conjuncts that mention the caller identity (`caller`, `origin`, a recovered `signer`, or an identity
  handed to a followed callee);
* **argument conditions** — conjuncts over arguments only, or arguments and storage, with no identity;
* **state conditions** — conjuncts over storage (and block data) only.

The list is computed from the **who** part:

1. **Candidates.** Every identity-keyed storage read in the who part names a mapping (or array, or struct field). Its
   keys are enumerated from the two sources the chain offers: the storage dump (`snapshot.py`: every occupied slot,
   explained by hashing known keys, including code-derived composite keys — §4.1) and the writers' event history
   (`logged.py`). Keys held directly in storage (an `owner` word, an array of addresses) are candidates by reading.
   Keys from a verified supplied fact (§6) are candidates too.
2. **Evaluation.** The who part is evaluated for each candidate with storage read at the block. Candidates for which
   it is true are **principals**. Evaluation is the solver's job; a term it cannot evaluate for a candidate leaves
   that candidate `undecided` with the term named.
3. **Completeness.** The list is **complete** when, for every mapping the who part reads, every occupied slot of
   that mapping is explained by an enumerated key (dump accounting), or the writers' history was read whole and the
   contract has no other writer of that storage (delegatecall, `selfdestruct`-redeploy). Otherwise the list is
   incomplete and the gap names the mapping and the count of unexplained slots. An unexplained slot's key is
   recovered, where the budget allows, by tracing the transaction that wrote it (`debug_traceTransaction`, as
   `snapshot.py` does today). Completeness is a statement about keys; it never depends on which code path produced a
   candidate.
4. **Crowds.** When the enumeration of a mapping exceeds the materialisation budget (`LIST_LIMIT` keys), the list is
   not materialised: the row reports the formula, the key count, and `crowd:<mapping>`. A reader who wants the full
   set asks for it per function. The engine never decides which functions matter.

Signer identities: a `signer` in the who part is an identity like `caller`. A who part that admits
`signer == stored` yields that stored address as a principal, exercised by signature (the row notes that the call may
be relayed). `signer == arg` yields "any account, for itself". The zero address is in the signer's domain (a
non-recovering signature); a who part satisfied by `signer == 0` is satisfied by anyone.

### 2.3 Composition of state

A state condition reads storage that other functions write. For each storage variable in a state condition, the map
already has the write set of every function and each writer's own formula. Composition substitutes:

> `paused == false`  ⇒  `paused == false at the block`, or `caller_of(unpause)` acts first, where
> `caller_of(unpause)` is unpause's who part.

Substitution repeats to depth `COMPOSE_DEPTH`, and stops at a variable no function writes, a cycle, or the depth.
The result is reported as the composition chain: the variable, its value at the block, the writers and their
principals, and where the chain stopped. The who part is composed the same way when it reads a mapping some function
writes for the caller: `registered[caller]` whose writer `register()` is open composes to "anyone, after `register`".

Composition replaces every notion of "later", "arranged", "after" and "conditional" in the old engine. Nothing is
simulated. Ether sent with a call (`msg.value`) and a function's own writes within the call are argument/state facts
and compose like any other.

### 2.4 Check

For each row with a materialised list, one `eth_call` per principal (its own call, at the block, with arguments
chosen by the solver to satisfy the argument conditions) and one for a stranger address that is in no mapping. The
check has exactly two outcomes:

* agreement — nothing is recorded beyond `checked: n`;
* disagreement — a principal's call reverts, or the stranger's passes: the row keeps its formula and list and adds
  the gap `engine_chain_disagree:<who>`; the row's openness is `not_determined`. A disagreement is a defect in the
  lowering or the evaluator and is fixed with a test, never with a decision rule.

The check never adds a principal, never removes one, never promotes a list to complete, never changes a condition.
A call the node does not answer is `read_failed:run`, not a disagreement.

### 2.5 Cases the three parts must cover

Resolved against the inventory (INVENTORY.md §G) so that no case needs a rule outside §2:

* **Signers.** A `signer` is an identity in the who part (§2.2). The check cannot sign for a principal, so a
  signature-gated principal is `checked: skipped:signature`; the stranger's call is still made with a non-recovering
  signature. Skipping is not a gap.
* **Preimages and proofs.** A who part or argument condition satisfiable by anyone who knows a preimage or a proof
  against a stored commitment is reported as an argument condition naming the commitment (`need:` per §6). Openness
  follows the identity conjuncts alone: with none, the row is open with that condition.
* **Identity as a mapping value** (`caller == records[id].manager`, caller-chosen `id`). Principals are the words
  held at the mapping's slots, which the dump gives directly; a slot is attributed to the mapping by key enumeration
  (integer ids, array lengths, traced writes). Completeness is every slot of that mapping attributed.
* **Linked lists and pointers in storage** (a sentinel-headed owner list). Walking storage is reading storage:
  candidates come from the walk, bounded by `LIST_LIMIT`, and the walk's end is the completeness condition.
* **Holdings in another contract** (`token.balanceOf(caller) >= x`). The same enumeration applied to the other
  contract's mapping; in practice a crowd, reported as the formula plus the key count (§2.2.4). Holdings are never
  excluded by kind.
* **State keyed by an argument** (a proposal id, a timelock operation). A state condition may read storage at a
  caller-chosen key; it composes through the writer of that storage like any other (`propose`'s who part).
* **Time.** Block number and timestamp are state atoms with no writer: reported with their value at the block and
  the bound the condition states (`after T`, `before T`). Composition stops at them with reason `time`.
* **Composition fixpoints.** A writer gated on the mapping it writes (`grantRole` by the role's admin) composes to
  the enumerated list of that mapping at the block, with reason `self`; it does not recurse.
* **Earlier implementations.** Event enumeration must cover every implementation the proxy ran (`versions`); dump
  enumeration needs no such care. Both stay.
* **Code at the caller's address** (`extcodesize(caller)`, EIP-7702 designators). A who conjunct on the caller's
  code is reported as a condition on the principal ("must be / must not be a contract"); the list comes from the
  other conjuncts, and the check evaluates the conjunct for each principal by reading its code.
* **Effect versus return.** The check asks whether the call reverts, not whether it changes state (COVERAGE G3,
  decision D3). A no-op `unpause()` while unpaused is therefore open to call and inert; the write set already shows
  the inertness and the row may say so, but no rule depends on it.
* **Check arguments.** The check's arguments are chosen by the solver to satisfy the argument and state parts at the
  block. When they cannot be satisfied at the block (a deadline passed, a stage not reached), the check is
  `skipped:unsatisfiable`, never a disagreement.
* **Caller-named delegatecall.** A function that delegates to code the caller names has, after its gate, an arbitrary
  effect; the formula is its gate, the effect is reported as `arbitrary`, and nothing about who may call it changes.

## 3. What a row contains

```
address, chain, block, function (signature, selector)
formula            the lowered term, printed, with its unknowns
who                the identity part (printed)
principals         addresses; for each: how it was found (storage word | dump slot | event | supplied fact),
                   checked (True | False | unanswered)
complete           bool
incomplete_because [ (mapping, unexplained_slots | history_cut | other_writer) ]
undecided          [ (address, term) ]
crowd              [ (mapping, key_count) ]            when not materialised
arguments          [ printed conjuncts ]                what the call must carry
state              [ (variable, value_at_block, holds: bool) ]
composition        [ (variable, writers: [(function, principals, complete)], depth, stopped: reason|None) ]
gaps               [ names from §5 ]
openness           open | restricted | not_verified | not_determined   derived (§3.1)
```

### 3.1 Derived openness

* `open` — the who part is a tautology (no identity conjunct, or one every address satisfies, `signer == 0`
  included), and no gap of §5 class A is present.
* `restricted` — the who part is not a tautology and the list is materialised (complete or not), or is a crowd.
* `not_verified` — a callee in the who part has no verified source (`unfollowed:<address>`). The row keeps its
  formula and the principals the rest of the who part yields; what the unverified code admits is unknown until its
  source is supplied and verified against the on-chain code hash (§6). This is a statement about the contract, not
  about the engine, and is reported as such.
* `not_determined` — the formula has an `unknown` construct in the who part, a read the who part needs failed, or
  the check disagreed.

Openness is a summary of the row for consumers; the row's content is the formula and list.

## 4. Enumeration

### 4.1 Storage dump accounting

Given every occupied slot of a contract at the block (`debug_storageRangeAt`), the accounting marks each slot that
the contract's layout reaches from known keys: plain variables, mapping entries at known keys, nested mappings,
struct fields, arrays to their length, long bytes, and **code-derived keys**: when the lowering's key term is a hash
over several words (`keccak(who, where, what)`), the accounting enumerates the identity position over candidates and
every other position over the known-word set (dump words, code constants, event words, supplied facts) and marks the
resulting slots. Slots left unmarked are unexplained; their count is reported. The accounting is bounded by
`ACCOUNT_SLOTS` computations; exceeding it is `budget:accounting`, which leaves the list incomplete.

### 4.2 Event history

Writers of a mapping emit events whose words name keys. History is read in windows (`LOG_WINDOW`, halved on refusal)
within `LOG_SECONDS`; a cut history is `history_cut:<address>`. A history is read once per contract and address per
run, not per function.

### 4.3 Sources of candidates are never sources of truth

A candidate from any source becomes a principal only by evaluation of the who part against storage at the block.

## 5. Gaps

Class A (set the row's openness):
`unknown:<construct>` in the who part (from the coverage table) → `not_determined` · `unfollowed:<address>` in the
who part (no verified source) → `not_verified` · `engine_chain_disagree:<who>` → `not_determined` ·
`read_failed:<what>` on a read the who part needs → `not_determined`.

The node is assumed to serve `debug_storageRangeAt` and `debug_traceTransaction` at the block, as the current
harness's node does (`corpus_parity.debug`, `Chain.storage_dump`); a mapping is therefore always enumerable from
its dump, and a dump the node does not answer is `read_failed:dump:<address>`, a transient like any failed read.

Class B (leave openness; qualify the list or conditions):
`incomplete:<mapping>:<n>` · `history_cut:<address>` · `crowd:<mapping>` · `budget:<which>` · `undecided:<n>` ·
`composition_stopped:<variable>:<reason>` · `unknown:<construct>` in an argument or state conjunct ·
`unfollowed:<callee>` outside the who part · `supplied:<fact kind>` (a list rests on a verified supplied fact).

No other gap names exist. Every name is listed in COVERAGE.md with the code that emits it, enforced by
`test_ir_coverage`.

## 6. Supplied facts

Some information the chain commits to but does not hold: the members of a Merkle root, the source of an unverified
contract, a history from another indexer, a dump from another node. A row that lacks such information names the
need in machine-readable form (`need: {kind, commitment, encoding}`). A supplied fact is accepted only after its
verifier checks it against the on-chain commitment (root recomputation with the stated construction; bytecode hash;
sampled window agreement; sampled slot reads). Verified facts are cached by commitment and invalidated when the
commitment changes. A fact without an on-chain commitment is shown as a claim with its source and never as a list.
Supplied facts are out of scope for the first restructure phase; the need field is in scope.

## 7. Budgets

Only these constants exist, and each bounds materialisation, never a claim:
`LIST_LIMIT` (keys materialised per mapping), `ACCOUNT_SLOTS` (dump accounting computations), `LOG_WINDOW`,
`LOG_SECONDS`, `LOG_TOTAL_SECONDS`, `READ_CAP` (chain reads per function), `COMPOSE_DEPTH`, `CALLEE_DEPTH`
(followed-callee nesting, a lowering budget). `test_failsafe` sweeps each: halving a budget may only add class B
gaps and remove principals from an incomplete list; it may never add a principal, complete a list, or turn
`not_determined` into anything else.

## 8. Removed from the engine

The following have no role and are deleted, with their tests: the five keyed strangers and `strangers_run`;
`_confirmed_open`, `_alike_for_strangers`, the `witnessed` flag and "open_*_unconfirmed" gaps; arranged/after
journeys, state overrides, `_decide_arranged`, `_state_blocked`, `_after_runs`, `_brought_runs`, `allowed`
now/later/conditional, `requires`, the `conditions` dictionary (business, holdings, arguments); `_opaque_conditions`
and `_rests_on_code_not_followed`; `_proven_by_code` and `World.assumed`; `callee_code_list/_pass/_refutation` and
every hint list drawn from logged words or depth; `_run_rest`, `UNPROVEN_*`, `_RUN_CANDIDATES`,
`_EXECUTED_CANDIDATES`; `scope.py` and `SCOPE.md`; the origin opcode walk (`_reachable_code`, `_opcodes`, `_instructions`,
`caller_bound`'s bytecode scan, `hidden`) — an `unknown` in the who part is class A and the check catches a misread,
so no bytecode heuristic stands in for either (decided 2026-10-27); the opcode reader stays only as far as proxy
detection (`_delegate_ops`) needs it to recognise delegating code; batch retry beyond one re-ask; `too_many_candidates`,
`identity_use`, `depth`, `others_unproven`, `unrepresentative`, `inert_when_allowed`, `state_blocks_everyone`,
`chosen_identity`, `now_unknown`, `strangers_differ`, `self_scoped*` and every other gap not in §5.

## 9. Tests

* Oracle tests (`_oracle.check`, `sound`, anvil truth) are the specification and stay. Their expectations are
  re-expressed in the §3 record: `open_at` → openness and principals; `later`/`after` → composition chain content.
* `test_failsafe` stays, re-pointed at §7's constants and §2.4's faults (callee lowered wrong, storage read failing,
  history halved, node unanswered): the property is §1's fail-safe clause plus "a fault produces a class A/B gap or
  a disagreement, never a bolder row".
* `test_ir_coverage` stays and additionally enforces §5's closed gap vocabulary.
* New: `test_composition` (pause/unpause, register, renounced owner with a setter, depth stop, cycle);
  `test_enumeration` (dump accounting incl. composite keys, history, crowd, zero signer); `test_check` (a
  deliberately mis-lowered callee produces a disagreement row, never a bolder one).
* Deleted: every test pinning the vocabulary in §8.

## 10. Phases

1. **Classify and freeze.** INVENTORY.md (KEEP/ADAPT/REMOVE per function, field, constant, gap, test). Commit.
2. **Record and vocabulary.** New `Verdict` per §3, gap set per §5, consumers (`report.py`,
   `logic_run_passes.py`, harness) adapted. Old fields removed. Commit; suite re-pointed.
3. **List.** Candidates from dump + history only; composite-key accounting; completeness per §2.2.3; crowds.
   Remove hint lists and the callee-code rule. Commit; sweep green.
4. **Composition.** Replace arranged/after/state-blocked with §2.3. Commit; `test_composition` green.
5. **Check.** Replace strangers and confirmation with §2.4. Remove witnessed/proven. Commit; `test_check` green.
6. **Signatures.** Fold round eleven's lowering (signer term, assembly staticcall shape, typed short returns) from
   `scratchpad/round11/round11.diff`; drop its decision code; zero signer per §2.2. Commit.
7. **Prune.** Delete everything in §8 still reachable; budgets per §7; COVERAGE.md rewritten to this spec. Commit.
8. **Measure.** Corpus rerun on the warm cache; compare with v53 and main on: rows with a formula (expect all),
   rows with a complete list, disagreements (expect a short list, each a filed bug), class A gaps by name.

Each phase is independently reviewed with anvil probes before the next starts. No phase may leave the sweep red.
