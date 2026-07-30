# Scorer data-gap fix plan

Execution plan for the 18 scorer-blocking data gaps investigated 2026-07-30
(groups A–D). Written to be executed by an **orchestrator agent** who was not
part of the investigation. Everything needed is here or pointed to; read §0–§5
before dispatching any unit.

**Status: PLAN — awaiting the user's approval to begin. Nothing here is
implemented. Do not commit or push without explicit user authorization.**

---

## READ FIRST — you are the ORCHESTRATOR, not a solo implementer

This file is executed by an **orchestrator agent that dispatches sub-agents**. Do
not implement it solo. The verification guarantee depends on this:

- **You never implement and review your own work.** Each unit is implemented by
  one **Opus** agent and refuted by a SEPARATE **Fable (high-effort)** adversarial
  reviewer that re-measures independently (§4). An agent grading its own diff is
  not an independent gate and voids the entire premise (§0). If you cannot spawn
  sub-agents, STOP and say so — do not self-review.
- **Models (no Sonnet anywhere):** orchestrator = Opus; the 13 implementers and
  the Phase-0 grounding agent = Opus; every adversarial reviewer (~10) and the
  final integration gate = **Fable, high effort**. Set `model:` explicitly on
  every dispatch.
- **13 units** (§6), dispatched in the waves of §5. The migration chain (Wave 2)
  is **sequential** — each alembic revision builds on the prior (§1.5).

### Required companion files — this spec is NOT self-contained without them
These MUST be present in the tree the agents work from. They are **untracked**
today, so a worktree branched off a clean commit will NOT contain them unless you
act first:
- `SCORING_GAP_FIX_PLAN.md` (this file)
- `scoring_prototype/gap_investigation/{adversarial,lane-A,lane-B,lane-C,lane-D}.json`
  — the per-gap provable cores. **Where a lane report and the adversarial verdict
  disagree, the adversarial verdict governs.**

**First action:** make a local commit of this file + those five JSONs onto
`feat/scorer-gaps` so every worktree inherits them (a local commit is inside the
"no push" boundary of §1.3; do not push). Alternatively, copy them into each
worktree. Do not dispatch a worktree agent until it can see them.

### Running a single pipeline phase for tier-2 verification (§3)
You may NOT run the orchestrator / full pipeline / dev server (§1.1). To exercise
a producer on one target in isolation, use the pattern the investigation used:
- `tests/support/label_corpus.py::_compile_and_attach(entry, workdir)` — compiles
  a unit through the pipeline's own Slither and attaches effects/predicate
  artifacts (the static/effects producer path).
- `services/static/contract_analysis_pipeline/core.py` — the static entrypoint.
- For resolution/effects producers, invoke the module functions in-process on a
  compiled unit or a stored artifact (MinIO via `artifacts.storage_key`), exactly
  as lanes A–D did; every on-chain read via `utils/rpc` (eRPC) with an explicit
  pinned block, never `"latest"`.

---

## 0. What this is and why the bar is what it is

These are the *data-gathering* fixes that feed a future protocol scorer. The
scorer consumer (`scorer_v3.py`, `site/src/protocolScore.js`) does **not** exist
in production form yet. Therefore:

> **The verification target is NOT "the grade changed." It is: the witness is
> now persisted in the correct three-state (proven-present / proven-absent /
> `not_determined`), replayably (inv.11/12), with fail-closed arms exercised.**

The governing rule, which is the entire point of the project:

> A value may be published as a positive fact **only when the evidence proves
> it**. Absence of a proven constraint is **not** proof that no constraint
> exists. An honest `not_determined` is a correct outcome; an invented witness
> is a regression.

A prior effort "fixed" a name-inference bug by committing a fresh one four
times. The investigation itself caught two fixes (R2, R3b) that looked general
and were not. **This is why every unit that mints a new positive fact has a
mandatory adversarial gate (§4).**

**The specific regression we CANNOT reintroduce: fail-open false positives.** A
revert, a swallowed exception, a fetch failure, a missing row, or a default
value must **never** be published as a proven fact of any polarity. A probe that
reverts yields `not_determined` — never "the gate is open" and never "the gate
is closed". This is the exact class the fail-open series and PR #161 closed
(functions defaulting to public, `require(cond, CustomError())` invisible and
read as open, an absent balance read as `$0`). Every new field here must carry a
`not_determined` state that is the one reached on revert / failure / absence, and
the adversarial gate (§4) **rejects any field whose failure or revert path
resolves to a positive or negative value instead of `not_determined`.** "Proven"
means proven; speculative, half-baked, or revert-derived is `not_determined`,
full stop.

### Source material (read as needed per unit)
- `scoring_prototype/gap_investigation/lane-A.json … lane-D.json` — the four
  investigation reports, per-gap: real? / fixable (file:line) / provable? /
  deterministic test / cost / flips-rows / small-populations / could-not-verify.
- `scoring_prototype/gap_investigation/adversarial.json` — per-gap verdict
  (UPHELD / WEAKEN / REFUTED) and, for WEAKEN, the **provable core** — the
  strictly-smaller fix that survives. **Where the lane report and the
  adversarial verdict disagree, the adversarial verdict governs.**
- `scoring_prototype/FIELDS.md` — the validated field register; §12 lists the
  upstream fixes.
- `SCORING_INVARIANTS.md` — §E (inv.16, amended) and `### B0b`. B0b governs
  over any Appendix B table row it contradicts.
- `WITNESS_INTEGRITY_LEDGER.md` — L-16 (freeze-duration unreachable branch),
  and the L-1..L-41 defect family for context.
- `git show 382d81dc` (PR #161) — the pattern every deterministic test follows.

---

## 1. Hard constraints (non-negotiable)

1. **No full-pipeline runs. No local dev server / orchestrator.** That is the
   live suite's job. You may run a **single phase in isolation on a specific
   target** — compile one unit through the pipeline's own Slither, invoke a
   static/effects/resolution producer in-process on one contract or a stored
   artifact, run a projection function on a persisted blob. You may **not** run
   the orchestrator end-to-end.
2. **eRPC (from `.env`, via `utils/rpc`) and Etherscan are allowed** for witness
   verification. **Pin an explicit block on every on-chain call — never
   `"latest"`.** Reference block: **25643300** (every investigation read is
   pinned there and reproduces).
3. **No commit or push without explicit user authorization.** No Claude
   attribution trailers.
4. **Batch pushes.** Each push triggers a preview deploy + a ~27-minute live
   suite on real credits. Land all branches, then **one** final live run.
   Verify CI only on the final state.
5. **Migration serialization.** Alembic revisions form a linear
   `down_revision` chain; two migration-bearing units authored in parallel
   worktrees WILL collide. The five migration-bearing units run as ONE linear
   chain, in this exact order (§5 Wave 2): **U4 (B1/B2) → U8 (C4) → U10A (D4) →
   U10B (D1) → U7B (D6-accept)** — each rebased on the prior's head, `down_revision`
   pointing at it. Never parallel, never branched.
6. **Worktree hygiene.** Every worktree agent must `git merge-base --is-ancestor`
   check against `main` first — the known failure mode is agents starting from a
   stale base. Only remove worktrees this session created; never `--force` over
   uncommitted work.

### Env / running tests (from CLAUDE.md)
- Services first: `docker compose up postgres minio minio-init -d`.
- Offline suite (preferred, parallel): `./run_tests_fast.sh [paths]`. It exports
  its own CI-faithful env — do **not** `source .env` or set `PSAT_LLM_STUB_DIR`
  around it.
- CI-faithful gate = the offline suite **plus** `ruff format --check` and
  `pyright`. The canonical CI file is `.github/workflows/_ci-checks.yml`.
- Pre-push gate runs under `uv run` with `pytest -p local_netguard` (the local
  fast runner skips netguard; `.venv` can drift).
- Schema drift (`UndefinedColumn`/`UndefinedTable`) → drop+recreate `psat_test`;
  the conftest reapplies migrations next run. **Drop+recreate `psat_test`
  before any offline rerun.**
- DB for investigation/verification reads: `set -a && source .env && set +a`,
  then `DATABASE_URL` → local Postgres (host port **5433**), a read-only replica
  of the PR-161 run, protocol_id=1 (etherfi). **Treat it read-only** — never
  UPDATE/DELETE.
- Artifacts: MinIO via `ARTIFACT_STORAGE_*`, keys via `artifacts.storage_key`
  (prefix `pr-161/`). **Trap:** some keys carry a stale `pr-160/` prefix — on a
  failed get, strip the leading `<bucket>/` segment and retry.
  `contract_materializations.predicate_trees_blob_key` is a separate pointer.

---

## 2. Blocker checks (Phase 0 — do first, they are cheap and gate the plan)

**Ownership:** Phase 0 is **one Opus grounding agent** that runs both ⏳ checks up
front and reports to the orchestrator BEFORE any wave starts. Its findings gate
dispatch: **Unit 6 must not be dispatched until the D2-row check passes; Unit 4
must not be dispatched until the B2 second-writer site is confirmed.** (The unit
sections cross-reference these as their own precondition, but the *measurement*
happens once, in Phase 0, not inside the units.)

- ✅ **solc 0.8.25 provisioned** (`.venv/.solc-select/artifacts/solc-0.8.25`) —
  C2's re-analysis compiles.
- ✅ **`chain_enabled` defaults to `{1}`** when `PSAT_SUPPORTED_CHAIN_IDS` is
  unset (`utils/chains.py:89,528-540`) — C2/C3 spawns queue for ethereum
  locally.
- ⏳ **Confirm the 18 real D2 receiver rows fall inside the tested synthetic
  shapes** (run the effects producer on those addresses, in isolation). Gates
  Unit 6 dispatch. Rows named in §6 Unit 6.
- ⏳ **Confirm the second balance-writer site for B2.** Lane B's garbled source
  referenced `…tion_worker.py:387`; lane B named both writers. Confirm both the
  `tvl.py` native path **and** the second writer get the
  `record_degraded(phase='balance_fetch')` trace. Grep before editing. Gates
  Unit 4 dispatch.

---

## 3. Verification model (applies to every unit)

Five tiers. A unit is "done" through tier 4; tier 5 is deferred to the final
live run.

1. **Offline unit test, PR #161 style** — the *primary* gate. Pinned inputs,
   **byte-exact** expected payload, and **every fail-closed arm exercised**
   (absent-descriptor, blockless-operand, head≠sentinel, "latest"-path,
   unverified-source, raise-on-fetch). Prefer extending the existing test family
   named per unit.
2. **In-process single-phase run on a real target** — proves the *production
   path*, not a hand-built input (compile a real unit / read a stored artifact /
   run the real projection fn). Never the orchestrator.
3. **Pinned on-chain re-verification** — re-read the witness via `utils/rpc`
   (eRPC) or Etherscan at block 25643300 (or the stated height), byte-exact.
4. **Adversarial review** (§4).
5. **"Field lands on real rows across a full run"** — **deferred to the live
   suite**, batched, one run. Never attempted locally.

---

## 4. Adversarial gate

Panel scope is defined by a **rule**, not an enumeration (an enumeration drifts
as units change). A unit gets a **full dedicated adversarial reviewer** if it
does ANY of: publishes a new positive field; **withdraws or licenses an earned
negative**; or changes a published fact. That set is: **A1, A2, A3, B1/B2 (U4),
C1, C2/C3 (U9), C4, D1, D2, D4 (U10A), D6-reject (U7A), D6-accept (U7B)** — every
unit except the four below. Note explicitly: **U4 (B2) and U10A (D4) are the
plan's two flagged gap-wideners** (U4 can flip holdings semantics for the 43
reach rows via `selection.py`; U10A licenses/withdraws earned negatives) — they
are the HIGHEST-priority panels, not exceptions.

Only these get a **single reviewer note** instead of a panel, because they mint
no positive fact: **U5 (D5, projection line), D3 (2-row mechanical propagation —
but note U6 pairs D2+D3, so U6 gets the full panel for D2), B3/B5's label (U3 —
string change + a plumbing pin), and B4 (test-only, no code).** When in doubt,
run the full panel. §5's "every unit gets tier-4 review" is the binding
statement; this paragraph only says which get a *panel* vs a *note*.

The reviewer's **only** job: find any newly-published field that is an unproven
positive. Auto-refute on any of these shapes:
- name / substring inference of any kind (inv.2) — including "the variable is
  called X", and including name-suffix classification;
- a default or fallback standing in for a witness;
- absence-as-witness without **(i)** proven coverage of the recording surface
  (for event absence: *every* topic that can write the variable has a warm
  cursor) **and (ii)** the observation block;
- a mutable now-fact (single-block observation) published as an invariant
  without its block and its counterfactual (inv.10);
- `tx.from` as "who authorised" a Safe/timelock action;
- inferring `expected_version` from a latch value;
- calibrating any rule/weight/threshold on a population **< ~5 rows** (B14);
- a strength gate published separately from (or after) its payload;
- a fix that closes one gap by **widening another** (check the blast radius on
  neighbouring rows — e.g. "always insert a balance row" changing absent-row
  semantics for consumers that read absence as `not_determined`).

**The reviewer verifies; it does not trust. Two obligations that make this a
real gate rather than a rubber stamp:**
- **Re-measure the load-bearing witnesses independently.** Do NOT accept the
  implementer's transcript for any newly-published positive — re-run the pinned
  on-chain read / DB query yourself. This is exactly how the investigation's own
  adversarial lane caught the false "9 Safes" claim (it re-measured and found 19,
  one module-bearing). A witness you did not reproduce is `not_determined` to you.
- **Audit the test's pinned expectations, not just that the suite is green.** A
  byte-exact test that pins an over-claiming expected value passes while being
  wrong — green proves the code matches the test, not that the test encodes a
  proven fact. Six over-claim shapes once survived a green suite in this codebase
  (see `project_effects_adversarial_review_findings` and the L-family in
  `WITNESS_INTEGRITY_LEDGER.md`). Read every pinned expected value against the
  reject-list.

Verdict per new field: **UPHELD** / **REFUTED** / **WEAKEN** (state the
strictly-smaller provable core).

**Model:** the adversarial reviewer runs on **Fable, high effort** — this is the
major verification and the highest-stakes judgment in the whole plan.

**Review loop (this is what happens when the reviewer has feedback):**

1. Round 1 — implementer (Opus) produces the change + tests on the unit's
   worktree branch. Orchestrator runs verification tiers 1–3. Reviewer (Fable)
   receives the diff, the list of newly-published fields, and the reject-list,
   and returns a verdict per field.
2. **All UPHELD → unit done.** Any WEAKEN/REFUTED → the orchestrator sends the
   reviewer's stated provable-core back to the **same implementer agent,
   resumed** (it keeps its context, so it revises rather than rebuilds).
   Implementer revises → tiers 1–3 re-run → the **same reviewer, resumed** (it
   keeps its objection, so it checks specifically whether that objection was
   met; a genuinely new objection counts as the next round).
3. **Cap: 3 review rounds.** On exhaustion the **orchestrator adjudicates — not
   the user** (per the review-loop-escalation rule).

**The loop cannot ship an unproven positive.** The reject-list is objective
(name / default / absence / mutable-now-fact / tx.from / latch-inference /
sub-5-row calibration / detached strength gate / gap-widening), so a reviewer's
objection is falsifiable — the implementer either removes the banned shape or it
survives. On deadlock the safe default is **always to shrink to the provable
core and publish the contested remainder as `not_determined`** — never to ship
the contested positive. So exhaustion fails *toward* an honest
`not_determined` (acceptable, possibly over-conservative), never toward a
regression. Adjudication options for the orchestrator: (a) accept the smaller
provable core and mark the rest `not_determined`; (b) if implementer and
reviewer disagree on a matter of fact, resolve it by direct measurement
(DB / pinned chain read); (c) park the unit as "blocked — genuine scope
question" and surface it at the next checkpoint. A real scope change still goes
to the user; a witness-strength disagreement does not.

---

## 5. Orchestration strategy

Units are partitioned **by file-ownership**, not by gap, so parallel worktree
agents never edit the same file. Within a unit the work is serial. Order follows
the ranked "fix before the scorer" list.

**Models (no Sonnet anywhere):** orchestrator = **Opus**; every implementer and
the Phase-0 grounding agent = **Opus**; every adversarial reviewer (§4) and the
final integration gate = **Fable, high effort** (the major-verification roles).
Agents default to the session model unless a call sets `model:` explicitly — set
it explicitly for every agent so the split is deterministic.

**All 13 units are placed below. Waves run one-at-a-time (a wave completes —
implement + verify + adversarial — before the next starts). Within a wave, units
run concurrently in worktrees ONLY if their file sets are disjoint; the shared-file
notes below say where that fails.**

- **Wave 1 (no migration):**
  Unit 1 `one_shot_probe.py`+`one_shot.py` · Unit 3 `anvil.py`+`config.py`+`claims_bridge.py`
  · Unit 5 `flows.py` · Unit 7A `tracking.py`+`summaries.py`+`predicate_evaluator.py` (D6-reject/C1)
  · **Unit B4** (test-only, new `tests/test_reach_indeterminate_branch.py` — disjoint from all, runs anywhere; put it here).
- **Wave 2 (migration chain — STRICTLY SEQUENTIAL, one linear `down_revision`
  chain; never parallelize):**
  **Unit 4 (B1/B2) → Unit 8 (C4) → Unit 10A (D4) → Unit 10B (D1) → Unit 7B
  (D6-accept).** Each unit's migration sets `down_revision` to the prior unit's
  revision. This order satisfies every dependency: 10B (D1) reuses U4's
  `contract_balances.block_number`; 7B (D6-accept) requires U10A's
  `first_indexed_block`. Do not branch the tail — it is a single line ending at
  7B.
- **Wave 3 (re-analysis-heavy / spawn):** Unit 6 (D2/D3, `effects.py`+`summaries.py`)
  · Unit 9 (C2/C3 policy spawn + jobs). Unit 6 waits on the Phase-0 D2-row check.
- **Unit 2 (A2/A3)** runs solo (or only with units touching neither
  `predicate_evaluator.py` nor `capabilities.py`).

**Shared-file collisions (the `never edit the same file` basis fails here — the
listed units must be SEQUENCED, never concurrent):**
- `predicate_evaluator.py` — **Unit 2** (A2 strip-arms / A3 whitelist ~:971-998,
  :775) and **Unit 7A** (D6 canonical-slot path ~:1030-1046). Already sequenced:
  7A is Wave 1, Unit 2 is solo after.
- `summaries.py` — **Unit 7A** (D6-reject, `_role_names_from_tree`) and **Unit 6**
  (D2, `_resolve_cast_head` ~:457-486, ~:536). 7A is Wave 1, Unit 6 is Wave 3, so
  they are already sequential — but do NOT reorder them into the same wave, and
  when Unit 6 branches it must be off the branch that already contains 7A's
  `summaries.py` edit (or rebase).

Per unit, the orchestrator: dispatches a worktree implementer with the unit
section below verbatim + §0–§4 context → runs tiers 1–3 → dispatches the
adversarial reviewer (tier 4) → on UPHELD, marks done; on WEAKEN/REFUTED, sends
the provable core back (≤3 rounds) → adjudicates. Trust the implementer's
reported pass counts; don't re-run the full suite to re-check (drop+recreate
`psat_test` if you do rerun).

---

## 6. The units

Each unit lists: **gaps · files · the provable witness and its three-state · the
DO-NOT list · deterministic test · migration? · phase-to-run · flips-rows ·
small-pop flags · dependencies.** File:line anchors are from the reports; the
implementer must re-verify each before relying on it (the transmission was
partly garbled).

---

### Unit 1 — one-shot latch descriptor (A1)

**Files:** `services/resolution/one_shot_probe.py` (write point
`annotate_capability_one_shot` ~:422-459, currently discards `result.transcript`);
`LatchReadResult` dataclass ~:70-75; producer
`services/static/contract_analysis_pipeline/one_shot.py` (`_latch_location`
~:214-298; guard ~:540/:584/:611; `_reinitializer_literal` ~:384-400;
`INITIALIZER_MODIFIERS` name set ~:64). Consumers (read-only awareness):
`site/src/oneShot.js` → `site/src/protocolScore.js:239` (`isInertOneShot`);
`site/src/surface/layout/guardSummary.js:116-121`.

**Witness (persist what the producer already computed — do not re-derive):**
the `transcript` already holds probe block, slot, raw slot word, standard —
persist verbatim. `guard{operator,constant}`, `byte_offset`, `size_bytes`,
`value_type`, `expected_version`, `role`, `variable` live on the local `chosen`
(~:340-349) and must be stashed onto the result object (add a field or widen the
dataclass). Publish `latch_basis` as a **four-valued discriminator**
`{sentinel, version_ge, value_gt_zero, guard}` + `not_determined`. Publish
`expected_version` **only** carrying `expected_version_basis:
"oz_initializable_modifier_literal"` (it comes from a modifier NAME set — a
closed standard-anchored match, admissible with the residual stated). Keys
**absent** (never null, never defaulted) where the producer had nothing.

**Three-state / consumer obligation:** an absent `latch_witness` reads as the
**weakest** branch. `consumed` is a **mutable now-fact** — `latch_target` is
`db_linked_proxy` on 39/39, so the inertness credit must publish as "consumed at
block `<probe_block>`; re-openable by the upgrade authority of `<proxy>`", not as
a static protection constant (`protocolScore.js:239` currently over-credits at
0.95 — flag for the eventual consumer, do not fix JS here unless in scope).

**DO NOT:** infer `expected_version` from `latch_value`. Publish any strength
**ordering** over the four bases (sentinel & value_gt_zero fired on 0 rows,
guard on 6/0-at-protocol-1 — B14 bars ranking them). Present the modifier literal
as compiler-forced.

**Test** (`tests/test_one_shot_probe.py` FakeRpc harness + new
`tests/test_one_shot_latch_witness.py`): pinned-wire replay of the 3 realized
shapes (Lido `unstructured_slot_latch` guard `eq 0`, an ERC-7201 `version_ge`,
the packed FiatToken byte) asserting the byte-exact condition dict; fail-closed
arm: absent descriptor → `latch_state` weakest branch, `latch_value` key
**absent** (confirmed constructible by R5b).

**Migration:** none (jsonb `effective_functions.conditions`). **RPC:** none (reads
already happen). **Phase-to-run:** resolution one-shot probe, in isolation, for
the 6 no-descriptor rows.

**Flips:** no verdict flips (32/32 replay, 9/9 chain agreement; 0/39 are
sentinel/value_gt_zero). Only strength metadata added.

**Small-pop:** guard 6 rows (0 protocol-1); no-descriptor 6 rows (protocol-1 ef
479, 480, 1456, 2745 — need re-analysis, publish `not_determined` until then);
Aragon-block-number type 1 row (ef 2120); bool type 1 row (ef 786). None may
calibrate.

---

### Unit 2 — exact-empty caller sets + accessor basis (A2, A3)

**Files:** `services/resolution/capabilities.py` (strip sites `_intersect_finite`
~:507, `_union_finite` ~:527, `_intersect_finite_blacklist` ~:543, **and both
negate arms ~:416/:428**); `services/resolution/predicate_evaluator.py`
(exact-empty at ~:783; accessor whitelist ~:971-998; `_AUTHORITY_GETTER_BASENAMES`
~:775; live read at ~:843). Consumer flip: `services/aggregations/analysis_detail.py`
~:437 (`capability_currency`).

**A2 witness (event-fold cursor height, already computed, stop dropping it):**
propagate `last_indexed_block` and `empty_reason` through the four strip sites
and both negate arms, **only when EVERY finite operand carries a height**
(fail-closed); `empty_reason` only on **inherited** emptiness. At `:783`, give the
live `_live_authority_result` a block + selector + contract trace and
`empty_reason='owner_read_zero'`, emitting `observed_at_block` **only when the
eth_call was pinned** (the read falls back to `"latest"` when block is None →
`not_determined` on that path). The burn-address branch (`result_addr == ""`)
must not share the zero shape.

**A2 three-state:** for an exact-**empty** result, the propagated height licenses
"empty at block MIN". For a **non-empty** exact set at heterogeneous operand
heights, publish `exact_as_of: not_determined` (MIN is a staleness floor, not an
as-of). Consumer gate for the earned-negative credit requires **trace[0].step
present AND an observation block AND a non-defaulted `empty_reason`**.

**A2 DO-NOT:** `min-of-present` when any operand is blockless (that is the exact
arm the fail-closed rule forbids). Emit `observed_at_block` on the `"latest"`
path. Keep the credit for **ef 192** — its `empty_reason='empty_by_design'` is a
**default argument value** in `_live_resolve_authority_slot(...,
zero_empty_reason="empty_by_design")`, not a witness; withdraw it alongside ef
1613 (protocol-1), 797, 1151.

**A2 REALITY CHECK (R2 — do not chase a phantom):** **0 of the 261 protocol-1
solmate rows will gain a block.** Each is `OR(canCall event-fold operand,
owner() live-getter operand)`, and the live-getter operand is blockless by
construction, so the fail-closed rule yields `None` on 261/261. A2's realized
benefit is on the **`enumerable_role_store` folds** (241 rows already carry a
block; 0 overlap the 261). **`capability_currency` will NOT flip on the 261** —
lane A's FLIPS claim is corrected by R2. Verify your yield against the
enumerable-role-store rows, not the solmate rows.

**A3 witness (re-publication of a computed fact):** hoist the basis to
`details.authority_basis` at top level beside `membership_quality`/`confidence`,
split into `{abi_auto_getter, standard_namespaced_accessor,
deunderscore_convention, slot_name_keyword}`; absent = `not_determined` =
weakest. Rank **only** `abi_auto_getter` above the two name-matched arms; leave
`standard_namespaced_accessor` and `deunderscore_convention` **mutually
unordered** (shared `accessor_name_matched` tier) with `accessor_slot_agreement:
not_determined` on both; cite the co-witness `live_getter_resolution` (33/33).

**A3 DO-NOT:** the differential storage-slot comparison as the primary fix
(unrunnable on 2 of 3 addresses, non-identifying on the third — rejected). Any
finer ordering than "abi_auto_getter > the rest" as a *measured* fact (it is a
model choice, published with the model version; B14 bars weight on 2 principals /
3 addresses). **R4 fixture correction:** the 6 CumulativeMerkleDrop rows fire the
**OZ-v5 namespaced arm** (`_oz_v5_namespaced_authority_selector` → `0x8da5cb5b`
via `_getAccessControlDefaultAdminRulesStorage`), not de-underscore; the ERC-7201
slot for that accessor is **`0xeef3dac4…8400`** (NOT the Initializable slot
`0xf0c57e16…` that lane A's test spec wrongly used).

**Test:** A2 — pinned combinator table through the real `intersect`/`union`/
`negate`+`capability_to_dict`: leaf height preserved; `intersect(fold@b1,
fold@b2)` → MIN; `intersect(fold, blockless_live_getter_set)` → `last_indexed_block`
**absent** (the fail-closed arm); same three arms for `union` and both negate
arms; plus an `empty_reason` default-vs-witness case. A3 — operand with
`callee_signature="_governor()"` reverting while `governor()` answers →
`authority_basis="deunderscore_convention"` at top level; a public `governor` →
`abi_auto_getter`; the OZ-v5 accessor → `standard_namespaced_accessor` with slot
`0xeef3dac4…8400`.

**Migration:** none (jsonb). **RPC:** none for the combinator half.
**Phase-to-run:** resolution capability build on a stored artifact.

**Flips:** A2 flips `capability_currency` in the **honest** direction for the
enumerable-role-store rows (not the 261 solmate). A3 flips nothing; a later
consumer basis-rank would demote 27+6 rows (gate/cite/three-state only).

**Small-pop:** A3 = 33 rows / 2 principals / 3 addresses (B14 — no weight);
`slot_name_keyword` 0 rows; A2 zero-trace empties 4 corpus / 2 protocol-1;
`empty_reason` present on 1 of 52.

---

### Unit 3 — fork block identity (B3) + freeze-duration label (B5)

**Files:** `services/effects/anvil.py` (~:676 `_build_anvil_cmd`);
`services/effects/config.py` (~:131-133 vocab); `services/effects/claims_bridge.py`
(~:198-201 semantics); the inspector string that reads "indefinite latch".

**B3 witness (deterministic pinned height, already a local int):** pass
`--fork-block-number str(ctx.block)` at `anvil.py:676`; publish
`witness.block_number` + `witness.block_source ∈ {invocation_pin, job_pin,
run_pin}` — tier-1 from the preflight pin, **tier-2 only where the fork was
actually pinned**. **Never emit 0** (0 is the failure sentinel = genesis). The 78
tier-2 rows' historical heights are unrecoverable → `not_determined`; nothing
back-filled. **FIELDS.md §7 correction:** `witness.block_number` is **0/274, key
absent** — not "304/304".

**B3 DO-NOT:** add the block to `uq_effect_verdicts_identity` without a
"latest-height-wins" selection rule (upsert→append hazard; also collides with
B5's in-place-upsert assumption). A per-run pin needs a new `jobs` column and is
a separate decision — do not smuggle it in.

**B5 — REFUTED as a severity reducer. Label only, zero severity effect.** Do
**not** publish `auto_expiry=True` or `duration_bound_source='fork_observed_recovery'`.
`setPauseUntilDuration(uint256)` dispatches on all 4 freeze contracts (window is
mutable storage) and re-pause is unbounded, so the effective freeze is indefinite
regardless of any per-call ceiling — publishing a bound would lower severity on
$4.05B from a 4-row population (B14) and contradict B0b/R1. The only change: the
inspector's "indefinite latch (no self-recovery bound)" string becomes **"window
not determined"** (needs no new witness). Duration contributes **zero** to
severity in either direction (B0b/R12). L-16 already proved the static
`_duration_from_trees` positive branch is unreachable.

**Test:** `tests/test_effects_block_identity.py` — exact anvil argv list compare
(so a future edit dropping the pin fails); block seam raises → `simulate_supported
False`, no tier-1 transcript, tier-2 verdict height `not_determined` never 0. B5
— assert the inspector string is "window not determined" and that **no**
`auto_expiry`/`duration_bound_source` positive is emitted on the 4 freeze rows.

**Migration:** none. **Flips:** no verdict values; provenance meaning of 78 tier-2
rows incl. freeze verdicts `effect_verdicts.id` 137/149/173/219.

**Small-pop:** 4 freeze rows, 7 two-block jobs — B14, argued from the code
contract.

---

### Unit 4 — balance provenance (B1, B2) — MIGRATION, multi-consumer

**Files:** `services/monitoring/tvl.py` (destructive DELETE ~:235; insert gated
`eth_wei>0` ~:238; swallow ~:224-227); the **second balance writer** (confirm in
Phase 0); readers to migrate in the SAME commit: `services/effects/selection.py`
(`_asset_holdings_by_deployment` ~:422-448, `_token_holdings_by_contract`),
`services/aggregations/company_overview.py`, `workers/policy_worker.py`, the three
`scoring_prototype/` scorers.

**B1 witness:** `observed_address` captured verbatim at both write points
(provable now — local variable). `block_number` populated **only on the pinned
Multicall3 path** (`utils/rpc.multicall3_aggregate3(block_tag=hex(block))` +
`Multicall3.getEthBalance`); the Etherscan path stays permanently `block_number
NULL = not_determined`. **Price gets its own `price_observed_at: not_determined`**
— `usd_value`/`price_usd` must NEVER inherit the quantity's block (price has no
height and diverges up to ~21% for the same asset within one recorded instant).
`asset_set_completeness ∈ {at_page_cap, not_determined}` from the raw page length
— no `complete` value exists.

**B1 delivery:** insert-only + a `latest` view, **migrating every reader in the
same commit** (a NULL-block row is not unique-constrained, so a naive reader would
sum across heights). Existing 1,617 rows are permanently `block_number NULL` (no
backfill possible — the height was never observed).

**B2 witness (three-state, do NOT default absence to $0):** `native_status ∈
{proven_zero (pinned path only), proven_nonzero, fetch_failed}` and
`asset_set_status ∈ {returned_assets, returned_empty, fetch_failed, at_page_cap}`.
Add `record_degraded(phase='balance_fetch')` to the `tvl.py` native path so both
writers leave the same trace. A pinned `eth_getBalance == 0x0` is a proven zero;
an Etherscan zero is `not_determined`.

**B2 CRITICAL DO-NOT (the delivery trap):** do **not** deliver the three-state by
inserting rows into `contract_balances` — `selection.py:422-448`
(`_asset_holdings_by_deployment`) has **no positive-balance filter** and treats a
row's mere **existence** as "this deployment holds this asset", and that set feeds
the 43 reach rows. Either (i) put the discriminator in a **separate
fetch-provenance plane** whose rows are explicitly NOT holdings, or (ii) change
`_asset_holdings_by_deployment` + `_token_holdings_by_contract` in the SAME commit
to require a positive witnessed balance, and re-measure the 43 reach rows before
and after.

**Test:** `tests/test_contract_balance_provenance.py` — stub `multicall3_aggregate3`
→ byte-exact row (block_number, observed_address, raw_balance); FAIL-CLOSED: reader
raises → **no** row deleted, **no** row written, pre-existing block untouched;
entity test: request `proxy_address` ≠ contract address → correct
`observed_address`. `tests/test_native_balance_three_state.py` — proven_zero (pinned)
vs not_determined (Etherscan); raise → `fetch_failed` + `record_degraded` from
**both** writers; ERC-20 fetch raise → existing rows NOT deleted.

**Migration:** yes — 3 nullable cols (block_number, observed_address, +
provenance), drop the destructive DELETE, add the `latest` view; +2 nullable
varchar for B2's statuses. **RPC:** ~6 Multicall3 calls (571 ERC-20 pairs, chunk
100) + ~1 for 60 native, per cycle — cheaper than today's sequential path.

**Flips:** no USD figure moves for the 16 impl-keyed sets (scorer already re-keys
impl→proxy, MAX per (runtime,asset)). Two unrepairable rows flip: `contracts.id`
**544** AuctionManager, **563** StakingManager — publish `observed_address`, withdraw
their USD as an M7/16a defect (do not re-key by guessing).

**Small-pop:** the 2 unrepairable rows + 3 of 5 proxy/impl double-count pairs
($0.00) — B14, decide each on its own witness.

**Dependency:** migration head shared with Unit 10B (D1's block column) — sequence.

---

### Unit 5 — router_ops projection (D5) — trivial

**Files:** `services/static/claims/matchers/flows.py` (one guarded projection
line) + golden regen. Value already computed (`_bare_callee_name`,
`services/static/contract_analysis_pipeline/effects.py` ~:410-418) and consumed
in-process at `services/static/claims/matchers/_facts.py` ~:529.

**Witness:** project `router_ops` = `{selector = keccak4 of the callee's
canonical signature, callee = the bare AST function name}`. `router_ops[].callee`
is an **intra-unit AST identity — never an on-chain target** (the interface-typed
case makes the declared signature hash differently, which is why the name is
carried). `if f.get("router_ops")` collapses missing and `[]` into "key absent",
preserving the existing fail-closed meaning (a router leaf blocks; the mandatory
gate falls to `not_determined`) — no consumer can read `[]` as "no router".

**Test:** extend `tests/test_claims_param_constraints.py` family
(`test_a_routed_flows_recorded_router_op_is_transparent` et al.) + a projection
test asserting the byte-exact witness flow entry.

**Migration:** none. **Phase-to-run:** claims stage on a stored artifact to
backfill. **Flips:** 41 protocol-1 rows gain the key; no meaning changes.
**Adversarial:** single note (no new positive fact — projection of an existing
one). **Small-pop:** none (73/73 producer, 41/41 claims).

---

### Unit 6 — flow asset identity (D2) + setter identity (D3) — `effects.py`

**Phase-0 prerequisite:** confirm the 18 real D2 receiver rows fall inside the
tested synthetic shapes (run the effects producer on those addresses in
isolation). Rows: `effective_functions.id` 423, 472, 1532, 1551, 1565, 1649,
2194, 2278, 2281, 2288, 2310, 2568 (+ the remainder listed in lane-D.json). Do
not implement until this passes.

**Files:** `services/static/contract_analysis_pipeline/effects.py` (receiver read
~:504; `_UnitCtx.setters` type change `set[str]` → `dict[str, list[str]]` at
~:942/:957/:1190/:2950); `services/static/contract_analysis_pipeline/summaries.py`
(`_resolve_cast_head` ~:457-486; `function.parameters` id pattern ~:536).

**D2 witness (two disjoint provable paths, neither is name resolution):**
(1) **7 parameter receivers** → `asset_identity = caller_named, param_index = n`
(a positive AST fact that DEMOTES pricing — direction-safe; must FAIL FIELDS §3's
`token_identity` precondition). (2) **immutable/public state-var receivers** →
resolve `asset_address` by pinned `eth_call` of the compiler-minted auto-getter
`keccak4(name+"()")`, **but** label `mutability: immutable_in_implementation` and
pair every resolved address with `observed_at_block` + `asset_identity_invariant:
not_determined` (or `redirectable_by_upgrade_authority`) wherever
`deployment_address` is a proxy (7 of the 10 immutable rows).

**D2 R3 corrections (both load-bearing):**
- **R3a:** `binding` MUST be `isinstance(resolved, StateVariable)` — **NOT
  `visibility`.** A parameter and an internal state var both read
  `visibility=='internal'`, so visibility is a silent false-positive
  discriminator. `isinstance(StateVariable)` is already used at `effects.py`
  ~:1014-1016. Guard the `SolidityVariable` case (it raises `AttributeError`).
  `param_index` is **not** derivable from visibility; the `{id(p) for p in
  function.parameters}` pattern (summaries.py:536) works but `_build_sink_records`'
  transitive walk means a nested helper's formal ≠ an ABI slot — verify per row.
- **R3b:** the strictly-stronger "read the inlined value out of `eth_getCode` at
  `immutableReferences` offsets" arm is **forbidden.** A follow-up
  residual-verification pass found `immutableReferences` is dropped by crytic and
  absent from all stored blobs (0/6140 in the local replica); crytic's
  `hardhat_like_parsing` copies only abi/bytecodes/srcmaps/natspec/ast, and the
  build dir is `rmtree`'d. **Build only the auto-getter arm.** Do not propose the
  offset read. (Note: the 0/6140 finding is from that residual pass, not from
  `lane-D.json`/`adversarial.json`, which left it a could-not-verify — see §9.
  The arm is forbidden regardless, so the fix does not depend on re-confirming
  it; but re-confirm before ever building the offset arm if the compile toolchain
  changes.)

**D3 witness:** `target_variable` (AST identifier off the resolved operand) +
`target_writer_signatures` (`all_state_variables_written`) **explicitly scoped to
the writers WITHIN the analysed compilation unit**; keep `writer_scan_complete`
as the assembly/indeterminate gate it already is; **add `writer_surface_closed =
not_determined` whenever `deployment_address` is a proxy or the unit is one of
several implementations** — both D3 rows are (ef 423 is a secondary impl of
`contracts.id` 461; ef 2748's impl is `0x89e45081`). The derived claim is
"redirectable **at least by** these writers' principals" — a floor, never the
closed set.

**DO-NOT:** resolve the asset or the setter **by variable name** (inv.2). Publish
`immutable` as a runtime invariant behind a proxy. Publish `writer_surface_closed:
true` on a proxied/secondary-impl row.

**Test:** golden extension adding `receiver` to the pinned witness key tuple
(`tests/support/label_corpus.py` ~:391, beside `router_ops`) so the corpus stops
being blind to it; 3 synthetic receivers (parameter / public-immutable / internal)
asserting byte-exact `binding`/`param_index`/`mutability`/`visibility`; D3 positive
+ assembly-sstore fail-closed sibling asserting the byte-exact projected entry.

**Migration:** none (jsonb). **RPC:** ~11 eth_call (Multicall3-batchable).
**Phase-to-run:** static stage on the target units. **Flips:** 18 rows (D2) + 2
rows (D3) gain a pricing/redirect precondition; no existing value inverts.

**Small-pop:** D2 `local` bucket 1 row (ef 2310), `constant` 0 rows; D3 = 2 rows —
B14, mechanical propagation only.

---

### Unit 7A — role definitions reject-side + Safe module/guard probes (D6-reject, C1)

**Files (D6-reject):** `services/static/contract_analysis_pipeline/summaries.py`
— the fix goes in the **leaf-admission** function `_role_names_from_tree`
(~:67-95; the bytes32-constant admission logic to gate is ~:79-89, per the
governing adversarial verdict "summaries.py:79-89"), **NOT** its wrapper
`_role_names_from_predicate_trees` (~:98-110, which only iterates trees and calls
the leaf function); **second use-site to fix**
`services/resolution/predicate_evaluator.py` `_canonical_authority_selector_for_slot`
~:1030-1046. **Do NOT touch** the name-suffix guard `_is_storage_layout_constant`
(`services/static/contract_analysis_pipeline/tracking.py:46-69) as the fix — R5
proves it misclassifies in **both** directions.

**Files (C1):** `services/resolution/tracking.py` (add 2 `eth_getStorageAt` at
~:463 fired AFTER `_classify_uncached_batched` returns `kind=='safe'` ~:677-687 —
**NOT** into `_CLASSIFY_PROBE_SIGS` ~:556-563, whose builders cannot pass
arguments); monitor half `services/monitoring/polling_plan.py` ~:179-190
(`_VENDORED_CONTRACT_TYPE_ENTRIES['safe']` — `kind:'storage_slot'` already
implemented at `services/monitoring/unified_watcher.py` ~:1401-1405);
`services/monitoring/event_topics.py` ~:40-52 / :73-89 / :151 (add
EnabledModule/DisabledModule/ChangedGuard topics + enroll the Safe addresses).

**D6-reject witness (structural — R1-verified 19/19 + 209-blob corpus sweep):**
accept a `bytes32`-constant role name **only** from a leaf where
`kind=='membership'` **AND** `set_descriptor.kind=='mapping_membership'` **AND**
the operand's `member_path` is empty. Delete `role_definitions` ids **1**
(AccessControlDefaultAdminRulesStorageLocation) and **19**
(OwnableStorageLocation).

**D6-reject DO-NOT (R1):** gate on `storage_var=='_roles'` or on
`enumeration_hint` presence — that drops **5 real Lido roles** (FINALIZE /
MANAGE_TOKEN_URI / ORACLE / PAUSE / RESUME, contract 599). Only the 3-part
conjunction is safe. **Coverage caveat:** 50 role-keyed gates carry the role as a
`view_call` (30) or `parameter` (20) operand and never reach `role_definitions` →
publish `not_determined`, never "no roles".

**C1 witness (on-chain, two agreeing witnesses):** from the 2-storage-read
classifier publish `modules_head` (raw word) and derive only the PROVEN-EMPTY
determination — **head == sentinel ⇒ `module_set: []`** (basis
`storage_linked_list_terminated`, at `probe_block`); **head != sentinel ⇒
`module_set: not_determined` + `protection_is_upper_bound: true`** + the head
address cited. Publish an enumerated `modules` array **only** where the list was
walked to the sentinel or a paginated `eth_call` returned `next == sentinel`.
Guard three-state: `proven_address` / `proven_zero` (v1.3.0+1.4.1) /
`feature_absent` (v1.1.1) / `not_determined`. Version + `probe_block` mandatory.
"no module ever enabled" stays `not_determined` absent a warm EnabledModule cursor
from creation.

Verified slot preimages (recompute in the test, do not trust memory):
`keccak256(abi.encode(address(0x1), uint256(1)))` = `0xcc69885f…792f` (modules
sentinel word); `keccak256("guard_manager.guard.address")` = `0x4a204f62…34c8`
(guard); `keccak256("module_manager.module_guard.address")` = `0xb104e0b9…9947`.

**C1 DO-NOT:** publish a `modules` array from the head word alone (a two-module
Safe would publish a one-element list as enumerated — the R5-refuted over-claim).

**FIELDS.md:84 / B0b R1-caveat correction:** there are **19** Safe principals, not
9, and one is module-bearing (`0x21f73d42…`, module `0x2e1b5a40…`
"ConfirmedTransactionModule"), so k/n is an upper bound for that Safe. Guard slot
zero on 19/19.

**Test (D6):** `_role_names_from_predicate_trees` on the two REAL measured role
leaves → `{"PAUSER_ROLE"}` etc.; the two REAL slot-constant leaves → `set()`; **plus
the two R5 hostile fixtures**: a genuine role constant whose name ends in a banned
suffix (structural rule keeps it, suffix rule wrongly drops it) and an ERC-7201
slot with an innocent name (structural rule drops it, suffix rule wrongly keeps
it). **Test (C1):** byte-exact `details` dict per branch — module-free 1.4.1
(head=sentinel → `[]`, guard `proven_zero`); module-bearing 1.1.1 (pin the real
word `0x…2e1b5a40…` → `modules_head` set, `module_set: not_determined`,
`protection_is_upper_bound: true`, guard `feature_absent`).

**Migration:** none for either (all jsonb: `role_definitions` delete is data;
C1 writes `function_principals.details` / `control_graph_nodes.details` /
`monitoring_config`). **RPC:** +2 `eth_getStorageAt` per classified Safe (~38) +
optional +1 VERSION() each. **Phase-to-run:** static (D6) / resolution classify
(C1) in isolation.

**Flips:** D6 deletes `role_definitions` ids 1, 19 (no reader today — grep-verify
`workers/`, `scripts/`, chat schemas too, which R6/lane-D did not exhaust). C1
none in scored output (the module Safe is protocol NULL).

**Small-pop:** D6 mis-parse 2 rows, 3 role-event emitters, 1-address
OPERATING_ADMIN set; C1 module-bearing 1 Safe / reach 4 rows (protocol NULL) —
B14, none may calibrate. The 5 Lido role names are **single-witness** (leaf shape
only; no corroborating fold — those addresses have no cursor).

---

### Unit 7B — role holder plane (D6-accept) — MIGRATION, depends on Unit 10A

**Deferred until Unit 10A (D4) lands** — the honest lower bound needs D4(a)'s
`first_indexed_block` and D4(c)'s per-window completeness.

**Witness:** a `(chain_id, registry_address, role_hash)` plane; `holders` as a
**proven LOWER BOUND** — each member independently confirmed by a pinned
`hasRole(bytes32,address)` read cited with its block; `holder_set_exhaustive:
not_determined` until D4(a)+(c) land; `as_of_block` + both cursor bounds mandatory
(lower bound `not_determined` today); `role_name` emitted **only** where
`keccak(name)==role_hash` (or the AccessControl `0x00` literal), else key absent
with `role_name_basis: not_determined`. A cold cursor on either topic ⇒ `holders:
null` / `coverage: partial`, never an empty set. `TIMELOCK_ADMIN_ROLE` stays
CONFIDENCE (unreplayable from stored inputs).

**DO-NOT:** publish `holders` as an exhaustive set (absence-as-witness without
proven recording-surface coverage). Attach `role_name` by keccak-mismatch.

**Migration:** yes (the role-hash plane). **Small-pop:** 3 emitters, 1-address
OPERATING_ADMIN, 1 TIMELOCK_ADMIN grant — B14.

---

### Unit 8 — upgrade executor fold (C4) — MIGRATION

**Files:** `services/discovery/upgrade_history.py` (`UpgradeEvent` constructor
~:592-606 — no executor col, no receipt in scope; `parse_upgrade_log` ~:114).

**Witness (per distinct tx_hash):** `is_deployment` = `receipt.to == null AND
receipt.contractAddress == proxy_address` (airtight); `governance_action_id =
tx_hash` (the only structural fix for the 19× fanout); `executor_kind ∈
{timelock_routed, safe_direct, not_determined}` gated on the emitter being
**independently classified** (an unclassified `ExecutionSuccess` emitter ⇒
`not_determined`); `receipt_log_set_complete_for_tx: true` published as the
**stated basis** for the marker-absence reasoning; where `receipt.to == proxy`,
publish the narrower `top_level_msg_sender: <tx.from>`.

**DO-NOT (C4 reject-list core):** publish `authorising_eoa` from `tx.from` —
**always `not_determined`** (6 different relayers measured for one Safe;
`tx.from` names the submitter, never the signer set), including the 4 one-hop
txs. Publish `timelock_is_decoy` from absence of observed bypass — keep
`not_determined` on all 24 proxies; publish only the positive
`direct_upgrade_witnessed_at_block: B`.

**Test:** `tests/test_upgrade_executor_fold.py` with pinned receipt fixtures from
the real measured txs: the 19-event tx → one `governance_action_id` (assert the
aggregate counts **1** action, not 19); a `safe_direct` tx → `authorising_eoa ==
not_determined` **even though** `receipt.from` is populated; a deployment tx →
`is_deployment True`.

**Migration:** yes — prefer a `upgrade_transactions` table keyed `(chain_id,
tx_hash)` with `upgrade_events` referencing it (the only shape that fixes the
double-count structurally), or 3–4 cols on `upgrade_events`. **RPC:** 68
`eth_getTransactionReceipt` (protocol 1), one-time (receipts are immutable —
cacheable). Reorg note: receipts are not block-pinnable by parameter; these
blocks (10743414–25533308) are final.

**Flips:** no score row flips (no upgrade-derived finding today; the anti-decoy
answer is negative, so **no timelock credit is retracted**). Published **counts**
flip: `EtherFiNodesManager` 18→17, `LiquidityPool` 17→16, `0x2b90103c` 1→0 (18 of
120 events are deployments) — **SCORING_INVARIANTS.md B9 (~line 1566)** must be
corrected.

---

### Unit 9 — perimeter spawn (C3) + timelock analysis job (C2) — SPAWN, compute-heavy

**Files:** the policy stage that calls `replace_control_graph_rows` (add the
missing `_queue_discovered_contracts` call after it); the discovery/selection
budget (`analyze_limit`).

**C3 witness (identity is structural, not the label):** spawn a child analysis
job for each `control_graph_nodes` row with `details->>'source' =
'semantic_capability:role_grant'`, `node_type='contract'`, `analyzed=true`, no
existing job (19 jobless nodes). Identity of a manager = the pinned `vault()`
back-link (10/10 at 25643300) — **never** the `control_graph_nodes.label` string
"ManagerWithMerkleVerification". The recursive fanout MUST use a **logged**
`analyze_limit` budget (newly-analysed managers add more role_grant nodes — it
fans out unbounded otherwise). `manageRoot(strategist)` is a hash, so the
strategist's admissible call-set stays `not_determined` even after the managers
are analysed — "the manager is analysed" must never become "the manage capability
is bounded".

**C2 witness:** run one analysis job for `0xcd425f44758a08baab3c4908f3e3de5776e45d7a`
(EtherFiTimelock, solc 0.8.25). Cause of the gap: a **silent `analyze_limit=2`
budget cut** (rank 0.3836, queue positions 42-57) — not a bug; the targeted fix is
one job, not a threshold change. **Budget cuts must LOG what they dropped** (a
silently dropped candidate is this exact defect). Interim publication:
`proposer_set: not_determined`, kind `timelock_proposer_unresolved` — do NOT
substitute the twins' role grants. The `delay=172800` that 53 rows already publish
needs the PR#161 negative control (a nonsense selector must revert) before it is
cited as a proven ordinal.

**DO-NOT:** identify the manager by its label string. Raise `analyze_limit`
globally as "the C2 fix". Let the recursive spawn drop candidates silently.

**Test:** `tests/test_policy_perimeter_spawn.py` — post-refresh graph with one
role_grant contract node → exactly ONE child job (chain/protocol_id inherited),
byte-exact request dict; idempotence (run twice → still one job); FAIL-CLOSED:
`analyzed=false` → zero jobs; `node_type='principal'` → zero jobs; `chain_enabled`
false → zero jobs + explicit skip log `reason='chain_not_enabled'`; zero-address →
zero jobs; a population invariant asserting **zero *unlogged* omissions** (not
"zero omissions" — a legitimate budget cut must not redden the gate); a `vault()`
back-link witness test + a mismatched-`vault()` stub → `not_determined`, never the
assumed pairing. C2 producer parity: feed the verified source as a fixture →
exactly the 12 non-view function names (= twins 12/472), authority_openness
`open` on renounceRole / `not_determined` on the three onERC*Received / `restricted`
on the other 8; FAIL-CLOSED: unverified-source stub → `failed_terminal` +
`stage_error`, NO fabricated `contracts` row; and the offline producer test must
**fail loudly** (not skip) if solc 0.8.25 is unprovisioned (the label-corpus gate
skips silently on `SolcNotInstalled`).

**Migration:** none. **Compute:** 1 job (C2) + 10–19 jobs (C3) — the expensive
unit. **Phase-to-run:** you may run the static/analysis stage for a single target
in isolation to validate the C2 shape; you may **not** run the orchestrator to
drain the spawn queue — that realization is the live suite's job.

**Flips:** C2 → `score_v3.json /findings[6]`, `/warnings[259..261]`. C3 → 30
`contract_gated_unknown_path` warnings may resolve (polarity undetermined, so
current zero contribution stays correct until they do). Also `/findings[1]/reach_addrs`
and `/subsumed_rows[0..1]/reach_addrs` (the 10 manager addresses).

---

### Unit 10A — event-cursor coverage (D4) — MIGRATION

**Files:** `indexed_event_cursors` (migration); the enroller
`workers/event_log_indexer.py` (`_seed_block`, `enroll_from_completed_jobs`); the
fetcher `services/resolution/repos/event_logs_rpc.py` (~:95-140 bisect).

**D4(a) witness:** add `first_indexed_block` + `first_indexed_block_basis ∈
{creation_block_minus_one, explicit_seed, not_determined}`, NULL on all 80 legacy
rows (= "lower bound unknown"). Witness-grade it via **two pinned `eth_getCode`
reads** (empty at B−1, code at B); the `etherscan_cache` value is admissible as a
**seed only**, not the proof. Do NOT trust the `_seed_block` code path as a stored
witness.

**D4(b) coverage gate:** publish `absence_coverage` with a ceiling of
`enrollment_complete` — a statement about **cursors** (write_surface / enrolled /
warm / missing) — and it must **NOT** alone license an earned negative. **R6: the
hole is source-level** — `enroll_from_completed_jobs` reads ONLY `predicate_trees`
artifacts; `monitored_contracts.tracked_topics` (224 pairs) has **no enrollment
path at all**. `toDenyList` (AllowTo/DenyTo) is **never** emitted as an
`enumeration_hint` anywhere, so it is un-enrollable at every emitter. Closing the
hole means wiring the `tracked_topics` surface into enrollment — scope this
deliberately; it is a structural connection, not a per-variable patch.

**D4(c) truncation:** the bisect fires only on a raised `RuntimeError`; a silently
truncated 200-OK `eth_getLogs` page advances the cursor with logs missing. Move
the truncation case into the bisect path, persist `returned_log_count` per window,
and promote a cursor to `coverage: complete` (licensing "no such event exists")
**only** if every window carries a sub-cap count. Until then every event-absence
negative publishes an unquantified residual. (eRPC has a documented silent
`getLogs` cap; verify the deployed `getLogsMaxAllowedRange` — could-not-verify.)

**FLIP a published register claim:** withdraw **SCORING_INVARIANTS.md B5.5**
("the transfer denylist has provably never been written") and the **FIELDS.md §9
limit-4** row → `not_determined`. No DB row carries it, so nothing in Postgres
flips.

**DO-NOT:** let `absence_coverage: complete` be assembled from the seed intent +
a truncation-blind fetcher (that is the "close one gap by widening another" shape
— it would license negatives that (c) shows are unproven).

**Test:** enroll → byte-exact row `{last_indexed_block, first_indexed_block,
first_indexed_block_basis:"creation_block_minus_one", backfill_complete:False}`;
`_seed_block` None → **no** row inserted; a legacy row with `first_indexed_block
NULL` → consumer publishes `not_determined`, never 0. Coverage gate over a fixture
with a missing writer topic → `enrollment_complete: false` and NO earned negative
licensed.

**Migration:** yes — 2 nullable cols on `indexed_event_cursors`. **RPC:** 2
`eth_getCode` per address for a witness-grade backfill (~64 for 32); enrolling the
missing cursors is a cold backfill each. **Small-pop:** denylist emitters 4
addresses, 0-cursor subset 3 — B14.

**Dependency:** prerequisite for Unit 7B (D6-accept honest lower bound).

---

### Unit 10B — per-node restaking position (D1) — depends on Unit 4 migration

**Witness (per ENUMERATED node instance, at a recorded block):** `{eigenpod,
position_shares_wei` (basis `eigenlayer_withdrawable_shares`, cross-read via
`EigenPodManager.podOwnerDepositShares` **and** `getWithdrawableShares`),
`active_validator_count, last_checkpoint_timestamp, consensus_layer_residual:
not_determined}`. `getEigenPod()==0x0` ⇒ `{position_shares_wei: 0, basis:
no_eigenpod_proven}` (a distinct proven-zero). A failed read ⇒ `null` ⇒
`not_determined`, **never 0**.

**DO-NOT:** publish the **consensus-layer residual** as a number — it lives on the
consensus layer, not readable from the execution layer (~66 ETH here, unbounded in
general). **Attach the position to `effective_functions.id` 1184** (the beacon
**implementation**, whose own `getEigenPod()==0x0`) **or 2038** as reach until a
**destination witness** proves `forwardExternalCall` reaches the EigenLayer
withdrawal path (`destination_constraint.state` is `not_determined` today) — both
rows stay `reach = not_determined`. This is the sweepETH 16a error (5,188×
over-valuation) waiting to recur. If ever published as a floor it carries its
direction (`>= $X`) and its own basis column so it can **never** be summed with a
spot balance.

**Test:** fixture position reader → byte-exact record incl.
`consensus_layer_residual: "not_determined"` present as a key; `getEigenPod()==0x0`
→ proven-zero; failed read → null/not_determined.

**Migration:** reuses Unit 4's `contract_balances.block_number` (+ a `basis`
discriminator so restaked shares are never summed with spot balances) — sequence
after Unit 4. Node enumeration = a cold event fold (`EigenPodManager.PodDeployed`
/ BeaconProxy creation), its own cursor. **RPC:** 3 reads/node/cycle steady-state.

**Small-pop:** 1 `EtherFiNode` contracts row (id 569), 1 probed node, 2
`forwardExternalCall` consumer rows — B14, no calibration.

---

### Unit B4 — reach-floor reachability test (B4) — NO CODE FIX

**This is correct absence** — the branch is live with a satisfiable precondition
that simply did not occur on this corpus. **Do not "fix" it.** Add a reachability
test (`tests/test_reach_indeterminate_branch.py`) proving the branch fires: a stub
`SimCallResult` moving an asset out of an address NOT in `value_holders`, with
non-empty `value_holders` and `acting_balance_usd=0.0`, → byte-exact
`{'reach_determined': False, 'reach_indeterminate': True, 'observed_reach_floor_usd':
0.0}`; and `value_holders=()` → empty dict (the early return). Document that the
`0.0` floor must be consumed as "no proven bound" beside `reach_indeterminate=true`
— it is sourced from the B1/B2 balance plane, **never** a measured zero. Note: both
G3 rows carry `witness.effect_verdict_id` 138/142 whose verdicts carry
`concrete_destination`, so a scorer join closes them with no new witness.
**Cost:** zero. **Adversarial:** single note.

---

## 7. Global DO-NOT-BUILD / publish-as-not_determined list

These are the refuted/weakened cores. An implementer must not "helpfully" add any
of them back. (Cross-reference the unit that owns each.)

- **B5:** any `auto_expiry`/`duration_bound_seconds`/`duration_bound_source`
  severity reducer. Window mutable + re-pause unbounded. Label only, zero
  severity. → Unit 3.
- **C4:** `authorising_eoa` from `tx.from`. Always `not_determined`. → Unit 8.
- **B2:** an absent native row as `$0`. Three-state; pinned-zero only is a proven
  zero. → Unit 4.
- **D2:** the `immutableReferences`-offset read (not retainable); asset by
  variable name; `immutable` as a runtime invariant behind a proxy. → Unit 6.
- **D3:** setter by variable name; `writer_surface_closed: true` on a proxied
  row. → Unit 6.
- **D6:** the name-suffix guard (`_is_storage_layout_constant`); gating on
  `_roles`/`enumeration_hint` (drops 5 real roles); `holders` as an exhaustive
  set. → Units 7A / 7B.
- **A1:** `expected_version` from `latch_value`; any strength ordering over the
  4 bases; `consumed` as a permanent (non-mutable) fact. → Unit 1.
- **A2:** `min-of-present` for heterogeneous heights; `observed_at_block` on the
  `"latest"` path; expecting yield on the 261 solmate rows. → Unit 2.
- **A3:** slot-differential as the primary fix; ranking the two name-matched
  arms. → Unit 2.
- **C1:** a `modules` array from the head word alone. → Unit 7A.
- **D1:** consensus-layer residual as a number; attaching position to ef
  1184/2038 without a destination witness. → Unit 10B.
- **D4:** `_seed_block` as a stored witness; `coverage: complete` licensing a
  negative without per-window sub-cap counts. → Unit 10A.
- **Any unit:** calibrating a rule/weight/threshold on a population < ~5 rows
  (B14). The under-5 populations are flagged per unit.

## 8. Register updates the fixes must land (close the witness → scorer loop)

**Every unit that publishes a NEW field (or changes a field's meaning) MUST
register it** — append a canonical entry to `SCORING_INVARIANTS.md` Appendix B
(the normative source, as amended by B0b) and mirror it into the flattened
`FIELDS.md` register. This is what lets the future scorer represent and consume
the data we generate here. **A field that is generated but not registered is
invisible to the scorer — the unit is not done until it is registered.** Each
entry states:

- field name + JSON path + population (`populated / applicable`);
- **status** — REQ / GATE / CONF / BAN (inv.16 vocabulary);
- **three-state semantics** — what proven-present / proven-absent /
  `not_determined` each mean, and **which reachable state is the
  revert/failure/absence path** (per §0's fail-open rule);
- **consumption obligation** — gate / arithmetic / cite / three-state (§E "what
  consume means"); a field carrying none of the four is CONF, not REQ;
- any **small-population** flag (< ~5 rows ⇒ may gate/cite/three-state, never
  calibrate a weight — B14).

**The register entry is held to the same proven bar as the code, and the
adversarial reviewer (§4) audits it.** The register is normative (inv.16), so an
entry that marks a `not_determined` field as REQ-proven, describes a lower bound
as a point value, or omits the failure-path three-state mis-instructs the scorer
exactly as bad code would — it is an unproven-positive vector and is rejected on
the same grounds.

### 8.1 Corrections to existing register claims

- `FIELDS.md` §7: `effect_verdicts.witness.block_number 304/304` → **0/274, key
  absent**. (Unit 3.)
- `FIELDS.md` §4 / :84 and `SCORING_INVARIANTS.md` B0b R1-caveat: "9 Safes,
  modules empty" → **19 Safes, one module-bearing, guard zero 19/19**. (Unit 7A.)
- `SCORING_INVARIANTS.md` B5.5 + `FIELDS.md` §9 limit-4: denylist "provably never
  written" earned negative → **`not_determined`**. (Unit 10A.)
- `SCORING_INVARIANTS.md` B9 (~line 1566): upgrade counts corrected down by the
  18 deployments. (Unit 8.)
- Lane A's A3 test spec used the wrong ERC-7201 slot (Initializable
  `0xf0c57e16…`); correct is AccessControlDefaultAdminRules `0xeef3dac4…8400`.
  (Unit 2.)

## 9. Carry-forward could-not-verify (state on every affected PR)

- **25643300 vs the observed run's true probe height** — `_resolve_probe_block`
  (uses head−12) persists nothing, so all pinned agreements prove stability at
  25643300, not that the run read there. Affects any replay-determinism claim.
- The 18 real D2 receiver rows vs the tested synthetic shapes (Unit 6 Phase-0).
- Older-solc / Vyper / production-Docker-forge variants of R3 (only 0.8.27 +
  forge 1.5.1 exercised).
- The `immutableReferences`-not-retained finding (0/6140 blobs) is from the
  residual-verification pass on the local replica, not the original investigation
  JSONs; the arm is forbidden regardless, but re-confirm before ever building the
  offset arm if the compile toolchain changes (Unit 6 / D2).
- Whether any enrolled cursor's `indexed_event_logs` is non-empty (D4).
- eRPC's deployed `getLogsMaxAllowedRange` / silent-truncation behaviour (D4c).
- Whether `role_definitions` has a reader outside `routers/`, `services/aggregations/`,
  `services/chat/`, `site/src` — `workers/`, `scripts/`, chat schemas not
  exhausted (Unit 7A "no reader" claim).
- "warm" is degenerate in this replica (present ⇒ warm on all 80 cursors);
  cold-vs-warm cannot be studied here; everything is `chain_id=1` (multichain
  untested).
