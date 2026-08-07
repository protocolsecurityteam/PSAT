# Execution Witness — Implementation Handoff

**Status:** implementation handoff. Nothing implemented. **Wave 0 is a blocking investigation that
must try to REFUTE this document** before any code is written.
**Written:** 2026-08-07, from a live read-only investigation against the local etherfi snapshot
(`protocol_id 1`, DB on port 5433), branch `fix/confidence-perimeter-admission` at `c9f2713e`
(model `1.1.0-provisional`, PR #169 — **OPEN and unmerged**).
**Deliverable expected from you:** a corrected, merged branch — two phases, §2.
**Supersedes and cancels:** `EXTRACTION_PRECONDITION_SPEC.md` **as a plan** — do not implement its
waves (§8 says why, per defect). ⚠ It is **not** deleted and remains a required *reference*: §8's
E1–E6 discussion and C20's "class-B" both depend on definitions that exist only there
(`EXTRACTION_PRECONDITION_SPEC.md:59`). Keep it on disk, keep it in the §0 tracked set, read it —
just do not execute it.

---

## 0. Operating rules (read first)

**Every subagent you spawn MUST run on Opus, except the two capstones, which run on Fable.**
Pass `model` explicitly on each `Agent` call. This is a deliberate, disclosed cost decision by the
repo owner. The failure mode on this task is *plausible-but-wrong reasoning about what the pipeline
proved* — cheaper models produce that confidently, and this document exists because a strong model
produced it four times in a row. Do not silently downgrade. If you think a unit is mechanical enough
for a cheaper tier, say so in your report and let the owner decide.

**You orchestrate; you do not write or review code.** All coding goes to fresh Opus subagents in
isolated worktrees. All reviews — including both capstones — go to *separate* fresh agents. Cap
review loops at **3 rounds**; on exhaustion **you** adjudicate, not the user.

**DO NOT TRUST THIS DOCUMENT.** Every numbered claim in §3 was measured, but the investigation that
produced it also produced four confidently-wrong rulings that had to be retracted (§5). Wave 0's job
is to independently reproduce or refute §3, and any claim it cannot reproduce is **struck**, not
worked around. The prior handoff into this line of work contained wrong claims that cost multiple
agent-days; assume this one does too.

**The local DB is READ-ONLY.** SELECT only, port 5433, `DATABASE_URL` from `.env`. Create your own
`psat_test_<unit>` database for DB-backed tests; that is the sole exception. Do not start workers,
the monitor, or the indexer.

**BLOCKING PREREQUISITE — five of the six governing documents are UNTRACKED.** Verified:
`EXECUTION_WITNESS_SPEC.md` (this file), `COMPOSITION_WITNESS_SHAPE_SPEC.md`,
`SCORING_INVARIANTS.md`, `SCORER_DISCIPLINE_CONTRACT.md` and `EXTRACTION_PRECONDITION_SPEC.md` are
all untracked; only `CLAUDE.md` is tracked. **Git worktrees carry tracked files only**, so a
subagent cut into `/home/riley/PSAT-wt/<unit>` will have the code and none of the record — including
the invariants and discipline contract §0 orders it to read.

**The owner has authorized tracking them for the duration of this run, and requires them untracked
again before the push.** Execute exactly this:

1. **Before Wave 0 cuts any worktree**, commit all five in **one dedicated commit** (suggested
   subject: `Track working specs for the execution-witness run`). They must be *committed*, not
   merely staged — a worktree checks out a commit and cannot see staged-only files.
   ⚠ **`git add` alone FAILS on two of them.** `SCORING_INVARIANTS.md` and
   `SCORER_DISCIPLINE_CONTRACT.md` are listed in `.git/info/exclude` (lines 61 and 68, verified), so
   the add is silently a no-op. Use **`git add -f`** for all five, then confirm with `git status`
   that five files are staged before committing.
2. **After CAP-B passes and before the push**, remove them in **one dedicated commit** using
   `git rm --cached <files>` — **`--cached` is mandatory**: it drops them from the index while
   leaving them on disk, which is what the owner wants. A bare `git rm` deletes the owner's working
   documents.
3. **Verify before pushing:** `git ls-files | grep -E '(EXECUTION_WITNESS|COMPOSITION_WITNESS|SCORING_INVARIANTS|SCORER_DISCIPLINE|EXTRACTION_PRECONDITION)'`
   returns **nothing**, and all five files still **exist on disk**. Both checks, every time.

Keep the two commits isolated and trivially identifiable, because the push is batched to the very
end (§0) — that leaves the owner free to drop or squash them at push time if they want a clean PR
diff. Do not fold either one into a code commit. Do not let a unit start without the docs present.

**No commit without explicit owner authorization for the push. No Claude attribution trailers.**
One batched push at the very end.

**Witness discipline governs the output** (`CLAUDE.md`): a value is published as a positive fact
only when evidence proves it; absence of a proven constraint is not proof that no constraint
exists. This entire defect class is a violation of that rule *inside the scorer*, so a fix that
itself launders an assumption into a number is a failed deliverable.

Read before proposing anything: `SCORING_INVARIANTS.md` (esp. 1, 6, 9, 13, 16),
`SCORER_DISCIPLINE_CONTRACT.md`, and `COMPOSITION_WITNESS_SHAPE_SPEC.md` §10/§11 (what PR #169
shipped, in its own words).

---

## 1. The one-paragraph problem

PR #169 publishes 40 composed magnitude entries whose dollar figures were proven by an execution
none of them describes. Measured over all 379 stored transcripts, the wrapper selectors the entries
claim to route through — `Teller.bulkWithdraw` `0x3e64ce99`, `Manager.manageVaultWithMerkleVerification`
`0x244b0f6a`, `0x46b563f4` — appear **zero times**. Every proof is a *direct* impersonated call to
the destination; every published claim routes it through a wrapper that authors the call's
arguments. Because the wrapper computes the amount (`Teller.bulkWithdraw`:
`assetsOut = shareAmount × rate`, burning `msg.sender`'s shares) or restricts the callee set
(`Manager`: merkle verification), the destination's magnitude does **not** transfer across it —
while the *gate* claim does, since `isAuthorized(msg.sender, msg.sig)` reads no arguments. The
figure is not a call amount either: the probe moves `ARG_AMOUNT = 1` wei and `_add_reach`
substitutes the holder's entire priced balance, which `distill.py:790` then stamps `proven_exact`.
And the block that hedges all this — `caller_holding_precondition` — is **one 1,222-character
string, identical on all 40 entries**, asserting a share-spending mechanism absent on the 12 whose
destination is `manage` (**MANAGE-12**, §9.0 — *not* the set the gate withholds).
That last item is not an isolated bug: **17 of the document's 42 `reading`/`note` paths are a single
constant string repeated.**

**The fix is scorer-and-plumbing only. No new probe, no new extraction, no schema change.**

---

## 2. What this handoff asks for — two phases, in order

**Phase A — resolve PR #169 before it merges.** Land the execution witness, cut what the evidence
does not support, and hit the measured numeric gate (§9). This must happen **on the branch, before
merge**, so `main` never receives the unsupported claim and the merge commit does not assert the PR
was correct as-is.

**Phase B — invoke the invariant everywhere, remeasure, and prove the defect pattern is gone.**
Phase A fixes the instance we caught. Phase B sweeps the class: every published number names its
execution, every published string is either derived from data or is a field description that makes
no data claim, and a fresh measurement confirms no surviving instance of either pattern.

Phase B is not optional polish. The reason this branch produced three successive over-claims is
that each fix addressed an instance. **If Phase B does not run, expect a fourth.**

---

## 3. Claims register — verify each, do not assume

Wave 0 reproduces or refutes every row. Method is named so you do not have to rediscover it. A claim
that fails to reproduce is **struck from the plan**, and you report that as a result, not a problem.

| # | claim | how it was measured | if it's wrong |
|---|---|---|---|
| C1 | The three wrapper selectors appear **0 times** across all 379 transcripts; routing matches **0/40** | fetch `effect_verdicts.transcript_ptr` → `artifacts (job_id, name)` → MinIO body; grep `calls[].data` | the whole premise fails — STOP and report |
| C2 | Target matches **40/40**; caller matches **30/40**; the 10 misses all swap a DelayedWithdraw for a Teller ($1,796,080.94) | same transcripts vs each entry's `act_as_chain[-1]` | the three-arm rule's caller conjunct needs re-ruling |
| C3 | `caller_holding_precondition.reading` has exactly **1 distinct value** across all 40 entries (28 `exit` / 12 `manage`) | walk the document JSON, `set()` the strings | F3 shrinks to a wording fix |
| C4 | **53** protocol-1 signals carry `proven_exact` from the attribution path ($1.916B nominal); only `distill.py:790/793` produces it | query `function_score_signals`; grep distill for the constant | the relabel's scope changes |
| C5 | `calldata.py:87 ARG_AMOUNT = 1` (1 wei); `_add_reach` (`recipes.py:1545`, loop `:1636-1690`) credits the holder's **entire** priced balance and discards the transferred value | read both | F4 collapses; magnitudes might be real |
| C6 | **4** rows publish a `>=` band on attribution-derived magnitudes: $90.06, $13.65, $1.59, $1.59. ⚠ **These four carry NO `reach_composed_magnitudes` — they are DISJOINT from the 40-entry population.** Do not hunt them inside the 40; you will find nothing. F5's entire blast radius is **~$106.89** | scan all 82 rows for `value_at_stake_bound_direction == "floor"` | F5 shrinks (it is already tiny — treat it as correctness, not value) |
| C7 | Safe `0xcea8039076…` is a `controller` on `setUserRole` + `setRoleCapability` at RolesAuthority `0x402dff43b4f2…`, **and** on `setAuthority` + `transferOwnership` on the five `exit`-destination vaults named in A.1 (unscoped it reaches 12 BoringVaults / 72 contracts) | `function_principals` ⋈ `effective_functions` ⋈ `contracts` | the deletability join has no live instance — re-scope Phase A |
| C8 | EOA `0xf8553c85…` and solver `0x98946898…` are principals on **zero** functions of any of the 5 vaults; `exit`'s admitting set is `{Teller}` or `{Teller, DelayedWithdraw}`, `membership_quality: exact` | same join | the EOA rows may be deletable too — changes which entries survive |
| C9 | `Manager.manageVaultWithMerkleVerification`'s `requiresAuth` (Manager.sol:134) resolves to roles [4,7] held by `0x18deea88` / `0x607d0c7e` / `0xc8111d00` — **no seized principal can call the manager at all** | authority resolution + `function_principals` | E2 is revived; re-open the cancelled spec |
| C10 | The `setManageRoot` `0x21801a99` → own-principal join **reproduces 6/6** but is **not load-bearing** given C9 | same join | as C9 |
| C11 | Blanket refusal on route mismatch → λ **84.0166**, `exposure_usd` **$76.07**, **0** entries, and it deletes the real $44.35M Safe finding | monkeypatched `_compose` in a throwaway process | refusal might be viable after all |
| C12 | The ruled three-arm rule → λ **73.2508**, `exposure_usd` **$18,059,003.86**, **28/40** entries, both Safe rows intact | same | §9's gate is wrong — re-derive it before any unit starts |
| C13 | Those equal `COMPOSITION_WITNESS_SHAPE_SPEC.md` §10.3's **pre-fix** values; the composition fix's entire gain was $2,121,701.96 across 2 findings + 2 subsumed rows | read §10.3 | the correction is larger or smaller than stated |
| C14 | `main` (`7b893396`) scores protocol 1 at **$22,096,832,609.90** summed / **$4,332,693,901.30** entity-deduped, λ 54.1614, `confidence_pct` **20.8** | `git checkout main`, run the CLI | the "don't revert to main's model" argument weakens |
| C15 | **17 of 42** `reading`/`note` paths in the document are a single constant string repeated | walk the JSON, group by path, count distinct | Phase B shrinks to the one instance |
| C16 | hop-count 1 ⟺ deletable (**28** entries, 6 rows); hop-count 2 ⟺ not (**12** entries, 4 rows) — a **corpus coincidence**, forbidden as a test | compare the deletability join against hop-count | if it's NOT a coincidence, say why — and still don't ship it |
| C17 | Transcripts store the call envelope only: **135/135** `value_out` blobs fetchable, **0** contain `logs`/`topics` (`harness.py::_result_dict` drops `SimCallResult.logs`) | fetch and grep | log-derived work becomes possible — still out of scope here |
| C18 | Tier-1 `eth_simulateV1` measured at **754.5 ms/probe** (129 of 135 are Tier-1); a prior ≈321 ms figure is 2.35× optimistic | phase timings in `logs/` | re-probe cost estimates change (out of scope here) |
| C19 | **$58,364,959.08** across **172** rows, **120** unpriced. ⚠ **"Six vaults" is a wrong name and cost a verifier two false FAILS.** The population is the six **`manage` (`0xf6e715d0`) destination ENTITIES** — disjoint from C7/C8's five `exit` vaults; 5 *addresses* / 6 *entities* (`0x657e8c86…` counts twice: `ethereum::` and `base::` are separate sheets); one (`0x86b5780b…`) is `BoringGovernance`, not a BoringVault. "Unpriced" means strictly `per_asset_state == 'unpriced'`; including `priced_below_resolution` gives **133**, not 120 | value plane source, `planes.py::load_value_plane` **:407** | the pricing deferral's size changes |
| C20 | Published class-B is **$42,587,080.93**, not $53.9M — $11,358,880.43 is subsumed-only | sum by class over all 40 | a prior spec's headline figure is wrong (already suspected) |

### ⚠ Read this before the table: these are LEADS, not verified facts

Two independent reviews of this register found the *arithmetic* reproduces almost everywhere and the
*methods* frequently do not. Known-imprecise as of writing, and **not** exhaustively repaired:

- **C1's "routing match" is never defined.** A reasonable reading of the phrase yields **28/40**,
  not 0/40. What was actually measured is: *the three named wrapper selectors appear in no
  transcript's `calls[].data`.* Derive and state your own definition before you assert a number.
- **C4's `proven_exact` is not a column** — it lives at
  `gate_inputs->'reach_magnitude_usd'->>'state'` on the signal row.
- **C7's "all five vaults" understates it** (the Safe reaches 12 BoringVaults / 72 contracts), and
  `principal_type = 'controller'` is a **tautology** — true on 28,689 of 28,689 rows. Any join
  relying on it fails open. There is **no `membership_quality` column** on `function_principals`.
- **C8's "the 5 vaults"** names a specific address set (Appendix A.1), not "vaults with an `exit`
  selector."
- **C15's method omits a load-bearing `n > 1` filter** — as stated it returns 37, not 17.
- **C19's "six vaults"** are `manage`-destination *entities*, **disjoint** from C7/C8's five, and
  "unpriced" means strictly `per_asset_state == 'unpriced'` (133 if you include
  `priced_below_resolution`).
- **C20's "class-B" is defined nowhere in this document** — entries carry no `class` field. The only
  definition is the class table at `EXTRACTION_PRECONDITION_SPEC.md:57-60`. **Inline definition:
  class-B ≡ MANAGE-12 — the 12 `manage` entries, 6 entities, $53,945,961.36.** The document already
  carries this set under the other name and never connects them.

**Treat every row in the table that follows as a lead with a figure attached.** Derive the method yourself, state it, and
report where this document's recipe was wrong — that reporting is part of the deliverable, not an
inconvenience. **Appendix A** holds the reproductions the author executed personally; everything else
is a subagent's summary transcribed by hand.

**The population, and the trap inside it:** 40 entries / 10 rows = **19 entries across 4 findings
rows + 21 entries across 6 subsumed rows stored under `provenance`**. Three separate investigation
passes silently measured findings-only. The subsumed set contains a timelock row ($11,358,880.43)
with no findings counterpart whose principal *is* authority-deletable — a **keep-it** row a
findings-only pass would have wrongly withheld. **Every unit covers all 40.**

---

## 4. Traps — this section is why the handoff is long

Each of these cost real time. Read them before writing code.

**Method traps**

1. **Read the transcript before the Solidity.** Four rulings in the originating investigation were
   wrong because they reasoned from contract source about executions the pipeline never ran. What a
   contract *could* do is not what a probe *proved*. If you find yourself explaining a number by
   reading a `.sol` file, stop and fetch the transcript.
2. **Cover all 40 entries** — findings **and** the 21 subsumed under `provenance`. See §3.
3. **Never classify from hop-count, selector name, or contract shape.** Compute the witness. C16 is
   a perfect correlation on this corpus and shipping it would be the same failure that produced
   every defect here.
4. **A green suite proves little.** Measure on the real corpus and report ADDED / CHANGED / REMOVED.
   A zero-diff counts only if you prove *why* it is zero.
5. **An absence is not a proof.** `no_rows` / `priced_below_resolution` is not a zero balance.

**Tooling traps**

6. **The score CLI does not persist.** `services.scoring.cli score` distils in memory, folds, and
   writes JSON to `--out` or stdout. It never writes `protocol_scores`. "Populate the DB and inspect
   it" is a misconception — the DB already holds the *inputs*.
7. **`differential` is arithmetic-first.** A row registers as `changed` only when `raw_points` moved.
   Claim-only repairs are **invisible** to it (`COMPOSITION_WITNESS_SHAPE_SPEC.md` §11.2 item (m)).
   Phase B's verification needs an exact **node-level JSON diff**, not the CLI.
8. **`distill._flow_reach` is the working monkeypatch seam** for simulating distill-level changes.
   Do **not** patch `services.scoring.population.signal_from_row` — ⚠ the `def` actually lives in
   `services/scoring/schema.py:461` (`schema.py:8`: "the seam is owned here"); `population.py:23`
   merely imports it and calls it at :84 and :114, so patching the population symbol intercepts only
   population's own calls and misses the rest.
9. **Artifact `storage_key` prefixes are per-job and NOT uniform** — measured on this data: **345
   keys under `pr-162/` and 34 under `artifacts/`**. Read keys from the column; never construct
   them, and never generalise from the prefix you saw first.
10. **`source_files.storage_key`'s trailing hash derives from the path** — fetch a contract's source
    from **its own** `job_id`. Base contract `0x86b5780b` has no `pr-162/`-style prefix.
11. **`site/src/score/derive.js`'s `BOUND_DIRECTIONS` allow-list silently nulls** an unknown
    direction — the badge vanishes rather than erroring. ⚠ The array is at **:107** and the
    silent-null at **:120** (an earlier draft cited :114, which is only the field read). Extend it
    in lockstep with any new direction value.
12. **Host Postgres is on 5433**; CI uses 5432. `PSAT_LLM_STUB_DIR` is load-bearing for the offline
    suite. `./run_tests_fast.sh` exports its own CI-faithful env — do **not** `source .env` for it.
13. **Never `-k "not live"`** — use the marker (`-m "not live"`).

**Measurement traps**

14. **`exposure_usd` is per-finding.** The gate figure is the sum over the 27 findings, not a
    top-level field.
15. **`confidence_pct` binds on `value_priced_pct` and DOES NOT MOVE.** `fold.py:3861` is
    `min(reach_pct, capability_pct, priced_pct, magnitude_pct)`; `refused` feeds **none** of the
    four. An earlier draft of this trap said it "must move in Phase A" — **that is false and is
    retracted**. Watch `reach_magnitude_witnessed_pct` / `_of_reaching_pct` instead (§9.1).
16. **The document is non-monotone under withholding.** Dropping 10 entries yielded 36, not 30 —
    `_compose` substitutes another candidate at the same entity. Do not reason by subtraction.
17. **Reproducing the baseline is the harness's own gate**: λ **62.3179**, `exposure_usd`
    **$19,438,110.14**, `confidence_pct` **18.6**, `grade_exposure` **99.55**. If your run doesn't
    reproduce it, stop — everything downstream is invalid.
18. **Known pre-existing offline failures, unrelated:** `test_appendix_a_funnel_on_dev_db`;
    `test_event_indexer_loop_records_heartbeat` (flaky).
19. **Only protocol 1 is scoreable locally** — `protocols` has one row, all 1059 signals are
    `protocol_id = 1`, and 521 contracts are orphaned at `protocol_id IS NULL`. Nothing here
    generalises without a second protocol.

---

## 5. Dead ends — do NOT re-propose these

Recorded because each was proposed confidently, pursued, and refuted. Re-deriving them costs an
agent-day each.

- **Log-derived netting** ("compute net-to-attacker from `Transfer` logs"). REFUTED: the probe's
  amount is a compile-time constant (`ARG_AMOUNT = 1` wei), so a log-derived figure measures the
  encoder, not exposure — published-to-gross ratio **1.1e8** on `exit`, **1.1e26** on `manage`. The
  logs aren't stored either (C17).
- **Balance-sheet reach** ("reach = entities commanded × value at them"). REFUTED: that is exactly
  `main`'s model and it produces **$4.33B** entity-deduped, including one EOA row at
  $4,229,271,828.89 republished across four capabilities. It witnesses *association*, not command.
- **Blanket refusal on route mismatch.** REFUTED by measurement: λ→84.0166, exposure→$76.07, zero
  entries, and it deletes the real $44.35M Safe finding (C11).
- **The A/B/C precondition taxonomy** (`EXTRACTION_PRECONDITION_SPEC.md`). Cancelled — §8.
- **The holder witness** (proving a principal holds/can acquire the spent quantity). Deferred a
  third time: it refines a wrapper gate the adversary bypasses.

---

## 6. Confirmed defects

**F1 — the published route was never executed.** C1, C2. The entry claims a route the proof did not
take.

**F2 — the magnitude does not transfer across an argument-authoring wrapper; the gate does.**
`isAuthorized(msg.sender, msg.sig)` reads no arguments, so caller-matched gate claims survive
routing mismatch. The amount does not: `Teller.bulkWithdraw` (Teller.sol:432-434) computes
`assetsOut` and passes `msg.sender` as the burn address; `ManagerWithMerkleVerification`
merkle-restricts the callee. Two distinct reasons, one rule.

**F3 — `caller_holding_precondition` is a constant, false on 30% of what carries it.** C3. It
asserts "the chain's last admitted call spends a quantity the caller must already hold or supply."
On **MANAGE-12** (§9.0) **no caller quantity is spent at all**, which under-claims ~$40.9M.

**F4 — an upper bound is published as `proven_exact`.** C4, C5. `proven_exact` is **unearnable in
principle** on the attribution path.

**F5 — four rows publish `>=` on an upper bound.** C6. `_bound_direction` (`fold.py:1986`) grants
`floor` on coverage grounds alone, never asking whether each contribution is itself a bound — a
question U4 taught it to ask for composed entries only.

**F6 — the proving caller is not persisted.** It exists only inside the transcript blob
(`harness.py:227 record_calls`), never on `effect_verdicts`.

**F7 (the class, Phase B) — authored strings that make data claims.** C15. F3 is one of 17. The
distinction that matters: a string **describing what a field means** may be constant (it is
documentation); a string **making a claim about the data** must be derived, because it can be false
for the row carrying it. Nobody has classified the other 16.

---

## 7. The fix

### 7.1 The invariant

> **A published magnitude carries the execution that produced it — caller, target, selector, decoded
> arguments, block, seeded-or-not — and every claim attached to it is DERIVED from that record. A
> field that cannot be derived from the record is not published. A string that makes a claim about
> the data is derived; a string that describes what a field means may be constant.**

### 7.2 The composition rule — three arms, ruled

1. **Gate claims transfer** on caller match; routing is irrelevant to them.
2. **Magnitudes are withheld** across an argument-authoring wrapper, under two typed reasons:
   `destination_amount_is_authored_by_the_intermediate` and
   `destination_callee_is_restricted_by_the_intermediate`. The entry publishes the gate, the
   execution record, and the refusal — never a figure.
3. **Direct paths are republished** where the **authority-deletability join** (§7.3) proves the
   principal can author the calldata itself. The published route is then the one the probe ran.

### 7.3 The authority-deletability join — the one genuinely new piece

Per row: does the principal control the authority gating the destination — a `function_principals`
row for `setUserRole` / `setRoleCapability` on the gating authority, or `setAuthority` /
`transferOwnership` on the host? Absence is a **typed refusal**, never a silent admission. An
unresolvable authority fails to `not_determined`, never to deletable.

### 7.4 Derived labels replace authored ones

- `caller_holding_precondition` — **deleted**, not corrected.
- `proven_exact` on the attribution path — becomes a **new third token** (Wave-0 ruling 5 names it).
  It must **not** be re-pointed at `proven_floor`, whose fold prose means "at least this much."
- `_bound_direction` learns that an attribution-derived contribution is a bound (F5).

### 7.5 Storage

The caller belongs in `effect_verdicts.observed_residue` (state-plane jsonb). It must **never** enter
`effect_behavior_cache` (`db/models.py:2581`), keyed on `behavior_hash` with no address by design.
**No migration.**

---

## 8. What gets CUT from PR #169 (and why cancelling `EXTRACTION_PRECONDITION_SPEC.md` is safe)

**Cut:** `_CallerHoldingPrecondition` and its block; `principal_extraction_bound`; the magnitudes on
**WITHHELD-12** (§9.0 — *not* MANAGE-12, and note that all 40 are route-mismatched, so
"the route-mismatched entries" names nothing). **Ruled on, not assumed:** `destination_predicates` (U3) —
unpolarized predicate text evaluated by nothing, carrying its own constant reading;
`composed_selector_tie` (U3); and U4's `ceiling` arm, whose behaviour once 12 magnitudes are
withheld is **NOT DETERMINED**. Wave 0 rules each.

**Kept, and correct:** W1a's destination-ACL act-as witness (a *gate* claim, and gate claims
transfer); U1's read taxonomy; U2's differential fix; the confidence-perimeter work; `_composed_order`
(still needed for the surviving 28).

**`EXTRACTION_PRECONDITION_SPEC.md` is cancelled:** E1 (classify from the traversed body) is moot —
the body is not traversed by the proof, and a withheld magnitude has nothing to classify. E2 is
**REFUTED** by C9. E3 is moot for the same reason as E1. E4 (seeding disclosure) and E5 (wrong named
subject) are **absorbed** into the execution record. E6 is carried to §12.

**Perspective, and do not lose it:** `main` publishes **$4.33B** entity-deduped with *higher*
reported confidence (C14). This branch cuts that to $119M. **This handoff corrects ~$2.12M on top of
a ~$4.33B fix.** Nothing here is a reason to revert composition.

---

## 9. Gates

### 9.0 Three different sets — name them, and never write "the 12"

Two distinct 12-entry sets exist and an earlier draft conflated them with a third that does not
exist. This is the single highest-cost ambiguity in the document; get it right before reading on.

- **ALL-40 — route-mismatched.** What was measured (§3): the three named wrapper selectors appear
  in **no** transcript's `calls[].data`. *Every* entry claims a route its
  proof did not take. There is **no** "12 route-mismatched" set.
- **MANAGE-12** — the 12 entries whose destination is `manage` `0xf6e715d0`. This is the set F3's
  constant reading is false about (no caller quantity is spent there). The other 28 are `exit`.
- **WITHHELD-12** — the 12 entries the §9.1 gate withholds: those whose principal the deletability
  join (§7.3) does **not** prove can author the calldata, so arm 3 cannot republish and arm 2
  withholds the figure. On this corpus they are the 2-hop entries on the 4 EOA rows,
  **$2,121,701.96**.

**MANAGE-12 ≠ WITHHELD-12.** Same size by coincidence, disjoint in purpose. An agent that cuts
MANAGE-12 will miss the gate with no diagnostic telling it why.

### 9.1 The numeric gate

**Phase A moves numbers, deliberately.** Unlike the two prior runs on this branch, "zero movement" is
**not** the gate.

| quantity | tip | Phase A target |
|---|---|---|
| λ | 62.3179 | **73.2508** |
| `exposure_usd` (sum over findings) | $19,438,110.14 | **$18,059,003.86** |
| composed entries | 40 | **28** |
| rows keeping a composed figure | 10 | 6 |
| `grade_exposure` | 99.55 | **99.582** (`COMPOSITION_WITNESS_SHAPE_SPEC.md:482`) |
| both Safe rows | priced | **priced, unchanged** |
| `confidence_pct` | 18.6 | **18.6 — unchanged.** Do not chase it |
| `reach_magnitude_witnessed_pct` | 37.9 | **must fall** — report the figure |
| `reach_magnitude_witnessed_of_reaching_pct` | 26.5 | **must fall** — report the figure |

**Correction, verified in code.** An earlier draft demanded `confidence_pct` move off 18.6, on the
theory that typed refusals feed it. **That is false.** `fold.py:3861` computes
`"pct": min(reach_pct, capability_pct, priced_pct, magnitude_pct)` and `refused` appears in **none**
of the four terms; the baseline `min(59.1, 45.0, 18.6, 37.9)` binds on `value_priced_pct`.
Independent measurement agrees — `confidence_pct` held at 18.6 across every modelled scenario
including total disproof, where `magnitude_pct` fell well below its 37.9 baseline and still exceeded 18.6. A unit that
reports 18.6 has **not** failed; a unit that makes 18.6 move has probably broken something.

**Provenance of these targets.** They derive from C12/C13, which are **leads, not gospel** (§3):
if V0-a's independent re-derivation differs, **V0-a's number is the gate** and this table is struck.
They are also the pre-composition values from `COMPOSITION_WITNESS_SHAPE_SPEC.md` §10.3 — reproducing
them is *not* a numeric revert of the branch, it is the removal of the one gain the execution record
does not support.

**The gate cannot distinguish a correct implementation from the banned shortcut.** On this corpus
the deletability join and the forbidden hop-count test (C16) partition the population *identically*
— 28 entries / 6 rows either way. Hitting the numbers above therefore proves nothing about *how* you
got there. The only discriminator is regression case 3 (§14), which is consequently **mandatory and
bidirectional**: a constructed fixture with a **1-hop chain and no deletability row must NOT
republish**, and a **2-hop chain WITH one MUST republish**. A unit that hits the numbers without
both fixtures passing has not demonstrated compliance, and the reviewer must fail it.

**Unit-level gates.** A1 and A2 are **zero-movement** units — any dollar movement before A3 is a
defect to report, not a result to ship. A3 hits the table above.

**Phase B is claims-only:** every Phase A number holds byte-identical, verified by exact node-level
diff (not the CLI — trap 7).

---

## 10. Invariant impact

| invariant | verdict |
|---|---|
| **1** three-valued logic | **PRESERVED** — every withheld magnitude publishes a typed refusal, never a zero |
| **6** monotone in resolution work | **PRESERVED** — the execution record is already produced; it is dropped in transit |
| **9** exact decomposition | **CHECK** — every entry must trace: proven execution → route comparison → arm taken → published claim |
| **13** anti-gaming | **CHECK and argue** — withholding *lowers* charges on **WITHHELD-12** (§9.0); confirm a protocol cannot suppress a `setUserRole` principal row to look non-deletable |
| **16** no abstraction above a witness | **ENFORCED — this is the whole point.** No classification from hop-count, selector name, or contract shape |

---

## 11. Wave plan and agent roster

Work directly on `fix/confidence-perimeter-admission` (tip `c9f2713e`), **before PR #169 merges**.
Cut each unit as a worktree off the current tip under `/home/riley/PSAT-wt/<unit>`; every prompt must
prove it is not on a stale base (`git merge-base --is-ancestor <tip> HEAD`) before writing code.
**Only remove worktrees this session created** — ⚠ `git worktree list` currently shows **49**
pre-existing entries from prior runs; do not clean any of them up, and record the exact paths you
add so the distinction survives a context handoff.  The integrating unit runs the suite, not just
the merge.

| Wave | Unit | Model | Scope | Depends on |
|---|---|---|---|---|
| **0** | **V0-a** | Opus | Verify/refute C1–C14 (execution, composition, deletability, blast radius). Re-derive §9's gate independently. | — |
| **0** | **V0-b** | Opus | Verify/refute C15–C20 + classify all 42 `reading`/`note` paths as field-description vs data-claim. Rule the three §8 surfaces. | — |
| **0** | **V0-R** | Opus | Review both V0 reports: are the rulings supported, is anything struck that shouldn't be, do the two disagree? | V0-a, V0-b |
| **A1** | | Opus | Execution record end-to-end (`E`→`D`→`F`) + F4/F5 label derivation; widen `_DestinationMagnitude`. **Zero movement.** | V0 |
| **A1-R** | | Opus | Review A1 | A1 |
| **A2** | | Opus | Authority-deletability join (`P`/`F`). **Zero movement.** | V0 |
| **A2-R** | | Opus | Review A2 | A2 |
| **A3** | | Opus | `_compose` three-arm rule; delete `_CallerHoldingPrecondition` + `principal_extraction_bound`; integrate A1+A2 and run the suite. **Hits §9.** | A1, A2 |
| **A3-R** | | Opus | Review A3 | A3 |
| **CAP-A** | | **Fable** | Capstone over the integrated Phase A branch: §9 gate, invariants, all 40 entries, subsumed parity | A3-R |
| **B1** | | Opus | Narration sweep: every data-claim string derived or deleted, per V0-b's classification | CAP-A |
| **B1-R** | | Opus | Review B1 | B1 |
| **B2** | | Opus | `destination_predicates` + `composed_selector_tie` per V0-b's rulings, **and the remeasure**: prove **no surviving instance** of either pattern (unnamed execution; constant data-claim). ⚠ **U4's `ceiling` arm is NOT in this unit** — see below | CAP-A |
| **B2-R** | | Opus | Review B2 | B2 |
| **CAP-B** | | **Fable** | Capstone over the full branch: the defect pattern is gone, Phase A numbers byte-identical, docs + PR body updated, deferrals registered. **Exit criterion: the §0 untrack step is executed and both verifications pass** — `git ls-files` names none of the five specs, and all five still exist on disk | B2-R |

**15 subagent UNITS** (13 Opus, 2 Fable), plus you as the Fable orchestrator. ⚠ **Units ≠ spawns:**
the 6 review units may each run up to 3 rounds, so budget **up to 18 review spawns** and ~27 total.

**Unowned scope — assign before Wave 1.** No unit currently owns `site/`, yet A1/A3 change
`value_at_stake_bound_direction` and delete published fields the page reads. Give `site/` to A3
(it owns the fold's output shape) or cut a separate unit. ⚠ And note the frontend gate is
**vacuous as written**: `site/src/test/fixtures/score_etherfi.json` is `1.0.1-provisional`,
λ 54.7638, and carries **no `reach_composed_magnitudes`** — `npm test` cannot see any of this work
until that fixture is regenerated. Regenerating it is part of whoever owns `site/`.

**B1's scope is 17 paths minus what A3 already deleted** — `caller_holding_precondition.reading`
appears twice in the 17 and A3 removes the whole block, so B1 inherits **15**, not 17. Confirm the
count against the post-Phase-A document rather than this number.

**⚠ U4's `ceiling` arm belongs to Phase A, not Phase B.** Once WITHHELD-12's figures are gone, four
rows lose every composed figure and `ceiling_entities` empties on them — that **moves numbers**.
Parking it in Phase B would violate Phase B's own byte-identical gate. **Assign it to A3**, and have
V0-b rule its behaviour (ruling 6), per §12's ownership list.

**⚠ A1 / A2 / A3 are NOT file-disjoint** — an independent review measured the collision. `fold.py`
is touched by all three, and `_compose` (:2556-2754) abuts `_instance_contributions` (:2755), which
A1 edits for the F5 work. **Do not run them as three independent worktrees and merge.** Partition:
`services/effects/` is A1-only and `planes.py` is A2-only (genuinely disjoint); for `fold.py`,
**A3 rebases onto A1 rather than merging**, and A2's `fold.py` join site must be a new function A3
calls, not an edit inside `_compose`. Assign each unit **disjoint new test modules** — a shared
`tests/test_scoring_redteam.py` region is a guaranteed three-way conflict for A3, who is also the
integrator.

**Two capstones rather than one, deliberately.** Phase A's gate is *numeric* (hit λ 73.2508 exactly);
Phase B's is *claims-only* (nothing moved, no pattern survives). Conflating them makes attribution of
any movement ambiguous — which is precisely how the earlier runs on this branch lost track of what
moved what.

---

## 12. Open rulings — Wave 0 produces these, implementation consumes them

1. **The deletability definition.** Which `(selector, target)` pairs constitute control of a gating
   authority? Must the authority be the one the destination actually consults (resolved on-chain),
   or does naming the host suffice? What `membership_quality` is required? How does an unresolvable
   authority fail?
2. **The published shape of the execution record.** Field names; which arguments decoded vs raw; how
   `input_seeded` rides (absorbing E4); what the entry publishes when the transcript is unfetchable.
3. **F5's scope.** Do the four `>=` rows flip? Does `ceiling_entities` need to learn about
   attribution generally, and does that reclassify rows beyond those four?
4. ~~**Confidence.**~~ **STRUCK** — resolved in §9.1: `confidence_pct` binds on `value_priced_pct`
   and `refused` feeds none of the four terms, so it does not move. What A3 must instead report is
   `reach_magnitude_witnessed_pct` (37.9 → ?) and `reach_magnitude_witnessed_of_reaching_pct`
   (26.5 → ?). **Owner: A3**, as reporting, not as a ruling.
5. **The `proven_exact` replacement token.** Name it, and rule what it does at `fold.py:2830` (which
   refuses non-exact magnitudes over ≥2 keys — zero live calls today, but a 2-key **$28.1M**
   `withdraw` signal sits unscored in the DB) and at `def _reach_rank` **`distill.py:1303`** /
   `bound_rank` **:1305** (:1225 is only a call site).
6. **The three §8 surfaces**: `destination_predicates`, `composed_selector_tie`, U4's `ceiling` arm.
7. **The field-description vs data-claim line**, applied to all 42 paths, with the rule stated
   crisply enough that a future field can be classified without re-litigating it.
8. **Corpus reach. Owner: V0-a. This ruling is UNANSWERABLE with the evidence available and you
   must not attempt to answer it** — only protocol 1 exists locally (§4 trap 19). Deliver instead:
   (a) the conditions a second protocol would have to satisfy before the three-arm rule is trusted
   beyond this vault family, and (b) the mandatory requirement that an unrecognised route fails to
   `not_determined`, never to an arm. Answering (a) affirmatively from this corpus is a failed
   deliverable.

**Ruling ownership (authoritative — this list wins over any scope cell above):** rulings 1, 2,
3, 5, 8 → **V0-a**; rulings 6, 7 → **V0-b**; ruling 4 is struck
(see above). Every ruling must have a named consumer unit before Wave 1 starts.

---

## 13. Verification commands

```bash
docker compose up postgres minio minio-init -d          # once

# ⚠ run_tests_fast.sh and local_perf_xdist.py are LOCAL-ONLY and UNTRACKED (.git/info/exclude),
# and pytest-xdist lives in .venv only (not uv.lock) — so they are ABSENT in every worktree.
# In a worktree, or on any fresh clone, use the serial command CI itself runs:
set -a; source .env; set +a
PSAT_LLM_STUB_DIR=tests/fixtures/scope_extraction/llm_responses \
  uv run pytest -m "not live" -q                        # full offline suite, serial
PSAT_LLM_STUB_DIR=tests/fixtures/scope_extraction/llm_responses \
  uv run pytest -m "not live" -q tests/test_scoring_redteam.py

# Only in the main checkout, where the local helpers exist:
./run_tests_fast.sh                                     # exports its own env — do NOT source .env
./run_tests_fast.sh tests/test_scoring_redteam.py

uv run ruff format --check <files>
uv run ruff check <files>
uv run pyright <files>
cd site && npm test -- --run                            # see §11's vacuity warning first
npx playwright test e2e/visual-baseline.spec.js         # the badge or band moves
# NOTE: the vitest fixture is stale and cannot see this work until regenerated — §11

set -a; source .env; set +a
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/before.json   # ONCE, from the tip
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/after.json
uv run python -m services.scoring.cli differential --protocol 1 --against /tmp/before.json
# ...and an exact node-level JSON diff for claim-only changes (trap 7)
```

---

## 14. Regression cases (assert in a NEW per-unit test module, never a shared region of
`tests/test_scoring_redteam.py` — §11's disjoint-modules rule)

1. **The route is compared, not assumed.** A magnitude proven by a direct call, claimed through a
   wrapper, withholds under the typed reason; the same magnitude claimed on the direct path
   publishes.
2. **The gate still transfers.** A caller-matched, route-mismatched entry keeps its gate claim and
   loses only its figure.
**3a. NEGATIVE ARM — a 1-hop chain with NO deletability row must NOT republish.**
Fixture: a composed candidate whose `act_as_chain` has **length 1**, whose destination carries a
`flow.out` magnitude, and for which the deletability join returns **no** `function_principals` row
naming the row's principal on any of `setUserRole` / `setRoleCapability` / `setAuthority` /
`transferOwnership` for the gating authority or the host.
Must take: **arm 2** (withhold). Must publish: the gate claim, the execution record, and the typed
refusal (`destination_amount_is_authored_by_the_intermediate` or
`destination_callee_is_restricted_by_the_intermediate`, whichever the traversed body earns).
Must NOT publish: `published_usd`, or any republished direct path.
**This is the anti-hop-count case.** A hop-count implementation republishes it (length == 1) and
fails. A deletability implementation withholds it and passes. **This fixture is the only thing in
the plan that distinguishes the two.**

**3b. POSITIVE ARM — a 2-hop chain WITH a deletability row MUST republish.**
Fixture: `act_as_chain` of **length 2**, otherwise identical, but the join **does** return a
qualifying row. Must take: **arm 3** (republish as the proven direct path). Must publish:
`published_usd`, the execution record, and the deletability basis (setter selector +
`function_principals` row id).
⚠ **This shape has no instance on this corpus** — all 12 hop-2 entries are non-deletable and all 28
hop-1 entries are deletable, which is exactly why the corpus gate cannot discriminate. **Construct
it synthetically**; do not wait to find one.

Both arms are **mandatory**. A unit that hits §9.1's numbers without 3a and 3b passing has not
demonstrated compliance, and the reviewer must fail it on that basis alone. A fixture that asserts
only that the code ran, without asserting the arm taken and the fields published, is decorative and
does not count.
4. **No exact from attribution.** An attribution-derived magnitude publishes neither the exact token
   nor `proven_floor`.
5. **No `>=` on a bound.** A row whose contributions are attribution-derived does not carry the floor
   prefix on coverage grounds alone.
6. **Refusals are typed.** A withheld entry increments `refused` and publishes its typed reason. It
   does **not** move `confidence_pct` — asserting that it does is a false proposition (§9.1).
7. **Subsumed parity.** Every case above holds on a subsumed row, not only a findings row.
8. **No constant data-claim.** A string asserting something about a row's data differs between two
   rows whose data differs. (Phase B)

---

## 15. Key file map

**All anchors below were verified against `c9f2713e` by an independent review.** Corrections from an
earlier draft are marked ⚠ — if you are working from a copy that cites the old numbers, this table
wins. Still: verify before you trust, and report any that have drifted.

`services/scoring/fold.py` — `_CallerHoldingPrecondition` **:183**, state literal **:218**,
`principal_extraction_bound` literal **:399**, `_DestinationMagnitude` **:2491**,
`_destination_magnitudes` `def` **:2499** ⚠ (:2500 is its docstring), `_caller_holding` **:2528**
(body :2528-2554), `_compose` **:2556** (body :2556-2754, called **:2231**),
`_instance_contributions` **:2755** ⚠ — **`from_ceilings` is NOT at :2755**; it is bound at **:2246**
and read at **:2272**; contributions loop → `ceiling_entities` **:2264-2273**; `_bound_direction`
**:1986** (body :1986-2027, call site **:1670**), `_ceiling_bearing_basis` `def` **:2030** ⚠,
`ceiling_entities` **:2139**, non-exact ≥2-key refusal **:2830**, `band = K.band(value_usd)`
**:1705** ⚠, `confidence` `min()` **:3861**, `_confidence` `def` **:3628**.

`services/scoring/distill.py` — `_flow_reach` **:766**, `VALUE_BOUND_EXACT` / `proven_exact`
**:790** and **:793**, gate publication **:1150**; `_reach_rank` — **:1225 is a CALL SITE** ⚠; the
logic §12 ruling 5 must rule on is `def _reach_rank` **:1303** and `bound_rank` **:1305**.

`services/scoring/planes.py` — `load_value_plane` **:407**, `sheet_state` **:165**, `total` **:189**,
`DestinationPredicates` **:1281**, `load_act_as_plane` / `destination_acl` (unanchored).

`services/effects/` — `recipes._add_reach` **:1545** (body :1545-1808); **attribution loops start at
:1683 / :1684 / :1686** ⚠ (the previously cited :1636-1690 lands in docstring prose);
**`input_seeded` is set at :423, :653, :691, :1060, :1275** ⚠ (:697-700 is `contract_balance_seeded`);
`SimCall(from_addr=…)` **:617**; `calldata.py:87 ARG_AMOUNT`; `harness.record_calls` `def` **:228** ⚠,
`_result_dict` `def` **:244** ⚠; `simulate.SimLog` **:41-48**, **`SimCallResult` :49** ⚠ with its
`logs` field at **:55**, `transfers_out` **:86**; `seeding.py`; `config.py:152-153` (only
`proven`/`unknown` verdict states).

`db/models.py` — `SessionLocal` lives here (not in a `db.session` module); `EffectVerdict` **:2666**, `__table_args__` **:2705** / `UniqueConstraint` **:2706**
(name at :2711), `effect_behavior_cache` (`class EffectBehaviorCache`) **:2581**.

`site/` — `src/score/derive.js`: **`BOUND_DIRECTIONS` at :107** ⚠ and the **silent-null at :120** ⚠
(`BOUND_DIRECTIONS.includes(direction) ? direction : null`); :114 is merely the field read.
`src/score/Deductions.jsx:132` (`BoundBadge` def) / **:217** (call site).

`tests/test_scoring_redteam.py` — literals pinned at **3987**, **4649**, **5784**; direction at
**2619/2658/2688/2716**, **3988**, **4018**, **4054**.

---

## 16. Deferral register (carried, not addressed here)

- **The magnitude is still attribution.** The 28 surviving entries will be honest about their
  execution and **still not floors** — whole-balance figures off 1-wei probes.
- **Adversarial-argument re-probe** — the only route to a genuine worst-case floor: on a deletable
  row there is no gate left to trip, so `setUserRole(self,N,true)` then
  `exit(to=self, assetAmount=<balance>, shareAmount=0)` executes and its log carries a real number.
  Tier-1, **754.5 ms/probe**, ~2 min for the population. Blocked on **stage order** — the fold
  computes which principal to impersonate after effects runs. Registered, not scheduled.
- **Pricing coverage** — $58,364,959.08 across the six `manage`-destination entities (5 addresses)
  with **120 of 172 rows unpriced**. A larger
  determinant of the published figure than anything in this handoff.
- **Transcript logs are dropped** (`harness.py::_result_dict`) — one function, and it forecloses
  every future log-derived question.
- **E6** — `observed_reach_value_usd` is balance attribution, not a call magnitude.
- **Holder witness** — deferred a third time.
- Everything in `COMPOSITION_WITNESS_SHAPE_SPEC.md` §11.2 not resolved here, unchanged.

---

## Appendix A — verbatim reproductions

These were executed by the author against `c9f2713e` and reproduced the stated figures. Provenance
is marked: **[ran]** = the author executed exactly this; **[subagent]** = measured by a subagent and
not independently re-run, so treat the method as a sketch and expect to refine it.

**A.1 — C7, the Safe's authority control. [ran]**

```sql
-- q1: controls the RolesAuthority that gates exit  [reproduces exactly]
SELECT c.address, c.contract_name, ef.function_name, fp.address AS principal, fp.resolved_type
FROM function_principals fp
JOIN effective_functions ef ON ef.id = fp.function_id
JOIN contracts c ON c.id = ef.contract_id
WHERE lower(c.address) LIKE '0x402dff43%'
  AND ef.function_name IN ('setUserRole','setRoleCapability');
-- → 0xcea8039076e35a825854c5c2f85659430b06ec96 (safe) on BOTH, at RolesAuthority 0x402dff43b4f2…

-- q2: controls the vaults directly. SCOPE THIS or the result is meaningless.
SELECT c.address, c.contract_name, ef.function_name
FROM function_principals fp
JOIN effective_functions ef ON ef.id = fp.function_id
JOIN contracts c ON c.id = ef.contract_id
WHERE lower(fp.address) LIKE '0xcea80390%'
  AND ef.function_name IN ('setAuthority','transferOwnership')
  AND lower(c.address) IN (  -- the five exit-destination vaults, named explicitly
    '0x917cee801a67f933f2e6b33fc0cd1ed2d5909d88','0xbc0f3b23930fff9f4894914bd745ababa9588265',
    '0xca8711daf13d852ed2121e4be3894dae366039e4','0xeda663610638e6557c27e2f4e973d3393e844e70',
    '0x352180974c71f84a934953cf49c4e538a6f9c997')
GROUP BY 1,2,3 ORDER BY 1,3;
-- → setAuthority + transferOwnership on each of those five
```

⚠ **Two corrections a review caught in an earlier draft of q2, both instructive:**
`principal_type = 'controller'` is a **tautology** — it is true on **28,689 of 28,689** rows, so it
filters nothing and any join relying on it (A2's, notably) **fails open**. And *unscoped*, q2 returns
**144 rows / 72 contracts / 12 BoringVaults** — the Safe controls far more than five vaults. The
"five" are specifically the five `exit`-destination vaults of C8, named above; the "six" of C19 are a
**different, disjoint** set of `manage`-destination entities. **Never write "the five vaults" without
the address list.**

Schema traps met here: `function_principals` has **`address`**, not `principal_address`, and has **no
`membership_quality` column** — it lives at `details->>'membership_quality'`, domain MEASURED as
`{lower_bound: 26493, exact: 2196}` (§12 ruling 1 needs both facts); `effective_functions` has **`deployment_address`** (often NULL) and
joins to `contracts` via `contract_id` — join through `contracts` for the address.

**A.0 — binding `DOC`. [ran]** The snippets below read a scored document. Regenerate it from the
tip rather than hunting for a stale copy:

```bash
set -a; source .env; set +a
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/doc.json   # DOC=/tmp/doc.json
```

Check it against trap 17 (λ 62.3179 / $19,438,110.14 / 18.6 / 99.55) before trusting anything
derived from it. Verified: A.2 and A.3 reproduce on a freshly regenerated file.

**A.2 — the population split (40 = 19 findings + 21 subsumed). [ran]**

```python
import json; d = json.load(open(DOC))
f  = d['findings']
sub = d.get('provenance', {}).get('subsumed_rows') or []
nf  = sum(len(x.get('reach_composed_magnitudes') or []) for x in f)
ns  = sum(len(x.get('reach_composed_magnitudes') or []) for x in sub)
# → findings 4 rows / 19 entries; subsumed 6 rows / 21 entries; TOTAL 10 / 40
```

**A.3 — C3 and C15, constant strings. [ran]**

```python
# C3: one distinct reading across all 40 entries
reads = {e['caller_holding_precondition']['reading']
         for r in f + sub for e in (r.get('reach_composed_magnitudes') or [])}
# → len(reads) == 1, len of the string == 1222; 28 exit / 12 manage

# C15: how widespread the pattern is — group every reading/note by its JSON path
from collections import defaultdict
vals = defaultdict(list)
def walk(o, path):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ('reading', 'note') and isinstance(v, str): vals[path + '.' + k].append(v)
            else: walk(v, path + '.' + k)
    elif isinstance(o, list):
        for x in o: walk(x, path + '[]')
walk(d, '')
# ⚠ the len(v) > 1 qualifier is LOAD-BEARING — without it you get 37, not 17.
# A path with a single occurrence is trivially "constant" and means nothing.
constant = sum(1 for k, v in vals.items() if len(set(v)) == 1 and len(v) > 1)
# → constant == 17, len(vals) == 42
```

**A.4 — C14, main's figures. [ran]**

⚠ **DO NOT `git checkout main` in the main working tree.** Once §0 has committed the five governing
specs to the branch, checking out `main` — which does not have them — **deletes all five from disk**,
including this handoff, until the restore line runs. Use a throwaway worktree instead:

```bash
git worktree add /tmp/psat-main main               # 7b893396
docker compose up postgres minio minio-init -d
set -a; source .env; set +a
(cd /tmp/psat-main && uv run python -m services.scoring.cli score --protocol 1 --out /tmp/main_score.json)
# → grade_lambda 54.1614, grade_exposure 71.7, confidence_pct 20.8, 54 of 82 rows priced,
#   row-sum $22,096,832,609.90, entity-deduped (max per entity) $4,332,693,901.30
git worktree remove /tmp/psat-main                  # a worktree YOU created — safe to remove
```

There are **no migrations** on the branch absent from main, so the schema is identical and scoring
main against this DB is safe. The `grade_exposure 71.7` and "54 of 82 priced" above are **expected
output** of this recipe, not independently sourced figures — treat them as what you should see.

**A.5 — the confidence formula. [ran]**

```bash
sed -n '3861p' services/scoring/fold.py
# → "pct": min(reach_pct, capability_pct, priced_pct, magnitude_pct),
grep -n "refused" services/scoring/fold.py | sed -n '1,20p'   # none of the four terms reads it
```

**A.6 — C1/C2, the transcript route comparison. [subagent]**

⚠ Bucket is `ARTIFACT_STORAGE_BUCKET=psat-artifacts` (`.env:26`), and **`artifacts.data` is JSON
`null` on all 379 rows** — the body is in object storage, never the column. Round 1 lost an hour here.

Resolve `effect_verdicts.transcript_ptr` (format `"{job_id}::{artifact_name}"`,
`workers/effects_worker.py:580-583`) → `artifacts (job_id, name)` → MinIO body via the stored
`storage_key` (per-job prefix, `pr-162/` on this data — **read the column, never construct the
key**). Blob top-level keys on the 60 proven `value_out`: `feature, version, tier, effect_class,
chain_id, block_number, hardfork, anvil_version, foundry_version, calls, results, block_source`
(+ `seeding, seed_attempts, input_seeded, contract_balance_seeded` on 23). Compare each `calls[].to`
/ `.from` / selector against the entry's `act_as_chain[-1]`. **135/135 blobs fetched, 0 errors, 0
containing `logs`/`topics`.**
