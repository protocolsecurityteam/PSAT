# Composition Witness Shape — Scope, Spec & Orchestration

**Status:** scope + spec + orchestration runbook (§9). Nothing implemented. **Wave 0 is an
investigation** whose rulings the implementation waves consume — do not skip it.
**Written:** 2026-08-06 against the local etherfi snapshot (`protocol_id 1`, DB on port 5433),
branch `fix/confidence-perimeter-admission` at `a9348f32` (model `1.1.0-provisional`, PR #169).
**Companion to:** `REACH_MODEL_FIX_SPEC.md` — this is a **bug fix to what that spec shipped**, not
a new capability. It lands on the same branch, before `CODE_CONTROL_MAGNITUDE_SPEC.md` (a feature).

Every figure below was reproduced read-only against that snapshot. Extrapolations are labelled.
Verdicts are CONFIRMED (evidence reproduced) or OPEN (needs a Wave-0 ruling).

---

## 0. The one-paragraph diagnosis

The reach-model fix correctly stopped the scorer pricing reach with balance sheets nobody proved
could be moved, and replaced it with a two-witness composition rule: the destination function's own
fork-proven `flow.out` magnitude, gated on an **act-as witness** that the seized node can be made to
call it. The act-as witness admits exactly one shape — *the caller's own state variable, read
on-chain, holding the destination's address*. That shape is correct for one call pattern and
**structurally unsatisfiable for another**: when a contract takes its callee as a **function
parameter**, the binding cannot live in the caller's storage, because the caller picks the target at
call time. For those call sites the binding lives on the *destination* side — in the destination's
own access-control list, which the pipeline already resolves and stores in `function_principals`.
The plane never looks there. A second, independent refusal (`GateGrant`'s same-kind bound) then
rejects the *next* hop even though its pointer **is** a state variable resolved on-chain, because it
compares the kind of variable the gate rewrites against the kind of variable the hop traverses. The
net effect on the audit's own headline cluster: a chain whose every link is witnessed in the
database publishes `not_determined`, and the correct number — **$2,229,837.61**, the figure the
pre-fix document published for that cluster — is discarded.

**The fix is scorer-only. No new pipeline capability, no new extraction, no re-analysis.** Both
witnesses are already extracted, stored, and loaded by the scorer for other purposes.

---

## 1. Findings register

### 1.1 The chain under test

The audit's headline cluster (`REACH_MODEL_FIX_SPEC.md` §1.1, §9.5 cases 1–2):

```
EOA 0xf8553c85  --authority.replace-->  AtomicSolverV3 0x98946898
                                              |
                    (restricted fns: redeemSolve 0x839799fd, finishSolve 0x2ddd62ce)
                                              |
        link 1:  solver --bulkWithdraw 0x3e64ce99-->  Teller        [callee is a PARAMETER]
                                              |
        link 2:  teller --vault pointer-->            BoringVault   [callee is a STATE VARIABLE]
                                              |
                                     the money lives here
```

Tellers and queues hold **no value** (`sheet_state == no_rows`, `total() is None`) — they are
routers. A failure at link 1 therefore costs the entire chain, because the value is one hop past it.

### 1.2 CONFIRMED defects

**B1 — `ActAsPlane` consults only the caller's storage, so a parameter-bound receiver can never be
witnessed.** `planes.py` `load_act_as_plane` requires an `effective_functions.sinks` entry with
`receiver.binding == "state_variable"` plus a `controller_values` row resolving that variable to the
destination. Measured on AtomicSolverV3's real sinks:

| function | openness | calls | receiver.binding |
|---|---|---|---|
| `redeemSolve` `0x839799fd` | restricted | `solve` `0xd93fc203` | **parameter** |
| `finishSolve` `0x2ddd62ce` | restricted | `bulkWithdraw` `0x3e64ce99` | **not_determined** |
| `setAuthority` `0x7a9e5e4b` | restricted | `0xb7009613` | `state_variable` ← the one that composes |

Published refusals on the finding: `call_site_receiver_is_not_a_state_variable` — 6 on
`ethereum::0xf8553c85`, 4 on `base::0xf8553c85`; plus
`no_function_of_the_caller_calls_this_selector` 5 / 1.

**The destination-side witness exists and is unread.** `function_principals` (joined through
`effective_functions`) records AtomicSolverV3 as a `controller` principal of:

| destination | contract | function | selector | roles |
|---|---|---|---|---|
| `0x99de9e5a` | TellerWithMultiAssetSupport | `bulkWithdraw` | `0x3e64ce99` | `[12]` |
| `0x417e1ef6` | TellerWithMultiAssetSupport | `bulkWithdraw` | `0x3e64ce99` | `[12]` |
| `0xc8c58d15` | TellerWithMultiAssetSupport | `bulkWithdraw` | `0x3e64ce99` | `[12]` |
| `0xa55a34d3` | TellerWithMultiAssetSupport | `bulkWithdraw` | `0x3e64ce99` | `[12]` |
| `0x63ede83c` | TellerWithMultiAssetSupport | `bulkWithdraw` | `0x3e64ce99` | `[12]` |
| `0x7c12c550` | AtomicQueue | `solve` | `0xd93fc203` | `[78]` |

(plus `bulkDeposit` `0x9d574420` at the same tellers). This is the destination stating *"I accept
this caller for this selector under this role"* — precisely the binding the parameter-bound call
site cannot supply. CONFIRMED.

**B2 — the same-kind conferral bound refuses a hop whose pointer is independently resolved
on-chain.** `fold.py` `_hop_bound` / `GateGrant.confers` walks a `state_var`-labelled hop only when
the gate's own witnessed function writes a variable of that name. The published basis on the
withheld hops of `ethereum::0xf8553c85` reads:

> *"authority.replace is witnessed rewriting ['authority'] on its own contract and not 'vault', so
> this hop runs on an authority of a different kind from the one the gate seizes."*

But `controller_values` resolves every Teller's `vault` pointer by `eth_call`, `resolved_type =
contract`:

```
0x417e1ef6 --vault--> 0x35218097   0x99de9e5a --vault--> 0x917cee80
0xc8c58d15 --vault--> 0xbc0f3b23   0xa55a34d3 --vault--> 0xeda66361
0x63ede83c --vault--> 0xca8711da   0x4de413a2 --vault--> 0x08c6f91e
```

The bound conflates *what the gate rewrites* with *what the seized node can then reach*. The gate
does not need to rewrite `vault`; it makes the solver **act**, and the solver follows its own,
independently witnessed pointer. CONFIRMED. (Note W4a's conferral map already names two of these
vaults directly — `0x35218097` and `0x917cee80` with `exit`/`enter` — so the role trace resolved
the vault-level capability too.)

**B3 — the consequence: the correct number is discarded.** Summing the five vaults reachable through
the witnessed ACL:

| teller | vault | sheet |
|---|---|---|
| `0x99de9e5a` | `0x917cee80` | $1,837,405.19 |
| `0x63ede83c` | `0xca8711da` | $216,831.12 |
| `0xc8c58d15` | `0xbc0f3b23` | $93,528.16 |
| `0x417e1ef6` | `0x35218097` | $57,028.58 |
| `0xa55a34d3` | `0xeda66361` | $25,044.56 |
| | | **$2,229,837.61** |

**That is exactly the exposure the pre-fix document published for this cluster**
(`REACH_MODEL_FIX_SPEC.md` §1.4, H1: *"$2,229,837.61 with and without the back-edge"*). The old
system reached the right number by the wrong method — summing whole sheets, which for these five
happened to be small vaults. The new system correctly refused the wrong method and then lost the
right answer. CONFIRMED.

**B4 — one-link failure costs the chain, because routers are unpriced.** All tellers and queues
return `sheet_state == no_rows`. Composition that dies at link 1 therefore recovers $0, not "the
teller's value". CONFIRMED.

### 1.3 Where this leaves the published document today

| row | rank | raw | value | exposure | why |
|---|---|---|---|---|---|
| `ethereum::0xf8553c85` `authority.replace` | #6 / 27 | 6.075 | `not_determined` | `null` | B1 + B2 |
| `base::0xf8553c85` `authority.replace` | #4 / 27 | 6.075 | `not_determined` | `null` | B1 + B2 |
| `ethereum::0x2322ba43` `authority.replace` | #5 / 27 | 6.075 | `not_determined` | `null` | **correctly** refused — see below |

`0x2322ba43` is a different case and **must stay refused**: `finishSolve` pins its caller to the
destination itself (`initiator != address(this)`), which D2's condition plane correctly reads as a
disproof; its reach collapsed 22 → 1 with 21 entities published as withheld behind that hop. This
fix must not resurrect it.

---

## 2. Root cause per defect

| defect | root cause | locus |
|---|---|---|
| B1 | the act-as witness admits one shape; the other shape's evidence lives on the destination and is unread | **fold/planes** — `ActAsPlane` gains a second admissible witness |
| B2 | the conferral bound tests the gate's rewrite kind against the hop's variable kind, rather than asking whether the hop's pointer is itself resolved | **fold** — `GateGrant.confers` |
| B3 | consequence of B1 + B2 | — |
| B4 | not a defect; the reason a partial fix yields nothing | — |

**Neither link alone yields a dollar.** Fixing B1 without B2 stops at a teller holding nothing;
fixing B2 without B1 never reaches the teller. Plan the gates accordingly (§6, §9.3).

---

## 3. Proposed model change

### 3.1 A second admissible act-as witness: destination-side acceptance

Admit a step `(N → D, selector s)` when **either**:

- **(existing, unchanged)** N's own state variable `v` is witnessed calling `s`, and `v` is read
  on-chain holding `D`; **or**
- **(new)** N's call site for `s` exists but is **parameter- or not_determined-bound**, *and* `D`
  independently witnesses N as a principal of `s` — a `function_principals` row for `D`'s function
  with `selector == s` and `address == N`, carrying the role that admits it.

Rationale to hold: a parameter-bound receiver means *the caller chooses the target at call time*.
The principal, having seized N's gate, **is** the caller. What bounds the choice is not N's storage
— it is which destinations will accept N. That is exactly what the destination's ACL records.

Requirements, all of which must be published:

1. the call site must still exist — N's code must actually call `s` (`no_function_of_the_caller_calls_this_selector` remains a refusal);
2. the calling function must still be `restricted` and gated by the authority the finding seizes
   (the existing third conjunct — unchanged);
3. the destination-side row must be protocol- and chain-scoped, matching `entity_key` discipline;
4. absence of a destination-side row is a **refusal**, not an admission — a new typed reason.

### 3.2 The conferral bound stops refusing independently-resolved pointers

`GateGrant.confers` currently refuses a `state_var` hop whose variable the gate does not rewrite.
Narrow the refusal: it should fire when **nothing witnesses where the hop leads**. When the hop's
variable is resolved on-chain in `controller_values` (`resolved_type == contract`, an accepted
observation kind), the hop's destination is a witnessed fact and the gate's rewrite-kind is
irrelevant to *where it goes* — what the gate governs is whether the seized node can be made to act,
which is the act-as question, answered separately.

Keep the same-kind bound where it still does real work: an unresolved or unlabelled hop stays
`not_determined`. Publish the count that moves from refused to walked.

### 3.3 Magnitude stays two-witness

Nothing here relaxes the magnitude rule. Once both links open, the existing Phase 6 machinery
attaches the **destination's own `flow.out` witness**, capped per R4 (`min` against the destination's
determined sheet, no sum-over-keys inflation). Where the destination carries no witness the magnitude
stays `not_determined`.

### 3.4 The 2-hop chain question comes due

W4b's reviewer registered *"chain length ≥ 2 is unsound by omission"* as latent — all 13 composed
chains on p1 are length 1. **This fix creates the first live 2-hop chain** (solver → teller → vault),
so that deferral must be resolved here, not carried. The concern: the step at hop *k+1* requires a
restricted, authority-delegated function of the **intermediate** node, and nothing yet witnesses that
the principal controls the intermediate's authority — only that it can cause the intermediate to
receive one call. Wave 0 must rule on what makes a multi-hop chain sound, and the rule must be that
**every hop is independently witnessed; no hop inherits its predecessor's authority**.

---

## 4. Invariant impact

| invariant | verdict |
|---|---|
| **1** three-valued logic | **PRESERVED** — this admits a second *witness*, not a second guess. Absence of the destination-side row is still `not_determined`. |
| **6** monotone in resolution work | **PRESERVED and repaired** — evidence the pipeline already produced now raises the answered fraction instead of being ignored. |
| **9** exact decomposition | **CHECK** — every regained dollar must trace: seized gate → restricted calling function → destination ACL row (role + selector) → resolved pointer → destination `flow.out` witness. Publish the whole chain per entry, as W4b does today. |
| **13** anti-gaming | **CHECK and argue** — the fix *raises* charges, so the gaming direction is unchanged, but confirm a protocol cannot suppress a destination-side ACL row more cheaply than it can suppress a storage pointer. |
| **16** no abstraction above a witness | **ENFORCED** — the published basis must say which of the two witness shapes admitted each step. |

---

## 5. Expected blast radius (to be measured in Wave 0, not assumed)

- `ethereum::0xf8553c85` and `base::0xf8553c85` regain a witnessed magnitude — expected ceiling
  **$2,229,837.61** on the ethereum side, subject to the share-balance ruling (§6, ruling 3).
- `ethereum::0x2322ba43` must remain `not_determined`.
- λ, `grade_exposure`, `exposure_usd`, `confidence_pct` and the
  `reach_magnitude_witnessed_of_reaching_pct` progress metric all move; every delta must be
  attributed. Note these rows currently sit at `raw_points` 6.075 with `UNPRICED_BAND`; a $2.23M
  magnitude bands to `0.3–0.5`, so `raw_points` roughly doubles-to-triples and the λ ordering shifts.
- Other rows may qualify. The Wave-0 census must enumerate every `(caller, selector, destination)`
  triple that the new witness admits corpus-wide, with dollars, **before** any code is written.

---

## 6. Open rulings — Wave 0 produces these, implementation consumes them

1. **Is destination-side ACL acceptance a sufficient act-as witness?** Argue it against the
   `SCORER_DISCIPLINE_CONTRACT` and inv. 16. If accepted, state precisely what it does and does not
   prove. (Author's view: it proves the destination will accept the caller for that selector, which
   is the binding a parameter-bound call site cannot carry — but it does **not** prove the principal
   can supply the other arguments profitably. See ruling 3.)
2. **How far does the conferral bound narrow?** Only for hops with a resolved `controller_values`
   pointer, or more broadly? Measure how many hops corpus-wide move refused → walked under each
   reading, and whether any row **gains reach** it did not have before W4a (it must not — Phase 5's
   gate was "no row gains reach", and this fix must not smuggle reach back in through the magnitude
   door).
3. **The share-balance bound.** `bulkWithdraw` burns the **caller's** shares; the audit found
   `0xf8553c85` bounded to a **$0 share balance** (`REACH_MODEL_FIX_SPEC.md` §1.1). So is the honest
   magnitude (a) the destination's `flow.out` witness, (b) the vault sheet as a ceiling, or (c) a
   share-balance-bounded number requiring a holder witness the pipeline may not have? Rule, and if
   (c) is right and the witness is absent, the honest answer may be a **ceiling** with the share
   bound disclosed — not a floor.
4. **Multi-hop soundness (§3.4).** What makes hop *k+1* sound? Rule that every hop is independently
   witnessed and none inherits authority, then state how the rule is enforced in code.
5. **Does this subsume the "authority-seat" deferral?** W4b registered a separate shape — where the
   seized node *is* the destination's authority, the principal grants itself the role and calls `D`
   directly, with no act-as step. Determine whether it is the same defect, adjacent, or independent;
   if adjacent, keep it deferred and say why.

---

## 7. Deferral register (carried, not addressed here)

- **Code-control magnitude** — `CODE_CONTROL_MAGNITUDE_SPEC.md`. Larger ($4.2B vs $2.2M) but a
  *feature*; this bug fix ships first.
- **Freeze fraction** (`pause.set`) — the one genuinely new pipeline capability.
- **`exec.arbitrary` destination semantics**, conjunctive act-as gates (26 latent candidates),
  act-as calling-function conditions (105 sites, 0 firing), `event_log` as a storage-read
  observation (0 rows), exact-branch/undetermined-sheet disclosure parity, the
  `ck_protocol_scores_grade_pairing` split — all as registered in `REACH_MODEL_FIX_SPEC.md` §7.

---

## 8. What this spec deliberately does not do

It does not relax the two-witness magnitude rule, does not price reach on membership, does not
restore any balance-sheet fallthrough, and does not widen reach membership — it opens **magnitude**
on hops whose evidence already exists. If a change would make a row reach an entity it did not reach
at the branch tip, that is out of scope and must be reported, not shipped.

---

## 9. Implementation & orchestration

This section is a dispatchable runbook and follows the repo-owner's standing model: the **main loop
orchestrates only** — it never writes or reviews code — all coding goes to fresh **Opus** subagents
in isolated worktrees, all reviews go to *separate* fresh **Opus** agents, review loops cap at
**3 rounds** with the orchestrator adjudicating on exhaustion, the capstone is **Fable**, and the
branch is **pushed once at the end** of the run.

### 9.1 Aligned parameters

- **~11 agents across 4 waves:** 1 investigator + 4 coders + 5 reviewers + 1 capstone (plus ≤3
  review rounds per unit).
- **Investigator: Opus. Coders: Opus. Per-unit reviewers: Opus. Capstone: Fable. Orchestrator: the
  main loop, no coding or reviewing.**
- **Wave 0 is a blocking investigation** — its five rulings (§6) gate every later wave. It writes no
  production code.
- **Wave 2's two units are worktree-parallel** but **neither can show a dollar alone** (§2). Their
  gates are structural; the combined dollar gate is at the wave merge.
- **One batched push**, after the capstone. All per-wave verification is local.

### 9.2 Branch model

Work **directly on `fix/confidence-perimeter-admission`** — this is a bug fix to the work in PR #169
and belongs in the same PR. Cut each unit as a worktree **off the current tip** of that branch, merge
back once its gate passes; the next wave branches from the updated tip. **Every worktree prompt must
prove it is not on a stale base before writing code** — `git merge-base --is-ancestor <tip> HEAD` —
the trap being a worktree cut before the previous wave merged. Create worktrees under
`/home/riley/PSAT-wt/<unit>`; **only remove worktrees this session created.**

### 9.3 Wave / work-unit table

`F` = `services/scoring/fold.py`, `P` = `services/scoring/planes.py`, `K` = `constants.py`.

| Wave | Unit | Scope (owns) | Defects | Depends on | Gate |
|---|---|---|---|---|---|
| **0 Investigation** | W0 | no production code; read-only measurement + rulings | B1–B4, §6 rulings 1–5 | — | all five rulings argued with measured corpus evidence; corpus-wide census of `(caller, selector, destination)` triples the new witness admits, **with dollars**; a written no-reach-gain argument; hand-off consumed by W1/W2 |
| **1 Witness** | W1a | `P` `ActAsPlane` / `load_act_as_plane`: second admissible witness shape + typed refusals + census | B1 | W0 | destination-side witness admitted only under §3.1's four requirements; **zero-diff on the published document expected** (link 2 still closed) — prove it and say so; refusal census published |
| | W1b | `F` `GateGrant.confers` / `_hop_bound`: narrow the same-kind refusal | B2 | W0 | hops move refused → walked **only** where a `controller_values` pointer resolves; **no row gains reach** vs the branch tip (enumerate every reach delta, expect zero); zero-diff on dollars expected — prove it |
| **2 Compose** | W2 (serial, one coder) | `F` composition + magnitude attachment, disclosure, provenance chain | B3, §3.3, §3.4 | W1a, W1b | the §9.5 regression cases; every regained dollar traces the full five-step chain (inv. 9); multi-hop rule enforced per ruling 4; full differential attributed |
| **3 Capstone** | W3 | full integrated branch | — | W2 | see §9.6 |

W1a and W1b are parallel (disjoint file regions: `P.ActAsPlane` vs `F`'s conferral). They merge
a→b. **Expect both to be zero-diff alone** — that is the correct outcome, not a failure, and each
unit must prove its own zero-diff rather than assume it.

### 9.4 Verification commands (every gate)

Local, CI-faithful — no push until the capstone.

```bash
docker compose up postgres minio minio-init -d          # once

./run_tests_fast.sh                                     # full offline suite
./run_tests_fast.sh tests/test_scoring_redteam.py       # DB-free fold fixture

uv run ruff format --check <files>
uv run ruff check <files>
uv run pyright <files>
cd site && npm test -- --run                            # if score-page-visible fields move

# real-corpus differential — THE gate
set -a; source .env; set +a
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/before.json   # capture ONCE from the tip before Wave 1
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/after.json
uv run python -m services.scoring.cli differential --protocol 1 --against /tmp/before.json
```

Known pre-existing offline failures, unrelated to scoring, present on the tip:
`test_appendix_a_funnel_on_dev_db`, `test_event_indexer_loop_records_heartbeat`.

Scoring tests that matter: `tests/test_scoring_redteam.py` (adversarial, DB-free `fold` fixture —
write regression cases here), `tests/test_scoring_distill_fold.py`,
`tests/test_scoring_integration.py`, `tests/test_scoring_schema.py`.

### 9.5 Regression cases (W2 gate — assert in `test_scoring_redteam.py`)

1. **The chain composes.** `ethereum::0xf8553c85` regains a magnitude traced through both links —
   destination ACL row (role 12, `bulkWithdraw`) → resolved `vault` pointer → destination witness —
   bounded per ruling 3. It is no longer `not_determined`.
2. **The blocked EOA stays blocked.** `ethereum::0x2322ba43` remains `not_determined`: `finishSolve`
   pins its caller to the destination itself and D2 correctly disproves the hop. This fix must not
   resurrect a hop the condition plane refused.
3. **No reach gained.** No row reaches an entity it did not reach at the branch tip. Enumerate.
4. **The witness is required, not assumed.** A parameter-bound receiver with **no** destination-side
   ACL row stays refused, with its own typed reason.
5. **The bound still holds.** No composed magnitude exceeds its destination's own witness or its
   determined sheet (W4b's anti-composition property, re-asserted over 2-hop chains).
6. **Multi-hop soundness.** Every hop of a ≥2-hop chain is independently witnessed; a chain with an
   unwitnessed intermediate step composes nothing.

### 9.6 Capstone (W3, Fable, fresh agent over the integrated branch)

- Full differential across every local protocol (p1 is the only one — confirm by SQL), attributing
  every headline movement to a named defect.
- **Invariant sweep:** 1, 6, 9, 13, 16 preserved as §4 claims; in particular that every regained
  dollar carries its full five-step chain and that no balance-sheet fallthrough returned.
- Confirm the shipped `not_determined` population is now exactly: freeze, act-as genuinely
  unwitnessed, unwitnessed destinations, and code control (the latter deferred to
  `CODE_CONTROL_MAGNITUDE_SPEC.md`).
- Update PR #169's description to cover this fix; register any new deferrals.
- Text-only write authorization (spec addenda, disclosure corrections); any code-level defect is
  reported, not fixed.

### 9.7 Guardrails (hand to every coder and reviewer verbatim)

- **The DB is READ-ONLY.** SELECT only, port 5433. Never write a row. Create your own
  `psat_test_<unit>` database for DB-backed tests; that is the sole exception.
- **No commit without explicit owner authorization for the push; no Claude attribution
  trailers/footers.**
- **A green suite proves little** — the golden corpus only pins fields it happens to contain.
  **Measure every change on the real corpus with `cli differential`** and report ADDED / CHANGED /
  REMOVED. A zero-diff is only meaningful if you prove *why* it is zero.
- **Do not widen reach.** This fix opens magnitude on witnessed hops. Any reach delta is a finding to
  report, not a result to ship.
- **Neither Wave-1 unit can show a dollar alone.** Prove your zero-diff; do not chase a number that
  cannot appear until the other unit lands.
- **Source-fetch trap:** `source_files.storage_key`'s trailing hash derives from the *path*, so the
  same path in two jobs collides under different content. Fetch a contract's source from **its own**
  `job_id` — AtomicSolverV3's bundle vendors an obsolete un-Auth'd AtomicQueue.
- **Worktree base check** (§9.2) before writing; only remove worktrees this session created.
- **Reviews go to fresh agents**, capped at 3 rounds; the orchestrator adjudicates on exhaustion.
- **Trust a subagent's reported pass counts** — do not re-run its suite to double-check.
- **Batch the push** — one push after the capstone.

---

## 10. Addendum — what shipped (capstone, 2026-08-06)

Recorded by the W3 capstone over the integrated branch (`ab89125f` W1a, `848ffcac` W2, on
`fix/confidence-perimeter-admission`). Every figure below is from the final full-corpus run
(`services.scoring.cli score --protocol 1`) diffed row-by-row against the tip baseline
(`a9348f32`), and cross-checked against the Wave-0 rulings, which override this spec where
they conflict.

### 10.1 What shipped

**W1a (`planes.py`).** The second admissible act-as witness of §3.1, under ruling 1's four
conjuncts: a parameter-bound call site of a restricted, authority-delegated function composes
with a `function_principals` row on the destination naming the caller for that selector with an
enumerated (`membership_quality == "exact"`) role. The step carries `witness_kind =
"destination_access_control_list"` and a basis naming the `function_principals` row id, the role
numbers, the destination function and the membership quality — never the state-variable basis
sentence. Three new typed refusals ship with it, ranked into the sharpest-shortfall order:
`destination_does_not_accept_this_caller_for_this_selector`,
`destination_access_control_row_names_no_admitting_role`,
`destination_access_control_membership_is_not_enumerable`. All three have **zero live instances
on this corpus** (measured in Wave 0 and confirmed on the shipped document); absence of the ACL
row is a refusal, never an admission.

**W2 (`fold.py`, `planes.py`).** Multi-hop composition under ruling 4: `_compose` carries, per
node, the functions each hop admitted **keyed by their own selector**, and past hop 1 the plane
is asked the narrower question (`via=`) — the intermediate's calling function must be one the
previous hop admitted, matched on that function's selector, refusing otherwise with
`intermediate_calling_function_is_not_the_selector_admitted_at_the_previous_hop`. The seized
gate is spent at seeds only. Ruling 3's disclosure ships on every composed entry:
`principal_extraction_bound: "ceiling"`, a `caller_holding_precondition` block (state
`not_determined`, the admitted caller, its sheet as context-not-bound, and the reading that a
zero spot balance proves nothing), `witness_granularity: "entity"`, `act_as_chain_length`, and
a `longest_composed_chain` census field (2 on this corpus).

### 10.2 W1b — cancelled

§3.2 and §9.3's W1b were **not implemented**, per ruling 2. Measured grounds: narrowing
`GateGrant.confers` is byte-identical on every published dollar (`state_var` CONFERRED hops
license no selector, so they compose nothing by construction) and moves 177 hops / 182
row-entity memberships across 18 rows into reach — a partial undo of W4a's conferral scoping,
violating §8's "do not widen reach". `GateGrant.confers`, `_hop_bound`, `_closure` and the
conferral constants are untouched on the shipped branch. B2 as diagnosed in §1.2 is **refuted**:
the teller→vault hops were already walked and act-as witnessed on the tip; the only missing link
was B1's.

### 10.3 The corrected headline figure

The honest composed magnitude for `ethereum::0xf8553c85 | authority.replace` is
**$1,971,291.83**, not §1.2's **$2,229,837.61**. The spec's number is the sum of five whole
vault balance sheets — the method the reach-model fix removed — and it appears nowhere in the
shipped document. The shipped figure is Σ over the five destinations of
`min(destination flow.out witness, determined sheet)`; per destination the witness bound on
four (`0x917cee80` $1,701,067.28, `0xca8711da` $99,746.57, `0xbc0f3b23` $88,418.57,
`0x35218097` $57,014.85) and the sheet bound on one (`0xeda66361` $25,044.56). The base-side
row composes $150,410.13 (sheet-bounded). Per ruling 3 every entry publishes the figure as a
**ceiling on what this principal can extract**: the `flow.out` witness fixed no caller and no
argument, and the chain's last call spends a caller-held quantity (vault shares) no witness in
this pipeline bounds — the caller-holding precondition is published `not_determined` beside the
number, and the caller's observed $0-dust sheet is context, not the bound.

Measured end state (identical to Wave 0's `doc_b1` prediction on every headline):
λ 73.2508 → 62.3179; `grade_exposure` 99.582 → 99.550; `exposure_usd` $18,059,003.86 →
$19,438,110.14 (+$1,379,106.28); newly witnessed `value_at_stake` $2,121,701.96 across 2
findings + 2 subsumed rows; `confidence_pct` 18.6 unchanged (still binds on `value_priced_pct`);
`reach_magnitude_witnessed_of_reaching_pct` 25.6 → 26.5; findings 27 → 27; rows gaining reach:
**0** (verified over all 82 rows, findings and subsumed); `ethereum::0x2322ba43` remains
`not_determined` behind the condition-plane disproof; `ethereum::0x80ce8a91` / `base::0x80ce8a91`
remain `not_determined` with `licensed_selectors == 0` and `caller_not_reachable` 21 / 5,
byte-unchanged from the tip.

### 10.4 Deferral register (supersedes §7)

Carried from §7 unchanged: code-control magnitude (`CODE_CONTROL_MAGNITUDE_SPEC.md`, ships
next); freeze fraction (`pause.set`); `exec.arbitrary` destination semantics; conjunctive
act-as gates (26 latent); `event_log` as a storage-read observation; exact-branch /
undetermined-sheet disclosure parity; the `ck_protocol_scores_grade_pairing` split — all as
registered in `REACH_MODEL_FIX_SPEC.md` §7. The act-as calling-function-conditions deferral
carried there is **widened** by (b) below.

Newly registered by this run:

- **(a) The authority-seat shape** (ruling 5): where the seized node *is* the destination's
  authority, the principal grants itself the role and calls directly — no intermediate, no
  act-as step, so the composition pass has nowhere to put it. Adjacent to this fix, not
  subsumed by it: the seat's seized node issues no external call at all (`ACT_AS_NO_CALL_SITE`,
  correctly). Pricing it needs its own two rulings (what witnesses the self-grant; what bounds
  the resulting surface). `0x80ce8a91`'s two rows stay `not_determined` until then.
- **(b) `function_principals.details.conditions` is unread at the act-as step.** The same row
  the destination-ACL witness reads for acceptance carries the destination's own business
  predicates (five on the teller row), and none are consulted — which also keeps
  `caller_holding_precondition.bound_kind` at the `"caller_supplied_arguments"` literal rather
  than the named quantity (`caller_share_balance`) those semantics would supply. The holder
  witness itself (share balance / outstanding-request depth) is the same class of missing
  evidence as the freeze fraction and is registered beside it.
- **(c) `target_constraint` witness-note pass-through** (W0 §10.7): nine of twelve vault
  `flow.out` rows carry `target_constraint = not_determined` in `witness_notes` and the note is
  dropped by composition time. It is the single fact that makes the composed figure a ceiling;
  today the ceiling claim is published (10.1) but the underlying note still does not reach
  `reach_composed_magnitudes`.
- **(d) Caller-naming calibration on `A → B(sv) → C(ACL) → D(sv)` chains.**
  `_caller_holding` names the caller the **last ACL step** admitted; on a chain whose ACL step
  is followed by further state-variable hops, the `msg.sender` at the final destination is the
  last intermediate, not the ACL-admitted caller. Calibrated on the shapes this corpus grows
  (ACL step is always last-but-one) and documented in the code as a choice, not a witness; a
  corpus growing the longer shape needs the precondition published per step.
- **(e) The same-kind conferral bound** (ruling 2's registration): it is a bound, not a
  witness — deciding a cross-kind hop needs the intermediate node's own function-surface join
  (`effective_functions` gated by the seized authority × outbound targets), not a
  pointer-resolution test.
- **(f) W0's similar-bugs appendix** — six same-shape candidates measured but not
  investigated in depth, recorded here because the Wave-0 artefacts live outside the repo:
  (1) `ActAsPlane.reads` conflates "never read" with "read, and it holds a non-contract" —
  a `zero` resolution is an earned negative the control closure already reads correctly and
  the act-as plane publishes as a coverage gap (4 live refusals); (2)
  `ACT_AS_CALL_SITE_IS_PUBLIC` is right at hop 1 and conservative-only at hop k≥2, where an
  open intermediate function is easier to reach, not harder (0 live instances; ruling 4's
  code comments name it); (3) `function_principals.details.conditions` — item (b) above;
  (4) `membership_quality` is now load-bearing in the act-as plane (the `enumerated` gate)
  but still read by no other scorer code; (5) `_compose` keeps the MAX composed figure
  across selectors at one entity with no `exposure_order_tie`-style disclosure — moot while
  the `flow.out` witness is entity-granular (every selector at a vault carries the identical
  figure, measured), live the day a corpus grows per-function witnesses; (6) the
  function-granularity implication itself, now disclosed per entry as
  `witness_granularity: "entity"` (shipped; listed for the record).

---

## 11. Addendum — second run: published claims, reasons and bound directions (capstone, 2026-08-06)

Recorded by the capstone of the second scorer witness-discipline run, over
`fix/confidence-perimeter-admission` at `c9f2713e` (`64820b92` U1, `642eccdd` U2,
`66f8b2f8`+`1dee2313` U3, `c9f2713e` U4, on top of §10's `848ffcac`). The run fixed the seven
bugs the second Wave-0 investigation (V0) ruled on: places where the scorer discarded stored
witness data, or published a reason, a basis or a bound direction the evidence contradicts.

**The gate this run was held to, and met: zero number movement.** λ **62.3179**, `exposure_usd`
**$19,438,110.14**, `confidence_pct` **18.6**, `grade_exposure` **99.55** — all byte-identical
to §10.3's end state, verified by exact node-level diff of the final document against the
`848ffcac` baseline (564 differing nodes, every one attributed to a unit below; zero dollar,
band-value, reach, census-count or points movement beyond the attributed renames). This run
repaired *published claims*, not numbers: per V0's rulings, any unit that moved a dollar had
over-reached.

### 11.1 What shipped, per unit

**U1 — the act-as read taxonomy (B1 + B4 + B3, `planes.py`).** `load_act_as_plane` stops
filtering `controller_values` on `resolved_type`: every read that returned an address is indexed
(the read and the address comparison are the witness; the classification is context), reads that
*reverted* are indexed apart in `read_failures`, and the refusal ladder is three-valued end to
end. New/renamed outcomes: `caller_state_variable_read_reverted_on_chain` (a not_determined —
the read row exists with a block and an observation kind, so "never read" was a coverage claim
the evidence disproves; 4 findings + 4 subsumed counts renamed from
`caller_state_variable_never_read_on_chain`, which now means exactly what it says),
`caller_state_variable_holds_the_renounced_zero_address` and
`caller_state_variable_holds_an_address_proven_to_hold_no_code` (two distinct proven-absents,
both 0 live — the 22 latent `zero` pairs are never asked on this corpus, as V0 measured), and
`call_site_caller_gate_openness_is_not_determined` (6 + 6 counts renamed from the sentinel
`call_site_receiver_is_not_a_state_variable`, which is retired and unreachable — the failing
conjunct was an unread openness field, not the receiver binding). Past hop 1 the delegation
conjunct is not applied — the licence there is the previous hop's admitted selector — and every
published `ActAsStep` carries `admitted_without_a_delegation_witness` saying whether that
relaxation admitted it (false on all 52 published steps: every one carries the witness anyway).
The openness conjunct is kept at every hop and the readings now state why: attribution, not
conservatism. The `frozenset(entries) or None` fail-open at the compose boundary (a non-seed
node with no admitted entries silently receiving the hop-1 question) is closed. Provenance now
publishes `state_variables_read_on_chain` (429), `state_variables_whose_read_failed` (91) and a
per-row `resolved_type` histogram — verified identical to the database (contract 265, zero 86,
safe 38, unknown 26, eoa 8, timelock 7).

**U2 — the differential (B5, `cli.py`).** `differential()` resolves the oracle's subsumed rows
from both stored shapes (top-level for the prototype oracles, `provenance` for every document
this CLI writes) and publishes which one answered (`oracle_subsumed_rows_source`, with `absent`
as a third state and an explicit count of rows ignored when both shapes are present). Matching
is identity-first on `(principal_unit, capability, access_path)`; the address-set match is a
recovery for re-keyed units only, and causes are computed against the identity twin with
`cause_computed_against` published. Gate met: a self-diff returns
`added 0 / changed 0 / removed 0 / split_by_access_path 0` — the 54 phantom `added` rows and 7
fabricated `arithmetic_changed` splits are gone, and the differential is trustworthy for the
first time since documents moved their subsumed rows under `provenance`.

**U3 — composition total order + destination predicates (B6 + B2, `fold.py`, `planes.py`).**
Both composed-candidate merges select the *whole* candidate by one total, evidence-first order:
highest figure, then weakest witness state (`proven_floor` before `proven_exact` — no exactness
minted by iteration order), then selector, then the chain's own published identity, total by
construction over every field a step publishes. Entries tied at the published figure are
disclosed under `composed_selector_tie` (12 non-null on this corpus, each listing the tied
candidates with the chosen one marked; `null` is the proven "one candidate"), and the published
chain always belongs to the published selector (8 entries flipped from order-decided `manage`
to rule-decided `exit`, dollars identical; `0x917cee80` keeps `proven_floor` where a tied
`proven_exact` existed). Every composed entry also gains `destination_predicates`: the
destination function's own `effective_functions.conditions` texts, verbatim, uncapped, with a
reading stating they are stored without polarity, evaluated by nothing, include the already-
satisfied auth guard and decompiler artefacts, and are published so the ceiling can be checked
against the evidence — never sourced from the drifted `function_principals.details.conditions`
copy, and never a filter, a bound or a number.

**U4 — the value-at-stake bound direction (B7, `fold.py`, `site/`).** The row header is
three-valued: `value_at_stake_bound_direction` ∈ `floor` / `ceiling` / `not_determined`, with
`value_at_stake_is_floor` true only on `floor` and the `">= "` band prefix earned only there.
The 10 rows whose every priced entity is a composed extraction ceiling — including every
headline figure — flip to `not_determined` and lose the prefix: a sum of ceilings under
incomplete coverage is bounded in *neither* direction, and the rewritten basis says so, naming
the ceiling entities (`entities_priced_from_a_composed_ceiling`, on every row) and the coverage
gaps. The 4 genuine floors (all `flow.out`, zero composed entries) keep `floor` untouched. The
`exact` and no-gap-`ceiling` arms are refused rather than minted — no row on this corpus earns
either, and the direction is never published from a default. The frontend renders the
three-valued direction (`BoundBadge`); the false "floor" badge is off every headline row.

### 11.2 Deferral register (supersedes §10.4)

**Carried forward unchanged** from §10.4: the §7-carried items (code-control magnitude; freeze
fraction; `exec.arbitrary` destination semantics; conjunctive act-as gates; `event_log` as a
storage-read observation; exact-branch / undetermined-sheet disclosure parity; the
`ck_protocol_scores_grade_pairing` split); **(a)** the authority-seat shape; **(c)**
`target_constraint` witness-note pass-through; **(d)** caller-naming calibration on
`A → B(sv) → C(ACL) → D(sv)` chains; **(e)** the same-kind conferral bound.

**Amended by this run:**

- **(b) — split, half closed.** The *surfacing* half shipped: every composed entry now carries
  `destination_predicates`, read from the canonical `effective_functions.conditions` column.
  What remains open is **evaluation**: the pipeline stores predicate text **without polarity**
  (the same text is a require-condition in one function and a revert-condition in another), so
  no evaluation is possible without a new extraction that records require-vs-revert per
  predicate. Until then `caller_holding_precondition.bound_kind` stays the
  `"caller_supplied_arguments"` literal, and the holder witness (share balance /
  outstanding-request depth) stays registered beside the freeze fraction.
- **(f)** — items (1), (2) and (5) are **closed** by this run (U1's read taxonomy; U1's
  conjunct gating + corrected prose; U3's tie-break and disclosure). Item (3) is item (b)/(j).
  Items (4) and (6) stand.

**Newly registered by this run:**

- **(g) Disagreeing reads still publish the never-read mislabel.** Two on-chain reads of one
  variable that disagree on the address make the plane drop the variable (correct: picking one
  would publish a call destination out of row order), but the resulting refusal is
  `caller_state_variable_never_read_on_chain` — the variable was read *twice*. 0 live
  (`variables_two_reads_disagree_under: 0`); the code marks the mislabel as standing and it
  needs its own reason (`caller_state_variable_two_reads_disagree`) before a corpus grows one.
  The paired failure record is deliberately dropped with the reads so the sharper
  `read_reverted` claim is not minted there either.
- **(h) `_ACT_AS_RANK` mixes two orderings.** The sharpest-shortfall rank interleaves "how
  completely the question was answered" (`zero` at rank 0 because it disposes of every
  destination) with "how far the call site got" (gate reasons ahead of receiver reasons, ACL
  reasons after both). Each pairwise choice is defensible; the scale as a whole has no single
  axis, and which reason a multi-site caller publishes depends on it. Needs a stated two-axis
  rule (or a published per-site reason list) before the ladder grows again.
- **(i) `receiver_resolved_type` is carried but published nowhere.** `ActAsVerdict` carries the
  resolved type beside the `holds_a_different_address` earned negative (0 live) so the refusal
  can say *what* the pointer held — but the census counts only outcome strings and no document
  field receives it. The claim "the refusal carries what it held" is true of the dataclass and
  not yet of the document.
- **(j) `function_principals.details.conditions` drift, measured precisely.** Of 1593
  protocol-1 controller rows, 1323 carry a byte-identical copy of
  `effective_functions.conditions`, **36 carry a copy that disagrees**, and **234 carry no copy
  at all** (270 non-identical total). Nothing reconciles them, no provenance reports the drift,
  and no consumer declaration says the column is authoritative — the scorer reads only the
  column (enforced in U3), but other consumers may read the copy.
- **(k) — CLOSED by the execution-witness run (B2).** The gloss now reads the chain component's
  field names off `ActAsStep.as_json()` on the candidates in hand, so it cannot under-state the key
  again. The fix went past the textual one this item asked for: reciting the whole ladder also read
  as though every component applied, when on a tie the components ahead of the deciding one hold the
  same value on every candidate and the ones behind it are never reached. `chosen_by` now names the
  component that actually separated the entry from each candidate it was chosen over, and a tie the
  order separates at no component publishes that as its own state. 12 carriers, 2 distinct strings on
  the reference corpus, 0 numbers moved. **Original text, for the record:**
  glosses the chain-identity component as "each step's caller, selector, calling selector,
  receiver variable and receiver block", but `_composed_order`'s tail is every field of
  `ActAsStep.as_json()` — `witness_kind`, `basis`, `destination_acceptance`,
  `calling_function_openness`, `receiver_observed_via` and
  `admitted_without_a_delegation_witness` included, and total by construction the day a field
  is added. The five-field list under-states the key it describes (reviewer round-3 note;
  adjudicated ship-with-registration). The fix is textual: the gloss should say the chain
  component is *every field each step publishes*, naming the list as illustrative, not
  exhaustive.
- **(l) V0's six additional same-shape defects** (V0 appendix, inlined here because the
  scratchpad artefacts rot): (1) the `details.conditions` drift — item (j); (2)
  `_composition_totals.roll()` sums `composed_usd_summed_over_rows` across rows while counting
  entities distinct, so the protocol-level figure ($48,285,848.25 findings / $71,003,609.11
  subsumed) counts one entity once per row reaching it — the reading names this but the field
  name still reads as a protocol total; (3) `ActAsPlane.destination_acl` drops every
  `function_principals` row with `principal_type != "controller"` and publishes the post-filter
  count as `function_principal_rows_returned: 1593` — the filter is now disclosed
  (`principal_type_read: "controller"`) but rows of other kinds are still uncounted, so the
  reader cannot see what other lists existed at those selectors; (4) disagreeing reads — item
  (g); (5) `_compose`'s `visited` set makes the published refusal reason path-dependent: a node
  reached first by one BFS path is never re-expanded, so the reason published is the first
  path's, and the docstring's "conservative on the refusal reason" overstates it — conservative
  on dollars, arbitrary on the reason; (6) `authority_openness == "not_determined"` on 326 of
  3302 act-as call sites reaches no confidence term — U1 named it at the *reason* level
  (`call_site_caller_gate_openness_is_not_determined`, 12 counts), but at the aggregate level
  `act_as_refused` still charges coverage gaps and earned negatives to one bucket.
- **(m) The differential is arithmetic-first by design.** A row registers as `changed` only
  when `raw_points` moved; `value_band` and basis strings are reported only as *causes* of an
  arithmetic change. This run's 10 band-prefix drops and all its reason renames are therefore
  invisible to `differential` — correct for its purpose (attributing score movement), but a
  claim-only repair leaves no trace there, so document-level claim diffs need the exact
  node-level diff, not the CLI.
- **(o) `destination_predicates` is published per ENTRY and the predicates are per DESTINATION
  FUNCTION.** Ruling 6.1 M3, registered rather than fixed. Identical text is republished up to 11×
  per row and 40× per document, because every composed entry at one destination carries its own copy
  of that function's stored condition list. Not a correctness defect — each copy is true of the entry
  carrying it and the block is the only place a reader can check the composed ceiling against the
  destination's own body — but a size deferral, and the natural fix (one keyed table under
  `provenance` with entries pointing into it) is a shape change nobody has ruled.
- **(n) A failed `eth_getCode` classifies as `"contract"`.** The resolver returns
  `("contract", …, had_rpc_error=True)` on a getCode failure — never cached, but returned, so a
  `controller_values.resolved_type = "contract"` row can in principle record a probe that
  failed. Blast radius on the scorer is context-only after U1 (the address comparison is the
  witness; `eoa`, the proven-absent arm, is only ever minted from a *successful* empty
  getCode), but the label is a positive classification a failed probe should not produce.
