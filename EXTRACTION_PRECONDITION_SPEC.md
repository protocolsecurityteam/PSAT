# Extraction Preconditions — Scope, Spec & Orchestration

**Status:** scope + spec + orchestration runbook (§9). Nothing implemented. **Wave 0 is an
investigation** whose rulings the implementation waves consume — do not skip it.
**Written:** 2026-08-07 against the local etherfi snapshot (`protocol_id 1`, DB on port 5433),
branch `fix/confidence-perimeter-admission` at `c9f2713e` (model `1.1.0-provisional`, PR #169).
**Companion to:** `COMPOSITION_WITNESS_SHAPE_SPEC.md` §10/§11 — this closes the precondition its
ceiling disclosure was forced to leave open, and it **supersedes the "holder witness" framing** of
that register's open item (§7 ruling here explains why).

Every figure below was reproduced read-only against that snapshot. Extrapolations are labelled.
Verdicts are CONFIRMED (evidence reproduced) or OPEN (needs a Wave-0 ruling).

---

## 0. The one-paragraph diagnosis

Composition publishes 40 entries across 10 rows as **extraction ceilings** with an unproven
`caller_holding_precondition`, on the theory that the destination call spends a quantity the seized
principal was never proven to hold. That theory is right for a **minority** of the money and wrong
about the rest. Classified by the **last hop's calling body** — not the destination's name — the
population splits three ways: `Teller.bulkWithdraw`, which passes `msg.sender` as the burn address
and genuinely spends the caller's own shares (26 entries, **$3.03M**); `Manager.manageVaultWithMerkleVerification`,
which moves **protocol** funds and requires the caller to hold no token at all (12 entries,
**$53.95M — 93.8% of the dollars**); and `Teller.refundDeposit`, which spends a *third party's*
shares and pays that third party, so the principal extracts **$0** (2 entries, $547K). The middle
class needs no new capability to resolve: its only remaining precondition is `manageRoot[msg.sender]`,
and `setManageRoot` is `requiresAuth` with the row's **own seized principal** already named in
`function_principals` on all six entities. That is a fold-time join against evidence already loaded.
Meanwhile the fork proofs behind the first class ran with `input_seeded: true` — the harness **wrote
the caller's shares into fork storage** — a conditional the document does not disclose. The dollars
that hinge on a genuinely absent holder witness, after accounting for entities that republish the
same figure through a `manage` path, are **$965,247.16 — 1.68%**.

**Three of the four fixes are scorer-only. None requires the deferred holder-witness capability.**

---

## 1. Findings register

### 1.1 The published population under test

40 composed entries, 10 rows, every one `caller_holding_precondition.state = not_determined`,
`bound_kind = caller_supplied_arguments`, `principal_extraction_bound = "ceiling"`. Only **two**
destination functions are ever published: `exit` `0x18457e61` (28 entries) and `manage` `0xf6e715d0`
(12). Dedup-by-entity value **$57,523,026.72** across 14 entities (the raw entry sum of $119.3M
double-counts entities reached by more than one path).

### 1.2 CONFIRMED defects

**E1 — the precondition class is decided by the intermediate, and two of the three classes are
mislabelled.** `BoringVault.exit`/`manage` themselves require nothing of `msg.sender` beyond
`requiresAuth`: `from` is an *argument*, and there is no `assetAmount`↔`shareAmount` invariant. The
caller-held quantity, where it exists, comes only from the intermediate's body:

| class | last hop's calling body → destination call | what it spends | entries | entities | dedup USD |
|---|---|---|---|---|---|
| **A** | `Teller.bulkWithdraw` → `vault.exit(to, asset, assetsOut, **msg.sender**, shareAmount)` (`Teller.sol:434`) | the **caller's own** shares | 26 | 7 | **$3,029,934.27** |
| **B** | `Manager.manageVaultWithMerkleVerification` → `vault.manage(…)` after a `manageRoot[msg.sender]` proof (`Manager.sol:151`) | **protocol** funds; the caller holds nothing | 12 | 6 | **$53,945,961.36 (93.8%)** |
| **C** | `Teller.refundDeposit` → `vault.exit(receiver, …, **receiver**, …)` (`Teller.sol:336`) | a **third party's** shares, paid to that third party | 2 | 1 | **$547,131.09** |

Only class A is a caller-balance bound. Classes B and C carry the same ceiling label for reasons
that are, respectively, *resolvable today* and *flatly wrong*. CONFIRMED.

**E2 — class B's remaining precondition is already witnessed, and the scorer does not join it.**
`manageRoot[msg.sender]` is set by `setManageRoot` `0x21801a99`, which is `requiresAuth`.
`function_principals` names the setter as the **row's own seized principal** on all six entities —
4× `0xcea80390` (findings[1]'s Safe), `0x70a64840` (the timelock the subsumed rows already price
through), and `base::0x183fe888` (findings[3]'s principal) — with
`owner_may_grant_itself_any_role_on_this_registry` witnessed alongside. A principal that can set the
root can prove any leaf, because the decoder is inside the hash. Every fact in that sentence is
already loaded by the scorer for other purposes. CONFIRMED.

**E3 — class C publishes value the principal provably cannot take.** `refundDeposit` returns a
depositor's shares to that depositor: the `exit` receiver and the burn address are both the third
party. The principal causes a movement it does not receive. Publishing it as this principal's
extraction is an over-claim with an **earned negative** available — the honest answer is a proven
`$0`, not a ceiling. CONFIRMED.

**E4 — the class-A magnitudes were proven with manufactured inputs, undisclosed.** 23 of 60 proven
`value_out` verdicts carry `input_seeded: true`, **including all three local `exit` `0x18457e61`
proofs**. The seeder writes the caller's share balance into fork storage; that is the only reason a
share-burning withdrawal proves at all. The published entry says a fork proved the movement and does
not say the proof supplied the precondition it is silent about. CONFIRMED.

**E5 — 14 class-A entries name the wrong subject.** On the single-hop class-A entries the published
`caller_holding_precondition.caller` is the **Teller**, but the burn falls on the *Teller's*
`msg.sender`. The row names a party whose holdings are not the bound. Distinct from
`COMPOSITION_WITNESS_SHAPE_SPEC.md` §11.2 deferral (d), which is about multi-hop caller *selection*.
CONFIRMED.

**E6 — `observed_reach_value_usd` is not a call magnitude.** `_add_reach`
(`services/effects/recipes.py:1636-1690`) attributes the holder's **entire priced balance** in each
moved asset, ignoring the `Transfer` log's actual value. Every reach figure inherits this. Reported
here because it bounds what any of the above can honestly publish; **out of scope** for this spec
(§8), and registered. CONFIRMED.

### 1.3 What the holder witness would actually buy

`_compose` publishes one candidate per entity. Disproving class A leaves **5 of 7** entities
republishing the identical figure through a `manage` path. Dollars existing **solely** because of a
caller-balance-bounded path: **$965,247.16 — 1.68%** of the population. The evidence for a truthful
class-A witness does not exist locally: the solver `0x98946898` holds five assets (HEX, 429 wei
USDC, 100 wei USDT, 12819 wei eETH, one spam token), sheet total **$0.00**, and **zero rows for any
of the five vault share tokens** — but that absence is *not* proof, because zero balances are
filtered before storage and completeness is `not_determined` below the 100-row page cap. There are 5
share-balance rows corpus-wide, all unpriced; 6 of 8 etherfi share tokens carry `price_usd = 0`; and
there is no `AtomicQueue.userAtomicRequest` enumeration, so the *acquisition* half is unanswerable
from stored data. **Ruling in §6.5: keep the holder witness deferred.**

---

## 2. Root cause per defect

| defect | root cause | locus |
|---|---|---|
| E1 | the precondition is classified from the destination, which never carries it; the intermediate's body decides | **fold** — the composition step must record which body it traversed |
| E2 | a witnessed self-grant on the gate-setter is never joined to the composed step | **fold/planes** — a gate-precondition join |
| E3 | a movement the principal causes but does not receive is priced as its extraction | **fold** — receiver identity is unread |
| E4 | the proof's own `input_seeded` flag never reaches the document | **effects → distill → fold** — a witness field is dropped in transit |
| E5 | the caller is taken from the published chain step rather than from the body that spends | **fold** — `_caller_holding` |
| E6 | balance attribution substitutes for log-derived movement | **effects** — out of scope, registered |

---

## 3. Proposed model change

### 3.1 Classify the precondition from the traversed body, not the destination

Composition already knows the last hop's calling function and its selector (`calling_selector`,
shipped by U1/U3). Extend `_CallerHoldingPrecondition` with a `bound_source` naming the body that
imposes the bound and a three-valued `subject_holds` — never inferred from a function name. The
published `bound_kind` must become one of a closed, witnessed set:

- `caller_own_balance` (class A: the body passes `msg.sender` as the spend address);
- `no_caller_quantity` (class B: the body spends protocol funds; the only precondition is the gate);
- `third_party_balance_to_third_party` (class C: the receiver is not the principal);
- `not_determined` where the body was not read or does not resolve to one of the above.

Every assignment must cite the body and the argument position it read.

### 3.2 A gate-precondition join for class B

Where the remaining precondition is a **gate the row's own principal is witnessed able to set**
(`function_principals` names it as a principal of the setter, and the setter is `requiresAuth`),
the precondition is **satisfied, not assumed**. Publish it as a witnessed conjunct with its evidence
(setter selector, `function_principals` row id, the self-grant witness), and the entry's
`principal_extraction_bound` becomes an earned bound rather than a ceiling-by-default. Absence of
such a row remains a refusal with its own typed reason — **never** a silent upgrade.

### 3.3 Class C earns a negative

Where the traversed body pays the spent quantity back to the party that supplied it, the principal's
extraction through that path is **proven zero**. Publish an earned negative with its basis, not a
ceiling, and let `_compose`'s existing per-entity selection substitute any other witnessed path to
the same entity (measured: it does, and the row's dollars are unchanged).

### 3.4 Seeding is a published property of the proof

`input_seeded` must ride from the verdict to the published entry as a first-class field
(`magnitude_proved_with_seeded_inputs`, three-valued: seeded / unseeded / not_determined), and any
reading that describes a fork proof must say when the proof supplied the precondition. A seeded
proof of a caller-balance-bounded call is evidence about the **function**, not about **this
principal** — the entry must say so in its own basis.

### 3.5 Nothing here relaxes a bound

No number rises because a class was relabelled. Class B's upgrade changes a *direction*, not a
figure; class C's negative removes a claim; the seeding disclosure only adds a qualifier. Any dollar
movement is a defect (§9.4).

---

## 4. Invariant impact

| invariant | verdict |
|---|---|
| **1** three-valued logic | **PRESERVED** — every new field carries a not_determined arm; the class-B join is a witness, not a default. |
| **6** monotone in resolution work | **PRESERVED and repaired** — evidence already loaded (the self-grant, the traversed body, the seeding flag) starts answering instead of being ignored. |
| **9** exact decomposition | **CHECK** — each entry must trace: traversed body → argument position → precondition class → (class B) setter row + self-grant witness → magnitude, with the seeding property attached. |
| **13** anti-gaming | **CHECK and argue** — class B *raises* charges (a ceiling becomes an earned bound), class C lowers them. Confirm a protocol cannot cheaply suppress a `setManageRoot` principal row, and that C's negative cannot be manufactured by naming a third party as receiver while retaining value. |
| **16** no abstraction above a witness | **ENFORCED** — `bound_kind` must cite the body and argument it was read from; no assignment from a function's name. |

---

## 5. Expected blast radius (Wave 0 measures; do not assume)

Modelled by monkeypatched `_compose` over real scorer runs (baseline reproduces the published
headline exactly): λ 62.3179 · `grade_exposure` 99.55 · `exposure_usd` $19,438,110.14 ·
`confidence_pct` 18.6.

| scenario | λ | Δλ | `exposure_usd` |
|---|---|---|---|
| class A disproved | 73.2508 | +10.93 | $17,721,167.35 |
| class B disproved | 65.2636 | +2.95 | $2,631,155.22 |
| class C disproved | 62.3179 | 0.00 | unchanged (substituted) |
| all disproved | 84.0166 | +21.70 | **$76.07** |

**λ is band- and rank-driven, not dollar-driven** — class A is 1.68% of exclusive dollars but +10.93
λ; class B is 93.8% of dollars but +2.95 λ. `confidence_pct` is **18.6 in every scenario** (it binds
on `value_priced_pct`); only `reach_magnitude_witnessed_*_pct` move. 99.9996% of etherfi's published
exposure is composed money resting on these preconditions — which is why §9.4's gate is on *both*
directions, not just on dollars going up.

**U4's `value_at_stake_bound_direction` on the 10 rows:** proving the precondition satisfied at the
published figure moves **no number** (`value_band` reads `value_usd` only) but empties
`ceiling_entities`; since all 10 rows carry coverage gaps, all 10 would flip `not_determined → floor`
and the `">= "` prefix returns. **A class-B-only upgrade flips no row by itself** (only the two
`0xf8553c85` principals are pure class A) — a fact each unit must prove rather than discover.

---

## 6. Open rulings — Wave 0 produces these, implementation consumes them

1. **Is a self-settable gate a satisfied precondition?** Argue E2 against the
   `SCORER_DISCIPLINE_CONTRACT` and inv. 16. State exactly what "the principal can set the root,
   therefore can prove any leaf" does and does not prove — in particular whether the decoder-in-hash
   argument holds for every Merkle-gated manager shape in the corpus or only this one.
2. **Class C's negative: proven zero, or merely not-this-principal's?** Rule whether "pays the
   supplier back" is an earned negative for *extraction* or only for *receipt*, and whether a
   principal could benefit by other means through the same call (fee capture, MEV, state change).
3. **What must a seeded proof say?** Rule the exact published shape and whether a seeded proof of a
   class-A call may carry a magnitude at all, or must degrade to `not_determined` with the function-
   level figure disclosed separately.
4. **Does the class taxonomy generalise?** Only two destination functions and one vault family exist
   locally. Rule what evidence a second protocol would need to produce before the taxonomy is
   trusted beyond this corpus, and how an unrecognised body must fail (it must fail to
   `not_determined`, never to a class).
5. **Holder witness: confirm the deferral.** Re-verify §1.3's 1.68% and the absent price/supply/queue
   evidence, and state the conditions under which it becomes worth building. (Author's view: defer —
   the fork harness *can* pin `msg.sender` today at ~321ms/proof, but the stage order is wrong, there
   is no negative verdict state, `effect_verdicts` admits one row per `(chain, contract, selector,
   effect_class)`, and the acquisition half is unanswerable.)

---

## 7. Deferral register (carried, not addressed here)

- **Holder witness** — proving a principal holds or can acquire the spent quantity. Feasibility
  measured: caller pinning exists (`recipes.py:617`, `anvil.py:815`), cost ~321ms/proof; blockers are
  stage order (the caller comes from the fold, which runs after effects), no negative verdict state
  (`services/effects/config.py:152-153` has only `proven`/`unknown`), no per-caller storage identity
  (`db/models.py:2704-2711`), no share-token price (6 of 8 at `price_usd = 0`), no `totalSupply`
  column, no queue-state table. Worth **1.68%** of exclusive dollars today.
- **E6 `observed_reach_value_usd`** — balance-attribution instead of log-derived movement
  (`recipes.py:1636-1690`). Bounds the honesty of every reach figure; larger than this spec and
  independent of it.
- Everything in `COMPOSITION_WITNESS_SHAPE_SPEC.md` §11.2, unchanged, plus its (d) caller-selection
  calibration — related to E5 but distinct.

---

## 8. What this spec deliberately does not do

It does not build the holder witness, does not read share balances, does not price a share token,
does not model queue state, and does not touch `observed_reach_value_usd`. It changes **no dollar
figure**: it classifies preconditions from evidence already stored, joins one gate witness already
loaded, earns one negative, and discloses one property of the proofs. If a change would move a
magnitude, that is out of scope and must be reported, not shipped.

---

## 9. Implementation & orchestration

Follows the repo-owner's standing model: the **main loop orchestrates only** — never writes or
reviews code — all coding goes to fresh **Opus** subagents in isolated worktrees, all reviews to
*separate* fresh **Opus** agents, review loops cap at **3 rounds** with the orchestrator adjudicating
on exhaustion, the capstone is **Fable**, and the branch is **pushed once at the end**, on the
owner's explicit authorization.

### 9.1 Aligned parameters

- **~12 agents across 4 waves:** 1 investigator + 4 coders + 6 reviewers + 1 capstone.
- **Wave 0 is blocking** — its five rulings (§6) gate every later wave; it writes no production code.
- **Wave 1's three units are worktree-parallel** and file-disjoint. Wave 2 depends on Wave 1's
  classification field existing.
- **One batched push**, after the capstone, on owner authorization.

### 9.2 Branch model

Work directly on `fix/confidence-perimeter-admission` (tip `c9f2713e`) — this continues PR #169's
line. Cut each unit as a worktree **off the current tip**; every prompt must prove it is not on a
stale base (`git merge-base --is-ancestor <tip> HEAD`) before writing code. Worktrees under
`/home/riley/PSAT-wt/<unit>`; **only remove worktrees this session created.** Integration is done by
the unit that owns the conflicted file, and the integration run **must execute the suite** — the last
run's fast-forward would have shipped a broken `_compose` call site otherwise.

### 9.3 Wave / work-unit table

`F` = `services/scoring/fold.py`, `P` = `services/scoring/planes.py`, `D` = `services/scoring/distill.py`,
`E` = `services/effects/`.

| Wave | Unit | Scope (owns) | Defects | Depends on | Gate |
|---|---|---|---|---|---|
| **0 Investigation** | V0 | no production code; read-only measurement + rulings | E1–E6, §6.1–5 | — | five rulings argued with measured evidence; the class taxonomy verified against every traversed body in the corpus; a written no-number-movement argument; unit partition confirmed |
| **1 Classify** | X1 | `F` `_CallerHoldingPrecondition` + `bound_kind` taxonomy from the traversed body; `bound_source`; typed not_determined arm | E1, E5 | V0 | every entry's class cites body + argument position; the 14 mis-subjected entries name the spending party; **zero number movement** — prove it |
| | X2 | `E`→`D`→`F` seeding property: carry `input_seeded` to the published entry + readings | E4 | V0 | all three local `exit` proofs publish `seeded`; no magnitude changes; readings state what a seeded proof does and does not prove |
| | X3 | `F`/`P` class-C earned negative + receiver identity read | E3 | V0 | the 2 entries publish a proven `$0` with basis; the row's dollars unchanged by substitution — enumerate the substituting candidates |
| **2 Join** | X4 | `F`/`P` class-B gate-precondition join (setter row + self-grant witness) | E2 | X1 | all 6 entities cite setter selector + `function_principals` row id + self-grant witness; absence is a typed refusal; **no row flips to `floor` on this unit alone** — prove it |
| **3 Capstone** | X5 | full integrated branch | — | X4 | §9.6 |

### 9.4 Verification commands (every gate)

```bash
docker compose up postgres minio minio-init -d          # once

./run_tests_fast.sh                                     # full offline suite
./run_tests_fast.sh tests/test_scoring_redteam.py       # DB-free fold fixture

uv run ruff format --check <files>
uv run ruff check <files>
uv run pyright <files>
cd site && npm test -- --run                            # if score-page-visible fields move
npx playwright test e2e/visual-baseline.spec.js         # if the badge or band moves

# real-corpus differential — THE gate (the CLI differential is trustworthy as of 642eccdd)
set -a; source .env; set +a
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/before.json   # capture ONCE from the tip
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/after.json
uv run python -m services.scoring.cli differential --protocol 1 --against /tmp/before.json
```

**HARD GATE, every unit:** λ `62.3179`, `exposure_usd` `$19,438,110.14`, `confidence_pct` `18.6`,
`grade_exposure` `99.55`, zero reach movement, **zero dollar movement in either direction**. Deltas
are limited to classification fields, disclosures, readings, and — for X3 — one earned negative whose
substitution must be enumerated. Note `confidence_pct` is insensitive here (it binds on
`value_priced_pct`), so it is a weak signal; watch `reach_magnitude_witnessed_*_pct` instead.

Known pre-existing offline failures, unrelated: `test_appendix_a_funnel_on_dev_db`;
`test_event_indexer_loop_records_heartbeat` (flaky).

### 9.5 Regression cases (assert in `tests/test_scoring_redteam.py`)

1. **The class is read, not named.** A destination called `exit` reached through a body that passes
   `msg.sender` classifies A; the same destination through a body that passes a parameter classifies
   B; an unreadable body classifies `not_determined`. No classification from a function name.
2. **The subject is the spender.** A single-hop class-A entry names the party whose balance the body
   burns, not the intermediate.
3. **The gate join is a witness.** Class B upgrades only with a `function_principals` row for the
   setter naming the row's own principal; absence keeps the ceiling under its own typed reason.
4. **The negative is earned and substituted.** A `refundDeposit`-shaped path publishes `$0` with its
   basis, and any other witnessed path to that entity still publishes its own figure.
5. **Seeding rides through.** A verdict with `input_seeded: true` publishes the property, and its
   entry's basis says the proof supplied the precondition.
6. **No number moves.** Under every combination above, `value_at_stake_usd`, `value_band`, λ and
   exposure are unchanged from the tip.

### 9.6 Capstone (X5, Fable, fresh agent over the integrated branch)

- Full differential across every local protocol (p1 is the only one — confirm by SQL: `protocols`
  has exactly one row and all 1059 score signals are `protocol_id = 1`, with 521 contracts orphaned
  at NULL and unreachable by the scorer — register that separately).
- **Invariant sweep:** 1, 6, 9, 13, 16 per §4; in particular that every class assignment cites a body
  and argument, and that no dollar moved in either direction.
- Confirm the shipped `not_determined` population and state which part is now genuinely
  precondition-bound versus classified.
- Update `COMPOSITION_WITNESS_SHAPE_SPEC.md` §11.2 to close what this run resolved and carry the
  rest; update PR #169's description; register new deferrals.
- Text-only write authorization; any code-level defect is reported, not fixed.

### 9.7 Guardrails (hand to every coder and reviewer verbatim)

- **The DB is READ-ONLY.** SELECT only, port 5433. Create your own `psat_test_<unit>` database for
  DB-backed tests; that is the sole exception.
- **No commit without explicit owner authorization for the push; no Claude attribution trailers.**
- **A green suite proves little.** Measure every change on the real corpus and report ADDED /
  CHANGED / REMOVED. A zero-diff is meaningful only if you prove *why* it is zero.
- **Do not move a number.** This spec classifies and discloses. Any magnitude movement is a finding
  to report, not a result to ship.
- **Do not reuse `ValuePlane.sheet_state` / `total`** (`planes.py:165`, `:189`) as a holdings witness:
  36 of 40 callers are `no_rows` / `priced_below_resolution`, which is **not** a proven zero.
- **Hardcodes you will meet:** `fold.py:218` (`"state": NOT_DETERMINED` is a literal, not a field) and
  `fold.py:399` (`"principal_extraction_bound": "ceiling"`). `_caller_holding` (`:2528`) is where a
  precondition plane is consulted; `_compose` (`:2556`, called at `:2231`) is the injection point;
  `from_ceilings` (`:2755` → `:2264-2273` → `_bound_direction` `:1986`/`:1670`) is the already
  three-valued path. Existing behaviour is pinned by `tests/test_scoring_redteam.py:3987`, `:4649`,
  `:5784`, and by `site/src/score/derive.js:114`, whose allow-list **silently nulls** an unknown
  direction — extend it or the badge disappears.
- **Source-fetch trap:** `source_files.storage_key`'s trailing hash derives from the *path*, so fetch a
  contract's source from **its own** `job_id`.
- **Worktree base check** (§9.2) before writing; the integrating unit runs the suite, not just the
  merge; only remove worktrees this session created.
- **Reviews go to fresh agents**, capped at 3 rounds; the orchestrator adjudicates on exhaustion.
- **Trust a subagent's reported pass counts** — do not re-run its suite to double-check.
- **Batch the push** — one push after the capstone, on the owner's authorization.
