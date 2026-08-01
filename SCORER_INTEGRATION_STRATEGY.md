# Scorer integration strategy — from prototype to pipeline

Companion to `SCORING_INVARIANTS.md` (the epistemics — *what* may be scored and how
findings compose) and `scoring_prototype/FIELDS.md` (the field register — *which*
data a conforming scorer consumes). This doc is the **mechanics**: where the score is
computed, persisted, invalidated, and served, once it stops being an offline
`scorer_v3.py` that loops over the whole DB and becomes part of the run.

Written 2026-08-01, against pipeline HEAD `d699c7b3` (#162) and a local full run
(365 jobs, protocol 1 = etherfi, schema head `f4d18a7c0b93`). Data-readiness was
spot-checked and confirmed: every REQ/GATE plane the register marked "prospective /
lands on the next run" is populated locally, and `scorer_v3.py` runs clean end-to-end
against it.

**Update 2026-08-01 (later same day): all open questions are RULED.** The §7 items and
the two either/ors buried in §2 and §8.1 were decided by the owner and folded in — §7
now records rulings, not questions. Delivery is a **single branch, single PR, backend
only** (§5); the frontend is out of scope entirely (the existing score page will be
scrubbed wholesale in a later session). This doc is complete and ready to build
against.

---

## Status of `scorer_v3.py`: a diagnostic probe, NOT a design to iterate

`scoring_prototype/scorer_v3.py` is a **throwaway data-shape diagnostic**. Its purpose
was answered the moment it ran clean against a full local run: it confirmed the planes
are populated and the shapes are consumable. It is **not** the design for the
production scorer and must not be iterated, patched, or designed around. The
production scorer is a fresh `services/scoring/` implementation (§1.3) that honors
`SCORING_INVARIANTS.md` + `FIELDS.md` from the start; the prototype survives only as
(a) proof the data is ready and (b) an offline differential oracle for the golden
tests. **Do not fix prototype bugs** — capture the *lesson* as a requirement on the
real scorer or as a pipeline item, then let the prototype go.

Corollary — how to read a prototype finding. A prototype defect is only interesting
for what it tells us about the **data**, never about the prototype's code. When a
finding looks wrong, the load-bearing question is exactly the one this exercise
forced: **is the underlying DATA honest (a disciplined consumer would get it right),
or did the pipeline publish a false or missing fact?** The delegatecall.execute FP
(§6) is the worked example: the data was honest, the prototype was not, so there is
**nothing to fix in the data on that finding's account** — only a requirement to carry
onto the real scorer and one optional coverage enhancement.

---

## 0. The core decision: signals per function, grade re-folded over all signals

The score is **two layers**, and they integrate differently.

**Layer 1 — per-function signals. Per contract, in the pipeline, incremental.**
For each `effective_functions` row: its capability (`flow.out`, `upgrade.implementation`,
`pause.set`, …), the proven severity of its behavior (destination lattice, fork
witness, freeze effectiveness), references to its resolved principals, and references
to the value it reaches. The pipeline *already computes the raw material* — this is
exactly what the claims + witnesses on `effective_functions` and the `effect_verdicts`
rows are. Distilling them into explicit per-function **signal rows** is incremental,
one contract at a time, and belongs at the end of the effects stage. This is the part
of the original "compute in effects" instinct that is correct and kept.

**Layer 2 — the protocol grade. A whole-protocol fold, recomputed each time.**
This layer **cannot** be an accumulator that adds one contract's contribution at a
time. Three invariants from `SCORING_INVARIANTS.md` make a running total wrong:

1. **Value is MAX per (entity, asset), not SUM** (inv. / FIELDS §1). Two contracts'
   `pause` functions can both reach the same $1.4B vault; summed one-at-a-time they
   charge $2.8B against a $1.4B entity. A correct running max would have to already
   know every entity every prior finding touched — i.e. it needs the whole set anyway.
2. **Principal units are cross-contract and mutable under new evidence** (FIELDS §4,
   Safe key-set union-find, timelock⊂proposer collapse). A finding keyed "EOA X can
   `setAuthority`" must be **re-keyed** into a Safe unit — with a different weakness —
   the moment a later contract reveals X is an owner on that Safe. An accumulator
   would have to un-count; a recompute just gets it right.
3. **Subsumption depends on the full finding set** (FIELDS §B). "Safe 4/6 can replace
   the authority" absorbs "Safe 4/6 can grant roles" — you charge the larger once.
   Which rows subsume which is only decidable with all rows present.

The fold is **cheap** — `scorer_v3.py` is 11 read-only queries plus in-Python passes,
seconds at this corpus; over pre-distilled signal rows it is sub-second. So
re-folding on every change costs nothing and removes the double-count / re-key /
subsumption bugs a running total would introduce.

**Conclusion: distill signals per function incrementally (Layer 1, in effects);
recompute the grade in full over all persisted signals on each trigger (Layer 2, in a
protocol-scoped loop). The per-job step is a producer + a dirty-mark; the grade is a
consumer that re-folds.**

---

## 1. The flow

```
   effects stage finishes for contract C
        │
        ├─(1) distill C's per-function signals ──► persist signal rows (per job)
        │
        └─(2) mark protocol P's score dirty ─────► (transactional, cheap)

   protocol_score loop (in protocol_monitor, next to the TVL loop)
        │
        ├─ sees P dirty (or staleness sweep) 
        ├─(3) re-fold ALL persisted signals for P ► compute_protocol_score(P)
        └─(4) INSERT one protocol_scores row (insert-only, history-preserving)

   GET /api/company/{name}/score ──► latest protocol_scores row (ledger payload)
   (frontend out of scope — old score page scrubbed in a later session)
```

### (1) Signal distillation — end of `EffectsWorker._process`
Hook after `_bridge_claims` (`workers/effects_worker.py:651`, before `_record_metrics`
at `:653`). At this point the job's `effect_verdicts` are written and the
`behavioral_observed` claims are merged onto `effective_functions`. Emit per-function
signal rows carrying: capability (`claim_id`), severity basis + proven severity,
principal references (`function_principals` ids, not resolved copies), value
references (holder-closure entity keys, not dollar amounts), and the witness tiers /
gate inputs the grade fold needs. **Signals reference, they do not resolve** — the
grade fold does the cross-contract resolution (principal units, MAX-per-entity value,
subsumption) because only it sees the whole protocol.

Fail-forward is free here: effects never emits `failed_terminal`
(`_finalize_terminal_failure`, `workers/effects_worker.py:1333`), so a distillation
raise cannot kill the job.

### (2) Dirty-mark
Mirror the existing `mark_enrollment_dirty` pattern (`services/monitoring/enrollment.py`).
Mark from every site that changes a scored input:
- end of effects (above) and end of `CoverageWorker.process`;
- `coverage_verify` when it flips `equivalence_status` (audit posture is a scored axis,
  FIELDS §8, and it settles *after* effects);
- `maybe_queue_reanalysis` (`services/monitoring/reanalysis.py:187`) minting a fresh job.

### (3) The grade fold — `services/scoring/`
Extract `scorer_v3.py` into `compute_protocol_score(session, protocol_id) -> ScoreDocument`:
- **pure, read-only, deterministic** — keep the prototype's `ORDER BY` discipline for
  inv.11/12 replay;
- **parameterized on protocol** — drop the hardcoded `PROTOCOL_ID = 1`, `"etherfi"`,
  and `chain_id = 1` (`scorer_v3.py:173`, `:2341`, `:502`);
- **chain-scoped entity keys** — protocol 1 already spans 4 chains locally
  (180 ethereum / 28 optimism / 1 base / 1 scroll). The entity key MUST become
  `(chain, address)` or the #158 cross-chain twin-aliasing bug re-enters through the
  scorer;
- **consume the planes the prototype predates** (see §3 conformance gaps below);
- keep a thin CLI wrapper so the offline differential workflow (`score_v2.json` diff)
  still works.

### (4) Persist — new `protocol_scores` table, insert-only
Mirror the `contract_balances → contract_balances_latest` pattern: insert-only base
table + a `_latest` view. Columns: `protocol_id`, `model_version`, `computed_at`,
`trigger` (job id / loop), `grade_lambda`, `grade_exposure`, `confidence_pct`,
`perimeter_settled` (bool — see §2), the findings document (inline JSONB if small,
else a MinIO artifact by `storage_key`), and a **provenance block** (per-plane row
counts + max `updated_at`, plus the `selection_summary` / `perimeter_spawn_summary`
ledger references) so a score is replayable-in-principle per inv.11. Insert-only gives
score **history** for free, which the Activity/Monitor timeline will want.

### The score loop — a supervised thread in `protocol_monitor`
Add a sixth tuple to `_build_default_supervisor` (`workers/protocol_monitor.py:172-205`),
e.g. `("protocol_score", lambda ev: run_score_loop(...))`. You get `record_heartbeat`
+ `WorkerHeartbeat` liveness for free, surfaced on `/api/fleet`. Sweep by dirty-flag
then staleness `NULLS FIRST`, exactly like `snapshot_all_protocols`
(`services/monitoring/tvl.py:575-591`) and the enrollment reconciler
(`services/monitoring/reconciler.py:305`).

### Serve
`GET /api/company/{name}/score` → latest `protocol_scores` row, serving the **ledger
payload verbatim**: `grade_lambda`, `grade_exposure`, `findings[]`,
`earned_negatives[]`, `warnings[]`, `model_parameters`, `confidence_pct`,
`perimeter_state`, and the provenance block. No projection into any other shape.
(`perimeter_state` is the shipped three-state — `settled`/`unsettled`/
`not_determined` — superseding the earlier `perimeter_settled` bool: a bool cannot
represent an unreadable queue, and stamping "unsettled" on a failed read would be a
positive claim with no witness. Reviewer-ratified 2026-08-01.)

**Frontend is OUT OF SCOPE for this build (ruled 2026-08-01).** The existing score
page and `site/src/protocolScore.js` will be deleted wholesale in a later session and
a new page built against this payload. (For the record, `protocolScore.js` is being
retired for cause, not just replaced: it is a divergent six-axis model that strips
`behavioral_observed` claims from its score path (`site/src/claimsVocab.js:492`) and
carries the known inv.10 violation `isInertOneShot → 0.95`
(`site/src/protocolScore.js:239`, recorded in FIELDS §6b). Do NOT project the ledger
into that shape — it would re-introduce the collapse at the display layer.)

---

## 2. Why NOT compute inside the effects worker

The original instinct was to compute the protocol score at the end of effects, per
contract, appending to a running total. Layer 1 (signals) does live there; Layer 2
(the grade) must not, for three mechanical reasons:

1. **Effects runs single-flight** (anvil snapshot/revert is process-global;
   `start_workers.sh` runs one effects worker). An N-query protocol fold on every
   contract's completion serializes scoring into the most contended worker and
   re-folds the whole protocol N times per run.
2. **The perimeter is not settled at any per-job instant.** Policy spawns more jobs
   (`policy_worker.py:864`), resolution spawns dependency providers
   (`resolution_worker.py:738`), and policy's `write_effective_function_rows` is a
   delete+reinsert — a fold snapped mid-run reads a half-rewritten plane.
3. **Audit coverage lands *after* effects**, and `coverage_verify` flips
   `equivalence_status` asynchronously after *that*. The audit axis (FIELDS §8,
   `equivalence_status='proven'` is the admissible core) is not settled at effects
   time.

The loop resolves all three: it fires on a dirty-mark at a settled read instant, off
the critical path. **Perimeter-settled gate — RULED (2026-08-01): compute and stamp,
never defer.** When the loop computes, check for queued/processing jobs with that
`protocol_id`; if any exist, compute anyway and stamp `perimeter_settled: false` on
the document. A mid-run score is a real fact about a partial perimeter — witness
discipline says publish it labeled, not suppress it — and deferring would leave the
endpoint empty for hours on a long run. The staleness sweep recomputes once the queue
drains (producing a settled row), and consumers can badge provisional rows. (Shipped
as three-state `perimeter_state` — see § Serve — with `not_determined` reserved for a
failed queue read.) The `selection_summary` + `perimeter_spawn_summary` ledgers (which
the register already gates coverage claims on, FIELDS §4) belong in the provenance
block for exactly this reason.

---

## 3. Conformance gaps in `scorer_v3.py` (data-ready ≠ scorer-ready)

Data-readiness was confirmed; the prototype predates the last two data waves and does
not yet consume several REQ/GATE planes. The extraction PR must close these:

- **Not consumed at all:** `role_holder_planes` (§15), `restaking_positions_latest`
  (§14), `upgrade_transactions` (§13 — the prototype still hits `upgrade_events`
  directly; the register requires `upgrade_action_counts` / `governance_actions_for`),
  `contract_balance_fetches.native_status` (§1), `safe_protection` (§4, the
  k/n-is-an-upper-bound gate), `gated_contract_backlink` (§4), `flow_asset_addresses`
  (§3, W2), `latch_witness` (§6b), the selection / spawn ledgers (§4).
- **Re-derives a served gate it must call instead:** `exact_empty_credit` is computed
  at serve time (`services/aggregations/analysis_detail.py:439` →
  `services/policy/capability_surface.py:137`) and never persisted; the prototype
  re-derives the earned-negative gate itself, which B16.3 bans. Call the served
  function.
- **Hardcodes:** `protocol_id=1`, `"etherfi"`, `chain_id=1` — see §1(3).

Populations with **zero positive instances on this corpus** (B14 — exercised only
through their absent branch; do not calibrate on them, and know the positive arm is
untested here): the W3 `reach_indeterminate` floor (never emitted; the 6
`reach_determined=false` rows are the documented no-flag shape at
`services/effects/recipes.py:1582`) and B20.2 `target_variable` (0 of 12
`storage_setter` flows, all the earned-absence branch).

---

## 4. Invalidation surface (what a persisted score must react to)

A persisted score is stale after any of: `advance_job`/`complete_job` on a job with
that `protocol_id` (`db/queue.py:787`/`:815`); `write_effective_function_rows`
(`services/policy/effective_permissions_writer.py:273`); `replace_control_graph_rows`
(both call sites — `resolution_worker.py:302`, `policy_worker.py:774`); the
`principal_labels` replace (`policy_worker.py:938`); `record_effect_verdict` upserts;
new `contract_balances` / `TvlSnapshot` rows (hourly); `upsert_coverage_for_contract`
(coverage stage, the audit-side scope worker, and `coverage_verify` flipping
`equivalence_status`); perimeter spawns adding contracts
(`resolution_worker.py:738`, `policy_worker.py:864`); and `maybe_queue_reanalysis`
minting a fresh job (`services/monitoring/reanalysis.py:187`). The dirty-mark +
staleness-sweep loop covers all of these without wiring a hook into each — the marks in
§1(2) are the low-latency subset; the sweep is the backstop.

---

## 5. Delivery plan — RULED (2026-08-01): one branch, one PR, backend only

The full backend lands in a **single branch and single PR** so it deploys to one
preview and is validated by **one** live-suite pass end-to-end (each push re-runs the
preview deploy + ~27-min live suite — batching is also the cheap path). Split
after the fact only if the diff proves unreviewable; do not pre-split. The frontend is
**excluded entirely** (see § Serve — the old score page gets scrubbed in a later
session).

Contents of the PR:

1. **Scorer core.** A **fresh** `services/scoring/` implementation (the prototype is a
   diagnostic, not a base to port line-by-line — see the status note at the top):
   - `distill_job_signals(...)` — a **pure function** from one job's planes to
     per-function signal rows (Layer 1), usable both in-memory and for persistence
     (see ruling §7.5);
   - `compute_protocol_score(session, protocol_id)` — the Layer-2 fold, pure /
     read-only / deterministic, consuming **signal rows**, `(chain, address)` keys,
     consuming the §3 planes per the §7.1 table, calling the served
     `exact_empty_credit`, honoring three-state on every field — including the
     delegatecall/exec destination requirement in §6 — and the §8 severity principle;
   - a thin CLI wrapper that distills all jobs in-memory then folds, so the offline
     `score_v2.json` differential oracle works with zero persistence.
2. **Persistence.** The two §7.3 tables + migration: the Layer-1 signal table and
   `protocol_scores` (+ `_latest` view).
3. **Loop + dirty-marks.** `run_score_loop` as the sixth supervised thread in
   `protocol_monitor`; the §1(2) marks; the §2 perimeter-settled stamping.
4. **API.** `GET /api/company/{name}/score` serving the ledger payload (§ Serve).
5. **Ride-along producer fix.** The §6 `self` recognizer in
   `delegatecall.py::resolve_operand` (`address(this)` → proven-fixed destination),
   with the §6 regression guards. Coverage enhancement, small and fully specified.
6. **Tests.** Offline golden tests against a fixture corpus with the prototype
   differential as oracle; live-suite coverage for the endpoint + loop liveness.

Kept **separate** from this PR (independent fixes, own passes): the zero-address spawn
guard (18 of the 40 `failed_terminal` jobs locally are discovery jobs for
`0x0000…0000`), and the pricing-coverage improvement (only 572/1,891 latest balance
rows are priced, which is what holds `confidence_pct` at ~25% — deserves its own
focused pass).

---

## 6. Worked example: the delegatecall.execute FP, and what it does / does not imply

The prototype's single largest deduction on etherfi (−30 λ, an F→C swing) was a
`delegatecall.execute` finding gated **ANYONE** at severity 1.0 on the `multicall`
function of 5 `BoringSolver` contracts. Two independent on-chain verifications (Opus,
2026-08-01, block 25662566, bytecode disassembly + behavioral proof + revert-parity)
confirmed it is a **false positive**: the `multicall` is unmodified OpenZeppelin v5.0.1
`Multicall`, whose delegatecall target is the compile-time constant `address(this)`;
delegatecall-to-self preserves `msg.sender` so every batched subcall re-runs its own
access control. It grants an arbitrary caller **zero** incremental capability.

The value of this example is the **scorer-vs-data split** it forces — the distinction
that decides what, if anything, we change:

**The false positive is a SCORER-CODE defect, not a data flaw.** The DB row published
the *honest* third state:
```
destination            = {target_kind: "indeterminate", reason: "unresolved_operand"}
destination_constraint = {state: "not_determined"}
```
The pipeline never claimed the destination was unconstrained — it said "I couldn't
resolve it," which is what witness discipline requires. The leap to
`destination_unconstrained` severity 1.0 happened entirely in the prototype
(`scorer_v3.py:1700`, an `else` that collapses `not_determined` → proven-open). Since
the prototype is throwaway, **that defect requires no data change**; it converts into a
**requirement on the real scorer**:

> **Requirement (carry to `SCORING_INVARIANTS.md` / `FIELDS.md` §3).** An
> `indeterminate` / `unresolved_operand` / `not_determined` delegatecall **or** exec
> destination MUST NOT be graded `destination_unconstrained`. It fails to
> `not_determined` and does not enter the grade — the same treatment the `flow.out`
> branch already gives an unproven destination. Absence of a resolved constraint is
> never proof the destination is open. (The register currently carries no rule for the
> delegatecall/exec destination field at all — this is the gap.)

**There is a SEPARATE, milder data item — a completeness gap, not an integrity flaw.**
The producer (`services/static/claims/matchers/delegatecall.py`, `resolve_operand`) has
recognizers for state-var / param / mapping-element / storage-setter destinations but
**none for `self`**, so a literal `address(this)` — a trivially-known constant — falls
through to the catch-all `indeterminate` at line 192. The data is not *wrong* (it
publishes no false fact), it is *needlessly uncertain*. Fixing it upgrades the outcome
from *correctly excluded* to *affirmatively credited as proven-fixed-benign*; it does
**not** fix any false positive (a disciplined scorer already gets the row right from
`not_determined`), so it is a coverage enhancement, not a correctness blocker — but it
is small and self-contained, so doing it in the same pass as the scorer is reasonable.

**The concrete edit** (verified against HEAD `d699c7b3`): in `resolve_operand`, insert
a `self` recognizer **between the binding substitution (line 181) and the
`StateVariable` check (line 182)**. After `root = bound`, `_root_variable` has resolved
`address(this)` to Slither's `SolidityVariable("this")` (it has no defining IR, so it
is returned as-is). Recognize it explicitly:

```python
from slither.core.declarations import SolidityVariable
if isinstance(root, SolidityVariable) and root.name == "this":
    return {"target_kind": "self"}   # address(this): fixed, unredirectable — an EARNED positive
```

Three attached considerations so the fix is complete, not just papered on:
- The matcher's destination-state docstring enumerates the kinds it can return; add
  `self` to it. `self` is a **proven** state (`address(this)` cannot be redirected),
  so it must read as a fixed-destination positive, never as a defaulted/weak value.
- `destination_constraint` is currently only computed on the `param` arm and hardcodes
  `{"state": "not_determined"}` elsewhere — a `self` destination should carry a
  proven-constrained constraint (state = `constrained`/`unredirectable`), so a
  three-state-respecting consumer credits severity ~0 instead of merely excluding it.
- The claim still fires (a delegatecall *is* happening) — only its destination changes
  from `indeterminate` to `self`. `_fold` needs no change (single site).
- Regression guard: the same shape appears on at least `ef.id` 3333 (`0x92b10e02…`)
  and 4505 (`0x102b3fdb…`) beyond the 5 in the finding — assert those resolve to
  `self` after the change, and that no genuinely caller/storage-supplied delegatecall
  (the `param` / `storage_setter` arms) is swallowed by the new branch.

**General rule this establishes.** A prototype finding that looks wrong is a probe into
the **data's** honesty, never a bug to fix in prototype code. Triage every such finding
into exactly one of: (a) *data is honest, consumer was undisciplined* → a requirement
on the real scorer, no pipeline change (this case); (b) *pipeline published a false or
missing fact* → a real producer/data fix. Only (b) touches the pipeline.

---

## 7. Rulings (owner-approved 2026-08-01) — the design decisions, now fixed

Formerly the open-questions section. Every item below was ruled by the owner on
2026-08-01; the build agent implements these, it does not re-litigate them. If
implementation uncovers a contradiction with `SCORING_INVARIANTS.md` or `FIELDS.md`,
surface it — don't silently deviate.

### 7.1 How each unconsumed plane enters the arithmetic — RULED (table below)
`FIELDS.md` says what the §3 planes *mean*; this table is the ruling on how each
**moves a number**. Columns: which model term it touches, what it does to that term,
and what its `not_determined` / absent branch does. The uniform principle: **every
`not_determined` branch fails closed** — no credit, no charge, no default. The build
agent formalizes each row against `SCORING_INVARIANTS.md` in the PR (and records any
row that proves unimplementable as stated, rather than improvising).

| Plane | Term | Action | `not_determined` / absent branch |
|---|---|---|---|
| `safe_protection` (§4) | weakness | k/n is an **upper bound**: a proven module/guard **withholds the k/n demotion** (credit denied). Never raises weakness beyond the un-demoted base. | Credit stands, annotated — no demotion claim either way (per the register's own hint). |
| `role_holder_planes` (§15) | weakness | `holders` is a **lower bound**; may **raise** breadth (more proven holders ⇒ broader access), never lower it. Otherwise cite-only evidence for principal enumeration. `len(holders)` is never a count; `holder_set_exhaustive` is always `not_determined`. | No effect. |
| `restaking_positions_latest` (§14) | value | Additional (entity, asset) contributions under the **same MAX-per-entity fold**, keyed by its **own** entity keys — never summed with `contract_balances` for the same entity (the plane is separate by construction; MAX dedups). | `consensus_layer_residual` **never enters arithmetic** (BAN-as-a-number); annotate only. Node-set is a floor. |
| `upgrade_transactions` (§13) | provenance-only (v1) | Counts via `upgrade_action_counts` / `governance_actions_for` **only**, never `COUNT(upgrade_events.id)`; `upgrade_count` is an upper bound; post-exclusion zero is `None`, never `0`. Executor-kind fold: **annotate**, does not modify the upgrade-authority weakness in v1. | No effect on severity/weakness. |
| `gated_contract_backlink` (§4) | reach gate | Licenses charging V's value against M's gated function (reachability input only). Honors all three register bans: never types M; a mismatch is **not** an earned negative; "analysed" ≠ "bounded". | Reach not licensed ⇒ that value is **not charged** through this pairing. |
| `contract_balance_fetches.native_status` (§1) | value | The proven-zero / fetch-failed discriminator: `native_status` decides whether an absent native balance is a real proven zero or unknown. | Fetch-failed / absent ⇒ value `not_determined`, **not counted** (and never read as zero). |
| `flow_asset_addresses` (§3, W2) | value precondition | Makes `token_identity` decidable; gates single-asset pricing. A precondition on a value read, not a term itself. | Absent ⇒ token identity `not_determined` ⇒ falls to the **unpriced branch** (a `confidence_pct` hit, not a zero). |
| `latch_witness` (§6b) | weakness | `consumed` = **re-openable via the proxy's upgrade authority**: at most an annotation whose strength is tied to *that authority's own* weakness. Never a permanent credit — the frontend sibling's `isInertOneShot → 0.95` is the flagged inv.10 violation, not a model to copy. | No credit. |
| selection / spawn ledgers (§4) | provenance + `perimeter_settled` only | Coverage/omission gate; lives in the provenance block and the §2 stamping decision. | Never a severity term. |

### 7.2 Model constants — RULED: port verbatim as provisional
Every prototype constant is carried over unchanged as **provisional**: `SEV_SCALE=60`,
`LAMBDA=0.6`, the 6-step value band (`<$100k→0.15 … ≥$1B→1.0`), per-capability
`BASE_SEV` (upgrade/delegatecall/exec 1.0, flow.out 0.9, authority.replace 0.75,
roles/ownership ≈0.55, pause 0.0-build-up, …), the freeze ladder (0.05/0.20/0.02), and
the weakness ladder. Rationale: there is no second corpus to calibrate against, so
re-derivation now would just re-fit the same single protocol. Requirements:

- All constants live in **one named parameter block** (the prototype's
  `model_parameters` output is the right shape), emitted verbatim in every score
  document, so recalibration is a data change, not a code change.
- `model_version = "1.0.0-provisional"`. Any constant change bumps the version, per
  `SCORING_INVARIANTS.md` §D (stability/comparability).
- The **B14 population-zero arms** are flagged as *uncalibrated* **in the score
  document itself** (so a consumer can see which rules have never fired their positive
  branch): the W3 `reach_indeterminate` floor, B20.2 `target_variable`, and the
  `constant` / `storage_no_setter` members of `FIXED_TARGET_KINDS`.
- Calibration happens after a second protocol is scored, as a data change + version
  bump.

### 7.3 The two persistence schemas — pinned; write the DDL first in the PR
Both need actual DDL + a migration **before the fold is written against them**,
because everything keys off their shape:

- **The Layer-1 signal-row table** (suggested name: `function_score_signals`) — the
  surface between per-function distillation (end of effects) and the grade fold.
  Minimum columns per §0/§1: `(job_id, chain, deployment_address, function_id)`
  identity; `capability` (`claim_id`); `severity_basis` + `severity_proven`;
  **references** to principals (`function_principals` ids) and value (holder-closure
  entity keys) — **not resolved copies**, because the fold does the cross-contract
  resolution; the witness tiers / gate inputs the fold needs; and every field's
  three-state branch preserved (a distilled `not_determined` must stay
  `not_determined`, never a distilled default).
  **Lifecycle (corrected 2026-08-01, supersedes "insert-only, job-scoped"):** a
  **current-state plane with contract-scoped wholesale replace**. The original
  "job-scoped, replaced on re-analysis" wording was unimplementable — re-analysis
  mints a NEW job (`maybe_queue_reanalysis` → `create_job`), so a job-scoped delete
  can never remove a prior job's rows, and stale signal sets would accumulate per
  re-analysis and double-count in the fold. Ruling: identity is
  `(chain, deployment_address, contract_id, selector, claim_id)` — `contract_id`
  is in the key because split-proxy secondary implementations share one
  `deployment_address` (live on this corpus, 4 colliding selector/claim pairs);
  the distillation writer delete+reinserts all signals for each contract it
  distills, in one transaction (the `effective_functions` currency pattern);
  `contract_id` is ON DELETE CASCADE so a contract removed from the perimeter
  stops charging exposure; `job_id` remains as a provenance column only, never in
  the identity. The fold's population query reads current rows with no
  job-currency filtering needed. `protocol_scores` (below) remains the insert-only
  history plane.
- **`protocol_scores`** — insert-only base + `_latest` view (mirror
  `contract_balances_latest`). Columns per §1(4): `protocol_id`, `model_version`,
  `computed_at`, `trigger`, `grade_*`, `confidence_pct`, `perimeter_settled`, the
  findings document, and the provenance block (per-plane row counts + max
  `updated_at` + ledger refs). **Document storage — ruled:** inline JSONB, with a
  MinIO `storage_key` spill only above ~1 MB (etherfi's document is well under that).

### 7.4 Multichain unit semantics — RULED: per-(chain, address), no cross-chain collapse
A Safe at the same address on ethereum and optimism is **two** principal units. Same
address across chains is not proof of same signer set (Safe owner sets diverge after
deployment), so merging without an owner-set proof would assert an unproven identity —
exactly the #158 twin-aliasing class re-entering through the unit key. Keeping units
split is the fail-closed direction: it slightly overstates principal independence but
never fabricates a merged super-unit or lets one chain's value pool inflate another's
finding. **Do not build the merge path in v1.** If a same-owner-set proof plane lands
later, cross-chain merging becomes a licensed collapse under a `model_version` bump,
justified against inv.13 at that time.

### 7.5 Fold input — RULED: the fold consumes signal rows; distillation is a pure function
Resolves the sequencing tension between "the fold runs over persisted signals" (§1)
and needing golden tests before persistence exists. `distill_job_signals` is a **pure
function** from one job's planes to that job's signal rows. The fold
(`compute_protocol_score`) consumes signal rows and nothing else. The offline CLI
distills **all** jobs in-memory then folds — so the `score_v2.json` differential
oracle works with zero persistence, and the persisted pipeline path (end-of-effects
distillation → signal table → loop fold) uses the **identical** distillation code.
One implementation, two feeding modes; no fold rewrite when persistence lands.

---

## 8. Discipline audit of the prototype's severity logic (2026-08-01)

Swept every severity-assignment site in `scorer_v3.py` (the `sev` / `sev_reason`
assignments enumerated at lines 1333, 1495–1554, 1678–1848) for the §6 defect class:
a `not_determined` / absent / indeterminate third state read as a positive graded
fact. **Result: the §6 collapse is the ONLY one — but it affects `exec.arbitrary` as
well as `delegatecall.execute`, not just the delegatecall rows the finding surfaced.**

- **`exec.arbitrary` shares the identical live defect.** Both capabilities run the same
  branch (`scorer_v3.py:1678-1701`); the `else` at line 1701 grades **any**
  `destination_constraint.state != "constrained"` — including `not_determined` — as
  `destination_unconstrained` severity 1.0, and both carry `BASE_SEV = 1.0`. Finding
  #10 (`exec.arbitrary` / `forwardExternalCall`) only escaped at 0.6 because it happened
  to be `constrained:external_call_revert`; an `exec.arbitrary` with a `not_determined`
  constraint scores 1.0 by the same collapse. **The §6 requirement must name both
  capabilities** (it does — "delegatecall **or** exec" — but the audit confirms the
  code path is literally shared, so one fix covers both).
- **Everything else is disciplined.** Three sound patterns, and the real scorer should
  keep to them:
  - **Build-up from zero** (`pause.set`, base `0.0`, lines 1782-1848): severity is
    *added* only from proven freeze components (`auto_expiry`, keyset test); a
    floor, never an absence-driven raise.
  - **Capability-class base refined DOWNWARD** (`ownership.transfer` → 0.35 on
    `default_admin_rules`; `authority.replace` base 0.75, escalated to 1.0 **only** when
    a registry owner resolves AND the Solmate mutator selectors are verified present,
    lines 1708-1734): mitigating witnesses lower it; the escalation is gated on positive
    proof.
  - **Capability-class base justified by the claim's proven existence**
    (`upgrade.implementation` 1.0, `roles.*`, `authorized_caller.rotate`): the severity
    reflects what the *proven* capability licenses (an upgrade can replace all code —
    maximally severe by nature); WHO can invoke it is the **weakness** axis and HOW MUCH
    value the **band** — each with its own three-state. This severity/weakness/value
    separation is correct and is **not** a collapse (severity does not rest on an absent
    witness).
  - **`flow.out` is the model to copy** (lines 1495-1676): `caller_arbitrary` requires
    `tier == behavioral_observed` (a fork proof) or the row is **withheld** (`continue`);
    an unproven destination emits `flow_out_destination_unproven` and `continue`s. This
    is exactly the treatment §6 requires for delegatecall/exec.

**General severity principle for the production scorer (carry to
`SCORING_INVARIANTS.md`):** severity must be either (a) built up from proven components
starting at 0, or (b) a capability-class constant reflecting what the claim's proven
existence licenses, refined **only downward** by mitigating witnesses. It must **never
be escalated by the ABSENCE of a constraint witness** — that is the single defect class
this audit found, and the delegatecall/exec branch is its only instance.

**Scope note:** this audit covered the severity axis. The **weakness** axis
(`principal_weakness`, `quorum_weakness`, `delay_discount`) and the **value** axis
(band / floor / reach) were spot-checked via the on-chain finding verification (#2–#7
all confirmed) but not swept site-by-site for the same defect class; the build agent
should apply the same sweep to those two axes when porting, since a `not_determined`
weakness or value read defaulting to a positive is the same bug in a different term.

### 8.1 Output/display contract — RESOLVED by scope (2026-08-01)
The prototype emits `{grade_lambda, grade_exposure, findings[], earned_negatives[],
warnings[], …}`; the live frontend (`site/src/protocolScore.js`) computes a
**different** six-axis composite and nothing in `site/` reads the prototype's output.
**Ruling: the frontend question is dropped.** The API serves the ledger payload
verbatim (§ Serve) and that payload IS the contract. The existing score page and
`protocolScore.js` will be deleted wholesale in a later session and a new page built
against the ledger — no flag-gated consumption of the old page, and **no projection**
into the six-axis shape (which would re-introduce the very collapse being retired for
cause).
