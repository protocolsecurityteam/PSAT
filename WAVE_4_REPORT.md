# Wave 4 Report — ledger closeout (legs A: effects+frontend, B: static producers, C: resolution/policy)

**Exit: PASS** (2026-07-28). Branch `fix/witness-integrity`, merged HEAD
`e3afd444` + final closeout commit. Gate: suite **5,439 passed / 0 failed**
(44 xfailed), vitest **615/615**, determinism both classes, R5 v32→v34 (two
bumps, one reason each; two recorded non-bumps with grounds), 11 test
deletions declared. Legs accepted A/C round 1, B round 2. Both tier-3 Fable
verdicts: **PASS / PASS**, controls held, differential reconciled line-by-line.

## What landed (admission test: a false claim could reach a published surface or scorer input)

### Leg A — effects/frontend (`witness/leg-w4a`, 6 commits)
- **L-46 closed** (`e88ebf3d`, R5 v33): the reach-vs-TVL ceiling now guards the
  priced-floor branch too; the four input shapes' published-state table
  verified on both planes; absent-TVL skips loudly. (Its sibling one branch up
  is new L-75.)
- **L-58 + L-60 closed** (`21be7b06`, R5 v34): the pause-window harvest is
  side/operator-aware — five fabricated severity-reducing windows (lead time
  3600, cooldowns 300/600, minus-window 300, latch-plus-window) now answer
  `not_determined` while the three gap-ceiling controls keep 2592000 and
  PlainLatch keeps `no_time_reference`; the mixed-clock L-60 shape
  discriminated; the fork-containment pin (consumers trust a bound only with
  `auto_expiry === true`) added and mutation-checked.
- **L-68 closed** (`88858399`): write-only `Candidate.effect_targets` dropped
  (no reader existed; verified again post-merge).
- **L-66 closed** (`fcee1044`): `coverageNote` composes the truncation and
  unpriced disclosures; both-facts vitest arm.
- **L-67 closed** (`52126cf9`): `test_artifact_storage_integration.py`
  idempotent (3 consecutive runs on one reused DB, clean teardown verified).
- **L-18 closed** (`8c7b8fdf`): the golden pins `action_summary` (schema 4→5);
  the regenerated diff is exactly the Wave-3 prose rows — prose copies are now
  gate-visible.

### Leg B — static producers (`witness/leg-w4b`, Fable, 7 commits)
- **L-25 closed** (`3655d3e1` + `f3c0da4b` + `4037b7bc`): `provenance._digest`
  derives `callee_args_digest` from content, not `hash()` — the operand
  tie-break that polluted every wave's differential settles to one canonical
  byte form; HEAD is byte-stable across seeds AND fresh processes (the base
  never was — see L-83, the standing method caution this fix retired); cost
  kept in band via per-instance tokens + XOR fold (perf restatement L-87);
  R5 treated as a recorded non-bump with three measured grounds (corrected at
  final closeout to drop the sample-dependent magnitude).
- **L-38 CLOSED BY ATTRIBUTION** (`2b7562b3`): the producer fix had already
  landed in Wave 1 (`a96b2ca3` — backwards-closure over internal callees);
  the two StrategyManager rows read `constrained`/`mapping_allowlist` at base
  and head alike, published into `target_constraint`. Wave 4 added the four
  mutation-checked pin arms (red under recursion suppression) and the
  source-quoted attribution. The ledger's "false unconstrained_proven on real
  rows" was stale against the merged branch — a refutation-shaped closure,
  recorded as such.
- **L-17 closed** (`ae2938fe`): the cross-contract join meets through a new
  canonical `abi_selector` stamped on every effects record (+2,220 keys, the
  only effects-plane diff); the corpus PolicyCaller/AssetRecovery pair now
  derives its `flow.out` claim at `policy_derived` (golden row added — and
  W0-7 fixture 10's consumer fix from Wave 3 means it scores at its own
  rank); `_propagatable` still gates first (negative control held). The
  declared-signature `selector` field itself survives with its false docstring
  — L-85, deliberately not rewritten here.

### Leg C — resolution/policy (`witness/leg-w4c`, 9 commits)
- **L-12 landed as reachability + honest deferral** (`d862a759`): the
  reconciler join rekeyed so orphaned-contract marker rows are reachable; the
  32-row convergence proof is structurally unsatisfiable locally (both
  orphaned contracts have zero jobs at their address — a fresh analysis job is
  the missing precondition, cost boundary), and lens 1 verified the deferral
  cause true. Sibling blind spot found and ledgered (L-79); the orphan-pool
  cost hazard quantified (L-78).
- **L-72 REFUTED on data** (`eeee8a31`): no empty-selector named row exists in
  any local DB (1,773/1,773 carry real selectors; fids 2893/2894 hold correct
  keccaks; the producer cannot mint `''` for a named function). The
  population-level invariant is now pinned instead. Wave 3's reviewer claim
  did not survive reproduction — a successful outcome under the charter.
- **L-34 closed with a correction** (`c8f1e905` + `47e1a234`):
  `not_a_contract` → `not_analyzable` on the analysis-detail payload (230
  Safes are literally contracts); the legacy token was never persisted, so the
  legacy enum member was dropped rather than migrated.
- **L-35 closed** (`ff1811e0`): a failed recursive accessor answers
  not-determined instead of silently narrowing the gate set (mutation-tested).
- **L-36 closed** (`9ffefee4`): the three-state columns asserted THROUGH the
  resolution_worker writes (SQL-NULL vs jsonb-null discipline at the
  persistence boundary).
- **L-52 / L-53 closed** (`5e871f47`, `195713af`): the unattributed-edge
  no-label rule and the artifact-plane `authority_openness` key are pinned
  (L-53's mutation: 2 red / 56 green with both blocks stripped).

### Final closeout (driving agent, this commit)
The two comments carrying the base-sample-dependent "12 verdicts on 6 units"
magnitude restated per L-83 (both verifiers required it); `policy_caller.sol`'s
stale "derives nothing" comment corrected; ledger swept L-75…L-88.

## Differential integrity
Full-replay differential (88 units, both sides, separate checkouts): predicate
trees show **179 operand-plane leaf diffs across 35 cids, zero structural
changes** (no leaf/tree/operator/authority_role/gate moved), all attributed to
the L-25 settle; effects show **exactly the +2,220 `abi_selector` keys**
(L-17) and nothing else; **published claims, controller-tracking targets, and
summaries: 0 diffs** — the L-41 gate re-projection confirms no new
provenance-absent targets. The merge's golden regeneration was byte-identical
to the union of the legs' declared diffs. The one initially-unattributed row
resolved to L-86 (the `leaf.expression` SSA-name noise, a NEW ledger entry,
not a leg defect). **Standing correction (L-83): the base side of every tree
differential in this effort was one sample of a distribution** — the pre-fix
tie-break varied at a fixed seed; only HEAD is byte-stable. Base-side counts
must never be re-cited as measurements.

## What was not checked
- No pipeline stage ran: L-12's convergence, L-81's persisted-selector
  rewrite, the L-41 gate, and every producer-side change from Waves 1–4 bind
  the next real run; the effects cache remains unmeasurable-by-hit.
- No second chain; every count remains a lower bound (one protocol, chain 1).
- The 4 source-less contracts and 48 effects-artifact-less rows stay invisible
  to projections; 594 protocol-NULL rows never enter the cascade (L-69).
- Playwright visual baselines were run in Wave 3 (4/4) and not re-run this
  wave (no CSS changes; Leg A's BalanceTable change is logic + one test).
