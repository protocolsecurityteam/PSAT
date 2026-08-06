# Reach Model Fix — Scope & Spec

**Status:** scope + spec + orchestration runbook (§9). Nothing implemented. Companion to `REACH_MODEL_AUDIT_HANDOFF.md`.
**Written:** 2026-08-05, from a seven-lane adversarial audit against the local etherfi
snapshot (`protocol_id 1`, DB on port 5433), branch `fix/confidence-perimeter-admission`.
**Evidence base:** every number below was reproduced read-only against that snapshot or
read from source; per-lane notes live in the session scratchpad `findings/`. Verdicts are
tagged CONFIRMED (evidence reproduced), PLAUSIBLE (mechanism read, not yet triggered on
data), REFUTED, or LATENT (real in code, unfired on this corpus).

Baseline of the shipped document (`cli score --protocol 1`): `grade_lambda 54.1614`,
`grade_exposure 71.7`, `confidence_pct 29.0`, `exposure_usd 1,227,107,593.64`,
`tracked_total_usd 4,336,022,005.48`, 27 findings.

---

## 0. The one-paragraph diagnosis

The reach model answers exactly one question — *"is entity E in the control closure of
principal P?"* — and then substitutes **E's entire priced balance sheet** for the three
questions it never answers: (Q-cap) *what can P make E do?*, (Q-cond) *do E's own guards
even permit it?*, and (Q-mag) *how much value does that move?* Whenever a magnitude is
unwitnessed — which is the case for **387 of 442 proven-reach signals** — the fold returns
`held = value_plane.total(key)` as a **floor dollar figure that enters the grade**
(`fold.py:1178-1180`). That is the banned move named in `SCORER_DISCIPLINE_CONTRACT.md` §1
and inv. 1: an unproven quantity published as a positive number instead of `not_determined`.
The single fact that makes the fix tractable: the confidence axis has no term in which an
unproven magnitude can land (`_confidence` measures reachability-answered, capability-scored,
value-priced only), so the code has nowhere to put the unknown *except* the grade. Give it
that term and the over-charge has an honest home.

The defects decompose onto three independent axes. Axis 2 dominates the blast radius.

| axis | question the code fakes | defects | fold-only? |
|---|---|---|---|
| **1 — reach membership** | can P reach E, and to do *what*? | D1, D2, D4, R10, R12, R13, R14, R15, R16, R18, R19 | yes (fold-only) |
| **2 — magnitude** | *how much* does the reach move? | D3, R2, R3, R4, R11, H8 | fold-only to stop the over-claim; **compositional** to restore a positive number for gate-control (reuse the destination's `flow.out` witness — Phase 6); only the **freeze fraction** needs genuinely new evidence |
| **3 — value-plane hygiene** | are the balances even current / real? | R5, R6, R7, R8, R9, R20, R21 | yes |

---

## 1. Findings register

### 1.1 The four handoff defects — all CONFIRMED

**D1 — the closure edge is unlabeled.** `services/scoring/planes.py:406` `load_control_closure`
returns `dict[str, set[str]]`; `edge.label`, `edge.relation`, and any selector are never read
(the query selects them, the loop discards them). The walked graph cannot tell "X may call
`exit()`" from "X may call `pause()`". CONFIRMED.
- **Correction (scope of the fix is larger than the handoff implies).** The label carries a
  role number (`"roles 12"`) or a state-variable name (`owner`, `hook`), **never a selector**:
  `0 / all` labels contain `0x`. The role→selector join needed to make an edge *mean*
  something lives in `function_principals.details.trace[].selector` + `effective_functions.selector`,
  not on the edge and not in `role_definitions`. Budget for it as a two-table join, not a
  plumbing change.
- **Correction.** 55 of 285 `role_principal` edges carry the literal label `"role principal"`
  with no role at all; a role-scoped walk must publish that shortfall as `not_determined`, not
  drop the edges.
- **Correction.** `CONTROL_RELATIONS` (`planes.py:32`) walks `controller_value` +
  `role_principal` + `mapping_member` = 3277 edges on p1, **88% `controller_value`** whose
  label is a getter name licensing nothing. D1 is mostly a `controller_value` problem; the
  three-hop role example is unrepresentative of the volume.

**D2 — composition ignores the conditions that gate it.** `fold.py:1183` `_closure(seeds, closure)`
receives only address→address adjacency. `FunctionSignal` (`schema.py:268-325`) has no
`conditions` field; `fold.py` never imports `EffectiveFunction`. The disproving
`initiator != address(this)` guard on `finishSolve` is stored verbatim in
`effective_functions.conditions` (id 570) **and** duplicated into `function_principals.details.conditions`
(ids 12877-12879) — the fold consults neither. CONFIRMED. The fold already articulates the
exact argument at `fold.py:693` (*"the gating contract may impose its own conditions. The hop
is a confidence fact, never this row's weakness"*) and applies it to **weakness only**, letting
**reach** walk unconditionally.

**D3 — no magnitude witness for the whole class; the fallthrough charges the sheet.**
`distill.py:1161-1170` (tail) and `:1146-1153` (pause.set) hardcode
`magnitude=Tri[float].not_determined()`; `_proven_number` (the sole constructor of a determined
magnitude) is called only at `distill.py:751/764/787`, **all three inside `_flow_reach`
(`:724`)**. With magnitude undetermined and `transitive=True`, `_entity_contribution:1178-1180`
returns `held = value_plane.total(key)` — the whole sheet. CONFIRMED, table reproduced exactly
(0/341 across the eight transitive capabilities; 55/161 for flow.out).
- **Correction (the class is bigger than 341).** 442 signals are `value_state=proven_reach`;
  only 55 carry a magnitude ⇒ **387 charge a balance sheet with no magnitude witness** = 341
  transitive + 46 non-transitive (`transfer_policy.configure` 18, `roles.revoke` 7,
  `lz_oapp.set_peer`/`set_delegate` 4+4, `pause.set` 4, `flow.in` 6, `timelock.set_delay` 3).
  A fix scoped to `TRANSITIVE_CAPABILITIES` silently leaves the 46.

**D4 — the category error.** `constants.py:140` `TRANSITIVE_CAPABILITIES` (8 members) conflates
**code control** — `upgrade.implementation`/`exec.arbitrary`/`delegatecall.execute` (86 signals),
where closure expansion is *sound* (control the code, exercise everything E is authorized to do)
— with **gate control** — `authority.replace`/`ownership.transfer`/`roles.grant`/`roles.configure`/
`authorized_caller.rotate` (255 signals, 74.8%), where you control only *who may call E* and E's
own code still bounds what happens next. CONFIRMED, counts exact.

**The sharpest regression case is an inversion the handoff §2 does not name.** AtomicQueue and
AtomicSolverV3 share one RolesAuthority `0x4df6b733…`. The principal that provably *can* reach
the $1.5M — the timelock controlling that authority — is published at **exposure $0.00**
(`findings[2]`), while the two principals that provably *cannot* (`0x2322…` blocked by the
initiator guard; `0xf8553c85…` bounded to a $0 share balance) are charged **$1,505,140.39** and
**$724,697.22**. Same protocol, same document. Use this, not the single over-claim, as the
headline test.

### 1.2 New CONFIRMED defects

**R2 — repoints charge an unnamed sheet, unvalidated (Axis 2, realized).** `distill.py:797-809`
`_repointed_entities` returns `entity_key(facts.chain, witness["callee"])` /
`...["configures"]` with **no** protocol / chain / existence / shape check, and no check that
the witness naming the entity is the witness that proved reach — in stark asymmetry with
`_licensed_reach_entities` (`:324-361`) 40 lines above, which checks all three. Consumed at
`distill.py:1161` (`or repointed`) and `:1123-1134`. The producers are `policy_derived`-tier
static inferences (`services/static/cross_contract.py:205-247` for `callee`, `:259-309` for
`configures`, whose own docstring concedes *"the written set-var stands in for the spec's 'read
by the hook fn'"*). CONFIRMED and **realized**: the published base row
`transfer_policy.configure` (host Teller `0xe2acf9f8`, unpriced) draws 100% of its
`value_at_stake_usd $150,410.13` from a repoint onto BoringVault `0x86b5780b` — the fold's own
no-repoint counterfactual publishes `not_determined`. Second sub-defect: the `or repointed`
clause **upgrades `value_state`** from `capability_not_scored(not_determined)` to
`proven_reach/floor` for 6 `flow.in` rows solely because a callee was named — bounded from the
grade today only by `enters_grade` needing a proven severity, so the fail-closed property is
already gone.

**R3 — the `gated_contract_backlink` licence is inverted; inert on 100% of the real population
(Axis 2).** The producer (`services/resolution/recursive.py:1480-1497`) writes the node at the
**principal's** address with `details.gated_contract_address = V` (the gated contract). The
consumer (`distill.py:253-263`, `:344-352`) matches on `gated_contract_address == this contract`
and then anchors on `node.contract_id` — which is V again. Measured on protocol 1: **53/53**
backlink nodes (69 DB-wide) have `gated_contract_address == own contract`, **0/53** have
`node.address == it`. So
`licensed_reach_entities` can only ever contain the distilled contract's own key; `extra_keys`
(`distill.py:1037-1040`) is a no-op union; **0** licensed signals carry any foreign key. The
green test `test_scoring_distill_fold.py:822-881` encodes a payload
(`gated_contract_address = manager.address`) the producer never writes, so the intended
semantics have never once fired. CONFIRMED. **Trap for the implementer:** correcting the join
*without first bounding the magnitude* converts a cite/gate object (a B14 **uncalibrated arm**,
`constants.py:223`) into a magnitude — a measured refold showed one row jumping
`$0.00 → $1,411,758.83` (3.33×). Live defect meanwhile: `reach_gate_state="licensed"` is
published as a positive on **197 signals across 15 contracts** where nothing was licensed, and
finding-level citations point at the backlink for entities actually admitted by the unlabeled
closure (D1) — witness laundering against the field's own cite obligation.

**R4 — one witnessed magnitude summed across N keys (Axis 2, realized).** `_entity_contribution`
is called per key; `_row_value` **sums** the results (`fold.py:1150`). But the magnitude is one
number for the whole call. The `proven_exact` branch caps per key with `min(held, magnitude)`
(`fold.py:1176`) but the sum across keys is uncapped, and the `proven_floor` branch (`:1177`)
has **no `min` at all**. `_grade` names this exact hazard one layer down (`fold.py:1221-1223`)
and guards against it; `_row_value` does not. CONFIRMED: `flow.out withdraw` on `0x308861a4`
carries `proven_exact $28,138,639.99` over 2 keys → `min(26.4M,28.1M)+min(1.77M,28.1M) =
$28,177,358.92`, $38,718.93 over the witness; both keys land in published rows. Floor branch is
unbounded (N keys × full floor, capped by nothing, not even the sheets); latent at N=1 on this
corpus.

**R5 — MAX reduces across two block-heights of the same account (Axis 3, realized).**
`planes.py:153-155` reduces `MAX` per `(canonical entity, asset)` over **all**
`contract_balances_latest` rows for that key — but the alias fold (`:140`) puts a proxy's live
`tvl`-writer rows and its implementation's frozen `resolution_worker` rows in the same bucket.
Those are the same on-chain account read twice at different heights, not two holdings. The loop
reads neither `observed_address` nor `block_number`. CONFIRMED: LiquidityPool `0x308861a4`
native ETH — `tvl` live `$14,346,384.46` (block 25,691,487) vs `resolution_worker` frozen
`$26,404,230.63` (block 25,658,048, 4.7 days stale); MAX publishes the stale figure, an **84%
inflation**. Corpus-wide: 66 competing pairs, 10 stale-max, **$12,182,490.19** inflation,
`differing_observed_address = 0` (never deduplicating — always a high-water mark). This inflates
`tracked_total_usd`, the denominator of `grade_exposure`, and three published rows (the two
largest `pause.set` / `upgrade.implementation` rows charge `0x308861a4` at the stale $26.4M).

**R6 — rounding-dust `$0.00` consumed as a proven price (Axis 3, realized).** `usd_value` is
`numeric(20,2)`; a $0.0035 holding stores as `0.00`, which `planes.py:80-90` `total()` returns
as `0.0` — a *determined* positive fact, indistinguishable from a proven-empty sheet (the NULL
guard at `:150` correctly refuses only NULLs). CONFIRMED: `base::0x04c0599a` has 10 rows at
`0.00` and 190 at NULL; `total() == 0.0`. **21 of 62 priced entities (34%)** have `total()==0.0`,
their entire sheet rounded dust. Consequences: (1) four findings publish
`value_at_stake_usd 0.0 / proven_reach / exposure 0.0` — a phantom earned negative ("proven to
reach nothing") from a price lookup that answered 10 of 200 rows; (2) large rows carry phantom
"priced" entities (`upgrade.implementation 0xcdd57d11` reach 15, of which 7 are $0.00; the §2
AtomicQueue row's 7 include 2 at $0.00); (3) `priced_entities += 1` on `held==0.0`
(`fold.py:1237`) sets `any_priced=True`, which gates `grade_state=computed` — an all-dust
protocol would publish a full grade at `grade_exposure 100.0`; (4) confidence value-term
inflated `33.7% → 27.8%` if a strictly-positive total is required (a 21% relative over-claim,
5 points from becoming the headline).

**R7 — budget exhaustion published as a measured `$0.00` (Axis 3, realized).** `fold.py:1237`
increments `priced_entities` **before** the budget test at `:1240-1242`. When two findings have
consumed a per-entity budget (`claimed[key] → 1.0`), a third takes `room = 0` on every entity
and lands in the `if priced_entities:` branch with `mine == 0.0`, publishing `exposure_usd: 0.0`
with a list of charged entities and **no `exposure_gaps` entry** (gaps fire only on `unpriced`
or `None`). CONFIRMED on `findings[2]` (`$2.23M` reach, `>=$1M-$10M` band, 5.94 λ-points, and
`exposure_usd 0.00` in the same object). Indistinguishable from a genuinely-measured zero.
Affects 3 rows (`#2`, `#8`, `#26`).

**R8 — exposure attribution decided by lexical address order (Axis 3, realized).** `fold.py:1067`
sorts `(-raw_points, capability, principal_unit)`; the AtomicQueue pair ties on the first two,
so `ethereum::0x2322… < ethereum::0xf855…` hands the **unreachable** principal 67.5% of the
$2.23M and the **reachable** one the remainder. Deterministic (tests stay green) but arbitrary,
and it inverts the true attribution. CONFIRMED.

**R9 — a merged Safe unit's weakness is `max` over members, applied to the union of reach
(Axis 1, realized).** The merge *predicate* is sound (REFUTED as a bug: all 4 merges on p1 are
same-chain, owner-set-backed, and satisfy `len(shared) >= max(k)`). But `_row_for`
(`fold.py:394-398`) keeps the **maximum** weakness across members while `_row_value` folds the
**union** of their reach, with no tie between a member's weakness and the entities that member
reaches. CONFIRMED on unit `ethereum::0x5ec5e6b4` (members 3/7, 3/7, 4/8; disjoint reach):
`$1,140,884.60` reachable **only by the 4/8 Safe** is published at the **3/7 rung** (weakness
0.55 vs its earned 0.35) — the document's own `min_coalition_to_act_as_both: 4` contradicts it;
`raw_points 10.5 → 16.5` (+57% via band inflation); `exposure $661,688.62 → $889,906.68`
(+34.5%). Contravenes `SCORER_DISCIPLINE_CONTRACT.md` §4 (k/n is an upper bound) and inv. 5
(weakest *path to that entity*, not weakest member of a unit).

**R10 — the zero address is a live control hub in the reach closure (Axis 1, LATENT).**
`load_control_closure` reverses every edge into `controls[principal].add(anchor)` with no
admission rule (`planes.py:429`), so ownership renounced to `0x0` records
`controls[chain::0x0] ⊇ {anchors}`. `_closure` has no sentinel guard. `_confidence` **does**
(the `5b5db0c4` fix, `fold.py:1316-1324`, `zero_address_entities_excluded: 2`) — the identical
gap, one function apart. Measured graph: `ethereum::0x0` controls 83 entities, `_closure` = 135
(the single largest fan-out in the graph), priced sum **$4,327,174,753.87** (99.8% of tracked).
Unfired today (0 signals seed `0x0`, and `0x0` has no in-edges so it is seed-only) — but any
witness repoint yielding `0x0` (R2's `callee`/`configures` path) hands one finding the entire
sheet. CONFIRMED in code + graph, LATENT on data.

**R11 — confidence has no reach-magnitude term (Axis 2, structural PREREQUISITE).** `_confidence`
(`fold.py:1340-1392`) has exactly three terms: reachability-answered, capability-scored,
value-priced. A `pause.set`/gate-control signal counts as fully answered, fully scored, its
entity priced — so there is **nowhere** for "we could not prove how much this reaches" to land.
Measured: `confidence_pct` is identical (29.0) in the base run and in the counterfactual where
pause reach is `not_determined`. This is *why* D3 and H8 push their unknowns into the grade.
CONFIRMED. Adding this term is the enabling change for the entire Axis-2 fix.

**R12 — the confidence perimeter frees confidence when a relation is declined (Axis 1,
monotonicity, realized).** `_confidence`'s closure term (`fold.py:1334-1336`) is built from the
**consumed** relation set, not the discovery-fixed one, so entities the pipeline *proved* are
principals of gated functions never enter the denominator purely because the scorer declines to
walk `capability_principal`. Measured by in-memory refold: consuming it moves the perimeter
`295 → 360` (a **+65 delta**, not a directly queryable count — 85 distinct `capability_principal`
principals exist), denominator `52.75 → 62.50`, and **published confidence `29.0 → 28.5`** — i.e.
confidence is 0.5pp *higher* because *less* was consumed. This violates inv. 6 (monotone in
resolution work) and is the exact shape `5b5db0c4` fixed one function over. CONFIRMED.

**R13 — `unconsumed_reach_relations` under-publishes its own bound (Axis 1, realized).** Its
docstring (`planes.py:456`) promises *"edges that exist but are NOT walked as reach, and why"*
and reports **one** relation (`capability_principal`, 217). Reality on p1: `safe_owner` (1689),
`controller_value_unattributed` (216), `external_call_target` (1539) are excluded by comment or
not named at all; `timelock_owner`/`proxy_admin_owner` are in `db.CONTROL_EDGE_RELATIONS` but
absent from `planes.CONTROL_RELATIONS` and would be **silently dropped** the day they carry rows.
3,444 excluded edges are invisible to the consumer. The stated `capability_principal` rationale
("budget-gated, so not a witnessed fact") is itself REFUTED: `FP_MATERIALIZE_LIMIT = 64` and the
max distinct FP principals per anchor on p1 is 39, so the budget never bites, and the same
spawn-budget logic gates the entire closure equally. CONFIRMED (a no-silent-caps violation, §7).

### 1.3 New CONFIRMED-but-LATENT defects (real in code, unfired on this corpus)

- **R14 — shared-implementation `min(key)` mis-fold.** `planes.py:124` pins the lowest proxy key
  when two proxies share an impl; a finding reaching only proxy B's impl is then charged proxy
  A's whole sheet and publishes A as a reach entity, and consumes A's exposure budget. Reproduced
  against the real `ValuePlane` + `_entity_contribution`. **Zero shared-impl pairs exist anywhere
  in the DB**, so unfired — but 26 of 29 alias keys are already closure endpoints, so the walk
  routinely lands on impl keys; one shared impl arms it. The `shared_implementations` annotation
  is published (`planes.py:236`) but **read by no code**, is pairwise (never names the pin), and
  its content is `contracts.id`-order-dependent under a block advertising determinism.
- **R15 — `canonical()` is a single-level lookup** (`planes.py:78`). An alias chain `J→I, I→P`
  would orphan J's balances and double-count P in `tracked_total`. 0 chains in the DB.
- **R16 — `Contract.beacon` is never walked, anywhere.** Whoever controls an `UpgradeableBeacon`
  sets the implementation for every proxy pointing at it — the broadest code-control link — and
  the closure has no representation of it. p1's only beacon is self-referential. The column is
  already populated by the same slot read that populates `admin`.
- **R18 — renounced-to-`0x0` is a discarded earned negative.** 342 consumed edges name `0x0` as
  principal across 86 anchors; `controller_value → 0x0` is *proven-absent* authority (renounced
  ownership), which the loader converts into a live control edge instead of reading as a resolved
  constraint. The mirror of the whole D-class: a proven fact thrown away. (Contained today only
  because `0x0` is seed-only; see R10.)
- **R19 — the `contract.admin` edge is uncitable and unguarded.** Synthesized in the loader from
  a `contracts` column (`planes.py:431`), it exists in no edge table, carries no label/provenance,
  and no finding can cite it; it also has no `0x0`/`is_proxy` guard. Both p1 admin rows are dead
  (source-only, unreachable), so its only live effect is a correct +0.2 confidence gap. Latent
  over-claim: its 26-entity closure is code-control at hop 1 and gate-control (D4) thereafter.
- **R20 — `load_role_holder_floors` is not protocol-scoped** (`planes.py:376-403`): it queries
  every `RoleHolderPlane` row in the DB, so its population depends on what other protocols have
  been analysed — a monotonicity smell against inv. 6 (floors may only raise weakness, so it is
  a smell, not yet a violation).
- **R21 — `signal_entities_outside_perimeter` checks deployment keys only, never reach keys**
  (`fold.py:1399`). Two reach keys sit outside the perimeter on this snapshot, invisible to the
  disclosure; both unpriced today, so nothing is charged, but a priced one would be charged into
  a finding while absent from the confidence denominator meant to account for it.
- **R22 — `_aggregate`'s `max(instance.severity)` breaks `_fold_severity`'s own contract**
  (`fold.py:956` vs `:816-820`): a `FREEZE_SUSTAINABLE` proven for one member's key set is
  charged to every member of a merged row. No live instance.
- **R17 — contradictory `exact` owner sets silently arbitrated.** Safe `0x607d0c7e` has two
  mutually-exclusive `exact` owner sets in `function_principals`; `principal_enrichment.py:83-89`
  *drops* such Safes, but the scorer keeps the highest-`id` row (`_safe_by_key`) and publishes
  `Safe 2/5` while the merge decision used the 4-owner witness. Harmless here (no shared owners).

### 1.4 REFUTED hypotheses (reported as explicitly as the confirmations)

- **H1 — cycles inflate reach/exposure/perimeter. REFUTED.** 23 two-cycles + 21 non-trivial
  SCCs exist (incl. AtomicQueue↔AtomicSolverV3), but `_closure`'s `seen` set fully neutralizes
  them: reach sets, exposure ($2,229,837.61 with and without the back-edge), and perimeter (297)
  are byte-identical acyclic-vs-cyclic; the walk is order-invariant (5 permutations). The AQ
  over-claim is caused by D1/D2, not the cycle. The cycle's *only* effect is to give two
  principals identical reach sets — which is R8's territory, not an inflation.
- **H7 — double-charging inflates a published total. REFUTED on every published dollar.** The
  exposure budget (`claimed[key] ≤ 1.0`) was independently replayed over the 27 findings: union
  45 entities, 0 overcharged, replayed total `$1,227,107,593.64` == `provenance.exposure_usd` to
  the cent; the AQ trio sums to exactly the 7-entity sheet. `_grade` and `_confidence` share no
  arithmetic. The proxy/impl guard (`fold.py:1132/1220/1325`) actively suppresses a 59% closure
  inflation. `SUM(value_at_stake_usd) = $9.15B` (2.11× the sheet) is published **nowhere**. (The
  per-finding overlap in `value_at_stake` is by design — MAX per entity, not a global SUM.)
- **H9 — cross-chain leakage. REFUTED empirically on a genuinely multi-chain snapshot** (p1 has
  ethereum/optimism/base/scroll contracts; 12 addresses on two chains). `entity_key` is the sole
  key constructor and rejects bare addresses; 0 mixed-chain closure edges (anchor chain is
  stamped on both endpoints); Safe merge, timelock collapse, role floors, licensed reach, and
  the principal plane all carry explicit chain guards. 0 findings span >1 chain. One documented
  *fiat* (endpoint chain inherited from the anchor row, not witnessed per node) is a
  witness-discipline nit affecting 3 unpriced edges, not a leak; closing it needs a chain column
  on `control_graph_edges`/`_nodes` (pipeline).
- **H5 — `contract.admin` over-claims value. REFUTED** (both p1 admin edges are dead); the
  *structural* problems it surfaced are R19 + the D1/D4 return-type prerequisite.
- **H10 — the Safe merge predicate pools principals unsoundly. REFUTED** (all merges witnessed);
  the *weakness attribution* is R9.

### 1.5 Adjacent PLAUSIBLE / pipeline-side leads (not scored here; see deferrals)

- Sibling selection is chain-blind and address-keyed (`workers/policy_worker.py:1132-1183`,
  last-writer-wins across chains); p1 has colliding eth/base pairs, and `0x86b5780b` holds
  `$150,410` on base vs `$40,599,387` on ethereum — a 270× mis-charge *if* the wrong twin's
  evidence ever drives a repoint key. Not proven mis-fired (identical deploys agree). Pipeline.
- `membership_quality` (`exact` / `lower_bound`) is never read by the scorer though two other
  modules gate on it; no test pins which reading is right.
- Split-proxy `secondary_implementations` are absent from the value-plane alias map; not a
  double-count here, but an `adminImpl`'s own balances are stranded (reached only by
  `delegatecall`) and would be a sheet-as-reach error if ever walked.

---

## 2. Root cause, per defect: fold-repairable or needs new pipeline evidence

| defect | root cause | locus |
|---|---|---|
| D1 | scorer discards extraction that succeeded (label/relation on the edge) | **fold** to plumb; **pipeline-adjacent** join (`trace[].selector`) to make role→selector meaningful |
| D2 | fold never queries the already-stored `conditions` | **fold** (read `effective_functions.conditions` into the closure walk) |
| D3 | the magnitude witness was never *composed* for non-flow capabilities | **fold** to *stop* charging the sheet (publish `not_determined`); **compositional** to restore a positive number — a gate-control reach's magnitude is the `flow.out` witness of the destination function it unlocks (Phase 6), which already exists for 100% of etherfi's gate-control reached value; only the freeze fraction needs new pipeline evidence |
| D4 | one capability table conflates code- and gate-control | **fold** (`constants.py` split + branch) |
| R2, R3 | reach membership set from unvalidated / mis-joined witnesses | **fold** to stop; **compositional** (Phase 6) to publish a bounded positive |
| R4, R5, R6, R7, R8, R9, R14–R22 | fold-local logic errors | **fold** (R6 full close needs a `priced_below_resolution` third state — column/plane, i.e. pipeline) |
| R11 | confidence model is missing a term | **fold** |
| R12, R13 | confidence/exclusion built from the consumed set, not the discovery-fixed set | **fold** |

**The honest headline:** every fact needed to *stop the over-claim* is already in the DB and the
fix is fold-only. Publishing a *correct positive magnitude* for the gate-control class is **mostly
compositional, not new capability**: a gate-control reach's magnitude is the `flow.out` witness of
the destination function the gate unlocks, and those witnesses already exist — on etherfi they
cover **14 of 24** entities in gate-control reach and **100% of the reached priced value** (the
uncovered 10 are $0 dust). What is left is composing them along the licensed reach path (Phase 6,
after the role→selector scoping of Phase 5). The *only* piece that needs genuinely new pipeline
evidence is the **freeze fraction** (pause.set — what share of a sheet a pause immobilises) and
any gate-control destination that carries no `flow.out` witness (none priced on etherfi today).
Those stay `not_determined` (charged to confidence) until the evidence exists.

---

## 3. Proposed model change

### 3.1 Axis 1 — reach membership carries relation and scope

1. **Change the closure representation** (shared D1/D4/R19 prerequisite). `load_control_closure`
   returns edges carrying `(relation, scope)` where `scope` is the parsed role number (or the
   state-var name, or `not_determined` for the 55 unlabelled role edges), **not** a bare
   `dict[str, set[str]]`. Nothing else changes behaviour in this step.
2. **Split the capability table** (D4). `CODE_CONTROL_CAPABILITIES = {upgrade.implementation,
   exec.arbitrary, delegatecall.execute}`; `GATE_CONTROL_CAPABILITIES = {authority.replace,
   ownership.transfer, roles.grant, roles.configure, authorized_caller.rotate}`. Both remain
   "transitive" in the inv. 7 sense (both expand over the closure); they differ in **what the
   expansion is bounded by**.
3. **Code control expands over the *whole* closure of the controlled node — but still bounded by
   each destination's caller-conditions** (D2 applies here too). Owning A's code lets A be made to
   call anything A is authorized to call, so the reach is **not** scoped to a particular role's
   selectors the way gate control is — that is the sense in which it is "broader." It is **not**
   unconditional: reaching a downstream B still requires B's own guards to pass with the controlled
   node as caller. The headline example proves it — `AtomicSolverV3.finishSolve` opens
   `if (initiator != address(this)) revert` (`effective_functions` id 570), so even holding
   `upgrade.implementation` over AtomicQueue and rewriting it to call `finishSolve` reverts
   (`initiator` = AtomicQueue ≠ AtomicSolverV3). So code control walks a hop **except where the
   destination's `conditions` disprove the controlled node as caller**; where the conditions cannot
   be evaluated, the hop is `not_determined`, not walked-as-proven. (The handoff's D4 framing of
   code-control closure as "sound by construction" is imprecise on exactly this point; 86
   code-control signals on p1 are affected in principle, latent only because no code-control row
   here walks through such a guard.)
4. **Gate control expands only to what the gate licenses** (D1/D2). From a gate over node A,
   reach is: A's own directly-gated functions, then the closure **only through edges whose
   `scope` the gate actually confers**, and **only where `effective_functions.conditions` for the
   next hop do not disprove the caller** (the `initiator != address(this)` case). Where the scope
   is unlabelled (55/285 edges) or the conditions cannot be evaluated, the hop is **not walked as
   proven** and is published as `not_determined`, not silently dropped and not walked. The two
   classes thus share the *condition* gate; they differ only in the *scope* gate (gate control is
   restricted to the licensed role's selectors, code control is not).
5. **Admission rules at closure construction**, each publishing its own count (the `5b5db0c4`
   template): refuse `chain::0x0` as principal *and* as anchor (R10); read `controller_value → 0x0`
   as a renounced-authority earned negative rather than an edge (R18); walk `Contract.beacon` as a
   code-control edge (R16); resolve the alias map to a fixed point and fail loud on a cycle (R15).
6. **Confidence perimeter and `unconsumed_reach_relations` are built from the discovery-fixed
   relation set, not the consumed one** (R12/R13): declining to walk a relation charges confidence
   (it does not free it), and every excluded relation is enumerated with its own reason and count.

### 3.2 Axis 2 — magnitude is a witness or it is `not_determined` (never the sheet)

7. **Add a fourth confidence term: reach-magnitude-answered** (R11). A proven-reach signal whose
   magnitude is `not_determined` counts as *unanswered* in this term — the honest home for the
   unknown that today lands in the grade. **The denominator must be defined precisely and
   measured before this ships**, because `confidence["pct"] = min(...)` over the terms
   (`fold.py:1389`): if the new term is denominated over *all* proven-reach signals it becomes the
   new minimum (55/442 carry a magnitude) and craters the headline toward the low-teens — which
   may be the honest number, but it must be a measured decision, not a side effect. The proposed
   denominator is **only signals for which a magnitude is a meaningful question** — i.e. reach
   claims whose capability *could* carry a fork-proven or holder-witnessed magnitude — so that a
   capability with no magnitude concept does not spuriously drag the term down; the exact set is a
   ruling to fix and measure at the Phase 3 gate, and the resulting `confidence_pct` must be
   quoted in the migration note.
8. **A `not_determined` magnitude never charges the sheet into the grade.** `_entity_contribution`'s
   fallthrough (`fold.py:1178-1180`) must return `not_determined` for the dollar magnitude, not
   `held`. The finding **stays alive** at the existence/floor weight (`UNPRICED_BAND`, per inv. 7's
   floor rule — a rug on an empty contract still scores), and the magnitude gap is charged to
   confidence via the new term. This is the core change; it is what moves the $745M out of the
   grade.
9. **Repoints and backlink set membership only from validated value-witnesses** (R2/R3). A repoint
   is admitted only when its witness is a *value* witness (not a `policy_derived` call/config
   inference), passes the same protocol/chain/existence checks as `_licensed_reach_entities`, and
   **never upgrades `value_state`** or supplies a magnitude it did not prove. The backlink join is
   corrected (match `node.address`) **only together with** the Axis-2 magnitude bound, so a
   cite/gate object cannot become a magnitude.
10. **A witnessed magnitude is a per-call quantity** (R4): cap `Σ`-over-entities at the witnessed
    magnitude for `proven_exact`; for `proven_floor` require a per-holder apportionment witness or
    fall to `not_determined`.
11. **pause.set** (H8) is the same rule: `pause_effective` proves *membership* (the latch takes
    effect), never a *fraction*; the immobilised-dollar magnitude stays `not_determined` and is
    charged to confidence, not banded off the whole sheet.

### 3.3 Axis 3 — value-plane hygiene

12. **R5:** reduce balances by *latest observation of the observed account* (key on
    `observed_address` + `block_number`), not `MAX` across heights.
13. **R6:** `total()` must not return `0.0` for a sheet whose only priced rows are at the storage
    rounding floor while unpriced rows remain — carry a `priced_below_resolution` third state
    rather than a proven zero.
14. **R7:** distinguish "measured zero" from "budget exhausted" — emit `None` + an `exposure_gaps`
    entry naming the findings that consumed the budget.
15. **R8:** where `raw_points` tie, the exposure split is disclosed as arbitrary rather than
    silently ordered by address (a *correct* split needs the D2 evidence).
16. **R9:** carry weakness per contributing member (`weakness(e) = max` over members **proven to
    reach e**), and price a published union at the `min_coalition_to_act_as_both` already computed
    at `fold.py:571`.
17. **S5/R21:** the floor flag and the unpriced-entity disclosure must reflect unpriced *assets
    within* a reached entity and the *reach* keys, not only whole-entity/deployment keys.

---

## 4. Invariant impact

| invariant | touched by | verdict |
|---|---|---|
| **1** three-valued logic | D3, R2, R3, R11, H8 | **PRESERVED — but note "the grade" is two numbers.** The change nulls `exposure_usd` (removing the unproven magnitude from `grade_exposure`); it does **not** zero the finding's λ contribution — the row keeps a positive `raw_points` at `band(None) = UNPRICED_BAND = 0.15`. inv. 1's literal text ("unknown contributes zero to the grade") would forbid even that floor; the clause that actually governs a proven-bad finding with an undetermined *weight* is **inv. 16's boundary-with-inv.1 paragraph** (`SCORING_INVARIANTS.md:278-291`: "not an unknown — a proven-bad finding with an undetermined weight, and inv.7's floor governs it"). So: three-valued discipline is enforced on the *magnitude* (proven / not_determined, never the sheet), the *exposure* goes to zero for these rows, and the *floor λ* is retained under inv. 7 / inv. 16, not inv. 1. No inv. 1 wording change. |
| **5** weakest-path composition | D2, R9 | **PRESERVED, sharpened.** "Weakest path" is read as weakest path *to a given entity*, not weakest member of a merged unit. Suggest a one-line clarification to §5 that a merged unit's weakness is per-reached-entity, bounded below by `min_coalition_to_act_as_both`. |
| **6** grade/confidence, monotone in resolution work | R11, R12, R13 | **PRESERVED and repaired.** R12 is a live violation (confidence rises when less is walked); the fix restores monotonicity. The new reach-magnitude term only *adds* an axis on which analysis raises confidence. Note: the model-version bump itself lowers confidence (we stop over-crediting) — permitted by inv. 11 (pure function of inputs **and** model_version); monotonicity is w.r.t. analysis at fixed version. |
| **7** value scales weight, transitively, with a floor | D3, D4, H8 | **AMENDED.** Current wording ("funds in anything it can upgrade, drain, or administer") already implies the code/gate distinction but the code walks any edge. Proposed replacement (see below). The floor rule is explicitly preserved: `not_determined` magnitude keeps the finding at floor weight, deletes nothing. |
| **8** explicit perimeter, deterministic | R7, R8, R12, R14 | **PRESERVED, hardened.** Determinism is currently satisfied but on an arbitrary basis (address tiebreak, `contracts.id`-order collision annotation); the fix makes the arbitrary parts disclosed rather than silent. |
| **11 / 12** pure function, replay | R5 | **PRESERVED.** All changes are pure over persisted inputs; R5 makes the balance term a function of the observed account rather than of writer race order, which *improves* replay fidelity. `model_version` bumps to `1.1.0-provisional`. **Load-bearing consequence:** the frontend letter band table (`site/src/score/gradeBands.js`) is keyed by `model_version` and holds **only** `1.0.1-provisional`; `letterFor` returns `{letter: null, calibrated: false}` for any other version (by design — "an unknown version gets NO letter"). So the bump **removes the published letter** until a recalibrated `1.1.0-provisional` band table is added. This is a required Phase 4 task, not an optional one (see §6). |
| **13** invariance to code factoring / anti-gaming | D3, H8, floor rule (§3 pt 8) | **PRESERVED, with an argued caveat.** The fix *inverts the incentive direction on magnitude witnessing*: today, an unwitnessed magnitude charges the full sheet (a **worse** grade); after the fix it nulls `exposure_usd` and floors band 0.15 (both grade numbers **improve**), and only confidence falls. A change that lets reduced evidence improve the grade must clear inv. 13 ("the only way to move the score is to change actual capability/protection facts"). It does, because (a) the confidence drop via the new reach-magnitude term is the backstop — the improvement is paid for in the confidence axis, which is first-class output; and (b) the magnitude witness is a **fork-proof / holder-observation**, a function of on-chain behavior the protocol cannot suppress without changing that behavior, so "make the magnitude unprovable" is not a code-factoring move available to a deployer. If (b) ever fails to hold for a new witness kind, that is itself a finding. |
| **16** no abstraction above a witness | D1, D3, R2, R3 | **PRESERVED and enforced** — this is the invariant the whole audit is about. |

**Proposed inv. 7 replacement wording** (§B): *"A finding's weight scales with the USD value it
can reach through the control graph. Reach is bounded by what the capability licenses **and by
each destination's own conditions**: for **code-control** capabilities (upgrade, arbitrary exec,
delegatecall) the reach is the control closure of the controlled node — not scoped to any one
role's selectors, because controlling the code exercises everything the code is authorized to do —
but a downstream hop is still walked only where that destination's conditions do not disprove the
controlled node as caller; for **gate-control** capabilities (authority/ownership/role changes) the
reach is only the functions the gate confers and the closure reachable through edges of that
scope, likewise bounded by the destination's own conditions. Where the value a reach moves is not
witnessed, the reach still establishes a finding at the floor weight (a rug-shaped capability on a
currently-empty contract still scores), but the dollar magnitude is `not_determined` and charged
to confidence, never to the grade as the entity's whole balance sheet. Value scales weight; it
never gates existence of a finding; and an unproven magnitude is never a proven number."*

---

## 5. Measured blast radius (real corpus, read-only counterfactuals)

Each component was measured by an in-memory refold against the live snapshot; the combined figure
is a reasoned stack, flagged as an estimate because no single refold applied all changes at once.

| change | figure | shipped | after | source |
|---|---|---|---|---|
| **Axis 2 — pause.set magnitude → `not_determined`** | `exposure_usd` | $1,227,107,593.64 | **$481,887,370.56** (−60.7%) | measured |
| | `grade_exposure` | 71.700 | 88.886 | measured |
| | `grade_lambda` | 54.1614 | 54.1847 | measured |
| | `confidence_pct` | 29.0 | 29.0 (no magnitude term yet) | measured |
| **R5 — stale-MAX → latest** | `tracked_total_usd` | 4,336,022,005.48 | −$12,182,490.19 | measured |
| **R6 — dust `$0.00` → third state** | `value_priced_pct` | 33.7 | 27.8 | measured |
| **R12 — consume `capability_principal`** | `confidence_pct` | 29.0 | 28.5 | measured |
| **R2 — repoints stubbed** | one subsumed row `value_at_stake` | $150,410.13 | null | measured |
| **Safe-merge disabled entirely (bound, not the fix)** | `exposure_usd` | 1,227,107,593.64 | 1,522,929,… (rises) | measured |

**Direction of the whole change on etherfi — hypotheses pending the Phase 4 combined
differential, not measured conclusions.** Only the per-component figures above are measured; the
following is a reasoned stack and each claim carries its caveat:

- *λ / letter.* On etherfi the λ-grade is expected to move little — but the only λ measurement is
  pause.set, whose `BASE_SEVERITY` is **0.0** (`constants.py:56`), so it is the case *least* able
  to move λ and is not representative. The 255 gate-control signals carry positive severity
  (0.55–0.75); collapsing their band from the full-sheet band (0.5–1.0) to `UNPRICED_BAND` 0.15
  cuts their `raw_points` 3–6×, which on etherfi is *absorbed only because those rows sit at deep
  λ-positions 7/14* (λ⁷ ≈ 0.028) — an ordering accident, **not** a general property. On a protocol
  whose top-few λ rows are gate-control, the letter would move. **And the letter is not even
  rendered until `gradeBands.js` gains a recalibrated `1.1.0-provisional` table** (see §4 inv.
  11/12) — so "letter stable" is at best "stable after recalibration," and must be reported as a
  measured delta per local protocol at the Phase 4 gate, not asserted here.
- *Exposure* is expected to drop sharply and honestly: the full Axis-2 change (all 387
  unwitnessed-magnitude proven-reach signals charged to confidence, not the grade) takes exposure
  well below the pause-only $481.9M — most of that residual is itself gate-control full-sheet
  charges — toward a floor comprising the 55 magnitude-witnessed flow signals (themselves trimmed
  by R4/R5/R6) plus floor-weighted existence. Direction measured for pause; magnitude for the full
  set is estimated.
- *Confidence* is expected to drop (the new reach-magnitude term is mostly unanswered, and R6/R12
  remove over-credited terms) — the correct direction (we stop counting unprovens as answered) —
  but the *size* depends entirely on the new term's denominator (§3 pt 7) and its `min()`
  interaction, which is unmeasured and could crater the headline toward the low-teens. Must be
  measured at the Phase 3 gate.

`reach_entities` sets are expected to be largely preserved (membership is mostly real — it is the
*magnitude* that was fake), shrinking only where Phase 4/5 scope gate-control reach. A full
combined differential (ADDED / CHANGED / REMOVED per row, and the recomputed grade/letter/
confidence/exposure for **every** local protocol) must be produced and attached at the Phase 4
gate before the `model_version` bump ships.

**Compositional-magnitude coverage (Phase 6 lever), measured.** The magnitude Phase 4 moves to
floor weight is not lost — for gate-control it is *recoverable by composition* from witnesses that
already exist. Measured on the shipped etherfi document:

| gate-control reach | count / value |
|---|---|
| gate-control findings | 9 |
| distinct entities in their reach | 24 |
| ...that already carry a determined `flow.out` magnitude | **14** |
| reached priced value | $85,521,224 |
| ...sitting at a magnitude-witnessed entity | **$85,521,224 (100%)** |

The 10 uncovered entities are the $0-priced dust rows (R6), so no priced value lacks a
compositional ceiling. Witnessed destination magnitudes include BoringVault `0x917cee` ($1.7M),
LiquidityPool `0x308861a4` ($28.1M), EtherFiRestaker `0x1b7a4c37` ($540M), `0x86b5780b` ($45.7M).
So Phase 4 (floor the unwitnessed magnitude) and Phase 6 (restore it by composition) are a matched
pair: Phase 4 stops the over-claim, Phase 6 recovers the honest grade weight for the 75% of the
class that is gate-control. Only the freeze fraction has no compositional source and stays
`not_determined`.

---

## 6. Phased implementation plan (verification gate per phase)

Each phase is independently shippable and measured on the real corpus; a green offline suite is
necessary but **not sufficient** (golden corpus pins only fields it contains — the differential is
the real gate).

**Phase 0 — closure carries relation + scope (D1/D4/R19 prerequisite).** Change
`load_control_closure`'s return type to carry `(relation, scope)`; thread it through `_closure`
and `_aggregate` with **no behavioural change**. *Gate:* byte-identical score document
(`cli differential` shows zero moved rows); offline suite green; `pyright`/`ruff` clean.

**Phase 1 — value-plane hygiene (R5, R6, R7, R8, R9, S5/R21).** Independent of reach semantics.
*Gate:* differential shows only the intended dollar corrections (LiquidityPool −$12M, dust
entities → third state, budget-exhausted rows → `None`+gap, merged-unit weakness re-attributed);
one adversarial redteam test per fix; `tracked_total` and `grade_exposure` recomputed and
explained. **Caveat:** R9's re-attribution (`weakness(e) = max` over members *proven to reach e*)
is computed against the **pre-scoping** reach sets; Phase 4/5 shrink those sets, so the R9 gate is
a provisional acceptance criterion and must be re-verified at the Phase 4/5 gates.

**Phase 2 — reach-removing admission rules (R10, R18).** Refuse `0x0` as principal and anchor;
read renounced-to-`0x0` as an earned negative — each publishing its count. These only *remove*
reach, so they are safe and monotone. *Gate:* differential + the new counts in `provenance.value`;
a redteam test seeding `0x0` as a repoint target proves it is refused. **R15 (fixed-point alias)
and R16 (walk `Contract.beacon`) are deferred to Phase 4**, not landed here: R16 *adds* a
code-control edge and R15's chain-collapse can add reach, and until Phase 4's magnitude discipline
caps it, any added reach is charged the full sheet (`fold.py:1178-1180`) — so on a corpus with a
real `UpgradeableBeacon` they would *raise* exposure. They are inert on p1 (self-referential
beacon, no alias chains) but must not ship ahead of the cap.

**Phase 3 — confidence completeness (R11, R12, R13).** Add the reach-magnitude term; build the
perimeter and `unconsumed_reach_relations` from the discovery-fixed relation set. *Gate:* a
monotonicity test (consuming `capability_principal` must not *raise* confidence); every excluded
relation enumerated with a count; confidence recomputed and explained.

**Phase 4 — the core: gate/code split + magnitude discipline + deferred reach-adders (D2, D3, R2,
R3, R4, R15, R16, H8).** Both classes' reach bounded by destination conditions (code-control too —
§3.1 pt 3); `not_determined` magnitude charged to confidence, not the grade; repoint/backlink
validation; per-call magnitude cap; land R15/R16 here now that the cap exists. *Gate:* full
combined differential attached (ADDED/CHANGED/REMOVED, all protocols); the four regression cases
pass — (a) both AtomicQueue rows lose their unwitnessed dollars while staying alive at floor
weight, (b) the inversion is corrected or both sides fall to `not_determined`, (c) pause.set
exposure leaves the grade, (d) the R3 backlink correction does **not** introduce the $1.4M
over-claim; `model_version` → `1.1.0-provisional`; **add a recalibrated `1.1.0-provisional` table
to `site/src/score/gradeBands.js` (the bump nulls the letter otherwise — §4 inv. 11/12) with cut
points recalibrated against the post-change λ distribution**; migration honesty note (grade *and
letter* deltas on every local protocol, not just etherfi).

**Phase 5 — scoped gate-control reach via role→selector (D1 refinement).** Join
`function_principals.details.trace[].selector` to bound gate-control reach to the functions a role
actually confers; publish the 55/285 unlabelled role edges as `not_determined`. *Gate:*
differential shows gate-control reach sets *shrink* to the licensed functions; no row gains reach;
re-verify the Phase 1 R9 attribution against the shrunk sets. **Prerequisite for Phase 6:** the
selector this join resolves is what names the destination function whose magnitude Phase 6 reuses.

**Phase 6 — compositional gate-control magnitude (restores the grade teeth Phase 4 floored).** For
each gate-control reach, attribute the magnitude of the destination `flow.out` function the gate
unlocks (identified by the Phase 5 role→selector join), rather than `not_determined`. The
magnitude is a *reuse* of the destination function's already-fork-proven `flow.out` witness — no
new pipeline evidence — composed along the licensed path and capped per the R4 rule
(`min` against the destination's own sheet, no sum-over-keys inflation). Where the destination
carries no `flow.out` witness, or the reach is a **freeze** (pause.set — no compositional source),
the magnitude stays `not_determined` and charged to confidence. *Gate:* differential shows
gate-control findings regain a *witnessed* (not sheet-derived) magnitude; every regained dollar
traces to a specific destination `flow.out` witness (inv. 9 exact decomposition); on etherfi 100%
of gate-control reached priced value ($85.5M, §5) becomes witness-backed while the freeze rows
stay floored; **no magnitude exceeds its destination's fork-proven bound** (the anti-composition
regression test); confidence's reach-magnitude term rises accordingly (inv. 6 monotone — more
composition, more answered).

Phase 0 is pure plumbing; Phase 1 is dollar corrections; Phase 2 is reach-*removing* admission
rules (R15/R16, which *add* reach, moved to Phase 4). Phase 3 adds the confidence term that Phase 4
depends on. Phase 4 is where grades move to floor weight and where every reach-adder is safely
capped; it must not ship without the attached differential and the recalibrated band table.
Phases 5–6 are the payoff pair: Phase 5 scopes the reach, Phase 6 restores a *witnessed* magnitude
to it by composition — together they return honest grade weight to the gate-control class that
Phase 4 conservatively floored. The freeze fraction is the only magnitude that no phase can supply
without new evidence (§7).

---

## 7. Deferral register

- **A witnessed magnitude for the FREEZE fraction** (pause.set — what share of a sheet a pause
  actually immobilises), and for any gate-control destination that carries no `flow.out` witness
  (none priced on etherfi today). This is the *only* magnitude that is genuinely **new pipeline
  capability** — nothing existing composes into "how much a freeze locks," so it cannot be
  recovered the way gate-control magnitude is (Phase 6 reuses the destination's `flow.out`
  witness). Until the evidence exists, freeze reach stays `not_determined` (charged to confidence);
  a guessed immobilised fraction would re-introduce the exact defect this spec removes. **Note:**
  gate-control / repoint / backlink magnitude is *not* deferred — it is Phase 6, compositional
  from existing witnesses (§5, §6). The earlier framing of the whole magnitude problem as deferred
  new capability was wrong; only the freeze fraction is.
- **Cross-chain endpoint witness** (H9 fiat): a `chain` column on `control_graph_edges`/`_nodes`
  written by the resolver. Not a leak today; deferred to pipeline.
- **Sibling-selection chain-blindness** (`policy_worker.py`): a real cross-chain
  last-writer-wins, latent because colliding twins deploy identically. Deferred to pipeline; flag
  for the #158 twin-aliasing owner.
- **`membership_quality` semantics**: two modules read the field two ways, the scorer reads it
  zero ways, no test pins it. Deferred pending a ruling, not a code change.
- **R17 contradictory `exact` owner sets**: harmless on this corpus; deferred behind a decision on
  whether the scorer should adopt `principal_enrichment`'s "refuse to arbitrate" drop.
- **R20 `load_role_holder_floors` protocol-scoping**: a monotonicity smell (floors only raise),
  low priority; fold-only when picked up.
- **Split-proxy `secondary_implementations` / stranded `adminImpl` balances**: PLAUSIBLE, not a
  live double-count; revisit with R14.

Added at the W5 capstone (2026-08-06), from the wave reviews and the capstone's own sweep:

- **Authority-seat composition** — what §9.5 case 2 would actually need. When the seized node
  IS the destination's authority (a RolesAuthority), the principal does not need an act-as chain
  through a licensed caller: it grants itself the role on the seized authority and calls the
  destination DIRECTLY. The composition pass prices only act-as chains through gated callers, so
  this seat's magnitude stays `not_determined` — which is why the case-2 inversion swap is
  unreachable today. Pricing the direct seat is a new composition shape and needs its own ruling
  (what witnesses the self-grant, and what bounds the resulting reach), not a join fix.
- **Conjunctive-gate admission in the act-as plane**: a call site whose caller gate is a
  conjunction (a `canCall` consult AND a second predicate) is admitted on the `canCall` witness
  alone; the W4b review measured 26 candidate sites, none composing on this corpus. Latent.
- **Act-as calling-function conditions unconsulted**: the act-as admission checks the calling
  function's openness and delegated gate but never reads `effective_functions.conditions` on the
  CALLING function (the caller-conditions bound exists for the reach walk, not the act-as step).
  W4b review measurement: 105 admitted-or-offered sites carry conditions the admission never
  read; 0 change an outcome on this corpus.
- **Chain-length ≥ 2 composition soundness**: every published `act_as_chain` has length 1
  (verified corpus-wide at the capstone). Composing two act-as steps — transitivity of "can be
  made to call" — has no ruling; one is required before a longer chain is ever walked.
- **`event_log` as a receiver-read observation**: `planes._READ_OBSERVATIONS` admits
  `event_log`, but 0 `controller_values` rows carry it on any measured corpus (p1: `eth_call`
  260, `eth_call_impl_fallback` 4, `beacon_owner` 1), and the reading string describes the
  receiver witness as "an on-chain read at a recorded block", which an event is not. Ruling +
  redteam test before the first row arrives.
- **Exact-branch / undetermined-sheet disclosure parity**: where the charged entity's sheet is
  `not_determined`, the floor branch discloses the unboundable figure
  (`unbounded_floor_magnitudes`); the exact branch publishes its witness with no analogous
  disclosure that no sheet bounded it. Parity is a field addition, no behaviour change.
- **`ck_protocol_scores_grade_pairing` coupling**: the persisted-row check ties exposure, λ and
  confidence together, so an undetermined exposure drags `grade_lambda`/`confidence` to
  `not_determined` in `protocol_scores`; splitting the pairing needs a DB migration, and W3
  widened the population that can hit the withhold (every magnitude now allowed to be
  `not_determined`).
- **Pipeline lever — parameter-bound call-site receivers**: 28 refused call sites
  (`call_site_receiver_is_not_a_state_variable`: 14 findings-census + 14 subsumed-census) are
  receivers bound to parameters — the whole AtomicSolverV3 family. Each receiver the pipeline
  learns to resolve to a witnessed address converts a refusal into a composed magnitude and
  moves λ honestly; this is the single largest recovery lever left on this corpus.
- **Role-scope multi-authority ambiguity, re-check per protocol**: on p1 all 271
  (destination, role) scopes resolve through exactly one authority (0 ambiguous). A corpus where
  one role number is defined by two authorities makes the role→selector join ambiguous; the
  count is published under `reach_bounds.gate_conferral` and must be read before trusting the
  join on a new protocol.

---

## 8. What this spec deliberately does not do

It does not delete closure expansion (inv. 7 makes transitivity mandatory), does not collapse an
unproven magnitude to a smaller guessed number or to zero (inv. 1), does not raise any grade or
confidence figure because *less* was analysed (inv. 6), and does not implement anything — per the
handoff §10, the value here is an accurate scope. The core insight to carry into implementation:
**the reach *membership* is mostly real; it is the *magnitude* that is fabricated — and the honest
magnitude is not out of reach, it is one already-proven witness away.** The fix is not to walk less
graph — it is to stop pricing the graph you walked with a balance sheet nobody proved the reach can
move (Phase 4), then re-price it with the destination function's own fork-proven `flow.out` witness
(Phase 6), and give the one remaining unknown — the freeze fraction — a home in confidence until it
is measured.

---

## 9. Implementation & orchestration

This section turns the §6 phases into a dispatchable runbook. It assumes the repo-owner's standing
model: the **main loop orchestrates only** — it never writes or reviews code itself — all coding
goes to fresh Opus subagents in isolated worktrees, all reviews go to *separate* fresh agents, review
loops cap at **3 rounds** with the orchestrator adjudicating on exhaustion, and the branch is
**pushed once at the very end** (each push costs a preview deploy + ~27-min live suite).

### 9.1 Aligned parameters

- **~15 agents across 5 waves:** 7 coders + 7 per-unit reviewers + 1 capstone (plus ≤3 review
  rounds per unit).
- **Coders: Opus, all waves.** **Per-unit reviewers: Opus.** **Capstone: Fable.** **Orchestrator:
  the main loop (Fable), no coding or reviewing.**
- **Wave 3 (the core) is a single serial coder** — no parallel seam through the tightly-coupled
  reach change.
- **One batched push**, after the capstone. All per-wave verification is local.

### 9.2 Branch model

Work **directly on `fix/confidence-perimeter-admission`** — the reach fixes build on top of its
existing scorer commit (`5b5db0c4`, the precedent this spec follows). No separate integration
branch: `fix/confidence-perimeter-admission` *is* the integration branch. Each wave's units are cut
as worktrees **off the current tip of `fix/confidence-perimeter-admission`**, and merge back into it
once their gate passes; the next wave branches from the updated tip. **Every worktree coder prompt
must first prove it is not on a stale base before writing code** — verify the branch tip is an
ancestor of `HEAD` (`git merge-base --is-ancestor <branch-tip> HEAD`), the trap being a worktree cut
before the previous wave merged. Only remove worktrees this session created. (Note: this branch is
unpushed and sits off the salience branch, so the single end-of-run push / PR will bundle
`5b5db0c4` together with the reach work — intended, since both are scorer changes.)

### 9.3 Wave / work-unit table

Each unit lists the files it **owns** (no two concurrent units in a wave share a file-region), what
it depends on, and its gate. `F` = `services/scoring/fold.py`, `P` = `planes.py`, `D` =
`distill.py`, `K` = `constants.py`.

| Wave | Unit | Scope (owns) | Defects | Depends on | Gate |
|---|---|---|---|---|---|
| **1 Foundation** | W1 | `P.load_control_closure` return type → carries `(relation, scope)`; thread through `F._closure`/`_aggregate` | D1/D4/R19 prerequisite | — | **byte-identical** score doc (`differential` = 0 moved rows) |
| **2 Hygiene+conf** | W2a | `P` value plane: `total`/`canonical`/`load_value_plane`; `unconsumed_reach_relations` enumeration; role-floor protocol scoping | R5, R6, R13, R20 | W1 | per-fix differential; dust→third-state; all excluded relations enumerated w/ counts |
| | W2b | `F` grade/exposure region: `_grade` budget, sort tiebreak, `_row_value`/`_entity_contribution` magnitude cap, floor flag | R4, R7, R8, S5/R21 | W1 | budget-exhausted→`None`+gap; magnitude never × N keys; floor flag reflects unpriced assets |
| | W2c | `F` unit-resolver + confidence: `_safe_by_key`/`_row_for` weakness, `_confidence` (0x0 refusal, reach-magnitude term, discovery-fixed perimeter) | R9, R10, R11, R12 | W1 | merged-unit weakness per reached-entity; **monotonicity test** (consuming a relation must not raise confidence); reach-magnitude term denominator measured |
| **3 Core** | W3 (serial, one coder) | `D` reach producers (`_reach_for_claim` tail, `_repointed_entities`, backlink, pause) → then `F`+`K` consumers (gate/code split, D2 condition-bounding, magnitude→confidence wiring, R15/R16) | D2, D3, D4, R2, R3, R14?, R15, R16, H8 | W1, W2c | **full combined differential** + the four §9.5 regression cases; `model_version`→`1.1.0-provisional` + recalibrated `gradeBands.js` |
| **4 Payoff** | W4a | role→selector scoping (`D`/`F` join on `function_principals.details.trace[].selector`) | D1 (Phase 5) | W3 | gate-control reach shrinks to licensed selectors; 55/285 unlabelled edges → `not_determined`; no row gains reach |
| | W4b | compositional magnitude (reuse destination `flow.out` witness) | Phase 6 | W4a | gate-control regains a **witnessed** magnitude tracing to a specific `flow.out` witness (inv. 9); **no magnitude exceeds its destination's bound**; freeze stays floored |
| **5 Capstone** | W5 | full integrated branch | — | W4b | see §9.6 |

W2a/W2b/W2c are worktree-parallel (disjoint file regions: `P` vs `F`-grade vs `F`-units/confidence
— the two `F` units own non-overlapping function sets and merge in the order a→b→c to avoid churn).
W4a→W4b is serial. R14 (shared-impl collision) is latent; fold it into W3's admission work or defer
to a follow-up — it fires on no local data, so its gate is a redteam test, not a differential.

### 9.4 Verification commands (every gate)

Local, CI-faithful — no push until the capstone.

```bash
# services up (once)
docker compose up postgres minio minio-init -d

# offline suite (fast local runner; exports its own CI-faithful env — do NOT source .env for this)
./run_tests_fast.sh                              # full offline suite
./run_tests_fast.sh tests/test_scoring_redteam.py    # the fold fixture (stubbed planes, no DB)

# CI-faithful lint + types on touched files
uv run ruff format --check <files>
uv run ruff check <files>
uv run pyright <files>

# real-corpus differential — the ACTUAL gate (green tests prove little; see §9.7)
set -a; source .env; set +a
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/before.json   # capture ONCE from the branch tip before Wave 1 lands
uv run python -m services.scoring.cli score --protocol 1 --out /tmp/after.json
uv run python -m services.scoring.cli differential --against /tmp/before.json     # report ADDED/CHANGED/REMOVED
```

Scoring tests that matter: `tests/test_scoring_redteam.py` (adversarial, has the `fold` fixture that
drives the fold with stubbed planes and no DB — write regression cases here),
`tests/test_scoring_distill_fold.py`, `tests/test_scoring_integration.py`,
`tests/test_scoring_schema.py`.

### 9.5 The four regression cases (W3 gate — assert in `test_scoring_redteam.py`)

1. **AtomicQueue, blocked principal.** EOA `0x2322ba43…` on AtomicQueue: the `finishSolve`
   `initiator != address(this)` condition disproves the hop (D2), so its reach to the solver path is
   dropped and its `authority.replace` magnitude is `not_determined` — **it is no longer charged the
   $1.5M**, and stays alive at floor weight.
2. **The inversion.** The principal that *can* reach the money — the timelock behind RolesAuthority
   `0x4df6b733…` (shipped `findings[2]`, exposure `$0.00`) — must carry the **witnessed** magnitude
   after Phase 6, not `$0`. The fake and real attributions swap to the honest direction.
3. **pause.set exposure leaves the grade.** The freeze rows' `exposure_usd` drops out of
   `grade_exposure` (magnitude `not_determined` → confidence), the finding survives at floor weight,
   and the ~$745M no longer sits in the grade as a proven number.
4. **The R3 backlink trap.** Correcting the backlink join (match `node.address`) **in the same unit
   as** the magnitude bound must **not** introduce the $1.4M over-claim — assert the corrected
   licensed reach carries a bounded/`not_determined` magnitude, never the destination's whole sheet.

### 9.6 Capstone (W5, Fable, fresh agent over the integrated branch)

- The **full combined differential across every local protocol** (not just etherfi): ADDED /
  CHANGED / REMOVED rows, and recomputed grade / **letter** / confidence / exposure per protocol.
- **Migration honesty:** report the letter deltas — and confirm the `1.1.0-provisional` band table
  exists and is recalibrated (the bump nulls the letter otherwise, §4 inv. 11/12).
- **Invariant sweep:** 1, 5, 6, 7, 8, 11, 12, 13, 16 each preserved/amended as §4 claims — in
  particular confidence monotonicity (R12) and no unproven magnitude in the grade (D3/H8).
- Confirm the **only** `not_determined` magnitude remaining by design is the freeze fraction (+ any
  unwitnessed destination), everything else witness-backed.

### 9.7 Guardrails (hand to every coder and reviewer verbatim)

- **The DB is READ-ONLY.** SELECT only, port 5433. Never write a row.
- **No commit without explicit owner authorization; no Claude attribution trailers/footers.**
- **A green suite proves little** — the golden corpus only pins fields it happens to contain.
  **Measure every change on the real corpus with `cli differential`** and report ADDED/CHANGED/
  REMOVED. A zero-diff is only meaningful if the golden pins the field *and* the corpus has the shape.
- **R3 ordering trap:** never correct the backlink join without landing the magnitude bound in the
  **same** unit — the corrected join without the bound mints a fresh $1.4M over-claim (a B14
  cite/gate object becoming a magnitude).
- **Source-fetch trap:** `source_files.storage_key`'s trailing hash is derived from the *path*, so
  the same path in two jobs collides under different content. Fetch a contract's source from **its
  own** `job_id` (AtomicSolverV3's bundle vendors an obsolete un-Auth'd AtomicQueue).
- **Worktree base check** (§9.2) before writing; only remove worktrees this session created.
- **Reviews go to fresh agents**, capped at 3 rounds; the orchestrator adjudicates on exhaustion.
- **Trust a subagent's reported pass counts** — do not re-run its suite to double-check.
- **Batch the push** — one push after the capstone.

---

## 10. Implementation outcome addendum (2026-08-06)

Written at the W5 capstone over the integrated branch (tip `d2313bea` = `5b5db0c4` + 19
commits, waves W1/W2a-c/W3/W4a/W4b). Every figure below was re-measured at the capstone against
the live snapshot (protocol 1 remains the only local protocol) or read from the published
document; determinism was re-verified (two `cli score` runs byte-identical modulo
`computed_at`).

### 10.1 Headline final state

| | shipped (1.0.1) | floored (intermediate) | final (1.1.0-provisional) |
|---|---|---|---|
| `grade_lambda` / letter | 54.1614 / C+ | 84.0166 / A− | **73.2508 / B+** |
| `grade_exposure` | 71.7 | 100.0 | **99.582** |
| `confidence_pct` | 29.0 | 18.6 | **18.6** |
| `exposure_usd` | $1,227,107,593.64 | $76.07 | **$18,059,003.86** |
| `reach_magnitude_witnessed_of_reaching_pct` | — | 15.3 | **25.6** |

27 findings before and after (0 added, 0 removed as findings; 4 rows changed — every cause a
`value_band → not_determined` collapse; 54 differential "added" rows are the new subsumed-row
granularity). The band table carries 1.0.1's cut points forward with the argument in
`site/src/score/gradeBands.js`; the letter delta is published as a migration fact
(`model_parameters.model_version_migration`), not absorbed. Confidence's binding term is
`value_priced_pct` 18.6 (the 29.0 → 18.6 fall is 1.0.1-arithmetic: dust third state + the
discovery-fixed perimeter widening 295 → 468 entities, admitting 108 `safe_owner` signer
wallets and 65 `capability_principal` principals); the reach-magnitude term sits at 37.6 and
does not bind. Every published dollar traces to a fork-proven `flow.out` witness — directly, or
composed along an all-hops-witnessed act-as chain and capped at both the witness and the
charged entity's own sheet. The `flow.out` witness is ENTITY-granular on this corpus (every
selector at a vault carries the same figure), so inv. 9's exact decomposition holds at entity
granularity, not per-function precision.

### 10.2 Spec claims refuted or corrected on data during implementation

- **§5 "λ is expected to move little" — REFUTED.** The gate-control collapse to floor moved λ
  +29.9 (54.16 → 84.02) and composition gave 10.8 back (→ 73.25); letter C+ → A− → B+. The
  spec's own caveat (deep-λ absorption is an ordering accident) was the accurate half.
- **§5 Phase-6 coverage table — PARTIALLY REFUTED.** "14 of 24 gate-control reached entities
  carry a `flow.out` magnitude covering 100% of reached priced value" counted the destination
  witness and never the act-as step. Measured: of 64 licensed (hop, selector) pairs offered, 27
  carry an act-as witness, 19 of those also a destination witness, composing **13 entities /
  $46,164,146.29 across 2 findings** (exposure share $18.06M after budgeting). The dominant
  refusal is a parameter-bound receiver (28 sites — the AtomicSolverV3 family).
- **§9.5 case 2 — landed on the OTHER admissible outcome, recorded not failed.** The timelock
  behind RolesAuthority `0x4df6b733` regains no witnessed magnitude: the seized authority's own
  hops refuse at `caller_not_reachable_from_the_seized_node` (5 and 21 hop-pairs on the two
  rows), because the destination callers that could carry the chain bind their receivers to
  parameters. The timelock and the two EOAs the shipped document over-charged now sit at
  `not_determined` together — symmetric honesty in place of the promised inversion swap, which
  needs the authority-seat composition ruling (§7).
- **§1.2 R4 "both keys land in published rows" — did not reproduce.** Neither the
  $28,138,639.99 witness nor the $28,177,358.92 over-sum appears in any published row of the
  shipped or final document. The code hazard was real and is closed both ways: exact branch
  `min` per key (pre-existing), floor branch now bounded by the charged entity's own sheet with
  the unboundable case disclosed (`unbounded_floor_magnitudes`, W4b).
- **R17 "contradictory exact owner sets" — the contradiction dissolves into two chains.**
  Re-verified by SQL at the capstone: Safe `0x607d0c7e` has exactly one owner set per chain —
  base 2/4 (4 owners) and ethereum 2/5 (5 owners). Two deployments, no arbitration; the
  deferral (§7) narrows to nothing on this corpus.
- **R21 "two reach keys outside the perimeter" — resolved to zero.** The disclosure now checks
  reach keys and the perimeter is discovery-fixed; `signal_entities_outside_perimeter` is `[]`
  on the tip (the audit's two keys are inside the widened denominator).
- **R18 "86 anchors" — measured 95.** 342 renounced (`→ 0x0`) edges across **95** anchors and
  98 authority slots (owner 72, authority 20, shareLocker 2, `_pendingOwner` 2,
  accessController 1, balancerVault 1), all read as earned negatives, none walked.
- **R2 measured at the fix:** all 31 repoint witnesses on p1 are `policy_derived`, all 31
  refused; proven-reach signals 442 → 436; the $150,410.13 repoint-funded row publishes
  `not_determined`.
- **W4a's conferral scoping was headline-invariant by construction:** 20 of 82 rows lost
  reach, 232 row-entity memberships removed, 0 gained, λ/exposure/confidence byte-identical —
  because gate control already charged $0 for an unwitnessed magnitude.

### 10.3 Disclosure correction shipped with this addendum

`planes.py` `act_as_composition.reading` claimed "(68 carry exactly one, 19 carry none)"
authority-kind state variables among the 87 canCall-guard contracts. That split does not
reproduce under any measurement tried. Re-measured four independent ways at the capstone
(guard-target heads; `controller_values` sources named `authority`; sources matching
`auth|role|access|registry`; `setAuthority` `state_writes`): **every one of the 87 carries
exactly one — `authority`** — so there is no second candidate the guard could be reading. The
string now states the verified form; the load-bearing claim (no second candidate) is unchanged
and is in fact strengthened, since "19 carry none" would have contradicted those contracts
carrying the guard at all.
