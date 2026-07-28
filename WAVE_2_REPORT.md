# Wave 2 Report — legs B (capability/authority) and D (effects/witness)

**Exit: PASS** (2026-07-28). Branch `fix/witness-integrity`, merged HEAD `cdb8257a`
(legs merged via `782d3c4d`, `cdb8257a`; zero conflicts). Gate at merged HEAD:
suite **5,371 passed / 0 failed** (44 xfailed), vitest 557/557, pyright/ruff clean,
determinism gate both classes, R5 v21→v31 (ten ordinal bumps, one reason each),
10 test deletions declared. Both tier-3 Fable verdicts: **PASS / PASS**, `controls_held`
and `differential_reconciled` true on both lenses; their findings are swept to the
ledger (L-45…L-62). One driving-agent adjudication (Leg D, below).

## What landed

### Leg B — capability/authority (`witness/leg-b`, 15 commits, accepted round 3, Fable implementer)
- **A1 root cause fixed at the true root**: not the resolver default but an
  **entry-parameter Phi in the provenance engine** — Slither's interprocedural SSA
  puts a Phi on every formal parameter whose rvalues are the arguments of EVERY
  call site in the contract, keyed by the parameter's base name, so `msg_sender`
  leaked into other functions' frames (`52cfcfa3` skips it; loop-join and
  state-var Phis keep union handling). Realised flip set: **public→gated exactly
  2** (cid 568 `upgradeTo`/`upgradeToAndCall` — the A1 rows), **gated→public
  exactly 3**, each a corrected base false-adverse source-verified by the
  verifier (cid 561 `shouldSubmitReport`, cid 454 `claim`, cid 570 `undelegate` —
  base's `unsupported` was worklist-cap saturation from the Phi pollution).
  118 leaves lost fabricated caller taint; 2 gained real taint (fail-closed).
- **`authority_openness` three-state** (new column, migration `c4b81e2a90fd`):
  751 open / 848 restricted / 174 not-determined projected over all 1,773 rows,
  re-derived independently by the differential; 0 disagreements with the old
  boolean where it was honest, and the 1,022-row `False` blob is now split.
- **`authority_roles` real derivation** (was the literal `[]` on 1,773/1,773):
  **200 witnessed / 364 not-determined / 1,209 proven-absent**; an `unsupported`
  node anywhere yields `None`, never proven-absent `[]` (inverted pin declared).
  Six consumers enumerated and verified.
- **`guard_extraction_uncertain` wiring** (`e639ad13`): the re-measured tree-absent
  population is **0** — Leg A's class-F/R widening closed the population G3
  measured (828 tree-less predicate targets, 0 with a detector-visible gate;
  instrument limit stated in L-51). The sentinel stays wired and test-covered with
  zero realised rows — the honest R2 statement, not a firing proof.
- **G2**: empty-intersection now yields `AND` residual (not-determined), never
  `resolved_empty` — **1 projectable persisted transition** (cid 577
  `WithdrawRequestNFT.requestWithdraw`, 14 candidates → ∅), the `_intersect_finite`
  half demonstrated on reconstructed conjuncts with an inherited-empty control
  (L-59 corrects the "3 of 80" figure); the event-fold direction bug and the live
  mapping-enumerator fold fixed (`bddcb2f3`, `24107786` — 0 realised, structural);
  GAP 2 chain filter shipped **in the same commit** as the adapter fix, plus
  error≠empty (a DB error can no longer reach `resolved_empty`).
- **L-40/L-41/L-42 gate** (`c2d5cbfb`): provenance-absent controller-tracking
  targets now mint `controller_value_unattributed`, which is **not in
  `CONTROL_EDGE_RELATIONS`** — 0 of 430 provenance-absent targets (162 armed at
  base + growth) can mint an authority-bearing edge; the 203 proven `caller_gate`
  targets keep authority. Realised delta today 0; binds the next resolution run.
- **`function_principals` provenance** (`31f37d25`): `details.resolver_path` — 8
  distinct paths + an explicit not-recorded state over the 1,132 projected rows
  (the `origin` column itself deliberately unchanged; the information now exists).
- `blacklist_quality` emitted always; `last_indexed_block` surfaced with a
  staleness threshold (`01d7ed8c`). L-27 fixed with declared scope (`c78870f3`).
  `terminal_principal` producer split landed (`4363497c`; consumer half is Wave 3).

### Leg D — effects/witness (`witness/leg-d`, 16 commits incl. adjudication, Opus implementer)
- **A7 vertical slice** (`1b51ed58`, `f60b931a`, `9872a206` + adjudication
  `0a7fa43e`): the L-16 leaf widening (operand absorption + `absorbed_operands`,
  marker `operand_absorption="recorded"`) makes the positive branch reachable from
  compiled source — the timed-latch corpus pair is now a full gate;
  `duration_bound_source` three-state (`guard_constant` / `not_determined` /
  `no_time_reference`) ships with BOTH prose copies and the three defect-pinning
  tests inverted with positive siblings. On the 61 persisted `freeze_pause`
  verdicts: **0 bounds and 0 proven-indefinite** — honest, because the absorption
  marker is absent on 1,741/1,741 persisted trees (proof-by-absence requires it);
  on post-widening replays the proven state is realised on exactly 6 rows and
  `not_determined` on 265. The row previously rendered "indefinite latch (no
  self-recovery bound)" now says *not determined*.
- **A2** (`ec83a422`, `067575cb`, `3963f9b8`, `9797985f`): per-asset holdings
  through `selection → Candidate → orchestrator → recipes` (once per
  (holder, asset)); the owed `eth_simulateV1` emitter check done live and
  verified by the reviewer with a WETH `deposit()` control (native log emitter =
  `0xeeee…eeee` at head and pinned 25619159); reach ≤ `defillama_tvl` gate with a
  loud three-state `reach_tvl_check` (absent-TVL = skip loudly); truncation/
  price/decimals discriminators land with the arithmetic (residuals L-45, L-46).
- **D3** (`9ff3012a`): a measured zero and an unmeasured one are now different
  payloads — `reach_determined`, `reach_indeterminate`, floor-vs-value keys split;
  W0-7 fixture 8 passes with the discriminating sibling.
- **`concrete_destination`** (`673adc95`, `23d38f07`): all 35 `caller_arbitrary`
  rows project to NULL; `NEUTRAL_CALLER` excluded alongside the sentinel;
  convergence-before-exclusion ordering pinned (a real counterparty in the same
  slot still records — positive control held).
- **Cache** (`c873b393`, `06ddc146`, `2b908319`): self-audit floor (a zero-key
  signature refuses the hit — 78/150 rows today, L-59 №3), code/deployment plane
  split (six `DEPLOYMENT_PLANE_KEYS` stripped on write, absent on a hit),
  proxy-hash refusal (`make_bytecode_hash_resolver` returns None on
  `is_proxy=true`, test-pinned), mutate-on-read declared via
  `REPLAY_IDENTITY_EXCLUDED_COLUMNS` in the schema.
- **L-4** (`d4b5844f`): `_principals_by_function` total order
  `(function_id, address, id)` — 5 probe identities re-pinned from heap order to
  data (9-process stability check on both sides).

### Driving-agent adjudication (Leg D, round-cap exhaustion)
The round-3 reviewer verified rounds 1–2 closed and left ONE violation: the A7
clock predicate counted only `block_context_kind == "timestamp"`, so `now`
(pre-0.7) and `block.number` latches still published proven-indefinite for
freezes that expire. Applied the reviewer's minimal prescription directly as
`0a7fa43e` (OPERATIONS §2 trivial-residual channel): demotion counts
`timestamp|now|number`; the seconds harvest counts `timestamp|now` only — the
units trap (216000 blocks ≈ 30 days, not 2.5 days) is test-pinned. 4 new arms,
4/4 mutation-checked red pre-fix; module controls (PlainLatch proven,
TimestampTwin demoted, AbsorbedWindow 2592000) green. Both verifiers confirmed
the adjudication implements the prescription exactly; the differential proved
the split monotone away from the proven state with 0 realised corpus delta.
Trivial residuals also closed directly at wave close (declared): the
`_resolve_destination_shape` docstring's nonexistent `NEUTRAL_CALLER` row
(L-59 №2), the 49→78 floor docstring (L-59 №3), the missing R5 note for Leg B's
predicate-shape changes (L-54), and the L-61 substrate hygiene (synthetic dev-DB
row deleted; dev DB migrated to head).

## Differential integrity

Full-replay differential (88/92 contracts, byte-reproducible `head`≡`head2`
across fresh processes, PYTHONHASHSEED pinned, base worktree code-identical to
`93954b96`): **every non-noise row attributed to a named commit** — 10
function-level verdict changes, 118+2 leaf taint changes, 404 relation
demotions (+26 new targets), 1,773-row openness/roles projections, 35
`concrete_destination` NULLs, 271 latch rows gaining a three-state source, 5
probe-identity re-pins. **L-25 noise bucket: 0 rows** (seed-pinned both sides
AND the flickering field is not read; flicker reproduced separately for the
record). Both verifiers reconciled it line by line.

**Method cautions for Wave 3+** (add to the standing list):
- The whole cache plane is **unmeasurable-by-hit**: all 150 rows carry
  `analysis_schema_version=5` vs constant 21/31, so no row is servable at either
  revision — every cache claim is a projection until an effects run happens.
- `effect_transcripts` hold no logs (L-49): reach/value verdicts are not
  re-derivable from persisted evidence; never cite a recomputation over the 41
  published rows.
- The `resolved_empty` `_intersect_finite` half is unobservable by re-projection
  (persisted `capability_expr` is the collapsed output) — demonstrate on
  reconstructed conjuncts.
- Operand-plane counts are not like-for-like across the A7 widening
  (`_compared_operands` = `operands ∪ absorbed_operands` exists only at HEAD).

## Harness changes this wave (deliberate corrections, not drift)
- **Per-leg test databases** (`psat_test_legb`/`psat_test_legd`): two parallel
  legs run serial suites concurrently without clobbering the shared `psat_test`.
- **Implementer prompts carry the reviewer's lens up front** (OPERATIONS §2) —
  first wave in force; Leg B's consumer-enumeration deliverable was verified
  (and its one gap, L-52, found) rather than sampled.
- `wave2exit.workflow.js` pattern reused deliberately: the legs phase halts at
  cap by design, the driving agent adjudicates, and an exit-only script runs the
  tail — no resume of a completed parallel phase.

## Carried into Wave 3+ (see ledger for detail)
- **W3-E folds now measured and waiting**: L-45 (`price_usd` double meaning at
  the consumer), L-47 (measured-$0 reach renders as silence), L-57
  (`undelegate` force-undelegate distinction in protocolScore), plus the Wave-1
  era list (L-1, L-2, L-19-class, L-30…). The 180 armed `terminal_principal`
  rows' post-fix distribution is unmeasured (needs a policy run) — consumer half
  is Leg E.
- **Wave 4 admissions**: L-46 (TVL ceiling skips the priced-floor branch), L-52
  (relation pin test), L-53 (openness payload half unpinned), L-58+L-60
  (side/operator-aware harvest + fork-containment pin).
- L-12 and L-38 remain open with stated cause (verified unworsened by Leg B).

## What was not checked
- No resolution / policy / effects / static pipeline stage ran (cost boundary):
  every Leg B item beyond the A1 flip set and every cache/verdict item is a
  **projection over persisted inputs**, never observed re-persisted rows. The
  L-41 gate, openness/roles writers, and the cache floor bind the next real run.
- No second chain: GAP 2's chain scoping and both G2 fold fixes have 0 realised
  rows and are structural on the first multichain run. All counts remain lower
  bounds (one protocol, one chain).
- The 4 source-less contracts (79, 639, 640, 641) remain invisible to the replay.
- The `now`-spelling clock arm is hand-built only (compiling it needs solc <0.7;
  deliberately not added to CI's compiler matrix) — the `number` arm is compiled.
