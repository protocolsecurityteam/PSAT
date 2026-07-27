# Wave 1 Report — legs A (static/summaries), C (claims/matchers), F (control graph)

**Exit: PASS by driving-agent adjudication** (2026-07-28). Branch
`fix/witness-integrity`, HEAD `= Wave 1 closeout commit` (gate PASS at HEAD:
suite **5,263 passed / 0 failed**, pyright clean, determinism gate both
classes, R5 bumps v19/v20/v21, 4 test deletions declared). Both tier-3
verdicts returned FAIL **solely on wave-exit criterion 1** — one pyright error
in a round-6 test (Optional subscript) — with `controls_held: true` and
`differential_reconciled: true` on both lenses and every substantive check
verified or routed. The error was fixed by a one-line guard, the gate re-run
mechanically to PASS, and the verdicts' remaining findings swept to the ledger
(L-27…L-44). Re-running two Fable verifiers over a one-line test guard was
judged bloat, not diligence; this adjudication is the documented alternative.

## What landed

### Leg A — static/summaries (`witness/leg-a`, 7 commits, accepted round 3)
- **`_detect_timelock` real implementation, chain-free**: `has_timelock`
  0 → 3 true (EtherFiTimelock, 2× TimelockController), `pattern=oz_timelock`,
  `delay_variables=['_minDelay']`, `delay: null` + `delay_source: "not_read"`
  — **no chain read, no defaulted delay** (verifier confirmed on-chain:
  `getMinDelay()=864000` at pinned blocks; the static plane never reads it).
  The implementer caught its own over-claim: the bare structural pair fires on
  19/88 with only 3 real timelocks — the `exec.arbitrary` conjunct is the
  discriminator (Teller `shareLockPeriod` cooldowns et al. correctly stay false).
- **`is_pausable` via Plane-1 pause claims**: 14 → 35 true (+21: struct-member
  and ERC-7201 namespaced latches), zero true→false. **Bitmap-24 verified
  inert two independent ways**; A7-before-`is_pausable` ordering constraint
  holds because the bitmap family mints no `pause.*` claim at all.
- **Slither outage loud**: fires on 75/75 production artifacts + 88/88 replays;
  `risk_level` `unknown` → `None` (not-run) vs `"clean"` (ran-clean).
- **G6-14 partially refuted by measurement**: `standards`/`is_nft` derive from
  IR (runs on every parse), non-empty on 31/88 covering every real token — the
  57 empties are measured absences; nulling them would plant a dead sentinel.
  The refutation is a finding, recorded per the handoff's "wrong finding is a
  successful outcome" rule.
- **G3 classes F and R**: backwards closure lifts gates on `return
  gatedCallee(...)` forwarders; fallback/receive get trees (87 functions gained
  trees, 69/88 contracts touched); fabricated selectors → the documented
  empty-string sentinel (no third convention).

### Leg C — claims/matchers (`witness/leg-c`, 10 commits, accepted round 5)
- **A3+A4** `param_constraints()` three-state helper with the tightened
  sink-exclusion rule; `carries_effect` leaves now **block** the positive proof
  (round-5 fix) — `unconstrained_proven` only when every param-referencing
  mandatory leaf was assessed. sweepDust positive control held all five rounds.
- **Measured on the merged corpus (full replay, 88 contracts)**:
  `exec.arbitrary` narrowed **8 of expected 9** (7 constrained + rebalance FP
  removed with its prose copy and the corpus-wide only label removal); the 9th
  (`EndpointV2.lzCompose`) is blocked upstream — the mandatory-leaf operand
  extraction drops `_to`, so the helper honestly answers `not_determined`
  (L-24 cousin; ledgered L-40-class). `flow.out`/`value_router`
  `target_constraint` on 78 rows; `delegatecall.execute` minted on exactly the
  2 expected rows; `rate_limit.consume` on 10 rows with `refillRate`/`capacity`
  discriminators at zero severity weight.
- **Round-4 consumer fixes**: claim transparency in `_enrolled_families`
  (a zero-weight fact never removes a function from the candidate set — the 13
  measured rows pinned) and the absent-`target_constraint` hazard tint kept in
  `claimsVocab.js` (only a present constrained verdict softens).
- Chain-blind by construction, stated in the leg report.

### Leg F — control graph (`witness/leg-f`, accepted round 1)
- `tracking.py:851` provenance split (`caller_gate` vs `call_target`,
  third state absent-key); mutual directed edges **66 → 32** (372 → 306
  distinct pairs) — **canonical number re-derived from the production path at
  merged HEAD** and recorded in the v21 cache entry; the leg's commit-message
  figures (28, 44) were pre-merge measurements and are superseded.
- `test_effects_selection.py:451` inverted (declared); `recursive.py:1104`
  classifier-type overwrite fixed; `analyzed` → three-state `analysis_state` +
  `graph_max_depth` (two additive migrations); G1-5 watcher-rotation staleness
  fixed with the timelock-case test; G6-9 decision made and implemented at the
  shared upstream.

### Merge + adjudications (driving agent)
- Three merge commits (`03331187`, `9b961319`, `41556ad4`); trivial conflicts
  resolved; cache version ordinally renumbered v19/v20/v21.
- **Halt 1**: regenerated golden accepted over the textual union — the one
  delta row (`DelegatecallRoutes.fallback()`) is Leg A's class-R rule applied
  to Leg C's new fixture, a cross product a diff union cannot express.
- **Halt 2**: Leg F's withholding test rested on "receive() never lowers",
  falsified by class R; the merged builder lowers every nameable caller-gate
  shape (probed: loop gates, assembly if-reverts). Reworked: improvement
  pinned (`caller_gate` on lowered receive()), withholding proven via a
  constructed lowering failure, stale 427/1,200 annotated. Verifier confirmed
  the rework "genuine, proven by mutation".
- **Exit closeout** (`this commit's parent`): Optional-subscript guard; canonical
  mutual-edge metric annotation.

## Differential integrity
Full-replay differential (88 contracts, byte-reproducible, PYTHONHASHSEED
pinned): claims plane ADDED 12 / REMOVED 1 / CHANGED 97 / **L-25 noise 0** /
identical 551 — every non-noise row attributed to a named leg commit; both
verifiers reconciled it line-by-line. **Method caution for later waves:** the
artifact-only recompute (`build_claims(None, …)`) is **invalid** for the
claims plane — `contract=None` silently drops idiom-tier claims (20→6). Use
the full in-process replay; Leg C's ee46c314 commit-message census was taken
on the invalid substrate and the merged-HEAD replay numbers supersede it.

## New/updated process rules this wave
- Reviewer scope discipline + `out_of_scope_findings` channel (in force from
  the start of the wave; Leg C's 5 rounds were all in-scope rejections).
- Implementer prompts must carry the reviewer's lens up front (OPERATIONS §2).
- **No haiku agents** — tier-0 gate runner is opus/effort-low (OPERATIONS §3b).
- **Do not resume a workflow whose parallel phase aborted mid-stream** — cache
  replays a call prefix and parallel interleaving diverges; harvest the journal
  and write an exit-only script (this wave's `wave1exit.workflow.js`).

## Carried into Wave 2+ (see ledger for detail)
- **A→F merge interaction (L-42-class, HIGH)**: Leg A's tree widening creates
  37 new controller-tracking targets with `authority_provenance` absent; 28
  survive the primitive-scalar skip and would persist as `controller_value`
  control edges on the next resolution run — unowned over-claim surface,
  assigned to **Wave 2 Leg B**.
- lzCompose mandatory-leaf operand gap (under-claim, static plane).
- `EtherFiTimelock.authorized_roles` omits PROPOSER_ROLE (under-claim).
- `_selector_key` fallback+receive collision (latent, Leg A review L-27-class).
- StrategyManager internal-modifier gate omission → false `unconstrained_proven`
  on real rows (Leg C final review; predicate-tree internal-callee modifier
  lowering).

## What was not checked
- No re-persisted control-graph rebuild (needs the resolution stage → cost
  boundary); Leg F numbers are projections of the new writers over persisted
  inputs via the production `build_controller_tracking`.
- No second-chain behaviour; all counts remain lower bounds.
- The 4 contracts with no stored sources (79, 639, 640, 641) cannot be
  replayed and are invisible to the differential.
