# Wave 3 Report — leg E (consumers), then D1 (candidate-set retarget) isolated

**Exit: PASS by driving-agent adjudication** (2026-07-28). Branch
`fix/witness-integrity`, HEAD `9e0c7f80` (E merged `8aaa3af1`, D1 merged
`d34638b4`, adjudication closeout `9e0c7f80`). Both tier-3 Fable verdicts:
**PASS / PASS** with `controls_held` and `differential_reconciled` true. The
tier-0 gate's one FAIL (`no-new-jsonb-isnull`) was identified by BOTH verifiers
as a grep false positive on the correct compound guard; it was disposed
mechanically (drop the redundant `IS NULL OR` — `jsonb_typeof(SQL NULL)` is SQL
NULL, so the CASE already folds it), the gate re-run to PASS, and no verifier
round spawned (adjudication-economics rule). Suite at final HEAD: **5,398
passed / 0 failed** (44 xfailed), vitest **606/606**, Playwright visual
baselines **4/4** (the previously unexercised gate), determinism both classes,
R5 v31→v32.

## ⚠️ Public-payload changes (called out per §10 special handling)

Two **removals** on the public unauthenticated `/api/analyses` detail payload
(`6de80484`): `principal_labels.confidence` is **renamed to `naming_rule`** on
1,420/1,420 principal rows (it was a naming-branch label, two-valued in
practice, ~97% a restatement of `resolved_type`, and could never say "not
determined" — inv 6 forbids publishing that as confidence), and the `label` key
is **suppressed where byte-identical to `display_name`** (1,420/1,420 locally —
a consumer reading both believed there were two facts). No `site/` consumer
reads either key (grep-verified). Anyone consuming these keys externally must
migrate to `naming_rule` / `display_name`.

## What landed

### Leg E — consumers (`witness/leg-e`, 15 commits, accepted round 3)
- **Summary three-state reaches the payload** (`419f1d0f`): `has_timelock` /
  `is_pausable` / `is_factory` now pass NULL through with a `summary_evidence`
  discriminator splitting the two null routes (no summary row vs row-with-NULL
  column) — 3 of the 56 served entries are the absence arm (all `UUPSProxy`
  dependencies); the "62 of 147" magnitude in the original commit did not
  reproduce and was corrected to the measured figure. Band/role folds hold:
  0 chips/roles moved on proven inputs; a `role_evidence: not_determined` node
  now lands in the neutral band, not the plumbing band.
- **BalanceTable** (`85ae65d3`): unpriced (`usd_value` NULL) renders "not
  priced" — never "—" — with the note *"an unknown value is not a small one"*;
  the dust filter is priced-only; `holdings_coverage` + `usd_value_state` land
  in the payload (265 of 448 rows not-determined, disclosed); page-cap
  truncation discloses (0 realised at-cap entries locally — R2-honest). The
  page-cap signal is read off the endpoint response, not the already-filtered
  list.
- **Chat plane** (`624e0478`, `bf7df309`): `classify_address` gains the chain
  predicate + a total order (the heap-order flip to a less-resolved `contract`
  was exhibited via TEMP-TABLE reorder and is now impossible); "last upgrade"
  polarity fixed (a NULL-block poll row was reported as the OLDEST event; now
  newest-by-timestamp with a `detection` discriminator); `role_holders`
  publishes the 8 real Solmate/Solady roles with per-role evidence instead of
  one fake role with 136 "holders" (re-published honestly as
  `authorized_callers`, *"NOT role holders"*).
- **`action_summary`** (`5194ebcd`): `summary_kind` discriminator on all 975
  rows (`effect_label` 570 / `effect_target_list` 313 / `vacuous` 92); the 15
  rows still quoting A3's narrowed "arbitrary" over-claim on the two public
  endpoints now say *"whether the destination is freely chosen was not
  determined"* — the last prose copy of A3 closed (R3).
- **Tier lattice reaches the score** (`a5a2972b`): `policy_derived` scores
  strictly below `standard_exact` and surfaces `provenance_tier`; W0-7 fixture
  10 is the gate (realised corpus effect 0 — the producer is still silent,
  which is the point); `claimSummaryLine` names mixed tiers. **L-47 closed**:
  a measured $0 reach renders as *"$0 — measured"*, distinguishable from
  never-attempted, and the pre-D3 keyless payload deliberately stays silent.
- **L-1 consumer half closed** (`fd30527d`): the upgrade-history 404 is now an
  EARNED proven-negative only — 56 of 186 jobs move to 503 +
  `X-PSAT-Artifact-State: not_determined` (55 no-contract-row, 1 the
  contradictory beacon row `0x3c5598…`, the L-1 falsification address); 85
  genuine non-proxies keep the 404 (negative control). **R4 deviation,
  declared and verified sound**: the two "defect-pinning" ActivityPanel arms
  were KEPT, because the server-side split makes their pinned mapping correct;
  positive siblings added. `proxyState`/`contractTypeForMachine` stop earning
  `regular` from unread machines (`unclassified` / `not_determined` arms).
- **L-2 closed** (`3ae10ed6`): a failed 30s poll keeps proven events and
  renders "not determined", never a clobbered empty list.
- **L-19/L-26 era folds closed** (`b6b374ba`): `buildTimeline` and
  `auditMatching` treat NULL blocks/timestamps as not-determined (6 of 15
  matrix cells flipped off the ±Infinity fold), with the single-impl and
  fully-bounded positive controls unchanged; L-21's badge inference verified
  0-realised with the armed population reproduced (15+2 rows).
- **terminal_principal wired** (`2a57f249`): `_build_principal_lookup` joins
  `PrincipalLabel`; 235 payload entries gain `details.terminal_principal`.
  Honest measurement: realised render delta is 0 — dominantly because the 22
  annotated addresses and the 22 rendered surface principals are disjoint sets
  on this corpus (comment corrected); the 180 armed rows' post-policy-run
  distribution remains unmeasurable (cost boundary).

### Leg D1 — the candidate-set retarget (`witness/leg-d1`, ONE commit `7bbb23ea`)
- `_has_effect_evidence()` replaces the `effect_targets` display-field read:
  six-disjunct evidence predicate over W0-6's persisted plane (proven write /
  proven sink / ABI-mutating / three not-determined arms), each disjunct
  sole-pinned by a test (the missing `state_changing IS NULL` arm was added at
  closeout, mutation-checked).
- **Candidate delta, re-derived independently: 443 → 481, +38 / −0**, with the
  438 surviving candidates byte-identical field-by-field and order unchanged.
  Filter (a) is vacuous today (the W0-6 plane is entirely unwritten — NULL on
  1,773/1,773), so every entering row is admitted by not-determined — the
  fail-closed direction. Projected onto the artifact plane: +49/−0 at filter
  (a); the 61 proven-inert rows are excluded the day the plane is written; all
  38 entering candidates survive it (36 ERC-receiver hooks + the 2 Solady
  alert rows).
- **The 156 external-call-only population**: retained 156/156 (147
  `state_changing TRUE` / 8 no-record / 1 proven-sink — fid 2344
  `shouldSubmitReport`, the one row the sink ground alone keeps); nothing was
  removed — what was removed is the *inference* that membership proved a
  write. The L-15 withheld set (14 rows / 89 sinks, reproduced exactly) is
  retained by (a) and dropped by (c) at both revisions.
- `SCORING_INVARIANTS.md:268-292` restated (the "260/756" conflation figure
  superseded; instrument limits ledgered L-71). R5: v32 with the stated
  reason. **Isolation verified**: the only executable diff in the range is the
  predicate swap + helpers; no other published value moved.

### Driving-agent adjudication (wave close, `9e0c7f80`)
Gate false-positive disposal (above) plus the reviewer-flagged trivial
residuals: L-63 (the `matchesEra` successor discriminator accepts either
sibling key — a proven successor with an unrecorded timestamp no longer
Infinity-folds; discriminating arm added), the sole-pin arm for
`state_changing IS NULL`, StatusStrip's omitted-prop default moved off the
proven state, the role-source prose corrected, and the two stated-magnitude
comments fixed to measured figures. Playwright visual baselines run: 4/4.
19 stale per-leg test DBs dropped.

## Differential integrity
Two sections, attribution kept apart, L-25 noise 0 in both (neither plane
reads the flickering field). Section 1 (Leg E): 2,884 payload leaf diffs = 2,863
ADDED + 21 transitions, every non-ADDED row attributed; render matrices
enumerated per input shape for proxyState/StatusStrip/buildTimeline/
auditMatching/BalanceTable/scoreClaimsView; chain-twin probes (30) and the
TEMP-TABLE heap-reorder exhibit. Section 2 (D1): the candidate delta above,
`nothing else moved` confirmed against the executable diff. Method cautions
earned (binding for Wave 4): effects artifacts are per-JOB keyed by
`jobs.address` with pre-canonicalization signatures — the wrong join
reproduces the right headline (+49) while mis-measuring every finer split;
`control_graph.nodes[]` payload entries carry `type`, not `resolved_type`.

## Harness changes this wave (deliberate corrections, not drift)
- Sequential two-leg workflow with per-leg merges and a SPLIT differential
  (D1's range measured alone) — the isolation contract held.
- The `no-new-jsonb-isnull` disposal was made in the flagged CODE, not by
  loosening the gate pattern — the check is unchanged and still guards the
  diff.

## Carried into Wave 4 (see ledger for detail)
- New admissions: L-66 (coverage-note disclosure suppression), L-67 (test-DB
  idempotence), L-68 (`Candidate.effect_targets` write-only trap), L-72
  (empty-string selectors on named functions).
- Wave-2 admissions still open: L-46 (TVL ceiling's priced-floor branch), L-52
  (relation pin test), L-53 (openness payload half unpinned), L-58+L-60
  (side/operator-aware harvest + fork-containment pin).
- Recorded, no owner: L-64, L-65, L-69 (protocol_id-NULL quantified), L-70,
  L-71, L-73 (wrong-chain kind/label — structural, §3 family), L-74.
- L-12 and L-38 remain open (unchanged since Wave 2's statement).

## What was not checked
- No pipeline stage ran (cost boundary): the D1 projections, the 180
  terminal_principal armed rows, and every producer-side gate from Waves 1-2
  still bind the next real run rather than being observed on re-persisted rows.
- No second chain; all counts remain lower bounds (2,506/2,506 control-graph
  rows on ethereum; the 3 real twins have no control-graph rows, so the
  chain-predicate fix is exercised by probe, not by realised data).
- The 4 source-less contracts and 48 effects-artifact-less rows remain
  invisible to projections; 594 protocol-NULL rows never enter the cascade
  (L-69).
- `action_summary`'s two public endpoints were exercised in-process only.
