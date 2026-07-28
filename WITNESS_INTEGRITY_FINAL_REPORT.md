# Witness Integrity — Final Report (Waves 0–4)

**Effort complete** (2026-07-28). Branch `fix/witness-integrity` off main
`db9f76b6`: **153 commits, 200 files, +38,280/−1,157. Nothing pushed** — per
the standing authorisation boundary, pushing/PR/merge/live-suite are the
operator's calls. Gate at final HEAD: suite **5,439 passed / 0 failed** (44
xfailed), vitest **615/615**, Playwright visual baselines 4/4 (run at Wave-3
close), determinism gate green on both classes, `EFFECT_CACHE_SCHEMA_VERSION`
5 → **34** (every bump with a stated reason; two recorded non-bumps with
grounds), `ANALYSIS_SCHEMA_VERSION` 2 → 4, `GOLDEN_SCHEMA_VERSION` → 5.

Zero human interactions, zero pushes, zero pipeline runs, zero live-suite
runs. Sparing live RPC was used four times across the effort (largest: 16
pinned reads), each with a discriminating control at block 25619159.

## Wave inventory

| wave | exit | HEAD | report |
|---|---|---|---|
| 0 — trustworthy measurement (9 items) | PASS | `a7c82e46` | WAVE_0_REPORT.md |
| 1 — legs A/C/F (static, claims, control graph) | PASS by adjudication | `93954b96` | WAVE_1_REPORT.md |
| 2 — legs B/D (capability/authority, effects/witness) | PASS | `5e17bd81` | WAVE_2_REPORT.md |
| 3 — leg E (consumers), D1 isolated | PASS by adjudication | `c85204a3` | WAVE_3_REPORT.md |
| 4 — ledger closeout (legs A/B/C) | PASS | `e3afd444` + closeout | WAVE_4_REPORT.md |

Driving-agent adjudications, each documented in the ledger's adjudication
records: W0-1 nine-round closeout (origin of the scope-discipline rules);
Wave-1 exit (one-line pyright guard, verdicts otherwise clean); Wave-2 Leg D
cap exhaustion (A7 clock-spelling split, applied per the reviewer's own
prescription, re-verified by both verifiers); Wave-3 gate false positive
(disposed in the flagged code, gate unweakened) + four reviewer-flagged
trivial residuals; Wave-4 final restatements (L-88). Every trivial-residual
direct fix is declared in its commit.

## Ledger accounting (L-1 … L-88)

- **Closed by fixes on this branch** (with the closing commit named in the
  ledger or wave reports): L-1, L-2, L-4, L-12 (reachability half), L-16,
  L-17, L-18, L-19, L-20, L-21, L-25, L-26, L-27, L-30, L-31, L-36
  (Wave-4 arm), L-38 (by attribution to `a96b2ca3`), L-40/L-41/L-42-class
  (the `controller_value_unattributed` gate), L-45–L-47, L-52–L-54, L-58,
  L-60, L-61, L-63, L-66–L-68, L-88.
- **Refuted on reproduction** (a successful outcome under the charter): L-72
  (no empty-selector named row exists; invariant pinned instead), L-34's
  persisted-legacy-token premise (never persisted; enum member dropped), and
  Wave-3's "62 of 147" / D1's "11 of 49" / Leg B's "12 on 6 units" magnitudes
  (all restated to measured or sample-qualified figures).
- **Open with owner + stated cause** (the deferral register below): the rest.
  Nothing was silently dropped; every entry is in
  `WITNESS_INTEGRITY_LEDGER.md` with a reproduction.

## Deferral register — open items, each with its stated cause

**Needs a pipeline/analysis run (cost boundary — first real run resolves or
rewrites):** L-12's convergence (orphaned contracts have no jobs at all),
L-81 (persisted fabricated fallback/receive selectors; producer fixed),
the 180 `terminal_principal` armed rows' post-fix distribution, every
producer-side gate verified by projection (the L-41 edge gate, the
`authority_openness`/`authority_roles` writers, the cache floor/plane-split/
proxy-refusal, D1's evidence filter once the W0-6 plane is written).

**Structural on the first multichain run (handoff §3 family):** the
deployment-key split, L-73 (wrong-chain `kind`/`label` from the chain-less
label plane), GAP-2-class chain scoping now shipped but with 0 realised
second-chain rows.

**Producer/orchestration planes outside every wave surface (recorded, not
scheduled):** L-69 (protocol_id-NULL orphaning: 594/1,773 EF rows, 26/107
artifacts), L-78 (orphan re-analysis cost pool, 511/641), L-79
(role-drift reconciler orphan join), L-80 (`fallback(bytes)` fabricated
selector), L-84 (`hash_commitment` guard-word mislabel — reaches the
rendered guard word; hedge correct), L-85 (declared-signature `selector`
field false on 317/2,247 effects records; `abi_selector` added beside it),
L-86 (`leaf.expression` SSA-name nondeterminism; PYTHONHASHSEED unpinned in
production images), L-9/L-10/L-24 (`derived_from` frame/origin edge cases),
L-14/L-15 (writer_selectors fabrication on persisted rows / view-contradiction
recall), L-17's audit-plane cousin (`AUDIT_LABEL_INTEGRITY_DEFERRED.md`
scope, untouched by instruction), L-22/L-23, L-28/L-29 (EigenStrategy
pause-variable misidentification, pre-existing), L-33, L-49
(transcripts hold no logs → effects replay identity), L-50, L-55, L-56,
L-62, L-64, L-65, L-70, L-74, L-75 (reach_indeterminate branch TVL check),
L-76, L-77 (solc silent-skip of the corpus gate), L-82, L-87.

**Standing method cautions (bind any future measurement):** L-83 — every
base-side tree count in Waves 1–4 was one sample of a distribution (the
pre-fix tie-break varied at a fixed seed); only post-L-25 HEAD is
byte-stable. The artifact-only claims recompute is invalid (Wave-1 lesson).
Effects artifacts are per-JOB, keyed by `jobs.address`, pre-canonicalization
signatures (Wave-3 lesson). The effects cache is unmeasurable-by-hit until a
real run writes v34 rows. The local DB is one protocol/one chain — every
count in this effort is a lower bound; the production DB is never evidence.

## Per-invariant closure honesty (re-derived against handoff §13; residuals unsoftened)

What changed since §13.3 was written, and what did not:

- **inv 2 (witness per scored item) / inv 3 ((capability, principal) pairs) /
  inv 5 (weakest path): the §13 conditions were MET on the code plane.**
  W2-B landed whole: the 351-row fall-through routes through real evidence,
  `authority_roles` is a real three-state derivation (200/364/1,209),
  `function_principals` carries `resolver_path`, the role-grant edge inputs
  exist for the graph builder, and the callee-as-controller conflation is
  gated (`controller_value_unattributed` ∉ `CONTROL_EDGE_RELATIONS`). **All
  verified by projection over persisted inputs — none observed on
  re-persisted rows.** These invariants are code-plane closed, run-plane
  pending: the honest state is "conditionally closed, condition = one real
  pipeline run behaves as projected".
- **inv 4 (dual-use both ways): the blocker named in §13 was fixed** (the
  provenance split reaches `principal_labels` via the shared upstream; the
  Ethereum-2-deposit-contract-as-controller class is gated), and A7 bounds
  the pause side with an honest three-state source. Same run-plane caveat.
- **inv 12 (re-analysis is a no-op): all three known classes are now closed**
  (W0-2 float, W0-8 string-hash, W2-D cache mutate-on-read declared via
  `REPLAY_IDENTITY_EXCLUDED_COLUMNS`) **plus the fourth found en route**
  (L-25 allocation-order tie-break, settled) — with L-86's expression-field
  noise the known remaining exception, ledgered with an owner. "No known open
  class except L-86" is a statement about what has been looked for.
- **inv 9 (exact decomposition): unchanged — closed for identity**; the
  credit-bearing timelock delay value remains deliberately unread
  (`delay: null` + `delay_source: "not_read"`) until a chain is threaded.
- **inv 13: closed** (unchanged; the fabricated-selector cosmetic is now
  narrower: producer emits the sentinel, L-81 rows await a run, L-85 owns the
  artifact-plane sibling).
- **inv 1, 6, 7, 8, 10, 11, 14, 15: STILL NOT CLOSED — unchanged from §13.3,
  and unsoftened.** Their blocking inputs live in planes no wave owned:
  `contracts.is_proxy`/`admin`/`beacon`/`deployer` NULL-means-both (inv 1, 7),
  monitoring/analysis/replay coverage denominators incl. D5's 268/354 blind
  gated functions (inv 6), the discovery perimeter (inv 8), the untested
  alerting substrate (inv 10), no `model_version` + input identity for
  81/641 (inv 11), one protocol row as the whole population (inv 14), no
  findings-ledger schema (inv 15). D4 (staked/validator value) also remains
  open — `EtherFiNodesManager` still weighs at its token holdings.
- **Net: a scorer built on today's inputs still builds on inv 1, 6, 7, 8, 10,
  11, 14, 15.** What this effort changed is that the pre-scorer witness plane
  no longer *manufactures* false proofs on the planes it touched — every
  fix's residual risk is a stated deferral, not a silent gap.

## What the operator gets to decide now (the actions this effort was not
authorised to take)

1. **Push / PR / merge** of `fix/witness-integrity` (153 commits; preview
   deploy + ~27-min live suite on push).
2. **One real analysis run** on a test protocol after merge — it converts
   every projection-verified producer gate into observed rows (and rewrites
   L-81's stale selectors, exercises the v34 cache, fires or falsifies the
   L-41 edge gate).
3. The **post-effort owners** named in the deferral register (discovery/
   orchestration-plane items, the multichain family, L-84/L-85/L-86).
