# Wave 0 Report — trustworthy measurement

**Exit: PASS** (2026-07-27). Branch `fix/witness-integrity` off main `db9f76b6`,
20 commits, nothing pushed. Tier-0 gate at HEAD: suite **5135 passed / 0
failed**, ruff/pyright clean, vitest clean, determinism gate PASS on **both
classes**, R5 version bumps present, 3 test deletions declared. Two tier-3
(Fable) verdicts: **PASS / PASS**, findings routed to
`WITNESS_INTEGRITY_LEDGER.md` (now L-1…L-26).

## What landed (commit order)

| item | commits | outcome |
|---|---|---|
| **W0-1** storage keys + three-state storage failures | `cd2f9671..52061e40` (7) | Prefix fallback reads all **8,256** stale-prefixed rows (0 readable before → 8,256 after; `audits/` control untouched, id 183 still raises). `StorageKeyMissing`≠`StorageKeyAbsent`≠`StorageContentNotDetermined`≠`StorageUnavailable`, classified terminal/transient correctly; SPA artifact endpoint answers 503+`X-PSAT-Artifact-State` for non-answers; frontend renders four history states (pending/not-determined/absent/present) with 404-only-negative predicates. `stored_object_size_bytes` rename (W0-1c). **Accepted by driving-agent adjudication after 9 review rounds** — see Process notes. |
| **W0-2** D6 determinism | `281e5b11` | `Decimal` end-to-end; 8 seeds: 8 distinct outputs → **1**; tiebreak fires on 413 pairs every seed; `sweepDust` control exact `4024163604.46`. Cache v7. |
| **W0-3** `_taint.py` binding | `c7d7b157`+`5cf792fd` | Witness bound to call operand positions; `EndpointV2.lzCompose`/`LRTSquaredAdmin.rebalance` misbindings gone; guessed destinations no longer published as proven. |
| **W0-4** provenance union | `940bb23b` | `_handle_solidity_call` unions `args_union`; `Teller.refundDeposit` commitment binds `receiver`+`amount` (idx 1,2 committed set verified); `derived_from` three-state vocabulary documented on `Operand`. |
| **W0-5** jsonb-null audit | `226ec3ee` | `jsonb_typeof` predicates replace `IS [NOT] NULL` across the sweep scope; helper added; `job_dependencies.cycle_path` included. |
| **W0-6** D2 persist | `c99861cb` | `state_changing`/`state_writes`/`sinks`/`writer_selectors` persisted, all nullable, `none_as_null=True` load-bearing, one-query three-state test. Unblocks W3-D1. |
| **W0-7** corpus fixtures | `55d83ced`+`a7c82e46` | All ten §4 fixtures; each proven to discriminate by mutation (M-tests re-run by reviewer + verifier); `claims[].witness` pinned; parent-golden projection: 65 common rows, 0 changed/removed. **Adjudicated honesty fix:** the timed-latch fixture discriminates a bound-*inventing* reader but cannot discriminate timed-vs-indefinite until A7 widens the two-operand leaf — now stated in-fixture. |
| **W0-8** determinism gate | `c3053c45` | `scripts/witness/determinism_gate.sh`: class A (string-hash, 8 seeds) + class B (allocation-order, 3 fresh processes), self-proving (reverting the fixes makes it fail: A0/A1 and B0/B1 red reproduced). Gate.sh now requires it. |
| **W0-9** UpgradeEvent write path | `8964ebfe` | Poll path writes NULL (never 0) + real timestamp-at-detection; `source` discriminator (backfill/event_scan/poll, NULL=unknown) on all three writers; `ImplWindow.successor` ∈ {none, known, block_unknown}. Poll-detected upgrades sort after real events. |
| Closeouts/harness | `ac8264b9`,`b3880d2a`,`bffd6329` | gate.sh SIGPIPE inversion fix (agent); W0-4's 5 pyright errors fixed (driving agent); workflow adjudication state committed. |

## Baseline → after (preflight numbers)

- Artifacts readable at recorded key: 0/8,256 → **8,256/8,256** (via candidate
  fallback; DB values untouched).
- `effective_functions.conditions` JSON-null 780/1773, `artifacts.data`
  JSON-null 5770/5770 — now *measured correctly* by every audit query (the
  point of W0-5); the values themselves are Waves 1–3 work.
- Mutual control edges: **66** (unchanged — Leg F's Wave 1 metric).
- Candidate ordering: deterministic across seeds and processes (was 8/8 distinct).

## Process notes (deliberate corrections, not drift)

1. **W0-1 ran 9 review rounds** and was closed by driving-agent adjudication:
   the storage core was validated in round 2; rounds 3–9 rejected on real
   defects progressively further down the consumer graph (API → SPA → render
   prose → producer semantics). Root cause: unbounded rejection scope vs
   bounded mandates. **Corrections now in force** (operator-approved): review
   cap 3; reviewer scope discipline (out-of-scope reproduced defects →
   `out_of_scope_findings` → ledger, never rejection grounds); trivial
   residuals fixed directly by the driving agent; no human escalation
   (`WITNESS_INTEGRITY_OPERATIONS.md`).
2. **Leg self-reports are claims, not facts** (verifier lens 2): W0-4's commit
   message claimed pyright-clean while leaving 5 errors at its HEAD (L-11,
   fixed `b3880d2a`). Tier-2/3 must keep re-running the mechanical checks.
3. One W0-6 implementer died on an API 529 mid-item; its partial working-tree
   edits were discarded and the item re-run clean.
4. Harness fixes during the wave: gate.sh test-deletion check inverted on long
   branches (SIGPIPE under pipefail) — fixed by agent, committed `ac8264b9`.

## Constraints carried into later waves

- **A7 must land before (or with) any `is_pausable` widening over the
  EigenLayer bitmap family** (handoff §5 Leg A); additionally the timed-latch
  corpus fixture only becomes a full gate after A7 widens the duration leaf
  (`_duration_from_trees` positive branch currently unreachable from compiled
  source — L-16).
- **Wave 1–3 real-corpus differentials must own or exclude the
  `callee_args_digest` operand-slot flicker** (L-25, 37–46 slots across 25/88
  units) or ADDED/CHANGED noise will be misattributed.
- `derived_from` misbinds one origin on flow-insensitive local reassignment
  (L-24, `depositAsset` omitted / `nativeWrapper` published on the flagship
  Teller gate) — **W1-C reads this field; it must not treat it as ground truth.**
- W0-9's NULL block relocates into two era-side consumers
  (`auditMatching.js` ±Infinity fold; `contract_audit_timeline.py`
  `to_block:None`) — latent, 23 pollers armed, owner W3-E (L-26).

## What was not checked

- Storage controls under a *persistent* outage in a long-running worker
  (retry cadence beyond the classifier verdicts).
- Any second-chain behaviour (no analysis job has ever run on chain ≠ 1); all
  counts remain lower bounds per handoff §2.
- `eth_simulateV1` synthetic-log emitter address (A2's owed check — Wave 2 Leg D).
