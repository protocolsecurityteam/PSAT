# Post-merge verification spec — Issue #119 (event-log cursor exactness)

**Purpose.** A living acceptance-criteria doc for the fix that corrects the
durable event-log fold's exactness label: an event-indexed authority set is now
reported `exact` **only when the durable index cursor demonstrably covers the
evaluated height**, and a per-pass finalized head-pin keeps a keeping-up cursor
`exact` while demoting a lagging/stalled one to `lower_bound`. This is a
**fail-closed label-correctness fix**: it can only move a verdict toward
`lower_bound` / gated, never toward public. See `analysis/issue-119-FINAL.md` and
`analysis/issue-119-FINAL2.md` for the settled root cause and spec.

> **Status:** committed on branch `wt/issue-119` (commit `36f9d68`), **not pushed**.
> Fill in PR # / preview URL when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state**. After the PR deploys to a preview env and a
   resolution pass runs, confirm each `## Change` section's checks against the
   preview API / DB / logs. Mark every check **PASS / FAIL** and report any FAIL
   with the actual observed value.
2. **This fix needs a resolution RE-RUN to take effect** (unlike an aggregation-only
   fix). The label is computed at the *policy/resolution* stage, so persisted
   `capability`/`effective_permissions` rows keep their pre-deploy labels until the
   contract is re-resolved (next scheduled pass, or an explicit re-run). Verify
   against a **fresh** resolution, not stale rows.
3. **Ground-truth caveat.** Absolute counts (how many folds stay `exact` vs demote)
   depend on the event indexer's live cursor position at resolution time — i.e. how
   far `last_indexed_block` trails the finalized head. **Verify the _invariants_**
   (what stays exact / what demotes / nothing goes public / nothing dropped), not a
   fixed integer. Re-derive counts by reading the `event_fold_partial_cursor_behind_block`
   metric (below) on the actual run.
4. **Trust but verify the direction.** The core correctness invariant is:
   *this fix never fabricates access.* Every change it makes is `exact → lower_bound`
   (adds gating) or preserves `exact` unchanged. If **any** guarded function newly
   reads **public/permissionless** after this deploy, that is a regression from some
   other cause — this fix cannot produce it.

### Environment / how to query

- **Stage metric (primary signal):** each partial fold increments
  `event_fold_partial_cursor_behind_block` via `record_stage_metric`, surfaced by
  `GET {preview_url}/api/jobs/{job_id}/stage_timings` under the policy stage's
  `metrics`. `0`/low when the indexer is keeping up; it rises only when a cursor
  lags the finalized pin. (ops/company reads may be admin-gated — PR #142; use the
  live-tests `live_client` if you get 401/403.)
- **Logs (Loki):** a demotion logs at **DEBUG**
  `event fold returned partial result: cursor_behind_block` with
  `extra={partial_reason, event_address, repo}` (correlate by `trace_id`). DEBUG is
  usually filtered in prod — prefer the metric. `cursor_behind_block` is intentionally
  **not** in `_DEGRADED_PARTIAL_REASONS` (a steady lag is not a fault, just less
  precise), so it is not a WARNING.
- **Direct (most deterministic):** run the committed proof + regression suite against
  the target DB (Appendix A). They drive the **real** `PostgresEventLogRepo` /
  `EventIndexedAdapter` / `_resolve_resolution_block`, only seeding rows.
- **Knobs:** `PSAT_RESOLVER_FINALITY_MARGIN` (default **64** blocks; the head-pin is
  `head − margin`). The indexer's own confirmation depth is
  `PSAT_EVENT_INDEXER_FINALITY_DEPTH` (default **12**); the margin is deliberately
  deeper so a keeping-up cursor covers the pin without a resolver-vs-indexer race.

### Global regression guards (apply to every change)

- CI green: `ruff check` / `ruff format --check` / `pyright` / offline `pytest -m "not live"`
  / frontend / diff-cover ≥ 70% on the PR.
- **Offline suite makes ZERO real external calls.** The offline network guard
  (`tests/conftest.py`) escalates the session exit to 1 on any blocked wire even when
  every test passes. The resolver's now-**unconditional** head read
  (`_resolve_resolution_block` → `eth_blockNumber`) is stubbed offline by the autouse
  `_stub_resolution_finality_head_read` fixture (degrades to the `block=None` path).
  A `[offline-guard] … eth_blockNumber` block is a FAIL.
- **No function moves toward public.** `exact → lower_bound` is the only label
  transition this fix makes; it can only add gating.
- Already-merged partial fixes unaffected: #132 (earned-public), #134 (assembly-only
  unsupported rows), #107 (deferred reconciler) — regression suites still green.

---

## Change 1 — event-log fold cursor-coverage gate + deterministic finality head-pin

- **Commit:** `36f9d68` `fix(resolution): event-log cursor exactness — keeping-up→exact, lagging→lower_bound (#119)`
- **Branch / PR:** `wt/issue-119` → PR **#____**
- **Files:** `services/resolution/repos/event_logs_pg.py` (fold gate + row-ceiling),
  `services/resolution/capability_resolver.py` (finality-margin head-pin),
  `services/resolution/repos/event_logs_hypersync.py` (sibling gate),
  `tests/conftest.py` (offline hermeticity), `tests/test_issue119_cursor_coverage.py`
  (regression), three co-land test edits, `proof_119_final.py`.

**What it does.**
- **Fold coverage gate.** `_cursor_covers_block(cursor, block)` gates all three PG
  folds (`fold_event_writes` / `fold_event_history` / `fold_event_values`). A warm
  (`backfill_complete`) cursor proves the member set only up to `last_indexed_block`;
  if it does not cover the evaluated `block` (or `block is None` = live head), the
  fold returns `partial`/`cursor_behind_block`, which the adapter routes to
  `finite_set(membership_quality="lower_bound")`. Previously the fold minted
  `enumerable`→`exact` on `backfill_complete` alone, never comparing to the point.
- **Row-scan decoupled from the pin** (`_row_ceiling`). Rows fold up to the index
  **frontier** (the cursor), never truncated at the lower finality pin. So an
  already-indexed **denylist** member in `(pin, cursor]` stays in the negated
  `cofinite_blacklist` (gated) instead of falling out and reading public.
- **Deterministic finality-margin head-pin.** `_resolve_resolution_block` pins the
  whole pass's `ctx.block = head − RESOLVER_FINALITY_MARGIN` (default 64), deeper than
  the indexer depth (12), so a keeping-up cursor **provably covers** the pin (stays
  `exact`, no head race) and a stalled cursor falls below it (demotes). `None` on
  no-RPC / head-read failure leaves `block` unpinned → folds demote (safe).
- **HyperSync sibling** — an unpinned `to_block` scans to the live archive tip →
  `cursor_behind_block` (defense-in-depth; the repo is test-only in prod today).

### Expected before → after (real/faithful data)

| Scenario (event-indexed authority set) | Before (`5152ff0`) | After (`36f9d68`) |
|---|---|---|
| Cursor keeping up (`last_indexed_block ≥ head − 64`) | `exact` | **`exact`, same members** (no precision loss in steady state) |
| Cursor lagging / indexer stalled (`< head − 64`) | `exact` (mislabeled) | **`lower_bound`** ("at least these"); members still surfaced, none dropped |
| Prod policy path (`block=None`, evaluate at live head) | `exact` (structurally can't be) | **`lower_bound`** unless the resolver's head-pin is covered |
| **Empty** event set whose only authority is a lagging fold | `exact` → `_is_root_authority_blocker=False` → **function PUBLIC** (worst-class fail-open) | `lower_bound` → blocker `True` → **function GATED** (fail-closed; self-heals next pass) |
| Denylist member indexed at block in `(pin, cursor]` | could drop from an `exact` blacklist → **public** | **stays in the exact blacklist → gated** |

On the etherfi corpus (the faithful stack), with a **healthy** event indexer the
observable is: **most event-indexed sets stay `exact` and unchanged** (Solmate
RolesAuthority `canCall` members, OZ AccessControl role sets), and
`event_fold_partial_cursor_behind_block ≈ 0`. The fix is **not** a broad demotion in
steady state — it demotes **only** genuinely-lagging folds.

### Detailed invariants (verify each)

- **A. Never fabricates access.** No guarded function newly reads
  public/permissionless. (Only transition is `exact→lower_bound`.) — headline check.
- **B. Keeping-up stays exact.** A set whose cursor is within `RESOLVER_FINALITY_MARGIN`
  of the finalized head keeps `membership_quality="exact"` and the **same members**.
- **C. Lagging demotes.** Cursor below the pin → `partial`/`cursor_behind_block` →
  `lower_bound`; members are still surfaced (a lower bound, never dropped).
- **D. Indexed denylist member in `(pin, cursor]` stays gated** (not dropped from the
  cofinite blacklist → not public).
- **E. Empty `lower_bound` event set ⇒ GATED** (fail-closed); it self-heals on the
  next pass once the cursor reaches the finalized head.
- **F. Determinism (no flap).** A healthy keeping-up cursor stays `exact` across
  resolver-timing jitter (margin 64 − depth 12 = 52-block headroom); it does not flip
  `exact↔lower_bound` between passes at the same cursor.
- **G. Offline hermeticity.** The offline suite makes zero real external calls (guard
  clean); the head read degrades to the `block=None` path under the autouse fixture.

### How to verify

1. **Offline (deterministic), against the target DB** — run Appendix A. Expect
   `PROOF: PASS` and the regression suite green.
2. **Metric.** On a fresh resolution job, `GET /api/jobs/{job_id}/stage_timings` →
   policy stage `metrics` → `event_fold_partial_cursor_behind_block`. Cross-check the
   indexer health via `/api/fleet` (event_indexer heartbeat + backfill). Healthy
   indexer ⇒ metric ≈ 0; a rising metric should coincide with a lagging/stalled cursor.
3. **Label spot-check.** For a contract with an event-indexed ACL, read the resolved
   capability's `membership_quality`. Keeping-up ⇒ `exact`; force/observe a lag ⇒
   `lower_bound`. (Direct: `resolve_contract_capabilities(session, address, chain_id)`
   at the pinned height.)
4. **Fail-open closed.** Confirm no function whose only authority is an event-indexed
   set flipped from GATED to PUBLIC across the deploy.

### Regression signals — FAIL if any of these

- Any event-indexed set labeled **`exact` while its cursor lags** the finalized pin
  (the original bug re-opened).
- Any guarded function newly reads **public/permissionless** (this fix cannot cause
  it — investigate another change).
- A **keeping-up** cursor (within margin of head) **demotes** in steady state
  (over-gating — likely margin under-set for the chain cadence; see follow-ups).
- A denylist member indexed **at/below the cursor** is **dropped** from the blacklist
  (fail-open — the `_row_ceiling` decoupling regressed).
- The offline suite trips the network guard (`[offline-guard] … eth_blockNumber`,
  session exit 1) — the head read is not stubbed.
- `event_fold_partial_cursor_behind_block` persistently high **while** the event_indexer
  heartbeat/backfill is healthy (mis-tuned margin, not a real stall).

### On-chain / cross-source sanity (optional)

Pick a contract with a Solmate RolesAuthority or an event-indexed role/denylist:
- A role/member granted **well below** the cursor → present and `exact`.
- A role granted **above the finalized pin** (`(pin, head]`) → correctly excluded only
  within the finality window (~64 blocks, ~13 min on Ethereum) and appears once
  finalized/re-resolved. This is finality latency, **not** the #119 under-report.

### Known follow-ups carried by this change (not regressions)

- **Finality-latency omission.** A grant in `(pin, head]` is invisible until finalized
  — inherent to any finalized-view reader, strictly better than pre-fix (unbounded for
  a stopped indexer). "Self-heals each pass" assumes periodic re-resolution; one-shot
  jobs see it until re-run.
- **Margin is chain-cadence dependent.** Default 64 fits ~2–12 s chains
  (Ethereum/Base/Optimism/Polygon). Sub-second chains (Arbitrum) want a higher
  `PSAT_RESOLVER_FINALITY_MARGIN` or a healthy cursor can fall below the pin. Every
  mis-tune only **demotes** (safe), never a false `exact`.
- **HyperSyncEventLogRepo not wired into prod resolution** (test-only today); its gate
  is defense-in-depth.

---

## Out of scope / open (track here; not regressions)

- **The actual data OMISSION** (a not-yet-indexed grant is invisible) is an
  indexer-throughput concern. This fix corrects the **label** (never asserts an
  un-covered set is complete), not membership.

---

## Appendix A — reproduction (committed artifacts)

Both run offline against a migrated test DB; only rows are seeded, real repo/adapter/
resolver code runs.

```bash
# From the worktree, with the main venv (do NOT `uv sync`):
cd <worktree>
set -a; source /home/riley/PSAT/.env; set +a
export TEST_DATABASE_URL="postgresql://psat:psat@localhost:5433/<packet_db>"   # migrated
export PSAT_LLM_STUB_DIR=<worktree>/tests/fixtures/scope_extraction/llm_responses

# 1) Real-Postgres proof (before→after on one seeded cursor): expect "PROOF: PASS"
PYTHONPATH=<worktree> /home/riley/PSAT/.venv/bin/python proof_119_final.py

# 2) Regression suite (fold demotion, adapter lower_bound/exact, the (pin,cursor]
#    denylist member, the finality-margin pin, HyperSync sibling):
PYTHONPATH=<worktree> /home/riley/PSAT/.venv/bin/python -m pytest -m "not live" \
  tests/test_issue119_cursor_coverage.py -q
```

`proof_119_final.py` prints, on one warm cursor seeded at `last_indexed_block=1000`:
`fold(block=None)→lower_bound`, `fold(block=990 covers)→exact`,
`fold(block=1050 lags)→lower_bound`, `fold_event_values` likewise, the empty-set
blocker flip (`exact`→not-blocker / `lower_bound`→blocker), and the `(pin,cursor]`
denylist member remaining in the exact cofinite blacklist (gated, not public).

## Appendix B — live demotion-rate probe (metric)

```bash
# Demotion counter on a resolution job (policy stage). ~0 while the indexer keeps up.
curl -s "{preview_url}/api/jobs/{job_id}/stage_timings" \
  | jq '.. | objects | select(has("event_fold_partial_cursor_behind_block"))
             | .event_fold_partial_cursor_behind_block'
# Cross-check indexer health (cursor should be within RESOLVER_FINALITY_MARGIN of head):
curl -s "{preview_url}/api/fleet" | jq '.event_indexer // .daemons'
```
