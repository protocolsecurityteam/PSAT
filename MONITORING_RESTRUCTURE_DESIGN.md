# Protocol Monitoring Restructure — Final Design (adversarially reviewed synthesis)

Status: recommended design, produced by adversarial review of Design A (evolve-in-place)
and Design B (consolidate onto existing infra). Base: **Design A's architecture**, with
six corrections found by attacking A, and five ideas adopted from B. Appendix A records
every adopt/reject decision with reasons. All file:line citations verified against HEAD
(`3fb79fe`).

Scaling target: 50 protocols / 5,000–10,000 monitored contracts / multi-chain.
Starting reality: monitor fly machine **stopped** (retries exhausted 2026-06-01),
`monitored_contracts.last_scanned_block` ~36 days (~250k blocks) behind head,
`monitored_events` empty in prod.

---

## 1. Architecture overview + memory math

### 1.1 Verified failure anatomy (both designers got this right)

- One 512MB machine, four CPython interpreters (`start_monitor.sh:34-41`, ~4×65MB
  baseline), `wait -n` (`start_monitor.sh:46`) → any child death restarts the machine,
  fly default `on-failure` retry budget → permanent stop.
- **R1 (fatal peak):** `reconcile_enrollments` (`services/monitoring/reconciler.py:87-102`)
  walks every `Protocol` and calls `enroll_protocol_contracts` with the default
  `enroll_controllers=True` (`enrollment.py:91,272-273`) → `_enroll_controller_addresses`
  (`enrollment.py:616-619`) → `controllers_for_protocol` → `build_governance_view`
  (`company_overview.py:2035,1039`) — the full Surface computation in RAM. `_boot_reconcile`
  (`unified_watcher.py:1113-1127`) re-runs the sweep at the start of both the scan loop
  (`:1133`) and the poll loop (`:1161`), making the OOM deterministic on every restart.
- **R2 (unbounded pass):** `scan_for_events` hydrates every active `MonitoredContract`
  ORM row incl. `monitoring_config` JSONB (`unified_watcher.py:79-85`), takes
  `from_block = min(all cursors)` (`:124`), preloads an O(history-in-range) dedupe set
  (`:167-183`), and commits once per pass (`:339`). The poller builds one batch over
  every poll entry of every contract (`:927-957`).
- **Silence:** heartbeats exist (`emit_monitor_cycle`, `services/monitoring/__init__.py:31`)
  but the only consumer is `/api/fleet` on demand (`routers/fleet.py:28`,
  `fleet.py:87-98` logs a WARNING nobody routes). The scanner/poller/TVL daemons aren't
  even in `PROCESS_META` (`fleet.py:56-62`).

### 1.2 Target architecture

```
fly `monitor` group — 1 machine, shared-cpu-1x, 512MB, [[restart]] policy = "always"
┌──────────────────────────────────────────────────────────────────┐
│ workers/protocol_monitor.py  (ONE interpreter, ~65MB baseline)   │
│  Supervisor: restarts a dead thread w/ backoff, error heartbeat  │
│   ├─ scanner thread  — cohort/window/budget scan, lease-gated    │
│   ├─ poller thread   — rotation + chunked batch, lease-gated     │
│   └─ tvl thread      — oldest-snapshot-first, per-pass cap       │
└──────────────────────────────────────────────────────────────────┘

fly `workers` group (16GB) — gains ONE drainer process:
  workers/protocol_monitor --reconcile
    drains monitoring_enrollment_queue (dirty protocols only, lease-stamped claim)
    + K-per-tick slow sweep as convergence backstop

fly `web` group (health-checked, min_machines_running=1) — gains the watchdog:
  ops_alerts lifespan task: worker_heartbeats staleness → Discord ops webhook
  + ERROR log (→ Grafana/Loki rule) + GET /api/health/monitoring (200/503)
  for an external uptime checker            [adopted from Design B §2.7]
```

Why this shape and not Design B's "everything on the workers fleet":
`start_workers.sh` ends in `wait -n` — **any** of its ~13 processes dying restarts the
whole machine, SIGKILLing in-flight forge/Slither/policy jobs. Hosting all of
monitoring there couples monitoring's survival to the busiest, crashiest machine in the
fleet; at N=1 workers machine a deterministic crash of *any* worker exhausts the same
fly retry budget that killed the monitor VM — recreating the original failure mode with
a strictly larger blast radius (pipeline + monitoring both dead). The dedicated 512MB
monitor VM is cheap, isolated, and — once the expensive computation is off it — sized
with ~6× headroom. Only the reconciler (a jobs-pipeline-weight computation) moves to
the 16GB box, and it is a drainer whose loop swallows all exceptions
(`run_enrollment_reconciler_loop` already does, `reconciler.py:127-141`), so the
`wait -n` exposure it adds is process-death-only (OOM/segfault), not exception-driven.

### 1.3 Memory math at 50 protocols / 10k contracts

Single interpreter baseline **~65MB** (vs ~260MB today).

**Scanner pass** (per chain):
- Contract index: columns-only `select(MC.id, MC.address, MC.chain, MC.last_scanned_block)`
  — 10k tuples × ~150B ≈ **1.5MB**. (Today: 10k full ORM rows whose `monitoring_config`
  carries tracked_topics + polling_plan at 5–50KB each ⇒ 50–500MB before any RPC. The
  columns-only load is the single most important change for the scale target.)
- Per window: hydrate only the ≤`PSAT_SCAN_ADDRESS_BATCH` (200) rows that emitted logs
  ≈ ≤4MB; logs bounded by the provider's own response cap (~10k logs ≈ 10MB worst case,
  ~zero typical — governance events are sparse). Committed and freed per window.
- Peak ≈ **~80MB**, independent of total contract count and of cursor lag.

**Poller pass:** rotation slice of `PSAT_POLL_CONTRACTS_PER_PASS` (500) hydrated rows
≈ 10MB + ≤500-call JSON batches (matches `MAX_BATCH_SIZE=500`, `utils/rpc.py:23`),
commit per chunk. **O(slice)**. Full rotation at 10k×60% needs_polling ≈ 12 passes ≈ 2h
at the 600s cadence — acceptable for the polling *backstop* (events are the low-latency
path); both envs are operator-tunable.

**TVL pass:** one protocol at a time (already true, `tvl.py:346-358`), now capped at
`PSAT_TVL_PROTOCOLS_PER_PASS` (10) oldest-snapshot-first. KBs.

**Reconciler (16GB workers box):** one `build_governance_view` at a time, fresh session
per protocol, dirty protocols only. Steady state = **zero** heavy recomputes per tick;
worst case (mass re-analysis of 50 protocols) serializes ~50 builds, each memory-bounded
to one protocol's view (~150–300MB observed for etherfi-sized), on a machine sized for
exactly this class of work. Honest ceiling: if a single protocol's view outgrows the
box at 10× contract counts, the view must be persisted/incrementalized — that is the
successor project, not smuggled into this one.

**Work proportionality:** scan work per pass = min(windows needed, budget) getLogs
calls; steady state ≈ `ceil(10k/200)` = 50 cheap head-checks + windows for new blocks
only. Poll = fixed slice. Enrollment = O(dirty) + O(K sweep). TVL = O(cap). No periodic
pass is O(total) in memory, and the only O(total-protocols) periodic work is the
K-per-tick sweep *scheduler* (a 1-row upsert per tick), not the computation.

Catch-up check against today's backlog: 250k blocks / 2,000-block windows = 125
windows; 50-window pass budget + 5s busy-interval ⇒ 3 passes, well under an hour, flat
memory. (Design B's 30-chunk budget gives the same answer; numbers agree.)

---

## 2. Component design (file-level)

### 2.1 Scanner — `services/monitoring/unified_watcher.py` (rewrite `scan_for_events`)

Adopts the event_log_indexer's proven pass discipline (budgets, rotation, per-window
durable commit, confirmation depth, busy-interval — `workers/event_log_indexer.py:52-60,
419-441,780-801`) over `monitored_contracts`, **without** merging cursor models (§5).

1. **Columns-only index load** (no ORM hydration, no `monitoring_config`).
2. **Cohorts:** group by `(chain, last_scanned_block // MAX_BLOCK_RANGE)`, split at
   `PSAT_SCAN_ADDRESS_BATCH` (200) addresses. Enrollment seeds cursors at head
   (`enrollment.py:239`) so cohorts are naturally few. Window scans from the cohort
   **min** cursor; members above the window floor are protected from duplicates by the
   per-window dedupe (below) — same semantics as today's `chunk_addresses` +
   `db_events` pair (`:194,167-183`), now bounded per window instead of per pass.
3. **Rotation + budgets:** most-behind cohort first; `PSAT_SCAN_MAX_WINDOWS_PER_COHORT`
   (25) and `PSAT_SCAN_MAX_WINDOWS_PER_PASS` (50). Budget-exhausted passes re-run after
   `PSAT_SCAN_BUSY_INTERVAL_S` (5s) instead of the 600s interval.
4. **Per window** `[cursor+1, cursor+2000]` clamped to `head − CONFIRMATION_DEPTH` (12;
   today the scanner reads raw head with no reorg story — new, and required so that
   `monitored_events`, which must never be reorg-rewound, only ingests confirmed logs):
   - one `eth_getLogs` with the cohort's addresses + the topics union (registry ∪
     per-contract tracked topic0s as today `:157`; per-pass `SELECT DISTINCT` over
     `monitoring_config->'tracked_topics'` replaces the up-front full-row walk);
   - **on provider rejection** (range/response caps): halve the block window and retry
     before failing the cohort's turn — reuse `RpcEventLogFetcher`'s bisect-on-reject
     (`services/resolution/repos/event_logs_rpc.py`) extended to accept an address
     list, so both scanning systems share one getLogs implementation
     [adopted from Design B §2.3];
   - hydrate only emitting MC rows; run the existing decode/side-effect pipeline
     unchanged (`parse_any_log`/`parse_tracked_log`, `_should_watch`,
     `_update_state_from_event`, `_sync_relational_tables`, `maybe_queue_reanalysis`,
     `unified_watcher.py:223-329`);
   - insert events with `ON CONFLICT DO NOTHING ... RETURNING id`, and **gate every
     side effect (state update, relational sync, reanalysis enqueue, notify) on the
     insert having won** [B's RETURNING idea, extended: A gated nothing, B gated only
     notify — an insert-lost duplicate must not double-queue reanalysis jobs or
     double-post Discord];
   - advance cohort cursors with one bulk
     `UPDATE monitored_contracts SET last_scanned_block = GREATEST(last_scanned_block, :window_end) WHERE id = ANY(:ids)`
     — monotonic; a zombie/lagging writer can only no-op, never rewind;
   - `session.commit()` per window; `notify_protocol_events` (`notifier.py:433`) per
     window so a long catch-up doesn't buffer thousands of notifications.
5. **Behind ≠ skipped invariant** (kept, now testable): the cursor advances only in the
   transaction that persisted that window's events; a failed getLogs ends the cohort's
   turn without advancing (today's `partial` break `:207-218`, now per-cohort). Lag is
   always the measurable `head − cursor`.
6. **Heartbeat detail** gains `max_lag_blocks`, `windows_scanned`, `cohorts`,
   `budget_exhausted` — "behind" becomes a first-class alertable number distinct from
   "dead".
7. Delete `_boot_reconcile` + both call sites; delete the pass-wide `db_events` preload
   (replaced by the unique index in stage 4; until then, one bounded per-window
   existence query preserves the overlap-after-failure dedupe).

Multi-chain: cohort key includes `chain`; per-chain `{chain: rpc}` map (shape of the
indexer's `fetchers` dict, `event_log_indexer.py:878-880`). Ships ethereum-only; adding
a chain is config. The `chain: str` vs indexer `chain_id: int` wart is a flagged
reconcile-later item.

### 2.2 Poller — same file, driver-only change

Keep `_rpc_call_for_entry` / `decode_poll_value` / suppression /
`_sync_relational_from_poll` verbatim. New driver: `monitored_contracts.last_polled_at`
(nullable), select `PSAT_POLL_CONTRACTS_PER_PASS` (500) active `needs_polling` rows
ordered `last_polled_at ASC NULLS FIRST`, chunk batches at 500 calls, decode + sync +
stamp + **commit per chunk**. A failed batch leaves the chunk's `last_polled_at`
unstamped so those contracts retry first next pass [B §2.4's retry-first detail].
Poll passes run **only under the daemon lease** — this is load-bearing, not
belt-and-braces (see 2.4: poll events are outside the unique index).

### 2.3 Enrollment — dirty-flag queue + slow sweep (Design A, with the claim fixed)

**New table** `monitoring_enrollment_queue`:

```
protocol_id   int PK, FK protocols.id ON DELETE CASCADE
dirty_at      timestamptz not null default now()
reason        varchar(64)   -- policy_complete | discovery_adoption | audit_added
                            -- | governance_rotation | manual | sweep
attempts      int not null default 0
lease_id      uuid null                 -- claim stamp (fix over Design A)
lease_expires_at timestamptz null
```

**Claim protocol (corrected):** Design A said "SELECT … FOR UPDATE SKIP LOCKED LIMIT 4
— the exact pattern `db/queue.py:claim_job` uses", but as written it would hold row
locks open across minutes-long governance builds (idle-in-transaction hazard on
Neon/pgbouncer) or lose exclusivity after commit. `claim_job` actually **stamps a lease
and commits** (`db/queue.py:544-559`). Do the same: SKIP-LOCKED select, stamp
`lease_id` + `lease_expires_at = now() + ttl` (TTL ≥ worst single-protocol build;
provisionally 15 min, measured on etherfi), commit, then run
`enroll_protocol_contracts(pid, enroll_controllers=True)` in a fresh session per
protocol. On success: `DELETE … WHERE protocol_id=:pid AND dirty_at=:claimed_dirty_at
AND lease_id=:mine` — the `dirty_at` guard keeps a concurrent re-dirty alive. On
failure: `attempts += 1`, clear lease, exponential `dirty_at` push-out so a poisoned
protocol can't wedge the queue.

**`mark_enrollment_dirty(session, protocol_id, reason)`** — one upsert. Call sites:
- `workers/policy_worker.py:~630` after `maybe_enroll_protocol` (which stays
  `enroll_controllers=False`, `enrollment.py:81` — the fast contract-row path).
- `workers/discovery.py:~526-551` — both adoption branches (structural + deployer-cascade).
- `routers/audits.py` audit-create; `routers/protocols.py:53` `/re-enroll` (stays
  synchronous as the urgent escape hatch, also marks dirty so a failed run self-heals).
- **`_sync_relational_tables` / `_sync_relational_from_poll`** when a controller-
  relevant value changes (owner/admin/authority writes, reason
  `governance_rotation`) — **new vs both designs**: an on-chain owner rotation updates
  only `ControllerValue` rows (`unified_watcher.py:785-819`), which neither Design B's
  jobs/contracts fingerprint nor Design A's four marks would see; without this, a
  newly-installed governance Safe goes unmonitored until the sweep (A: ~4.2h) or the
  snapshot max-age (B: 24h). With it: one drain tick.

**Slow sweep backstop:** `protocols.last_enrollment_reconcile_at`; each tick enqueues
the `PSAT_RECONCILE_SWEEP_K` (2) least-recently-reconciled protocols (reason `sweep`).
Any drift from an *unknown* write site (psql fix-ups) converges within ≤ 50/2 × 600s ≈
**4.2h** at a fixed 2-views-per-tick cost — vs 50 per tick today.

`enroll_protocol_contracts` internals unchanged (idempotent upserts, promote/demote,
stale deactivation — `enrollment.py:85-323,578-695`). **No controller snapshot table**:
persisting `controllers_for_protocol` output (Design B) forks the source of truth the
enrollment docstring exists to unify (`enrollment.py:588-596`) and inherits a
fingerprint-completeness hole; the dirty queue reaches O(changed) without the fork.

### 2.4 Singleton correctness by construction — two layers, honestly scoped

**Layer 1 — `daemon_leases` row lease** (required for full correctness):

```
name varchar(64) PK   -- 'protocol_scanner:ethereum', 'protocol_poller:ethereum'
holder uuid not null
expires_at timestamptz not null
```

`db/queue.py::try_acquire_daemon_lease` — `INSERT … ON CONFLICT (name) DO UPDATE …
WHERE expires_at < now() OR holder = excluded.holder`, reporting win/lose. Acquired at
pass start, renewed each window/chunk commit (TTL 120s ≥ 3× worst window, and ≥ the RPC
client timeout so a stalled getLogs rarely outlives it). A row lease, not a pg advisory
lock: session-scoped advisory locks break under Neon/pgbouncer transaction pooling and
don't survive per-window commits.

**Layer 2 — idempotent writes** (makes lease bugs harmless **on the scan path**):
- `monitored_events.log_index int NULL` + **partial** unique index
  `uq_monitored_events_identity (monitored_contract_id, tx_hash, log_index, event_type)
  WHERE log_index IS NOT NULL`; scan inserts populate `log_index` and use
  `ON CONFLICT DO NOTHING RETURNING id`; side effects gated on the win.
  The index is deliberately **partial**: poll-path `state_changed_poll` rows carry
  `tx_hash=""`/`block_number=0` and stay `log_index NULL`, outside the constraint —
  Design B's full `UNIQUE(mc, tx, block, type, log_index)` with `server_default 0`
  would make the **second legitimate poll detection on a contract collide** and be
  silently dropped. Historical rows (zero in prod) also stay outside; no backfill.
- Cursor updates are `GREATEST(...)` — no rewinds ever.
- **Stated honestly (Design A overclaimed "either layer alone")**: Layer 2 does *not*
  cover the poller (its events are outside the index by design) and cannot cover
  non-insert side effects on its own — the lease is load-bearing for the poll path and
  for at-most-once notifications. Tests assert both layers independently.

This converts `DO NOT scale above 1` (`fly.toml:38`, `start_monitor.sh:9-11`) from an
operator convention into schema + lease properties; scaling the group becomes wasteful,
not corrupting.

### 2.5 Process model — one interpreter, supervised threads

`workers/protocol_monitor.py` default mode: scanner/poller/TVL as three daemon threads
under a small Supervisor — catches any escape, records
`record_heartbeat(name, status="error", detail={exc_type})`, restarts the thread with
exponential backoff (5s → 300s cap). `--poll/--tvl/--reconcile` flags remain (rollback
lever + the workers-group reconciler entrypoint). `start_monitor.sh` becomes one
`exec uv run --no-sync python -m workers.protocol_monitor` — no `PIDS`, no `wait -n`.
`start_workers.sh` adds the reconciler drainer next to the other drainers. `fly.toml`:

```toml
[[restart]]
  policy = "always"
  processes = ["monitor"]
```

so a crash-loop degrades (and pages) but never permanently stops. Threads are RPC/DB-
bound (GIL irrelevant); the indexer already runs a backfill thread beside its reconcile
loop (`event_log_indexer.py:780-801`) — house pattern. Per-thread RPC/DB sessions only
(`requests.Session` thread-reuse is a documented repo gotcha).

### 2.6 Alerting — a consumer for worker_heartbeats + external check surface

New `services/monitoring/ops_alerts.py`, started from the web app lifespan
(`api.py:47-79`; web is the only group fly health-checks + auto-starts,
`fly.toml:46-66`):
- Every 120s: read `worker_heartbeats` + `PROCESS_META` freshness rules (shared module
  so watchdog and fleet view can't drift [B]); classify fresh/stale/error.
- On transition: one `logger.error("ops: daemon %s is down")` with structured extras
  (→ Grafana Loki alert rule as belt-and-braces) + one Discord post to
  `PSAT_OPS_WEBHOOK_URL` (reuse `_send_discord`, `notifier.py:51`); recovery post on
  return. Dedupe/cooldown state CAS-persisted in an `ops_alerter` heartbeat row
  (doubles as the alerter's own heartbeat) so multiple web machines rarely double-post [B].
- **`GET /api/health/monitoring`** (unauthenticated, like `/api/health`): 200/503 with
  the stale list — pointable from any external uptime checker, closing the
  "web up, monitoring dead" blind spot [adopted from B §2.7; A's plain `/api/health`
  ping only proves web is alive].
- `PROCESS_META` gains `protocol_scanner`/`protocol_poller`/`protocol_tvl`/
  `enrollment reconciler drainer`/`ops_alerter`; scanner also alerts on
  `max_lag_blocks > PSAT_SCAN_LAG_ALERT` (50,000 ≈ 7 days) — "behind" alarm distinct
  from "dead".

### 2.7 TVL — `services/monitoring/tvl.py`

`refresh_all_protocols` → oldest-snapshot-first, ≤`PSAT_TVL_PROTOCOLS_PER_PASS` (10)
per hourly tick; `MIN_SNAPSHOT_INTERVAL` dedupe (`tvl.py:275-291`) unchanged. Real
bound is the Etherscan rate limit, not memory.

### 2.8 File-level change list

| File | Change |
| --- | --- |
| `services/monitoring/unified_watcher.py` | scan rewrite (cohorts/budget/per-window commit/columns-only/confirmation depth/GREATEST/ON CONFLICT RETURNING-gated side effects); poller rotation+chunking under lease; delete `_boot_reconcile` + `db_events` preload; busy-interval; lag metric; dirty-mark on governance-rotation sync |
| `services/monitoring/reconciler.py` | dirty-queue drain (SKIP LOCKED + lease stamp + commit, fresh session/protocol, dirty_at-guarded delete, attempts backoff) + K-sweep enqueue |
| `services/monitoring/enrollment.py` | add `mark_enrollment_dirty`; `enroll_protocol_contracts` unchanged |
| `services/monitoring/tvl.py` | per-pass cap + oldest-first rotation |
| `services/monitoring/ops_alerts.py` | **new** — watchdog + Discord + shared PROCESS_META |
| `routers/health.py` (or api.py) | **new** `GET /api/health/monitoring` |
| `workers/protocol_monitor.py` | supervised 3-thread default mode; keep flags |
| `workers/policy_worker.py`, `workers/discovery.py`, `routers/audits.py`, `routers/protocols.py` | +1–2 lines each: `mark_enrollment_dirty` |
| `services/resolution/repos/event_logs_rpc.py` | `fetch_logs` accepts address list (shared bisect-on-reject) |
| `db/models.py` + migrations | `monitoring_enrollment_queue` (+lease cols); `daemon_leases`; `monitored_contracts.last_polled_at`; `monitored_contracts.last_scanned_block → BigInteger` [B §2.3.6 — aligns with `IndexedEventCursor`]; `monitored_events.log_index` + partial unique index; `protocols.last_enrollment_reconcile_at` |
| `db/queue.py` | `try_acquire_daemon_lease`/renew; promote `HEARTBEAT_PROTOCOL_*` constants (closing `services/monitoring/__init__.py:9-13` blocker) |
| `services/aggregations/fleet.py` | PROCESS_META → shared module + new entries; surface `max_lag_blocks` |
| `start_monitor.sh` | single exec line |
| `start_workers.sh` | + reconciler drainer |
| `fly.toml` | `[[restart]] policy="always"` (monitor); interim `PSAT_ENROLLMENT_RECONCILE_INTERVAL=3600` (stage 1, removed stage 5) |

**Not deleted:** `services/monitoring/proxy_watcher.py` — Design B marked it "legacy,
delete", but `workers/static_worker.py:36` imports `resolve_current_implementation`
from it; deleting it breaks the static pipeline stage. Only the `--legacy` runner path
may be pruned, separately, after moving that helper.

---

## 3. Hard-requirements checklist

**HR1 — Enrollment convergence.** Fast path unchanged (`maybe_enroll_protocol`,
`enroll_controllers=False`). Controllers land via the dirty-queue drain (full
`enroll_controllers=True`, unchanged code) within one drain tick of: policy completion,
discovery adoption, audit create, manual re-enroll, **and monitoring-detected
governance rotations** (the gap both original designs left). The K-sweep bounds
staleness from unknown write sites to ~4.2h at 50 protocols. Always computes fresh via
`controllers_for_protocol` — no persisted-snapshot fork, no fingerprint blind spots.

**HR2 — Singleton by construction.** `daemon_leases` gates every scan/poll pass
(pool-safe, TTL, holder-reentrant); independently on the scan path, the partial unique
index + `ON CONFLICT ... RETURNING`-gated side effects + `GREATEST` cursors make even a
lease failure produce zero duplicate rows, zero duplicate side effects, zero rewinds.
Poll path correctness rests on the lease (documented, tested). Scaling the monitor
group becomes safe-wasteful, not corrupting.

**HR3 — Failure isolation + observability.** Thread supervisor: one loop's death never
touches siblings, never the machine. `[[restart]] policy="always"`: no retry budget to
exhaust — degrade, never permanently stop. Detection: web-hosted watchdog (fly-
health-checked group) consumes heartbeats every 120s → Discord + ERROR log → Grafana
rule; `/api/health/monitoring` 503 for external uptime checkers. Reconciler failures
are per-protocol-swallowed + attempts-backed-off; its process death on the workers box
is covered by the same watchdog.

**HR4 — Bounded catch-up; behind ≠ skipped.** 2,000-block windows, 50-window pass
budget, per-window commits, O(batch) memory, 5s busy-interval drains backlogs at RPC
speed; cursor advances only in the transaction that persisted the window; confirmation
depth 12 kills reorg phantoms. Lag exported (`max_lag_blocks`) and alerted on its own
threshold. Acceptance: the live 250k-block gap = 125 windows ≈ 3 passes, < 1h, flat RAM.

**HR5 — Migration-safe, incremental, no new infra.** Six PR-sized stages (§4), each
leaving prod working, each revertible; all migrations additive (2 tables + 3 columns +
1 index + 1 type widen); zero new services — queue/lease are Postgres rows, alerter
lives in the existing web process, webhook is the existing Discord path.

**HR6 — Repo norms.** All new tests offline (`pytest -m "not live"`), stubbing only the
wire (`rpc_request`/`rpc_batch_request`/`fetch_logs`) over the real stack + real test
DB (per `feedback_integration_tests`); per-stage test lists keep diff-cover ≥70%; live
suite extends fleet checks to the new heartbeats + `/api/health/monitoring`.

---

## 4. Phased rollout (from a stopped fleet, 36-day-old cursors)

### Stage 1 — un-wedge: bounded scan + heavy compute off the 512MB box
*The PR that makes restarting the dead machine safe. Order matters: the machine must
NOT be started before this deploys — boot reconcile is the deterministic OOM.*
- `start_monitor.sh`: remove the `--reconcile` line; `start_workers.sh`: add it
  (reconciler behavior unchanged, now on 16GB; documented converge-safe as co-process,
  `reconciler.py:36-43`).
- Delete `_boot_reconcile` + both call sites. Rewrite `scan_for_events` per §2.1
  (cohorts, budgets, per-window commit + per-window bounded dedupe query, columns-only
  load, GREATEST, confirmation depth, busy-interval, lag metric).
- `fly.toml`: `[[restart]] policy="always"` for monitor; interim
  `PSAT_ENROLLMENT_RECONCILE_INTERVAL=3600` (full sweeps still exist until stage 5; cut
  6× while on the big box).
- **Ops runbook in PR description:** after deploy, `fly machine start <monitor-id>`
  (deploys do not start stopped machines). Watch `/api/fleet`: `max_lag_blocks` steps
  down per pass, ~0 within the hour; `monitored_events` receives its first prod rows.
- Tests: `test_unified_watcher_budget.py` — cohort split, budget stop, mid-pass durable
  commits, cursor-never-passes-failed-window, 36-day-gap convergence simulation, lag
  metric; rework `test_watcher_unit.py` assumptions; anvil variant for catch-up.

### Stage 2 — alerting (watchdog + health endpoint)
*Second because silence was the costliest failure.*
- `ops_alerts.py`, web lifespan wiring, `PSAT_OPS_WEBHOOK_URL`, shared PROCESS_META
  (+ scanner/poller/tvl entries), `GET /api/health/monitoring`, Grafana Loki rule;
  point an external uptime checker at the endpoint (one-liner in any monitoring SaaS).
- Tests: transition/dedupe/recovery/cooldown, webhook payload (wire-stubbed), 503
  semantics, stale classification on synthetic heartbeat rows.

### Stage 3 — poller + TVL bounding
*Pulled forward from Design A's stage 6: the unbounded 30k-call poll batch is the next
O(total) pass and must land before enrolling more protocols, not last.*
- Migration: `monitored_contracts.last_polled_at`. Poller rotation + chunked commits;
  TVL per-pass cap + rotation.
- Tests: rotation order incl. NULLS FIRST, chunk boundaries, per-chunk commit, failed-
  batch retry-first, suppression across chunks; TVL rotation.

### Stage 4 — singleton lease + event identity
- Migration: `daemon_leases`; `monitored_events.log_index` + partial unique index;
  `last_scanned_block → BigInteger`.
- `try_acquire_daemon_lease` + scanner/poller acquire/renew/skip; scan inserts →
  `ON CONFLICT DO NOTHING RETURNING` with side effects gated on the win; delete the
  per-window dedupe query; drop the "DO NOT scale above 1" comments.
- Tests: lease contention/TTL-steal/holder-reacquire; duplicate-pass property test
  (two concurrent scan passes over the same stubbed logs ⇒ row count, reanalysis-job
  count, and notify count identical to one pass — real Postgres); poll-path duplicate
  events under deliberately-broken lease documented as the known non-guarantee.

### Stage 5 — dirty-queue enrollment
- Migration: `monitoring_enrollment_queue` (+ lease cols) +
  `protocols.last_enrollment_reconcile_at`.
- `mark_enrollment_dirty` + five call sites (incl. governance-rotation sync); drainer
  claim/lease/delete/backoff + K-sweep; drop interim 3600s env (tick can fall to 60s
  now that a tick is O(dirty)).
- Tests: mark→drain→controllers-enrolled e2e (real `enroll_protocol_contracts`, seeded
  DB, stubbed rpc); concurrent-drain exclusivity incl. lease expiry mid-build;
  dirty_at-guarded delete keeps re-dirtied rows; governance-rotation mark fires from
  the watcher sync path; sweep ordering; poisoned-protocol backoff.

### Stage 6 — single-process collapse
- Supervisor default mode; `start_monitor.sh` one-liner; monitor VM stays 512MB
  (~195MB freed headroom).
- Tests: raising loop body restarts with backoff, siblings unaffected, error heartbeat,
  SIGTERM joins all threads.

Dependencies: 2/3/4 are order-independent after 1; 5 needs nothing from 3/4; 6 depends
on 1. Every stage deploys green on `pytest -m "not live"` + live suite.

---

## 5. Non-goals

- **No merge with the event_log_indexer** (both designers converged; B's math is the
  proof and is verified): indexer cursors are per-(address,topic0), born misaligned at
  creation blocks (`event_log_indexer.py:489+`), fetched one address-group per getLogs
  (`:290-295`), all cursor rows loaded per pass (`:363-370`); monitoring cursors are
  born at head and advance in lockstep, so a multi-address filter serves thousands of
  contracts per request. At 10k contracts, per-address tailing ≈ 10k getLogs/pass on a
  flat-1000-credit/request lane (`:37-42`) vs ~10; plus ~250k cursor rows of bloat.
  What is shared: the fetcher (bisect/provider quirks) and the pass discipline.
- **No merge of `monitored_events` into `indexed_event_logs`**: raw/append-only/
  reorg-rewindable (`:243-267` DELETEs on rewind) vs decoded/semantic/side-effectful —
  a reorg rewind must never silently delete a Discord-notified governance event.
- **No jobs-pipeline hosting of cadence** (B's own argument, accepted): jobs model
  finite work; wedging infinite cadence into `JobStage` pollutes retry semantics and
  run-history UIs.
- **No persisted controller snapshot / no fingerprint gate** (B's central mechanism,
  rejected — Appendix A).
- **No `periodic_tasks` runner framework** (rejected — Appendix A).
- **No changes to `enroll_protocol_contracts` internals, the decode/sync/reanalysis
  pipeline, `notifier.py`, `event_topics.py`, `polling_plan.py`** — cadence and
  placement were the bug, not the computation.
- **No redis/kafka/celery/cron**; Postgres rows + SKIP LOCKED + existing fly groups.

## 6. Risks & open questions

1. **Provider caps on multi-address getLogs** (both designs flagged): start at 200
   addresses, bisect the block window on rejection via the shared fetcher; confirm the
   prod lane's exact caps during stage-1 rollout (the acceptance run is the probe).
2. **Reconciler on the workers box**: (a) competes with pipeline bursts — acceptable,
   serialized, memory-bounded to one view; (b) inherits `start_workers.sh`'s `wait -n`
   shared fate — its loop swallows exceptions so only process death (OOM/segfault)
   triggers it; watchdog pages either way. If `build_governance_view` outgrows ~1GB per
   protocol at 10× scale, persist/incrementalize the view — successor project.
3. **Lease TTL vs slow windows/builds**: scan/poll covered by Layer 2 on overlap; the
   reconciler's TTL must exceed the worst single-protocol build (measure on etherfi;
   15 min provisional). A too-short TTL double-*computes* but cannot double-*corrupt*
   (enroll is idempotent).
4. **Dirty-mark completeness**: direct SQL fix-ups bypass marks by definition; the
   4.2h sweep is the bound; manual `/re-enroll` remains for urgency. Runbooks for psql
   fix-ups should end with a re-enroll call.
5. **Web+monitor simultaneous death** (regional outage): Discord path dies with web;
   Grafana Loki rule + the external uptime check on `/api/health/monitoring` are the
   two independent backstops.
6. **Multi-chain**: cursors/cohorts/leases chain-keyed from stage 1, but per-chain RPC
   config, confirmation depths, poll-suppression tuning for fast chains, and the
   `chain: str` vs `chain_id: int` normalization are unvalidated beyond ethereum.
7. **Poll-event duplicate window without the lease**: accepted and documented (the
   partial index deliberately excludes poll events); if it ever bites, a per-
   (mc, field, day) synthetic identity could extend the index — deferred.

---

## Appendix A — adopted / rejected, with reasons

**From Design A (base):** dedicated small monitor VM + supervised threads; dirty-queue
enrollment (always-fresh compute, no source-of-truth fork); partial unique index
(correct shape — B's full constraint breaks the poll path); columns-only scan load;
per-window commit/budget/rotation/confirmation/busy-interval; web-hosted watchdog;
K-sweep backstop; restart policy `always`.

**Fixed in A:** (1) HR2 overclaim — Layer 2 never covered the poller or side effects;
side effects now RETURNING-gated and the lease documented as load-bearing. (2) Dirty-
queue claim underspecified — now lease-stamped + committed like `claim_job`
(`db/queue.py:544-559`), no locks held across governance builds. (3) Poller bounding
moved from last stage to stage 3 (it is the next O(total) pass). (4) Governance-
rotation dirty-mark added (watcher sync path). (5) `last_scanned_block` BigInteger
widen added. (6) `wait -n` shared-fate of the drainer acknowledged + watchdog-covered.

**Adopted from Design B:** `/api/health/monitoring` 503 endpoint for external checkers;
RETURNING-id gating of duplicate-insert consequences (extended beyond notify); shared
`RpcEventLogFetcher` with address-list support; shared PROCESS_META module; alert-
cooldown CAS; BigInteger alignment; the indexer-merge rejection analysis (§5).

**Rejected from Design B:**
- *Stage 1 as written* — it keeps reconcile on the 512MB VM, and the fingerprint gate
  makes every protocol "dirty" on the first tick (no snapshot rows exist), so the first
  600s tick re-runs `build_governance_view` per protocol on the incident's exact
  machine; an OOM mid-build never commits the snapshot ⇒ the deterministic crash loop
  returns. "Stage 1 alone un-wedges the outage" is false by B's own memory ledger.
- *`protocol_controller_snapshots` + fingerprint* — the fingerprint
  (jobs/contracts counts + updated_at) is blind to ControllerValue-only changes the
  watcher itself writes (owner rotations touch neither table,
  `unified_watcher.py:785-819`), leaving a new governance Safe unmonitored for up to
  the 24h max-age; and the snapshot forks the Monitoring↔Surface source of truth
  (`enrollment.py:588-596`). The dirty queue achieves O(changed) without either hole.
- *Full unique constraint with `log_index` default 0* — collides on the second
  legitimate `state_changed_poll` detection per contract (tx_hash=""/block=0), silently
  dropping real detections under `ON CONFLICT DO NOTHING`.
- *Hosting all monitoring on the workers fleet + deleting the monitor group* —
  `start_workers.sh`'s `wait -n` couples monitoring's survival to ~13 pipeline
  processes on the busiest machine; at N=1 it recreates the retry-exhaustion failure
  mode with pipeline+monitoring in one blast radius.
- *Deleting `proxy_watcher.py`* — `workers/static_worker.py:36` imports
  `resolve_current_implementation` from it; not legacy-only.
- *`periodic_tasks` runner framework* — three tables' worth of scheduling machinery to
  host four loops; the supervisor + `daemon_leases` + busy-interval reach the same
  correctness with fewer moving parts and no new vocabulary. Revisit if the number of
  periodic daemons grows.
