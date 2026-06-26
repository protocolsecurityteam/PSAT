# PSAT Caching — Implementation Plan

Companion to **`CACHING_AUDIT.md`** (that doc has the full evidence/inventory; this doc
is the actionable plan). This is the authoritative spec for the caching fix work.

**How to use this doc (esp. for implementing agents):** §A records decisions already
made and investigations already closed this session. **Do not re-investigate or re-open
anything in §A** — in particular #6 (CGN reconcile) is a confirmed *non-issue*; do not
"fix" it. Implement §C against the invariant in §B. Verify against §D.

---

## §A. Settled decisions & non-issues — READ FIRST, do not re-investigate

These were decided/verified against the live code this session. Treat as fixed inputs.

| # | Topic | Decision | Why (so it's not re-litigated) |
|---|---|---|---|
| 1 | `getsourcecode` in-mem | **psql-only** (NO in-mem copy). Small bounded LRU only for the *small* `getabi` + `getcontractcreation`. | Source is already durable + whitelisted in PG `etherscan_cache`; the multi-MB blobs are the #1 OOM lever. `contract_materializations` proves source-derived data serves fine PG/blob-only. |
| 2 | tx history (`txlist`) in-mem | **Do not cache in-mem.** | Volatile-class; policy says short/medium TTL, simplest correct = don't cache in-mem. PG already excludes it. |
| 3 | `_LOG_CACHE` | **Bound (maxsize) + short/medium TTL. DO NOT DELETE.** | It *is* used: key `(chain_id, authority, topic0)` dedups across every contract sharing an authority (e.g. one timelock → 20 contracts). And `_fetch_logs` (`principal_history.py:529`) uses a **raw `requests.get` that bypasses the global rate limiter**, so deleting would amplify un-rate-limited full-history `getLogs`. Your own policy (logs → short/medium TTL) makes bound+TTL the consistent fix; delete is stricter *and* costlier. |
| 4 | `_CLASSIFY_CACHE` staleness | **Split TTL:** keep long TTL (1800s) for the immutable type; short TTL (or block-pin) for entries whose `details` carry mutable Safe `owners`/`threshold` or timelock `delay`/`min_delay`. | Feasible: cached tuple is `(type, details, ts)` (`tracking.py:39`); `details` holds those exact keys. Security-relevant (stale Safe owner-sets). |
| 5 | `contract_materializations` staleness | **Add a manually-bumped `ANALYSIS_SCHEMA_VERSION` constant.** NOT a git-SHA tie. | A git-SHA tie cold-rebuilds every 5–20 MB forge+Slither bundle on unrelated deploys (frontend/docs/workers). Only changes to analysis/tracking_plan/predicate output should invalidate. |
| **6** | **CGN ↔ FunctionPrincipal divergence** | **NON-ISSUE. Do nothing. Do NOT add a new trigger.** | **Verified this session.** `reconcile_control_graph_types` (`control_graph_types.py:98`, added PR #98; wired PR #100 "enrollment correctness + reconciler") **already runs after every policy completion**: `policy_worker.py:622` → `maybe_enroll_protocol` (docstring: *"fires from PolicyWorker.process() immediately after a job completes"*) → `enroll_protocol_contracts` → `reconcile` at `enrollment.py:148` (runs regardless of the `enroll_controllers` flag). Plus a backstop reconciler (`services/monitoring/reconciler.py`). The audit flagged the data-model divergence without tracing this wiring. The `maybe_enroll` docstring even shows they already removed a gate that caused "silent skips". |

**Other "do not touch" items (already correct):**
- Already size-capped caches: `_GETCODE_CACHE` (rpc.py, the reference model), `_CLASSIFY_CACHE` *bound* (only its TTL logic changes, per #4), `_PROBE_CACHE`, `_ONE_SHOT_CACHE` (capability_resolver, 4096+trim, block-pinned). Leave their caps.
- exa/tavily blob caches — justified (distinct providers), off by default in prod. No change.
- The PG/blob durable layers (`etherscan_cache`, `bytecode_cache`, `mapping_enumeration_cache`, `contract_materializations`, indexed logs) are policy-compliant and correctly keyed. No change except #5.

---

## §B. Guiding invariant + reference pattern

**Invariant (the whole point — prevents OOM across repeated runs):**
> Every **process-global** in-memory cache has a **size cap with active eviction**.
> Everything else is **request/job-scoped** (created in-call, GC'd on return) or lives in
> **psql/blob**. A TTL is for *staleness*, **not** memory — it never substitutes for a cap.

Rationale: lazy TTL only frees an entry when that exact key is re-read; never-re-hit keys
sit forever. So **"bound it" always means add `maxsize` + eviction**, with a TTL *on top*
only where freshness matters.

**Reference pattern — copy `_GETCODE_CACHE` (`utils/rpc.py:45-48, 515-521`) / `_CLASSIFY_CACHE`
(`services/resolution/tracking.py:39-42, 232-242`).** Every new/fixed process-global cache must have:
1. a module constant `…_MAX` (sized to the value: **small for multi-MB blobs**, ~4096 for tiny values);
2. eviction when `len >= MAX` (drop oldest fraction — both reference caches do this);
3. a TTL only if the datum is mutable (store `(value, monotonic_ts)`; treat `age > ttl` as miss);
4. registration with `utils.memory.cache_pressure_message(name, len, MAX)` → log `[CACHE_PRESSURE]` on 50/75/95%;
5. a `clear_*()` helper that clears the dict **and** calls `reset_cache_pressure_state(name)` (for tests/manual reset);
6. thread safety (`threading.Lock`) — these run in multi-threaded workers.

**Comment style:** comments state the *current* invariant only (size cap / TTL / key), never the
historical bug. Match surrounding density; don't narrate the obvious.

---

## §C. Work items

File:line anchors are current as of this session; re-grep before editing.

### P0 — correctness + the #1/#2 OOM levers (ship first)

**P0.1 — Whitelist-gate the in-mem `_cache` (`utils/etherscan.py`).**
The in-mem read (`get()` ~`:173-178`) and both writes (PG-hit backfill ~`:184-185`; wire-result
write ~`:208-210`) currently fire for **every** action. Gate them so volatile data never enters
process memory. Introduce a **separate, narrower** in-mem whitelist (distinct from `_PG_CACHE_WHITELIST`):
- `_INMEM_CACHE_WHITELIST = {("contract","getabi"), ("contract","getcontractcreation")}` — **not** `getsourcecode` (decision #1: psql-only).
- Wrap the in-mem read+writes in `if _inmem_cache_eligible(module, action):`.
- **Done when:** balances/prices (`stats/ethprice`, `account/balance`, `account/addresstokenbalance`), `txlist`, and `getsourcecode` never enter `_cache`; this also auto-fixes the empty-unverified-source poisoning (source reads now go through PG's `_is_persistable`).

**P0.2 — Bound the in-mem `_cache` (`utils/etherscan.py:73`).**
Replace the plain `dict` with the §B reference LRU for the `getabi`/`getcontractcreation` entries it
now holds: **small** `_MAX` (these are small responses, e.g. 256), eviction, `cache_pressure` name
`"etherscan"`, and a `clear_*` helper. `getsourcecode` is psql-only (served by `_pg_cache_get`/`_pg_cache_put`).
- **Done when:** `_cache` cannot grow without bound; `getsourcecode` is never held in `_cache`; closes the **#1 OOM lever**.

**P0.3 — `_LOG_CACHE` bound + short TTL (`services/policy/principal_history.py:24`).**
(Decision #3 — **bound, do not delete.**) Apply the §B pattern: `maxsize` + eviction + short/medium TTL
+ `cache_pressure` name `"principal_log"`. Read `:520`, write `:557`.
- **Done when:** the dict is size-capped and entries expire; role grants after first fetch are eventually seen; closes the **#2 OOM lever**.

### P1 — bounded leaks + real divergence

**P1.1 — Delete `_ABI_CACHE` (`services/policy/principal_history.py:23`).** Redundant 3rd ABI layer:
`_fetch_abi` already calls `utils.etherscan.get("contract","getabi")`, which is PG-whitelisted and (after
P0.2) in-mem-LRU'd. Remove the dict + its get/set (`:507`, `:514`); call `get()` directly. Update
`tests/test_principal_history.py:216,219` (drop the `_ABI_CACHE.clear()` lines).

**P1.2 — `source_equivalence` memoize hash, not full text (`services/audits/source_equivalence.py:402`).**
Change the `lru_cache(4096)` target to return `(status, detail, sha256)` rather than `GithubFetch(content=r.text)`.
Callers use only the hash (`:543`) / null-check (`:559`). ~1000× per-entry shrink; kills the ~20 GB worst case.

**P1.3 — mapping-enum L1 re-key + bound (`services/resolution/mapping_enumerator.py:78` `_CACHE`, `:698` `_VALUE_CACHE`).**
Re-key **both** on `(chain, address, specs_hash)` to match L2 (`db/mapping_enumeration_cache.py`) — fixes the
active L1-defeats-L2 cross-chain/cross-specs collision. Add `maxsize` + eviction (the lazy-TTL `del` at `:484`/`:736`
is not a size bound). Optional: make L1 a thin read-through of L2.

**P1.4 — Bound remaining unbounded resolution dicts.**
- `external_check_materializer.py:31 _CANDIDATE_CACHE` — add `maxsize` on **entry count** (the existing `_MAX_CANDIDATES=512` caps each *value list's* length, **not** the number of entries).
- `creation_block_floor.py:38 _FLOOR_CACHE` — add `maxsize`; **and stop caching `None` permanently** (`:114-115`) so a backfilled creation block is picked up.

**P1.5 — Instance-scope `_EXPRESSION_TEXT_CACHE` (`services/static/contract_analysis_pipeline/revert_detect.py:128`).**
Make it an attribute on `RevertDetector` (mirror `_container_reads` at `:216`). Fixes the unbounded growth **and**
the `id()`-reuse hazard (it currently outlives the Slither instance whose object ids it keys on).

**P1.6 — Fix/eliminate `audit-timeline-bytecode-keccak-cache` (`services/aggregations/contract_audit_timeline.py:21`).**
Eliminate the 3rd keccak cache: read `code_keccak` from the existing PG `bytecode_cache` layer. If an in-mem layer
is kept, add `chain_id` to the key + a size cap. Correct the fictional "30s freshness" comment (`:19-20`).

**P1.7 — `_BRANCH_SHA_CACHE` (`services/discovery/audit_reports/_github.py:114`).** Add a short TTL (HEAD advances
every push), **don't cache `None`** (let transient GitHub 5xx retry), and add a small `maxsize` (amendment: count
grows per repo over repeated runs, even though values are tiny).

**P1.8 — `_research_cache` bound (`services/discovery/run_discovery.py:80`).** Add `maxsize` + eviction on top of
the existing 24h TTL.

### P2 — staleness windows + structural

**P2.1 — `_CLASSIFY_CACHE` split TTL (`services/resolution/tracking.py:39`).** (Decision #4.) Keep 1800s for the
immutable type; apply a short TTL (or block-pin) to entries whose `details` carry `owners`/`threshold`/`delay`/`min_delay`.
Detect mutable keys in `details` at read time and use a shorter effective TTL for those.

**P2.2 — `contract_materializations` analyzer-version dimension.** (Decision #5.) Add a manually-bumped module
constant `ANALYSIS_SCHEMA_VERSION`. Add an `analysis_schema_version` column to `ContractMaterialization`
(`db/models.py:1066`) and include it in the `find_by_keccak`/`find_by_address`/`materialize_or_wait` WHERE clauses
(`db/contract_materializations.py`) so an old-version row reads as a **miss → rebuild**. **Alembic migration required**
(default existing rows to the current constant). Bump the constant by hand only when analysis/tracking_plan/predicate
output actually changes.

**P2.3 — `_chain_id_cache` (`utils/rpc.py:54`).** Amendment, lowest priority: add a tiny cap, or leave + add a one-line
comment that it's cardinality-bounded (~handful of RPC URLs). Your call.

**P2.4 — `getcode-inmem` rekey (`utils/rpc.py`).** Optional/cosmetic: key on `(chain_id, address)` not `(rpc_url, address)`
to dedup URL aliases. Correctness-safe today (eRPC URLs embed the chain).

**P2.5 — Operational (not code).** Optional retention pruning for the unbounded **disk** stores (`etherscan_cache`,
`mapping_enumeration_cache`, `IndexedEventLog`). Not OOM (disk, not RSS). Defer unless disk pressure shows up.

---

## §D. End-state invariant checklist (all 19 process-global in-mem containers)

After the plan, every process-global cache must land in one of: **capped**, **eliminated**, or **fixed-cardinality**.
Use this to verify completeness.

| Cache (file:line) | Target end-state |
|---|---|
| `etherscan.py:73 _cache` | **capped** small LRU; getabi/creation only (P0.1/P0.2) |
| `rpc.py:45 _GETCODE_CACHE` | already capped (reference) |
| `rpc.py:54 _chain_id_cache` | fixed-cardinality (P2.3 optional cap) |
| `run_discovery.py:80 _research_cache` | **capped** (P1.8) |
| `_github.py:114 _BRANCH_SHA_CACHE` | **capped** + TTL + no-negatives (P1.7) |
| `contract_audit_timeline.py:21 _BYTECODE_KECCAK_CACHE` | **eliminated** → PG (P1.6) |
| `revert_detect.py:128 _EXPRESSION_TEXT_CACHE` | **eliminated** → instance attr (P1.5) |
| `mapping_enumerator.py:78 _CACHE` | **capped** + re-keyed (P1.3) |
| `mapping_enumerator.py:698 _VALUE_CACHE` | **capped** + re-keyed (P1.3) |
| `capability_resolver.py:493 _PROBE_CACHE` | already capped (4096) |
| `capability_resolver.py:625 _ONE_SHOT_CACHE` | already capped (4096) |
| `creation_block_floor.py:38 _FLOOR_CACHE` | **capped** + no-None (P1.4) |
| `external_check_materializer.py:31 _CANDIDATE_CACHE` | **capped on entries** (P1.4) |
| `tracking.py:39 _CLASSIFY_CACHE` | already capped; split TTL (P2.1) |
| `tracking.py:410 _KNOWN_BYTECODE_IMPLS` | fixed (static table) — no change |
| `principal_history.py:23 _ABI_CACHE` | **eliminated** (P1.1) |
| `principal_history.py:24 _LOG_CACHE` | **capped** + TTL (P0.3) |
| `hypersync_bound.py:30 _SEMAPHORES` | fixed-cardinality (per chain) — no change |
| `utils/memory.py:143 _CACHE_PRESSURE_STATE` | fixed (per cache-name) — no change |

All function-local memos (provenance, coverage, per-pass/per-job classify, event-indexer block/seed) are GC'd on
return by construction — not process-global, no action.

---

## §E. Testing & process requirements

- **No commits/PRs without explicit authorization** — implement and report; wait for the go-ahead to commit. No
  `Co-Authored-By: Claude` / "Generated with Claude Code" trailers.
- **Offline suite** (CLAUDE.md): `docker compose up postgres minio minio-init -d` then `./run_tests_fast.sh`
  (or the canonical serial command with `PSAT_LLM_STUB_DIR`). Filter by **marker** (`-m "not live"`), never `-k "not live"`.
  Drop+recreate `psat_test` before a rerun if schema drifts (P2.2 adds a column → migration + reset).
- **Real integration tests for new logic**, driving the production stack — stub only the wire (e.g. `requests`/`rpc_request`),
  not the cache class itself. CI diff-cover gates new lines at **70% vs origin/main** (tests can pass while coverage fails).
- **Each capped cache needs a test** proving: eviction at `MAX`, TTL expiry where applicable, and `clear_*` resets
  pressure state. Mirror existing `tests/cache_helpers.py` / `test_*_pg_cache.py` patterns.
- **Parity where behavior must not change**: P1.3 re-key must not change resolution outputs for single-chain/single-specs
  runs — assert against L2. P0.1 must not drop source/abi/creation cache hits.
- **Frontend:** none of these touch `site/`; no visual-baseline impact.
- **Verify CI on the final state only** if staging commits.

---

*Evidence and per-site reasoning: see `CACHING_AUDIT.md`. Decisions in §A are final for this work — raise with the
user before reopening, don't silently re-investigate.*
