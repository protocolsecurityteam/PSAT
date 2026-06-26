# PSAT Caching Audit

**Scope:** all cache sites across six subsystems (wire I/O, discovery, static analysis, resolution, policy/aggregations, monitoring/indexing/coverage), cross-referenced for redundant caching, volatile-data caching, and unbounded/OOM risk, graded against the stated caching policy.

**Policy under test:**
- source / ABI / creation-code → persist in PostgreSQL (durable); in-memory copy **only** as a **bounded LRU** (the size cap is the OOM fix, meant to bound these source blobs).
- tx history → short/medium TTL.
- balances / prices → **do not cache**.
- Open design choice answered in §6: bounded in-mem LRU for source vs. psql-only.

**Headline verdict:** the durable Postgres layers are correctly designed. The OOM and the policy violations are concentrated in **two process-global in-memory dicts** — `utils/etherscan.py:73 _cache` and `services/policy/principal_history.py:24 _LOG_CACHE` — both unbounded, both never whitelist-gated, both in long-lived workers. The 8192-entry size cap that *does* exist was applied to the small datum (bytecode), not to the multi-MB source blobs the policy says it should bound. **The user's belief is confirmed: the unbounded in-mem Etherscan source cache is the #1 OOM lever** — with `_LOG_CACHE` and the byte-unbounded GitHub `lru_cache` close behind.

---

## 1. Master cache inventory

48 distinct cache sites after de-duplicating ids that appeared in multiple reports (e.g. the Etherscan in-mem `_cache` was reported by three subsystems; the materialization cache by two). Grouped by subsystem; one row per physical cache.

### Wire-level / shared I/O (`utils/`, `db/storage.py`)

| id | location | data_class | medium | key | bound (size / TTL) | scope | env-gate |
|---|---|---|---|---|---|---|---|
| etherscan-inmem-cache | utils/etherscan.py:73 | source/abi/creation **+ balances/prices/txlist** | in-mem dict | (module, action, chain_id, sorted params) | **UNBOUNDED — no maxsize, no TTL, no eviction** | process | ETHERSCAN_CACHE=1 |
| etherscan-pg-cache | utils/etherscan.py:92/137 | source/abi/creation | postgres | PK (module, action, chain_id, params_hash) | unbounded rows / no TTL (ttl_expires_at never set) | cross-process | ETHERSCAN_PG_CACHE=1 + whitelist |
| getcode-inmem-cache | utils/rpc.py:45 | bytecode (+keccak) | in-mem LRU | (rpc_url, address) | **bounded 8192 + oldest-25% evict + TTL 1800s** | process | always on; PSAT_GETCODE_CACHE_TTL_S |
| bytecode-pg-cache | utils/rpc.py:100/129 | bytecode (+keccak) | postgres | PK (chain_id, address) | unbounded rows / no TTL (immutable) | cross-process | PSAT_BYTECODE_PG_CACHE=1 |
| chain-id-cache | utils/rpc.py:54 | chain metadata | in-mem dict | rpc_url | unbounded but ~handful of URLs | process | none |
| exa-search-blob-cache | utils/exa.py:57/94 | search results | blob storage | sha256(canonical request) | unbounded objects / TTL 30d / schema-versioned | cross-process | PSAT_EXA_CACHE (unset=OFF) |
| tavily-search-blob-cache | utils/tavily.py:101/141 | search results | blob storage | sha256(request shape) | unbounded objects / TTL 30d | cross-process | PSAT_TAVILY_CACHE (unset=OFF) |
| storage-client-singleton | db/storage.py:263 | S3 client handle (not data) | lru_cache(1) | () | bounded = 1 | singleton | ARTIFACT_STORAGE_* |

### Discovery (`services/discovery/`, `services/crawlers/`, `db/queue.py`)

| id | location | data_class | medium | key | bound (size / TTL) | scope | env-gate |
|---|---|---|---|---|---|---|---|
| research-cache | services/discovery/run_discovery.py:80 | search results (deep_research) | in-mem dict | (instructions, sha1(schema)) | **unbounded entry count** / 24h TTL on read only | process | none |
| branch-sha-cache | services/discovery/audit_reports/_github.py:114 | git HEAD sha (+negatives) | in-mem dict | (owner, repo, branch) | unbounded / **no TTL** (low cardinality) | process | none |
| protocols-cache | services/discovery/protocol_resolver.py:13 | DefiLlama protocol directory | singleton list | none (module global) | bounded (one list) / no TTL | process | none |
| defillama-adapters-repo | services/crawlers/defillama/scan.py:25 | adapter repo source | file (git clone) | fixed /tmp path | bounded / `git pull` each job | process | none |
| static-analysis-artifact-reuse | db/queue.py:1320/1469 (+static_worker.py:644) | static analysis / proxy class. | postgres | (lower(address), chain) | unbounded rows / re-validated vs live chain | cross-process | per-request `force` |
| discovery-request-code-cache | static_dependencies.py:73; dynamic_dependencies.py:421; classifier.py:515; unified_dependencies.py:135 | bytecode / name+selectors | request-scoped | address | per-call, GC'd on return | request | none |

### Static analysis (`services/static/`, `db/contract_materializations.py`, `workers/static_worker.py`)

| id | location | data_class | medium | key | bound (size / TTL) | scope | env-gate |
|---|---|---|---|---|---|---|---|
| contract-materializations | db/contract_materializations.py:285; recursive.py:185 | static-analysis bundle (5–20MB) | postgres + blob | PK (chain, bytecode_keccak); 2ndary (chain, address) | unbounded rows / **no TTL, no analyzer-version dim** | cross-process | PSAT_CONTRACT_MATERIALIZATIONS=1 |
| expression-text-cache | services/static/contract_analysis_pipeline/revert_detect.py:128 | diagnostic str(expr) | in-mem dict | **id(expr)** | **UNBOUNDED, never cleared** | process | none |
| provenance-sub-engine-memo | provenance.py:305 | static analysis (SourceSet) | in-mem dict | (callee, frozenset bindings) | per-engine (per-function), GC'd | request | none |
| provenance-leaf-value-cache | provenance.py:315 | static analysis (SourceSet) | in-mem dict | id(value) | per-engine, GC'd | request | none |
| predicate-helper-engine-cache | predicates.py:107 (ContextVar) | static analysis (ProvenanceMap) | in-mem dict | (callee, sorted bindings) | per-contract, reset in finally | request | none |
| revert-container-reads | revert_detect.py:216 | static analysis (var names) | in-mem dict | id(container) | per-detector (per-function), GC'd | request | none |
| enrichment-info-cache | workers/static_worker.py:1665 | name + selectors | in-mem dict + per-job PG artifact | address; artifact by job_id | per-job | request / cross-process | none |

### Resolution (`services/resolution/`, `workers/resolution_worker.py`)

| id | location | data_class | medium | key | bound (size / TTL) | scope | env-gate |
|---|---|---|---|---|---|---|---|
| mapping-enum-l1-present-set | services/resolution/mapping_enumerator.py:78 | resolution result (ACL set) | in-mem dict | **address only** (no chain/specs) | **UNBOUNDED** / lazy per-key TTL 1800s | process | PSAT_MAPPING_ENUMERATION_CACHE_TTL_S |
| mapping-enum-l1-value-fold | mapping_enumerator.py:698 | resolution result (value fold) | in-mem dict | **address only** | **UNBOUNDED** / lazy TTL 1800s; no L2 | process | (same TTL) |
| mapping-enum-l2-pg-cache | db/mapping_enumeration_cache.py:106 | resolution result | postgres | (chain, address, specs_hash) | unbounded rows / TTL 1800s | cross-process | PSAT_MAPPING_ENUMERATION_DB_CACHE=1 |
| differential-probe-cache | capability_resolver.py:493 | resolution result | in-mem LRU | (chain_id, addr, selector, **block**) | bounded 4096 + trim / no TTL (block-pinned) | process | PSAT_DIFFERENTIAL_PROBE (OFF) |
| one-shot-latch-cache | capability_resolver.py:625 | resolution result (latch) | in-mem LRU | (chain_id, addr, **probe_height**, slots) | bounded 4096 + trim | process | one_shot_probe (ON) |
| capability-live-read-memo | capability_resolver.py:360 | resolution result (getter reads) | request-scoped | (kind, rpc_url, addr, selector, **block**) | per-pass, GC'd; success-only | request | none |
| one-shot-pass-cache | capability_resolver.py:380 | resolution result (latch) | request-scoped | (chain_id, addr, probe_height, slots) | per-pass, GC'd | request | none |
| creation-block-floor-cache | services/resolution/creation_block_floor.py:38 | chain metadata (scan floor) | in-mem dict | (address, chain_id) | **UNBOUNDED, no TTL; caches None forever** | process | none |
| external-check-candidate-cache | services/resolution/external_check_materializer.py:31 | event_logs (candidate addrs) | in-mem dict | (chain_id, checker_address) | **UNBOUNDED, no TTL** (≤512 addrs/entry) | process | none |
| classify-resolved-address-cache | services/resolution/tracking.py:39 | classification (+Safe owners/delay) | in-mem LRU | (rpc_url, address, block_tag='latest') | **bounded 4096 + half-evict + TTL 1800s** | process | PSAT_CLASSIFY_CACHE_TTL_S |
| resolution-worker-classify-job-cache | workers/resolution_worker.py:184 | classification | request-scoped | address | per-job, GC'd | request | none |
| classified-addresses-artifact | resolution_worker.py:212 → policy_worker.py:330 | classification | postgres/blob | (job_id,'classified_addresses'); inner by address | per-job snapshot / no TTL | cross-process | none |

### Policy & aggregations (`services/policy/`, `services/aggregations/`, `workers/policy_worker.py`)

| id | location | data_class | medium | key | bound (size / TTL) | scope | env-gate |
|---|---|---|---|---|---|---|---|
| principal-history-log-cache | services/policy/principal_history.py:24 | **event_logs (tx-history class)** | in-mem dict | (chain_id, authority, topic0) | **UNBOUNDED, no TTL; ≤10k log dicts/entry** | process | none |
| principal-history-abi-cache | services/policy/principal_history.py:23 | **abi (3rd copy)** | in-mem dict | (chain_id, address) | **UNBOUNDED, no TTL** | process | none |
| audit-timeline-bytecode-keccak-cache | services/aggregations/contract_audit_timeline.py:21 | bytecode keccak (3rd copy) | in-mem dict | **address only** (no chain) | **unbounded entry count** / 30s read TTL, no evict | process (web) | none |
| policy-worker-classify-cache | workers/policy_worker.py:331 (+cache_lc :72) | classification | request-scoped | address | per-job, GC'd | request | none |
| fp-writer-type-memo | services/policy/effective_permissions_writer.py:170 | classification | request-scoped | address | per-call, GC'd | request | none |

### Monitoring / event indexing / audit coverage (`services/monitoring/`, `workers/event_log_indexer.py`, `services/audits/`, `services/governance/`)

| id | location | data_class | medium | key | bound (size / TTL) | scope | env-gate |
|---|---|---|---|---|---|---|---|
| source-equivalence-github-lru | services/audits/source_equivalence.py:402 | source (GitHub raw, full text) | lru_cache(4096) | (url[commit-pinned], token) | **count 4096 but BYTE-unbounded (≤5MB/entry)** | process | none |
| event-indexer-block-hash-memo | workers/event_log_indexer.py:367 | chain metadata | request-scoped | (chain_id, block_number) | per-pass, GC'd | request | none |
| event-indexer-seed-cache | workers/event_log_indexer.py:486 | chain metadata (creation block) | request-scoped | address | per-pass, GC'd | request | none |
| indexed-event-log-durable-store | workers/event_log_indexer.py (IndexedEventLog/Cursor) | event_logs (system-of-record) | postgres | logs (chain,addr,topic0,tx,log_idx); cursor (chain,addr,topic0) | unbounded rows / self-heal reorg+backfill | cross-process | PSAT_EVENT_INDEXER_* |
| coverage-row-cache | services/audits/coverage.py:577/799/1449 | resolution result | request-scoped | (protocol_id, addr, chain_key, fallback) | per-call, GC'd | request | none |
| coverage-proxy-events-cache | services/audits/coverage.py:578/800/1450 | event_logs | request-scoped | contract_id | per-call, GC'd | request | none |
| coverage-preload-audit-contract-cache | services/audits/coverage.py:1045 | audit/contract rows | request-scoped | id | per-call, GC'd | request | none |
| coverage-etherscan-source-cache | services/audits/coverage.py:1177 | source | request-scoped | address | per-upsert, GC'd, thread-safe | request | none |
| coverage-bytecode-keccak-anchor | services/audits/coverage.py:967 | bytecode keccak (snapshot, not cache) | request-scoped | contract_id | per-upsert, re-fetched fresh | request | none |
| control-graph-node-classification | services/governance/control_graph_types.py:98 | classification (fold-back) | postgres | (contract_id, address) | unbounded rows / backfill-only, no downgrade | cross-process | none |

**Constants that look like caches but are not** (excluded from the count): `_PG_CACHE_WHITELIST`, `_CLASSIFY_PROBE_SIGS`, `_EFFECT_CAPABILITY`, `PROCESS_META`, `polling_plan._HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES`, `tracking._KNOWN_BYTECODE_IMPLS`, `hypersync_bound._SEMAPHORES`.

---

## 2. Redundant / multi-place caching (the headline)

Eight logical data classes are cached in more than one place. Four are **improper** (divergence or a redundant unnecessary copy); four are **justified** L1/L2 layering.

### 2.1 Bytecode + its keccak — **4 caching layers, 1 improper** ⚠️
- **Layers:** (1) `getcode-inmem-cache` (utils/rpc.py:45, bounded 8192, TTL 1800s, key `(rpc_url,addr)`); (2) `bytecode-pg-cache` (utils/rpc.py:100, durable, **no TTL**, key `(chain_id,address)`); (3) `audit-timeline-bytecode-keccak-cache` (contract_audit_timeline.py:21, web process, 30s read TTL, **address-only key**); (4) the keccak is the PRIMARY KEY of `contract-materializations` (derived, not a copy). Plus a request-scoped anchor at coverage.py:967 (a snapshot, fine).
- **Divergence:** YES. (1) is TTL'd, (2) is not → under the (rare, post-EIP-6780) metamorphic redeploy they **converge toward the stale PG value**, not the wire. (3) **advertises 30s freshness but sits on top of the 1800s/immutable layers underneath** (`_fetch_bytecode_keccak` → `utils.rpc.get_code`), so its freshness contract is fictional (drift can be missed for ≥30 min).
- **Verdict:** Layers 1+2 are **justified** immutable L1/L2. Layer 3 (`audit-timeline-bytecode-keccak-cache`) is **improper** — a third keccak cache that should read `code_keccak` from the existing `bytecode_cache` layer; it also drops the chain dimension. Fix in P1.

### 2.2 Etherscan source / ABI / creation — **up to 4 layers; ABI specifically in 3, 1 improper** ⚠️
- **Layers:** (1) `etherscan-inmem-cache` (utils/etherscan.py:73, **unbounded**); (2) `etherscan-pg-cache` (utils/etherscan.py:92, durable, whitelisted, chain-keyed); (3) scaffolded `SourceFile` rows / `source_file_key` blobs (different representation, durable); (4) request-scoped `coverage-etherscan-source-cache` (ephemeral). **ABI additionally** lives in `principal-history-abi-cache` (principal_history.py:23) — a **third** ABI copy.
- **Divergence:** YES and real. The in-mem layer is **never invalidated** while PG does `ON CONFLICT … UPDATE` (etherscan.py:161-162). Worse, the in-mem layer caches an **empty/unverified `getsourcecode` response permanently** (write at :207-211 fires for any `status=="1"`), while PG **refuses** it (`_is_persistable`, :122-134). Because the in-mem read (:173-178) short-circuits before PG, a process that probed a contract while unverified serves empty source **forever**, even after the contract is verified and even though a fresh process would get the real source from PG.
- **Verdict:** Layers 2+3 are the **justified** durable store. The in-mem layer (1) is the OOM/divergence problem (§4). `principal-history-abi-cache` is **improper and fully redundant** — `('contract','getabi')` is already PG-whitelisted (etherscan.py:63); delete it (P1).

### 2.3 Address classification — **up to 6 layers, 1 improper divergence** ⚠️
- **Layers:** (1) `_CLASSIFY_CACHE` (tracking.py:39, process, bounded 4096, TTL 1800s — **the only well-behaved tier**); (2) per-job `resolution_worker.classify_cache` (:184); (3) persisted `classified_addresses` artifact (:212→policy_worker.py:330); (4) `policy_worker.classify_cache` (:331) + a lowercased copy `cache_lc` (:72); (5) `fp-writer-type-memo` (effective_permissions_writer.py:170); (6) **persisted `control_graph_nodes.resolved_type`** (control_graph_types.py) vs the policy-stage `function_principals.resolved_type`.
- **Divergence:** Layers 1–5 are job-scoped/snapshot and **benign** (a deliberate perf bridge; the snapshot is point-in-time per job). Layer 6 is the **improper** one: `control_graph_nodes.resolved_type` (resolution stage, graph-walk only) and `function_principals.resolved_type` (policy stage, with a **live classify fallback**) are two independently-computed *persisted* classifications that disagree; the policy answer is strictly more complete but **does not propagate back to CGN** unless `reconcile_control_graph_types` runs, so CGN serves a stale `unknown` to monitoring enrollment / chat context / Surface canvas.
- **Verdict:** Tiers 1–5 justified. Tier-6 divergence is real; the reconcile pass is the fix and must run after every policy completion (P2).

### 2.4 Mapping enumeration — **2 layers that DISAGREE on key dimensions** ⚠️ (improper)
- **Layers:** L1 `mapping-enum-l1-present-set` (mapping_enumerator.py:78, **address-only key**) and L2 `mapping-enum-l2-pg-cache` (db/mapping_enumeration_cache.py:106, key `(chain, address, specs_hash)`).
- **Divergence:** YES, **active correctness bug.** The L1 hit short-circuits (mapping_enumerator.py:469-484) **before** L2 is consulted, so the coarse address-only L1 key **defeats** L2's careful keying: same address on two chains collides, and a re-analysis with different `writer_specs` returns the first specs' principals. `mapping-enum-l1-value-fold` (:698) has the same address-only key and **no L2 at all**.
- **Verdict:** Improper. Re-key L1 on `(chain, address, specs_hash)` to match L2 (or make L1 a thin read-through of L2). P1.

### 2.5 Static-analysis bundle — **2 durable copies + recompute** (improper-ish)
- **Layers:** `contract-materializations` row (keyed keccak) AND the per-job `contract_analysis` artifact (static_worker.py:1815, keyed job_id) hold the **same analysis dict**; the resolution builder even **recomputes** it (`recursive.py:228 _build_static_artifacts` fresh rather than reading the artifact). `predicate_trees` here duplicates the per-job `semantic_predicate_trees`.
- **Divergence:** Independent lifecycles, no cross-invalidation; diverge across an analyzer upgrade. `nested_artifacts.py:9-13` shows the team already de-duplicated analysis/tracking_plan OUT of the recursive artifacts in favor of this table — the top-level job `contract_analysis` artifact is the remaining straggler.
- **Verdict:** Consolidate to the materialization row as single source of truth; have resolution reuse the static stage's output (P2).

### 2.6 Web search results — exa + tavily (justified)
Parallel providers, identical envelope/key design, different prefixes; overlapping queries cache the same logical datum twice. Both **off by default in prod** → low impact. **Justified** (genuinely different providers/results).

### 2.7 Bytecode-in-rpc vs DefiLlama protocols — single sites
`getcode-inmem` + PG is the legit L1/L2 already covered in 2.1. `protocols-cache` is one singleton (reported by two subsystems, but a single physical cache) — not a redundancy.

### 2.8 Audit-side GitHub source vs Etherscan source (not a duplicate)
`source-equivalence-github-lru` (commit-pinned GitHub raw) is a **distinct datum** from Etherscan verified source — not a redundancy, but it has its own OOM issue (§4.3).

---

## 3. Volatile-data-cached — graded against policy

Policy: **balances/prices = do not cache; tx history = short/medium TTL.**

| datum | where cached | TTL | policy | grade |
|---|---|---|---|---|
| **ETH price** (`stats/ethprice`) | etherscan-inmem-cache (utils/etherscan.py:73; get_eth_price :391) | **none — frozen for process life** (single global key `('stats','ethprice',1,())`) | do not cache | **FAIL (high)** |
| **balances** (`account/balance`) | etherscan-inmem-cache (get_eth_balance :385) | **none** | do not cache | **FAIL (high)** |
| **token balances** (`account/addresstokenbalance`) | etherscan-inmem-cache (get_token_balances :401) | **none** | do not cache | **FAIL (high)** |
| **tx history** (`account/txlist`) | etherscan-inmem-cache (activity.py:59, deployer.py:81, dynamic_dependencies.py:85-114) | **none — infinite** | short/medium TTL | **FAIL (medium)** |
| **authority event logs** (`logs/getLogs`) | (a) etherscan-inmem-cache (upgrade_history.py:243); (b) **`_LOG_CACHE`** (principal_history.py:24, raw `requests.get`) | **none** (both) | short/medium TTL | **FAIL (high)** |
| balance/price/tx in **PG** layer | etherscan-pg-cache | excluded by `_PG_CACHE_WHITELIST` (:60-66) | do not persist stale | **PASS** |
| on-chain slot reads (watchers, polling_plan) | not cached (read fresh each pass) | n/a | — | **PASS** |
| bytecode keccak anchor (drift) | coverage.py:967 — re-fetched per upsert, stored as point-in-time column | n/a | snapshot, not cache | **PASS** |

**Mechanism of the failure (confirmed in source):** `get()` caches **every** `status=="1"` response in the in-mem dict at `utils/etherscan.py:207-211` with **no whitelist check** — the whitelist gates only `_pg_cache_get`/`_pg_cache_put`. So `services/monitoring/tvl.py` (`run_tvl_loop`, a `while True` at :362-373) calls `get_eth_price`/`get_eth_balance`/`get_token_balances` each cycle (tvl.py:131,147,153), but the **first** value is frozen for the whole process lifetime. **Every hourly `TvlSnapshot` after the first reuses process-start prices/balances** — the periodic-refresh product is silently defeated, and DefiLlama-vs-on-chain comparison drifts. `workers/resolution_worker.py:326-328` fetch balances through the same frozen path.

**`_LOG_CACHE` doubly offends:** it bypasses `utils.etherscan` entirely (raw `requests.get … getLogs … toBlock=latest`, principal_history.py:518-560) and stores `fromBlock=0..latest` snapshots with no TTL — **re-introducing exactly the stale tx-history serving that the PG whitelist was designed to avoid** (etherscan.py:58-59). Role grants/revokes after the first fetch are invisible to every later job in the same worker.

---

## 4. Unbounded / OOM risks (ranked)

Ranked by **key cardinality × value size**. Process-global, no size cap, in long-lived workers = real OOM. (Postgres/blob row growth is disk, not RSS — excluded from OOM ranking; noted separately.)

| # | cache | location | key cardinality | value size | severity |
|---|---|---|---|---|---|
| **1** | **etherscan-inmem-cache (source view)** | utils/etherscan.py:73 | high (per address) | **multi-MB source bundles** | **HIGH — the OOM lever** |
| **2** | **principal-history-log-cache `_LOG_CACHE`** | principal_history.py:24 | high (chain×authority×topic0) | **≤10k log dicts/entry** | **HIGH** |
| **3** | **source-equivalence-github-lru** | source_equivalence.py:402 | count-capped 4096 | **≤5MB/entry → ~20GB worst case**, full text callers never use | **MED-HIGH** |
| 4 | mapping-enum `_CACHE` + `_VALUE_CACHE` | mapping_enumerator.py:78, 698 | high (per address) | principal lists (100s–1000s addrs) | MED |
| 5 | external-check-candidate-cache | external_check_materializer.py:31 | per checker contract | ≤512 addrs (~21KB) | MED-LOW |
| 6 | expression-text-cache | revert_detect.py:128 | **very high** (per Slither expr, all contracts) | small strings | MED (count, not bytes) |
| 7 | research-cache | run_discovery.py:80 | #protocols × pass-types | deep_research JSON | MED |
| 8 | etherscan-inmem-cache (balances/txlist view) | utils/etherscan.py:73 | high (per address) | small–medium | MED |
| 9 | audit-timeline-bytecode-keccak-cache | contract_audit_timeline.py:21 | high (per address, web proc) | tiny (66-char hash) | MED (unbounded entries) |
| 10 | principal-history-abi-cache | principal_history.py:23 | per authority | ABI list | LOW |
| 11 | creation-block-floor-cache | creation_block_floor.py:38 | per address | scalar (int/None) | LOW |
| — | branch-sha / chain-id | _github.py:114 / rpc.py:54 | low cardinality | scalar | INFO |

**Is the unbounded in-mem Etherscan source cache the real OOM lever? — YES, confirmed, but it is not alone.**
- The size cap that exists (`_GETCODE_CACHE_MAX = 8192` + eviction + TTL + cache-pressure logging, utils/rpc.py:45-48,515-521) was applied to **bytecode**, which is *small*. The **multi-MB `getsourcecode` blobs** — the exact data the policy says the cap should bound — sit in the **unbounded** `_cache` (utils/etherscan.py:73) with no maxsize, no TTL, no eviction, and **no cache-pressure registration**. The OOM fix was applied to the wrong cache. This is the #1 lever and matches the user's belief precisely.
- **Two other heavy unbounded process-globals** the policy framing misses: `_LOG_CACHE` (principal_history.py:24 — 10k log dicts × unbounded keys in the long-lived **policy worker**, with ~zero intra-job benefit so it is almost pure memory liability), and the GitHub `lru_cache` (source_equivalence.py:402 — count-bounded but **byte-unbounded**, caching full file text that callers only hash). Bounding the Etherscan source cache alone will not stop OOM on the policy worker or the audit path.
- Lighter but still-unbounded contributors: the four resolution dicts (mapping L1 ×2, external-check, floor) and `_EXPRESSION_TEXT_CACHE` (which also carries an `id()`-reuse correctness hazard because it outlives the Slither instance whose object ids it keys on).

---

## 5. Policy grade by data class

| data class | intended | current behavior | grade | gap |
|---|---|---|---|---|
| **source / ABI / creation** | PG durable + in-mem **bounded LRU** | PG durable layer correct & whitelisted (PASS); in-mem `_cache` is an **unbounded dict**, not a bounded LRU; ABI redundantly cached a 3rd time in `_LOG_CACHE`'s module (`_ABI_CACHE`) | **PARTIAL → FAIL on in-mem** | in-mem is unbounded (violates the literal "bounded LRU"); the cap exists but bounds bytecode instead |
| **bytecode** | (by family) bounded in-mem + durable | bounded LRU 8192 + TTL (utils/rpc.py:45) over a no-TTL durable PG table | **PASS** (reference model) | minor: in-mem keyed `(rpc_url,addr)` not `(chain_id,addr)` → duplicate entries across URL aliases |
| **tx history** | short/medium TTL | `txlist` cached in-mem with **no TTL**; `getLogs` cached in `_LOG_CACHE` with **no TTL**; PG correctly excludes both | **FAIL** | infinite TTL on tx-history-class data in two in-mem caches |
| **balances / prices** | **do not cache** | cached process-globally with no TTL via etherscan-inmem-cache; TVL loop serves frozen process-start values | **FAIL** | direct violation; in-mem layer not whitelist-gated |

PG layers (etherscan_cache, bytecode_cache, mapping_enumeration_cache, contract_materializations, indexed_event_log) are policy-compliant and correctly keyed (chain_id present). The failures are entirely in the in-memory layers.

---

## 6. Open design choice: bounded in-mem LRU for source vs. psql-only

**Recommendation: bounded in-mem LRU restricted to the whitelist — with `getsourcecode` (the multi-MB blob) given a *very small* dedicated cap (or made psql-only).** This matches the policy's literal ask ("in-memory copy only as a bounded LRU") while neutralizing the OOM.

Reasoning specific to this codebase:
1. **The durable layer already exists and is correct.** `etherscan-pg-cache` (utils/etherscan.py:92) is cross-process, chain-keyed, whitelisted, immutable-correct, and degrades to no-op without a DB. Source/ABI/creation already persist exactly where the policy wants them. So the in-mem layer is a pure latency optimization, not a correctness dependency — which makes either option safe.
2. **psql-only is proven viable in-tree.** The far larger static-analysis bundle (5–20MB) is `contract-materializations` — **PG + blob only, with no process-global in-mem map** (recursive.py:262-277 deep-copies per job and discards). This is the codebase's own precedent that source-derived data can be served durably without an accumulating in-mem cache.
3. **But intra-job re-reads are real.** Each worker re-reads the same contract's source several times within one job (fetch → scaffold → static → resolution). A **small** bounded LRU preserves that hot-path latency at trivial cost — which is why a tiny LRU edges out strict psql-only for the common case.
4. **The blob size forces the nuance.** A 256-entry LRU of `getsourcecode` could be 256 × several MB ≈ ~1GB resident — still dangerous on a memory-capped Fly machine. So **the LRU maxsize must be small for `getsourcecode` specifically** (e.g. 32–64 entries), or `getsourcecode` goes psql-only while the small `getabi`/`getcontractcreation` responses use a 256-entry LRU. Bytecode's 8192 cap is only safe because bytecode is small; do **not** reuse that number for source.
5. **Non-negotiable regardless of the choice:** gate the in-mem layer by `_pg_cache_eligible(module, action)` so balances/prices/txlist/getLogs **never** enter it. That single change fixes the volatile violations (§3) and stops the high-cardinality volatile keys from feeding the dict — it is independent of the LRU-vs-psql question and must ship first.

**Net:** bounded LRU restricted to the whitelist, modeled on `_GETCODE_CACHE`, registered with `utils/memory` cache-pressure, **small maxsize for `getsourcecode`**. psql-only is an acceptable simpler fallback (and is the strictly-safer choice if they would rather not maintain an LRU) — choose it for `getsourcecode` if maximum memory safety is preferred over intra-job read latency.

---

## 7. Prioritized recommendations

### P0 — correctness + the OOM lever (ship first)
1. **Whitelist-gate the in-mem `_cache` read+write.** `utils/etherscan.py` — wrap the read (`:173-178`) and both writes (`:184-185`, `:207-211`) in `if _pg_cache_eligible(module, action):`. Effect: balances/prices/txlist/getLogs never enter process memory → fixes the balances/prices **FAIL** and the txlist **FAIL** (§3) in one guard mirroring the existing PG path. *(Independent of #2; do both.)*
2. **Bound the in-mem `_cache` for the remaining source/abi/creation.** `utils/etherscan.py:73` — replace the plain dict with a bounded LRU (`OrderedDict` + small maxsize, modeled on `utils/rpc.py:45-48,515-521`), **small cap for `getsourcecode`**, and register it with `utils/memory` cache-pressure. Effect: closes the **#1 OOM lever**.
3. **Delete (or short-TTL + bound) `_LOG_CACHE`.** `services/policy/principal_history.py:24` (write at `:557`). It is the **#2 OOM lever** (10k log dicts × unbounded keys in the long-lived policy worker), gives ~zero intra-job benefit, and serves stale authority history. Prefer deletion; if kept, add a short/medium TTL + maxsize + cache-pressure registration.

### P1 — bounded leaks and real divergence
4. **Delete `_ABI_CACHE`.** `services/policy/principal_history.py:23` (write `:514`). Redundant 3rd ABI layer; `('contract','getabi')` is already PG-whitelisted (etherscan.py:63) and in-mem-cached by `utils.etherscan`. Free removal of an unbounded process-global.
5. **Stop caching full file text in the GitHub `lru_cache`.** `services/audits/source_equivalence.py:402` / `:489` — memoize at the `fetch_github_source_hash` level returning `(status, detail, sha256)`, not `GithubFetch(content=r.text)`; callers use only the hash (`:543`) / null-check (`:559`). Removes ~20GB worst-case byte-unboundedness (~1000× per-entry shrink).
6. **Cap + re-key the four unbounded resolution dicts.** Add maxsize/LRU to `mapping_enumerator._CACHE` (`:78`), `_VALUE_CACHE` (`:698`), `external_check_materializer._CANDIDATE_CACHE` (`:31`), `creation_block_floor._FLOOR_CACHE` (`:38`). Additionally: **re-key the mapping L1 caches on `(chain, address, specs_hash)`** (`:469`, `:727`) so L1 stops defeating L2's correct keying (§2.4); and **stop caching `None` permanently** in `_FLOOR_CACHE` (`:114-115`) so a backfilled cursor is picked up.
7. **Instance-scope `_EXPRESSION_TEXT_CACHE`.** `services/static/contract_analysis_pipeline/revert_detect.py:128` — make it an attribute on `RevertDetector` like `_container_reads` (`:216`). Fixes both the unbounded leak and the `id()`-reuse diagnostic-correctness hazard (it currently outlives the Slither instance whose object ids it keys on).
8. **Fix / drop `audit-timeline-bytecode-keccak-cache`.** `services/aggregations/contract_audit_timeline.py:21` — read `code_keccak` from the existing `bytecode_cache` layer instead of a 3rd cache; add `chain_id` to the key; correct the fictional "30s freshness" comment (`:19-20,30`).
9. **Bound `research-cache` and don't cache negative branch SHAs.** `run_discovery.py:80` (LRU/evict on expiry); `_github.py:148` — do not cache `None` (let transient GitHub 5xx retry) and add a short TTL to branch HEAD (it advances on every push).

### P2 — staleness windows + structural cleanups
10. **Shorten TTL / pin block for mutable classification details.** `services/resolution/tracking.py:39` — entries whose `details` carry Safe `owners[]/threshold` or timelock `delay` are served up to 1800s stale at `block_tag='latest'` (stale_on_upgrade, security-relevant). Shorten TTL for those, or key on a pinned block.
11. **Add an analyzer/pipeline-version dimension to `contract-materializations`.** `db/models.py:1085` (PK) — a code deploy currently leaves every `(chain, keccak)` serving the OLD bundle forever. Add a version column/guard; and de-dup the per-job `contract_analysis` artifact (static_worker.py:1815) against the materialization row (§2.5).
12. **Guarantee `reconcile_control_graph_types` runs after every policy completion.** `services/governance/control_graph_types.py` — closes the CGN-vs-FunctionPrincipal classification divergence (§2.3) so monitoring/chat/Surface don't read stale `unknown`.
13. **Key `getcode-inmem-cache` on `(chain_id, address)`.** `utils/rpc.py:474` — align with the PG layer and dedup RPC-URL aliases (low priority; correctness-safe today because eRPC URLs embed the chain).
14. **Operational:** optional lifecycle/retention pruning for the unbounded **disk** stores (etherscan_cache, mapping_enumeration_cache, IndexedEventLog) — not OOM, but unbounded disk growth.

---

## Appendix — caches confirmed safe (no action)
Request/job/pass-scoped (created in-call, GC'd on return): all `provenance.py` engine memos, `predicate-helper-engine-cache` ContextVar, `revert-container-reads`, `capability-live-read-memo`, `one-shot-pass-cache`, `resolution-worker`/`policy-worker` classify dicts, `fp-writer-type-memo`, all `coverage.py` per-call dicts, `event-indexer` block-hash + seed memos, `discovery-request-code-cache`. Bounded/block-pinned process caches: `_GETCODE_CACHE` (the reference model), `_CLASSIFY_CACHE` bound, `_PROBE_CACHE`, `_ONE_SHOT_CACHE`. Well-behaved durable/blob stores: `etherscan-pg-cache`, `bytecode-pg-cache`, `mapping-enum-l2-pg-cache`, `contract-materializations`, `indexed-event-log-durable-store`, exa/tavily blob caches (off by default), `storage-client-singleton`.
