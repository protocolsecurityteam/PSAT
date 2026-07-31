# Scoring field register — what a production scorer must collect

Consolidated from `SCORING_INVARIANTS.md` Appendix B **as amended by B0b** (the
nine-lane validation round, 2026-07-30, five lanes probing on-chain). Appendix B is
organised as a validation record with errata; this file is the flattened
"collect this" list. Where they differ, this file already has B0b applied.

Status vocabulary: **REQ** must be consumed · **GATE** a precondition on a sibling
field · **CONF** real but not grade-admissible · **BAN** must not be used as a
witness. Consumption means one or more of: gate / arithmetic / cite / three-state
(§E). Reading a column is not consumption.

Two rules that apply to every field below:
- **NULL / absent is a third state, never a zero.** Every value axis needs a
  `not_determined` branch that reaches the consumer.
- **The entity key is the runtime address**, `effective_functions.deployment_address`
  falling back to `contracts.address`, and value reduces **MAX per (entity, asset)**
  — never SUM per `contracts` row, which double-counts a proxy against its
  implementation (measured: 2 pairs, $1,589,342.37).

---

## 1. Value and perimeter

| field | pop. | status | notes |
|---|--:|---|---|
| `contract_balances.token_address` (NULL = native) | 702 ERC-20 + 19 native | REQ | the asset key. Join against flow `kind` for the native-vs-ERC-20 split |
| `contract_balances.usd_value` | 289/721 non-null | REQ | **NULL is not_determined, never 0** |
| `contract_balances.price_usd` | 721/721 | REQ **/ BAN** | admissible for unit reconstruction where `usd_value IS NOT NULL`; **banned as a pricing source** — 433 rows carry `price_usd = 0` and nothing separates worthless spam from a failed lookup |
| `contract_balances.token_symbol / decimals / raw_balance` | 721 each | REQ | unit reconstruction |
| `contract_balances.fetched_at` | 721/721, spans 1h40m | CONF | a WRITE timestamp, never an observation height. **AMENDED (B1/Unit 4):** the delete+reinsert is gone (insert-only) and a `block_number` column exists — but it is NULL on all 1,617 pre-existing rows, permanently, so figures sourced from THEM remain non-replayable |
| **absent native row** | 41 of 60 entities | GATE | still means "zero **or** the fetch failed" **for these 1,617 rows** — the insert is gated on `eth_wei > 0` and both swallows turned a failure into 0. Per-asset native answer is `not_determined`, never $0. **AMENDED (B2/Unit 4):** going forward the discriminator is `contract_balance_fetches.native_status`, not the absence |
| **absent balance row entirely** | — | GATE | same rule. An entity with no row is `not_determined`; do not default it to `0.0` |
| `contract_balances.observed_address` | 0/1617 | REQ | the address the read was ISSUED against, verbatim from the write-point local. NULL = not_determined. The two writers differ on purpose: `tvl.py` reads `contracts.address`, `resolution_worker.py` reads `request['proxy_address'] or address` |
| `contract_balances.block_number` | 0/1617, **native rows only** | GATE | the height **this quantity** was read at, pinned-`Multicall3.getEthBalance` path only. NULL = not_determined, permanently. Failure, a `success=False` sub-call, or **returndata shorter than 32 bytes** all fall back to the unpinned path and leave it NULL — never a stamped `eth_blockNumber` |
| `contract_balances.price_block_number` | 0/1617, structurally always NULL | CONF **/ BAN** | the price height is not_determined and no source in this system carries one; the same asset diverges up to 20.97% within one recorded instant. **Substituting `block_number` for it is banned** — `usd_value`/`price_usd` are never as-of-block. DB-enforced |
| `contract_balances.fetch_id` | 0/1617 | GATE | the fetch that observed the row. NULL = legacy, provenance not_determined |
| `contract_balance_fetches.native_status` | new plane | GATE | `proven_zero` (pinned only, block required, DB-enforced) / `proven_nonzero` / `fetch_failed` / `not_determined`. **An unpinned zero is `not_determined`** — Etherscan answers `tag=latest` and proves zero at no height. Read only as the PAIR with `block_number`, via `balance_reads.native_balance_fact` |
| `contract_balance_fetches.asset_set_status` | new plane | GATE | `returned_assets` / `returned_empty` (a proven-empty **page**, not "holds nothing") / `at_page_cap` / `fetch_failed`. **No `complete` value exists** |
| `contract_balance_fetches.asset_page_length` | new plane | GATE | the RAW endpoint count before the `raw_balance > 0` filter. NULL = not_determined. The only witness for the at-cap case — a stored-row count is a lower bound |
| `contract_balance_fetches` **rows** | new plane | — | **NOT holdings.** They record that a read was attempted, never that anything is held. `contract_balances` row existence still means a witnessed positive quantity, and `_asset_holdings_by_deployment` now requires one |
| `contract_balances_latest` | view | REQ | **the read surface.** Both writers are insert-only, so the base table carries every past cycle. Per row class, the latest NON-FAILED fetch wins wholesale; legacy rows stay visible until a non-failed fetch exists. **Currency is per `contract_id` and IGNORES `observed_address`** — a contract fetched at two addresses publishes whichever writer wrote LAST, not the union (this preserves the pre-migration last-writer-wins semantics; per-address currency would double-count the 5 proxy/impl pairs in the per-contract sum). Depends on a writer invariant: **a non-failed class status promises that class's row set was written** |
| **`selection.build_authority_graph` $0.00 keys** | 22 of 60 | GATE | `coalesce(sum(usd_value),0)` collapses "all current rows unpriced" into the same `$0.00` as "proven to hold nothing" — `contracts.id 563` among them. The INNER join defends only the NO-ROW case. `observed_reach_floor_usd` publishes such a key as a floor |
| `contracts.is_proxy / implementation / admin / beacon` | admin 1 of 24; impl 25 | REQ | entity collapse. `is_proxy` is **not** a reliable is-a-proxy predicate (the one beacon row has `is_proxy=false`); `admin`'s emptiness is `not_determined`, not "no admin exists" |
| `tvl_snapshots.defillama_tvl` | 3 distinct values | CONF | if used as a denominator, **state which snapshot** — the answer moves $53M. Contains a wrapped-position overlap vs `sum(usd_value)`; publish the caveat |
| **restaking / position value** | — | **CLOSED IN PART (D1 / Unit 10B)** | see §14. The EigenLayer beaconChainETH share leg is a pinned read on its own plane (`restaking_positions`); the consensus-layer residual stays `not_determined` and unbounded above. `forwardExternalCall` (ef 1184 / 2038) **still floors** — the position may not be attached to it without a destination witness |

## 2. Extraction magnitude

All under `effective_functions.claims[].witness.observed`. **87 `flow.out` claims; 43 carry `observed`, 44 carry none** — that fourth state is the majority and needs a branch.

| field | pop. | status | notes |
|---|--:|---|---|
| `reach_determined` | 43/43 (T 38, F 5) | GATE | false ⇒ magnitude undetermined |
| `observed_reach_value_usd` | 38 | REQ | fork-proven magnitude |
| `observed_reach_holders[]` | 43/43, 47 entries | REQ | **whose** value it is — a holder-closure, not a contract bound. **10 of 38 name a non-self holder**; attribute value to the holder entity, not the analysed row |
| `observed_reach_assets[]` | 43/43 | REQ | native = the `0xeeee…eeee` sentinel |
| `observed_reach_priced_usd` | 3 | REQ | a proven **lower bound**. May raise a weight, never cap one; publish with its direction |
| `observed_reach_priced_holders[]` | 3 | REQ | whose holdings the floor is made of |
| `observed_reach_unvalued_pairs / _reasons / _assets` | 5 / 5 / 4 | REQ | confidence gaps, **never a small reach**. `[]` is earned; an absent key means the branch never ran |
| `observed_reach_floor_usd` | **0 here** | REQ-when-present | implemented end-to-end in both projection and producer; the documented fix for "$0 reach on a zero-balance router that can move millions" |
| `shape_proved_by` | 43/43 (sim 36 / none 4 / static 3) | GATE | `none` ⇒ the shape was not proved |
| `contract_balance_seeded` | 2, both true | GATE | the contract's balance was **overridden before the payout**, so the verdict proves a code capability, not an outflow of present treasury. Absence ≠ "the contract is funded" |
| `input_seeded` | 39 all true | REQ, presence-gated | the principal **was given** the asset ⇒ extraction conditional on holding it (a redemption). Lowers **only** on the proven-present state |
| `reach_tvl_check` | 41/41, one value | CONF | discriminates nothing today |
| `effect_verdicts.concrete_destination` | 6 of 69 proven | REQ **+ GATE** | not projected into claims — join on `witness.effect_verdict_id`. **Must be gated on `shape_proved_by`**: on the `unknown`/`none` branch it is one destination from one probe, and it is deliberately withheld on `caller_arbitrary`. Ungated, `0x0…0` reads as a proven fixed burn address |

## 3. Destination and amount (the static lattice)

Under `claims[].witness.flows[]`. **`direction` is on the WITNESS, not on the flow entry** — reading it off the entry silently disables the whole conjunction.

| field | pop. | status | notes |
|---|--:|---|---|
| `flows[].target_kind.{kind,tier}` | 127 entries, 100% | REQ | both tiers admissible (`dispositive_ast`, `static_trace`). `several` is a **set**: expand `target_kinds` (members are **dicts**) and take the **worst** — best-member mints 4 false `immutable_fixed` |
| `flows[].amount_kind.{kind,tier}` | 152 entries; 19 of 86 bounded | REQ | `capped_by_balance` = a proven upper bound / mitigation. **`token_identity` forbids pricing the row off a fungible balance sheet** — a hard precondition, not a note |
| `flows[].target_constraint.{state,guard,binding,pins}` | 63 entries; **`state` only on 52**, `pins=true` on 2 | REQ | only `unconstrained_proven` licenses the theft-shaped reading. A missing tree is **not** proof no gate exists |
| `flows[].from_is_self` | 152/152 | REQ | absent must skip, not default true |
| `flows[].router_ops[].{selector,callee}` | 0/41 applicable `value_router` claims in this snapshot — projected as of U5/D5, stored rows gain it on re-analysis **only if that re-run recomputes `build_claims`**: a claims stage served from the `ANALYSIS_SCHEMA_VERSION = 5` materialization cache (`db/contract_materializations.py:147`) republishes stored claims unchanged and leaves the count at 0, so the backfill needs explicit invalidation or a forced rebuild; producer 73/73 routed flows | CONF (cite) | the identity of the call(s) carrying a routed move — the routed flow's own `selector` is the CALLEE's inner transfer, so this is the only identity of the call this function makes. `selector` = keccak4 of **the signature the AST records** — ABI-canonical where the parameter types lower (`enter` → `0x39d6ba32`), the **declared interface-typed** signature otherwise (`safeTransferFrom(IERC20,address,address,uint256)` → `0x5beae096`, not the canonical `0xd9fc4b61`); **`callee` is an intra-unit AST name, NEVER a resolved on-chain target** (the unlowered case hashes to a selector no dispatch matches, which is why the name travels with it) — join it to this unit's functions and nothing else. **Key absent = `not_determined`** and is the only failure state (unrecorded, pre-field artifact, or unrouted); `[]` is never emitted, because an empty op list would read as "no router" and license the transparency absence denies. A routed flow with the key absent stays fail-closed: its router leaf blocks and the mandatory gate falls to `not_determined`. **No proven-absent state exists** — do not infer "crosses no call" from absence |
| `flows[].kind` | 3 values only | REQ | `low_level_value_call` + **`native_transfer_send`** = native; `callee_erc20_selector` = ERC-20. Partition is total; include `native_transfer_send` |
| `witness.destination_constraint.{guard,binding,pins}` | 5/5/4 on `exec.arbitrary` | REQ | `hash_commitment`+`pins` is materially stronger than `external_call_revert` (only as strong as the external contract) |
| `witness.configures` (+`set_vars`,`hook_pointer`) | 8/8 | REQ | re-points value to the contract the policy affects |
| `witness.callee` (+`sink_id`,`source_tier`) | 11 | REQ | where the value actually is — all name BoringVault ($1,392,349) from a $0 Teller |
| **recomputation:** `calldata.py:static_destination_shape` | — | REQ | replay over `flows[]`. **Three rules, all fail open if skipped:** (1) `several` → worst member; (2) `value_router` flows inside the conjunction; (3) **a `flow.out`/`value_router` claim with no `flows` key BLOCKS** — this is the primary rule, population 8. `policy_derived` tier must also block |
| — validation strength | 3 agreements | — | the fork's published shape **is** this function, so agreement tests projection fidelity only, and the refuting sentinel is absent by construction on every row it would newly decide. `constant` and `storage_no_setter` are 0/0. **Soften severity on a proven fixed shape; never escalate** |
| — composition rule | — | REQ | `immutable` is the Solidity keyword, living in **implementation** code, so a fixed destination is conditional on **upgrade authority**. Compose, don't assert |
| `flows[].target_variable` / `target_variables` | 6 producer rows on the corpus; the 2 `storage_setter` rows (423, 2748) are the gap population | CONF (cite) | **supersedes the old `storage_determined | 2 | defer` row** — the field name was wrong (`storage_determined` appears in 0 persisted rows; the value is `target_kind.kind = 'storage_setter'`) and the destination is no longer nameless. The scalar is published only when the kind NAMES a state variable AND every site agreed; on disagreement the scalar is ABSENT and `target_variables` lists the members — take the worst, never one as the whole. A mapping/array **element** emits neither |
| `flows[].target_writer_signatures` (+ `target_writer_scan_complete`) | 2 | CONF (cite) — **a FLOOR** | "redirectable **at least by** these writers' principals, within the analysed compilation unit" — never the closed set. `[]` ONLY under `storage_no_setter` (the kind is the completed-scan negative); **key absent = no callable writer attributed**, which is a different thing. The gate travels in the same dict: `scan_complete=false` means an assembly `sstore`/`delegatecall`/unresolved alias left the attribution non-exhaustive |
| `flows[].writer_surface_closed` | every row carrying `target_variable` | GATE | **always the string `not_determined`; no other value exists** (type-enforced). The static stage sees ONE compilation unit; the deployed address may be a proxy or one of several implementations — both D3 rows are. Reading its absence as "closed", or the writer list without it, is non-conformant |
| `flows[].amount_kind = 'param_derived'` | 6 | BAN | "NOT a bound, NOT proof of caller control"; `amount_param_index` on such a row is the slot that fed the conversion |
| `witness.sink_ids` | 107 entries, 0 addresses | BAN for asset identity | carries a variable name only; name-based resolution is inv.2-banned. **Read `witness.sink_receivers` instead** — same sinks, keyed by the same ids |
| `witness.sink_receivers{sink_id}.{binding,param_scope,param_index,mutability,visibility,auto_getter_selector,variable,asset_identity,not_determined_reason}` | 57 of 76 external-call sinks on the corpus (the 19 without are low-level `.call`, where the key is ABSENT = never computed); the 18 gap rows split 4 entry-parameter / 3 helper-formal / 10 state-variable / 1 local | GATE (+CONF members) | full semantics in `SCORING_INVARIANTS.md` **B20.1**. The three that matter here: `binding` is decided by `isinstance`, **never** by `visibility` (a `LocalVariable` and an internal state var are indistinguishable on it); `auto_getter_selector` is licensed by the **declared type** and only for a NULLARY public getter (`uint256[] public amounts` → `amounts(uint256)`, not `amounts()`); and **`variable` is display/identity only — `variable + "()"` is the banned shape.** No address is published on this plane |
| — `token_identity` precondition | — | REQ | now **decidable**: satisfied only by `asset_identity = contract_state_unresolved` + a resolved address + a non-`not_determined` invariant. **FAILS** for `caller_named` (4 rows lose single-asset pricing — a demotion, in the honest direction), for `not_determined`, and for an absent `receiver` |

## 4. Principals and protection

| field | pop. | status | notes |
|---|--:|---|---|
| `function_principals.details->>'delay'` | **139/139**, 0 nulls | REQ | three timelocks: 864000 / 432000 / 172800. **Honest strength is duck-type-plus-negative-control**: a nullary uint256 getter named `getMinDelay` **or `delay`** answered, and the address is not a catch-all. Which selector answered is **not recorded**, and one timelock has no structural corroboration at all |
| `details->>'threshold'` + `details->'owners'` | 454/454 | REQ | live `getOwners()`/`getThreshold()`. **CORRECTED 2026-07-30 (C1): the "exact on this corpus, all 9 Safes" claim is RETRACTED.** There are **19** Safe principals, not 9; re-probed at 25643300 the module head holds the sentinel on 18 and a module (`0x2e1b5a40…`) on **`0x21f73d42…`** (VERSION `1.1.1`), so **k/n is an upper bound for 1 of 19**. Guard slot zero on **19/19**. Read `details->'safe_protection'` (next row) before crediting k/n |
| `details->'safe_protection'` (`probe_block`, `safe_version`, `modules_head`, `module_set`, `module_set_basis`, `protection_is_upper_bound`, `guard`) | 19 applicable | REQ, three-state | the module/guard witness at a pinned height. `module_set == []` is **proven empty** (head == sentinel, basis `storage_linked_list_terminated`) and licenses k/n **at `probe_block` only**; anything else — non-sentinel head, zero word, unreadable word, unresolvable height — is `not_determined`, and **an enumerated non-empty array is never published from the head word**. `protection_is_upper_bound` is `true` (proven module present ⇒ demote the k/n credit) or `not_determined`, **never `false`**: "no module ever enabled" needs a warm `EnabledModule` cursor from creation. `guard ∈ proven_address / proven_zero (1.3.0, 1.4.1 only) / feature_absent (1.1.1 — the slot is unused storage there) / not_determined`. **B14: 1 module-bearing Safe, reach 4 rows, `protocol_id IS NULL` — cite, never calibrate.** Full entry: `SCORING_INVARIANTS.md` B10.1a |
| `role_definitions.role_name` | 19 rows / 11 protocol-1 | CONF | **CORRECTED 2026-07-30 (D6-reject): ids 1 and 19 were ERC-7201 storage-layout pointers, not roles, and are no longer written.** A `bytes32` constant is admitted only where it is witnessed as the **KEY of a persisted mapping**: `kind=="membership"` **AND** `set_descriptor.kind=="mapping_membership"` **AND** empty operand `member_path` — the in-contract `_roles[ROLE][account]` read. **Cross-contract role checks mint no row, including a genuine `hasRole(bytes32,address)` registry:** the callee's signature/selector come from `ir.function.full_name` (`predicates.py:2338`), the CALLER's declared interface, not a proven property of the deployed callee — a slot lens, a merkle tree, or a `hasRole` that ignores its `account` argument all lower identically under that name, each measured minting a non-role constant. Argument position adds nothing (`key_sources` is built from every call argument). Zero measured cost: the `external_set` descriptor count over the 19 rows is **0**. Row absence is `not_determined`, never "no roles" — that also covers the 50 role-keyed gates carrying the role as a `view_call`/`parameter` operand. **Banned:** the `_is_storage_layout_constant` name-suffix guard (wrong both ways) and gating on `storage_var=='_roles'`/`enumeration_hint` (drops 5 real Lido roles). Full entry: `SCORING_INVARIANTS.md` B4c |
| `details->'owners'` **pairwise intersection** | 11 Safes, 11 pairs | REQ | **mandatory, not optional.** Independence is a property of owner **key sets**: P and U are independent iff `\|owners(U) \ owners(P)\| ≥ threshold(U)`. Comparing principal *addresses* publishes a protective credit for a configuration where 4 keys freeze $3.5B and hold it. Publish the **minimum coalition size**, never a boolean. All 3 overlapping pairs can both act-as and block both Safes |
| `details->'trace'[*].step` | 6 steps | REQ | provenance tiers: event folds (622 rows) > live getter/slot > `param_keyed_mapping_enumeration` (the only `lower_bound` rows) |
| `details->'trace'[*].basis` | 33 | GATE | accessor-NAME bases publish `exact`+`enumerable` — **maximum strength** — while the binding is a name match. Read `basis` and tier every name-matched arm below `abi_auto_getter`. **Two vocabulary epochs:** the 33 persisted rows carry the pre-A3 `internal_accessor_convention`; rows written after A3 carry `standard_namespaced_accessor` (ERC-7201 accessor-table match) or `deunderscore_convention` — split so a consumer can tell them apart, **not** ranked against each other, and `auto_getter` renamed `abi_auto_getter`. A scorer must seat **all** of {`internal_accessor_convention`, `standard_namespaced_accessor`, `deunderscore_convention`, `slot_name_keyword`} in the weak tier and default an unknown label to the weakest. All 33 also carry `live_getter_resolution`, so none rests on the convention alone |
| `function_principals.details->>'authority_basis'` | 0 (prospective) | GATE | the same basis hoisted **top-level, beside `membership_quality`/`confidence`**, so the strength gate travels with its payload. Emitted only for a single-member set named by exactly one basis step with no other member-attributing trace step; unrecognised/legacy labels are **not** passed through (key absent). Absent = `not_determined` = **weakest**, never `abi_auto_getter` |
| `function_principals.details->>'accessor_slot_agreement'` | 0 (prospective) | CONF | always `not_determined`, published on the name-matched arms so the open residual (does the matched accessor read the storage the canonical getter reads?) is stated rather than left looking settled. A slot differential is unrunnable on 2 of 3 runtime addresses here and non-identifying on the third |
| `details->>'membership_quality'` / `'confidence'` | 863 exact / **7** lower_bound | GATE | must gate **non-empty** sets too, not only empties |
| `details->'trace'[*].probe_block` / `fold_frontier` / `candidate_count` | 141 safe / 108 timelock / 47 eoa / **0 contract** | REQ | the observation block — inv.11 replayability. Co-occur as one atomic block |
| `capability_expr->'members'` cardinality | 1:1 on 643/643 | REQ | breadth. Two rows have 10 holders each; `max(weakness)` is a floor that discards it |
| `effective_functions.authority_roles` | 824 arrays, 643 empty, 181 with a role | REQ | inv.13 aggregation unit. Key must be **(registry_address, role)** — a Solmate role integer is meaningful only per registry. `principals[*].resolved_type` is NULL on all 211; resolve through `function_principals` |
| `details->'trace'[*].role_labels` | 296 | REQ | keccak-id → source constant, read from the registry. Not inferred |
| `controller_values.{source,value,resolved_type,authority_provenance,observed_via,block_number}` | 290 rows | REQ | `authority_provenance='caller_gate'` means a lowered predicate-tree leaf provably gates on that variable; the key is **omitted** when unanswered, so absence is a real third state. Proves the whole registry root. **Caveat: `block_number` is not the evaluation height** (reads use `"latest"`) |
| `control_graph_edges.relation` | 5,030 | REQ, **whitelist** | admit `controller_value`, `role_principal`, `mapping_member`. **Exclude** `safe_owner` (one owner does not satisfy k-of-n) and `controller_value_unattributed` (CONF, not zero) |
| `control_graph_nodes.analysis_state` | 39 failed / 29 depth-horizon | CONF | only those 68 can improve; `not_analyzable` (1299) is terminal and must not count as improvable |
| **timelock ⊂ proposer collapse** | — | REQ | the proposer Safe is the sole PROPOSER and sole EXECUTOR, so upgrade-by-timelock ⊂ exec-by-proposer. Collapse in the **aggregation key**, severity = **max**. Two rows otherwise charge the same $4.06B twice |
| **inv.5 direct-path discount** | — | **partly closed 2026-07-30 (C4 / Unit 8)** | the 4/7 Safe directly gates all 16 contracts the 2-day timelock gates. Who **executed** each upgrade is now witnessed per transaction (`upgrade_transactions.executor_kind`, §13) and a direct-Safe path is published where it was exercised (`direct_upgrade_witnessed_at_block`). What stays a **gap**: who *authorised* it — `authorising_eoa` is `not_determined` on all 68 transactions, `tx.from` being the submitter (5 distinct relayers measured over the 11 `ExecutionSuccess`-bearing transactions on one Safe) — and whether the direct path is open *now*, which history cannot show. `timelock_is_decoy` therefore stays `not_determined` on all 24 proxies and the delay is neither credited nor discounted on this evidence |

## 5. Freeze

| field | pop. | status | notes |
|---|--:|---|---|
| `observed.pause_effective` | 4 of 36 | REQ | fork proof the latch took effect. **Gate the value membership on it** — charging an entity whose latch is unproven is the balance-sheet error |
| `observed.observed_blast_radius[]` | 4 non-empty of 63 | REQ | key present on 63/63, `[]` on 59 — a non-empty count, not availability |
| `effect_verdicts.witness.scored_denominator[]` | present 63/63, non-empty **28** | REQ | static's predicted guard set. **5 of 33 entries are source-level type names matching no `abi_signature`** — normalise and surface unmatched, don't drop. Remove the recovery path **structurally** (functions carrying a `pause.*` claim), not by name prefix. Label the result a **coverage fraction, not a value fraction** |
| `witness.pre_pause_succeeding[]` | 63/63 | REQ | the measured live surface. Caller is an **unauthorized sentinel**, so it is a lower bound and includes no-ops |
| `observed.duration_bound_seconds` + `auto_expiry` | 0 populated | GATE | trust the bound as a reducer **only when `auto_expiry is True`**; `False` means the fork contradicted the static constant |
| `observed.duration_bound_source` | 4/4 `not_determined` | GATE | **not** "indefinite". `no_time_reference` (proven indefinite) and `guard_constant` never appear, so **duration contributes zero to severity** in either direction |
| `pause.unset` claims + their principals | 30/30 contracts | REQ | the recovery path, resolved **per pauser key set**. `pause.unset` has no behavioural witness — the static claim is the correct available evidence but is not a fork proof |
| `claims[].witness.polarity` | **75/79** | CONF | the 4 missing are exactly the 4 fork-witnessed `pauseUntil` claims. **Do not gate on it** — key on `claim_id`, which covers 36/36 |
| freeze value reduction | — | REQ | **SUM over distinct entities** (pausing two contracts is not a choice), with MAX per (entity, asset) inside. Membership gated on `pause_effective` |
| `no_blast_radius_observed` | 29 | CONF | does **not** prove those functions are not freezes: subjects are admin setters with no claims, `scored_denominator` is empty on 26 of 29, and the producing code says "correct to leave unknown" |

## 6. Preconditions — read `effective_functions.conditions`, never the display copy

Real population (the register's own B6 table was measured from the **banned** copy):
`business` 2089 · `time` 153 · `denylist` 28 · `one_shot` 23 · `self_service` 15 ·
`pause` 13 · `reentrancy` 9 · **`permit_sig` 7** (a kind the register omits).

| kind | status | notes |
|---|---|---|
| `one_shot` + `latch_state` | REQ, **selector-level** | `consumed` is a pinned live `eth_getStorageAt` at the runtime proxy, fail-closed to `indeterminate`. The strength fields are no longer dropped — see `latch_witness` in §6b (0/39 today; they land on the next resolution pass, and every currently stored row must be read as the weakest branch). Do not generalise to contract level — only `_disableInitializers()` proves that, and it fired 0 times |
| `time` | REQ | structure, **not a duration bound**. Licenses no numeric credit |
| `pause` | CONF | 13 entries carry **both polarities**, and polarity lives only in free-text `description`. Not creditable without text parsing (inv.2-banned) |
| `self_service` | REQ | caller may act only on their own position — not privileged (inv.3) |
| `reentrancy` | REQ | structural. 9 entries, **2 contracts** |
| `denylist` | **CONF, not a guard** | all 28 read `"at least 0 excluded; not exhaustive"` — a lower bound with zero known members. Crediting it credits an empty set |
| `business` | CONF | free-text `require`; 102 of 2089 are opaque `REF_nnn` placeholders |
| name channels | CONF w/ residual | `one_shot`'s `_initializing` and `permit_sig`'s 5 canonical signatures are closed, standard-anchored exact matches — admissible with the residual stated |

## 6b. One-shot latch witness — `conditions[].latch_witness` (A1 / Unit 1)

Mirrors `SCORING_INVARIANTS.md` **B15** (normative). JSON path:
`effective_functions.conditions[] where kind='one_shot' → .latch_witness`, served
verbatim by `analysis_detail.py:434-436`. **Population 0/39 today** — the keys
appear on the next resolution pass only. `latch_state`/`latch_value` are
unchanged on every row (6/6 rows re-run through the production path reproduce
byte-exactly at pinned block 25643300; all 39 conditions replay from their
job-artifact descriptor + stored `latch_value`, 39/39).

**Realized bases, measured through the resolver's own load path**
(`get_artifact(session, analysis_job.id, "predicate_trees")`, tree keyed via the
artifact's `canonical_signatures` map): `guard` 6 · `version_ge` 32 ·
`sentinel` 0 · `value_gt_zero` 0 · **zero-decisive-descriptor 0**, over 38
functions. Lane-A's "6 not recoverable" was measured through
`contract_materializations` — the wrong surface (no row for 3 of the 4
protocol-1 addresses; `EigenStrategy`'s trees keyed by Slither `full_name`, not
`abi_signature`) — and is withdrawn. See B15.

**An absent `latch_witness` is the third state**, not a defect and not a
negative: no latch was read (RPC failure, unreadable slot, no decisive latch, or
a pre-change row). Read such a row as the **weakest branch** that could have
produced its `latch_state`. Every failure / revert / absence path in the producer
lands here or on `latch_basis: "not_determined"`.

| field | pop. | status | three-state, and where failure lands | consume as |
|---|--:|---|---|---|
| `latch_basis` | 1/1 with the witness | GATE | `sentinel` / `version_ge` / `value_gt_zero` / `guard` / **`not_determined`**. An unfoldable guard — any classification failure — lands on `not_determined`, never on a branch label | gate + cite. **No ordering over the four bases** may be published as measured |
| `probe_block` | only when a height was pinned | GATE | absent = the read used `latest`, so it has no reproducible height and must not be credited (inv.11/12) | gate + cite |
| `probe_address` | with the witness | REQ | the **runtime** address the read hit, never `contracts.address` | cite |
| `raw_word`, `read_kind`, `getter_selector` | with the witness; selector only on `read_kind='getter'` | CONF / trace | the returned word, verbatim, plus which read returned it — so a getter answer is never attributed to `slot` | cite (replay input) |
| `standard` | with the witness | GATE | the latch family; with `latch_basis` this is what stops `latch_value` reading as an OZ version everywhere | gate |
| `slot` | with the witness | REQ | keccak-anchored or layout-derived | cite |
| `byte_offset`, `size_bytes` | often neither on `guard` rows | GATE | **absent = no byte range**, so `latch_value` is the whole word. The sentinel test is keyed on `size_bytes`, so a range-less descriptor can never be `sentinel` — 255 is one only for a 1-byte latch | gate + three-state |
| `value_type` | absent on `unstructured_slot_latch` | CONF | **does not** on its own fix the `latch_value` mis-typing: it is absent exactly where it is worst (Lido's Aragon block number) | cite + three-state |
| `role` | `version` on standard arms only | CONF | the static pass's **claim**, not an independently verified fact | cite |
| `variable` | with the witness | CONF | referent varies by `standard`: state variable, **getter** name, or **modifier** name (Lido's is `"onlyInit"` — a modifier) | cite only; gating on it is inv.2 |
| `guard.operator`, `guard.constant` | on `guard`-basis rows | REQ when `latch_basis='guard'` | `constant` absent for `falsy`/`truthy`, which take none — never a defaulted 0 | gate + cite. The only thing separating FiatTokenV2_2's `initializeV2`/`_V2_1`/`_V2_2`, all `consumed` at `latch_value=3` behind `eq 0`/`eq 1`/`eq 2` |
| `expected_version` + `expected_version_basis` | both or neither | CONF w/ residual | bases `oz_reinitializer_argument_literal` (AST literal) and `oz_initializer_modifier_standard_constant` (the standard's 1, never read from source). Both match the closed `INITIALIZER_MODIFIERS` **name** set — the residual. A descriptor with no basis (every pre-change row) publishes **neither** key | cite. Never inferred from `latch_value` (banned) |

**Permanence.** `latch_target='db_linked_proxy'` on 39/39, so `consumed` is a
mutable now-fact: present it as "consumed at `probe_block` on `probe_address`;
re-openable by the upgrade authority of that proxy". **Who can re-open is
`not_determined`** and is not published. `site/src/protocolScore.js:239`
(`isInertOneShot → 0.95`) currently credits it as permanent — an inv.10 violation,
not fixed by Unit 1, recorded as the scorer's obligation.

**Small-pop (B14), none may calibrate:** `guard` 6 rows / **0 at protocol_id=1** ·
`sentinel` 0 · `value_gt_zero` 0 · Aragon-block-number type 1 (ef 2120) · bool
type 1 (ef 786). The protocol-1 population is **22 rows, all `version_ge`**.
With two bases at zero rows, **no reliability ordering over the four is
measurable here.**

## 7. Proof-strength gates

| field | pop. | status | notes |
|---|--:|---|---|
| `effect_verdicts.verdict` | proven 69 / unknown 205 | GATE | only `proven` admissible. All 205 unknown are unreferenced by claims; the projection is sound |
| `effect_verdicts.tier` / `witness.verdict_tier` | tier1 207 / tier2 67 | GATE | |
| `witness.observation` | executed 179 / reverted 95 | GATE | all 95 reverted are already `unknown`, so the `{"value_moved": false}` trap has no live instance |
| `claims[].witness.effect_verdict_id` | 69 distinct | REQ | the join key for every B2/B3 field not projected |
| `claims[].tier` | 353/100/69/19 | REQ, **cite + three-state only** | never multiplies severity. May **withhold** an escalation needing a behavioural proof (`caller_arbitrary`); `policy_derived` must **block** the static conjunction. Never raises |
| `effect_verdicts.witness.revert_reason` | 39, **21 distinct concrete values** | CONF | not "all unknown". A decodable 4-byte selector separates "the gate rejected the caller" from "a business precondition was unmet" — a re-probe queue |
| `effect_verdicts.transcript_ptr` | 274/274 | CONF / trace | resolves via `(job_id, name)` → `artifacts.storage_key`; genuinely human-checkable. 271 distinct (5 rows share a blob) |
| `effect_verdicts.witness.block_number` | **0/274, key absent** | CONF, **three-state** | CORRECTED: the earlier "304/304, 51 distinct blocks" row was wrong on both location and denominator. `witness`'s key universe across the 274 rows is 20 distinct keys (per-row 2–10), none a block key; the 304 figure counted **transcript blobs**, which do carry it (51 distinct heights, min 25640764, max 25641259, span 495 blocks in one run; 7 jobs carry two heights each, so the pin is per stage INVOCATION, not per job). Now emitted by `harness._stamp_observation_height`. **proven-present** = a positive height the probe demonstrably ran at (Tier 1 simulates at `hex(block_number)`; Tier 2 reports the `--fork-block-number` its fork was spawned with). **proven-absent does not exist** — there is no such thing as a verdict observed at no block. **not_determined = the key is ABSENT**, and that is the reachable state on every failure/absence path: an unpinnable head (`_preflight` returns the `0` sentinel and Tier 1 is disabled), a fork spawned unpinned, a Tier-0 index read (no single height), and a twin's plain cache hit (state-plane key, stripped on the cache write). **`0` is never published** — it is the failure sentinel and forks at genesis. Consumption: **cite + three-state**; never arithmetic, never a gate. All 274 pre-existing rows stay `not_determined`; the 78 Tier-2 rows' true heights are unrecoverable and nothing is back-filled. Small-pop flags: the 4 freeze rows (137/149/173/219) and the 7 two-block jobs are named as instances only — the fix is argued from the code contract (an unpassed `--fork-block-number`), never calibrated on their count (B14) |
| `effect_verdicts.witness.block_source` | **0/274, key absent** | CONF, **three-state** | New, beside `block_number` and **only ever with it** — a height without the scope of the pin that fixed it cannot be compared across rows. Closed vocabulary `config.BLOCK_SOURCES` = `invocation_pin` \| `job_pin` \| `run_pin`; an unrecognized value publishes nothing. **proven-present** = the named scope the height is shared across. Only `invocation_pin` is emitted today (one `eth_blockNumber` per effects-stage invocation), and it explicitly does **not** make a run coherent — one run spanned 51 heights. `job_pin`/`run_pin` are reserved and unemitted: a per-run pin needs a run/batch column `jobs` does not have. **proven-absent does not exist**; **not_determined = ABSENT**, on exactly the same paths as `block_number` (the two keys are stamped and stripped together). Consumption: **three-state + cite** — a consumer may only treat two verdicts as one world state when both carry the same height AND a scope that spans them; it must never read an absent scope as "current". Small-pop: same 4 freeze rows / 7 two-block jobs, instances only (B14) |

## 8. Audit and change management

| field | pop. | status | notes |
|---|--:|---|---|
| `equivalence_status = 'proven'` | 36/209 | REQ | the admissible core, **and the whole of it** |
| `matched_commit_sha` | 36 | REQ | the sha printed verbatim in the PDF |
| `bytecode_keccak_at_match` | 201/209 (36/36 within proven) | REQ | join to `bytecode_cache.code_keccak`: 33 still matching / 0 replaced / 3 no cache. **`bytecode_cache` has no block**, so the honest claim is "matches the bytecode cached during this run", not "deployed right now". Survives as a deterministic negative generator |
| `equivalence_status` (non-proven) | 117 / 45 / 10 / 1 | REQ | three epistemic states: our-side gap 162, **deployed source provably differs 10**, infrastructure 1. inv.6 promote-or-clear |
| `equivalence_reason` | 209/209 | CONF | **free text, ~59 distinct values** — branch on `equivalence_status`, cite the reason |
| `covered_from_block` / `covered_to_block` | 150 / **12** | GATE, withhold-only | usable closed interval is **8 rows / 4 contracts sharing one block value**. Only ever withholds a credit |
| `audit_reports.classified_commits` | 60/67, 183 entries | **BAN** | LLM commit-role labels |
| **`proof_kind`** | 36 populated, 3 of 4 values n=1 | **BAN, all four values** | `clean` and `pre_fix_unpatched` are opposite branches of one `if` over the same LLM labels, and the sha compare is a fuzzy 7-char prefix. Only `unclassified` is LLM-free and it carries no information |
| `upgrade_events` | 120 rows / 24 proxies — **96 upgrades + 24 deployments**, over **68 transactions** | REQ | deterministic `getLogs` of `Upgraded`/`AdminChanged`/`BeaconUpgraded`. `old_impl` is NULL 120/120 **by construction** — derive predecessors by ordering on `block_number`, never by diffing the column. **Two counting corrections (2026-07-30, C4 / Unit 8):** a proxy's own creation emits `Upgraded`, and all 24 proxies carry exactly one such row, so **every per-proxy count drops by exactly one** — EtherFiNodesManager **18→17**, LiquidityPool **17→16**, Liquifier **8→7**, EETH **6→5**, and the three single-row proxies `0x2b90103c` / `0x4a84ba0b` / `0x5585996e` **1→0**, leaving **96 real upgrade EVENTS across 21 proxies** — which are **93 ACTIONS** summed per proxy (`0x8f08b704` 6 events / 4 actions, `0xdadef1ff` 5 / 4) over **44 distinct non-deployment transactions** protocol-wide. The published `upgrade_count` is the **action** count. And the unit of an upgrade count is the **transaction, not the log**: `0xc9c80e5b…` carries 19 protocol-1 events across 19 proxies and is **one** governance action (the register's "11 proxies on 2026-07-14" was also wrong — 19). Count via `upgrade_action_counts` / `governance_actions_for`, never `COUNT(upgrade_events.id)` |
| 18 contracts with audit rows and 0 proven | — | CONF | must read **unknown**, not 0 (inv.1). `max(proven firms)` is 1 on every contract while `all_firms` reaches 7 |

## 9. Earned negatives — publish as findings with a counterfactual, not dismissals

| fact | pop. | status | notes |
|---|--:|---|---|
| `capability_expr` `finite_set` + `members=[]` + `exact` + `enumerable` + 0 principals | 52 | REQ | "no resolved caller can reach this". Verified 50/50 against live authority state. **Do not re-derive this gate** — read the served `exact_empty_credit` (B16.3), which requires `exact`+`enumerable`, an **allow-listed** coverage-proving trace step (presence of *a* step is not a witness), an observation block that is **not** `last_indexed_block`, and an **allow-listed** read-confirmed `empty_reason`. `0 of 86` such rows are `earned` today |
| — disposition | — | REQ | **not a dismissal.** All 10 registries have `authority=0x0` with owner = the 4/6 Safe, so **two transactions re-enable any of the 50**. Publish "currently unreachable; re-enablable by \<principal\>" with the counterfactual |
| — axiom | — | REQ | state it: with `owner == 0x0` the owner disjunct is `{0x0}`, a **singleton**, not `∅`. Sound on mainnet only because `msg.sender` can never be `0x0`. A differential prober without an explicit `from` override **inverts this on all 52** |
| — as-of block | 0 persisted, **prospective** | GATE | ~~dropped by the `finite_set` combinators~~ — **FIXED (Unit 2 / A2).** Nine of ten mint sites now carry `last_indexed_block` + inherited `empty_reason`, fail-closed (**every** operand must carry a height, else absent). New `exact_as_of` is the only key that may be read as "the set was exactly this at block B", and only on **equal** operand heights; the MIN is a staleness floor and cannot be promoted — both fold families publish state-AT-h with revocations applied, so "empty at MIN" is false across heterogeneous heights and **inverts** on the subtractive paths. Realizable population **≤25** rows (8 provable candidates); the **261 solmate rows gain nothing** — their live-getter operand is blockless by construction. See B16 |
| `controller_values` `owner` + `resolved_type='zero'` + `caller_gate` + `observed_via='eth_call'` | 22 rows / $94,026,174 | REQ | verified 22/22 on-chain. **Exclude any `observed_via='eth_call_impl_fallback'` row** — impl storage reads as zero. The "raises" direction (an affirmative irreversibility witness) has **population 0** |
| `indexed_event_cursors.backfill_complete` + `last_indexed_block` + hash | 80/80 warm | GATE | bounds the range from **above only** — **five limits**, of which 1 and 5 fail on all 80 legacy rows |
| — limit 4 (**the one the register missed**) | — | GATE | absence is proven for a state variable only if **every topic that can write it has a warm cursor**. **`not_determined` (U10A): no proven inverse index exists** — writer hints attach only to caller-keyed mappings, `mapping_writer_events` is declared-never-populated, `effect_tags.writes[]` is banned. Measured surface: 6 denylist topics × 4 emitters = **24 pairs, 4 enrolled**; `AllowTo`/`DenyTo` have **0 cursors at all 4 emitters**, and 3 of 4 emitters have 0 cursors of any kind. ~~Two of six denylist writers have no cursor~~ understated it |
| — limit 5 (**U10A, new**) | 0 cursors page-complete | GATE | a 200-OK page at the upstream's result cap is now a REJECT that bisects, and `max_window_log_count` + `window_stats_cap` + `window_stats_basis` are persisted. Shipped cap **unset**, so **every** event-absence negative carries an unquantified residual. eRPC `getLogsMaxAllowedRange` measured at **2,000,000 on the inclusive count** (`toBlock−fromBlock+1`), loud `-32012`; no truncation to 125,629 logs/window; genesis-anchored requests bypass the guard yet matched a 1M-chunked fold byte-for-byte and fail loud at ~82k. A mutable now-fact, not an invariant |
| — limits 1–3 | — | GATE | limit 1 **partly closed (U10A)**: `first_indexed_block` + `first_indexed_block_basis` persisted, citable only on basis `creation_block_minus_one` (three pinned reads: code empty at `B−1`, non-empty and not a 0xef0100 EIP-7702 stub at `B`, and zero logs genesis→`B−1`). NULL on all 80 legacy rows, deliberately un-backfilled — must read as "lower bound unknown", **never 0**. Limits 2–3 stand |
| `indexed_event_cursors.first_indexed_block` + `_basis` | 0/80 | GATE | three-state `{creation_block_minus_one, explicit_seed, not_determined}` + NULL (predates column). **Revert/failure/absence → `not_determined` with the block discarded.** `explicit_seed` has population 0 (no production writer). Consume: **cite** + **gate** (U7B `holder_set_exhaustive`) |
| `indexed_event_cursors.enrollment_basis` | 0/80 | GATE (**allow-list**) | exactness permitted **only** for NULL (legacy) or `predicate_tree_hint`; `tracked_topics_asserted`, the literal `not_determined` default, and any future token are all refused at `event_logs_pg._cursor_state` and at the two out-of-band readers. A deny-list here would fail open on the `not_determined` default that `enroll_event_cursor` already writes. Consume: **gate** |
| — B5 denylist withdrawal, enforcement gap | 4 cursors on `0x4de413a2` | **stated, not enforced** | those cursors predate the column so their basis is NULL and the allow-list still admits them: the resolver can **still** mint the exact empty the B5 row declares `not_determined`. Closing it = the limit-1 stated deferral (demotes all 80 legacy rows, collapses the 52 exact-empties above), not a U10A change |
| `absence_coverage` object | per (chain, address), computed | GATE (CONF payload) | `enrollment_complete` and `earned_negative_admissible` are **hard-wired false**; `write_surface_basis` is **always `not_determined`**. `write_surface_topics` supplied by a caller populates `enrolled`/`missing`/`blocking_reasons` **for reporting only** and changes neither verdict. Small-pop **4 / 3 addresses — B14, no calibration** |
| `monitored_contracts.monitoring_config.tracked_topics[].effect_tags.writes[]` | 224 entries | **BAN as a topic→variable map** | it is a **union across all emitters** of a signature, so reading it forward attributes a write to the wrong event; and it deliberately skips every standard governance topic |

## 10. Banned, with cause

| field | why |
|---|---|
`effective_functions.effect_targets` | a display projection built to be a **prose sentence** (`_action_summary`) and then persisted as a column; 288 of 1,056 protocol-1 rows are call heads only. Use `state_writes` / `sinks` / `state_changing`
`control_graph_edges.relation='external_call_target'` | not a control edge; 50 targets hold **$180.59B** (WETH, stETH, Lido, the ETH2 deposit contract). Exclusion is load-bearing
`contract_dependencies` (all relations) | **the same $180.6B under a second name.** `regular` mixes protocol-owned Boring contracts with WETH9 so the label discriminates nothing; `implementation` ($4.15B) is a double-count of value already inside the perimeter; `library` is documented-heterogeneous
`principal_labels.label / display_name / confidence` | minted as `f"controller_{_slug(edge.label)}"` from a **state-variable name**; `confidence` is display-name confidence. 73% of *rows* are structural and separable by a 14-value allowlist, but the clean subset just restates `control_graph_edges.relation` — use the edges. New hazard: `authority_controller`/`owner_controller` (211 rows) are minted by a literal string compare and published at confidence "high"
`role_definitions.role_name` | ~~mis-parses ERC-7201 slot constants as roles~~ — **mis-parse FIXED 2026-07-30 (D6-reject); see §4.** Still not a scorer input on its own: the 9 real names are **not** in the authority plane by name or keccak — `authority_plane_coverage: not_determined`, a coverage gap and never "no roles"; the grants are witnessed in `indexed_event_logs` and unused
`dapp_interactions.method_selector / data / value` | transaction-shaped columns holding scrape provenance (JS-bundle filenames, source URLs); 0 rows match any `(deployment_address, selector)`
`contract_summaries` | IR-derived, not LLM, and genuinely three-valued — but **redundant**: `is_pausable` agrees with "has a `pause.set` claim" 64/64, and that agreement is partly tautological (a claim *causes* the flag). `standards` is entailed by `claim_id`. Third state is an **absent row**, not NULL
`function_principals.details.conditions` | a lossy display copy — a strict **subset** of the parent on all 32 differing rows, missing an entire condition kind in aggregate
`effect_transcript_*.foundry_version` | byte-identical to `anvil_version` on all 78; reading them as two agreeing sources is fabricated corroboration
`rate_limit` witness (`capacity`, `refill_rate`, `bounds_total_extraction`) | all `not_determined` 10/10 while `mandatory='proven'`; the witness's own text refuses a severity conclusion. Live temptation: mandatory on a $467M function
`effect_verdicts.current_check_passed` · `bytecode_cache.selfdestructed_at` · `upgrade_events.old_impl` | 0 populated / NULL by construction
`tx.from` as the upgrade's authoriser (any shape: `receipt.from`, `eth_getTransactionByHash().from`, an `eoa_one_hop` executor kind) | it is the **submitter**. 11 of the 15 `ExecutionSuccess`-bearing transactions were relayed to one Safe by **five distinct** senders (those 11 are precisely the ones that are NOT `safe_direct` — their emitter is unclassified, so the verdict is `not_determined`). Even where `receipt.to == proxy` it proves only msg.sender in the **top-level frame** — not msg.sender at the upgrade site, and nothing about what the guard reads. Publish `top_level_msg_sender` and stop there
`timelock_is_decoy` from "no direct upgrade after the first timelock-routed one" | absence of an observed bypass is not proof no bypass exists. Zero-after-first holds on all 8 dual-class proxies and licenses nothing. Only the positive `direct_upgrade_witnessed_at_block` is publishable
`semantic_functions[].contract` (declaring contract) | the code-factoring information inv.13 requires the score to be invariant to

## 11. Product-vs-privileged

`claim_id ∈ PRODUCT_CLAIMS` is **not** name inference — `erc20.transfer` requires structural `is_erc20` **and** a keccak selector identity. But `claim_id` does not prove permissionlessness. **Gate on `authority_openness = 'open'`; `not_determined` is not product.** Two counter-examples exist. Note `supply.mint`/`supply.burn` sit in the same list: harmless here, but an EOA-gated `mintShares` on a $3.5B token would be dropped silently.

## 12. Upstream fixes that gate witnesses

The pipeline computes proof-strength gates and **discards them at the persistence boundary**. Until these land, three earned negatives are not replayable from stored inputs:

1. ~~**One-shot latch**~~ — **LANDED (Unit 1 / A1).** `conditions[].latch_witness` now carries `standard`, `slot`, `byte_offset`, `size_bytes`, `value_type`, `role`, `variable`, `guard{operator,constant}`, `expected_version`+`expected_version_basis`, `probe_address`, `probe_block`, `raw_word`/`read_kind`, and the `latch_basis ∈ {sentinel, version_ge, value_gt_zero, guard, not_determined}` discriminator. See §6b / B15. Keys are absent, never null, where the producer had nothing. Every one of the 38 one_shot functions has a signature-exact decisive descriptor on the resolver's job-artifact path, so none is blocked for want of one; when a given row gains its witness depends on when that job is next re-resolved.
2. ~~**Exact empty caller sets**~~ — **LANDED (Unit 2 / A2).** All nine height-bearing mint sites in `capabilities.py` carry `last_indexed_block` (fail-closed MIN) and inherited-only `empty_reason`; the tenth (`negate(external_check_only)`) is a stated non-site. `_live_authority_result` and `_live_resolve_authority_slot` now publish their read (`step`, selector/slot, contract, and `observed_at_block` **only when pinned** — the `"latest"` path publishes no block), with `owner_read_zero`/`slot_read_zero`, the burn address split off the zero shape, and the `empty_by_design` **default argument** removed. New `exact_as_of` (int / `"not_determined"` / absent) and the served `exact_empty_credit` gate. See B16.
3. ~~**Accessor-convention principals**~~ — **LANDED (Unit 2 / A3).** `details.authority_basis` is published top-level beside `membership_quality`/`confidence`, the conflated label is split into `standard_namespaced_accessor` / `deunderscore_convention` at the write point (by which helper produced the selector), `auto_getter` → `abi_auto_getter`, and `accessor_slot_agreement: not_determined` is stated on the name-matched arms. Only `abi_auto_getter` is ranked above them; the two are mutually **unordered**. The scorer's `WEAK_RESOLVER_BASES` was extended in the same change to seat both epochs — a rename that detached the tier map would have silently un-weakened all 33 rows.
4. ~~`contract_balances` — add `block_number`, and stop the destructive delete+reinsert.~~ — **LANDED (Unit 4 / B1+B2).** `observed_address`, `block_number`, `price_block_number`, `fetch_id`; the new `contract_balance_fetches` plane carrying `native_status` / `asset_set_status` / `asset_page_length` / `writer`; insert-only writers with a `contract_balances_latest` view and **every reader migrated in the same commit**. The 1,617 pre-existing rows stay `block_number NULL` forever — the height was never observed and no backfill can invent it. See §1 and B8.1a. **Two deferrals carried:** ERC-20 quantities stay UNPINNED, so `block_number` lands on native rows only and every token row keeps `NULL = not_determined` (re-sourcing moves 571 money figures per cycle and needs its own per-sub-call three-state — a capability deferral, not an epistemic one); and `tvl.py:348`/`:429` still accumulate with `if usd:`, dropping a genuine PRICED `usd_value == 0` exactly as an unpriced NULL — pre-existing, orthogonal to provenance, not repaired here.
5. `effect_verdicts` — pin fork observations to one block per run, or publish the per-verdict block as part of the witness identity.
6. **2-day timelock** (`contracts.id=11`) — 0 `effective_functions` while gating 53 rows across 16 contracts. Cheapest fix to the largest weakest-path blind spot.
7. ~~**Safe modules and guard**~~ — **LANDED 2026-07-30 (C1).** Two `eth_getStorageAt` plus `VERSION()` after `kind=='safe'`, at a pinned height, published as `details->'safe_protection'` (§4). NOT via `getModulesPaginated` in `_CLASSIFY_PROBE_SIGS` — those calldata builders cannot pass arguments. k/n is an upper bound **in fact**, not in principle, on 1 of the 19 Safes.

## 13. Upgrade executor fold — `upgrade_transactions` (C4 / Unit 8)

Per **distinct transaction**, from that transaction's own receipt (one
`eth_getTransactionReceipt` per `tx_hash`; a mined receipt is immutable, so this
is one-time). Normative entry: `SCORING_INVARIANTS.md` **B17**.

**The row's existence is the coverage discriminator** — a row means the receipt
was read and decoded; no row means never read or read failed. Do not read a
missing row as any polarity.

| field | pop. | status | notes |
|---|--:|---|---|
| `governance_action_id` (= the PAIR `(upgrade_transactions.chain_id, .tx_hash)`) | 68 tx / 120 events | REQ | **the unit of an upgrade count.** `0xc9c80e5b…` is 19 events across 19 proxies and ONE action. `governance_actions_for` returns `set[tuple[int, str]]` — the bare hash is not the id, since the same 32 bytes can name a different transaction on another chain (#158). Count with `governance_actions_for` / `upgrade_action_counts`, never `COUNT(upgrade_events.id)` |
| `executor_kind` | 3-valued, never NULL | REQ (gate + cite) | `timelock_routed` / `safe_direct` / `not_determined`. A positive needs three things at once: a keccak-matched marker log, an emitter the **persisted classification plane** independently typed, and a provably complete log set. Unclassified emitter ⇒ `not_determined` (the 11 measured transactions on the unmodelled Safe `0xf155a263…` are exactly this) |
| `executor_address` + `executor_classification_source` + `executor_classified_type` | iff kind positive | REQ / GATE | a CHECK constraint makes the gate inseparable from the payload |
| `executor_classification_block` | **0 today** | REQ | `not_determined` on every current row; from B10.1a's `safe_protection.probe_block` going forward. Why it matters: the kind asserts the emitter is typed a Safe/timelock **by our classifier**, not that it was one at the upgrade's block |
| `executor_call_targets` → `executor_call_targeted_proxy(tx, proxy)` | gated on `timelock_routed` | REQ | the `target` word of each `CallExecuted`. On `0xc9c80e5b…` **24 of the 26** `Upgraded` emitters are targets — joining every log in the transaction to the executor over-attributes `0x3c55986c…` and `0xd789870b…`. `not_determined` (never `false`) for `safe_direct`: `ExecutionSuccess` carries no target |
| `receipt_log_set_complete_for_tx` | computed | GATE | **computed, never asserted**, and all three must hold: the stored `Upgraded` events appear in the receipt's own logs; the `logsBloom` is **usable** (present, well-formed, and confirming an `Upgraded` log the array carries — the positive control that rules out the all-zero bloom, which is shape-valid and reports every marker absent); and that usable bloom agrees with the array about `CallExecuted`. A bloom has no false negatives, so bloom-absent is then independent proof of absence — which is what licenses `safe_direct`. **Unusable bloom ⇒ not complete ⇒ the absence arm is never licensed** (a bloom-stripped pruned receipt would otherwise mint `safe_direct` over a ground truth of `timelock_routed`). Bloom-present with no such log ⇒ `not_determined` (a pruned array) |
| `receipt_upgraded_counts` | 68/68 | GATE | the receipt's own `Upgraded` count per proxy. The stored rows cannot witness their own under-projection, so the A6 exactly-one-event guard reads the larger of (stored pair count, receipt count). Latent — 0 live instances |
| `is_deployment` (derived, per (tx, proxy)) | **24 of 120** | REQ | two arms, either sufficient: receipt (`to IS NULL AND contractAddress == proxy`, 18) or the **two-witness** creation pair (`getcontractcreation` naming the tx AND `eth_getCode(proxy, event_block−1) == 0x`, 6 — all via factory `0x356d1b83…`). Neither witness alone. A not-determined event **stays counted** |
| `upgrade_count` + `upgrade_count_basis` | per contract | REQ / GATE | an **upper bound**: proven deployments removed, unproven events kept. **Post-exclusion zero publishes `None`**, never `0` — the number is rendered as "N upgrades" and zero would read as an earned negative over a recording surface that is itself unwitnessed (`recorded_event_coverage: not_determined`) |
| `top_level_msg_sender` (derived) | 4 tx | CONF | `receipt.from` where `receipt.to == proxy`. Claim = "msg.sender in the top-level frame". Never "who authorised" |
| `direct_upgrade_witnessed_at_block` | per proxy | CONF | "a direct-Safe path WAS exercised at block B". Says nothing about now |
| `authorising_eoa` | **0/68 ever** | **BAN** | always `not_determined`, published as the literal string so the refusal reaches the consumer |
| `timelock_is_decoy` | **0/24 ever** | **BAN** | always `not_determined`; no column, no computation |

## 14. Per-node restaking position — `restaking_positions` (D1 / Unit 10B)

Per **enumerated node instance** at a pinned block, on its own plane. Normative
entry: `SCORING_INVARIANTS.md` **B19**.

**Separate from `contract_balances` by construction, not by filter.** Nodes are
BeaconProxy deployments with no `contracts` row; every spot-balance reader joins
`contract_balances(_latest).contract_id` to `contracts.id`. No reader was
modified and **no USD column exists on this plane**.

**What a `0` means:** zero EigenLayer beaconChainETH **withdrawable shares** — not
"holds nothing". Measured at 25643300: the 26 enumerated nodes read 0 shares each
while their pods hold **374.148164612 ETH**, one of them exactly **320 ETH**.
Node/pod execution-layer native balances are `not_determined` here.

| field | pop. | status | notes |
|---|--:|---|---|
| `block_number` + `block_hash` | new plane | REQ | every read ISSUED at this height; the hash is the reorg witness. Head or header unreadable ⇒ **no row at all**. No unpinned path exists |
| `eigenpod_basis` | new plane | GATE | `proven_pod_cross_read` needs **all three** legs: `getEigenPod()` == `ownerToPod()`, both non-zero full words, AND `hasPod()` **exactly 1**. `no_eigenpod_proven` needs all three zero/zero/false. Anything else ⇒ `not_determined`. **Two of three never suffices** |
| `eigenlayer_beacon_shares_wei` | new plane | REQ | integer (may be 0) or **0** under `no_eigenpod_proven` (a distinct proven-zero); NULL = not_determined. **A failed read is NULL, never 0** |
| `shares_basis` | new plane | GATE | `eigenlayer_beacon_shares` / `no_eigenpod_proven` (OBSERVING) vs `read_failed` / `not_determined` (NON-OBSERVING, NULL quantity). Reading the quantity without this is non-conformant |
| `shares_strategy` | new plane | GATE | witnessed from `EigenPodManager.beaconChainETHStrategy()` at the SAME block. A **literal is banned**: the near-miss `0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` answers `[0]/[0]` with success, as does a non-staker |
| `deposit_shares_wei` | new plane | CONF | `podOwnerDepositShares`, **`int256`**, stored signed and unclamped. `stakerDepositShares` is the `uint256` one |
| `cross_read_agreement` | new plane | GATE | `agree` / `disagree_within_invariant` (publishes **with** the flag) / `inconsistent` (**suppresses** the quantity) / `not_determined`. An **absent** deposit leg is `not_determined`, never `inconsistent` |
| `active_validator_count`, `last_checkpoint_timestamp` | new plane | CONF | NULL unless the pod is proven (DB-enforced), else a `0` "never checkpointed" could be minted against an address never proven to have a pod |
| `consensus_layer_residual` | new plane | **BAN** as a number | always present, always the string `not_determined`. Unbounded above post-Pectra (up to 2048 ETH per validator). Consuming it as `0` is non-conformant |
| `node_set_completeness` | new plane | GATE | **`not_determined` only**, DB-enforced. The fold proves existence, never absence — any cross-node aggregate is a floor (`>= X wei`), never a total |
| `manager_contract_id` | new plane | CONF | the `contracts` row whose ADDRESS EQUALS the emitting `event_address` (proxy `0x8b71140a…`, id **531**), never the implementation row that carries the name (id 591). Provenance only |
| `restaking_positions_latest` | view | REQ | **the read surface.** Per `(chain_id, node_address)`, latest OBSERVING row wins under a total order. **Absence from the view is `not_determined`, never "no position"** — reading a missing row as `0` reintroduces the absent-row-as-`$0` shape §1 closes |
| **reach on ef 1184 / 2038** | 2 rows | **BAN** | both stay `reach = not_determined`. Attaching the position without a destination witness is inv.16a's sweepETH error (5,188×) in a new place. Row 1184 is the beacon **implementation**, whose own `getEigenPod()` is a 32-byte zero. **The two rows differ:** 1184's `destination_constraint` is `{"state":"not_determined"}`; 2038's is `{"state":"constrained","guard":"external_call_revert","binding":"operand","pins":null}` — a revert-propagation guard pins no destination, so it is not a destination witness either |
| **production writer** | **0 rows published** | **deferral** | the plane has no scheduled writer: nothing calls `read_positions` / `persist_positions` / `enroll_restaking_fold`, and no `PubkeyLinked` cursor exists. Stated with cause in B19 — the periodic step is the one part that cannot be verified without an end-to-end run |
