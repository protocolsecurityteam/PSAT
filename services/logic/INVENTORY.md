# Logic engine inventory for the FORMULA / LIST / CHECK restructure

Read-only inventory of `services/logic` at branch `test/auth-fuzz-restructure` (5d7bca54), worktree
`scratchpad/pr266r`. Line numbers are from that checkout. Classification is against the new design:
FORMULA (lower.py), LIST (snapshot.py + logged.py enumerate keys; evaluate per candidate; split WHO / ARGUMENT /
STATE; compose state reads through write sets), CHECK (one eth_call per principal + one stranger, disagreement =
`engine_chain_disagree` gap). KEEP = as is; ADAPT = needed, role or signature changes; REMOVE = hedge, simulation,
arrangement, provenance rule or label with no role.

Module sizes: decide.py 5830, lower.py 4312, verdict.py 2664, logged.py 811, terms.py 654, holders.py 606,
scope.py 405, writer_events.py 398, deployment.py 329, snapshot.py 204, versions.py 143, yul.py 141,
immutables.py 128, taint.py 94, report.py 51, `__init__.py` 7. Total 16,777.

---

## A. Top-level functions and classes

### decide.py (5830 lines) — totals: KEEP ~2,400 · ADAPT ~1,950 · REMOVE ~1,500

Sentinels (59-75): `UNK`, `PREIMAGE`, `REVERTED`, `ASSUMED`, `CROWDED`, `TRANSIENT`, `FRESH`, `ANY_KEY`. KEEP `UNK`,
`REVERTED`, `CROWDED`, `TRANSIENT`, `FRESH`, `ANY_KEY`; REMOVE `ASSUMED` (an action whose success is assumed = arrangement);
ADAPT `PREIMAGE` (see G).

| Lines | Name | What it does | Class |
|---|---|---|---|
| 79-84 (6) | `class FreeHash` | hash with unknown inputs; `identity` / `choosable` flags | ADAPT: feeds solver's treatment of hashed keys; drop `choosable` if preimage-holder opens are dropped (G) |
| 116-118 (3) | `class Offline` | BaseException for a read asked while detached | KEEP |
| 121-145 (25) | `_tracked` | log-read bookkeeping: `truncated`, partial reads | KEEP (completeness input) |
| 148-724 (577) | `class Chain` | reads at one pinned block: `gather`/`prefetch`/`_batch_once` (batching), `storage`, `call`, `call_value`, `block_field`, `code`, `balance`, `logs`/`_scan_logs`/`_bounded`, `storage_dump`, `creation_tx`/`creation_trace`/`creation_block`/`_created`, `slot_writers`, `all_log_words`, `log_addresses`, `log_words`, `cut` | KEEP, except `call_value` 315-322 (state override of sender balance) REMOVE; `slot_writers` 475-560 ADAPT (traces a dump slot to the tx that wrote it: becomes the key-recovery step of snapshot enumeration) |
| 730-744 (15) | `_frame_words` | words of a callTracer tree | KEEP |
| 747-763 (17) | `batch_results` | classify batch slots (REVERTED / TRANSIENT) | KEEP |
| 766-769 (4) | `_crowded` | node refused a log range by count | KEEP |
| 791-795 (5) | `_is_revert` | EVM-revert message classifier | KEEP (CHECK needs revert vs node error) |
| 798-799 (2) | `_hex20` | | KEEP |
| 805-1032 (~230) | `_size`, `_struct_fields`, `_pack_fields`, `_slots`, `_key_bytes`, `locate`, `_locate`, `_layout`, `_pack_layout`, `_named_type`, `_walk`, `_decode_word` | storage layout: slot/offset/type of `contract.var[path]` | KEEP (dump reading, slot location) |
| 1039-1167 (129) | `class World` | evaluation context; ~45 fields | ADAPT: keep `chain, this, selector, contracts, values, named, deadline, work, work_limit, solver_record, parameters, payable, cut, cover, callee, declared_size, written, writer_topics, writer_events, complete, values_of, entries, latest, inverse, immutable, code_of, created, dumped, failed_at, recorded`; REMOVE `arranged, arrange, arrangers, rests_on, brought, sampled, records, records_free, overlay, code_refuted, code_passed, confirm_left, prior, effective, arrange_unknown, requirements, held_actions, action_open, credited, caller_bound, asker_free, latched, constant_load, hints, ranking, scope, hashed_only` |
| 1170-1210 (41) | `class _Reads` | assignment that records which entries evaluation consulted | KEEP |
| 1213-2109 (897) | `class Evaluator` | evaluates a term for one identity/argument binding against chain + overlay | ADAPT: KEEP `truth`, `_test`, `eval`, `_eval_new`, `_eval`, `_coded`, `_compare`, `_owned`, `_load`, `_stored_bytes`, `word`, `_callee`, `sender`, `_chain_call`, `storage_cell`, `_hash`, `_encoded_length`, `_encoded`, `_call`, `_guessed`, `_returned_size`, `_try_outcome`, `_array_words`, `_bytes_of`, `_calldata`, `_own_data`, `_argument`, `call_input`, `_op`, `nested`; REMOVE `passes`/`ranked`/`_without_code`/`without_code` (1269-1309: witnessed/proven split on callee code), `overrides` (1661-1671: state overrides), `_action` (1798-1854: ASSUMED/arranged actions — a state-changing callee becomes a followed callee or a gap) |
| 2112-2195 (~84) | `_fixed_bytes_type`, `conversion_width`, `converted`, `_abi_word`, `_decoded_item`, `_abi_value` | ABI/width helpers | KEEP |
| 2202-2255 (54) | `class Verdict` | the record | ADAPT (section B) |
| 2258-2328 (71) | `decide` | orchestrates `_state_blocked(_decide)`, second pass on opaque conditions, stranger run via `_executes`/`strangers_run`, `callee_code_*` gaps, `_confirmed_open`, `witnessed`, `core`/`condition_terms` | REMOVE; replaced by LIST orchestrator (enumerate → evaluate → split → compose) + CHECK |
| 2331-2390 (60) | `_confirmed_open` | demotes "open now" unless a stranger's eth_call (with overrides/arranged state) passes | REMOVE (simulation as decision input); replaced by CHECK tripwire → `engine_chain_disagree` |
| 2393-2402 (10) | `_budget_gaps` | `budget:reads` / `budget:confirm` | ADAPT: keep `budget:reads` (enumeration bound), drop `budget:confirm` |
| 2405-2412 (8) | `_overrides` | storage words → eth_call state overrides | REMOVE |
| 2415-2443 (29) | `_after_runs` | runs a stranger's first call then this one, on overrides | REMOVE |
| 2446-2482 (37) | `_brought_runs` | runs the calls that bring a stranger's entries about | REMOVE |
| 2485-2487 (3) | `_handed_actions` | state-changing calls handed the identity | ADAPT: identifies callee calls FORMULA must follow |
| 2490-2505 (16) | `_quantified` | caller-chosen args keying an identity lookup | ADAPT → ARGUMENT part |
| 2508-2527 (20) | `_opaque_conditions` | conjuncts set aside as "conditions" when unknown | REMOVE |
| 2530-2553 (24) | `_rests_on_code_not_followed` | provenance test on an atom | REMOVE |
| 2556-2584 (29) | `_on_conditions` | verdict with opaque conjuncts freed, `allowed=conditional` | REMOVE |
| 2591-2602 (12) | `_changing_reads` | names of state a tx may change | REMOVE (composition replaces) |
| 2605-2654 (50) | `_state_blocked` | refuses "nobody ever" on settable business state | REMOVE; composition of STATE reads through writers makes this structural |
| 2657-2660 (4) | `_readings` | render atoms | ADAPT → formula rendering of parts |
| 2663-2671 (9) | `_business` | render identity-free conjuncts + unknown labels | ADAPT → STATE part rendering |
| 2674-2689 (16) | `_decide` | wraps `_decide_arranged` and `_arranged_later`, restores `world.arranged` | REMOVE |
| 2692-2714 (23) | `_arranged_later` | demotes "open later" resting on arranged entries | REMOVE |
| 2717-3299 (583) | `_decide_arranged` | the decision proper: when-states, `_may_single_out`, `_outcome` per state, holder candidates via `_built`/`_screened`, batched `_decide_one`, executed candidates, `requires`/holdings, self-scope skip, `conditions` labels, snapshot plan, undecided/untested gaps | REMOVE as a unit. Salvage into LIST: candidate loop over `_built` keys, `_prefetch`, `_outcome` per candidate, `_snapshot_plan` call, `undecided_candidates`/`untested_candidates` bookkeeping |
| 3302-3318 (17) | `_unsettled` | why a formula reads UNK for an identity | ADAPT (gap derivation) |
| 3321-3324 (4) | `_unread_gaps` | unread `when` conditions | ADAPT |
| 3327-3368 (42) | `_open_parts` | what leaves an atom unknown: `unknown:`, `read_failed:*`, `unfollowed:`, `depth:`, `action:` | ADAPT: drop `action:`; keep read_failed/unknown/unfollowed/depth |
| 3371-3415 (45) | `target_unread` | why a call target reads unknown (`read_failed`/`budget`/`keyed`/`argument`/`call_result`/`memory`/`unresolved`) | KEEP |
| 3423-3429 (7) | `class _Snapshot` | listed / cleared / found slots | ADAPT (becomes the enumeration result) |
| 3432-3586 (155) | `_snapshot_plan` | dump-based enumeration, only for unlisted lookups a stranger fails; traces slots via `slot_writers`/`creation_keys` | ADAPT: becomes the primary LIST step for every identity-keyed mapping, unconditional on stranger failure |
| 3589-3598 (10) | `_runtime_code` | compiled runtime code | KEEP (snapshot `code_constants`) |
| 3601-3615 (15) | `_blind_gaps` | `storage:<var>` / `namespaced:<var>` / `call:<sig>` per unlisted lookup | KEEP (completeness gaps) |
| 3618-3627 (10) | `call_gap` | `call:<sig>:argN` | KEEP |
| 3630-3691 (62) | `_acts_once_allowed` | "open once allowed" has an effect, not a no-op | REMOVE (effect hedge; see G) |
| 3700-3720 (21) | `_plausible` | plausible arguments for a candidate's call | ADAPT: argument choice for CHECK replay |
| 3723-3741 (19) | `_run_rest` | eth_call the rest of undecided candidates | REMOVE (chain as decision input) |
| 3744-3799 (56) | `_executes` | find args with which a candidate's eth_call returns | REMOVE as decision input; its encode-and-call core folds into `runs` |
| 3802-3818 (17) | `strangers_run` | every other stranger's call goes through | REMOVE (sampled open) |
| 3821-3857 (37) | `runs` | eth_call of `fn` from `who` with named args | ADAPT → the CHECK primitive |
| 3860-3863 (4) | `_argument_values` | | KEEP |
| 3902-3909 (8) | `_when_states` | assignments of `when` conditions (capped `_MAX_WHEN`) | REMOVE (composition replaces state search) |
| 3912-3939 (28) | `_hashed_only` | caller-chosen values used only in hashes | ADAPT (solver only) |
| 3942-3967 (26) | `_outcome` | `_decide_one` with batched prefetch | ADAPT: per-candidate evaluation entry |
| 3970-4161 (192) | `_decide_one` | True/False/UNK for one identity: domain search, z3 `solve`, `confirmed` | ADAPT: drop `fixed` when-states and callee-code confirm; keep search |
| 4167-4187 (21) | `confirmed` | re-ask without callee code | REMOVE |
| 4190-4206 (17) | `confirming` | confirm within `confirm_left` reads | REMOVE |
| 4209-4220 (12) | `_decisive` | stranger fails a lookup-only conjunct | ADAPT (WHO part evaluated for the stranger) |
| 4223-4235 (13) | `_strangers_allowed` | `now`/`later` for strangers with records | REMOVE |
| 4238-4246 (9) | `_strangers_pass` | all five strangers pass | ADAPT: the stranger evaluation is one formula evaluation at FRESH, not five samples |
| 4255-4261 (7) | `_kept_identity` | identity through address-preserving conversions | KEEP |
| 4264-4316 (53) | `_alike_for_strangers` | formula's form makes every unconfigured address alike | ADAPT: the structural test that "open" is a proof over the WHO part (keep); drop the `rests_on`/sampled inputs |
| 4319-4334 (16) | `_origin_unread` | no view call may reach tx.origin | REMOVE (provenance) |
| 4337-4367 (31) | `_prefetch` | one batch of identity-keyed slots/calls for candidates | KEEP |
| 4370-4448 (~80) | `_chosen_steps`, `_keys_chosen`, `_recorded_keys`, `_owned_keys` | caller-chosen mapping keys and their recorded values | KEEP → ARGUMENT part enumeration |
| 4451-4576 (~125) | `_with_encoded`, `_free_compounds`, `_dynamic`, `_first_zero`, `_domain_takes`, `_independent`, `_ranked_product`, `_small`, `_caller_chosen`, `_domain`, `comparands` | argument domains for the search | KEEP |
| 4582-4615 (34) | `_call_targets` | contracts a caller-chosen address may be | KEEP |
| 4618-4623 (6) | `_exact_bindings` | | KEEP |
| 4626-4646 (21) | `_unlisted` | addresses an unlisted lookup's logs name + `history_truncated` | ADAPT: incomplete-list candidates; reason goes to gaps |
| 4649-4677 (29) | `_built` | candidates from `holders.listed` with bindings | ADAPT: candidate = enumerated key |
| 4680-4688 (9) | `gate_of` | rendered gate for self-scoped | REMOVE (scope label) |
| 4691-4693 (3) | `_ranked` | | KEEP |
| 4701-4737 (37) | `_screened` | candidate order by state (`_SHARE`/`_MIN_SHARE`/`_SCREEN_WORK`) | ADAPT: ordering under enumeration budget only |
| 4741-4758 (18) | `detached` | evaluate with no chain reads, leave no trace | KEEP |
| 4761-4767 (7) | `_copied` | | KEEP |
| 4770-4794 (25) | `_requirements` | holdings the arranged conditions ask for | REMOVE |
| 4797-4814 (18) | `_least_held` | least amount an atom lets through | REMOVE |
| 4817-4829 (13) | `contains_term` | | KEEP |
| 4832-4856 (25) | `_atoms_of` | boolean atoms of a formula | KEEP |
| 4862-4908 (47) | `_free_sat` | SAT over freed atoms (`_FREE_SAT_MS`) | ADAPT: generic "satisfiable with these atoms unknown" is needed for composition to a depth; drop "freed conditions" meaning |
| 4911-4927 (17) | `_may_single_out` | whether identity can matter | ADAPT → WHO part non-empty |
| 4930-4935 (6) | `_singling_code` | callee code alone says nobody singled out | REMOVE (provenance) |
| 4938-4956 (19) | `_singles_out` | | REMOVE |
| 4959-4979 (21) | `_reads_origin` | view call may reach tx.origin | REMOVE |
| 4982-5005 (24) | `_with_callees` | formula plus followed callee code on identity kinds | ADAPT: lowering should already inline followed callees; keep as the walker over callee formulas |
| 5008-5029 (22) | `_identity_atoms` | atoms naming caller/signer | ADAPT → WHO part |
| 5032-5041 (~8) | `_hash_inputs`, `_chosen_reads` | | KEEP |
| 5044-5064 (21) | `_jointly_freed` | | REMOVE |
| 5067-5089 (23) | `relaxed_atoms` | atoms not involving caller/signer | ADAPT → ARGUMENT ∪ STATE parts |
| 5092-5101 (10) | `held_atoms` | amounts in identity's own entries | REMOVE (holdings) |
| 5104-5124 (21) | `_names_identity` | identity outside opaque values | KEEP |
| 5127-5160 (34) | `when_atoms` | atoms with no caller and no argument | ADAPT → STATE part |
| 5163-5184 (22) | `_record_state` | caller-chosen values only as storage keys | REMOVE |
| 5187-5197 (9) | `contains_any_free`, `_contains_any` | | KEEP |
| 5206-5208 (3) | `refute` | | KEEP |
| 5211-5233 (23) | `solve` | `_solve` with give-up memory (`_SOLVER_GIVE_UPS`) | KEEP |
| 5236-5552 (317) | `_solve` | z3 model for arguments/unknowns; nested `build` (123) | KEEP; drop the `callee_code`/`ground.blind` provenance branches (5462-5482) |
| 5558-5578 (21) | `_chain_lemmas` | chain answers for view calls at model inputs | KEEP |
| 5581-5606 (~24) | `_rlimit_count`, `_fits`, `_bits` | | KEEP |
| 5613-5625 (13) | `class Coverage` | `representative`, `blind`, `lookups`, `fixed`, `values` | ADAPT: `blind`/`lookups` → completeness; `representative` → whether WHO part is lookup-only |
| 5628-5767 (140) | `coverage` | walks formula for identity uses; `complete`/`listed`/`valued`/`settled` callbacks | ADAPT: drop `settled` (callee formula already true/false for FRESH) |
| 5770-5827 (~50) | `_handed_whole`, `_fixed_choice`, `_strip_conv`, `_chosen_keys`, `_named_lookup`, `_is_identity`, `RAW_SLOT`, `_identity_keys` | | KEEP |

### holders.py (606) — totals: KEEP ~130 · ADAPT ~440 · REMOVE ~40

| Lines | Name | What | Class |
|---|---|---|---|
| 49-68 (20) | `class Who` | `members` (addr → bindings) or everyone-but-`excluded`; `sources`, `hints`, `why`, `groups`, `hinted` | ADAPT: `members` → candidate keys; `why` → gaps; drop `hints`/`groups`/`hinted` ("likely" addresses are not a list; incomplete is a gap) |
| 71-72 | `ANYONE`, `NOBODY` | | KEEP |
| 75-78 (4) | `_anyone` | everyone with a reason | ADAPT (reason → gap) |
| 81-134 (~50) | `_hinted`, `_bindings`, `_meet`, `_join` | lattice ops | KEEP |
| 137-140 (4) | `listed` | identities of `caller`/`signer` the formula singles out | ADAPT: signature becomes "candidates per identity-keyed read" |
| 143-581 (439) | `_sets` | P/N sets per subformula; nested `atom`, `equal`, `stored`, `entries_of` (events/`world.entries`, `inverse`, `_walked` linked lists, `_STORED_ROWS` storage reads), `_by_code`, `_unproven`, `_named_members`, `_logged_words` | ADAPT: `entries_of`/`stored`/`equal`/`_walked` are the event-side enumeration (KEEP inside); REMOVE `_by_code` (callee-code settles), `_unproven`+`callee_code_list:` (likely members), `_logged_words`/`_named_members` as hints (become "incomplete" gap) |
| 587-606 (~20) | `_asked`, `_hash_parts`, `_one_word`, `_strip_conv` | | KEEP |

### verdict.py (2664) — totals: KEEP ~1,000 · ADAPT ~300 · REMOVE ~1,360

| Lines | Name | What | Class |
|---|---|---|---|
| 68-124 (~57) | `_event_args`, `_writer_events`, `_address_literals` | | KEEP |
| 131-195 (65) | `_written_values` | (var, path) → writes each entry point makes, with path condition | KEEP → the COMPOSE engine's write set |
| 198-201 (4) | `class _Write` | (condition, constants, value, writer) | KEEP (compose record) |
| 204-248 (~45) | `_by_reference`, `_stores` | storage params; writes per exit | KEEP |
| 251-273 (~23) | `_delegates`, `_own_code`, `_arbitrary` | delegatecall shapes | ADAPT (proxy following in FORMULA; `_arbitrary` → gap) |
| 276-292 (17) | `_all_subterms` | | KEEP |
| 299-320 (22) | `_values_at` | writes that may land at a load | KEEP (compose) |
| 323-348 (26) | `_reachable` | constants a load can come to hold (`_REACH_ROUNDS`) | REMOVE (latching; composition to depth replaces) |
| 351-386 (36) | `_can_flip` | | REMOVE |
| 398-467 (~70) | `_may_hold`, `_atoms`, `_loads`, `_hashed`, `_settled` | | KEEP |
| 470-527 (~58) | `_value_leaves`, `_encoded_call`, `_words`, `_getter` | | KEEP |
| 530-613 (~84) | `_codeless`, `_permanent`, `_strip`, `_fixed_target`, `_delegating`, `_delegate_ops` | code-at-address permanence; proxy/delegate detection | ADAPT: `_delegating`/`_delegate_ops` for proxy following; REMOVE `_codeless`/`_permanent` (latching of "no code") |
| 621-641 (21) | `_time_flips` | | REMOVE |
| 644-694 (51) | `latched_atoms` | `when` conditions code can never flip | REMOVE (composition: no writer ⇒ constant, else writer formula) |
| 702-709 (8) | `arranged_within_budget` | | REMOVE |
| 712-779 (68) | `arranged_atoms` | conditions a caller can bring about itself | REMOVE (composition of writers subsumes) |
| 782-1071 (~290) | `_load_shape`, `_compared_with_hash`, `_held_by_caller`, `_recordable`, `_field`, `_branches`, `_recordable_under`, `_identity_outside`, `_owner_key`, `_arrangeable`, `_creditable`, `_guard_atoms`, `_loads_in` | arrangement machinery | REMOVE (`_field`/`_branches` KEEP as struct-write helpers if compose needs them) |
| 1077-1178 (102) | `after_own_call` | a stranger's first call that writes the entries read (`_PRIOR_WRITERS`) | REMOVE |
| 1181-1268 (~87) | `_first_then`, `_then_passes`, `_written_keys` | | REMOVE |
| 1271-1289 (19) | `writer_words` | storage words a call's writes leave | REMOVE |
| 1292-1318 (~25) | `_zero_of`, `call_data` | ABI-encode a call with named args | KEEP (CHECK) |
| 1321-1387 (~65) | `_clears_own`, `_unconverted`, `_concrete_writes`, `_leaves` | | REMOVE |
| 1390-1524 (~135) | `_declared_events`, `_same_lookup`, `_matched_lookup`, `_type_shape`, `_merged`, `_places`, `_read_place`, `_spec_name` | map events to lookups across implementations | KEEP (LIST via events) |
| 1535-1570 (~35) | `_metadata_map`, `_runtime_reach` | ORIGIN/call opcode reach | REMOVE (provenance) |
| 1573-1727 (~155) | `_opcodes`, `_EFFECTS`, `_instructions`, `_reachable_code` | bytecode reachability | REMOVE unless proxy detection (`_delegate_ops`) keeps it: then ADAPT |
| 1730-1755 (~26) | `_hidden_calls`, `_unconditional` | inlining rules | REMOVE |
| 1769-1811 (43) | `_inlined_verdict` | verdict with/without inlined callee, `inlined_callee:` gap | REMOVE |
| 1814-1822 (9) | `function_reads` | per-function read budget | KEEP |
| 1825-2632 (808) | `function_verdict` | orchestrator; nested: `address_of`, `contract_at`, `writer_specs`, `versions`, `every`, `valued_specs`, `running_specs`, `complete`, `keyed`, `listed`, `entries`, `_topics`, `logging_events`, `writer_events`, `values_of`, `writer_topics` (LIST side, ~330 lines: KEEP); `callee`, `declared_size`, `lower_call`, `delegate`, `immutable`, `inverse`, `latest`, `_latest_written`, `valued`, `settled`, `_codeless_address` (~150: KEEP); `asker_free`, `action_open`, `credited`, `caller_bound`, `_code_reach`, `bind_callers`, `constant_load` (~270: REMOVE — provenance, arrangement, latching); skeleton (~60) ADAPT: lower → follow callees in the lowering itself → coverage → LIST → CHECK | ADAPT |
| 2635-2664 (30) | `_configurable` | `("configurable", "<lookup> by <writer>")` | REMOVE: this is exactly what the composition chain reports |

### taint.py (94) — KEEP ~45 · ADAPT ~45

| 20-23 | `singles_out_nobody` | unknown marked alike for every caller | ADAPT (only `loop:N:anyone`-style lowering marks; drop call stand-ins) |
| 37-59 | `tainted` | term may read otherwise for another caller | KEEP |
| 62-69 | `_parts` | | KEEP |
| 72-75 | `split` | WHO core vs the rest | KEEP (first cut of the three-way split) |
| 80 | `CALL_STAND_INS` | `origin:`, `unfollowed:`, `read_failed:call_target:`, `unknown:call_target:` | ADAPT: drop `origin:` |
| 83-94 | `unknown_gap`, `unknown_labels` | labels → gaps | ADAPT |

### scope.py (405) — REMOVE 405

`class Scope`, `class Facts`, `_strip` … `classify` (320-405), `contract_facts` (256-308): the effect-scope labeller
(`self`/`shared`/`none`, `scope_writes`, `SKIP_SELF_SCOPED`). Unverified by its own SCOPE.md; no role. Replacement: none
(enumeration is bounded by budgets, not by a label).

### logged.py (811) — KEEP 811

`_entries` (23-60), `logged` (63-80), `_logged` (83-140), `_declarations`, `_place`, `_readable`, `written_by` (198-303),
`keyed_by` (306-417), `members`, `logged_raw` (438-472), `_logging`, `_iterated`, `_from_list` (537-590), `_set_values`,
`_sets`, `_zero`, `_implies` (621-647), `_implies_as_logic`, `_propositional` (673-702, z3 on path conditions),
`_boolean`, `_strip`, `_parts`, `_inputs`, `_names`, `_constant`, `_may_be_entry`, `_hashed_slot`, `_shape`,
`_offset_of_hash`. All are "is every write to this lookup logged with its key, and where in the event": the
completeness proof for event-side enumeration. KEEP as is.

### snapshot.py (204) — KEEP 204 (role widens)

`_hash`, `_is_address`, `code_constants` (41-54), `class Accounting` (57-172: `run`, `_mark`, `_visit`; `target_keys`),
`creation_keys` (175-204). ADAPT only in role: today a fallback for unlisted lookups a stranger fails
(`decide._snapshot_plan`); becomes the primary enumeration for every identity-keyed mapping, events a second source.

### report.py (51) — ADAPT 35 · REMOVE 7

`openness_label` (8-14): `open_witnessed` — REMOVE. `render` (17-51): term → text — ADAPT (renders WHO/ARG/STATE parts and
the composition chain).

### deployment.py (329) — KEEP ~230 · ADAPT ~95

`class IndexedChain` (32-119: logs from `indexed_event_logs`, `covered`) KEEP; `_hex20`, `_words` KEEP; `parse_project`
(136-155) KEEP; `class Builds` (158-221: address → Slither contract, `code_address`) KEEP; `deployment_verdicts` (224-318)
ADAPT: emits the new record (section B), drops `witnessed`, `label`, `conditional`, `allowed`, `after`, `requires`;
`_jsonable`, `_is_getter` KEEP.

### terms.py (654) — KEEP 654

`Term`, `mk`, `reset_terms`, `term_epoch`, `reintern`, constants (`TRUE`, `FALSE`, `CALLER`, `ORIGIN`, `THIS`, `CALLDATA`,
`IDENTITY_KINDS`), constructors (`mk_not/and/or/ite/cmp/op`, `mk_slice`, `fits`, `signed`, `conjuncts`), `contains`,
`stable`, `size`, `cheapest_first`, `subterms`, `substitute`, `replace_terms`, `assume_conjuncts`, `returned_part`,
`abi_array`, `packed_width`. Term kinds (docstring 1-32): caller, origin, this, sig, callvalue, calldatasize, arg, const,
time, load, rawload, hash, enc, signer, call, immutable, item, abi, ok, caught, len, elem, slice, op, conv, ite, unknown,
opaque, assumed, delegate, array, struct, upd, ptr, slot, retsize, balance, code, codesize, codehash, constant. KEEP;
`assumed` and `delegate` kinds change meaning (G).

### lower.py (4312) — public surface only; KEEP

`Lowerer(contract)` (970-3201; 5 public + 54 private methods): `success(fn) -> Term` (1016), `returns(fn, args, pc) ->
(Term, tuple)` (1047), `called(fn, args, view)` (1059, callee in its own frame), `paths(fn, state) -> list[Exit]` (1104),
`run(fn, state, depth)` (1114), `val(var)` (3146); attributes `effective` (1031: condition under which the call has an
effect), `written` (1033: (contract, var) the function may write), `exits`, `lost`, `contract`. Module API: `State`,
`Exit`, `merge`, `read_store`, `stored`, `project`, `element`, `update`, `length_of`, `parameter`; tables
`HANDLED_OPERATIONS`, `REJECTED_OPERATIONS`, `HANDLED_BUILTINS`, `REJECTED_BUILTINS`, `HANDLED_VARIABLES`,
`REJECTED_VARIABLES`, `LEGACY_YUL_*` (enforced by test_ir_coverage). Also `writer_events.py` (398, writer specs and
`complete_relations`), `immutables.py` (128), `versions.py` (143, implementation history), `yul.py` (141): KEEP.

---

## B. The Verdict record (decide.py 2202-2255) and siblings

| Field | Today | Class / new meaning |
|---|---|---|
| `openness: str` | open / restricted / not_determined | KEEP; derived: open = WHO part true for FRESH; restricted = principals listed; not_determined = gaps block the WHO part |
| `principals: frozenset[int]` | callers shown to pass | KEEP (callers for which the formula is True at the block) |
| `complete: bool` | principals+signers are everyone | KEEP; meaning narrows to "every identity-keyed read's keys were enumerated" |
| `undecided: frozenset[int]` | candidates left UNK | KEEP (candidates the evaluation left UNK under budget) |
| `signers: frozenset[int]` | identities whose signature lets any caller through | KEEP (see G.1) |
| `witnesses: dict[int, dict]` | arguments per principal (and FRESH) | RENAME → `arguments` (the ARGUMENT binding per principal; input to CHECK) |
| `gaps: tuple[str]` | why incomplete/unsettled | KEEP; vocabulary in D; add `engine_chain_disagree` |
| `requires: tuple[(contract, what, least)]` | holdings | REMOVE |
| `allowed: str` | now / later / conditional | REMOVE; replaced by `state` part + composition |
| `after: tuple[(sig, args)]` | stranger's first calls | REMOVE |
| `witnessed: bool` | open rests on samples | REMOVE (open is a proof over WHO or it isn't open) |
| `conditions: dict[int, str]` | holders listed only with business/arguments/holdings freed | REMOVE |
| `scope: str`, `scope_writes` | effect scope label | REMOVE |
| `gate: tuple[str]`, `members: int` | self-scoped gate rendering/count | REMOVE |
| `core: tuple[str]` | rendered identity conjuncts | RENAME → `who` (rendered WHO part) |
| `condition_terms: tuple[(level, reading)]` | business / arguments / configurable | RENAME → split into `argument` (conditions on args, incl. quantified keys) and `state` (conditions at the block, each with its composed form) |
| (new) `formula` | — | the lowered success condition (stable digest + rendering) |
| (new) `composition` | — | per state read: the chain of writer functions substituted, to depth, and where the depth cut |
| (new) `check` | — | per principal and the stranger: eth_call result; `engine_chain_disagree` entries |
| `__post_init__` | dedups gaps, forces `unexplained` | KEEP (strict mode `PSAT_LOGIC_STRICT_GAPS`) |

Siblings: `holders.Who` (B above: `members`, `excluded`, `sources` KEEP; `hints`, `why`, `groups`, `hinted` REMOVE/→gaps);
`decide.Coverage` (`representative`, `blind`, `lookups`, `fixed`, `values` KEEP); `decide._Snapshot` (`listed`, `cleared`,
`found` KEEP); `verdict._Write` KEEP; `scope.Scope`/`scope.Facts` REMOVE; `decide.FreeHash` ADAPT.

Consumers today read (E): `openness`, `principals`, `signers`, `complete`, `gaps`, `witnesses`, `undecided`, `witnessed`,
`allowed`, `after`, `requires`, `conditions`, `scope`, `scope_writes`, `gate`, `members`.

---

## C. Module-level constants (budgets and caps)

Swept by `tests/logic/test_failsafe.py`: **BUDGETS** (must change some verdict), **SAMPLED** (seeded sample),
**INVARIANT** (must change nothing), **UNREACHED** (swept, no probe reaches). D=decide, V=verdict, H=holders, W=lower,
L=logged, S=snapshot.

| Constant | Value | Bounds | failsafe | Class |
|---|---|---|---|---|
| D `LOG_ROWS` 88 | 50_000 | rows per log read before "crowded" | BUDGETS | KEEP (enumeration) |
| D `LOG_WINDOW` 94 | 1_000_000 | blocks per getLogs window | SAMPLED/INVARIANT | KEEP |
| D `LOG_MIN_WINDOW` 97 | LOG_WINDOW//64 | smallest window on split | not swept (derived) | KEEP |
| D `LOG_CALLS` 98 | 400 | getLogs calls per scan | BUDGETS | KEEP |
| D `LOG_SECONDS` 102 | 20.0 | one history scan | SAMPLED | KEEP |
| D `LOG_TOTAL_SECONDS` 103 | 90.0 | all scans per function | SAMPLED | KEEP |
| D `LOG_BATCH` 104 | 50 | windows per batch | SAMPLED/INVARIANT | KEEP |
| D `BATCH_RETRIES` 109, `BATCH_RETRY_WAIT` 110 | 3, 0.5 | dropped-batch retries | SAMPLED/INVARIANT | KEEP |
| D `SNAPSHOT_SLOTS` 111, `SNAPSHOT_PAGE` 112 | 400_000, 10_000 | dump size / page | UNREACHED / INVARIANT | KEEP (becomes primary) |
| D `CREATION_PROBES` 113 | 16 | creation-block probes | INVARIANT | KEEP |
| D `_STORED_BYTES` 73 | 8192 | long bytes read back | UNREACHED | KEEP |
| D `_EARLY_GUESSES` 74 | 32 | guesses before solver | SAMPLED | KEEP |
| D `_MAX_CALLDATA` 75 | 2**32 | | not swept | KEEP |
| D `_LOCATED` 892 | 100_000 | memo size for `locate` | INVARIANT | KEEP |
| D `_SNAPSHOT_TRIES` 3418, `_RESOLVE_SLOTS` 3419 | 128, 16 | dump slots tried / traced | UNREACHED | KEEP (now reached) |
| D `_EXECUTED_CANDIDATES` 3694 | 8 | candidates settled by eth_call | BUDGETS | REMOVE (chain not a decision input); CHECK is one call per listed principal |
| D `_RUN_CANDIDATES` 3697 | 256 | rest of candidates run on chain | SAMPLED | REMOVE |
| D `_MAX_WHEN` 3866 | 4 | when-condition states enumerated | SAMPLED | REMOVE (composition replaces state search); a composition depth constant replaces it |
| D `_GATHER_GUESSES` 3867 | 4 | | INVARIANT | KEEP |
| D `_SEARCH_BATCH` 3868 | 32 | | SAMPLED | KEEP |
| D `_SOLVER_GIVE_UPS` 3869 | 3 | | UNREACHED | KEEP |
| D `_LOWEST_SENDER` 3870 | 2**16 | | not swept | KEEP |
| D `_OTHER_STRANGERS`, `_STRANGERS` 3871-2 | FRESH^{1,2,4,8} | five sampled strangers | — | REMOVE (one stranger; alikeness is structural) |
| D `_CANDIDATE_BATCH` 3873 | 256 | | BUDGETS/INVARIANT | KEEP |
| D `UNPROVEN_CANDIDATES` 3879, `UNPROVEN_READS` 3880, `UNPROVEN_BATCH` 3881 | 48, 300, 8 | "likely" members asked when list not whole | BUDGETS | REMOVE (no likely members; incomplete is a gap) — or KEEP only if hints survive as candidates |
| D `_CALLEE_DEPTH` 3882 | 3 | callee following depth in decision | SAMPLED | ADAPT → lowering depth (`MAX_DEPTH`) |
| D `IDENTITY_DEPTH` 3885 | 4 | identity-handed callee depth / `caller_bound` rounds | SAMPLED | ADAPT → single following depth in FORMULA |
| D `DECISION_SECONDS` 3887 | 120.0 | wall-clock per function | SAMPLED | KEEP |
| D `DECISION_WORK` 3891 | 1200.0 | deterministic work budget | BUDGETS | KEEP |
| D `SKIP_SELF_SCOPED` 3894 | env | scope skip | fault column | REMOVE |
| D `NODE_WORK` 3895, `RLIMIT_PER_WORK` 3896, `QUESTION_WORK` 3897, `SOLVER_RLIMIT` 3898 | 1/1000, 300_000, 0.1, 2_000_000 | evaluation/solver cost | SAMPLED | KEEP |
| D `_MAX_OWNED_KEYS` 3899 | 16 | keys tried for `identity == m[arg]` | UNREACHED | KEEP |
| D `_FREE_SAT_MS` 4859 | 200 | | UNREACHED | ADAPT (composition SAT) |
| D `_HELD_ADDRESSES` 4579 | 16 | caller-chosen call targets tried | UNREACHED | KEEP |
| D `_SHARE` 4696, `_MIN_SHARE` 4697, `_SCREEN_WORK` 4698 | 0.5, 10.0, 100.0 | candidate screening | UNREACHED / INVARIANT | KEEP (ordering) |
| D `_CHAIN_ROUNDS` 5555 | 8 | chain lemma rounds in solver | BUDGETS | KEEP |
| D `_W` 5203 | 2**256 | | — | KEEP |
| V `_MAX_LATCH_STATES` 127, `_REACH_ROUNDS` 128 | 64, 8 | latching search | UNREACHED / SAMPLED | REMOVE |
| V `_ARRANGE_DEPTH` 697, `_ARRANGE_ATOMS` 698, `ARRANGE_WORK` 699 | 2, 48, 60.0 | arrangement | UNREACHED / SAMPLED / BUDGETS | REMOVE; a `COMPOSE_DEPTH` constant replaces them |
| V `_PRIOR_WRITERS` 1074 | 6 | after-own-call writers | BUDGETS | REMOVE |
| V `_WALK` 1640 | 400_000 | bytecode reachability steps | SAMPLED | REMOVE (with origin scan) |
| V `READS_PER_FUNCTION` 1759 | 2000 | reads per function | BUDGETS | KEEP |
| V `READ_CAP_SHARE` 1763 | 0.25 | share of remaining read cap | SAMPLED | KEEP |
| V `CONFIRM_READS` 1766 | 300 | callee-code confirm reads | BUDGETS | REMOVE |
| H `_BINDINGS` 41, `_WALK_STEPS` 42, `_STORED_ROWS` 45 | 64, 256, 2048 | bindings per member / linked-list walk / storage rows read | BUDGETS/INVARIANT | KEEP |
| L `_PROPOSITIONAL_MS` 650, `_PROPOSITIONAL_SECONDS` 651 | 150, 2.0 | z3 on path conditions | UNREACHED | KEEP |
| S `_SPENT` 21, `_ARRAY_ITEMS` 22, `_ARRAY_SLOTS` 23, `_CONSTANT_SPAN` 24, `_DEPTH` 25 | 300_000, 4096, 1<<20, 16, 2 | dump accounting | UNREACHED | KEEP (now reached) |
| W `MAX_DEPTH` 99, `MAX_UNROLL` 100, `MAX_SYMBOLIC_UNROLL` 101, `UNROLL_BUDGET` 103, `VALUE_STEPS` 698, `MAX_ARRAY_ITEMS` 3459 | 12, 8, 2, 4_000, 50_000, 64 | lowering | SAMPLED/BUDGETS | KEEP |
| W `_MEMORY_SPAN` 314, `_FREE_MEMORY` 317 | 0x400, 2**32 | | not swept | KEEP |
| deployment `ALL_LOG_ROWS` 25, `INDEX_LAG` 27, `HISTORY_TIMEOUT` 29 | 20_000, 300, 5.0 | indexed-log reads | not swept | KEEP |
| terms `_SIZE_CAP` 422 | 10**9 | | not swept | KEEP |

Cross-check: every name in failsafe `BUDGETS`/`SAMPLED`/`INVARIANT`/`UNREACHED` exists above. Not swept but bounding
work: `LOG_MIN_WINDOW`, `_MAX_CALLDATA`, `_LOWEST_SENDER`, `ALL_LOG_ROWS`, `INDEX_LAG`, `HISTORY_TIMEOUT`, `_SIZE_CAP`,
`_MEMORY_SPAN`, `_FREE_MEMORY`. Failsafe fault columns besides constants: `callee_nobody/false/everyone` (callee lowering
replaced), `storage`, `calls`, `logs`, `scope_skip`, `scope_skip_all_self` — the scope two go with scope.py.

---

## D. Gap vocabulary (every string the code can emit)

Source: grep of `gaps`/`why`/`unknown(...)` literals in decide.py, verdict.py, holders.py, taint.py. Families with
`<...>` are parametric.

| Gap | Emitted at | Class |
|---|---|---|
| `unexplained` | decide 2255 (`__post_init__`) | KEEP |
| `read_failed:storage:<var>` | decide 3365, holders 450 | KEEP |
| `read_failed:block` | decide 3367 | KEEP |
| `read_failed:call:<sig>` | decide 3347 | KEEP |
| `read_failed:target:<sig>` | decide 3339 | KEEP |
| `read_failed:call_target:<sig>` | verdict 2459, taint 80 | KEEP |
| `read_failed:condition` | decide 3324 | RENAME → `read_failed:state` |
| `read_failed:run` | decide 2294, 2389, 2792 | REMOVE; CHECK node errors → `check_unanswered:<who>` |
| `unknown:<label>` | taint 89/94, decide 3333-4 | KEEP (lowering rejects) |
| `unknown:target:<why>:<sig>` / `unknown:call_target:<why>:<sig>` (`<why>` ∈ keyed, argument, call_result, memory, budget, unresolved) | decide 3339, verdict 2459 | KEEP |
| `unfollowed:<sig>` | decide 3351, verdict bind_callers | KEEP (callee not followed) |
| `depth:<sig>` | decide 3354 | KEEP (following depth cut) |
| `origin:<sig>` | verdict 2547-2555 | REMOVE (provenance) |
| `action:<sig>` | decide 3344 | REMOVE → `unfollowed:<sig>` when the state-changing callee isn't followed |
| `call:<sig>[:argN...]` | decide 3612, 3621 (`call_gap`) | KEEP (identity handed to an unlisted callee lookup) |
| `storage:<var>` / `namespaced:<var>` | decide 3609-3614, 4633 | KEEP (lookup not enumerated whole) |
| `history_truncated` | decide 4646, holders 325 | KEEP |
| `unlisted` | decide 4665 | KEEP (fallback reason) |
| `untested_candidates:<n>` | decide 3116, holders 452 | KEEP (enumeration budget) |
| `undecided_candidates` | decide 3274 | KEEP |
| `others_unproven` | decide 3272 | REMOVE (hints) |
| `unrepresentative` / `other` | decide 3287 | RENAME → `who_not_lookup` ; REMOVE `other` (must say why) |
| `now_unknown` | decide 2768, 3203-3232, 3287 | RENAME → `state_unread` |
| `budget`, `budget:reads` | decide 3308-3311, 2399 | KEEP |
| `budget:confirm`, `budget:unproven_reads` | decide 2318/2401, 3157 | REMOVE |
| `chosen_identity` | holders 381-382 | KEEP (identity is a mapping value at a caller-chosen key; see G.3) |
| `identity_use` | holders 25 in `_sets` (relative) | REMOVE |
| `callee_code_list:<sig>` | holders 280 | REMOVE |
| `callee_code_refutation` / `callee_code_pass` | decide 2313, 2316 | REMOVE |
| `callee_unsingled:<sig>` | decide 2749, 2782 | REMOVE |
| `inlined_callee:<sig>` | verdict 1790 | REMOVE |
| `strangers_differ` | decide 2294, 2792 | REMOVE → `engine_chain_disagree` |
| `open_unconfirmed`, `open_arranged_unconfirmed`, `open_arranged_later_unconfirmed`, `open_value_unconfirmed`, `open_assumed_action_unconfirmed` | decide 2358-2389, 2713, 2861 | REMOVE → `engine_chain_disagree` |
| `conditional:<reason>` | decide 2574 | REMOVE |
| `state_blocks_everyone:<name>` | decide 2631 | REMOVE (composition) |
| `inert_when_allowed`, `effect_unknown` | decide 2778, 3190 | REMOVE (effect hedge; G.7) |
| `later_on_callee:<sig>` | decide 3684 | REMOVE |
| `holding_unread`, `holders` | decide 2833, 2837 | REMOVE |
| `self_scoped`, `self_scoped_ran` | decide 2883-2890 | REMOVE |
| (new) `engine_chain_disagree:<who>` | CHECK | ADD |
| (new) `compose_depth:<var>` | COMPOSE | ADD (state read whose writers were not followed to a fixpoint) |

Count: ~47 distinct families today; ~20 survive, 2 renamed, 2 added.

---

## E. Consumers of the verdict record

**services/logic/report.py** reads `verdict.openness`, `verdict.witnessed` (`openness_label`). `render` reads terms only.

**services/logic/deployment.py** (`deployment_verdicts`, 299-313) emits per function: `openness`, `witnessed`, `label`
(= `openness_label`), `principals`, `conditional` (from `conditions`), `signers`, `complete`, `allowed` (None when
not_determined), `after`, `requires`, `gaps`, `undecided` (count), `witnesses`, `seconds`; plus `error`.

**scripts/logic_run_passes.py** (275 lines) reads JSONL rows by key: `lego` (openness), `lego_principals`,
`lego_conditions` (conditional holders), `lego_complete`, `lego_witnessed`, `lego_scope`, `lego_gaps` (only
`self_scoped`), `lego_formula_false`, `lego_commit`, `written`, `checks` (harness replay per holder, `anyone`),
`nobody_refuted`, `nobody_differs`, `contract`, `address`, `function`, `corpus`. Checks (a) faulty never bolder,
(b) replay-confirmed holders never lost/missed, (c) budget-only never changes openness or listed set, (d) "provably
nobody" refuted by replay, (m) missing rows; prints scope flips, now↔conditional moves, confidence moves. Under the new
design (b)/(c)/(d) survive on `principals`+`complete`; `lego_conditions`, `lego_witnessed`, `lego_scope` branches go;
(d) becomes a reading of `engine_chain_disagree` gaps.

**../corpus_parity.py** (1063 lines, scratchpad harness) reads from the `Verdict`: `openness`, `principals`, `signers`,
`complete`, `gaps`, `allowed`, `witnessed`, `conditions`, `after`, `requires`, `scope`, `scope_writes`, `gate`,
`members`, `witnesses` (for replay args, keyed by holder and `FRESH`); from `function_verdict`'s second return the
`lowered` formula (`lego_formula_false = lowered == FALSE`). Writes rows `lego`, `lego_principals` (principals ∪ signers),
`lego_complete`, `lego_gaps`, `lego_allowed`, `lego_witnessed`, `lego_conditions`, `lego_after`, `lego_requires`,
`lego_scope`, `lego_scope_writes`, `lego_gate`, `lego_members`, `lego_formula_false`, `decide_seconds`, `decide_cpu`,
`checks`, `differ`, `conditional_pass_now`, `nobody_refuted`, `nobody_differs`, `lego_commit`, `written`, `rpc_calls`.
It also monkeypatches `verdict.READS_PER_FUNCTION`, `decide.LOG_WINDOW`, and imports `Chain`, `FRESH`, `REVERTED`,
`batch_results`, `_is_revert`, `LOG_ROWS`, `reset_terms`, `logged._PROPOSITIONAL`, `terms._TABLE`, `deployment.parse_project`.
Its VERIFY block is itself a CHECK stage (eth_call per listed holder + `anyone`): in the new design that moves into the
engine and the harness reads `check`/`engine_chain_disagree` instead.

New record must provide, minimum: `openness`, `principals`, `signers`, `complete`, `undecided` (count), `gaps`,
`arguments` (per principal + stranger), `formula` digest and `formula == FALSE`, `who`/`argument`/`state` renderings,
`composition`, `check` results, `seconds`.

---

## F. tests/logic (16,130 lines, 67 test files)

Oracle: `_oracle.py` (480) — `check(v, ...)` (every listed holder passes eth_call with its witness args; open only when
all `_STRANGERS` pass; proven open also at `UNSEEN` addresses), `sound(v, truth)`, `chain_sound`, `never_bolder`,
`chain_says`/`engine_says`/`agrees` (semantics oracle), `Faulty` chain, `Probe` registry (`PROBES`). `_anvil.py` (76):
solc + throwaway anvil `Deployment`. KEEP both; `check` loses its `witnessed`/`UNSEEN`/`arrange` arms, `never_bolder`
loses the witnessed rank.

Legend: **SPEC** = asserts chain truth via `check`/`sound`/`agrees` on anvil (keep as specification, drop hedge arms);
**STRUCT** = structural, keep; **REWRITE** = chain-backed but pins vocabulary; **DELETE** = pins removed behaviour only.

| File | Lines | Oracle | Class |
|---|---|---|---|
| test_abi_encode_types | 298 | check 3, PROBES | SPEC (semantics) |
| test_actions | 240 | check 8, PROBES | REWRITE: arrangement of actions → followed callee; keep chain assertions |
| test_arranged | 936 | check 32, sound 3, PROBES | REWRITE: `after`/arranged → composition; the eth_call truths stay |
| test_batch_retry | 77 | none | STRUCT (Chain batching) KEEP |
| test_budget_bites | 156 | check 5, PROBES | REWRITE (budget cuts → `untested_candidates`) |
| test_budgets | 421 | none (Chain stubs) | REWRITE: keep "smaller budget never bolder, accounts with a gap"; drop `now_unknown`/conditional |
| test_call_structs | 368 | check 4, PROBES | SPEC |
| test_callee_actions | 117 | check 2, PROBES | REWRITE (confirm-by-run → CHECK) |
| test_callee_depth | 139 | check 14, sound 1 | SPEC; depth gaps rename |
| test_callee_frame | 201 | check 10, sound 1 | SPEC |
| test_callee_misread | 158 | check 6 | SPEC (never bolder than chain) |
| test_callee_reads | 105 | none | STRUCT KEEP (read-order independence) |
| test_callee_refutation | 303 | anvil, no check | DELETE (callee-code refutation hedge) |
| test_chosen_identity | 168 | none | REWRITE → ARGUMENT part (`chosen_identity`) |
| test_chosen_key_crowd | 144 | check 2, PROBES | SPEC (storage-read enumeration) |
| test_conditions | 245 | check 2 | DELETE (holders on conditions / holdings) |
| test_constructs | 505 | anvil semantics | SPEC |
| test_consumed_conditions | 59 | check 1 | REWRITE → composition (function writes what it reads) |
| test_core | 182 | check 12, sound 4 | DELETE (conditional allowed, `conditional:` gap) |
| test_core_soundness | 124 | check 7, sound 3 | REWRITE: keep "never open on failed read / spent budget" |
| test_declaration_scope | 157 | anvil semantics | SPEC |
| test_deployment | 126 | none (DB) | STRUCT KEEP (IndexedChain) |
| test_elements | 500 | check 7, sound 4 | SPEC |
| test_engine_pieces | 356 | anvil partly | STRUCT mostly KEEP; drop `_executes` pieces |
| test_executed_holders | 100 | check 1 | DELETE (holders settled by eth_call) |
| test_failed_reads | 358 | check 1, sound 1, Faulty | SPEC (fail-safe) ; drop `after` arm |
| test_failsafe | 372 | never_bolder over all PROBES | STRUCT KEEP; prune constants/faults per C |
| test_gaps | 92 | Chain stub | STRUCT KEEP (read_failed naming) |
| test_governance | 389 | check 11, PROBES | REWRITE: drop `allowed`/`requires`/`after`; keep chain truths |
| test_governance_shapes | 301 | check 7 | SPEC |
| test_holders | 134 | none | REWRITE → enumeration completeness |
| test_ir_coverage | 323 | — | STRUCT KEEP (COVERAGE enforcement) |
| test_known_gaps | 249 | check 8, xfails | SPEC (strict xfails naming gaps; rename gaps) |
| test_language | 252 | anvil semantics | SPEC |
| test_latching | 274 | check 2 | DELETE (latching) → re-express G5 cases as composition tests |
| test_library_writers | 144 | none | STRUCT KEEP (logged) |
| test_logged | 238 | check 8, sound 2 | SPEC |
| test_loop_control | 298 | anvil semantics | SPEC |
| test_lower_shapes | 345 | agrees | SPEC |
| test_nobody_refuted | 42 | none | STRUCT (run_passes) KEEP, adapt keys |
| test_open_business | 333 | check 5 | DELETE (`requires`, assumed actions) |
| test_open_confirmed | 398 | check 8 | DELETE (`_confirmed_open`); rewrite 2-3 cases as `engine_chain_disagree` |
| test_origin_callees | 217 | check 6, sound 2 | DELETE (origin inlining); keep chain truths as SPEC of following |
| test_origin_scan | 202 | check 2 | DELETE (opcode scan) |
| test_origin_shapes | 160 | check 7, sound 3 | SPEC (callee reads tx.origin: CHECK sets origin=sender) |
| test_pool_shapes | 558 | check 11 | SPEC |
| test_review_probes | 926 | check 13, sound 3 | SPEC |
| test_run_passes_conditions | 64 | none | DELETE (conditional holders in run_passes) |
| test_scope_review | 45 | none | DELETE |
| test_scope_skip | 211 | check 3 | DELETE |
| test_self_credit | 183 | check 4 | DELETE (arrangeable) → composition |
| test_self_scoped_gate | 110 | none | DELETE |
| test_selfdestruct | 67 | check 2 | SPEC |
| test_slice_source | 67 | none | STRUCT KEEP (lowering) |
| test_snapshot | 372 | Chain stubs | STRUCT KEEP; widen to primary enumeration |
| test_state_blocked | 230 | check 8, sound 1 | REWRITE → composition ("nobody ever" only when no writer) |
| test_stranger_call | 80 | check 2, sound 1 | DELETE (stranger run as decision input) |
| test_stranger_runs | 157 | check 6 | DELETE |
| test_taint | 25 | none | STRUCT KEEP |
| test_target_gaps | 243 | check 6, Faulty | SPEC (target gap naming) |
| test_versions | 171 | none | STRUCT KEEP (implementation history) |
| test_witness_domains | 183 | none | STRUCT KEEP (argument search domains) |
| test_witnessed | 218 | check 6 | DELETE |
| test_yul, test_yul_siblings | 158, 196 | anvil | SPEC |

Totals: SPEC ~7,900 lines (26 files) · STRUCT KEEP ~2,900 (15) · REWRITE ~3,200 (11) · DELETE ~3,000 (16).

---

## G. What the new design cannot express as stated

1. **Signers** (`("signer", digest, v, r, s)`, `Verdict.signers`, `holders.listed(root="signer")`): the identity is
   whoever signed, not `msg.sender`. CHECK by eth_call from a principal does not exercise a signature. Needs a signer
   identity class in WHO and a CHECK that supplies a signature or skips with a gap.
2. **Preimage-choosable hashes** (`PREIMAGE`, `FreeHash.choosable`, Merkle/commit schemes): the formula is satisfiable by
   anyone who can compute a preimage; there is no key to enumerate. Today: open with `PREIMAGE` counted true. Spec must
   say open-with-argument-condition or not_determined.
3. **Identity as mapping value** (`caller == m[arg]`, `chosen_identity`, `_owned_keys`, `inverse`/`latest`): keys are
   caller-chosen; principals are the *values*. A storage dump gives slot→word but not the key for hashed slots;
   enumeration goes by value through events (`inverse`) or `slot_writers` traces. Completeness is by writes being
   logged with the value, not by keys.
4. **Hashed raw slots and namespaced storage** (`rawload`, `logged_raw`, ERC-7201, `keccak(seed, role, holder)`): a dump
   lists slots whose preimage is unknown; `_snapshot_plan` tries each as the stranger's own entry and traces it. Fine
   for the design but the "all keys enumerated" criterion needs a per-slot "explained" accounting
   (`_Snapshot.listed/cleared/found`).
5. **Linked lists in storage** (Safe `owners[SENTINEL] -> ...`, `holders._walked`): a membership condition whose
   candidates come from walking storage, bounded by `_WALK_STEPS`; neither events nor dump keys.
6. **Holdings in other contracts** (`token.transferFrom`, `balanceOf(caller) >= x`, Aave caps): a STATE condition over an
   identity-keyed mapping *in another contract*. Enumerating balance holders is unbounded; composing `transfer` writers
   gives "anyone with a balance". With holdings excluded as inputs, every deposit-like function is either open on an
   argument condition or `storage:<var>` incomplete. Spec must choose.
7. **Effect vs return** (`Lowerer.effective`, `_acts_once_allowed`, `inert_when_allowed`): CHECK is eth_call success; a
   no-op `unpause()` while unpaused reads open. Known gap G3 in COVERAGE.md ("open should be claimed on the effect").
8. **Records the caller names** (`world.records`: vote ids, proposal hashes, timelock operation ids): a STATE read keyed
   by a caller-chosen argument that may not exist yet. Composition of the writer (`propose`, `schedule`) gives "whoever can
   propose"; the design's STATE part needs to accept argument-keyed state.
9. **Time** (`("time", ...)`, deadlines, timelocks): STATE conditions nobody writes; composition has no writer. Needs a
   time atom class: "true at block B" or "true after T".
10. **Delegatecall to caller-named code** (`_arbitrary`), **proxies with unverified implementations**, **callees with no
    source** (`unfollowed:`): no formula. Today a provenance hedge; in the design a gap, which makes the whole function
    not_determined where today it is restricted-incomplete.
11. **Earlier implementations' writes** (`versions.py`, `every`, `_matched_lookup`): event completeness must hold for every
    implementation the proxy ran. Dump enumeration sidesteps this; event-only enumeration cannot.
12. **Composition fixpoints**: a writer gated on the same mapping it writes (`grantRole` by role admin,
    `transferOwnership` by owner) recurses to itself; "repeated to a depth" must define the base: the enumerated list of
    the mapping at the block, not the writer formula.
13. **Crowded/truncated histories** (`CROWDED`, `history_truncated`, `LOG_ROWS`): incomplete enumeration; fine as a gap,
    but the dump must then be the source or the function is never complete (tokens with millions of transfers).
14. **CHECK arguments**: a principal's eth_call needs arguments satisfying the ARGUMENT part at the block (`witnesses`,
    `_plausible`); an unsatisfiable argument condition (`deadline` passed) makes every replay revert without the engine
    being wrong. The disagreement rule must condition on the ARGUMENT/STATE parts being satisfiable at the block.
15. **EIP-7702 designators / `extcodesize` on the caller** (`Evaluator._coded`): WHO conditions on code at the caller's
    address; enumerable only from the dump/trace, not from keys.
