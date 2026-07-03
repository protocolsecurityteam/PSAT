# Function-Effect Labels — Redesign Specification

**Design investigation, read-only. 2026-07-03.**
Produced per `LABELS_REDESIGN_HANDOFF.md` by a 2-agent adversarial workflow (evidence-first
prior vs clean-slate prior, opposing steelman/attack assignments, independent measurement)
plus orchestrator synthesis with independent verification of every deciding disagreement.
All numbers come from (a) exhaustive prod queries over 2,182 `effective_functions` rows,
(b) local in-process runs of current `main` (@ `90d8774`) on 21+27 Etherscan-verified real
contracts covering the hard-case battery, and (c) prototype implementations of the candidate
designs re-run on the same sources. Measurement scripts and per-contract outputs are
preserved (Appendix C).

---

## 1. Verdict

**Winner: the Claims-Registry Two-Plane Architecture** — both investigators, given opposing
priors and told to attack each other's assigned hypotheses, independently invented
essentially this same design as their H5 and recommended it over every listed hypothesis.

- **Plane 0 — FACTS**: `effects.py` hardened into a substrate of machine-checkable records
  (state writes with member paths and hygiene classes, sinks with origin, value flows,
  variable roles sourced from the predicate-leaf taxonomy). Nothing in this plane is a guess.
- **Plane 1 — CLAIMS**: the semantic vocabulary reborn as typed objects
  `{claim_id, tier, witness}` minted **only** through a code registry. Every registry entry
  carries a written claim sentence, a machine-checkable evidence spec (contract-level gate +
  per-function trigger over Plane-0 facts / predicate trees), at least one positive fixture,
  at least one counterexample fixture, and an approved corpus label-diff. A guess tier is
  **not representable in the schema** — the current system's entire failure class
  (`summaries.py:727`) becomes untypeable, not merely discouraged.
- **Production sites chosen by evidence locality**: static for single-contract evidence
  (trees, selectors, gates, sinks); a thin policy-stage pass for claims whose evidence only
  exists downstream (beacon upgrades, callee value-flow propagation, cross-contract transfer
  policy, proxy-verified provenance upgrades). The existing `cross_contract.py`
  propagate-every-label rule is replaced by these typed derivations.
- **Unknown = silence + fact text.** No marked-guess tier: the marked-guess variant was
  measured — it is today's `hook_update` at 1/69 correct — and the governance consumers
  already treat coarse labels as noise (`primary_controller.py:161`,
  `company_overview.py:940`).

H1 (evidence-standard redesign) and H3 (standard-aware models) each contributed their
measured-good half; H2 contributed the substrate principle; H4 contributed the scoped
cross-contract layer. H0 (keep + patch), pure H2, pure H3, full H4, LLM-labeling, and
capability-expr-drives-UI were all rejected on measurements (§4).

---

## 2. Measured state of the current system

Two independent ground-truth passes (different contract samples, same method: read the
verified source, grade the emitted claim sentence) agreed on every headline:

| Label | Agent 1 (local-21) | Agent 2 (local-27) | Prod scale (2,182 rows) |
|---|---|---|---|
| `hook_update` | **1/54 correct** | **1/69 correct** | 340 rows, ~4.7% genuine; only real TP class: `setBeforeTransferHook` |
| `ownership_transfer` | 26/44 | 40/85 | 284 rows, ~74% defensible; FP classes: OZ v5 ghost writes (incl. `owner()` **views**), non-owner pointer rotations rendered as "Transfers contract ownership" |
| `pause_toggle` | 8/12 | 10/16 | 73 rows; **44% are `initialize(...)`** (OZ init-latch matches the detector verbatim); misses require-based (Teller), struct (Accountant), OZ v5, bitmask (EigenLayer) pauses |
| `implementation_update` | 0 emissions | 0 emissions | **0 of 2,182 — the severity-1.0 label is corpus-dead**; `protocolScore.js:167` silently compensates with `name.includes("upgrade")` |
| `role_management` | — | 9/9 | 57/57 correct (selector-canonical — the only 100% tier) |
| `authority_update` | 52+3?/55 | 5/6 | canonical rows 100%; the `dest:{name}` structural tier produced the FPs (e.g. `registerEth2DepositContract` — a data-freshness call in a modifier, same error class as composeQueue) |
| `asset_*`/`mint`/`burn` | 17/18 | 30/33 | direction FP (`recoverERC721` labeled *pull* while sending out); large FN side: `Dai.mint/burn`, `BoringVault.enter/exit`, `WETH9.withdraw` all silent (prod: mint 6, burn **0**) |
| `external_contract_call` | fact-true | 19/26 informative | 858 rows (39% of corpus); 25% sit on views; guard-path `auth.canCall` counted as an "effect" (test-pinned at `tests/test_contract_analysis.py:295`) |
| `timelock_operation` | dead | dead | 0 producers, consumed at `meta.js:13`, `lane.js:36/62`, `protocolScore.js:177`, `principal_enrichment.py:165` |
| `arbitrary_external_call` | dead | dead | 0 producers (dossier missed this one), consumed at `protocolScore.js:170` (0.95), `principal_enrichment.py:120/156` (`_manager` tag — **never granted in prod history**) |

**Defects found beyond the dossier** (each verified on-disk and on real contracts):

1. **The "precise layer" is itself a top-3 FP source.** `apply_authority_effect_labels`
   (`effects.py:482`) has no constant/view/type filtering; on OZ v5 namespaced storage,
   Slither attributes the slot **constant** (`OwnableStorageLocation`) as *written* by every
   touching function, so `owner()` (a view), `setPeer`, `sweep`, etc. all get
   `ownership_transfer`. Reproduced on current code (L1SyncPoolETH
   `0x39272ee1...`), matching prod rows on 4+ contracts. The handoff's premise "the precise
   layer already exists" is **false for OZ v5** — one of the deciding facts of this
   investigation.
2. **Interface-record clobbering in `build_effects`**: the functions dict is keyed by
   `full_name`, so an inherited 0-node interface re-declaration can overwrite the concrete
   record — verified live on EigenLayer StrategyManager, whose `pause(uint256)` loses **all**
   sinks and labels.
3. **Guard-origin sink dilution**: modifier bodies are walked as effects, so
   `requiresAuth`'s `auth.canCall` becomes Teller.pause()'s only recorded "effect".
4. **Cross-contract label contagion**: `cross_contract.py:29` propagates *every* callee
   label; `Teller.deposit` inherits WETH9's `hook_update` mislabel across 10+ deployments,
   and the same function gets different labels on different deployments
   (`updateExchangeRate`: `{hook_update}` on one, `{external_contract_call}` on four).
5. **Monitor watch flags do not consume effect labels at all** (`enrollment.py:397-432`
   derives from `contract_type`/`is_pausable`/`control_model`) — dossier correction; labels
   affect monitoring only indirectly via `is_pausable`-style inputs.
6. A second, higher-rigor pause detector already exists and is unused for labels
   (`reentrancy_pause.py::PauseAnalyzer`) — it independently gets Teller and `initialize`
   right, but has its own two bugs: `contract.state_variables` misses inherited private vars
   (`_paused` invisible on 4+ contracts) and `_is_pause_typed` accepts `uint256`
   (flags `validatorSizeWei`, `ownerCount`, `_minDelay`).

---

## 3. What a label IS under the winning design

Two kinds of emitted statement, both objects, both machine-checkable:

**FACT** (Plane 0) — a record checkable directly against Slither IR by a deterministic
predicate:

- state write `{var, declared_type, member_path?, granularity: var|member|assembly_slot,
  hygiene_class: normal|constant|storage_location_pseudo|reentrancy_guard|view_writer}`
- variable role `{gate_bool_for_N_fns (from pause-role predicate leaves),
  caller_authority_equality (leaf role + operand var name),
  callee_pointer_invoked_by_sibling, fallback_delegatecall_read, one_shot_latch}`
- value flow `{low_level_value_call | native_transfer_send | callee_erc20_selector,
  direction (from==this corrected)}`
- sink `{kind, target, selector, origin: body|guard}`

**CLAIM** (Plane 1) — `{claim_id, tier, witness}` where:

- `claim_id` is a schema-enforced Literal drawn from the registry (namespaced:
  `ownership.transfer`, `pause.set`, `upgrade.implementation`, `safe.set_guard`, …). Each
  registry entry declares a **legacy projection** (the current string, e.g.
  `ownership_transfer`) so consumers migrate on their own schedule.
- `tier ∈ {standard_exact, idiom_structural, policy_derived}` — there is **no**
  heuristic/fallback value; adding one requires changing the schema, the registry contract,
  and the CI gate simultaneously (three loud diffs instead of one quiet `labels.add(...)`).
- `witness` is replayable: a leaf path into `predicate_trees`, a selector + corroborating
  gate/event, a sink id, a `(var, member)` pair, or (policy tier) a
  `(sibling artifact, controller_value, slot read)` triple.

**Registry entry contract** (the anti-creep core, §6): written claim sentence +
machine-checkable gate/trigger predicates + ≥1 positive real-contract fixture + ≥1
counterexample fixture (the composeQueue pattern, institutionalized from the comment at
`effects.py:436-443`) + one adversarial near-miss + an approved corpus label-diff.

---

## 4. Hypothesis scoreboard

| Hypothesis | Verdict | Deciding evidence |
|---|---|---|
| **H0 keep + patch** | REJECT (both agents) | 16 measured defect classes; individual patches measured to trade FPs for FNs (constant-guard erases OZ v5 TPs; uppercase-guard silences real pause); vocabulary still can't express Safe/timelock/wards; no structural protection against defect #17 |
| **H1 evidence-standard redesign** | Half-adopted | Its derivations (guarded tree tiers, canonical selectors, guess-tier deletion) were prototyped and measured good: hook 54→1 TP, pause 12→14 all-correct, ownership −18 FP/+2 FN-recovered, impl 0→10. But its premise "extend the existing precise layer" is unsound as stated (OZ v5 ghost writes, §2.1) — the tree tiers survive only as *registry-governed idioms with guards and fixtures*, and ownership's primary carrier must be the standards tier |
| **H2 facts-only** | REJECT as architecture, ADOPT as substrate | Starvation measured on all 2,182 prod rows with faithful consumer ports: 866 severity drops (40%), 481 lane changes, **all 65 admin-display principals lose their tags**; naive fact-derived lanes put `nonReentrant` `_status` writers in the control lane and lose the one real hook. Facts + role taxonomy + a semantics layer does not starve — that is the winning design |
| **H3 standard-aware models** | REJECT as whole-contract packs, ADOPT as mechanism-level gates | Whole-pack semantics unverifiable on forks (5/8 sampled ERC-20 matches deviate behaviorally); 8/21 contracts match no standard — strict H3 leaves LiquidityPool's `pauseContract`/`upgradeTo` unlabeled. But mechanism-granular gates measured **154 exact claims / 415 fns (37%) at 0 observed false claims**, recovering everything the current system is blind to: UUPS+zos `implementation_update` 17 (vs 0 today), timelock ops 6 (vs 0), Safe signer/module/guard 12 (vs 0-or-wrong), Solady + OZ v5 ownership ghost-immune, Maker wards, Comp delegation |
| **H4 relocate downstream** | REJECT full relocation, ADOPT scoped | Trees + PauseInfo are already in scope at static labeling time (`core.py:206-241`) — relocation buys single-contract claims nothing and couples chip text to policy-stage freshness. But cross-contract evidence genuinely lives downstream: beacon upgrade (`upgradeEtherFiNode`), callee mint/burn propagation, Teller→BoringVault transfer-policy, proxy-verified provenance. The mechanism already exists (`cross_contract.py` + `policy_worker.py:731`) with a broken propagate-all rule — replace with typed derivations |
| **H5 claims-registry two-plane** | **ADOPT** | Independently invented by both agents; unifies the measured-good parts; only evaluated configuration with zero measured wrong claims and a structural anti-creep story |
| **H6 LLM-assisted labeling (gated on facts)** | REJECT as producer | The residue it would serve is precisely where facts cannot verify its output (`writes accountantState` can neither confirm nor refute "pauses the vault"); nondeterministic corpus diffs break the A/B gate. Acceptable offline as a registry-authoring assistant |
| **H7 capability_expr + sinks drive UI** | REJECT | Category error: capability answers WHO can call, not WHAT the function does — `manage` and `deposit` share `requiresAuth` shape; `approve` and `withdraw` are both public. Lane/severity need effect semantics; the system already contains the disproof (name-hint fallbacks at `lane.js:24-26`) |

Hard-case battery: every hypothesis was scored on all 11 battery items on real contracts;
per-case results live in the agents' structured outputs (Appendix C). The winning design
passes every item except the two honest residues noted in §7 (EigenLayer
PauserRegistry-family pause until its registry entry lands; OZ v5 `initialize` owner-set).

---

## 5. Per-label disposition table (entire current vocabulary + new)

Tiers: **SE** = standard_exact, **IS** = idiom_structural, **PD** = policy_derived, **F** = fact.

| Label (legacy → claim_id) | Disposition | Claim sentence | Evidence required | Tier | Battery result |
|---|---|---|---|---|---|
| `ownership_transfer` → `ownership.transfer/renounce/accept` | **redefine** | "changes the contract-ownership principal (per standard X)" | Standard gates: OZ Ownable/2Step (selector `0xf2fde38b`/`0x715018a6` + `OwnershipTransferred` or owner-var write identity), Solady handover family, DefaultAdminRules staged transfer. Tree tier **corroborates but never solely emits** for canonical-owner vars | SE | OZ v4 ✓ kept; OZ v5 ✓ ghost-immune (12 FPs/contract removed, `transferOwnership` kept); Solady ✓ recovered (silent today); FiatToken `updateMasterMinter` correctly **not** ownership |
| — → `authorized_caller.rotate` | **new** | "rotates a non-owner scalar that authorizes callers of specific gated functions" (renders the var name: "rotates caller-authority address `pauser`") | Tree idiom with guards: `caller_authority` **equality** leaf referencing msg.sender + operand is scalar address-typed non-constant var (via `_all_state_variables`) + writer is state-changing non-view. Guards structurally exclude composeQueue (membership ≠ equality) and OZ v5 ghosts (constant) | IS | `updatePauser`/`updateBlacklister`/`updateMasterMinter`/`updateRescuer` (USDC, StakedTokenV1), `setL1SyncPool` family ✓ — ends the false "Transfers contract ownership" sentence on 26+ prod rows while keeping admin severity |
| `role_management` → `roles.grant/revoke` | **keep** | "grants/revokes membership in a role-based access scheme (per standard X)" | Today's canonical selectors (`summaries.py:288`) + contract gates (hasRole/getRoleAdmin siblings; Solmate write-target identity); extended by `wards.rely/deny` idiom (Maker) and DAR staged-transfer claims | SE | 57/57 + 9/9 measured; composeQueue **mandatory counterexample fixture**; Maker `rely`/`deny` gains a true claim (today: "changes hook") |
| `authority_update` → `authority.replace` | **keep** | "replaces the external authority contract consulted for permission checks" | Canonical `setAuthority 0x7a9e5e4b` + authority write-target gate. The `dest:{name}` substring detector (`summaries.py:498`) **deleted** (source-verified category error: `registerEth2DepositContract` freshness check) | SE | 52/55 prod already canonical ✓; 3 structural FPs stop being emitted |
| `pause_toggle` → `pause.set/unset` | **redefine** | "toggles a flag that blocks/unblocks other state-changing entry points of this contract" | Either standard (OZ Pausable selectors + `{paused,isPaused,_paused}` var identity; isPaused-var idiom) **or** tree idiom = the PauseAnalyzer derivation with four verified fixes: `_all_state_variables` lookup (recovers inherited `_paused` ×4 contracts), member-path + bool member type (struct pause), bool/polarity type gate (kills `validatorSizeWei`/`threshold`/`_minDelay` FPs), one_shot-leaf writer exclusion (kills the 31-row `initialize` class) | SE / IS | modifier ✓ kept; require-based (Teller) ✓ recovered; struct (Accountant `isPaused`) ✓ recovered with `payoutAddress` excluded — **verified in prototype, resolves the inter-agent dispute (§8 D1)**; inherited private ✓; EigenLayer bitmask+PauserRegistry = honest residue until its registry entry; `initialize` ×31 ✓ removed |
| `implementation_update` → `upgrade.implementation` | **redefine** | "changes which code executes behind this deployment" | Standard gates only: UUPS (`proxiableUUID` + `upgradeTo(AndCall)`), 1967 selector+marker (+`Upgraded` event), zos/proxy-shell (fallback-with-delegatecall + upgrade selectors), beacon via policy join. The never-fired same-contract dataflow detectors (`summaries.py:381/404`) **retired as producers** (0 emissions ever, both samples); `fallback_delegatecall_read` remains a fact | SE / PD | UUPS 14/14 ✓ (vs 0 today); zos wBETH 3/3 ✓ incl. `changeAdmin`; suppresses the misleading `delegatecall_execution` emphasis on the same fn; `protocolScore` name-heuristic arm becomes deletable |
| — → `proxy.admin_change` | **new** | "changes the proxy admin who can upgrade this deployment" | `changeAdmin 0x8f283970` + `AdminChanged` event / proxy-shell gate | SE | FiatTokenProxy.changeAdmin (today: **nothing**) ✓; TransparentProxy.changeAdmin (today: "delegatecall path") ✓ |
| `hook_update` → `callee_pointer.rotate` (+ `safe.set_guard`) | **redefine/retire name** | "changes a code pointer that another entry point of this contract invokes at runtime" | Use-link idiom on IR identity (writes X; sibling has body-origin call to X + value/mapping-write sinks) — the one measured-clean signal (`summaries.py:517`). The unclassified-pointer fallback (`summaries.py:727`) **deleted**: 53/54 and 68/69 of its emissions were wrong | IS / SE | `setBeforeTransferHook` ✓ survives (verified fired by use-link); prod 340-row class collapses to ~14 true rows + fact text; `SafeL2.setGuard` gets its exact claim via the Safe gate |
| `asset_send` / `asset_pull` → `flow.out/in` | **keep** | "sends value out / pulls value in" | Selector facts with `from == address(this)` direction correction + low-level value calls + **native `.transfer()`/`.send()` IR ops (new)** | F / SE | `WETH9.withdraw` ✓ recovered (today: "changes hook"); `recoverERC721` direction ✓ fixed |
| `mint` / `burn` → `supply.mint/burn` | **redefine** | "increases/decreases token supply or share balances" | Callee selectors (existing) + own-selector within ERC-20/FiatToken gate + local supply-write sign tier (`is_erc20 ∧ writes totalSupply ∧ IR sign`). The `str(ir)` sandwich parser (`summaries.py:576`) **retired** | SE / IS | `Dai.mint/burn`, `BoringVault.enter/exit`, `USDC.mint`, `BackingEigen.mint` ✓ recovered (prod burn count today: 0) |
| `contract_deployment` | **keep** | "deploys a new contract" | `contract_creation` sink | F | unchanged (sound) |
| `delegatecall_execution` | **keep** | "a delegatecall is reachable from this entry" (renderer must stop implying intent) | delegatecall sink + origin annotation; suppressed when an upgrade claim explains the same sink | F | proxies ✓; upgrade-fn emphasis corrected |
| `selfdestruct_capability` | **keep** | "can destroy the contract" | selfdestruct sink | F | no corpus instance |
| `external_contract_call` | **demote to fact** | body-origin external call exists (no semantic weight, never alone drives lane/severity/tags) | sink with `origin=body` (guard-origin excluded) | F | Teller.pause `auth.canCall` dilution ✓ excluded; both governance consumers already ignore it |
| `timelock_operation` → `timelock.schedule/execute/cancel/set_delay` | **resurrect** | "schedules/executes/cancels a timelocked operation / changes its delay" | oz_timelock gate (`getMinDelay`+`schedule`+`execute` siblings, `hashOperation`/AccessControl markers) + per-selector | SE | 6/6 on real TimelockController ✓; `schedule` no longer silent, `execute` no longer "moves value out" in the outflow lane; 4 dead consumer branches become live |
| `arbitrary_external_call` → `exec.arbitrary` | **resurrect** | "forwards caller-supplied target and calldata (arbitrary execution)" | Standard gates (Safe `execTransaction`/module exec, timelock `execute`) + `manage(address,bytes,uint256)` idiom (parameter-tainted destination **and** data on a body-origin call sink) | SE / IS | `BoringVault.manage`, `OneSig.executeTransaction`, `Timelock.execute` ✓ — the 0.95 severity and `_manager` tag consumers have been waiting on get producers for the first time |
| — → `safe.signer_mgmt` / `safe.module_mgmt` | **new** | "changes signer set / threshold" · "grants/revokes module execution rights" | Safe gate (`getThreshold`+`getOwners`+`execTransaction`) + canonical selectors | SE | 12/12 on real SafeL2 ✓ (today: `hook_update` or silent) |
| — → `gov.delegate` | **new** | "delegates voting power (user operation)" | Comp-style gate (delegates+checkpoints write identity) + selectors | SE | 2/2 ✓ (today silent); stays out of the control lane |
| — → `transfer_policy.configure(target)` | **new** | "changes another contract's transfer gating" | **Policy tier**: written set-var read by this contract's hook fn + sibling's hook-pointer `controller_value` == this contract | PD | Teller.allowFrom→BoringVault ✓ (replaces both the `hook_update` mislabel and propagate-all contagion) |

**Facts-plane prerequisites** (consensus of both agents, each measured necessary):
sink `origin ∈ {body, guard}`; `build_effects` keying prefers concrete records over 0-node
interface declarations; member-level write pairs; hygiene classes excluding
constants / `*StorageLocation`/`*_SLOT` pseudo-vars / reentrancy-role vars / view writers
from role-facts (still visible as raw writes); native transfer/send value sinks;
`from==this` direction fix; typed cross-contract propagation replacing propagate-all.

---

## 6. Anti-heuristic-creep — the structural mechanism

1. **Closed claim schema.** Claims are constructible only via
   `emit_claim(claim_id, tier, witness)`; `claim_id` is a Literal validated against the
   registry at artifact build time; tier has no guess value. An unevidenced label is
   *unrepresentable*, not reviewable-away.
2. **Registry entry contract.** Every entry: claim sentence + evidence predicates over
   Plane-0 facts + ≥1 positive fixture + ≥1 counterexample fixture + 1 adversarial
   near-miss (e.g. pause: Teller require-pause positive, `initialize` negative, OneSig
   config-toggle near-miss — the pattern that would have caught every one of the 16 defect
   classes measured here).
3. **Frozen-corpus A/B diff gate in CI.** The 21+27 real contracts from this investigation
   become checked-in compilation fixtures; CI recomputes all
   `(contract, selector, claim_id, tier)` tuples and fails unless the PR includes the
   reviewed golden diff. A matcher edit that silently relabels `WETH9.deposit` cannot merge.
4. **Witness replay tests.** Per tier, a generic test re-verifies emissions on the fixture
   corpus (tree witness: leaf exists with required role/kind/operand types; selector
   witness: gate and marker present; taint witness: destination/data trace to parameters).
   A detector that drifts from its evidence spec fails without anyone writing a new test.
5. **Consumer-coverage invariant.** CI asserts consumer-referenced claim ids ⊆ registry ids
   ⊆ fixture-produced ids. This invariant is violated **twice on main today**
   (`timelock_operation`, `arbitrary_external_call`) — the rot mode becomes a build failure.
6. **Single vocabulary module per side.** Consumers import
   `claim_id → {lane, tone, sentence, severity-kind, tag-set}` from one shared map per
   language, eliminating the measured 5-site drift.
7. **Presentation heuristics quarantined.** Frontend name-hints (`lane.js:24-26`,
   `CONFIG_HINTS`) may affect **layout only** — never chip sentences, severity, or principal
   tags. No semantic sentence renders without a claim.

---

## 7. Consumer fit (verified against consumer code)

| Consumer | Decision today | Under the design |
|---|---|---|
| `lane.js` / `meta.js` (lane, tone, chip text, ordering) | label strings + name-hint fallback | control lane := control-plane claim families; flow lanes := flow claims/facts; chip text := registry sentences via renderer map (legacy words like "changes owner" survive as display text, now checkable); ordering := family priority. **Fewer hint-fallback firings** because timelock/Safe/upgrade/exec claims now exist |
| `protocolScore.js:162-179` | `hook_update`→config 0.78 (inflated by approve-class mislabels); upgrade detection **by function name**; dead branches at :170/:177 | upgrade severity keys on `upgrade.*` claims (name-substring arm deletable); `exec.arbitrary`→0.95 and `timelock.*`→0.62 become live; the measured 143-row config-severity inflation disappears; tier available for weighting |
| `principal_enrichment.py:120-168` | `_admin` granted off `hook_update` (mislabel-driven); `_manager` never grantable | `_admin` := control-claim families (`ownership.*`, `authorized_caller.rotate`, `roles.*`, `authority.replace`, `upgrade.*`, `proxy.admin_change`, `callee_pointer.rotate`, `timelock.*`); `_operator` := flow claims; `_manager` := `exec.arbitrary` (producible for the first time). Measured: **zero prod principals** depend on `hook_update` for their `_admin` tag — no regression |
| `primary_controller.py:161-179` | deliberately ignores `hook_update`/`external_contract_call` | same exclusion preserved by construction (facts carry no significance weight); gains `upgrade.implementation` coverage on upgrade fns (today reachable only via `delegatecall_execution`) |
| `company_overview.py:940-963` | capability chips; deliberately unmapped coarse labels | chips key off `claim_id`; its existing choice (show function names for the coarse class) is exactly the design's fact-text disposition |
| Monitoring enrollment | does **not** read labels (dossier correction) | unchanged; pause claims can feed `is_pausable` recall (Teller case measured) |
| `graph.js:322`, `PermissionsTab.jsx:20` | render raw label strings | render registry sentences + provenance tier |

H2's starvation measurement is the proof this layer is necessary: deleting semantics without
a replacement costs 40% of severity signal and every admin display name (§4).

---

## 8. Inter-agent disagreements and how evidence resolved them

**D1 — Struct-member pause: derivable or ceiling?** Agent 2 called Accountant-style struct
pause "unprovable at current engine granularity"; Agent 1 claimed a working member-path
derivation. **Resolved for Agent 1 by orchestrator verification**: the v2 prototype output
(`h1v2_results/0x05a1552c...json`) shows `pause()`/`unpause()` → `pause_toggle` while
`updatePayoutAddress`/`updateDelay`/fee setters (other members of the *same struct*) are
excluded, and the prototype code extracts `(var, member)` pairs from IR with the member's
declared bool type checked against `contract.structures` — no name matching. Struct pause is
a fixture-gated registry idiom, not a ceiling. (Agent 2's own confidence note anticipated
exactly this outcome.)

**D2 — Tree-derived ownership: producer or corroboration-only?** Agent 2 measured the tree
tier unsound both unguarded (45 FPs kept) and `is_constant`-guarded (11 real OZ v5 TPs
lost). **Resolved by composition**: both are true of the tree tier *alone*; the design makes
standards gates the primary carrier for `ownership.transfer` (ghost-immune, catches OZ
v5/Solady where write attribution fails) and keeps the guarded tree idiom only for what
standards can't see — bespoke non-owner rotations — as the new `authorized_caller.rotate`
claim. Agent 2's fact-rendering ("rotates caller-authority address `pauser`") and Agent 1's
new label were the same statement in different clothing; it must be a claim (not a fact)
because consumers grant `_admin`/0.88 severity off it.

**D3 — Vocabulary shape.** Agent 1 kept legacy strings + 3 additions; Agent 2 namespaced
claim ids + renderer map. **Resolved as both**: namespaced ids are canonical in the registry
(strictly more expressive — `safe.signer_mgmt` has no honest legacy equivalent); every entry
declares a legacy projection so consumers migrate independently.

**D4 — `implementation_update` structural dataflow detectors.** Agent 1 kept them (with a
slot-value rewrite, designed not prototyped); Agent 2 retired them. **Resolved for Agent 2 by
the corpus**: 0 firings ever, in prod and in both local samples, while the standards gates
recovered 17/17 measured cases including the zos proxy the string-matcher provably fails on.
The dataflow signal survives as a Plane-0 fact (`fallback_delegatecall_read`), available as
evidence for a future bespoke-pattern registry entry.

**D5 — Pause via fixed PauseInfo vs registry idioms.** Agent 2's measured PauseInfo failures
(8 missed `pauseContract` fns, `threshold`/`_minDelay` FPs) are precisely the two bugs Agent
1 found mechanisms for (inherited-private-var lookup; bool/polarity typing). **Resolved as
convergent**: the fixed derivation *is* a registry idiom entry — Agent 2's own disposition
table specifies the identical fact-chain. No residual conflict.

Consensus items (no adjudication needed): facts-plane hardening list, guess-tier deletion,
selector canonicalization (the only 100% tier), dead-label resurrections, typed policy-stage
propagation, silence-over-marked-guess, the registry + fixtures + A/B gate mechanism, and
all of §2's defect findings (independently discovered by both).

---

## 9. Irreducible ceilings (what stays unknowable, and the design's response)

1. **OZ v5 namespaced / Solady assembly writers outside canonical selectors** — Slither
   cannot attribute which slot a `$.member` or `sstore` write hits. Canonical selectors carry
   the standard functions; non-canonical writers on such contracts stay **silent** (fact
   text). OZ v5 `initialize`'s owner-set is knowingly unlabeled.
2. **Caller-keyed map purpose** (composeQueue vs wards): never derivable from write shape —
   permanent; only selector/standard evidence may claim role management. Institutionalized
   as a mandatory counterexample fixture class.
3. **Whole-standard behavioral conformance on forks** (5/8 sampled ERC-20 matches deviate):
   claims are mechanism-level with witnesses, never pack-level.
4. **Whether an upgrade function controls a live proxy**: static sees the impl only; the
   policy tier upgrades provenance when the classifier confirms the linked slot — claim text
   never exceeds its tier.
5. **Intent/economic severity** (benign ops pause vs rug vector): silence; severity remains
   a consumer-side policy over claims + capability + principals.
6. **Meaning of arbitrary calldata** (`manage`/`execute` payloads): only arbitrariness is
   provable (taint); claimed as `exec.arbitrary`, nothing more.
7. **Guard-extraction-uncertain functions** (predicate pipeline fails closed): no tree ⇒ no
   tree-tier claims; selector/fact tiers only — consistent with existing fail-closed policy.
8. **Engine variance floor**: 2/27 contracts yielded empty write-sets for functions that
   plainly write storage (LayerZeroTeller.pause, EndpointV2.sendCompose — cause undiagnosed).
   Mitigation is multi-source corroboration, not certainty.
9. **Value-flow beneficiary**: mechanism (transferFrom, target) is provable; who ultimately
   benefits is not. Claims state mechanism only.

---

## 10. Migration sketch (non-binding; explicitly not a decision criterion)

- **Phase 0** — facts-plane fixes behind the existing artifact schema (sink origin, member
  writes, clobber fix, hygiene classes, native-transfer sinks, direction fix). Pure accuracy;
  no consumer change. Add the fixture corpus + A/B gate pinned to *current* behavior first.
- **Phase 1** — registry module with the ~20 measured matchers (18 standards/idioms from
  h3sim + callee_pointer + exec.arbitrary + the fixed pause/authorized-caller idioms);
  fixtures from this investigation's corpus. Emit claims alongside legacy `effect_labels`
  (dual-write; legacy strings derived from claim projections). Golden diff reviewed against
  this report's expected corrections (hook 340→~14, pause −32 FP/+7 FN-recovered, impl
  0→17+, ownership −47 FP, timelock 0→6).
- **Phase 2** — consumers cut over one at a time behind flags: `lane.js`/`meta.js` (with
  Playwright visual baselines per CLAUDE.md), then `protocolScore` (delete the name-substring
  upgrade arm once `upgrade.*` claims flow), `principal_enrichment`, `primary_controller`,
  `company_overview`.
- **Phase 3** — replace `cross_contract.py` propagate-all with the typed policy derivations;
  delete the guess/structural-stringly detector tiers and the legacy column; retarget pinned
  tests (`test_contract_analysis.py:301` asserts `callee_pointer.rotate`;
  `test_effects.py:334` asserts ownership claims). Stored prod rows are stale either way;
  recompute on next protocol run. Rollback boundary is per-consumer flags.

---

## Appendix A — Corpus and method

Prod: read-only SELECTs over 2,182 `effective_functions` rows (label distributions,
per-fn-name breakdowns, principal-tag dependency queries). Local: current `main` run
in-process (crytic-compile etherscan → Slither → `build_effects` →
`apply_authority_effect_labels`) on 21 (Agent 1) and 27 (Agent 2) verified contracts spanning
the hard-case battery + prod corpus: WETH9, EETH, BoringVault, Teller, Accountant,
RolesAuthority, L1SyncPoolETH, EndpointV2, FiatTokenProxy, FiatTokenV2_2, DAI, Comp,
EtherFiTimelock, OneSig, TopUp(V2), EtherFiNodesManager, StakedTokenV1, BackingEigen,
LiquidityPool, StrategyManager (proxy+impl), SafeL2, TimelockController, wBETH proxy,
MembershipManager, and others. Ground truth: verified source read per labeled row; graded
against the rendered claim sentence. Prototypes: H1 derivations (two iterations, own FPs
found and fixed), H3 gate matcher (two iterations), H2 starvation simulation over all prod
rows, naive facts-lane derivation.

## Appendix B — Dossier corrections

(a) `apply_authority_effect_labels` is itself a top FP source on OZ v5 (the "precise layer
already exists" premise fails there); (b) **two** labels are dead, not one
(`arbitrary_external_call` also has zero producers); (c) monitoring watch flags do not
consume effect labels; (d) additional verified defects: interface-record clobbering,
guard-origin sink dilution, cross-contract propagate-all contagion + per-deployment label
nondeterminism, initialize-as-pause (44% of the pause corpus), `recoverERC721` direction,
`WETH9.withdraw` miss, PauseAnalyzer inherited-var and uint-typing gaps.

## Appendix C — Artifacts

All investigation artifacts are preserved in-repo under `labels_redesign/` (see its README
for layout and re-run instructions):

- `labels_redesign/agent_outputs/` — both investigators' full structured outputs
  (workflow `wf_b3e979d9-ebf`).
- `labels_redesign/agent1/` — evidence-first investigator: in-process pipeline runner,
  H1 prototypes (v1/v2 incl. the member-path pause derivation), 21-contract baseline +
  prototype results, prod row dump, fetched source scaffolds.
- `labels_redesign/agent2/` — clean-slate investigator: harness, per-function grading
  (`score_labels.py`, auditable verdicts), `h1sim`/`h1g` guard measurements, `h3sim`
  standards matcher (the registry seed), `derive_sim` starvation bound, fetched sources
  (`crytic-export/`).

The source scaffolds double as the seed of the frozen fixture corpus required by §6.3.
