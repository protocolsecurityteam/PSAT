# Handoff — design investigation: what should function-effect labels BE?

## Mission
PSAT's per-function effect labels (`ownership_transfer`, `hook_update`, `pause_toggle`, …)
drive user-visible semantics — Surface chip text ("changes owner", "changes hook"), lane
placement, lane ordering, chip color, protocol risk score, and principal permission tags —
but they are produced by a mixed bag of detectors of wildly varying rigor, including at
least one pure shape-guess with a confirmed corpus-wide mislabel (ERC-20 `approve`/`transfer`
rendered as control-lane "changes hook"). Run a **2-agent workflow** to determine the
CORRECT redesign of this system from first principles, then synthesize their findings
yourself into one decisive recommendation. This is a **design investigation — READ-ONLY**:
no code edits, no commits, no DB writes. Deliverable = a design spec + evidence, not a patch.

## The question (do not narrow it prematurely)
What should a "label" be, such that every emitted semantic statement about a function is
**verifiable** and the system is **structurally resistant to heuristic creep**? Candidate
directions include (evaluate ALL, generate more):
- **H1 — evidence-standard redesign (incumbent proposal — ATTACK IT, don't assume it):**
  keep the current vocabulary; write a per-label claim + required-evidence spec; derive the
  authority-adjacent labels from predicate trees (extend the existing
  `apply_authority_effect_labels` pattern to pause/authority/implementation); canonical
  selectors where a standard exists; DELETE the guess tier (fact-text fallback instead);
  optional provenance tiers on labels (tree-proven / selector / structural / fact-only).
  NOTE: this hypothesis comes from the same assistant that wrote this handoff — it is one
  hypothesis among equals, not the favorite.
- **H2 — facts-only:** static stops emitting semantic labels entirely; it emits verifiable
  facts (state writes + the ROLE of written state + sinks + value flows); each consumer
  (lanes/score/enrichment) derives its own view from facts. UI vocabulary becomes a
  presentation-layer mapping.
- **H3 — standard-aware semantic models:** match functions/contracts to known standards
  (ERC-20/721/4626, EIP-1967, OZ Timelock/AccessControl, Solmate/Solady auth, Safe) and
  emit exact per-standard semantics; everything non-standard gets facts only, no labels.
- **H4 — relocate labeling downstream:** compute labels at the policy/aggregation stage
  where predicate trees, resolution results, proxy classification, and the control graph
  ALL exist (e.g. `implementation_update` provable via slot + classifier; role semantics
  via resolved authorities) — static emits facts only.
- **H5+ — agent-generated:** each investigator MUST propose at least one serious
  alternative not listed here (e.g. labels-as-claims objects with provenance; two-tier
  claim/fact split; LLM-assisted labeling hard-gated on facts; retiring labels in favor of
  capability_expr + sinks driving the UI directly). "Keep as-is + patch bugs" is also a
  hypothesis and must be costed honestly.

## Hard constraints on the evaluation
- **Correctness is the criterion. Migration cost / tech debt / invalidated stored data are
  EXPLICITLY NOT criteria.** A migration sketch is a deliverable, but it must not bias the
  recommendation. Do not soften the answer to protect existing code.
- **Zero unfalsifiable claims:** under the recommended design, every emitted semantic
  statement must have a written, checkable evidence standard. If something can only be
  guessed, the design must either not say it or explicitly mark it as unproven — pick and
  defend one.
- **Anti-heuristic-creep must be structural**, not aspirational: the design must include a
  mechanism that makes adding an unevidenced label HARD (e.g. a label registry requiring an
  evidence spec + a corpus label-diff A/B gate on every change). Name the mechanism.
- **Consumer fit is required evidence:** enumerate what each consumer actually decides off
  labels (lane membership, ordering, color, score severity, `_admin`/`_operator` principal
  tags, monitor flags) and show the recommended design serves those decisions at least as
  well. A precise design that starves consumers fails.
- **Honest ceilings:** some semantics are provably not derivable statically — the repo
  documents one (see dossier). The recommendation must name what remains unknowable and
  what the design does about it (silence vs marked-guess).

## Context dossier (verified 2026-07-03 — verify line numbers on disk, don't trust blindly)
Repo `/home/riley/PSAT`, branch `fix/surface-controls-fp-gate` — do NOT switch branches.

**Producer:** `services/static/contract_analysis_pipeline/summaries.py::_effect_labels` (~:664).
Detector tiers as they exist today:
- Exact facts: sink kinds (`contract_creation`/`delegatecall`/`selfdestruct` via graph_entry),
  `_function_has_low_level_value_call` (:358 → asset_send), `_detect_encoded_selectors`
  (:621, canonical ERC-20 selectors), `_access_control_label` (:317, canonical OZ/Solmate
  selectors → role/authority setters).
- Structural use-based (right idea, stringly matching): `_writes_pause_like_bool` (:445 —
  bool written here + read by a modifier that gates OTHER functions),
  `_writes_owner_like_address` (:463 — substring scan for var name + "msg.sender" in
  stringified modifier IR), `_writes_authority_reference` (:498 — `dest:{name}` substring),
  `_writes_hook_reference` (:517 — a mapping-writing sibling calls the written var,
  `dest:{name}` substring), `_writes_delegatecall_target` (:381),
  `_writes_assembly_delegatecall_slot` (:404).
- Pure guesses: `_writes_unclassified_address_pointer` fallback → hook_update (:727) —
  KNOWN BUG: `_is_address_like_state_var` (:542) matches `mapping(address=>…)` by substring,
  so ERC-20 approve/transfer/increaseAllowance/decreaseAllowance get hook_update (confirmed
  on prod AND on a since-torn-down preview run: 52 rows across ~11 tokens — EETH,
  FiatTokenV2_2, StakedTokenV1, WrapTokenV3ETH, LinkToken, Comp, Dai, WETH9, BackingEigen,
  Eigen, WeETH; dates to PR #45); `_detect_supply_change_pattern` (:576) parses `str(ir)` text.
- `_action_summary` (:806) maps labels → the one-line text.

**The precise layer already exists:** `services/static/contract_analysis_pipeline/effects.py`
— facts artifact (EffectInfo/SinkRecord: state writes, sinks, writer selectors, targets);
`apply_authority_effect_labels` (:482) pulls state vars from predicate-tree
`caller_authority` EQUALITY leaves (`_owner_vars_from_predicate_trees` :462) and labels
their writers `ownership_transfer`, superseding `_COARSE_AUTHORITY_LABELS =
("hook_update","external_contract_call")` (:446). **The comment at :440 records the
counterexample that killed general role derivation: a caller-keyed data map (LayerZero
`composeQueue`) is structurally identical to a caller-keyed ACL membership leaf — writing
one is NOT reliably "role management". That is why role_management is selector-canonical.**
Predicate trees (leaves carry kind/operator/operands/references_msg_sender/authority_role ∈
caller_authority|pause|business|reentrancy|time|one_shot) are the same artifacts that drive
authority verdicts — the highest-trust data in the system.

**Consumers (what labels decide):**
- `site/src/surface/meta.js:5` `CONTROL_EFFECTS` → lane membership; `site/src/surface/lane.js:30-67`
  → chip color (`toneForFunction`), visible text (`compactActionSummary`: "changes owner",
  "changes hook", "changes logic", "pause control", "moves value in/out"), ordering
  (`lanePriority`).
- `site/src/protocolScore.js:172` — labels → risk severity (hook_update = config 0.78; the
  approve mislabel inflates protocol scores today).
- `services/policy/principal_enrichment.py:118-170` — labels grant principal permission
  tags (`_manager`/`_operator`/`_admin`).
- `services/governance/primary_controller.py:161` + `services/aggregations/company_overview.py:940`
  deliberately IGNORE hook_update/external_contract_call as too coarse.
- Frontend consumes `timelock_operation`, which is PRODUCED NOWHERE (dead label).
- Tests pinning current behavior: `tests/test_contract_analysis.py:301` (genuine setHook →
  hook_update), `tests/test_effects.py:334-340` (transferOwnership must NOT be hook_update),
  `tests/test_symbolic_effects.py:~400/449/572`, `tests/test_effective_permissions.py:241/298`.

**Known defects/gaps to account for:** the hook_update mapping bug (above); name-collision
FPs possible in the `dest:{name}` / substring matching; supply-change string parsing;
timelock_operation dead; deferred detections: Maker-style inline `wards` mapping auth,
inline pause writes, cross-contract PauserRegistry-style pause.

**Hard-case battery — every hypothesis must be scored against these on REAL contracts:**
LayerZero composeQueue (caller-keyed data map ≠ ACL); BoringVault/Teller beforeTransfer
denylist (a REAL transfer hook); Solady EnumerableRoles assembly owner gate; EIP-1967 + zos
legacy assembly slot writes (UUPS / FiatTokenProxy); ERC-20 approve/transfer (must NOT be
control-plane); WETH9; OZ TimelockController queue/execute; Maker wards mapping; pause via
require vs modifier vs external PauserRegistry; Comp-style delegation maps; one-shot
initializers.

## Access (read-only; each Bash call is a fresh shell)
- **The pr-144 preview app is TORN DOWN — do not try to reach it.** The only remote DB is PROD.
- Prod DB: `PRODURL=$(fly ssh console -a psat -C "printenv DATABASE_URL" | tr -d '\r' | tail -1)`;
  psql with `PGOPTIONS='-c default_transaction_read_only=on'`, SELECT only.
- **Prod-data caveat — read carefully:** prod is VERY OUTDATED (jobs are mostly 2026-06-01
  vintage; they predate the recent authority-accuracy work — #132 earned-public, #134, the
  #111–#122 batch, and the 93868bc revert-sink fix). Its capability verdicts / authority
  rows / principal data contain KNOWN stale defects that are already fixed or tracked
  elsewhere — do NOT investigate, re-diagnose, or report them; they are out of scope. What
  IS still representative there is the summaries/effect-label output: the same label
  symptoms are present (verified: identical hook_update labels + action_summary text on the
  same address+selector pairs — EETH, StakedTokenV1, WrapTokenV3ETH, WETH9.approve). Use
  prod rows as evidence of the symptom and its corpus-wide distribution, nothing more.
- **Primary measurement path for CURRENT-code labels:** prod rows reflect old deployed code,
  so to measure what the code on THIS branch emits, run the static pipeline locally and
  in-process on Etherscan-fetched verified sources (crytic-compile etherscan platform →
  Slither → `build_effects` / `_effect_labels` / `apply_authority_effect_labels`). Pick
  targets from the prod corpus + the hard-case battery. This also lets you prototype-score
  each hypothesis's derivation on the same sources.
- Prod Tigris artifacts (predicate_trees + effects for prod jobs, useful as tree examples):
  derive ARTIFACT_STORAGE_* via `fly ssh console -a psat -C "printenv <VAR>"`; boto3
  get_object, read-only.
- `ETHERSCAN_API_KEY` in `/home/riley/PSAT/.env`; verified source via
  module=contract&action=getsourcecode; eth_call recipes: owner()=0x8da5cb5b,
  addr='0x'+result[-40:].
- Ground-truth method for accuracy measurement: sample labeled rows per label (exhaust the
  control-plane labels; sample ≥30 for high-volume ones), read the verified source, judge
  correct/wrong/unprovable. Numbers, not adjectives.

## Workflow shape — exactly 2 agents, then YOU synthesize
Both agents inherit the orchestrator's model (do NOT set per-agent model overrides); run
them in parallel at high/max effort. Give them OPPOSING priors to prevent convergence:
- **Agent 1 — evidence-first prior:** steelman H1/H4 (ground labels in existing pipeline
  artifacts), attack H2/H3. 
- **Agent 2 — clean-slate prior:** the current vocabulary is NOT sacred; steelman H2/H3 and
  novel proposals, attack H1/H4.
Each agent must independently: (1) map the current system from the CODE (the dossier above
is a starting index, not the truth); (2) measure current per-label accuracy on the real
corpus with ground-truthed samples (prod rows for the deployed symptom + local in-process
runs for current-code output; ignore prod's stale authority-side defects per the Access
caveat — the scope is the label system only); (3) evaluate EVERY hypothesis including the opposing
agent's assignments; (4) run the hard-case battery per hypothesis; (5) enumerate consumer
needs from the consumer code; (6) produce a per-label disposition table under its
recommended design; (7) name the irreducible ceilings.
Then you (the orchestrator) adversarially synthesize: agreements are strong signal;
disagreements get resolved by evidence (re-run the deciding measurement yourself if
needed), never by splitting the difference. Produce the final recommendation.

## Per-agent output schema (StructuredOutput)
{ current_system_map, corpus_accuracy (per-label numbers: sampled n, correct, wrong,
  unprovable, with the worst concrete examples), hypotheses: [{id, summary,
  evidence_standard, hard_case_results, corpus_impact_numbers, consumer_fit, failure_modes,
  verdict}], novel_hypotheses, recommended_design, label_disposition_table: [{label,
  disposition(keep|redefine|retire|merge|new), claim_it_makes, evidence_required,
  provenance_tier, hard_cases_passed}], irreducible_ceilings, anti_heuristic_guardrails,
  migration_sketch (explicitly non-criterion), confidence }

## Definition of done
One decisive recommendation with: the winning design named and specified (per-label claim +
evidence table covering the ENTIRE current vocabulary plus any new/retired labels); every
hypothesis scored on the hard-case battery and real-corpus numbers; consumer-fit
demonstrated against the actual consumer code; the structural anti-heuristic mechanism
specified; the honest list of what stays unknowable; a non-binding migration sketch; and
each inter-agent disagreement surfaced with how the evidence resolved it. All claims
grounded in the real corpus/code/on-chain — not in this dossier's summaries.
