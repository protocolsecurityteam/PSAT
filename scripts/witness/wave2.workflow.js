export const meta = {
  name: 'witness-wave2',
  description: 'Witness-integrity Wave 2: legs B (capability/authority) and D (effects/witness) in parallel worktrees',
  whenToUse: 'Run only after Wave 1 exited (see WAVE_1_REPORT.md) and the tier-0 gate passes at HEAD.',
  phases: [
    { title: 'Legs', detail: 'B, D in parallel worktrees; impl -> review -> retry(<=3) each' },
    { title: 'Merge', detail: 'merge leg branches into fix/witness-integrity, resolve goldens' },
    { title: 'Exit gate', detail: 'tier-0 gate + full-replay differential (L-25 bucket)' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

// Conventions carried from wave1.workflow.js: cap-3 review loop, reviewer
// scope discipline + out_of_scope_findings channel, halt -> driving-agent
// adjudication. See WITNESS_INTEGRITY_OPERATIONS.md. New this wave (OPS §2,
// added post-Leg-C): implementer prompts carry the reviewer's lens up front.

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const W24 = 'WITNESS_INTEGRITY_WAVES_2_4_HANDOFF.md'
const OPS = 'WITNESS_INTEGRITY_OPERATIONS.md'
const BRANCH = 'fix/witness-integrity'
const W2_BASE = '93954b96' // Wave 1 closeout HEAD; every leg must contain this commit
const WT_ROOT = '/tmp/claude-1000/-home-riley-PSAT/d8116573-440b-4ce0-8e02-ddab7ee5b902/scratchpad/wave2'
// Wave-1 full-replay substrate (scaffold from source_files -> local PG ->
// collect_contract_analysis_with_artifacts, PYTHONHASHSEED pinned; 88/92
// contracts — cids 79/639/640/641 have no stored sources):
const REPLAY_SUB = '/tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/work'

const REVIEW_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['accepted', 'violations', 'summary'],
  properties: {
    accepted: { type: 'boolean' },
    summary: { type: 'string' },
    violations: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['rule', 'detail', 'reproduction'],
        properties: {
          rule: { type: 'string', description: 'R1 | R2 | R3 | R4 | R5 | other' },
          detail: { type: 'string' },
          reproduction: { type: 'string' },
        },
      },
    },
    out_of_scope_findings: {
      type: 'array',
      description: 'Real reproduced defects OUTSIDE the leg scope — ledgered, never rejection grounds',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['detail', 'reproduction'],
        properties: { detail: { type: 'string' }, reproduction: { type: 'string' } },
      },
    },
  },
}

const GATE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['passed', 'failures', 'raw'],
  properties: {
    passed: { type: 'boolean' },
    failures: { type: 'array', items: { type: 'string' } },
    raw: { type: 'string' },
  },
}

const VERIFY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'findings', 'controls_held', 'differential_reconciled'],
  properties: {
    verdict: { type: 'string', description: 'PASS | FAIL' },
    controls_held: { type: 'boolean' },
    differential_reconciled: { type: 'boolean' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['severity', 'claim', 'evidence'],
        properties: {
          severity: { type: 'string' },
          claim: { type: 'string' },
          evidence: { type: 'string' },
        },
      },
    },
  },
}

const boilerplate = `
Repo /home/riley/PSAT. Read \`${OPS}\` FIRST (authority: no human escalation —
judgment routes to the driving agent; cost boundary: never start workers/
pipeline stages/live suite/analysis jobs, never regenerate the analyzed
corpus, never loop RPC over the population; verification ladder ends in
defer-with-stated-cause). Then \`${HANDOFF}\` §0-§2 (governing rule, traps,
R1-R5 + review-lens charter), \`${W24}\` (Wave 2 folds + measurement-method
warnings), and WAVE_1_REPORT.md ("Carried into Wave 2+").

AUTHORISED: commit to your leg branch. NOT AUTHORISED: git push, PR, merge to
${BRANCH} or main, live suite, production, editing .env/CLAUDE.md/settings.

Traps (§1): stale pr-160/ storage-key prefix is handled by the read path — but
StorageKeyMissing is still never evidence of absence; jsonb null vs SQL NULL
(use jsonb_typeof); jsonb_array_elements needs a case-guard; eRPC "latest"
flakes (pin hex(head()-10); 25619159 for historical). On-chain facts: >=3 reads
+ a pinned read at 25619159, with a discriminating control address. SPARING RPC
use — single facts, never population scans. Handoff line numbers may have
drifted a few lines after Waves 0-1 landed; locate by content, not offset.

MEASUREMENT METHOD (burned two Wave-1 agents — binding): the artifact-only
claims recompute build_claims(None, effects, trees) is INVALID (drops
idiom-tier claims 20->6). Any claims/summaries-plane measurement uses the full
in-process replay (scaffold from source_files, PYTHONHASHSEED pinned) — the
Wave-1 substrate is at ${REPLAY_SUB} (replay.py; rebuild from the description
in ${W24} if it is gone). The local DB is one protocol/one chain: every count
is a LOWER BOUND. The production DB is stale and is NEVER evidence.

IMPLEMENTER'S LENS, up front (OPS §2 — the reviewer verifies these, so do them
first, not after): (1) enumerate EVERY consumer of every field you change and
state per consumer how it keeps proven-present / proven-absent /
not-determined apart; (2) for each new/changed evidence field, write the
input-shape -> published-state table and verify the two chronic failure
routes — a not-determined input reaching a proven state, and the adverse
branch never executing; (3) ask the collapsed-inputs question of your OWN new
code (what did the input discard before this code saw it?); (4) you may look
beyond your item list freely — report out-of-scope observations in your
report, never fix them silently.
`

function implPrompt(leg, retryNote) {
  return `${boilerplate}

You are the tier-1 implementer for **Wave 2 Leg ${leg.key} — ${leg.title}**.

WORKTREE SETUP (do this first, exactly):
  cd /home/riley/PSAT
  git worktree remove --force ${WT_ROOT}/leg-${leg.branch} 2>/dev/null; git branch -D witness/leg-${leg.branch} 2>/dev/null
  git worktree add ${WT_ROOT}/leg-${leg.branch} -b witness/leg-${leg.branch} ${BRANCH}
  cp /home/riley/PSAT/.env ${WT_ROOT}/leg-${leg.branch}/.env
  cd ${WT_ROOT}/leg-${leg.branch}
  git merge-base --is-ancestor ${W2_BASE} HEAD && echo BASE_OK   # must print BASE_OK; if not, STOP and report
Work ONLY in this worktree, commit ONLY to witness/leg-${leg.branch}. Docker
services are shared and already up. Offline tests: the worktree has no
run_tests_fast.sh (untracked); use the canonical serial command from CLAUDE.md
scoped to the test files you touch, and run the FULL suite only once before
your final report. TEST-DB ISOLATION (new this wave — two legs run suites
concurrently): create your own test DB and use it for every pytest run:
  PGURL=$(echo "$TEST_DATABASE_URL" | sed 's|+psycopg2||; s|/psat_test.*|/postgres|')
  psql "$PGURL" -c "DROP DATABASE IF EXISTS psat_test_leg${leg.branch};" -c "CREATE DATABASE psat_test_leg${leg.branch};"
  export TEST_DATABASE_URL=$(echo "$TEST_DATABASE_URL" | sed "s|/psat_test|/psat_test_leg${leg.branch}|")
(conftest applies migrations on first run). If a MinIO-backed storage test
fails inexplicably while the other leg is running its suite, re-run that file
once before treating it as real.

Read \`${HANDOFF}\` §6 "Leg ${leg.key}" IN FULL — problem statements, measured
evidence, exact fix shapes, including every "Added by G6/G7" item (they are
your scope). Also read \`${W24}\` "WAVE 2 — Leg ${leg.key}" for the items
folded in from the Wave-1 ledger. §11 lists known-wrong hypotheses — do not
implement against a refuted premise. Your items:
${leg.items}

${leg.constraints}

BEFORE writing code, state: (1) POSITIVE control (row that must stay flagged),
(2) NEGATIVE control (row that must stay clean), (3) measured "before" numbers.
R1-R5 are binding. R2: any sentinel/fail-closed branch needs a firing proof
against real data (or the honest "reachable by construction + test-covered,
zero realised rows — lower bound" statement where the shape has no realised
rows). Corpus goldens: never regenerate blindly — enumerate and justify every
ADDED/CHANGED/REMOVED row in your report. Expect to delete/invert tests that
pin defects; declare each in the commit message.

One commit per coherent item (not one giant commit). Report: per-item what
changed, before/after numbers, controls status, sentinel proofs, golden diffs
enumerated, consumer enumeration for every changed field, and an explicit
"what I did not check".${retryNote}`
}

function reviewPrompt(leg, implReport) {
  return `${boilerplate}

You are the tier-2 reviewer for **Wave 2 Leg ${leg.key} — ${leg.title}**.
Review ALL commits on branch witness/leg-${leg.branch} (worktree
${WT_ROOT}/leg-${leg.branch}; run tests there — it has .env copied in; use the
leg's own test DB psat_test_leg${leg.branch} via TEST_DATABASE_URL override as
described in the implementer's setup, to avoid clobbering the other leg's
concurrent runs). Compare against ${BRANCH} (merge-base ${W2_BASE}).

Adversarial in miniature, not a checklist. The judgment-bearing pair:
  R1  three representable states on every new/changed evidence field,
      distinguishable by a consumer; a non-nullable boolean on an evidence
      field is a defect by construction.
  R4  positive-case tests, not only hedges; a test pinning a hedge needs a
      sibling pinning the un-hedged value's reachability.
Also: R2 (run every firing query yourself), R3 (consumers changed in the same
commit — over-claims often have a PROSE copy), R5 (EFFECT_CACHE_SCHEMA_VERSION
if witness shape changed; it is 21 at base), both declared controls, the
implementer's consumer enumeration VERIFIED (not sampled — the enumeration is
the deliverable), and the leg's stated constraints (below) held.

${leg.constraints}

SCOPE DISCIPLINE (binding, ${OPS} §2): a violation may reject ONLY if it lies
inside this leg's declared scope — the handoff §6 Leg ${leg.key} surface (incl.
G6/G7 additions and the ${W24} folds) plus same-commit consumers of fields the
leg changed. Real defects outside that scope (including pre-existing behaviour
the leg strictly improves) go under out_of_scope_findings with a reproduction —
never rejection grounds.

The implementer reported:
${implReport}

Refuting is a successful outcome. Accepting something you did not reproduce is
the only failure mode. Every violation needs an exact reproduction command.`
}

const LEGS = [
  {
    key: 'B',
    branch: 'b',
    title: 'capability/authority',
    model: 'fable', // highest-risk leg: 351-function reroute (handoff §8)
    items: `
1. guard_extraction_uncertain made LIVE for G3's tree-absent class: the
   fail-closed branch in services/policy/effective_permissions.py (~:529-533,
   locate by the "guard not extracted" comment) has NEVER executed — 351
   functions fall through to status='public' as the else of a resolver-
   availability check. Populate guard_uncertain_signatures where the static
   stage could not lower a caller-authority guard into a tree, so those rows
   route to 'unsupported' instead of 'public'. R2 WITH FULL FORCE: prove the
   sentinel fires on the MERGED corpus via full replay. FIRST re-measure the
   tree-absent population — Leg A's class-F/R work ADDED trees (87 functions
   gained trees), so the wiring target moved since G3 measured >=5. A1's
   binding scope: NO fix scoped/tested/accepted against "blast radius 2".
2. A1 root cause: a Solady EnumerableRoles assembly-backed, named-return role
   read the static lifter cannot lower, after which caller taint is hashed
   away and a hardcoded authority_role="business" default takes over. (§11:
   the "callee parameter binding" hypothesis is REFUTED — do not implement
   against it.)
3. effective_functions.authority_public is bool NOT NULL — split the value
   (R1): the capability algebra can say external_check_only; the COLUMN
   collapses it to the same value a fully-resolved function gets. Alembic
   migration + writer + every consumer enumerated.
4. G2 empty-intersection: an empty AND-intersection must yield not_determined,
   NEVER resolved_empty/finite_set/members=[]/membership_quality=exact/
   confidence=enumerable. 3 of 80 resolved_empty rows are false, all on
   user-facing withdrawal paths (WithdrawRequestNFT.requestWithdraw is the
   canonical one: 14 candidates intersected to empty while liquidityPool() on
   the contract itself returns the actual caller). membership_quality='exact'
   / confidence='enumerable' must not be emitted on an unwitnessed set.
5. GAP 2 — SAME COMMIT as item 4 (chain requirement, binding):
   services/resolution/adapters/enumerable_role_store.py resolves the registry
   implementation + ControllerValue rows by bare lower(address) with NO chain
   predicate while ctx.chain_id is in scope 4x in the same file. Add the chain
   filter. Also the except-Exception -> return set(), {} in that block turns a
   DB error into "no candidates" — the exact empty-set shape this leg exists
   to stop; distinguish error from empty (R1): an error must never be able to
   reach resolved_empty.
6. G2 HIT2 — the LIVE fold: services/resolution/mapping_enumerator.py
   (~:388-405) detects add/remove ambiguity, del's the topic from
   topic0_to_specs, then returns an EnumerationResult reporting SUCCESS over a
   knowingly incomplete fold. Same class as item 7; fixing only the durable
   path leaves the class half-open.
7. G2 fold bug: services/resolution/repos/event_logs_pg.py (~:241-256) — the
   inner loop runs BOTH add and remove hints over EVERY row, so membership is
   decided by hint-list order, not the event's boolean payload;
   value_position is never consulted.
8. effective_functions.authority_roles is [] hardcoded on 1773/1773
   (effective_permissions.py, the literal constant near :646). inv 3's scoring
   unit is the (capability, principal) pair and the role half does not exist.
   Derive and persist real role requirements. R3 consumers (enumerate + keep
   three states apart in the same commit): site/src/surface/layout/
   controlGraph.js:77, site/src/surface/layout/governsIndex.js,
   services/aggregations/analysis_detail.py:300,
   services/resolution/recursive.py:572,
   services/policy/principal_enrichment.py:353.
9. function_principals.origin + principal_type are single constants on
   1132/1132 (semantic_capability:finite_set / controller) — split the value:
   record the resolver path that produced the row in the writer
   (services/policy/effective_permissions_writer.py). Check first whether
   function_principals.details already carries enough to reconstruct it (open
   per G6) and say what you found.
10. Two capability_expr keys: (a) blacklist_quality — the defect is the
    DEFAULT: emit-when-non-default means absence => 'exact', so a naive
    consumer reads every cofinite denylist as complete; fix shape: narrow —
    emit it ALWAYS (capability_resolver.py ~:1067). (b) last_indexed_block —
    present on 240 rows, read by nothing; inv 11/12 need exactly this fact;
    surface it with a staleness threshold (spread within one job is 203
    blocks). State what a consumer sees when it is absent.
11. FOLDED IN from Wave 1 (L-40/L-41/L-42-class, HIGH — see the ledger + ${W24}):
    Leg A's class-F/R tree widening mints 37 new controller-tracking targets
    with authority_provenance ABSENT; 28 survive the primitive-scalar skip
    (incl. pure constants MAX_SHARE_AMOUNT/TYPE_3/HUNDRED_PERCENT_IN_BPS and
    non-authority mappings _balances/peers/assetData). On the next resolution
    run they persist as controller_value control edges — an over-claim surface
    created by the Wave-1 merge. Decide the correct gate (provenance-absent
    targets must not mint control edges / must carry not-determined) and
    implement it WHERE THE RESOLUTION STAGE READS THE PLAN
    (services/resolution/recursive.py ~:1265-1270 maps absent provenance to
    EDGE_RELATION_CONTROLLER_VALUE — "not-determined must not silently
    demote" was Leg F's rule for call_target; absent-provenance NEW targets
    are a different population: nothing ever proved they gate anyone). Prove
    the gate on the 28-row armed population via projection over persisted
    inputs (no resolution run — cost boundary).
12. terminal_principal producer half: 5 of 6 statuses never fire; 1556 rows
    written, read by nobody (the consumer wiring is Wave 3 Leg E — do NOT wire
    the frontend here). In scope here: services/resolution/tracking.py
    ~:293-304 returns None on ANY probe failure, merging "no such getter" /
    "returned zero" / "RPC failed" — split unknown_unfetched from error so the
    Wave-3 consumer has something true to render. If you judge this belongs
    wholly to Wave 3, defer WITH STATED CAUSE in your report instead.`,
    constraints: `LEG-B CONSTRAINTS: (a) CHAIN REQUIREMENT (handoff §3):
required. GAP 2's chain filter ships in the SAME commit as the
empty-intersection fix. services/resolution/ threads chain_id throughout — use
the context you are handed; any read you add keying on bare address without
contract_id or a chain predicate is unscoped. (b) The zero-cost mitigation
note (status='public' AND jsonb_typeof(conditions)='null' selects exactly the
351) is incidental, not designed — if any of your changes gives an unwitnessed
function an empty array instead of null conditions, you break that census
silently; pin the population definition with a test. (c) Ledger items in your
surface — read before coding, then either fix WITH DECLARED SCOPE or leave
ledgered with stated cause in your report: L-12 (deferred reconciler inner
join on Contract.job_id drops its own 32 marker rows — the ${W24} cites it as
"L-9"), L-27 (_selector_key ""/NULL collision on fallback+receive), L-38
(StrategyManager internal-callee-modifier gates invisible to predicate trees
-> false unconstrained_proven; producer is predicate-tree lowering, at the
boundary of your tree-absent work). (d) Your reroute target: functions whose
guard was seen-but-not-lowered route to 'unsupported'; functions that are
GENUINELY ungated must stay 'public' — state the discriminator precisely and
test both directions (a fail-closed sweep that marks real public functions
'unsupported' is an over-hedge the spec forbids).`,
  },
  {
    key: 'D',
    branch: 'd',
    title: 'effects/witness',
    model: 'opus',
    items: `
1. A7 — RANK 1, ONE vertical slice (one commit): the timed-latch duration
   bound. 0 of 61 freeze_pause verdicts carry a bound because
   _duration_from_trees (services/effects/calldata.py ~:1816) requires a
   constant operand in the latch guard leaf and etherfi's guard is
   storage >= block.timestamp. L-16 (ledger): the positive branch is
   UNREACHABLE from compiled source — the leaf must be WIDENED (the builder
   never co-emits timestamp + state_var + constant in one leaf) before any
   latch fixture can reach it; W0-7's timed-latch fixture only becomes a full
   gate after that widening (its in-fixture docstring says so). The bound
   itself: pauseUntilDuration()/MIN_PAUSE_DURATION()/MAX_PAUSE_DURATION()
   getters exist (28800/86400/172800/2592000 measured at 25619159) — decide
   the static-derivable half vs what needs an eth_call and keep the published
   value honest (no defaulted bound). Ship backend + BOTH prose copies
   (claimsVocab.js pauseQualifier AND claimWitnessFacts ~:966) + inverted
   tests in the SAME commit (R3/R4). The three known defect-pinning tests:
   test_acceptance_timed_latch_publishes_no_bound_it_cannot_prove,
   claimsVocab.test.js:470 "(indefinite)" render, :641 "labels an indefinite
   latch honestly" — each needs a positive-case sibling or inversion,
   declared in the commit message. Do NOT touch the blast radius (it is
   correct). R5 bump with reason.
2. A2 — per-asset holdings. OWED CHECK BEFORE CODING (sparing live read, >=3
   reads + pinned 25619159 + discriminating control): confirm the synthetic
   ETH log's emitter address against a real eth_simulateV1 response with
   traceTransfers. Then fix the INPUT, not the filter (§11: only_asset is
   REFUTED — it would under-claim 100%): per-asset holdings through
   selection.py -> Candidate -> orchestrator -> recipes. 2 of 41 rows carry
   64.96% of all published reach USD and both are truly $0.
3. A2's corroborating gate: reach must never exceed protocol TVL. Read
   defillama_tvl, NEVER total_usd (NULL on every row — a gate against it
   silently never fires, R2 violation). State loudly what the gate does when
   defillama_tvl is absent: skip loudly, not silently.
4. A2's broken inputs (G6-11) land WITH the arithmetic or the error just
   relocates: contract_balances.price_usd = 0 means "no price known" on
   1007/1376 (usd_value already encodes it correctly — NULL=unpriced); the
   holdings fetch caps at 100 with no marker (7 contracts at the cap, one
   $8.6B) and a failed fetch returns [] (holds-nothing / not-fetched /
   fetch-failed all collapse); decimals has a silent 18 default. Consumer
   rule when unknown: a truncated or failed holdings fetch must LOWER
   CONFIDENCE, never produce a confident low value weight.
5. D3 — add reach_determined (R1). The "make reach_indeterminate reachable"
   half is REFUTED (§11) — the branch at recipes.py ~:1533-1535 already fires
   (W0-7 fixture 8 proves it; 18 functions armed). The real defect: when it
   fires it publishes observed_reach_value_usd = acting_balance_usd ($0 for a
   zero-balance router) BESIDE reach_indeterminate — a consumer reading the
   number and ignoring the flag gets "$0 reach" for a function that may move
   millions. Fix what the branch publishes.
6. A6 — approve-then-pull: the transfer sink lives in the callee; class size
   7 (2 manifest, 5 latent) and BINDING: no fix scoped/tested/accepted
   against "2 rows" — each successful probe converts latent to manifest.
   (§11: the resolve_claim_precedence hypothesis is REFUTED.)
7. concrete_destination: minimum viable per G6-3 — write NULL whenever
   destination_shape = caller_arbitrary, and exclude NEUTRAL_CALLER
   (calldata.py ~:77) alongside the existing sentinel; the docstring
   guarantee is one address short. On 35/35 caller_arbitrary rows today the
   value is the probe's own recipient echoed back. A caller-arbitrary
   destination is already the adverse finding; the address can only mislead.
8. Cache proxy-hash refusal (G6-C0): make_bytecode_hash_resolver must refuse
   to hash a contracts row with is_proxy=true — return None (the existing
   "skip, degraded, never guess" path) — and pin with a test. The unstated
   invariant "a proxy row never carries effective_functions" is asserted by
   nothing; 16 colliding surface-hash groups / 149 addresses measured, one
   group of 15 implementations behind UUPSProxy's hash.
9. Cache mutate-on-read (G6-C6): bump_hit + mark_audited are called from the
   READ path and _mark_residue_gaps makes run N+1's probe set a function of
   run N — inv 12 violation (two identical runs leave different DB states).
   Fix shape: split the value (separate cache-stats rows) OR accept and
   EXPLICITLY exclude the columns from replay identity in the schema — state
   which and why. hit_count=0 means both "never looked up" and "looked up
   and missed" — split that too or document.
10. Cache self-audit floor: authority_change (49/150 cache rows) passes the
    audit on a zero-key signature — ('unknown', None x5) on both sides —
    unconditionally. Require at least one structural key present, else refuse
    to trust the hit. Two allowlisted keys (gate_mutation, upgradeable)
    appear in no row at all. Preferred shape per G6-C1: split details into
    code_plane (comparable, cacheable; audit = diff over it) and
    deployment_plane (observed_blast_radius, pre_pause_succeeding,
    scored_denominator, input_seeded, contract_balance_seeded, backing)
    written only to the producing deployment's verdict and ABSENT on a hit —
    absent, not null and not false (R1).
11. FOLDED IN from Wave 1 (L-4, ledger): _principals_by_function has no
    ORDER BY and its FIRST element is the probe's caller identity
    (calldata.py :1377/:1419/:1702/:2224) — a third determinism class
    (query-plan order). Add the deterministic order + a test. R5 applies
    (probe identity changes -> witness changes).`,
    constraints: `LEG-D CONSTRAINTS: (a) CHAIN: inherits — services/effects/*
thread chain_id (orchestrator.py:135, preflight.py:50-81); do not drop it.
effect_behavior_cache has NO chain_id predicate in find_cached_verdict BY
DESIGN (cross-chain twin transfer is the stated purpose, db/effect_cache.py) —
do not "fix" that; G6-C1's code/deployment plane split is where it bites.
(b) ORDERING: A7 landing this wave satisfies the A7-before-is_pausable
constraint (bitmap-24 verified inert at Wave-1 HEAD); do not widen anything
toward the bitmap family here. (c) COST BOUNDARY on verification: no fork
probes against live RPC, no pipeline stages — verify via corpus fixtures,
unit tests, and projections of the new code over persisted artifacts (the 61
freeze_pause verdicts' trees are all local; recompute duration bounds from
them). The eth_simulateV1 emitter check (item 2) is the ONE sanctioned live
read; keep it sparing. (d) §11 known-wrong hypotheses bind items 2, 5, 6 —
re-read before coding. (e) R5: EFFECT_CACHE_SCHEMA_VERSION is 21 at base;
one bump per witness-shape-changing commit with the reason in the comment.`,
  },
]

async function runLeg(leg) {
  let feedback = null
  let accepted = false
  let report = null
  let review = null
  const cap = 3
  for (let round = 1; round <= cap && !accepted; round++) {
    const retryNote = feedback
      ? `\n\nThis is a RETRY (round ${round}). A reviewer rejected the previous attempt. Fix exactly these in the SAME worktree/branch (do not recreate it; amend or add commits), do not re-litigate:\n${feedback}`
      : ''
    report = await agent(implPrompt(leg, retryNote), {
      label: `impl:leg-${leg.branch}`,
      phase: 'Legs',
      model: leg.model,
      effort: 'high',
    })
    if (!report) { log(`Leg ${leg.key}: implementer returned nothing (round ${round})`); continue }
    review = await agent(reviewPrompt(leg, report), {
      label: `review:leg-${leg.branch}`,
      phase: 'Legs',
      model: 'opus',
      effort: 'high',
      schema: REVIEW_SCHEMA,
    })
    if (!review) { log(`Leg ${leg.key}: reviewer returned nothing (round ${round})`); continue }
    accepted = review.accepted === true
    if (review.out_of_scope_findings?.length) {
      log(`Leg ${leg.key}: ${review.out_of_scope_findings.length} out-of-scope finding(s) for the ledger`)
    }
    if (!accepted) {
      feedback = (review.violations || [])
        .map((v) => `- [${v.rule}] ${v.detail}\n  reproduce: ${v.reproduction}`)
        .join('\n')
      log(`Leg ${leg.key}: rejected round ${round} — ${(review.violations || []).length} violation(s)`)
    }
  }
  log(`Leg ${leg.key}: ${accepted ? 'ACCEPTED' : 'NOT ACCEPTED after 3 rounds — driving agent adjudicates'}`)
  return { leg: leg.key, accepted, report, review }
}

phase('Legs')
log('Wave 2 — legs B, D in parallel worktrees off ' + BRANCH)

const legResults = await parallel(LEGS.map((l) => () => runLeg(l)))
const clean = legResults.filter(Boolean)
const failed = clean.filter((r) => !r.accepted)
if (failed.length || clean.length !== LEGS.length) {
  log(`HALT: ${failed.map((f) => f.leg).join(', ') || 'missing results'} — driving agent adjudicates before merge.`)
  return { wave: 2, halted_at: 'legs', legResults: clean }
}

phase('Merge')

const mergeReport = await agent(
  `${boilerplate}

You are the MERGE agent for Wave 2. Mechanical job, no redesign.

In /home/riley/PSAT (the main checkout, branch ${BRANCH}):
  1. Confirm ${BRANCH} is checked out and clean (untracked docs are fine).
  2. git merge --no-ff witness/leg-b, then witness/leg-d.
  3. Conflicts in CODE: if trivial (disjoint hunks, import lists), resolve
     minimally and say exactly what you did. If substantive, STOP, report the
     conflict, do not guess. Watch specifically for: both legs bumping
     EFFECT_CACHE_SCHEMA_VERSION (renumber ordinally, one entry per reason,
     as Wave 1 did for v19/v20/v21) and both touching site/src/claimsVocab.js.
  4. Conflicts in corpus GOLDENS (tests/fixtures/**): resolve by REGENERATING
     the golden with the repo's regeneration path after the code merge, then
     verify the regenerated diff equals the UNION of the diffs the two legs
     declared. If it does not, STOP and report the delta rows (Wave 1's halt 1
     found a legitimate cross-product — report, don't guess).
  5. Reset the shared test DB first (drop+recreate psat_test), then run the
     offline suite once (./run_tests_fast.sh — main checkout has it) and
     cd site && npm test. Report counts.
  6. Remove the two worktrees (git worktree remove ${WT_ROOT}/leg-b etc.) —
     they are this wave's own — but KEEP the witness/leg-* branches.
Report: merge commits created, conflicts + resolutions, suite counts.`,
  { label: 'merge-legs', phase: 'Merge', model: 'opus', effort: 'medium' }
)

phase('Exit gate')

const gate = await agent(
  `Run the tier-0 mechanical gate and report results verbatim. You make NO
judgments — execute and report. First reset the test DB:
  cd /home/riley/PSAT && set -a && source .env && set +a
  PGURL=$(echo "$TEST_DATABASE_URL" | sed 's|+psycopg2||; s|/psat_test.*|/postgres|')
  psql "$PGURL" -c "DROP DATABASE IF EXISTS psat_test;" -c "CREATE DATABASE psat_test;"
Then:
  bash scripts/witness/gate.sh --base main --require-determinism

Return passed=true only if the script prints "GATE: PASS". List every FAIL line
in failures. Put the full summary block in raw.`,
  // opus, not haiku: operator decision 2026-07-28 (OPS §3b).
  { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
)

const differential = await agent(
  `${boilerplate}

Produce the Wave 2 FULL-REPLAY DIFFERENTIAL on ${BRANCH} (post-merge HEAD) vs
${W2_BASE} (Wave 1 closeout). Local recompute over existing DB artifacts only —
no pipeline, no workers, no fork probes.

METHOD (binding — see the measurement warnings above): use the full in-process
replay substrate at ${REPLAY_SUB} (replay.py; 88/92 contracts replayable;
PYTHONHASHSEED pinned; rebuild from the ${W24} description if the scratchpad
is gone). The artifact-only build_claims(None, ...) recompute is INVALID.

For the planes Wave 2 touched:
  - capability/authority plane (Leg B): project the new policy writers over
    the replayed analyses + persisted inputs. Tabulate effective_functions
    status transitions (public -> unsupported etc.) against the re-measured
    tree-absent population; guard_extraction_uncertain firing count (R2 —
    was 0/75 artifacts); authority_public three-state transitions;
    resolved_empty -> not_determined transitions (expected: the 3 false
    empties, incl. WithdrawRequestNFT.requestWithdraw); authority_roles
    population (was [] on 1773/1773 — report how many rows now carry roles
    and spot-check 3 against source); function_principals.origin
    discrimination (was 1 constant on 1132/1132); the L-41 gate — the 28
    surviving provenance-absent targets must no longer be able to mint
    controller_value edges (projection, not a resolution run).
  - effects/witness plane (Leg D): recompute duration bounds from the 61
    freeze_pause verdicts' persisted trees (was 0/61 with a bound — report
    the new count and each bound's provenance); concrete_destination
    projection on the 35 caller_arbitrary rows (must all go NULL);
    reach_determined / reach_indeterminate publication shape on W0-7
    fixtures 8 + the timed-latch pair; cache self-audit floor behaviour on
    the 49 zero-key authority_change rows; _principals_by_function ordering
    (deterministic across 3 fresh processes).
KNOWN NOISE TO EXCLUDE: the callee_args_digest operand-slot flicker (L-25,
37-46 slots, 25/88 units) — bucket separately as 'L-25 noise', never count as
CHANGED. Every non-noise row must be attributable to a named leg commit.
Output the full tabulation; flag anything unexplained LOUDLY.`,
  { label: 'full-replay-differential', phase: 'Exit gate', model: 'opus', effort: 'high' }
)

phase('Milestone verify')

const lenses = [
  {
    key: 'mainnet',
    brief: `LENS 1 — CORRECTNESS AGAINST MAINNET. Re-derive the wave's central
claims yourself from chain + verified source (SPARING pinned reads, controls).
In particular: (a) A7's duration bounds — re-derive 2-3 of the newly published
bounds against the verified source / the pinned getters (pauseUntilDuration
28800 weETH / 86400 LiquidityPool / MAX 2592000 at 25619159) and confirm no
defaulted bound was introduced for a latch whose bound is NOT readable; (b)
Leg B's empty-intersection fix on the real WithdrawRequestNFT.requestWithdraw
shape — liquidityPool() returns the actual caller that was never a candidate;
confirm the row now answers not_determined, not resolved_empty, and that a
GENUINELY empty enumerable set still can answer resolved_empty (the negative
control); (c) the 351-function reroute — sample 3 rerouted rows and 3
still-public rows against verified source: rerouted rows must have a real
seen-but-unlowered guard; still-public rows must be genuinely ungated (an
over-hedge sweeping real public functions into 'unsupported' is a spec
violation, not a safe default); (d) A2's synthetic-emitter finding — verify
the implementer's eth_simulateV1 evidence is real and correctly read.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION. (a) Reconcile the full-replay
differential LINE BY LINE — every non-noise ADDED/CHANGED/REMOVED row
attributed to a leg commit, or it is not explained; verify the L-25 bucket
really is operand-slot-only. (b) Prose copies: A7 has TWO (pauseQualifier,
claimWitnessFacts) — did both change in the A7 commit, and did any over-claim
RELOCATE into prose elsewhere (action_summary restates exec.arbitrary — Wave 3
owns it; confirm nothing this wave made it worse)? (c) Did any declared
control move (sweepDust, the bitmap-24 inertness, audits/ storage control)?
(d) Does any existing test now pin wrong behaviour; were the three known
defect-pinning tests (timed-latch None assert, claimsVocab :470/:641)
inverted with positive-case siblings? (e) For each leg: what did the input
discard before the code saw it — apply the collapsed-inputs question to the
NEW code (the reroute discriminator, the per-asset holdings join, the cache
plane split). (f) R5: every witness-shape-changing commit bumped
EFFECT_CACHE_SCHEMA_VERSION (was 21) with a stated reason; no two commits
share a bump number after the merge.`,
  },
]

const verdicts = await parallel(
  lenses.map((l) => () =>
    agent(
      `${boilerplate}

You are a tier-3 MILESTONE VERIFIER for Wave 2 — the last gate before Wave 3
builds on this work. A miss here is caught by nobody.

${l.brief}

Tier-0 gate result:
${JSON.stringify(gate, null, 2)}

Merge report:
${mergeReport}

Full-replay differential:
${differential}

Read ${HANDOFF} §6 (Wave 2 detail) and §11 (known-wrong hypotheses — do not
validate work built on a refuted premise), plus ${W24}. YOUR JOB IS TO REFUTE.
Every verdict needs pasted command output. Return verdict=FAIL if any
wave-exit criterion (§10) is unmet, and say which. Finish with "what I did
not check".`,
      { label: `verify:${l.key}`, phase: 'Milestone verify', model: 'fable', effort: 'high', schema: VERIFY_SCHEMA }
    )
  )
)

const cleanVerdicts = verdicts.filter(Boolean)
const allPass = gate?.passed === true && cleanVerdicts.length === lenses.length && cleanVerdicts.every((v) => v.verdict === 'PASS')

log(allPass ? 'WAVE 2 EXIT: PASS' : 'WAVE 2 EXIT: FAIL — driving agent adjudicates')

return {
  wave: 2,
  exit_pass: allPass,
  gate,
  merge: mergeReport,
  differential,
  verdicts: cleanVerdicts,
  legs: legResults.map((r) => ({
    leg: r.leg,
    accepted: r.accepted,
    summary: r.review?.summary,
    out_of_scope_findings: r.review?.out_of_scope_findings || [],
  })),
}
