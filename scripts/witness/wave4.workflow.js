export const meta = {
  name: 'witness-wave4',
  description: 'Witness-integrity Wave 4: ledger closeout — three parallel legs over admitted fixes, then gate + verify',
  whenToUse: 'Run only after Wave 3 exited PASS (see WAVE_3_REPORT.md). The driving agent writes the final report afterwards.',
  phases: [
    { title: 'Legs', detail: 'W4-A effects+frontend, W4-B static producers, W4-C resolution/policy — parallel worktrees, impl -> review -> retry(<=3)' },
    { title: 'Merge', detail: 'merge the three leg branches' },
    { title: 'Exit gate', detail: 'tier-0 gate + targeted differential' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const W24 = 'WITNESS_INTEGRITY_WAVES_2_4_HANDOFF.md'
const OPS = 'WITNESS_INTEGRITY_OPERATIONS.md'
const LEDGER = 'WITNESS_INTEGRITY_LEDGER.md'
const BRANCH = 'fix/witness-integrity'
const W4_BASE = 'c85204a3' // Wave 3 closeout HEAD
const WT_ROOT = '/tmp/claude-1000/-home-riley-PSAT/d8116573-440b-4ce0-8e02-ddab7ee5b902/scratchpad/wave4'
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
          rule: { type: 'string' },
          detail: { type: 'string' },
          reproduction: { type: 'string' },
        },
      },
    },
    out_of_scope_findings: {
      type: 'array',
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
Repo /home/riley/PSAT. Read \`${OPS}\` FIRST (no human escalation — judgment
routes to the driving agent; cost boundary: never start workers/uvicorn/
pipeline stages/live suite/analysis jobs, never regenerate the analyzed
corpus, never loop RPC over the population; ladder ends in
defer-with-stated-cause). Then \`${HANDOFF}\` §0-§2 (governing rule, traps,
R1-R5), the ledger \`${LEDGER}\` entries named in your items, and the
"Carried into Wave 4" + method-caution sections of WAVE_2_REPORT.md and
WAVE_3_REPORT.md.

AUTHORISED: commit to your leg branch. NOT AUTHORISED: git push, PR, merge,
live suite, production, editing .env/CLAUDE.md/settings.

WAVE 4 CHARTER: this is the LEDGER CLOSEOUT. Admission test (operator-set):
does the defect let a false claim reach a published surface or a scorer
input? Your items passed it. Fix minimally and prove; if an item turns out to
require a producer redesign or a pipeline run to verify, DEFER WITH STATED
CAUSE in your report instead of forcing it — a deferral with an honest cause
is a successful outcome here, an over-reaching fix is not.

Traps: jsonb null vs SQL NULL (jsonb_typeof); handoff line numbers drift —
locate by content; local DB = one protocol/one chain, every count a LOWER
BOUND; production DB never evidence; effects cache unmeasurable-by-hit;
effect_transcripts hold no logs; effects artifacts are per-JOB keyed by
jobs.address with pre-canonicalization signatures (the wrong join reproduces
the right headline); artifact-only build_claims(None,...) recompute INVALID —
full replay substrate at ${REPLAY_SUB}. NEVER start a dev server; frontend =
vitest render tests.

IMPLEMENTER'S LENS up front (OPS §2): consumer enumeration for every changed
field; input-shape -> published-state tables; the collapsed-inputs question of
your own code; report out-of-scope observations, never fix silently.
`

function worktreeSetup(branch) {
  return `WORKTREE SETUP (first, exactly):
  cd /home/riley/PSAT
  git worktree remove --force ${WT_ROOT}/leg-${branch} 2>/dev/null; git branch -D witness/leg-${branch} 2>/dev/null
  git worktree add ${WT_ROOT}/leg-${branch} -b witness/leg-${branch} ${BRANCH}
  cp /home/riley/PSAT/.env ${WT_ROOT}/leg-${branch}/.env
  cd ${WT_ROOT}/leg-${branch}
  git merge-base --is-ancestor ${W4_BASE} HEAD && echo BASE_OK   # must print BASE_OK; else STOP
Work ONLY here, commit ONLY to witness/leg-${branch}. TEST-DB ISOLATION:
  PGURL=$(echo "$TEST_DATABASE_URL" | sed 's|+psycopg2||; s|/psat_test.*|/postgres|')
  psql "$PGURL" -c "DROP DATABASE IF EXISTS psat_test_leg${branch};" -c "CREATE DATABASE psat_test_leg${branch};"
  export TEST_DATABASE_URL=$(echo "$TEST_DATABASE_URL" | sed "s|/psat_test|/psat_test_leg${branch}|")
Scoped serial pytest per CLAUDE.md; full suite once before the final report.
Frontend (leg A only): cd site && npm install --no-audit --no-fund && npm test.`
}

const LEGS = [
  {
    key: 'A',
    branch: 'w4a',
    title: 'effects/witness + frontend/test residuals',
    model: 'opus',
    items: `
1. L-46 (FIX): the reach-vs-TVL ceiling in services/effects/recipes.py
   _add_reach applies only on the reach_determined:True path; the unvalued
   branch sets observed_reach_priced_usd (published as a partial floor) and
   returns BEFORE _reach_tvl_state — a floor above the protocol's own TVL is
   publishable with no reach_tvl_check at all. Apply the ceiling (or its
   three-state check) to the priced-floor branch too. R5: judge whether this
   changes witness content (it does — bump, one reason). Test both branches.
2. L-58 + L-60 (FIX): _duration_from_trees' guard_constant harvest is
   side/operator-blind — require(block.timestamp + 3600 < pausedUntil) yields
   (3600,'guard_constant'): a lead time published as the freeze window, error
   direction MITIGATING. Make the harvest side/operator-aware (a constant
   qualifies only when the comparison shape actually bounds the latch window),
   or where genuinely undecidable answer not_determined. PLUS the containment
   pin L-58 demands: a test asserting every consumer (both prose copies +
   claims_bridge scorer contract) trusts a bound only with auto_expiry===true,
   so the fork cross-check cannot be silently loosened. Controls: the
   AbsorbedWindow (2592000,'guard_constant') positive and PlainLatch
   no_time_reference must hold; the two L-58 shapes must stop publishing
   3600/300. L-60's mixed-clock leaf falls out of the same awareness — assert
   it. R5 applies.
3. L-68 (FIX): Candidate.effect_targets (selection.py:143, populated ~:1268)
   is write-only and carries the conflated display list into the dataclass —
   the next reader's trap. Remove the field (verify by grep no reader exists;
   the dataclass and its construction site only).
4. L-66 (FIX): BalanceTable.coverageNote returns early on
   may_be_incomplete, suppressing the unvalued_rows disclosure when both
   facts hold. Compose the sentences; vitest arm for the both-facts case.
5. L-67 (FIX): tests/test_artifact_storage_integration.py is not idempotent
   against a reused test DB (second run fails two named tests). Make the
   fixtures self-cleaning/idempotent; prove by running the file twice against
   one DB.
6. L-18 (FIX if the one-line shape holds): the label-corpus golden does not
   pin action_summary — add it to _flatten_record's pinned keys so prose
   copies are gate-visible; regenerate the golden and enumerate every changed
   row (they should all be the Wave-3 5194ebcd prose). If the diff is larger
   than expected, STOP on the item and defer with the rows listed.`,
    constraints: `LEG-A CONSTRAINTS: (a) surfaces: services/effects/
{recipes,calldata,selection}.py, site/src (BalanceTable + its test), tests/,
tests/support/label_corpus.py + goldens. Do not touch policy/resolution/static
producers (legs B and C own them). (b) R5: EFFECT_CACHE_SCHEMA_VERSION is 32
at base. (c) The A7 controls are load-bearing: PlainLatch proven,
TimestampTwin/NumberTwin/NowLatch demoted, AbsorbedWindow bound kept, the
units-trap arms green. (d) No fork probes; corpus fixtures + unit tests +
projections only.`,
  },
  {
    key: 'B',
    branch: 'w4b',
    title: 'static-plane producers (predicate lowering, cross-contract, operand tie-break)',
    model: 'fable',
    items: `
1. L-38 (FIX with tight controls, else DEFER): internal-callee-modifier gates
   are invisible to predicate trees — EigenLayer StrategyManager routes both
   deposit entries through _depositIntoStrategy(...) internal
   onlyStrategiesWhitelistedForDeposit(strategy) whose body is a
   mapping-allowlist require on parameter 0, but neither entry's tree carries
   a leaf for it, so param_constraints() publishes
   {'state': 'unconstrained_proven'} — a positive proof of absence over a gate
   that exists, on 2 of the 12 unconstrained_proven rows in the local DB
   (false ADVERSE direction). Fix at predicate extraction: walk modifiers of
   INTERNAL callees the way body requires already are (the lowering already
   walks the entry function's own modifiers). CONTROLS, binding: (i) the two
   StrategyManager rows flip to constrained/mapping_allowlist (or honestly
   not_determined); (ii) sweepDust stays at its published state; (iii) the
   corpus goldens change only where a real internal-callee-modifier gate
   exists — enumerate every changed row with the source modifier quoted;
   (iv) run the full-replay differential over the 88 contracts and attribute
   every claims/trees change. If the blast radius exceeds what you can
   attribute row-by-row, STOP and defer with the differential attached.
2. L-25 (FIX if the shape is as diagnosed, else DEFER): the third
   nondeterminism surface — _operand_for_value breaks ties between competing
   computed sources on callee_args_digest built with hash() over a frozenset,
   which is seed-dependent; 37-46 operand slots flicker across 25/88 units and
   every wave's differential has had to bucket it (L-25). Replace the
   seed-dependent tie-break with a stable total order (e.g. sorted canonical
   digest), prove byte-stability across 3 fresh processes x 2 seeds on the
   affected units (cids 537/528 named in the ledger), and state which slots
   settle. This closes the standing noise bucket. R5-adjacent:
   ANALYSIS_SCHEMA_VERSION governs materialized trees — judge and state.
3. L-17 (FIX if cheap, else DEFER): build_callee_claim_map keys a callee's
   claims by the effects record's DECLARED-signature selector while the
   caller's sink records the ABI selector (AssetRecovery sweepTo:
   0x38541c00 vs 0x0aeef8c8), so the cross-contract join misses every callee
   taking an interface/contract-typed parameter — the strong candidate for
   policy_derived's zero producers. Canonicalize the join key (the repo
   already has selector canonicalization for enums/structs — reuse it).
   Prove: the corpus PolicyCaller/AssetRecovery pair derives its claim;
   negative control: a non-propagatable callee still derives nothing. Note
   W3-E's tier-lattice consumer fix means a derived claim now scores at its
   own rank — state that interaction.`,
    constraints: `LEG-B CONSTRAINTS: (a) surfaces:
services/static/contract_analysis_pipeline/{predicate_artifacts,predicates,
provenance,revert_detect}.py, services/static/claims/**, services/static/
cross_contract.py, tests + corpus. Do not touch services/effects (leg A) or
services/resolution|policy (leg C). (b) The full-replay substrate is at
${REPLAY_SUB} (replay.py; PYTHONHASHSEED pinned; 88/92 replayable). Any
claims-plane measurement uses it — the artifact-only recompute is INVALID.
(c) MERGE INTERACTION WARNING: predicate-tree shape changes are what Wave-1
L-40 taught us mint unowned controller-tracking targets — after your L-38
change, re-run the L-41-gate projection (controller-tracking targets by
provenance) and report any NEW provenance-absent targets your leaves create;
the Wave-2 gate (controller_value_unattributed) should absorb them — verify,
don't assume. (d) A defer with the differential attached is a fully
acceptable outcome for every item on this list; an unattributed blast radius
is not.`,
  },
  {
    key: 'C',
    branch: 'w4c',
    title: 'resolution/policy residuals',
    model: 'opus',
    items: `
1. L-12 (FIX): reconcile_deferred_resolutions inner-joins Contract on
   Contract.job_id == Job.id, so the 32 effective_functions rows carrying the
   deferred_pending_index marker on contracts with job_id NULL are
   structurally unreachable — deferred authority resolution never completes
   for them and a permanent "pending" capability is published. Rekey the join
   (address-based or via ef.contract_id) so the marker rows are reachable;
   prove with a query showing the 32 rows now join, and a test pinning the
   orphaned-contract shape. Do NOT run the reconciler against live RPC — the
   join reachability is the fix; the resolution itself binds the next run.
2. L-52 (FIX): one pin test — principal_enrichment's label dispatch must not
   mint any controller_* label for relation='controller_value_unattributed'
   (today correct by fall-through; nothing pins it, and a future arm silently
   re-admits unattributed edges).
3. L-53 (FIX): one mutation-pinning test — the build_effective_permissions
   half of the authority_openness R1 fix (both blocks in
   services/policy/effective_permissions.py) is unpinned: reverting them
   leaves the suite green because the writer independently derives openness.
   Pin the PAYLOAD-plane key (schemas/effective_permissions.py
   authority_openness) so a future edit cannot silently drop it.
4. L-72 (INVESTIGATE, fix if cheap): fids 2893/2894 (alertBatchMetadataUpdate,
   alertMetadataUpdate) carry selector='' beside well-formed abi_signatures.
   Find the producer path that wrote '' for a NAMED function (the empty
   string is the fallback/receive sentinel, L-27/G6-13); fix the producer so
   a named function always gets its computed selector, and state what should
   happen to the 2 persisted rows (do not hand-edit the DB; the next analysis
   run rewrites them — say so).
5. L-34 + L-35 + L-36 (FIX, small): (a) rename the analysis_state token
   not_a_contract -> not_analyzable (producer _analysis_state +
   schemas/resolved_control_graph + tests; the analysis-detail payload
   publishes it and 230 Safe nodes are literally contracts — no frontend
   consumer reads it yet, so the rename is still free — verify that first);
   (b) _recursive_read's except-Exception fallback to the NON-recursive
   accessor silently narrows the gate set (fail-open) — propagate
   not-determined instead (return None route), with the mutation test the
   ledger describes; (c) the persistence-boundary test arm L-36 names:
   authority_provenance / analysis_state / graph_max_depth asserted through
   workers/resolution_worker.py writes (SQL NULL vs jsonb-null discipline).`,
    constraints: `LEG-C CONSTRAINTS: (a) surfaces: services/resolution/**,
services/policy/**, workers/resolution_worker.py, schemas/, tests. Do not
touch services/effects (leg A) or the static pipeline (leg B). (b) Chain
requirement: any query you touch keying on bare address gains the chain
predicate or contract_id (handoff §3). (c) L-12's fix must not widen the
reconciler's population beyond the marker rows — enumerate what the new join
matches that the old one did not, and show it is exactly the orphaned class.
(d) The 32-row count is a lower bound (one protocol); pin the SHAPE, not the
number.`,
  },
]

async function runLeg(leg) {
  let feedback = null
  let accepted = false
  let report = null
  let review = null
  for (let round = 1; round <= 3 && !accepted; round++) {
    const retryNote = feedback
      ? `\n\nThis is a RETRY (round ${round}). Fix exactly these in the SAME worktree/branch (do not recreate it), do not re-litigate:\n${feedback}`
      : ''
    report = await agent(
      `${boilerplate}

You are the tier-1 implementer for **Wave 4 Leg ${leg.key} — ${leg.title}**.

${worktreeSetup(leg.branch)}

Your items (each names its ledger entry — read those entries in full first):
${leg.items}

${leg.constraints}

BEFORE writing code, state per item: positive control, negative control,
measured "before" numbers. R1-R5 binding; R2 firing proofs or the honest
zero-realised statement; declare every deleted/inverted test in the commit
message. One commit per coherent item. Report: per-item what changed (or the
deferral with stated cause), before/after numbers, controls, consumer
enumeration, "what I did not check".${retryNote}`,
      { label: `impl:leg-${leg.branch}`, phase: 'Legs', model: leg.model, effort: 'high' }
    )
    if (!report) { log(`Leg ${leg.key}: implementer returned nothing (round ${round})`); continue }
    review = await agent(
      `${boilerplate}

You are the tier-2 reviewer for **Wave 4 Leg ${leg.key} — ${leg.title}**.
Review ALL commits on witness/leg-${leg.branch} (worktree
${WT_ROOT}/leg-${leg.branch}, own test DB psat_test_leg${leg.branch}).
Compare against ${BRANCH} (merge-base ${W4_BASE}).

The judgment-bearing pair: R1 (three states, consumer-distinguishable) and R4
(positive-case tests, not only hedges). Also R2 (run firing queries yourself),
R3 (consumers + prose copies same commit), R5 (EFFECT_CACHE_SCHEMA_VERSION 32
at base), controls held, consumer enumeration VERIFIED, and — Wave-4 specific
— every DEFERRAL's stated cause is true (a deferral whose cause you can
refute is a rejection ground; a correct deferral is a successful outcome).
${leg.key === 'B' ? `For L-38/L-25/L-17: re-derive the full-replay differential attribution
yourself on the affected units; an unattributed changed row is a rejection
ground inside this leg's scope.` : ''}

SCOPE DISCIPLINE (${OPS} §2): reject only inside the leg's declared item
scope; real out-of-scope defects go under out_of_scope_findings with
reproductions.

The implementer reported:
${report}

Refuting is success; accepting unreproduced claims is the only failure mode.`,
      { label: `review:leg-${leg.branch}`, phase: 'Legs', model: 'opus', effort: 'high', schema: REVIEW_SCHEMA }
    )
    if (!review) { log(`Leg ${leg.key}: reviewer returned nothing (round ${round})`); continue }
    accepted = review.accepted === true
    if (review.out_of_scope_findings?.length) {
      log(`Leg ${leg.key}: ${review.out_of_scope_findings.length} out-of-scope finding(s)`)
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
log('Wave 4 — ledger closeout: legs A (effects+frontend), B (static producers), C (resolution/policy)')

const legResults = await parallel(LEGS.map((l) => () => runLeg(l)))
const clean = legResults.filter(Boolean)
const failed = clean.filter((r) => !r.accepted)
if (failed.length || clean.length !== LEGS.length) {
  log(`HALT: ${failed.map((f) => f.leg).join(', ') || 'missing results'} — driving agent adjudicates before merge.`)
  return { wave: 4, halted_at: 'legs', legResults: clean }
}

phase('Merge')

const mergeReport = await agent(
  `${boilerplate}

You are the MERGE agent for Wave 4. Mechanical job, no redesign.

In /home/riley/PSAT (branch ${BRANCH}):
  1. Confirm clean (untracked docs fine).
  2. git merge --no-ff witness/leg-w4a, then witness/leg-w4b, then
     witness/leg-w4c.
  3. CODE conflicts: trivial -> resolve minimally and say what; substantive ->
     STOP and report. Watch: legs A and B may both bump
     EFFECT_CACHE_SCHEMA_VERSION (renumber ordinally, one reason each); legs A
     and B may both touch label-corpus goldens (regenerate after merge and
     verify the diff equals the union of declared diffs — mismatch: STOP,
     report the delta rows).
  4. Reset psat_test (drop+recreate, FORCE the gw* DBs too), run
     ./run_tests_fast.sh once and cd site && npm test. Report counts.
  5. Remove the three worktrees (--force); KEEP the branches.
Report: merge commits, conflicts + resolutions, suite counts.`,
  { label: 'merge-legs', phase: 'Merge', model: 'opus', effort: 'medium' }
)

phase('Exit gate')

const gate = await agent(
  `Run the tier-0 mechanical gate and report verbatim. NO judgments.
  cd /home/riley/PSAT && set -a && source .env && set +a
  PGURL=$(echo "$TEST_DATABASE_URL" | sed 's|+psycopg2||; s|/psat_test.*|/postgres|')
  psql "$PGURL" -c "DROP DATABASE IF EXISTS psat_test WITH (FORCE);" -c "CREATE DATABASE psat_test;"
  bash scripts/witness/gate.sh --base main --require-determinism
passed=true only on "GATE: PASS"; every FAIL line in failures; summary in raw.`,
  { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
)

const differential = await agent(
  `${boilerplate}

Produce the Wave 4 TARGETED DIFFERENTIAL on ${BRANCH} (post-merge HEAD) vs
${W4_BASE}. Local recompute only — no pipeline, no workers, no fork probes.

Per landed item, measure the before/after on its own plane and attribute:
  - L-38 (if landed): full-replay claims/trees differential over the 88
    contracts (substrate ${REPLAY_SUB}) — the two StrategyManager rows'
    param_constraints states, sweepDust control, every other changed row
    attributed to a real internal-callee-modifier gate (quote the modifier);
    ALSO re-run the L-41-gate projection (controller-tracking targets by
    provenance) and report new provenance-absent targets and whether the
    controller_value_unattributed gate absorbs them.
  - L-25 (if landed): byte-stability of the affected units (cids 537, 528)
    across 3 fresh processes x 2 PYTHONHASHSEEDs; state the settled slots;
    confirm the standing noise bucket is now provably empty rather than
    bucketed.
  - L-17 (if landed): the corpus PolicyCaller/AssetRecovery derivation exists
    with tier policy_derived; the negative control derives nothing; count any
    OTHER new policy_derived claims corpus-wide and attribute each.
  - L-46: both _add_reach branches' TVL-check behaviour on fixture shapes
    (over-TVL floor now checked / skip-loudly on absent TVL).
  - L-58/L-60: the two lead-time/cooldown shapes stop publishing bounds;
    AbsorbedWindow keeps 2592000; the consumer containment pin exists and
    fails when auto_expiry gating is loosened (mutation).
  - L-12: the 32 marker rows now reachable by the reconciler join (SQL
    proof); nothing beyond the orphaned class newly matched.
  - L-34/35/36, L-52, L-53, L-66, L-67, L-68, L-72: per-item one-screen
    proof (test run, grep, or query) that the fix/pin behaves as the ledger
    entry demanded.
L-25 noise bucket: if leg B landed the tie-break fix, assert 0 by
byte-identity; otherwise bucket as before. Every changed row attributed or
flagged LOUDLY.`,
  { label: 'wave4-differential', phase: 'Exit gate', model: 'opus', effort: 'high' }
)

phase('Milestone verify')

const lenses = [
  {
    key: 'mainnet',
    brief: `LENS 1 — CORRECTNESS AGAINST SOURCE/DATA. (a) L-38: re-derive the
StrategyManager verdicts from the verified source (the internal modifier's
require) and confirm the two rows' new state is earned, not swept; sweepDust
and the corpus negative controls re-checked. (b) L-17: read the AssetRecovery/
PolicyCaller fixtures and confirm the derived claim's witness matches the
callee's actual flow.out claim; confirm no derivation appears where
_propagatable is false. (c) L-12: run the join-reachability SQL yourself; the
32 rows (lower bound) join, and the newly-matched population is exactly the
orphaned class. (d) L-46/L-58: replay the fixture shapes through the real
code paths yourself. (e) Any deferral: refute or confirm its stated cause.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION. (a) Reconcile the differential
line by line; for L-38 especially, every changed corpus row must quote its
real gate. (b) Controls: sweepDust, PlainLatch/AbsorbedWindow/A7 family,
bitmap-24 inertness, the D1 candidacy controls — none moved. (c) R4/R5: new
tests pin positives, not hedges; cache-version bumps ordinal with one reason
each after the merge. (d) The L-41-gate re-projection after L-38 (new
tree shapes must not mint authority-bearing edges). (e) Collapsed inputs on
each new discriminator (the side/operator-aware harvest, the canonicalized
join key, the rekeyed reconciler join). (f) Deferral honesty: each deferral's
cause re-checked; a refutable cause is a FAIL-grade finding.`,
  },
]

const verdicts = await parallel(
  lenses.map((l) => () =>
    agent(
      `${boilerplate}

You are a tier-3 MILESTONE VERIFIER for Wave 4 — the LAST verification of the
whole witness-integrity effort. Nothing runs after you.

${l.brief}

Tier-0 gate result:
${JSON.stringify(gate, null, 2)}

Merge report:
${mergeReport}

Differential:
${differential}

Read ${HANDOFF} §11 (known-wrong hypotheses) and the ledger entries for every
landed item. YOUR JOB IS TO REFUTE. Every verdict needs pasted output. Return
verdict=FAIL if any wave-exit criterion (§10) is unmet, and say which. Finish
with "what I did not check".`,
      { label: `verify:${l.key}`, phase: 'Milestone verify', model: 'fable', effort: 'high', schema: VERIFY_SCHEMA }
    )
  )
)

const cleanVerdicts = verdicts.filter(Boolean)
const allPass = gate?.passed === true && cleanVerdicts.length === lenses.length && cleanVerdicts.every((v) => v.verdict === 'PASS')

log(allPass ? 'WAVE 4 EXIT: PASS' : 'WAVE 4 EXIT: FAIL — driving agent adjudicates')

return {
  wave: 4,
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
