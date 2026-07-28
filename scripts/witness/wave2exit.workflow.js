export const meta = {
  name: 'witness-wave2-exit',
  description: 'Wave 2 exit: merge legs B/D, tier-0 gate, full-replay differential, two Fable verdicts',
  whenToUse: 'Run after the Wave 2 legs are accepted/adjudicated; replaces the halted tail of wave2.workflow.js.',
  phases: [
    { title: 'Merge', detail: 'merge witness/leg-b then witness/leg-d into fix/witness-integrity' },
    { title: 'Exit gate', detail: 'tier-0 gate + full-replay differential (L-25 bucket)' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

// Why this script exists: wave2.workflow.js halted at the legs phase by design
// (Leg D hit the 3-round cap). The driving agent adjudicated per OPERATIONS §2:
// the round-3 reviewer's sole remaining violation (A7 clock predicate counted
// only block_context_kind=="timestamp"; `now` and `block.number` latches still
// published proven-indefinite) was the trivial-residual class, fixed directly
// as witness/leg-d commit 0a7fa43e using the reviewer's minimal prescription
// (demotion counts timestamp|now|number; seconds harvest counts timestamp|now
// only), mutation-checked, 160 relevant tests green. Do NOT resume the
// original run — its parallel phase is complete and only these tail phases
// remain.

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const W24 = 'WITNESS_INTEGRITY_WAVES_2_4_HANDOFF.md'
const OPS = 'WITNESS_INTEGRITY_OPERATIONS.md'
const BRANCH = 'fix/witness-integrity'
const W2_BASE = '93954b96' // Wave 1 closeout HEAD (differential baseline)
const WT_ROOT = '/tmp/claude-1000/-home-riley-PSAT/d8116573-440b-4ce0-8e02-ddab7ee5b902/scratchpad/wave2'
const REPLAY_SUB = '/tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/work'

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
Repo /home/riley/PSAT, branch ${BRANCH}. Read \`${OPS}\` FIRST (no human
escalation — judgment routes to the driving agent; cost boundary: never start
workers/pipeline stages/live suite/analysis jobs, never regenerate the
analyzed corpus, never loop RPC over the population). Then \`${HANDOFF}\`
§0-§2 and \`${W24}\` (measurement-method warnings).

AUTHORISED: commit to ${BRANCH}. NOT AUTHORISED: git push, PR, merge to main,
live suite, production, editing .env/CLAUDE.md/settings.

Traps: jsonb null vs SQL NULL (jsonb_typeof); eRPC "latest" flakes (pin
hex(head()-10); 25619159 for historical); on-chain facts need >=3 reads + a
pinned read at 25619159 with a discriminating control. SPARING RPC — single
facts, never scans. The artifact-only build_claims(None, ...) recompute is
INVALID; claims/summaries measurements use the full in-process replay
(substrate at ${REPLAY_SUB}, replay.py). The local DB is one protocol/one
chain — every count is a LOWER BOUND; the production DB is never evidence.

ADJUDICATION CONTEXT (part of the wave record): Leg B accepted round 3. Leg D
hit the cap; the driving agent applied the round-3 reviewer's minimal
prescription directly as witness/leg-d 0a7fa43e (clock-spelling split:
demotion counts timestamp|now|number, seconds harvest timestamp|now only;
4 new test arms, mutation-checked; v31 comment amended — unreleased version).
`

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
     EFFECT_CACHE_SCHEMA_VERSION (renumber ordinally, one entry per reason, as
     Wave 1 did for v19/v20/v21) and both touching site/src/claimsVocab.js.
  4. Conflicts in corpus GOLDENS (tests/fixtures/**): resolve by REGENERATING
     the golden with the repo's regeneration path after the code merge, then
     verify the regenerated diff equals the UNION of the diffs the two legs
     declared. If it does not, STOP and report the delta rows (Wave 1's halt 1
     found a legitimate cross-product — report, don't guess).
  5. Reset the shared test DB first:
       set -a && source .env && set +a
       PGURL=$(echo "$TEST_DATABASE_URL" | sed 's|+psycopg2||; s|/psat_test.*|/postgres|')
       psql "$PGURL" -c "DROP DATABASE IF EXISTS psat_test;" -c "CREATE DATABASE psat_test;"
     then run the offline suite once (./run_tests_fast.sh — main checkout has
     it) and cd site && npm test. Report counts.
  6. Remove the two worktrees (git worktree remove --force ${WT_ROOT}/leg-b
     and ${WT_ROOT}/leg-d) — they are this wave's own — but KEEP the
     witness/leg-* branches.
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
  { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
)

const differential = await agent(
  `${boilerplate}

Produce the Wave 2 FULL-REPLAY DIFFERENTIAL on ${BRANCH} (post-merge HEAD) vs
${W2_BASE} (Wave 1 closeout). Local recompute over existing DB artifacts only —
no pipeline, no workers, no fork probes.

METHOD (binding): use the full in-process replay substrate at ${REPLAY_SUB}
(replay.py; 88/92 contracts replayable; PYTHONHASHSEED pinned; rebuild from
the ${W24} description if the scratchpad is gone). The artifact-only
build_claims(None, ...) recompute is INVALID.

For the planes Wave 2 touched:
  - capability/authority plane (Leg B): project the new policy writers over
    the replayed analyses + persisted inputs. Tabulate effective_functions
    status transitions (public -> unsupported etc.) against the re-measured
    tree-absent population; guard_extraction_uncertain firing count (R2 — was
    0/75 artifacts); authority_openness/authority_roles three-state censuses
    (the leg's round-2 report claims 751/848/174 and 200/364/1209 — re-derive,
    do not take them); resolved_empty -> not_determined transitions (expected:
    the 3 false empties, incl. WithdrawRequestNFT.requestWithdraw, while a
    genuinely-empty enumerable set still answers resolved_empty);
    function_principals.origin discrimination (was 1 constant on 1132/1132);
    the L-41 gate — the 28 surviving provenance-absent targets must no longer
    be able to mint controller_value edges (projection, not a resolution run);
    the A1 flip set (cid 568 upgradeTo/upgradeToAndCall public->gated, and
    the corrected base false-adverses the leg declared: cid 561
    shouldSubmitReport, cid 454 claim, cid 570 undelegate).
  - effects/witness plane (Leg D): recompute duration bounds from the 61
    freeze_pause verdicts' persisted trees (was 0/61 with a bound — report
    the new count and each bound's provenance, incl. how many land
    no_time_reference vs not_determined and WHY that is honest — note the
    persisted trees predate the operand_absorption marker, so the proven
    state should have zero realised rows until the static stage re-runs);
    concrete_destination projection on the 35 caller_arbitrary rows (all must
    go NULL); reach_determined / reach_indeterminate publication shape on
    W0-7 fixture 8 and the timed-latch pair; cache self-audit floor on the 49
    zero-key authority_change rows; _principals_by_function ordering
    (deterministic across 3 fresh processes); the adjudication fix 0a7fa43e
    (clock-spelling split) — include its 4 test arms' status and confirm the
    corpus block_context census ({timestamp: 183, number: 16, now: 10} per
    the round-3 review) yields ZERO newly-proven no_time_reference rows that
    carry a non-timestamp clock in a latch tree.
KNOWN NOISE TO EXCLUDE: the callee_args_digest operand-slot flicker (L-25,
37-46 slots, 25/88 units) — bucket separately as 'L-25 noise', never count as
CHANGED. Every non-noise row must be attributable to a named leg commit
(including 0a7fa43e). Output the full tabulation; flag anything unexplained
LOUDLY.`,
  { label: 'full-replay-differential', phase: 'Exit gate', model: 'opus', effort: 'high' }
)

phase('Milestone verify')

const lenses = [
  {
    key: 'mainnet',
    brief: `LENS 1 — CORRECTNESS AGAINST MAINNET. Re-derive the wave's central
claims yourself from chain + verified source (SPARING pinned reads, controls).
In particular: (a) A7's duration-bound machinery — re-derive 2-3 published or
projectable bounds against verified source / the pinned getters
(pauseUntilDuration 28800 weETH / 86400 LiquidityPool / MAX 2592000 at
25619159) and confirm no defaulted bound was introduced for a latch whose
bound is NOT readable; verify the adjudicated clock-spelling split against the
production builder (the repro at
/tmp/claude-1000/-home-riley-PSAT/d8116573-440b-4ce0-8e02-ddab7ee5b902/scratchpad/rv2/a7_blockclock_repro.py
should still print not_determined for NumberTwin/NowLatch and
no_time_reference for PlainLatch); (b) Leg B's empty-intersection fix on the
real WithdrawRequestNFT.requestWithdraw shape — liquidityPool() returns the
actual caller that was never a candidate; confirm not_determined, and that a
GENUINELY empty enumerable set still answers resolved_empty (negative
control); (c) the reroute — sample 3 rerouted rows and 3 still-public rows
against verified source: rerouted rows must have a real seen-but-unlowered
guard; still-public rows must be genuinely ungated; also spot-check the leg's
declared corrected false-adverses (cid 561 shouldSubmitReport, cid 454 claim)
against their verified source; (d) A2's synthetic-emitter finding — verify
the implementer's eth_simulateV1 evidence is real and correctly read.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION. (a) Reconcile the full-replay
differential LINE BY LINE — every non-noise ADDED/CHANGED/REMOVED row
attributed to a leg commit (incl. adjudication 0a7fa43e), or it is not
explained; verify the L-25 bucket really is operand-slot-only. (b) Prose
copies: A7 has TWO (pauseQualifier, claimWitnessFacts) — did both change in
the A7 commits, and did any over-claim RELOCATE into prose elsewhere
(action_summary restates exec.arbitrary — Wave 3 owns it; confirm nothing this
wave made it worse)? (c) Did any declared control move (sweepDust, the
bitmap-24 inertness, audits/ storage control, PlainLatch's proven state,
AbsorbedWindow's 2592000)? (d) Does any existing test now pin wrong behaviour;
were the three known defect-pinning tests (timed-latch None assert,
claimsVocab :470/:641) inverted with positive-case siblings? (e) For each leg:
what did the input DISCARD before the code saw it — apply the collapsed-inputs
question to the NEW code (the reroute discriminator, the per-asset holdings
join, the cache plane split, the clock-kind sets). (f) R5: net cache-version
state at merged HEAD is coherent (one version per shipped shape, reasons in
the comment block; the legs' bumps must not collide after the merge). (g) The
adjudication itself: confirm 0a7fa43e implements the round-3 reviewer's
prescription exactly (demotion timestamp|now|number; harvest timestamp|now)
and that the units trap is pinned (a block-count constant never published as
seconds).`,
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
}
