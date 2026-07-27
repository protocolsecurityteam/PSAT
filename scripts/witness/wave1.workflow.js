export const meta = {
  name: 'witness-wave1',
  description: 'Witness-integrity Wave 1: legs A (static/summaries), C (claims/matchers), F (control graph) in parallel worktrees',
  whenToUse: 'Run only after Wave 0 exited green (see WAVE_0_REPORT.md).',
  phases: [
    { title: 'Legs', detail: 'A, C, F in parallel worktrees; impl -> review -> retry(<=3) each' },
    { title: 'Merge', detail: 'merge leg branches into fix/witness-integrity, resolve goldens' },
    { title: 'Exit gate', detail: 'tier-0 gate + corpus differential' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

// Conventions carried from wave0.workflow.js (post-correction): cap-3 review
// loop, reviewer scope discipline + out_of_scope_findings channel, halt ->
// driving-agent adjudication. See WITNESS_INTEGRITY_OPERATIONS.md.

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const OPS = 'WITNESS_INTEGRITY_OPERATIONS.md'
const BRANCH = 'fix/witness-integrity'
const W1_BASE = 'a7c82e46' // Wave 0 exit HEAD; every leg must contain this commit
const WT_ROOT = '/tmp/claude-1000/-home-riley-PSAT/b4f9f02c-c3af-4273-bccf-1e8a13045413/scratchpad/wave1'

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
pipeline/live suite; verification ladder ends in defer-with-stated-cause).
Then \`${HANDOFF}\` §0-§2 (governing rule, traps, R1-R5 + review-lens charter),
and WAVE_0_REPORT.md ("Constraints carried into later waves").

AUTHORISED: commit to your leg branch. NOT AUTHORISED: git push, PR, merge to
${BRANCH} or main, live suite, production, editing .env/CLAUDE.md/settings.

Traps (§1): stale pr-160/ storage-key prefix is now handled by the read path —
but StorageKeyMissing is still never evidence of absence; jsonb null vs SQL
NULL (use jsonb_typeof); jsonb_array_elements needs a case-guard; eRPC "latest"
flakes (pin hex(head()-10); 25619159 for historical). On-chain facts: >=3 reads
+ a pinned read at 25619159, with a discriminating control address. SPARING RPC
use — single facts, never population scans.
`

function implPrompt(leg, retryNote) {
  return `${boilerplate}

You are the tier-1 implementer for **Wave 1 Leg ${leg.key} — ${leg.title}**.

WORKTREE SETUP (do this first, exactly):
  cd /home/riley/PSAT
  git worktree remove --force ${WT_ROOT}/leg-${leg.branch} 2>/dev/null; git branch -D witness/leg-${leg.branch} 2>/dev/null
  git worktree add ${WT_ROOT}/leg-${leg.branch} -b witness/leg-${leg.branch} ${BRANCH}
  cp /home/riley/PSAT/.env ${WT_ROOT}/leg-${leg.branch}/.env
  cd ${WT_ROOT}/leg-${leg.branch}
  git merge-base --is-ancestor ${W1_BASE} HEAD && echo BASE_OK   # must print BASE_OK; if not, STOP and report
Work ONLY in this worktree, commit ONLY to witness/leg-${leg.branch}. Docker
services are shared and already up. Offline tests: the worktree has no
run_tests_fast.sh (untracked); use the canonical serial command from CLAUDE.md
scoped to the test files you touch, and run the FULL suite only once before
your final report.

Read \`${HANDOFF}\` §5 "Leg ${leg.key}" in full — it carries the measured
evidence and exact fix shapes, including the "Added by G6/G7" items which are
part of your scope. Your items:
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
enumerated, and an explicit "what I did not check".${retryNote}`
}

function reviewPrompt(leg, implReport) {
  return `${boilerplate}

You are the tier-2 reviewer for **Wave 1 Leg ${leg.key} — ${leg.title}**.
Review ALL commits on branch witness/leg-${leg.branch} (worktree
${WT_ROOT}/leg-${leg.branch}; run tests there — it has .env copied in).
Compare against ${BRANCH} (merge-base ${W1_BASE}).

Adversarial in miniature, not a checklist. The judgment-bearing pair:
  R1  three representable states on every new/changed evidence field,
      distinguishable by a consumer; a non-nullable boolean on an evidence
      field is a defect by construction.
  R4  positive-case tests, not only hedges; a test pinning a hedge needs a
      sibling pinning the un-hedged value's reachability.
Also: R2 (run every firing query yourself), R3 (consumers changed in the same
commit — over-claims often have a PROSE copy), R5 (EFFECT_CACHE_SCHEMA_VERSION
if witness shape changed), both declared controls, and the leg's stated
constraints (below) held.

${leg.constraints}

SCOPE DISCIPLINE (binding, ${OPS} §2): a violation may reject ONLY if it lies
inside this leg's declared scope — the handoff §5 Leg ${leg.key} surface plus
same-commit consumers of fields the leg changed. Real defects outside that
scope (including pre-existing behaviour the leg strictly improves) go under
out_of_scope_findings with a reproduction — never rejection grounds.

The implementer reported:
${implReport}

Refuting is a successful outcome. Accepting something you did not reproduce is
the only failure mode. Every violation needs an exact reproduction command.`
}

const LEGS = [
  {
    key: 'A',
    branch: 'a',
    title: 'static/summaries',
    model: 'opus',
    items: `
1. \`_detect_timelock\` stub -> real STATIC implementation (has_timelock,
   pattern, delay_variables, queue_execute_functions, authorized_roles from
   source). The delay VALUE ships as null + delay_source:"not_read" (R1) — NO
   chain read, NO hardcoded chain_id, NO default delay (a defaulted delay is a
   fabricated credit). 92/92 currently false incl. EtherFiTimelock.
2. \`is_pausable\` widening EXCLUDING the EigenLayer bitmap shape
   (pause(uint256)/pauseAll()/unpause(uint256), 24 fns / 8 contracts) — see
   constraints below. 32 contracts currently false with pause* functions.
3. Slither outage made LOUD: analysis_status errors:[] on a total outage is a
   defect; 75/75 currently silent. risk_level "unknown" split not-run vs
   run-clean (R1).
4. Six summary columns three-state: is_factory/is_nft/standards (+ the original
   trio) — all already nullable; emit NULL when the detector did not run,
   never false/{} as "not looked". standards={} on 61/92 drives role="token".
5. G3 classes F and R: revert_detect.py:364-370 recursion skip on read lvalues
   (gate lost on \`return gatedCallee(...)\` forwarders); predicate_artifacts.py:642
   excludes fallback/receive so trees are never built. Class R selector
   representation: use the EMPTY-STRING sentinel db/effect_cache.py:384-388
   documents — do NOT keep the fabricated keccak("fallback")[:4] selectors (7
   rows) and do NOT invent a third convention.`,
    constraints: `LEG-A CONSTRAINTS: (a) A7 lands in Wave 2 — if \`is_pausable\`
widening cannot CLEANLY exclude the bitmap-pause family, do not widen at all;
implement the rest, state the blocker in your report, and the driving agent
adjudicates. Verify the exclusion: the 24 bitmap rows must stay status=NULL,
authority_public=False, labels=[], nclaims=0 after your change. (b) This module
has NO chain in scope — introducing a chain_id=1 hardcode is the single most
likely failure of this leg (§5). (c) summaries consumer
services/aggregations/company_overview.py:1258-1262 defaults has_timelock/
is_pausable/is_factory to False on row ABSENCE — that consumer fix is Wave 3;
your R3 duty covers consumers of the VALUES you change, not that absence
default; state it, don't fix it.`,
  },
  {
    key: 'C',
    branch: 'c',
    title: 'claims/matchers',
    model: 'fable',
    items: `
1. A3+A4 as ONE analysis: \`param_constraints()\` in _facts.py — "does a
   mandatory revert gate reference this parameter between entry and sink?",
   three states (R1). _mandatory_operands (:57-90) already walks the mandatory
   path but :76-83 drops parameter operands. TIGHTENED RULE: a mandatory leaf
   constrains a param only if it is NOT the function's own value sink — join
   against _facts.body_sinks, NOT witness.sink_ids (empty on value_router).
   Do NOT blanket-exclude external_call_revert leaves (forwardExternalCall's
   deployedEtherFiNodes(...) is a genuine constraint). POSITIVE CONTROL:
   sweepDust must stay unconstrained/flagged — a prior proposal suppressed it.
   Measured: 9/20 exec.arbitrary overstate; 20/93 param destinations
   constrained (a narrowing, not a retreat).
2. Remove LRTSquaredAdmin.rebalance's exec.arbitrary claim — pure false
   positive (no arbitrary call exists).
3. A5: record the rate limiter as a FACT at zero severity weight — NOT in the
   amount_kind lattice. MUST record refillRate and capacity as discriminators
   (a zero-refill or zero-capacity bucket is a pause in disguise; the fact
   shape must let a future scorer tell throughput cap / total cap / freeze).
   EtherFiRateLimiter refill status is CLOSED on-chain (4h-24h) — do not
   re-verify, cite G7 §4.2.
4. A8: new \`delegatecall.execute\` claim family (NOT upgrade.implementation).
   Two shapes: LRTSquaredCore.fallback split-proxy dispatch off
   onlyGovernor-settable slot -> storage_setter; LRTSquaredAdmin.depositToStrategy
   caller-keyed mapping element -> not_determined. The library-route sink
   records the LIBRARY's own param name ('target') which does not exist in the
   subject contract — your classifier must resolve that without misclassifying
   storage_setter as not_determined. W0-7 fixture 9 is your gate. Do NOT widen
   scope on the refuted "producer misses OZ functionDelegateCall" premise
   (handoff §11).`,
    constraints: `LEG-C CONSTRAINTS: (a) chain-blind by construction — STATE
this in your report rather than leaving it unaddressed; do not acquire a chain
assumption. (b) WAVE_0_REPORT.md L-24: \`derived_from\` misbinds one origin on
flow-insensitive local reassignment (Teller depositAsset omitted,
nativeWrapper published) — if param_constraints() consumes derived_from, it
must not treat it as ground truth; handle or bound the misbind case and say
how. (c) The corpus now pins claims[].witness — your golden diffs will be
LARGE; enumerate every changed row against the A3/A4/A8 measured counts (9/20,
20/93, 2 rows) and justify each.`,
  },
  {
    key: 'F',
    branch: 'f',
    title: 'control graph',
    model: 'opus',
    items: `
1. tracking.py:851 — split \`_collect_authority_state_vars(...) |
   external_contract_vars_from_effects\`: "gates the caller" vs "gets called"
   are different provenances; keep them distinguishable on the persisted row
   (:977 types both external_contract today). REGRESSION METRIC: 66 mutual
   directed edges must DROP; state the new number in the commit.
2. tests/test_effects_selection.py:451 asserts a mutual control pair is a
   legitimate "cycle" — expect to invert it (R4, declare in commit message).
3. recursive.py:1104 hardcodes resolved_type="contract" — stop overwriting the
   classifier type (EtherFiTimelock's node loses its 'timelock' type + delay).
   Do NOT simplify away _build_principal_lookup's priority fold — it currently
   protects the surface from this overwrite.
4. control_graph_nodes.analyzed bool NOT NULL collapses three populations
   (not-a-contract / attempted-failed / beyond depth horizon); split (R1) and
   persist max_depth so the third is detectable.
5. G1-5 (REVERSED into this leg): watcher rotation writes only cv.value
   (unified_watcher.py:1215-1252) leaving resolved_type/details STALE — a
   Timelock->EOA rotation publishes the new EOA as resolved_type="timelock"
   with the old delay (safety-inflating false credit, inv 1's worst class).
   Fix: on watcher write, null resolved_type+details or re-run
   classify_resolved_address. Armed population: 13 rows (8 safe + 5 timelock).
   Test must assert the TIMELOCK case, not only the Safe case.
6. G6-9 decision (REQUIRED, not optional): the same callee-as-controller
   conflation lives in principal_labels via services/policy/principal_enrichment.py
   (Ethereum 2 deposit contract labelled a "controller" of StakingManager;
   Curve pool of Liquifier). Either make the provenance split at the shared
   upstream so principal_enrichment inherits it, or add that file to this leg —
   DECIDE, implement the choice, and state it; your mutual-edge metric will NOT
   detect this plane.`,
    constraints: `LEG-F CONSTRAINTS: (a) chain requirement §5: none of the five
tables this leg writes has a chain column; deployment_address is a bare
String(42). Every read you ADD must key on contract_id (chain-scoped) or carry
an explicit chain predicate; the new provenance column must not be correct only
because one chain has ever been analysed. (b) The watcher-rotation fix touches
services/monitoring/unified_watcher.py — shared with no other leg this wave;
confirm with git log that no Wave-0 commit conflicts. (c) Prefer append-only
rows keyed (contract_id, controller_id, block_number) per the handoff if the
schema change stays small; otherwise nulling stale fields is acceptable —
justify the choice.`,
  },
]

async function runLeg(leg) {
  let feedback = null
  let accepted = false
  let report = null
  let review = null
  // Driving-agent adjudication 2026-07-28: Leg C granted ONE extra round. Its
  // round-3 reject was two reproduced in-scope consumer violations with clear
  // minimal fixes (selection.py claim transparency; claimsVocab absent-key
  // hazard tint), and the reviewer explicitly deferred the selection.py
  // placement decision to the driving agent — decided: fix here, minimally,
  // so Wave 2 Leg D inherits a clean baseline.
  // Second Leg C extension (2026-07-28): round-4 mandate items landed and
  // reproduced; round-4 review found a genuine R1 at the leg's CORE surface —
  // param_constraints() publishes unconstrained_proven through the
  // carries_effect fall-through. In-scope, concrete, repro in hand. Round 5 is
  // the last extension; if it fails, the driving agent closes out directly.
  const cap = 3 + (leg.key === 'C' ? 2 : 0)
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
      if (leg.key === 'C' && round === 3) {
        feedback += `

ADJUDICATION NOTE from the driving agent — binding for this round. Fix exactly
the two violations, nothing broader:
1. [R3 / selection.py] The driving agent has decided the repair lands HERE,
   minimally, so Wave 2 Leg D inherits a clean baseline. Shape: make claim
   classes that do not explain value/supply behaviour TRANSPARENT to
   \`_enrolled_families\` — filter fact-class claims (rate_limit.consume) and
   delegatecall.execute out BEFORE bucketing, so a function whose only claims
   are transparent stays families=None (full §6 synthesis) exactly as before
   the leg. Do NOT redesign the bucketing; do NOT enumerate flow./supply.
   differently. Pin with a test: the 13 measured rows (ef 647 depositToStrategy
   + the 12 EtherFiNodesManager rate-limit rows) must remain in the candidate
   set — assert via _cascade_rows/_enrolled_families against the local DB shape
   or a synthetic fixture reproducing it. A zero-weight FACT must never remove
   a function from evidence-gathering — state that invariant in a comment at
   the filter. Ensure the EFFECT_CACHE_SCHEMA_VERSION comment covers this
   (extend v15's reason or bump; the probe set changes back to pre-leg for
   those 13, which is the intended restoration).
2. [R1 / claimsVocab.js] Minimum fix as the reviewer prescribed: an ABSENT
   target_constraint keeps the hazard tint and the caller-chosen reading
   (sawUnknownParam must set the same tone path as the unconstrained case, or
   route into sawCaller), wording may note the gate is not yet analysed. Only
   a PRESENT constrained verdict may soften. Add the regression test: a
   legacy-shaped claim (no target_constraint key) must render the same tone
   chip as before the leg (compare against bf240fe9 behaviour, which the
   reviewer's repro script already does).
Run the touched test files + full vitest; report counts. Same worktree, same
branch, new commit(s).`
      }
      if (leg.key === 'C' && round === 4) {
        feedback += `

ADJUDICATION NOTE from the driving agent — binding for this round (the LAST
extension; fix exactly these two, nothing broader):
1. [R1 / _facts.py:548-568] The carries_effect \`continue\` must BLOCK the
   positive proof, not erase the leaf: a mandatory leaf that references the
   parameter but is excluded from counting as a constraint (because it is the
   function's own value sink / in the transparency set) means "cannot prove
   unconstrained" — route the function-wide default to not_determined, never
   unconstrained_proven. unconstrained_proven may only be published when every
   mandatory leaf referencing the param was actually assessed and none
   constrains. CONSTRAINT: both declared controls must hold — sweepDust stays
   at its currently-published state and the corpus negative controls
   (payAnyone, withdrawUnlimited/withdrawDecoy) stay clean. If honouring this
   rule CHANGES sweepDust's published state, STOP on that item and report the
   exact leaf-by-leaf tension instead of choosing silently — the driving agent
   decides. Fix the effect_sink_identities docstring to state the true
   consequence. Pin with tests: one function where the only param-referencing
   mandatory leaf carries_effect (must publish not_determined), and the
   existing positive/negative controls re-asserted.
2. [guard mislabel / _facts.py:465-467] Structural discriminators run FIRST;
   \`via_derived\` may set the BINDING (derived_from) but must not coerce the
   guard word: hash_commitment only when the computation is actually a
   commitment shape (keccak/abi.encode computed_kind), a comparison bound stays
   numeric_bound. Update the claimsVocab GUARD_WORD rendering only if the
   emitted vocabulary changes; enumerate any golden rows that change.
Run the touched test files + full vitest + the corpus gate; report counts.
Same worktree, same branch, new commit(s).`
      }
      log(`Leg ${leg.key}: rejected round ${round} — ${(review.violations || []).length} violation(s)`)
    }
  }
  log(`Leg ${leg.key}: ${accepted ? 'ACCEPTED' : 'NOT ACCEPTED after 3 rounds — driving agent adjudicates'}`)
  return { leg: leg.key, accepted, report, review }
}

phase('Legs')
log('Wave 1 — legs A, C, F in parallel worktrees off ' + BRANCH)

const legResults = await parallel(LEGS.map((l) => () => runLeg(l)))
const clean = legResults.filter(Boolean)
const failed = clean.filter((r) => !r.accepted)
if (failed.length || clean.length !== LEGS.length) {
  log(`HALT: ${failed.map((f) => f.leg).join(', ') || 'missing results'} — driving agent adjudicates before merge.`)
  return { wave: 1, halted_at: 'legs', legResults: clean }
}

phase('Merge')

const mergeReport = await agent(
  `${boilerplate}

You are the MERGE agent for Wave 1. Mechanical job, no redesign.

In /home/riley/PSAT (the main checkout, branch ${BRANCH}):
  1. Confirm ${BRANCH} is checked out and clean (untracked docs are fine).
  2. git merge --no-ff witness/leg-a, then witness/leg-c, then witness/leg-f.
  3. Conflicts in CODE: if trivial (disjoint hunks, import lists), resolve
     minimally and say exactly what you did. If substantive, STOP, report the
     conflict, do not guess.
  4. Conflicts in corpus GOLDENS (tests/fixtures/**): resolve by REGENERATING
     the golden with the repo's regeneration path after the code merge, then
     verify the regenerated diff equals the UNION of the diffs the two legs
     declared. If it does not, STOP and report the delta rows.
  5. Run the offline suite once (./run_tests_fast.sh — main checkout has it)
     and cd site && npm test. Report counts.
  6. Remove the three worktrees (git worktree remove ${WT_ROOT}/leg-a etc.) —
     they are this wave's own — but KEEP the witness/leg-* branches.
Report: merge commits created, conflicts + resolutions, suite counts.`,
  { label: 'merge-legs', phase: 'Merge', model: 'opus', effort: 'medium' }
)

phase('Exit gate')

const gate = await agent(
  `Run the tier-0 mechanical gate and report results verbatim. You make NO
judgments — execute and report.

  cd /home/riley/PSAT && bash scripts/witness/gate.sh --base main --require-determinism

Return passed=true only if the script prints "GATE: PASS". List every FAIL line
in failures. Put the full summary block in raw.`,
  // opus, not haiku: the only structured-output contract failure in this
  // session came from the haiku gate runner (operator decision 2026-07-28).
  { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
)

const differential = await agent(
  `${boilerplate}

Produce the Wave 1 REAL-CORPUS DIFFERENTIAL on ${BRANCH} (post-merge HEAD) vs
${W1_BASE} (Wave 0 exit). Local recompute over existing DB artifacts only — no
pipeline, no workers.

For the planes Wave 1 touched:
  - claims plane (Leg C): recompute claims for the protocol-1 functions whose
    matchers changed; tabulate ADDED / CHANGED / REMOVED claims + witness
    fields vs the DB rows, with counts against the measured expectations
    (9/20 exec.arbitrary narrowed, 20/93 param constrained, rebalance FP
    removed, 2 delegatecall.execute rows minted).
  - summaries plane (Leg A): recompute contract summaries for the 92 protocol-1
    contracts; tabulate has_timelock/is_pausable/is_factory/is_nft/standards/
    risk_level transitions (false->true, false->NULL, {}->NULL etc.), and
    confirm the 24 bitmap-pause functions are UNTOUCHED (status NULL,
    authority_public False, labels [], nclaims 0).
  - control graph (Leg F): rebuild the graph for protocol 1; report the mutual
    directed edge count (was 66), nodes whose resolved_type changed, and
    principal_labels rows whose labels changed (if the leg touched that plane).
KNOWN NOISE TO EXCLUDE (WAVE_0_REPORT.md): the callee_args_digest operand-slot
flicker (L-25) — if you see operand-slot-only diffs with kind/operator/role
unchanged, bucket them separately as 'L-25 noise', do not count them as CHANGED.
Every non-noise row must be attributable to a named leg commit. Output the full
tabulation; flag anything unexplained LOUDLY.`,
  { label: 'real-corpus-differential', phase: 'Exit gate', model: 'opus', effort: 'high' }
)

phase('Milestone verify')

const lenses = [
  {
    key: 'mainnet',
    brief: `LENS 1 — CORRECTNESS AGAINST MAINNET. Re-derive the wave's central
claims yourself from chain + verified source (SPARING pinned reads, controls).
In particular: (a) Leg A's timelock static facts against EtherFiTimelock's
verified source — and confirm NO chain read and NO defaulted delay was
introduced (delay null + delay_source not_read); (b) Leg C's A3/A4 narrowing on
2-3 real functions incl. the sweepDust positive control and forwardExternalCall's
external_call_revert constraint; (c) Leg F's provenance split on real rows:
eETH/lido/stETH/treasury must no longer be controllers, EtherFiTimelock's node
must carry its classifier type; re-run the mutual-edge count yourself.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION. (a) Reconcile the real-corpus
differential LINE BY LINE (it is in your context below) — every non-noise
ADDED/CHANGED/REMOVED row attributed to a leg commit, or it is not explained;
verify the L-25 noise bucket really is operand-slot-only. (b) Did any
over-claim RELOCATE into prose (action_summary restates exec.arbitrary on 20
rows — did Leg C's narrowing reach it, or is that correctly deferred to Wave 3
and stated?); (c) did any declared control move; (d) does any existing test now
pin wrong behaviour; (e) for each leg, what did the input DISCARD before the
code saw it (five of the largest defects were collapsed inputs; no grep finds
them); (f) the A7-before-is_pausable constraint: confirm the bitmap-24 are
inert at HEAD.`,
  },
]

const verdicts = await parallel(
  lenses.map((l) => () =>
    agent(
      `${boilerplate}

You are a tier-3 MILESTONE VERIFIER for Wave 1 — the last gate before Wave 2
builds on this work. A miss here is caught by nobody.

${l.brief}

Tier-0 gate result:
${JSON.stringify(gate, null, 2)}

Merge report:
${mergeReport}

Real-corpus differential:
${differential}

Read ${HANDOFF} §5 (Wave 1 detail) and §11 (known-wrong hypotheses — do not
validate work built on a refuted premise). YOUR JOB IS TO REFUTE. Every verdict
needs pasted command output. Return verdict=FAIL if any wave-exit criterion
(§10) is unmet, and say which. Finish with "what I did not check".`,
      { label: `verify:${l.key}`, phase: 'Milestone verify', model: 'fable', effort: 'high', schema: VERIFY_SCHEMA }
    )
  )
)

const cleanVerdicts = verdicts.filter(Boolean)
const allPass = gate?.passed === true && cleanVerdicts.length === lenses.length && cleanVerdicts.every((v) => v.verdict === 'PASS')

log(allPass ? 'WAVE 1 EXIT: PASS' : 'WAVE 1 EXIT: FAIL — driving agent adjudicates')

return {
  wave: 1,
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
