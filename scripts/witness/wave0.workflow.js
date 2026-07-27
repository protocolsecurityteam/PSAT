export const meta = {
  name: 'witness-wave0',
  description: 'Witness-integrity Wave 0: trustworthy measurement (blocks all later waves)',
  whenToUse: 'Run first. Waves 1-3 are meaningless until this exits green.',
  phases: [
    { title: 'Preflight', detail: 'branch + merge-base + baseline gate' },
    { title: 'W0 items', detail: '9 sequential fixes, each impl -> Opus review -> retry(<=2)' },
    { title: 'Exit gate', detail: 'tier-0 script + corpus discrimination proof' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

// ---------------------------------------------------------------------------
// Tiering (see WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md §8):
//   tier 0  script, run by a haiku agent whose only job is to execute + report
//   tier 1  Opus  implementers
//   tier 2  Opus  per-agent review (judgment, local to one diff)
//   tier 3  Fable milestone verification (strongest model where errors are
//           least likely to be caught by anything downstream)
// ---------------------------------------------------------------------------

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const BRANCH = 'fix/witness-integrity'

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
          rule: { type: 'string', description: 'R1 | R2 | R3 | R4 | other' },
          detail: { type: 'string' },
          reproduction: { type: 'string', description: 'exact command that shows it' },
        },
      },
    },
    out_of_scope_findings: {
      type: 'array',
      description: 'Real reproduced defects OUTSIDE the item scope — recorded in the ledger, never rejection grounds',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['detail', 'reproduction'],
        properties: {
          detail: { type: 'string' },
          reproduction: { type: 'string' },
        },
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

// The 9 Wave 0 items, in mandatory order. Detail lives in the handoff §4 —
// agents read it there rather than having it duplicated (and drifting) here.
const W0 = [
  { id: 'W0-1', label: 'artifact-prefix', title: 'Artifact storage-key prefix + loud storage failures' },
  { id: 'W0-2', label: 'determinism-d6', title: 'D6 cross-process determinism (PYTHONHASHSEED class)' },
  { id: 'W0-3', label: 'taint-binding', title: '_taint.py param binding (allocation-order class)' },
  { id: 'W0-4', label: 'provenance-union', title: 'provenance.py argument union (shared by B and C)' },
  { id: 'W0-5', label: 'jsonb-null-audit', title: 'jsonb-null audit across the query surface' },
  { id: 'W0-6', label: 'persist-sinks', title: 'D2 persist mutability + sinks (additive only)' },
  { id: 'W0-7', label: 'corpus-fixtures', title: 'Corpus extension with DISCRIMINATING fixtures' },
  { id: 'W0-8', label: 'determinism-gate', title: 'The determinism gate (both classes)' },
  { id: 'W0-9', label: 'upgrade-write-path', title: 'UpgradeEvent write-path integrity (block_number=0 ordering; old_impl discriminator)' },
]

const boilerplate = `
Repo: /home/riley/PSAT, branch \`${BRANCH}\`. Read \`${HANDOFF}\` §0 (governing rule +
authorisation boundary), §1 (traps), §2 (rules R1-R5) before anything else.

AUTHORISED: commit to the branch. NOT AUTHORISED: push, PR, merge, live suite,
production, editing .env/CLAUDE.md/settings. Do not push.

Verify \`git merge-base\` before you start. In a prior fan-out 9 of 9 agents began
from a stale base.

Traps that will waste your time: artifacts carry a stale \`pr-160/\` storage-key
prefix (bytes are at the prefix-STRIPPED path; StorageKeyMissing is NEVER evidence
of absence); \`IS NOT NULL\` over a jsonb column is wrong (use jsonb_typeof);
\`jsonb_array_elements\` needs a case-guard; eRPC "latest" fails intermittently
(pin to hex(head()-10), and 25619159 for historical).

On-chain facts: >=3 reads plus a pinned read at block 25619159, always with a
discriminating control address.
`

async function implementItem(item, feedback) {
  const retry = feedback
    ? `\n\nThis is a RETRY. A reviewer rejected your previous attempt. Fix exactly these, do not re-litigate:\n${feedback}`
    : ''
  return agent(
    `${boilerplate}

You are the tier-1 implementer for **${item.id} — ${item.title}**.

Read \`${HANDOFF}\` §4 and find the **${item.id}** subsection. It carries the
problem, the measured evidence, and the exact fix. Implement it.

BEFORE writing code, state in your first message:
  1. the POSITIVE control - a row that must stay flagged after your change
  2. the NEGATIVE control - a row that must stay clean
  3. the measured "before" numbers you will compare against
A prior implementer's proposal would have suppressed \`sweepDust\`, the stated
positive control, and only production data caught it.

R1-R5 are binding (R5 = bump EFFECT_CACHE_SCHEMA_VERSION on any witness-shape change). In particular R2: if your fix relies on a sentinel or a
fail-closed branch, your commit MUST include a query proving the sentinel FIRES
on real data. Two sentinels in this codebase were built, wired, and dead.

Expect to delete or invert existing tests - several assert the defect as correct.
Declare every such change in the commit message (the gate checks for this).

Verify against PRODUCTION artifacts, never local reproductions: MinIO bucket
\`psat-artifacts\`, key \`artifacts/<job_id>/<name>\`.

Commit to the branch, one commit for this item. Report: what changed, before/after
numbers, both controls' status, your sentinel proof, and an explicit
"what I did not check".${retry}`,
    { label: `impl:${item.label}`, phase: 'W0 items', model: 'opus', effort: 'high' }
  )
}

async function reviewItem(item, implReport) {
  return agent(
    `${boilerplate}

You are a tier-2 reviewer for **${item.id} — ${item.title}**. Review the HEAD
commit on \`${BRANCH}\`.

This is adversarial in miniature, NOT a checklist - the mechanical checks (ruff,
pyright, suite, greps) are already run by \`scripts/witness/gate.sh\` and are not
your job. Yours is the judgment-bearing pair:

  R1  Does every new/changed EVIDENCE field have three representable states
      (proven-present / proven-absent / not-determined), distinguishable by a
      consumer? A non-nullable boolean on an evidence field is a defect by
      construction.
  R4  Is there a POSITIVE-case test, not only a hedge test? A test pinning a
      hedge must have a sibling pinning the reachability of the un-hedged value.
      Known example of the failure: a test named "publishes no bound it cannot
      prove" asserts None for a bound that IS readable by one eth_call.

Also confirm:
  R2  If a sentinel is relied on, is a FIRING PROOF attached? Run the query
      yourself; do not take the claim.
  R3  If a published field changed, did its consumers change in the SAME commit?
      Over-claims often have a PROSE copy - \`action_summary\` restates
      exec.arbitrary verbatim on 20 rows; A7 has two prose copies.
  - Did both declared controls hold?

SCOPE DISCIPLINE (driving-agent adjudication 2026-07-27, binding): a violation
may reject this commit ONLY if it lies inside the item's declared scope — the
handoff §4 subsection's problem/fix surface, plus same-commit consumers of
fields this commit changed (R3). A real defect found OUTSIDE that scope —
including pre-existing behaviour this commit strictly improves — is a
successful review outcome but NOT a rejection ground: report it under
\`out_of_scope_findings\` with a reproduction; the driving agent records it in
WITNESS_INTEGRITY_LEDGER.md. W0-1 ran 9 rounds because this line did not exist.

The implementer reported:
${implReport}

Refuting is a successful outcome. Accepting something you did not reproduce is
the only failure mode. Every violation needs an exact reproduction command.`,
    { label: `review:${item.label}`, phase: 'W0 items', model: 'opus', effort: 'high', schema: REVIEW_SCHEMA }
  )
}

async function runGate(note) {
  return agent(
    `Run the tier-0 mechanical gate and report results verbatim. You make NO
judgments - you execute and report.

  cd /home/riley/PSAT && bash scripts/witness/gate.sh --base main --require-determinism

Return passed=true only if the script prints "GATE: PASS". List every FAIL line
in \`failures\`. Put the full summary block in \`raw\`.

${note || ''}`,
    // was haiku; opus per operator decision 2026-07-28 (structured-output reliability)
    { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
  )
}

// ---------------------------------------------------------------------------

phase('Preflight')
log('Wave 0 — trustworthy measurement. Nothing downstream is meaningful until this exits.')

const preflight = await agent(
  `${boilerplate}

Preflight for Wave 0.
  1. Ensure branch \`${BRANCH}\` exists off current \`main\`; create it if absent.
     Report the merge-base SHA.
  2. Run \`bash scripts/witness/gate.sh --base main --skip-suite\` to capture a
     BASELINE. Wave 0 has not started, so a determinism SKIP is expected here.
  3. Record the "before" numbers Wave 0 will be measured against, by query:
     - artifacts with a stale prefix: count of \`artifacts.storage_key LIKE 'pr-160/%'\`
     - \`effective_functions\`: total, and count where jsonb_typeof(conditions)='null'
     - \`artifacts\`: total, and count where jsonb_typeof(data)='null'
     - the mutual-edge count:
       with e as (select distinct from_node_id f, to_node_id t from control_graph_edges)
       select count(*) from e a join e b on a.f=b.t and a.t=b.f;
  Report all numbers with the exact SQL used.`,
  { label: 'preflight', phase: 'Preflight', model: 'opus', effort: 'medium' }
)

phase('W0 items')

const outcomes = []
for (const item of W0) {
  let feedback = null
  let accepted = false
  let report = null
  let review = null

  // impl -> review -> retry, capped at 3 rounds (unbounded loops converge on
  // agreement rather than correctness). Cap raised 2 -> 3 by operator decision
  // 2026-07-26; on exhaustion the run halts and the DRIVING AGENT adjudicates.
  //
  // Driving-agent adjudications 2026-07-26: W0-1 granted TWO extra rounds.
  // Round-3 reject was a single boundary residual (routers/analyses.py 404
  // collapse on the SPA-facing artifact endpoint); round 4 fixed it but the
  // reviewer found two narrow bugs in the round-4 additions themselves
  // (StorageKeyAbsent caught in the proven-absent tuple; sticky not-determined
  // banner state in EntityActivity.jsx). Every prior round's fix keeps
  // surviving independent reproduction, and each residual set is smaller than
  // the diff that produced it — converging, not agreeing. Round 5 is scoped to
  // a one-line tuple move + a state reset, both with reviewer-written failing
  // repro tests in hand.
  // Round-5 reject: code confirmed correct; residuals were 2 evidence defects
  // (false 21-cell docstring claim; monkeypatch.undo() test) + 2 one-hop
  // consumers (get_all_artifacts silent drop; stale history state). Root cause
  // of the treadmill is per-citation fixing, so round 6's mandate (injected
  // below via the round-5 feedback) adds an exhaustive consumer-surface sweep.
  // Round-6 reject: the exhaustive-sweep mandate held (reviewer reproduced the
  // whole enumeration); residual collapsed to ONE root cause in two frontend
  // sites — not-determined keyed to `status === 503` only, so 500/502/504/
  // network errors collapse into the absence state (plus a poisoned null in
  // dependencies.js's module cache). Round 7 is a predicate inversion with
  // reviewer-written repro tests in hand.
  // Round-7 reject: R1/R2/R4/R5 all HOLD (mutation-tested, Loki-verified);
  // single R3 residual — Timeline.jsx's prose absence claim ("No activity
  // before the line.") renders beside the hedge marker when history is
  // unknown. Reviewer prescribed the remedy and scope: suppress/re-word that
  // branch when historyUnknown, as a follow-up commit, NOT a rework.
  // Round-8 reject: the round-8 fix itself used a non-nullable boolean prop
  // (historyUnknown) — R1's defect-by-construction — leaving the PENDING state
  // rendering as proven absence (no fetch timeout => indefinitely). Round 9
  // prescribes the state shape so the fix cannot be another boolean.
  //
  // CLOSEOUT — driving-agent adjudication 2026-07-27: after round 9 the item
  // was CLOSED rather than extended. The storage core was validated in round 2
  // and survived every later round's independent reproduction; rounds 3-9 each
  // fixed real defects progressively further down the consumer graph. An
  // unbounded rejection scope against bounded per-round mandates cannot
  // converge. Accepted as scoped (cd2f9671..52061e40; last residual fixed
  // directly by the driving agent); remaining reproduced findings live in
  // WITNESS_INTEGRITY_LEDGER.md; the reviewer charter gained scope discipline
  // for all subsequent items. The W0-1 round-note blocks below are dead code
  // kept as the historical record of those adjudications.
  if (item.id === 'W0-1') {
    outcomes.push({ id: item.id, accepted: true, adjudicated: 'accepted 2026-07-27 at cd2f9671..52061e40; ledger: WITNESS_INTEGRITY_LEDGER.md' })
    log('W0-1: ACCEPTED by driving-agent adjudication (ledger: WITNESS_INTEGRITY_LEDGER.md)')
    continue
  }
  const cap = 3
  for (let round = 1; round <= cap && !accepted; round++) {
    report = await implementItem(item, feedback)
    if (!report) { log(`${item.id}: implementer returned nothing (round ${round})`); break }
    review = await reviewItem(item, report)
    if (!review) { log(`${item.id}: reviewer returned nothing (round ${round})`); break }
    accepted = review.accepted === true
    if (review.out_of_scope_findings?.length) {
      log(`${item.id}: ${review.out_of_scope_findings.length} out-of-scope finding(s) recorded for the ledger`)
    }
    if (!accepted) {
      feedback = (review.violations || [])
        .map((v) => `- [${v.rule}] ${v.detail}\n  reproduce: ${v.reproduction}`)
        .join('\n')
      // Adjudication (driving agent, 2026-07-26): appended ONLY to the feedback
      // that seeds W0-1 round 6, so rounds 2-5 prompts stay cache-identical.
      // Five rounds each fixed exactly what was cited and the reviewer found
      // the next consumer one hop away; the mandate below closes that class.
      if (item.id === 'W0-1' && round === 5) {
        feedback += `

ADJUDICATION NOTE from the driving agent — binding for this round:
After fixing the four cited violations, do NOT stop at the citations. Close the
whole consumer class in this same round:
1. Enumerate EVERY consumer of the surfaces this commit changed: every caller of
   storage_key_candidates / StorageClient.get / get_artifact / get_all_artifacts /
   get_source_files / hydrate_analysis / hydrate_tracking_plan /
   hydrate_predicate_trees, and every raise/catch site of StorageKeyAbsent /
   StorageKeyMissing / StorageContentNotDetermined / StorageUnavailable
   (grep, list them exhaustively in your report).
2. For EACH consumer, state whether it keeps proven-present / proven-absent /
   not-determined apart, with a one-line justification or a fix in this commit.
3. Same for component state in EntityActivity.jsx: enumerate every useState/
   useMemo that survives a selection change and state why each is safe or reset.
4. On R2 evidence: state the HONEST claim. StorageKeyAbsent has zero realised
   rows in the working DB today; that is a lower bound, and the class is
   reachable by construction (store_artifact with no data under an unconfigured
   backend). Say exactly that — "reachable by construction, test-covered, not
   yet realised on real rows" — and fix the false 21-cell docstring claim.
   Do NOT manufacture a firing claim.
Your report must present the enumerations so the reviewer can verify
completeness rather than sample for the next gap.`
      }
      if (item.id === 'W0-1' && round === 6) {
        feedback += `

ADJUDICATION NOTE from the driving agent — binding for this round:
Both violations are ONE root cause: mapping the not-determined state off a
single status code. Fix it as a class, not per-site:
1. The rule everywhere: only a proven negative (404 / a genuine empty answer)
   may render as absence. EVERY other non-answer — 500, 502, 504, a thrown
   error with no .status — must open the question (hedge marker / sawUnknown).
   Invert the predicates in dependencies.js and EntityActivity.jsx accordingly.
2. Never persist a conclusion derived from a non-answer: dependencies.js must
   not write null into its module cache when sawUnknown is true — leave the
   cache unset so a later healthy fetch can answer.
3. Sweep site/src for ANY other site that maps a hedge/unknown state off
   \`status === 503\` (or any single code) and apply the same rule; list the
   grep and every hit in your report.
4. Adopt the reviewer's two repro tests (inverted to pin the fix) and fix the
   false comment "An empty result is only 'confirmed' if no id left the
   question open" to match the now-true behaviour.`
      }
      if (item.id === 'W0-1' && round === 7) {
        feedback += `

ADJUDICATION NOTE from the driving agent — binding for this round:
The reviewer accepted everything except ONE R3 residual and prescribed both the
remedy and its scope. Do exactly this, nothing broader:
1. A scoped FOLLOW-UP commit (do not rework d981d378): when the upgrade history
   is not-determined (historyUnknown), the Timeline.jsx:93-99 "No activity
   before the line." branch must not emit its absence prose — suppress it or
   re-word it to the hedge. Thread the flag in however is cleanest (prop or
   gate at the call site).
2. While in Timeline.jsx, check its other empty-state prose branches for the
   same shape (an absence claim reachable when the input was unread) and state
   per branch why it is safe or fix it in the same commit.
3. Adopt the reviewer's repro (scratchpad w0_1_r3_prose_repro.test.jsx),
   inverted to pin the fix: 500 -> marker AND no bold absence prose; 404 ->
   prose, no marker; 200 -> history, neither.
4. Run the full vitest suite; report counts.
Do not touch the Python side; this round is frontend-only.`
      }
      if (item.id === 'W0-1' && round === 8) {
        feedback += `

ADJUDICATION NOTE from the driving agent — binding for this round:
The rejected round introduced a BOOLEAN evidence prop; R1 calls that a defect
by construction, and the reviewer proved the missing state (pending) renders as
proven absence. Fix the SHAPE, still confined to Timeline.jsx + EntityActivity.jsx:
1. Replace the boolean with an explicit state, e.g.
   historyState in 'pending' | 'not_determined' | 'absent' | 'present'
   (or equivalent). Initial state at mount and while any fetch is unsettled is
   'pending'. Only 'absent' (a resolved 404 / genuinely-empty answer) may render
   the absence prose; 'not_determined' renders the hedge marker; 'pending'
   asserts NOTHING (no absence prose, no marker or a neutral loading state —
   your choice, but no claim).
2. Pin with tests: the repo's own in-flight fixture (ActivityPanel.test.jsx:453,
   "job2 never resolves") must render NO bold absence prose; keep the existing
   404/200/non-answer pins. The reviewer's repro is kept at
   scratchpad/ReviewerRepro_inflight.test.jsx — adopt it inverted.
3. The reviewer flagged (not filed) a lesser instance: a 200 whose body is not
   an object collapses to h = null (EntityActivity.jsx:88) and renders the same
   prose. Route that to 'not_determined', or state precisely why it is
   unreachable from the handler.
4. Full vitest; report counts. Frontend-only, no rework of accepted commits.`
      }
      log(`${item.id}: rejected round ${round} — ${(review.violations || []).length} violation(s)`)
    }
  }

  outcomes.push({ id: item.id, accepted, review, report })
  log(`${item.id}: ${accepted ? 'ACCEPTED' : `ESCALATE — ${cap} rounds exhausted`}`)
  if (!accepted) {
    log(`HALTING: ${item.id} could not be accepted in ${cap} rounds. Per the handoff §10 the driving agent adjudicates the way forward.`)
    return { wave: 0, halted_at: item.id, outcomes, preflight }
  }
}

phase('Exit gate')

const gate = await runGate('Wave 0 is complete, so a determinism SKIP is now a FAILURE (see W0-8).')

// W0-7's fixtures are only worth anything if they DISCRIMINATE. A green corpus
// proves nothing unless a wrong implementation would have gone red.
const corpusProof = await agent(
  `${boilerplate}

Prove the Wave 0 corpus fixtures DISCRIMINATE. A zero-diff corpus result means
nothing unless the golden pins the field AND the corpus contains the shape AND a
WRONG implementation would differ.

For each fixture added in W0-7, demonstrate it fails against the pre-fix
behaviour: revert the relevant fix locally (or stub the code path), show the
fixture goes RED, then restore. Paste the red output for each.

Fixtures that must be shown to discriminate — **all TEN in handoff §4 W0-7**, not
just the first six. Read that subsection and enumerate them from it; do not work
from this list alone if it disagrees with the handoff. Fixtures 7-10 are
load-bearing GATES for later waves, and Wave 0 must not exit green without them:
  1. \`claims[].witness\` pinned in the golden
  2. constrained \`param\` destination (hash-commitment / mapping allowlist /
     storage equality) + the UNCONSTRAINED negative control
  3. \`delegatecall_execution\`: storage_setter target, and a caller-keyed
     mapping element (must resolve not_determined)
  4. \`exec.arbitrary\` with TWO address params where the NON-FIRST is the target
  5. a timed latch with a readable bound, and one genuinely indefinite
  6. a tree-absent public function of each of G3's classes F and R
  7. the dead \`backing\` branches
  8. **the R2 evidence for D3** — proves the reach branch actually fires
  9. **the gate the A8 commit must pass** (Leg C depends on it)
  10. **the gate for Leg E's tier fix**

Any fixture you cannot show going red is NOT a gate. Say so plainly rather than
asserting coverage. Leave the working tree clean when done.`,
  { label: 'corpus-discrimination', phase: 'Exit gate', model: 'opus', effort: 'high' }
)

phase('Milestone verify')

// Tier 3: strongest model, at the boundary, where a miss is caught by nothing
// downstream. TWO lenses, deliberately different — in the source investigation
// diversity of lens caught more than redundancy did.
const lenses = [
  {
    key: 'mainnet',
    brief: `LENS 1 — CORRECTNESS AGAINST MAINNET.
Re-derive Wave 0's central claims yourself from chain + verified source. Do not
trust the implementers' numbers. In particular:
  - D6: run the aggregate under 8 PYTHONHASHSEED values AND in 3 fresh processes
    at a fixed seed. Both must be byte-identical. These are DIFFERENT classes:
    Slither vars use object.__hash__ (identity), so no seed pins them.
  - W0-1: read one artifact successfully from each of the 5 affected storage
    columns (artifacts.storage_key, source_files.storage_key, and the three
    contract_materializations *_blob_key columns).
  - W0-4: confirm the provenance union binds \`receiver\` on
    Teller.refundDeposit's keccak commitment, AND that the \`computed\` operand
    does not drop out causing leaf reclassification. That caveat was flagged and
    never closed.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION.
Wave 0 is meant to be behaviour-preserving except where stated. Find where it was not.
  - Reconcile the real-corpus differential LINE BY LINE. Every ADDED / CHANGED /
    REMOVED row explained, or it is not explained.
  - Did any over-claim RELOCATE rather than get fixed? Structured fields often
    have a prose copy.
  - Did any declared control move?
  - Does any existing test now pin the wrong behaviour? Four are known; assume more.
  - COLLAPSED INPUTS: for each change, ask what the input discarded before the
    code saw it. Five of the largest defects in this codebase are that shape and
    NO GREP FINDS THEM.`,
  },
]

const verdicts = await parallel(
  lenses.map((l) => () =>
    agent(
      `${boilerplate}

You are a tier-3 MILESTONE VERIFIER for Wave 0. You are the strongest model in
this pipeline and you are the last gate before Waves 1-3 build on this work. A
miss here is caught by nobody.

${l.brief}

Context — tier-0 gate result:
${JSON.stringify(gate, null, 2)}

Context — corpus discrimination proof:
${corpusProof}

Read \`${HANDOFF}\` §4 (Wave 0 detail) and §11 (known-wrong hypotheses — do not
validate work built on a refuted premise).

YOUR JOB IS TO REFUTE. Refuting is a successful outcome; confirming without
reproducing is the only failure mode. Every verdict needs pasted command output.
Return verdict=FAIL if any Wave 0 exit criterion is unmet, and say which.

Finish with an explicit "what I did not check".`,
      { label: `verify:${l.key}`, phase: 'Milestone verify', model: 'fable', effort: 'high', schema: VERIFY_SCHEMA }
    )
  )
)

const clean = verdicts.filter(Boolean)
const allPass = gate?.passed === true && clean.length === lenses.length && clean.every((v) => v.verdict === 'PASS')

log(allPass
  ? 'WAVE 0 EXIT: PASS — Waves 1-3 are unblocked.'
  : 'WAVE 0 EXIT: FAIL — do NOT start Wave 1. See verdicts.')

return {
  wave: 0,
  exit_pass: allPass,
  gate,
  verdicts: clean,
  outcomes: outcomes.map((o) => ({ id: o.id, accepted: o.accepted, adjudicated: o.adjudicated, summary: o.review?.summary, out_of_scope_findings: o.review?.out_of_scope_findings || [] })),
  preflight,
  corpus_discrimination: corpusProof,
  next: allPass
    ? 'Write WAVE_0_REPORT.md, then AUTHOR wave1.workflow.js per handoff §12 (it does not exist yet), then run it (legs A, C, F in parallel).'
    : 'Escalate to the human with the failing verdicts. Do not proceed.',
}
