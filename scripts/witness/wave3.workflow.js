export const meta = {
  name: 'witness-wave3',
  description: 'Witness-integrity Wave 3: leg E (consumers), then D1 (candidate-set retarget) isolated — sequential',
  whenToUse: 'Run only after Wave 2 exited PASS (see WAVE_2_REPORT.md).',
  phases: [
    { title: 'Leg E', detail: 'consumers: impl -> review -> retry(<=3)' },
    { title: 'Merge E', detail: 'merge witness/leg-e into fix/witness-integrity' },
    { title: 'Leg D1', detail: 'selection.py retarget, isolated: impl -> review -> retry(<=3)' },
    { title: 'Merge D1', detail: 'merge witness/leg-d1' },
    { title: 'Exit gate', detail: 'tier-0 gate + differentials (E plane; D1 alone)' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const W24 = 'WITNESS_INTEGRITY_WAVES_2_4_HANDOFF.md'
const OPS = 'WITNESS_INTEGRITY_OPERATIONS.md'
const BRANCH = 'fix/witness-integrity'
const W3_BASE = '5e17bd81' // Wave 2 closeout HEAD; every leg must contain this commit
const WT_ROOT = '/tmp/claude-1000/-home-riley-PSAT/d8116573-440b-4ce0-8e02-ddab7ee5b902/scratchpad/wave3'
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
uvicorn/pipeline stages/live suite/analysis jobs, never regenerate the analyzed
corpus, never loop RPC over the population; verification ladder: offline suite
/ vitest / corpus / local Postgres+MinIO -> in-process FastAPI TestClient ->
SPARING pinned RPC (>=3 reads + pinned block 25619159 + a discriminating
control) -> defer-with-stated-cause). Then \`${HANDOFF}\` §0-§2 (governing
rule, traps, R1-R5 + review-lens charter), \`${W24}\` (Wave 3 section), and
WAVE_2_REPORT.md ("Carried into Wave 3+" and the method cautions).

AUTHORISED: commit to your leg branch. NOT AUTHORISED: git push, PR, merge to
${BRANCH} or main, live suite, production, editing .env/CLAUDE.md/settings.

Traps (§1): jsonb null vs SQL NULL (use jsonb_typeof); jsonb_array_elements
needs a case-guard; eRPC "latest" flakes (pin hex(head()-10); 25619159 for
historical); StorageKeyMissing is never evidence of absence. Handoff line
numbers may have drifted after Waves 0-2 landed; locate by content. The local
DB is one protocol/one chain: every count is a LOWER BOUND. The production DB
is stale and NEVER evidence. NEVER start a local dev server for the site —
validate frontend behaviour with vitest render tests (site/ npm test), not a
browser against a running app.

Wave-2 method cautions (binding): the effects cache plane is unmeasurable-by-
hit (all 150 rows carry analysis_schema_version=5 vs constant 31); effect_
transcripts hold no logs so reach/value verdicts are NOT re-derivable from
persisted evidence (L-49); the artifact-only build_claims(None, ...) recompute
is INVALID — full in-process replay only (substrate at ${REPLAY_SUB}).

IMPLEMENTER'S LENS, up front (OPS §2 — the reviewer verifies these, so do them
first): (1) enumerate EVERY consumer of every field you change and state per
consumer how it keeps proven-present / proven-absent / not-determined apart;
(2) for each new/changed evidence field, write the input-shape ->
published-state table and verify the two chronic failure routes; (3) ask the
collapsed-inputs question of your OWN new code; (4) report out-of-scope
observations freely in your report, never fix them silently.
`

function worktreeSetup(branch) {
  return `WORKTREE SETUP (do this first, exactly):
  cd /home/riley/PSAT
  git worktree remove --force ${WT_ROOT}/leg-${branch} 2>/dev/null; git branch -D witness/leg-${branch} 2>/dev/null
  git worktree add ${WT_ROOT}/leg-${branch} -b witness/leg-${branch} ${BRANCH}
  cp /home/riley/PSAT/.env ${WT_ROOT}/leg-${branch}/.env
  cd ${WT_ROOT}/leg-${branch}
  git merge-base --is-ancestor ${W3_BASE} HEAD && echo BASE_OK   # must print BASE_OK; if not, STOP and report
Work ONLY in this worktree, commit ONLY to witness/leg-${branch}. Docker
services are shared and already up. Offline tests: use the canonical serial
command from CLAUDE.md scoped to the test files you touch; run the FULL suite
only once before your final report. TEST-DB ISOLATION: create your own test DB
and use it for every pytest run:
  PGURL=$(echo "$TEST_DATABASE_URL" | sed 's|+psycopg2||; s|/psat_test.*|/postgres|')
  psql "$PGURL" -c "DROP DATABASE IF EXISTS psat_test_leg${branch};" -c "CREATE DATABASE psat_test_leg${branch};"
  export TEST_DATABASE_URL=$(echo "$TEST_DATABASE_URL" | sed "s|/psat_test|/psat_test_leg${branch}|")
Frontend: cd site && npm install --no-audit --no-fund (worktree has no
node_modules) && npm test.`
}

const LEG_E = {
  key: 'E',
  branch: 'e',
  title: 'consumers (site/, routers/, services/chat/, services/aggregations/)',
  model: 'opus',
  items: `
1. company_overview.py row-ABSENCE default (~:1258-1262): has_timelock/
   is_pausable/is_factory default to False when NO summary row exists — fires
   on absence, survived Leg A's producer fix, and now also swallows Leg A's
   new NULLs. Split absence/NULL from proven-false through the payload.
   Same commit (L-30): the NULL-folding consumers of the SAME values —
   company_overview.py ~:1252 (caps_set "pause") and ~:1276 (timelock band),
   site/src/surface/sidebar/activity/helpers.js:32,
   site/src/surface/layout/elkLayout.js:854 — a not-determined None must not
   fold to the proven-False outcome. L-31: elkLayout.js ~:857-865 prose is
   factually stale (has_timelock semantics inverted by Leg A) — fix the prose.
2. BalanceTable.jsx: usd_value NULL-vs-0 render identically as "—" (0 is falsy
   in JS); the dust filter keeps unpriced rows while hiding priced-worthless
   ones (:12-14). Plus the Wave-2 folds: L-45 — price_usd NULL now has TWO
   meanings ("unpriced" vs "no divisor reported"; usd_value encodes unpriced
   correctly — read THAT); truncation disclosure — the holdings fetch caps at
   100 with no marker (7 contracts at the cap, one $8.6B): the rendered view
   must be able to say "coverage of this contract's holdings is incomplete".
3. Chat tools: role_holders returns {"holders": []} for every real role
   because it filters function_principals.origin on a value that is a single
   constant on 1132/1132 rows — fix the query (Wave 2 added
   details.resolver_path; origin itself is unchanged by design).
   action_summary needs a summary_kind discriminator (130 vacuous / 528
   restating D1's conflation / 20 duplicating A3's narrowed over-claim) — no
   first-party UI renders it, but it ships on two public unauthenticated
   endpoints; R3: the A3 narrowing landed in Wave 1 and the prose copy is
   still quoting the old claim on those rows.
4. services/chat/data.py ~:72-74 (classify_address): add the chain predicate
   (chain is a parameter of the enclosing function and used on the next line)
   + a deterministic ORDER BY. Three real cross-chain twins exist (TopUp
   0x5bdd4b0d… ethereum+scroll both protocol_id=1). One where clause. Also
   L-20 (data.py ~:175): "last upgrade" uses DESC + nullslast, so a
   poll-detected (block NULL) upgrade — the actual latest — is reported as
   the OLDEST; fix the polarity (nullsfirst under DESC, or order by
   timestamp).
5. scoreClaimsView tier collapse (site/src/claimsVocab.js ~:418-436): only
   behavioral_observed is stripped; policy_derived (TIER_RANK 1, no
   single-contract evidence) scores identically to standard_exact (rank 3).
   TIER_RANK already exists — use it. claimsSummary (~:547-573) surfaces only
   the strongest tier, hiding policy provenance entirely. W0-7 fixture 10
   (the policy_derived golden row) is the gate.
6. terminal_principal consumer half (G7 §2.8): _build_principal_lookup
   (company_overview.py ~:962-1002) never joins PrincipalLabel, so
   claimsVocab.terminalControllerNote — the one consumer that handles all six
   statuses correctly — can never receive the data. WIRE IT (the producer
   split landed in Wave 2, commit 4363497c). 180 armed rows carry
   unknown_unfetched; their post-fix distribution is unmeasured (needs a
   policy run — cost boundary): state that honestly.
7. principal_labels.confidence carries no epistemic content (G6-8): a
   naming-branch label, two-valued in practice, ~97% a restatement of
   resolved_type; label is byte-identical to display_name on 1556/1556. Fix
   shape: narrow the assertion — rename to naming_rule (or drop it) with its
   consumers; do NOT invent a real confidence from nothing (that derivation
   needs on-chain verification wiring that is not this leg).
8. L-1 consumer half: upgrade-history 404 -> the SPA renders proven absence
   ("No activity before the line.") for BOTH "no proxies found" and "stage
   raised". Split at the endpoint (routers/analyses.py ~:287-288 — 404 only
   for proven-absent; not-determined gets a distinguishable answer) + SPA.
   TWO GREEN TESTS PIN THE DEFECT and must be inverted (R4, declare):
   ActivityPanel.test.jsx "keeps the absence prose for a 404" and "keeps the
   no-boundary empty state for a 404". Also look at the
   is_proxy=False-with-proxy_type='beacon' inconsistency (L-1 note): it
   changes which render path a real beacon proxy takes.
9. L-2: EntityActivity.jsx ~:58 catch { setEvents([]) } — a failed 30s poll
   replaces events a previous tick had proven present. Keep proven data on a
   failed refresh; distinguish "no events" from "poll failed".
10. L-19/L-26 era-side NULL folds: buildTimeline.js ~:25 implEras() folds
    unknown block_introduced to 0 (identical to the fold W0-9 removed
    server-side); auditMatching.js ~:51-55 folds block_introduced/
    block_replaced None to ±Infinity so a bounded audit spreads onto a
    poll-introduced era. Both must treat None as not-determined, not as a
    boundary value. L-21 (contract_audit_timeline.py ~:240 covered_to_block
    is None inference) — fix or record with cause.
11. L-47: a MEASURED $0 reach (reach_determined:true,
    observed_reach_value_usd:0.0) renders as silence in claimWitnessFacts
    (formatUsdUpperBound(0) falsy) — a measured zero must render as a measured
    zero, distinguishable from never-attempted.
12. L-3 note: artifacts_not_determined (analysis-detail payload) has zero
    consumers in site/ — wire a consumer or state why not. L-57: protocolScore
    treats undelegate's force-undelegate arm as plain public — fix if cheap
    within the scoring vocabulary, else record with cause.`,
  constraints: `LEG-E CONSTRAINTS: (a) CHAIN REQUIREMENT (handoff §3):
required — chat/data.py is the live instance; any query you touch that keys on
a bare address gains the chain predicate. (b) FRONTEND VERIFICATION: vitest
render tests only (npm test); NEVER claim what a page shows without reading the
render logic; do not start a dev server or backend (cost boundary; in-process
TestClient is the API ladder rung). If you edit styles.css, note that Playwright
visual baselines are NOT updatable in this environment — avoid CSS-cascade
changes; logic/markup only. (c) The producer planes are NOT yours: summaries,
policy, effects, monitoring writers are out of scope — consumer-side splits
only; if a fix truly requires a producer change, defer that half with stated
cause. (d) action_summary's two public endpoints are the R3 prose-copy surface
for A3's Wave-1 narrowing — do not leave the quotable copy contradicting the
structured claim on the 20 rows. (e) Corpus goldens: fixture-10
(policy_derived) is the scoreClaimsView gate; enumerate any golden diffs.`,
}

const LEG_D1 = {
  key: 'D1',
  branch: 'd1',
  title: 'selection.py candidate-set retarget — ISOLATED',
  model: 'opus',
  items: `
THE ONE CHANGE: retarget services/effects/selection.py ~:691 (the candidate
filter that currently reads effect_targets / external-call targets) onto
W0-6's persisted state-write evidence (state_changing / state_writes / sinks /
writer_selectors — all nullable, none_as_null, persisted since Wave 0). The
docstring (~:656-657) claims "the sink is the state-write target list", which
is false today: 501 of 1642 populated rows carry zero state-write evidence,
and 156 protocol-1 gated functions enter the fork cascade on external-call
targets alone. This DELIBERATELY changes the candidate set, therefore verdicts
and claims downstream — that is the point, and it is why this leg is isolated
and measured alone.

Binding details:
- THREE-STATE discipline on the new filter (R1): state_writes NULL means
  not-determined (the withheld view-contradiction rows, L-15: 14 records had
  89 external_call sinks nulled — state the recall consequence for them),
  which must NOT silently equal proven-no-writes ([]). Decide and document
  what each state does to candidacy, with the input-shape -> candidacy table.
- L-14 (ledger): writer_selectors carries fabricated selectors on 15
  fallback/receive records (keccak("fallback")[:4] etc.) — if your filter
  consumes writer_selectors, handle the fabricated-selector rows (Wave 1 Leg A
  moved class-R to the empty-string sentinel in NEW artifacts; persisted rows
  keep the old shape).
- R5: bump EFFECT_CACHE_SCHEMA_VERSION (32) — the candidate set changes what
  gets probed, which changes the witnesses a cached row would serve. State the
  reason in the version comment.
- Restate SCORING_INVARIANTS.md:268-272 in the same commit: its "260/756"
  figure measures exactly the conflation you are removing.
- MEASURE THE CANDIDATE-SET DELTA in-process over the local DB
  (select_candidates / the cascade entry, no probes, no anvil): report
  functions entering / leaving / unchanged, with per-row cause (gained
  state-write evidence vs external-call-only vs NULL-evidence), and pin the
  156 external-call-only population's fate explicitly.
- NOTHING ELSE in this leg: no drive-by fixes, no refactors — any other defect
  you see goes in your report as an out-of-scope observation. The wave's
  attribution story depends on this differential having exactly one cause.`,
  constraints: `LEG-D1 CONSTRAINTS: (a) ISOLATION IS THE CONTRACT: the diff
touches selection.py, its tests, the SCORING_INVARIANTS restatement, and the
R5 bump — nothing else. (b) No fork probes, no pipeline stages (cost
boundary): the candidate-set measurement is an in-process selection run over
the local DB. (c) The Wave-2 leg D changes (per-asset holdings, L-4 ordering)
are upstream of your surface in the same file — do not re-litigate them; your
change composes with them. (d) Positive control: a function with real
persisted state-write evidence and a current candidate slot must remain a
candidate. Negative control: a view-only function must remain excluded. State
both before coding with row ids.`,
}

async function runLeg(leg) {
  let feedback = null
  let accepted = false
  let report = null
  let review = null
  const phaseTitle = `Leg ${leg.key}`
  for (let round = 1; round <= 3 && !accepted; round++) {
    const retryNote = feedback
      ? `\n\nThis is a RETRY (round ${round}). A reviewer rejected the previous attempt. Fix exactly these in the SAME worktree/branch (do not recreate it; amend or add commits), do not re-litigate:\n${feedback}`
      : ''
    report = await agent(
      `${boilerplate}

You are the tier-1 implementer for **Wave 3 Leg ${leg.key} — ${leg.title}**.

${worktreeSetup(leg.branch)}

Read \`${HANDOFF}\` §7 IN FULL plus \`${W24}\` "WAVE 3" and the ledger entries
named below — they carry the measured evidence and exact fix shapes. Your
items:
${leg.items}

${leg.constraints}

BEFORE writing code, state: (1) POSITIVE control (row/render that must stay
flagged), (2) NEGATIVE control (row/render that must stay clean), (3) measured
"before" numbers. R1-R5 are binding. R2: any sentinel/fail-closed branch needs
a firing proof against real data (or the honest zero-realised-rows lower-bound
statement). Expect to delete/invert tests that pin defects; declare each in
the commit message.

One commit per coherent item. Report: per-item what changed, before/after
numbers, controls status, sentinel proofs, consumer enumeration for every
changed field, and an explicit "what I did not check".${retryNote}`,
      { label: `impl:leg-${leg.branch}`, phase: phaseTitle, model: leg.model, effort: 'high' }
    )
    if (!report) { log(`Leg ${leg.key}: implementer returned nothing (round ${round})`); continue }
    review = await agent(
      `${boilerplate}

You are the tier-2 reviewer for **Wave 3 Leg ${leg.key} — ${leg.title}**.
Review ALL commits on branch witness/leg-${leg.branch} (worktree
${WT_ROOT}/leg-${leg.branch}; it has .env copied in; use the leg's own test DB
psat_test_leg${leg.branch} via the TEST_DATABASE_URL override from the
implementer's setup). Compare against ${BRANCH} (merge-base ${W3_BASE}).

Adversarial in miniature, not a checklist. The judgment-bearing pair:
  R1  three representable states on every new/changed evidence field,
      distinguishable by a consumer.
  R4  positive-case tests, not only hedges; the two named ActivityPanel tests
      (Leg E) pin the defect and must be inverted, with positive siblings.
Also: R2 (run every firing query yourself), R3 (consumers + PROSE copies in
the same commit), R5 (EFFECT_CACHE_SCHEMA_VERSION is 31 at base — Leg D1 must
bump it; Leg E must justify if it does not), both declared controls, the
implementer's consumer enumeration VERIFIED (not sampled), and the leg's
stated constraints held.${leg.key === 'D1' ? `
D1-SPECIFIC: verify the ISOLATION contract (diff touches only selection.py +
tests + SCORING_INVARIANTS + the R5 bump) and re-derive the candidate-set
delta yourself in-process — entering/leaving counts with per-row cause; the
156 external-call-only population's fate must be pinned by a test.` : ''}

SCOPE DISCIPLINE (binding, ${OPS} §2): a violation may reject ONLY if it lies
inside this leg's declared scope — the handoff §7 Leg ${leg.key} surface plus
same-commit consumers of fields the leg changed. Real defects outside that
scope go under out_of_scope_findings with a reproduction — never rejection
grounds.

The implementer reported:
${report}

Refuting is a successful outcome. Accepting something you did not reproduce is
the only failure mode. Every violation needs an exact reproduction command.`,
      { label: `review:leg-${leg.branch}`, phase: phaseTitle, model: 'opus', effort: 'high', schema: REVIEW_SCHEMA }
    )
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

function mergePrompt(branch, extra) {
  return `${boilerplate}

You are the MERGE agent. Mechanical job, no redesign.

In /home/riley/PSAT (the main checkout, branch ${BRANCH}):
  1. Confirm ${BRANCH} is checked out and clean (untracked docs are fine).
  2. git merge --no-ff witness/leg-${branch}.
  3. Conflicts in CODE: trivial -> resolve minimally and say exactly what you
     did; substantive -> STOP and report, do not guess.
  4. Conflicts in corpus GOLDENS: regenerate via the repo's regeneration path,
     verify the diff equals what the leg declared; mismatch -> STOP and report.
  5. Reset the shared test DB (drop+recreate psat_test), run ./run_tests_fast.sh
     once and cd site && npm test. Report counts.
  6. Remove the worktree ${WT_ROOT}/leg-${branch} (git worktree remove --force);
     KEEP the branch.
${extra}
Report: merge commit, conflicts + resolutions, suite counts.`
}

phase('Leg E')
log('Wave 3 — sequential: leg E (consumers), then D1 isolated')
const eResult = await runLeg(LEG_E)
if (!eResult.accepted) {
  log('HALT: Leg E not accepted — driving agent adjudicates before anything else runs.')
  return { wave: 3, halted_at: 'leg-e', eResult }
}

phase('Merge E')
const mergeE = await agent(mergePrompt('e', ''), { label: 'merge-leg-e', phase: 'Merge E', model: 'opus', effort: 'medium' })

phase('Leg D1')
const d1Result = await runLeg(LEG_D1)
if (!d1Result.accepted) {
  log('HALT: Leg D1 not accepted — driving agent adjudicates. Leg E is already merged.')
  return { wave: 3, halted_at: 'leg-d1', eResult, mergeE, d1Result }
}

phase('Merge D1')
const mergeD1 = await agent(
  mergePrompt('d1', `  7. Record (git rev-parse) the pre-merge and post-merge HEAD SHAs in your
     report — the D1 differential needs the exact pre-D1 baseline.`),
  { label: 'merge-leg-d1', phase: 'Merge D1', model: 'opus', effort: 'medium' }
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
Return passed=true only if the script prints "GATE: PASS". List every FAIL
line in failures. Put the full summary block in raw.`,
  { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
)

const differential = await agent(
  `${boilerplate}

Produce the Wave 3 DIFFERENTIAL on ${BRANCH} (post-merge HEAD) vs ${W3_BASE}
(Wave 2 closeout), in TWO SEPARATE sections whose attribution must not mix.
Local recompute over existing DB artifacts + in-process TestClient only — no
pipeline, no workers, no fork probes, no dev server.

Merge reports (contain the pre-D1 baseline SHA you need):
=== E merge ===
${mergeE}
=== D1 merge ===
${mergeD1}

SECTION 1 — LEG E (consumer plane), measured base ${W3_BASE} -> the pre-D1
baseline SHA:
  - company_overview payload projection over the 92 protocol-1 contracts via
    in-process aggregation calls: has_timelock/is_pausable/is_factory
    absence-vs-NULL-vs-false transitions; caps_set/band folds on None inputs.
  - chat classify_address: the chain predicate + ordering on the 3 real twins
    (TopUp 0x5bdd4b0d… etc.); "last upgrade" polarity on a NULL-block fixture.
  - scoreClaimsView / claimsSummary on W0-7 fixture 10 (policy_derived must
    score below standard_exact and surface its provenance); vitest counts.
  - role_holders on the real role rows (was {"holders": []} for every role).
  - the ActivityPanel/EntityActivity/buildTimeline/auditMatching render
    states: enumerate the new render outcomes per input shape (404 vs
    not-determined vs absent; failed poll; NULL block eras).
  - BalanceTable: NULL-vs-0 vs truncation disclosure render outcomes.
  - terminal_principal: the lookup now joins PrincipalLabel — project the
    payload for the 180 armed unknown_unfetched rows and confirm
    terminalControllerNote receives data (render-level, vitest).
SECTION 2 — LEG D1 ALONE, measured pre-D1 baseline -> post-D1 HEAD:
  - THE CANDIDATE-SET DELTA, re-derived in-process (no probes): functions
    entering / leaving / unchanged with per-row cause buckets (state-write
    evidence present / external-call-only / NULL evidence withheld); the 156
    external-call-only population's fate; the L-15 14-record withheld set's
    fate; positive and negative controls held.
  - CONFIRM NOTHING ELSE MOVED: the only non-test diff in this range is
    selection.py + SCORING_INVARIANTS.md + the effect_cache version bump; any
    other changed published value is a FINDING to flag loudly.
Bucket any L-25-class noise separately (should be 0 — these planes do not
read the flickering field). Every non-noise row must be attributable to a
named leg commit. Output the full tabulation; flag anything unexplained
LOUDLY.`,
  { label: 'wave3-differential', phase: 'Exit gate', model: 'opus', effort: 'high' }
)

phase('Milestone verify')

const lenses = [
  {
    key: 'mainnet',
    brief: `LENS 1 — CORRECTNESS AGAINST DATA + SOURCE. Re-derive the central
claims yourself. (a) L-1 consumer: the beacon-proxy falsification row
(0x3c55986c…, 14 Upgraded logs at or before 25619159) — confirm the endpoint +
SPA now answer not-determined (not proven-absent) for the raised-stage case,
and that a genuinely proxy-less contract still renders the absence prose
(negative control). (b) chat chain predicate: the TopUp twin must resolve to
the chain asked about; a single-chain address must be unaffected (control).
(c) scoreClaimsView on fixture 10: policy_derived scored at its rank, not
standard_exact's; a standard_exact-only function unchanged (control). (d) D1:
spot-check 3 functions that LEFT the candidate set (must have zero
state-write evidence in their persisted effects artifact, verified by reading
the artifact) and 3 that STAYED (real state-writes) — from the stored
artifacts, not the leg's tables. (e) terminal_principal: the armed
unknown_unfetched rows reach the renderer; no invented status appears.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION. (a) Reconcile BOTH differential
sections line by line; Section 2's isolation contract is the wave's attribution
story — any non-D1 change inside the D1 range is a FAIL-grade finding. (b)
Prose copies: action_summary on the 20 A3-narrowed rows (public endpoints);
elkLayout's stale has_timelock prose; any new render prose that overstates.
(c) Did any declared control move (sweepDust, bitmap-24 inertness, PlainLatch
proven state, the D1 positive/negative candidacy controls)? (d) R4: the two
ActivityPanel defect-pinning tests inverted with positive siblings; no other
test now pins wrong behaviour. (e) Collapsed inputs on the NEW code: the
candidacy filter's three-state table (NULL vs [] vs populated), the
principal-label join, the 404 split. (f) R5: D1 bumped the cache version with
a stated reason; Leg E justified not bumping. (g) Wave-2 carried items: L-45/
L-47/L-57 addressed or explicitly re-deferred with cause.`,
  },
]

const verdicts = await parallel(
  lenses.map((l) => () =>
    agent(
      `${boilerplate}

You are a tier-3 MILESTONE VERIFIER for Wave 3 — the last gate before Wave 4
closes the ledger on this work. A miss here is caught by nobody.

${l.brief}

Tier-0 gate result:
${JSON.stringify(gate, null, 2)}

Merge reports:
=== E ===
${mergeE}
=== D1 ===
${mergeD1}

Differential:
${differential}

Read ${HANDOFF} §7 and §11 (known-wrong hypotheses), plus ${W24} "WAVE 3".
YOUR JOB IS TO REFUTE. Every verdict needs pasted command output. Return
verdict=FAIL if any wave-exit criterion (§10) is unmet, and say which. Finish
with "what I did not check".`,
      { label: `verify:${l.key}`, phase: 'Milestone verify', model: 'fable', effort: 'high', schema: VERIFY_SCHEMA }
    )
  )
)

const cleanVerdicts = verdicts.filter(Boolean)
const allPass = gate?.passed === true && cleanVerdicts.length === lenses.length && cleanVerdicts.every((v) => v.verdict === 'PASS')

log(allPass ? 'WAVE 3 EXIT: PASS' : 'WAVE 3 EXIT: FAIL — driving agent adjudicates')

return {
  wave: 3,
  exit_pass: allPass,
  gate,
  mergeE,
  mergeD1,
  differential,
  verdicts: cleanVerdicts,
  legs: [eResult, d1Result].map((r) => ({
    leg: r.leg,
    accepted: r.accepted,
    summary: r.review?.summary,
    out_of_scope_findings: r.review?.out_of_scope_findings || [],
  })),
}
