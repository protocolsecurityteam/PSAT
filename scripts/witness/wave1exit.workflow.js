export const meta = {
  name: 'witness-wave1-exit',
  description: 'Wave 1 exit only: tier-0 gate, real-corpus differential, two Fable verdicts (legs + merge already on the branch)',
  whenToUse: 'Run after Wave 1 legs are merged and adjudicated; replaces the aborted tail of wave1.workflow.js.',
  phases: [
    { title: 'Exit gate', detail: 'tier-0 gate + real-corpus differential' },
    { title: 'Milestone verify', detail: '2 Fable verifiers, different lenses', model: 'fable' },
  ],
}

// Why this script exists: the original wave1 run aborted at the gate agent
// (structured-output failure); on resume the parallel-leg call cache did not
// replay cleanly and leg reviews started re-running against removed worktrees.
// Legs and merge are DONE and committed on fix/witness-integrity — this script
// runs only the remaining exit steps, with the merge context embedded, so
// nothing upstream can re-execute.

const HANDOFF = 'WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md'
const OPS = 'WITNESS_INTEGRITY_OPERATIONS.md'
const BRANCH = 'fix/witness-integrity'
const W1_BASE = 'a7c82e46' // Wave 0 exit HEAD

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
escalation; cost boundary: never start workers/pipeline/live suite; SPARING
pinned RPC reads only). Then \`${HANDOFF}\` §0-§2 and WAVE_0_REPORT.md.

AUTHORISED: read everything, run local suites/queries. NOT AUTHORISED: git
push, PR, merging, live suite, production, editing .env/CLAUDE.md/settings.
Commit nothing unless your prompt explicitly says otherwise.

Traps: jsonb null vs SQL NULL (jsonb_typeof); eRPC "latest" flakes (pin
hex(head()-10); 25619159 historical); on-chain facts need >=3 reads + a pinned
read at 25619159 with a discriminating control address.
`

const MERGE_CONTEXT = `
WAVE 1 STATE (already on the branch — do not redo):
- Legs A (static/summaries), C (claims/matchers), F (control graph) implemented
  on witness/leg-{a,c,f}, each accepted by tier-2 review (C after 5 rounds; its
  final round made claim transparency earned-by-router-op and kept the hazard
  tint on absent target_constraint).
- Merge commits on ${BRANCH}: 03331187 (A, clean), 9b961319 (C, 2 trivial code
  conflicts resolved), 41556ad4 (F, 1 resolved). EFFECT_CACHE_SCHEMA_VERSION
  renumbered ordinally to v19 (C) / v20 (A) / v21 (F), no argument text changed.
- Driving-agent adjudication commit 2586fdc3 resolved the merge agent's two
  halts: (1) accepted the REGENERATED corpus golden over the textual union —
  the one delta row, DelegatecallRoutes.fallback(), is Leg A's class-R rule
  applied to the fixture Leg C introduced (a cross product a diff union cannot
  express); (2) reworked Leg F's withholding test after class R falsified its
  precondition — receive() now lowers and its liquidityPool earns caller_gate
  (pinned as an improvement), while the withholding sentinel is proven via a
  constructed lowering failure (tree removed from the artifact, the shape a
  degraded tree stage persists); the stale 427/1,200 pre-class-R measurement is
  annotated in the v21 cache entry, not re-claimed.
- Worktrees removed; witness/leg-* branches kept. Merge-time suite (with the
  regenerated golden): 5261 passed / 1 failed — the one failure being the
  Leg A x Leg F conflict that 2586fdc3 then fixed.
`

phase('Exit gate')

const gate = await agent(
  `Run the tier-0 mechanical gate and report results verbatim. You make NO
judgments — execute and report.

  cd /home/riley/PSAT && bash scripts/witness/gate.sh --base main --require-determinism

Return passed=true only if the script prints "GATE: PASS". List every FAIL line
in failures. Put the full summary block in raw.`,
  { label: 'tier0-gate', phase: 'Exit gate', model: 'opus', effort: 'low', schema: GATE_SCHEMA }
)

const differential = await agent(
  `${boilerplate}
${MERGE_CONTEXT}

Produce the Wave 1 REAL-CORPUS DIFFERENTIAL on ${BRANCH} (current HEAD) vs
${W1_BASE} (Wave 0 exit). Local recompute over existing DB artifacts only — no
pipeline, no workers.

For the planes Wave 1 touched:
  - claims plane (Leg C): recompute claims for the protocol-1 functions whose
    matchers changed; tabulate ADDED / CHANGED / REMOVED claims + witness
    fields vs the DB rows, with counts against the measured expectations
    (9/20 exec.arbitrary narrowed, 20/93 param constrained, rebalance FP
    removed, 2 delegatecall.execute rows minted).
  - summaries plane (Leg A): recompute contract summaries for the 92 protocol-1
    contracts (the leg's replay substrate under the scratchpad may help);
    tabulate has_timelock/is_pausable/is_factory/standards/risk_level
    transitions, and confirm the 24 bitmap-pause functions are UNTOUCHED
    (status NULL, authority_public False, labels [], nclaims 0).
  - control graph (Leg F): rebuild the graph for protocol 1; report the mutual
    directed edge count (was 66), nodes whose resolved_type changed, and
    principal_labels-plane changes per the leg's G6-9 decision.
KNOWN NOISE TO EXCLUDE (WAVE_0_REPORT.md): the callee_args_digest operand-slot
flicker (L-25) — operand-slot-only diffs with kind/operator/role unchanged go
in a separate 'L-25 noise' bucket, not CHANGED. Every non-noise row must be
attributable to a named leg commit. Output the full tabulation; flag anything
unexplained LOUDLY.`,
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
must carry its classifier type; re-run the mutual-edge count yourself; (d) the
2586fdc3 adjudication: confirm the regenerated golden row for
DelegatecallRoutes.fallback() matches what the merged code actually produces.`,
  },
  {
    key: 'collateral',
    brief: `LENS 2 — COLLATERAL AND RELOCATION. (a) Reconcile the real-corpus
differential LINE BY LINE — every non-noise ADDED/CHANGED/REMOVED row
attributed to a leg commit, or it is not explained; verify the L-25 noise
bucket really is operand-slot-only. (b) Did any over-claim RELOCATE into prose
(action_summary restates exec.arbitrary on 20 rows — did Leg C's narrowing
reach it, or is that correctly deferred to Wave 3 and stated?); (c) did any
declared control move; (d) does any existing test now pin wrong behaviour —
including the 2586fdc3 rework: does the constructed-lowering-failure test
actually exercise the withholding branch, and does anything still assert the
pre-class-R absence?; (e) for each leg, what did the input DISCARD before the
code saw it; (f) the A7-before-is_pausable constraint: confirm the bitmap-24
are inert at HEAD.`,
  },
]

const verdicts = await parallel(
  lenses.map((l) => () =>
    agent(
      `${boilerplate}
${MERGE_CONTEXT}

You are a tier-3 MILESTONE VERIFIER for Wave 1 — the last gate before Wave 2
builds on this work. A miss here is caught by nobody.

${l.brief}

Tier-0 gate result:
${JSON.stringify(gate, null, 2)}

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

const clean = verdicts.filter(Boolean)
const allPass = gate?.passed === true && clean.length === lenses.length && clean.every((v) => v.verdict === 'PASS')

log(allPass ? 'WAVE 1 EXIT: PASS' : 'WAVE 1 EXIT: FAIL — driving agent adjudicates')

return { wave: 1, exit_pass: allPass, gate, differential, verdicts: clean }
