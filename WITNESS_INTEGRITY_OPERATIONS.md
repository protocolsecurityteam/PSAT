# Witness Integrity — Operating Rules (waves 0–4)

Operator-decided rules (2026-07-26/27) that bind every agent in this effort, at
every tier. They supplement `WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md`
(which remains the spec for *what* to build) and override it where they
conflict. Subagent prompts cite this file; read it before starting.

## 1. Authority and escalation

- **The human is not in the loop.** No agent asks the human anything, ever.
  Every judgment call escalates to the **driving agent** (the session
  orchestrator), which adjudicates: extend, re-scope, accept-with-ledger-entry,
  defer-with-stated-cause, or revert.
- The handoff's old "escalate to the human" list is void. Items on it are
  handled as: judgment calls → driving agent; **actions outside the cost
  boundary (§3) → simply not done**, recorded in the wave report / ledger with
  stated cause so the human can act later. The session never blocks.
- Authorisation is unchanged otherwise: commit freely to
  `fix/witness-integrity`; never `git push`, open a PR, merge, run the live
  suite, touch production/Neon, or edit `.env`/`CLAUDE.md`/settings.

## 2. Review loop and disputes

- **Cap: 3 impl→review rounds per item.** On exhaustion the wave halts and the
  driving agent adjudicates. (Raised from 2; unbounded loops converge on
  agreement, unbounded *rejection* converges on nothing.)
- **Reviewer scope discipline** (earned by W0-1's nine rounds): a violation is
  a rejection ground **only if it lies inside the item's declared scope** — the
  item's handoff subsection problem/fix surface plus same-commit consumers of
  fields the commit changed (R3). A real, reproduced defect found **outside**
  that scope — including pre-existing behaviour the commit strictly improves —
  is a *successful review outcome but not a rejection ground*: report it under
  `out_of_scope_findings` with a reproduction; the driving agent records it in
  `WITNESS_INTEGRITY_LEDGER.md`.
- **Trivial residuals at closeout** (a one-line guard, a missing test arm) may
  be fixed directly by the driving agent and noted as such — do not spawn
  another impl+review round for them. The operator explicitly objected to
  agent bloat on trivial fixes.
- Reviewers reproduce, never take on claim; refuting is success; every
  violation carries an exact reproduction command. Unchanged from the handoff.
- **Implementer prompts must carry the reviewer's lens up front** (added
  2026-07-28 after Leg C's 5 rounds; the round count came from checks that
  happened for the first time at review): (1) enumerate every consumer of
  every field you change and state per consumer how it keeps the three states
  apart — the reviewer verifies the enumeration, not samples for gaps; (2) for
  each new/changed evidence field, write the input-shape → published-state
  table and verify the two chronic failure routes — a not-determined input
  reaching a proven state, and the adverse branch never executing; (3) ask
  the collapsed-inputs question of your OWN new code; (4) implementers may
  look beyond their item list freely — report out-of-scope observations in
  the report (same channel as reviewers), never fix them silently.

## 3. Cost boundary — what verification may and may not do

**Never, under any framing:** start workers, uvicorn, or any pipeline stage;
spawn analysis jobs; run the live suite; deploy; regenerate or extend the
local DB's analyzed corpus; loop RPC/API calls over the contract population.
If proving a claim seems to require any of these, the claim is
**deferred-with-stated-cause** in the ledger — not executed, not asked about.

**The verification ladder — exhaust in this order:**
1. Local + free: offline suite (`./run_tests_fast.sh`), vitest, corpus
   fixtures, mutation-testing the diff (revert fix → expected tests go red),
   local Postgres queries, local MinIO reads.
2. In-process: FastAPI `TestClient` against the local DB (no server, no
   worker, nothing listening).
3. **Targeted, pinned, sparing** live reads via eRPC / Etherscan (creds in
   `.env`): the handoff's protocol — ≥3 reads plus a pinned read at block
   **25619159**, always with a discriminating control address. Single facts
   and bounded log ranges only; single-digit-to-tens of calls per fact is the
   norm (the largest legitimate use so far was 16 reads; a falsification took
   2). Read-only Grafana/Loki queries are likewise allowed.
4. Anything beyond → defer with stated cause.

Rationale: each push would trigger a preview deploy + ~27-min live suite on
real credits, and pipeline runs burn OpenRouter/Etherscan/eRPC quota at scale.
Zero pushes and zero pipeline runs ⇒ zero of that spend.

## 3b. Model floor

**No haiku agents** (operator decision 2026-07-28): the tier-0 gate runner is
**opus** (effort low) — the session's only structured-output contract failure
came from a haiku runner. Acceptable alternative: fold the gate run into the
merge/closing agent of the phase instead of a dedicated runner.

## 4. Bookkeeping

- `WITNESS_INTEGRITY_LEDGER.md` — out-of-scope reproduced defects, deferrals
  with stated cause, adjudication records. Append; never silently drop.
- `WAVE_<n>_REPORT.md` per wave: what landed, before/after numbers, controls,
  adjudications, harness changes (deliberate correction vs drift must be
  tellable), out-of-scope findings swept to the ledger, "what was not checked".
- Wave 4 = ledger closeout, sized after Wave 3. Admission test: **does the
  defect let a false claim reach a published surface or a scorer input?** If
  yes, fix; if it is schema hygiene on an unread column, it stays recorded.
