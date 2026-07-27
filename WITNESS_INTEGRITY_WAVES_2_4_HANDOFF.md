# Witness Integrity — Waves 2–4 Handoff

**You are the driving agent for Waves 2–4.** Waves 0 and 1 are COMPLETE on
branch `fix/witness-integrity` (off main `db9f76b6`). Your job: Wave 2 (legs B
and D), Wave 3 (leg E, then D1 isolated), Wave 4 (ledger closeout), each with
a wave report — then stop and summarize for the operator.

## Read in this order, before anything else
1. `WITNESS_INTEGRITY_OPERATIONS.md` — **binding rules**: authority, disputes,
   cost boundary, model floor, bookkeeping. Every subagent prompt cites it.
2. `WAVE_0_REPORT.md` and `WAVE_1_REPORT.md` — what landed, constraints carried
   forward, measurement-method warnings.
3. `WITNESS_INTEGRITY_IMPLEMENTATION_HANDOFF.md` §6–§7 — the Wave 2/3 item
   specs (measured evidence + exact fix shapes). §2 (rules R1–R5), §11
   (known-wrong hypotheses — do not implement against a refuted premise).
4. `WITNESS_INTEGRITY_LEDGER.md` (L-1…L-44) — every out-of-scope reproduced
   finding, with owners. Several are folded into your wave scopes below.

## The operator's standing rules (all already encoded in OPERATIONS.md — this
is the short form)
- **Zero human interaction.** Never ask the operator anything. Judgment calls
  are yours; out-of-boundary actions are *not done* and recorded.
- **Never**: `git push`, PR, merge to main, live suite, start workers/uvicorn/
  any pipeline stage, spawn analysis jobs, regenerate the analyzed corpus,
  population-scale RPC loops, touch prod/Neon, edit `.env`/`CLAUDE.md`/settings.
- **Verification ladder**: local suites/corpus/mutation tests → local Postgres
  (port 5433) / MinIO → in-process FastAPI TestClient → SPARING pinned RPC/
  Etherscan reads (≥3 reads + pinned block 25619159 + a discriminating control
  address; single facts, never scans) → defer-with-stated-cause in the ledger.
- **Review loop**: cap 3 rounds; reviewer scope discipline (reject only inside
  the item's declared scope; real out-of-scope defects → `out_of_scope_findings`
  → ledger); on cap exhaustion YOU adjudicate (targeted extra round with a
  binding prescription / accept + ledger / revert). Trivial residuals (a
  one-line guard, a test arm) you fix directly — never spawn a round for them.
- **Implementer prompts carry the reviewer's lens up front** (OPERATIONS §2:
  consumer enumeration, input→published-state table, collapsed-inputs question
  inward, free observation + report channel).
- **No haiku agents.** Tier-0 gate runner is opus/effort-low, or fold the gate
  run into the merge agent.
- **Model tiers** (handoff §8): opus implementers/reviewers; **fable for
  W2-B's implementer** (351-function reroute — highest-risk leg) and both
  tier-3 milestone verifiers (two genuinely different lenses).

## Workflow mechanics
- One Workflow script per wave; author `wave2.workflow.js` etc. following
  `scripts/witness/wave1.workflow.js` (parallel legs in explicit worktree
  branches `witness/leg-*`, `.env` copied in, merge-base verified, cap-3
  reviews, merge agent that HALTS on substantive conflicts, gate + real-corpus
  differential + 2 Fable verdicts). Scripts cannot use Date.now/Math.random.
- **Resume trap**: if a run with a PARALLEL phase aborts mid-stream, do NOT
  `resumeFromRunId` — cache replays a call *prefix* and parallel interleaving
  diverges (Wave 1 re-ran leg reviews against removed worktrees). Harvest
  completed results from the run's `journal.jsonl` and write an **exit-only
  script** embedding them (`scripts/witness/wave1exit.workflow.js` is the
  template).
- Adjudication economics: when tier-3 verdicts FAIL solely on a mechanically
  re-provable criterion, fix it, re-run `bash scripts/witness/gate.sh --base
  main --require-determinism` yourself, and document — do not re-run Fable
  verifiers over a one-line fix.
- Sweep every `out_of_scope_findings` array and verifier finding into the
  ledger at each wave boundary; write `WAVE_<n>_REPORT.md`; commit docs.

## Measurement-method warnings (both burned a wave-1 agent)
- **The artifact-only claims recompute is INVALID**: `build_claims(None,
  effects, trees)` silently drops idiom-tier claims (20→6). Use the full
  in-process replay: scaffold a project dir from `source_files` in local
  Postgres, run `collect_contract_analysis_with_artifacts()`, PYTHONHASHSEED
  pinned. Wave 1's replay covers 88/92 contracts (4 have no stored sources:
  cid 79, 639, 640, 641). The wave-1 substrate lived in a session scratchpad
  and may be gone — rebuild it from this description if needed.
- **L-25 noise bucket**: `callee_args_digest` operand-slot flicker (37–46
  slots, 25/88 units) must be bucketed separately in every differential, never
  counted as CHANGED.
- The local DB is one protocol / one chain; every count is a **lower bound**.
  The production DB is stale and is never evidence (handoff §2).
- Leg-A-style replay is also how you measure summaries-plane changes; a
  re-persisted control-graph rebuild needs the resolution stage → cost
  boundary → project the new writers over persisted inputs instead.

---

## WAVE 2 — legs B and D in parallel worktrees

Spec: handoff §6, both "Added by G6/G7" blocks included. Chain requirements:
Leg B **required** (GAP 2 `enumerable_role_store.py:405-414` bare-address
resolution ships in the same commit as the empty-intersection fix); Leg D
inherits (do not drop `chain_id`; `effect_behavior_cache` has no chain
predicate BY DESIGN — G6-C1 is where it bites).

**Leg B (capability/authority) — fable implementer.** §6 items plus:
- **FOLDED IN (L-42-class, HIGH — from Wave 1)**: Leg A's class-F/R tree
  widening mints 37 new controller-tracking targets with `authority_provenance`
  ABSENT (28 survive the primitive-scalar skip, incl. pure constants and
  non-authority mappings like `_balances`). On the next resolution run they
  persist as `controller_value` control edges — an over-claim surface created
  by the Wave 1 merge. Decide the correct gate (provenance-absent targets must
  not mint control edges / must carry not-determined) and implement it where
  the resolution stage reads the plan.
- Remember A1's binding scope: no fix scoped/tested/accepted against "blast
  radius 2"; G3 measures ≥5 via classes F and R over 351 unwitnessed publics —
  and Leg A's class F/R work has since ADDED trees, so re-measure the
  tree-absent population before wiring `guard_extraction_uncertain` (R2: prove
  the sentinel fires on the merged corpus).
- Ledger items in this surface worth reading first: L-9 (deferred reconciler
  join drops its own rows), L-27-class (`_selector_key` ""/NULL collision on
  fallback+receive — Leg A review), StrategyManager internal-modifier gate
  omission (Leg C final review; false `unconstrained_proven` on real rows —
  the producer is predicate-tree lowering of internal-callee modifiers, which
  sits at the boundary of this leg's tree-absent work; if you fix it here,
  declare the scope; if not, it stays ledgered with cause).

**Leg D (effects/witness) — opus implementer.** §6 items plus:
- **A7 is rank 1** and ships as ONE vertical slice (backend + BOTH prose
  copies + inverted tests, R3/R4). Note L-16: `_duration_from_trees`'s
  positive branch is unreachable from compiled source — the leaf must be
  widened for any latch fixture to reach the positive branch; W0-7's
  timed-latch fixture only becomes a full gate after that widening (its
  in-fixture docstring says so).
- **FOLDED IN (L-4)**: `_principals_by_function` has no ORDER BY and its first
  element is the probe's caller identity (calldata.py:1377/1419/1702/2224) —
  a third determinism class (query-plan order). Add the deterministic order +
  test. R5 applies.
- A2 per-asset holdings: the owed check (synthetic ETH log emitter against a
  real `eth_simulateV1` response) is a SPARING live read — do it before coding.
  The reach ≤ TVL gate reads `defillama_tvl` (never `total_usd`); state loudly
  what happens when it is absent.
- Cache items: proxy-hash refusal (G6-C0), mutate-on-read split (G6-C6),
  self-audit floor (zero-key signatures must not pass), `concrete_destination`
  → NULL on `caller_arbitrary` + `NEUTRAL_CALLER` exclusion.

Wave 2 exit: same shape as Wave 1 (gate + full-replay differential with L-25
bucket + 2 Fable lenses; differential must attribute every non-noise row).

## WAVE 3 — sequential: leg E, then D1 isolated

Spec: handoff §7 plus these folds from the ledger:
- `company_overview.py:1258-1262` row-ABSENCE default (survives Leg A's fix;
  Leg A confirmed it now also swallows the new NULLs — same defect, wider).
- L-1 consumer half (upgrade-history 404 → `absent` vs `not_determined` at the
  endpoint + SPA; **two green tests pin the defect and must be inverted**);
  L-2 (`setEvents([])` clobber); L-3 notes; L-19-class (buildTimeline NULL→0
  fold; chat `last upgrade` DESC+nullslast bug; `covered_to_block is None`
  inference; coverage timestamp-None collapse — all from the W0-9 review
  sweep, all consumer-plane).
- `services/chat/data.py:72-74` chain predicate + deterministic order;
  `scoreClaimsView` tier collapse (W0-7 fixture 10 is the gate);
  `terminal_principal` wiring decision; `principal_labels.confidence` renaming;
  `BalanceTable` NULL-vs-0 + truncation disclosure.
- **D1 last, isolated, measured alone** (retarget selection.py:691 onto W0-6's
  persisted state-write list; the candidate-set change must be the only thing
  in its differential). R5 applies. Restate `SCORING_INVARIANTS.md:268-272`.

## WAVE 4 — ledger closeout

Admission test (operator-set): **does the defect let a false claim reach a
published surface or a scorer input?** Fix those; schema hygiene on unread
columns stays recorded with cause. Work the ledger (L-1…L-44 plus whatever
Waves 2–3 add), newest evidence first; many entries name their owner — anything
already fixed en route gets closed with a pointer to the fixing commit. End
with a final report: per-invariant closure honesty per handoff §13 (do not
soften residuals), full commit inventory, and the deferral register.

## State snapshot (verify, don't trust)
- `git log --oneline main..fix/witness-integrity` ≈ 40+ commits: Wave 0
  (`cd2f9671`…`8964ebfe` + closeouts), Wave 1 legs (merged via `03331187`,
  `9b961319`, `41556ad4`), adjudications (`2586fdc3` + exit closeout).
- Gate at HEAD: PASS (suite 5,263 / pyright clean / determinism both classes /
  R5 v21). Re-run it first thing (`bash scripts/witness/gate.sh --base main
  --require-determinism`) — if it does not pass before you start, something
  moved; investigate before any wave work.
- Services: `docker compose up postgres minio minio-init -d`. Local DB is at
  Leg F's two additive migrations (`alembic upgrade head` on the test DB is
  handled by conftest).
- `EFFECT_CACHE_SCHEMA_VERSION = 21`; mutual-edge canonical number 66→32
  (v21 comment); the is_pausable/A7 ordering constraint is SATISFIED-so-far
  (bitmap-24 verified inert at Wave 1 HEAD) but A7 remains rank 1.
