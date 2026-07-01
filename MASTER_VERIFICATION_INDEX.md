# Master verification index — critical accuracy issues #111–#122

Single entry point to **every** verification spec and diagnosis record produced for
the #111–#122 accuracy series, so the whole series can be re-verified after the next
live run. All work landed on `integration/issues-111-122` (this branch); the seven
per-issue merges are `9bd7bfc` #114/#115 · `257d3a9` #117 · `f7ab5c0` #120 ·
`dfd4ff8` #116 · `993542a` #121/#122 · `a77fae3` #119 · `b8492c3` #111/#112.

**Two issues in the range are NOT fixes:**
- **#113 — REFUTED (not a bug).** The real pipeline yields a conservative
  `unsupported` (the resolver returns `None` for a trees-less artifact), never
  `public`. Only residual is a poison-cache/observability nit. Do not "verify a fix" —
  there is none.
- **#118 — OUT OF SCOPE** (hardcoded `chain_id=1`), excluded from this series by request.

The unifying defect across the other **10** issues is **fail-open polarity**: an
unknown / failed / empty / unmodeled condition was coerced to a less-restrictive
posture (usually PUBLIC), or a real privileged capability was dropped so it went
invisible. Every landed fix moves strictly **fail-closed** — it can only add gating,
never fabricate access.

**How to read the specs (important):** only the Surface series (Section B) is
**aggregation-only** (correct numbers appear the moment new code serves existing
data). **Every Section A fix needs a static and/or resolution RE-RUN** on the target
contracts before its corrected verdict appears — serving stale `effective_functions`
rows shows the old (pre-fix) answer. Each spec states its exact re-run requirement and
a no-DB Appendix reproduction. Verify the *invariants / direction* (nothing flips
toward public, no real caller dropped), not raw integer counts, which are corpus-dependent.

Paths are repo-relative to `/home/riley/PSAT`.

---

## A. Per-issue post-merge verification specs (what to observe on the next live run)

Durable acceptance-criteria docs authored by this series — the expected end-state of
each fix, its fail-closed invariants, and what a re-broken state looks like. *(These
seven are committed on this branch; B/C/D below are the investigation bundle.)*

- [`ISSUE_111-112_FIX_VERIFICATION.md`](ISSUE_111-112_FIX_VERIFICATION.md) — **#111/#112 cold caller-keyed thresholds:** on a fresh resolution run, an admin-curated `map[msg.sender] >= K` gate whose holder set is exact-empty (#112) or cold/unsupported/no-adapter (#111) must render **GATED**, while genuine self-service balance/points thresholds stay **PUBLIC**; fires 0× on etherfi (precision only — recall flip lives in Appendix B), fail-closed only.
- [`ISSUE_114-115_FIX_VERIFICATION.md`](ISSUE_114-115_FIX_VERIFICATION.md) — **#114 guard-uncertain public-default + #115 multi-statement revert recall:** after a static re-analysis, a `if(msg.sender!=owner){…;revert();}`-guarded function shows `status='unsupported'`/guarded with `authority_public=false`, never `public`; the load-bearing check is monotonicity **G1** (no function flips toward public) and an empty `guard_extraction_uncertain` marker on the real corpus.
- [`ISSUE_116_FIX_VERIFICATION.md`](ISSUE_116_FIX_VERIFICATION.md) — **#116 event `topic0` ABI canonicalization:** after re-analysis, an event with a non-elementary param (interface/enum/array/struct/UDVT) derives `topic0 = keccak(canonical ABI sig)` that matches real on-chain logs, so its privileged-mapping allowlist enumerates **real members** (not EMPTY with `status=complete`) and the watch plan subscribes to a live topic0; elementary-only events are byte-identical (no change).
- [`ISSUE_117_FIX_VERIFICATION.md`](ISSUE_117_FIX_VERIFICATION.md) — **#117 assembly-sink fail-closed:** after re-analysis on modern solc (0.8.x), inline-assembly `sstore`/`delegatecall` effects become visible and an assembly-gated mutator moves `public → unsupported` (never guarded→public, never drops a capability); inert on legacy ≤0.5.x (documented fail-closed residual).
- [`ISSUE_119_FIX_VERIFICATION.md`](ISSUE_119_FIX_VERIFICATION.md) — **#119 event-log cursor exactness:** on a fresh resolution pass, an event-indexed authority set is labeled `exact` **only when the durable cursor covers the evaluated height**; a keeping-up cursor stays `exact`, a lagging/stalled one demotes to `lower_bound`; watch the `event_fold_partial_cursor_behind_block` stage metric; nothing ever goes public.
- [`ISSUE_120_FIX_VERIFICATION.md`](ISSUE_120_FIX_VERIFICATION.md) — **#120 if/else `return true` polarity:** after re-analysis, a bool-returning authority provider's if/else chain (DSAuth/Solmate `isAuthorized`, denylist/whitelist) lifts to correct per-path predicates — early-deny shapes are no longer inverted and the always-true `business` fallback leaf is gone; a guarded function must never newly read public/permissionless.
- [`ISSUE_121-122_FIX_VERIFICATION.md`](ISSUE_121-122_FIX_VERIFICATION.md) — **#121 unread-proxy-slot + #122 no-impl proxy, COUPLED:** on a new analysis run, a proxy slot that fails to read (transient RPC outage, #121) becomes `degraded`/`unknown` instead of confident `type='regular'`, and a no-impl proxy (EIP-2535 diamond, reverting beacon, short-bytecode `unknown`, #122) as a nested controller becomes `analyzed=False`/degraded rather than a clean shell whose impl/facet guards read permissionless; both trigger on non-default conditions (verify via Appendix A/B + the negative invariants).

## B. Surface controls verification + diagnosis (pre-existing, user-supplied — REQUIRED)

The Surface `controls`/principal over-attribution pair that seeded this audit. This is
the **aggregation-only** exception: the corrected numbers appear the moment the new
code serves existing data — **no resolution re-run needed**.

- [`SURFACE_CONTROLS_FIX_VERIFICATION.md`](SURFACE_CONTROLS_FIX_VERIFICATION.md) — **verification spec:** living acceptance-criteria for the `/api/company/{name}` principal/`controls` FP-gate; each landed `## Change N` gives before→after data; core invariant — every principal the fix removes must have `controls_detail == []` (removing one with real call-rights is a regression).
- [`SURFACE_CONTROLS_OVERATTRIBUTION.md`](SURFACE_CONTROLS_OVERATTRIBUTION.md) — **diagnosis:** 18 etherfi Gnosis Safes listed as `controls`-bearing principals are all real Safes but hold **zero** real authority (0/18 are `owner()`, 0/18 hold a RoleRegistry role); sourced from non-authority signals (`treasury`/`feeRecipient`/`_owner`/`payoutAddress`, node-operator registry) via an unfiltered `ControlGraphNode` walk in `company_overview.py`, inflating the "Safes (N)" filter.

## C. Per-issue diagnosis records (settled root cause + proof)

The `-FINAL` (and `-FINAL2` where a second pass closed an open fork or added an
independent adversarial corpus measurement) settlement files — the earliest
correctness-loss point, the decided fix, and the real-data proof behind each Section A
spec. Full record for each issue also has `-rootcause` / `-challenge` / `-VERIFY*`
siblings in the same directory.

- [`issue-fixes-111-122/analysis/issue-111_112-FINAL.md`](issue-fixes-111-122/analysis/issue-111_112-FINAL.md) — discriminator between a genuine authority set and a self-service threshold for a caller-keyed COMPARISON leaf is the **writer-gate `_classify_writers` verdict** (was unwired for comparison leaves); evaluator L380 `and cap.members` was a symptom, not the root.
- [`issue-fixes-111-122/analysis/issue-111_112-FINAL2.md`](issue-fixes-111-122/analysis/issue-111_112-FINAL2.md) — independent adversarial verify + corpus measurement: discriminator holds, **measured over-report = 0/45 (0%)** on the real 56-contract etherfi corpus, 191 related tests green, 0 regressions.
- [`issue-fixes-111-122/analysis/issue-114-FINAL.md`](issue-fixes-111-122/analysis/issue-114-FINAL.md) — the broad FIX-A gate **over-broadens catastrophically** (flipped 7/7 genuinely-public functions incl. `WETH9.transfer`, 0 real bugs; 100% FP among flips); settled fix = fix #115's recall + a **precise** caller `==`/`!=` RevertGate marker (FP-free on the corpus). Do NOT ship the broad discriminator.
- [`issue-fixes-111-122/analysis/issue-114-FINAL2.md`](issue-fixes-111-122/analysis/issue-114-FINAL2.md) — IMPLEMENTED + corpus-verified: two coupled parts (revert_detect cross-node CFG walk + narrow `guard_extraction_uncertain` marker) as real in-file edits, +155/-33, proven on real Etherscan contracts + the real static→policy pipeline.
- [`issue-fixes-111-122/analysis/issue-115-FINAL.md`](issue-fixes-111-122/analysis/issue-115-FINAL.md) — root is `RevertDetector._scan_node`'s **one-hop son scan**, which misses a multi-statement guard body whose `revert` sits ≥2 hops below the IF; fix = a cycle-safe CFG revert-walk that also covers revert-after-nested-if (Shape A, in scope).
- [`issue-fixes-111-122/analysis/issue-116-FINAL.md`](issue-fixes-111-122/analysis/issue-116-FINAL.md) — **two** independent `topic0` producers (`mapping_events.py` + `tracking.py`) each keccak'd Slither's *declared* type names (`IGem`, `Vat.Status`, `IGem[]`); fix = a recursive ABI canonicalizer (interface→`address`, enum→`uint8`, `T[]`, struct-tuple, UDVT→underlying) applied at both.
- [`issue-fixes-111-122/analysis/issue-117-FINAL.md`](issue-fixes-111-122/analysis/issue-117-FINAL.md) — `effects.py::_classify_node_irs` inspects only `selfdestruct(` and drops the `sstore`/`delegatecall` SolidityCall IR ops modern Slither emits (confirmed dropped on real weETH `ERC1967Proxy`); narrowing: inert on legacy ≤0.5.x (opaque `NodeType.ASSEMBLY`, verified on real USDC `FiatTokenProxy`).
- [`issue-fixes-111-122/analysis/issue-119-FINAL.md`](issue-fixes-111-122/analysis/issue-119-FINAL.md) — the fold mints `enumerable`→`exact` for a set complete only up to a **stale durable cursor**, gated solely on `backfill_complete`; `block=None` (prod path) means "live head", which the cursor structurally lags; the head-pin companion is **REQUIRED**, not optional — 3 code parts + 1 explicit non-change.
- [`issue-fixes-111-122/analysis/issue-119-FINAL2.md`](issue-fixes-111-122/analysis/issue-119-FINAL2.md) — the naive `resolver_head − 12` head-pin is **structurally racy** (degenerates to blanket exact→lower_bound whenever any block arrived since the indexer's last pass); resolved with a deterministic finality-margin pin so a keeping-up cursor **provably stays exact**.
- [`issue-fixes-111-122/analysis/issue-120-FINAL.md`](issue-fixes-111-122/analysis/issue-120-FINAL.md) — `_build_if_else_returns_or_children` hard-codes `polarity=allowed_when_true` against the **closest** IF (inverting early-deny) + emits an always-true `business` leaf when no IF is found; the one-IF fix **fabricates access** on multi-deny chains — decided fix ANDs the negations of **all** dominating deny-IFs (else fail-closed).
- [`issue-fixes-111-122/analysis/issue-121-FINAL.md`](issue-fixes-111-122/analysis/issue-121-FINAL.md) — `_read_proxy_slots_batched` conflates "slot read FAILED" with "slot empty" (`except RuntimeError: raw = None`), so `classify_single` returns a confident `type='regular'` during a transient RPC outage; a raise/signal is necessary but **not sufficient** — all three downstream callers still consume the shell as a clean contract.
- [`issue-fixes-111-122/analysis/issue-122-FINAL.md`](issue-fixes-111-122/analysis/issue-122-FINAL.md) — `recursive.py::_materialize_contract_artifacts`'s proxy retarget has `if impl:` with **no `else`**, so a `type='proxy'` with no `implementation` key Slithers the delegatecall **shell** (every impl/facet guard reads permissionless); four honest classifier cases (diamond / beacon `implementation()` failure / two `unknown` shapes) all collapse here — fix = fail-closed `UnresolvedProxyError`.

## D. Orchestration narrative (how the series was diagnosed, planned, and landed)

The connective tissue: the audit's reasoning, the deduped fix plan, the traps that
almost shipped wrong, and the landing playbook.

- [`ISSUES_111-122_MASTER_REPORT.md`](ISSUES_111-122_MASTER_REPORT.md) — single source of truth: per-issue status table, the four-phase investigation history, and the **six "key corrections" the rigor caught** (would have shipped wrong otherwise, e.g. FIX-A's 7/7 false positives, #120 fabricating access, #119's racy head-pin).
- [`ROOTCAUSE_FIX_PLAN_111-122.md`](ROOTCAUSE_FIX_PLAN_111-122.md) — the minimal deduped **9-fix set for 10 issues**, fix locations, sequencing rationale (FIX-A keystone first), and the cross-cutting **co-land constraints** (FIX-D ⟂ FIX-A mandatory; #121+#122 coupled at `recursive.py:316`).
- [`issue-fixes-111-122/ORCHESTRATOR_HANDOFF.md`](issue-fixes-111-122/ORCHESTRATOR_HANDOFF.md) — the implement/verify/land playbook: inherited state, the hard-won ground rules ("distrust convenient proofs", fail-closed only), the patch→issue map, and the file-overlap warnings.
- [`issue-fixes-111-122/README.md`](issue-fixes-111-122/README.md) — the bundle resume guide: candidate-patch table, the prose-only issues (#120/#121/#122), recommended landing order, and the required fail-closed follow-ups.
- [`AUDIT_ISSUES_111-122_DIAGNOSIS.md`](AUDIT_ISSUES_111-122_DIAGNOSIS.md) — phase-1 fixed-vs-remains diagnosis (history; superseded for current status by the master report, kept for the original mechanism traces).
