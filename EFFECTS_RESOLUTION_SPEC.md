# Effects Resolution Spec

How PSAT determines what a function *does*, with witness-grade confidence and
no name-based inference. This is the substrate the protocol score reads; the
scoring design in `SCORING_INVARIANTS.md` is deliberately downstream and is
**not** touched until this lands. Cross-reference: scoring invariants 1
(three-valued logic), 2 (every scored item has a witness), 7 (transitive
value-at-stake).

Grounded in the local etherfi DB (protocol_id=1, queried 2026-07-19). Numbers
in Appendix A are measured, not estimated.

**To implement this:** the phase plan and orchestration rules (branch, agent
structure, gates, Progress log) are at the end of this doc — "Implementation
plan & orchestration rules". A fresh orchestrator session starts there; a
resumed one starts at the Progress log.

---

## 1. The problem this fixes

Effect labels today are minted by a static claims registry
(`services/static/claims/`, PR #145): a whitelist of ~20 code-shape idioms.
Anything outside the vocabulary projects to **nothing**, even when the facts
plane has fully recorded the function's state writes. Measured on etherfi:

- **265 of 406 gated functions** have proven state-write facts
  (`effect_targets` populated) but empty `effect_labels` **and** empty
  `claims`. The facts exist; the projection discards them.
- The largest single cluster is an **ERC-7201 namespaced-storage blind spot**:
  the top blank write-targets are `PAUSABLE_UNTIL_STORAGE_SLOT` (66 rows),
  `PAUSABLE_STORAGE_SLOT` (42), and a tail of `*StorageLocation` pseudo-vars.
  Matcher fact-helpers consume only plain typed state-var writes
  (`_facts.bool_write_targets` requires `declared_type == "bool"`), so modern
  OZ-v5 / etherfi keccak-slot storage is invisible to Plane 1.
- Consequence in practice: `pauseUntil` across 11 contracts, 25/30 `pause()`
  rows, and 24/24 plain `unpause()` rows carry **no pause claim**. `pause`,
  `unpause`, `pauseUntil` on all six money contracts (WeETH $3.2B →
  Liquifier $1.1M) are gated + facts-present + label-blank.

**Any shape-recognizer has an infinite tail of idioms it doesn't know.**
ERC-7201 is just the current one. Patching matchers one idiom at a time treats
the symptom. The fix is a second, idiom-agnostic evidence class.

## 2. The reframe: effects are behavioral, proven by two planes

An effect **is** a state transition. So define each effect class by the
transition it causes and *observe* it on a fork, instead of recognizing the
code shape that causes it. This yields an unhallucinatable witness of the exact
form the score needs: **"this principal CAN cause this transition on current
chain state."**

Two planes, different logical questions, both retained:

| Plane | Answers | Can prove | Cannot prove |
|---|---|---|---|
| **Static** (claims/facts) | universals | "nothing *else* writes X", "no asset sink exists", "gate is mandatory on every path"; enumerates entry points, sinks, tainted params, resolved principals | idioms outside its vocabulary |
| **Simulation** (fork) | existentials | "X *can* happen from this state, by this caller" — idiom-agnostic, works on unverified bytecode, through proxies/delegatecall, indifferent to storage layout | absence / universals; only what's reachable from the forked state with the inputs tried |

They form a ladder, not a competition: **static proposes** (which functions,
which params, which callers) → **simulation confirms** (observed transition) →
verdict carries an evidence tier. Static remains the sole source of
universal/credit facts (`resolved_empty`, one-shot detection, "gated
exclusively by Safe+timelock") and the candidate/parameter/identity generator
that makes simulation affordable. **Neither plane is retired.**

Disagreement is a feature: static-positive + simulation-negative (e.g. a
bool-pause matcher fires but the revert-set doesn't change) means a matcher bug
or a probe-soundness hole — a systematic way to grow the static vocabulary from
evidence instead of user-test embarrassment. See §9 for resolution.

## 3. Evidence tiers (cheapest, most authoritative first)

Every effect verdict is stamped with the tier that produced it.

- **Tier 0 — indexed history (free, ground truth).** `upgrade_events`,
  `monitored_events` are effects that *already happened* on mainnet — a
  **historical** existential. The score's target statement is present-tense
  ("CAN cause on current chain state"), so a Tier 0 witness discharges it only
  in **conjunction with a current-state check** (one `eth_call`: admin/impl
  slot still non-zero, owner resolved and non-renounced). Indexed upgrade +
  current check passing ⇒ proven upgradeable now; current check failing ⇒
  "historically upgradeable, current capability `unknown`" (fail-closed).
  Prefer this whenever it answers the question.
- **Tier 1 — `eth_call` / `eth_simulateV1` with state overrides (cheap).**
  Authorization differential + single-call effect diff via `from`-override.
  Reuses the hermetic call-batch pattern already in
  `services/resolution/differential_probe.py`. Covers most classes.
- **Tier 2 — anvil fork with impersonation + `evm_increaseTime` (moderate).**
  Only for effects needing sequencing or time (prove `pauseUntil` auto-expires
  at its `MAX_PAUSE_DURATION`; prove an unpause reverses the revert-set).
  Reserve for what Tier 1 leaves ambiguous.

All tiers are read-only against a fork: `eth_call`, state overrides, and anvil
snapshot/revert. No mainnet writes, no keys.

**Infra preflight (blocking, before any recipe is trusted):**

- **`eth_simulateV1` support is probed, never assumed.** Tier 1 recipes that
  need logs or multi-call context (4.2, 4.5) require `eth_simulateV1`; plain
  `eth_call` returns neither. At stage init, issue a trivial `eth_simulateV1`
  through eRPC once per chain and persist the result. Where unsupported, those
  classes route to Tier 2 (anvil) — an explicit, declared fallback that
  changes the cost model, never a silent degradation.
- **Anvil is a new worker runtime dependency** with a real footprint: cap one
  instance per worker; reuse one fork per run per chain with snapshot/revert
  between contracts (amortizes upstream `getStorageAt`/`getCode` fetches);
  route the fork RPC through eRPC with a distinct client tag so cost is
  attributable. **Fork access is single-flight (decided):** anvil
  snapshot/revert is process-global, so two jobs interleaving on a shared
  fork silently corrupt each other's probes — production runs
  `PSAT_EFFECTS_JOB_CONCURRENCY=1` (correctness first; bounding anvil CPU is
  the side benefit). Any future parallelism needs a per-chain fork mutex,
  never concurrent snapshot users. Memory is headroom, not a blocker —
  effect workers have 16GB against the 512MB monitor-OOM precedent — but the
  Appendix B experiment still records peak RSS and upstream request counts
  for attribution. The Dockerfile already ships foundry (`foundryup`), so
  anvil needs no new provisioning — but pin the foundry release in the
  Dockerfile (bare `foundryup` floats to latest-nightly per image build)
  and record the anvil version in every transcript, so witnesses are
  reproducible across image rebuilds.
- **Hardfork pinning.** The fork must pin/assert the target chain's current
  hardfork (post-Cancun semantics on both mainnet and Base) and record it in
  the transcript. A fork on stale semantics can mint witnesses that are wrong
  for the live chain (EIP-6780 is the concrete case — see §4's exclusion
  note).

**Cost verdict (2026-07-20; go).** Tier 1 — four of the five classes — needs
no fork at all: `eth_call`/`eth_simulateV1` with state overrides are
simulated server-side by the hosted node. Tier 2's fork is a lazy state
mirror, not a network sync: anvil fetches only first-touched slots/code
(fork at `latest`; no archive access needed) and caches them for the fork's
lifetime, and snapshot/revert reuse means the 11 `PausableUntil` sharers pay
for shared state once. Estimated first full etherfi run: ~10–30k upstream
requests, nearly all cheap methods (`eth_call` ≈ 26 CU, `getStorageAt`
≈ 17 CU on Alchemy) ≈ ~1M CU — cents, invisible against the current
$30–60/mo non-indexer Alchemy line; hyperrpc cannot serve these methods, so
this traffic routes to the full-node upstream with no eRPC routing change.
Re-runs and cross-chain twins hit the behavioral cache (§7) and pay
~nothing. The scarce resources are wall-clock (anvil's lazy fetches are
serial round-trips — fork reuse matters for latency more than money) and
worker CPU (bounded by single-flight), not RPC dollars or memory. Against
this cost: 265 of 406 gated functions (65% of the gated surface), including
`pause`/`unpause` on all six money contracts, are invisible to the score
today — the information gain is the entire blank set.

## 3a. Pipeline placement

The current lifecycle is
`discovery → selection → static → resolution → policy → coverage → done`
(`db.models.JobStage`). Effect simulation is a **new stage inserted between
`policy` and `coverage`**, per contract job, backed by a persistent
behavioral-hash cache. It is **not** folded into `static`.

**Why a new stage after `policy`, not folded into `static`:**

1. **Inputs don't exist until `policy`.** Simulation needs the resolved
   principals (whom to impersonate — written by `policy`/`resolution` with
   `require_rpc_url`) and the finalized claim set (to know *which* functions
   came out blank). `static` runs Slither in a temp dir with no RPC and cannot
   know its own targets.
2. **Capability split is fundamental.** `static` is hermetic, offline, and
   cached by content hash — a property the CI suite and the multichain
   code-plane/state-plane split depend on. Simulation is fork-pinned,
   RPC-bound, state-dependent. It maps exactly onto the **state plane** of
   `MULTICHAIN_INVARIANTS` inv. 1 ("cache the code plane, re-resolve the state
   plane"): behavioral-hash dedup *is* code-plane caching, concrete values
   *are* the state plane. It belongs on the resolution/policy side by that
   logic, and folding it into `static` would poison static's offline
   testability.
3. **Failure isolation — and the stage is fail-forward (decided).** Fork/RPC
   flake has a different failure profile from policy's resolution work. As
   its own stage it gets its own retry policy and `stage_timing_simulation`
   observability. But isolation must be made true, not assumed:
   `BaseWorker`'s default outcome on exhausted retries is `failed_terminal`
   (`workers/base.py`), which would kill a job whose claims/principals are
   already complete and correct — strictly worse than flag-off. The effects
   stage therefore never terminals a job: on retry exhaustion it writes
   `unknown` verdicts (the §8 fail-closed verdict anyway), records degraded,
   and advances to `coverage`.
4. **Independent rollout.** Same spirit as `PSAT_DIFFERENTIAL_PROBE`, with
   one difference that matters: that flag is *in-stage*, this one gates a
   *stage transition*. **Flag-off means `policy` advances directly to
   `coverage`** — the flag must gate the transition itself, never just the
   worker's processing, because a queued job parked at a stage no worker
   drains sits forever (the stale sweep only rescues *claimed* jobs).
   Deploy-order corollary: the effects worker must be launched from
   `start_workers.sh` (the `workers` process group) before the flag flips.
5. **Latency is absorbed by coverage's audit gate.** `coverage`'s claim
   readiness predicate blocks until every audit in the protocol is terminal
   (1h stuck-timeout escape), so effects runs inside the window coverage
   would spend blocked anyway — typical added wall-clock to `done` is
   ~zero. Placed after `coverage` instead, a wedged audit PDF would delay
   effect verdicts too.

**Grain: per contract job + persistent shared cache.** The stage runs per
contract (aligning with incremental re-analysis — scoring inv. 15: re-analyzing
one contract touches only its ledger and hits cache for unchanged behaviors),
but the behavioral-hash cache is a **persistent table shared across jobs and
cross-chain twins** — the 11 `PausableUntil` sharers are separate jobs, so a
sibling (or prior run, or twin on another chain) that already witnessed a
behavior yields a free hit. This is the same cross-job cache-table pattern as
the code-plane reuse cache (PR #155) and `bytecode_cache`.

- **Cache key — two levels (§7).** *Kernel* verdicts (function-local) key on
  (resolved-function behavioral hash, effect class). *Projection* verdicts
  (contract-scoped, e.g. pause blast radius) key additionally on the
  whole-contract code identity. **Value:** the structural verdict + tier +
  transcript pointer. Concrete values (§7) are never in the key.
- **Cache is code-plane** (chain- and deployment-independent); the state-plane
  residue (concrete destination address, exact impl) is written to the contract
  row, never the cache.

**Why per-contract is sufficient (not protocol-level):** the no-floor decision
(§6) means every distinct behavior is simulated regardless of value, so global
priority ordering only affects *latency to first result*, never coverage.
Transitive value-at-stake orders work *within* reach of the data a job has; a
protocol-wide priority pass, if ever wanted for latency, layers on top without
changing correctness.

**Lighter-touch fallback (documented, not chosen):** a tail-phase of `policy`
would avoid re-loading the effects/principals artifacts from the DB since
`policy` holds them in memory. Take it only if artifact-reload cost is shown to
dominate — it trades away the failure isolation and independent retry/rollout
of a clean stage.

**V1 consumption boundary (decided): write-only.** This PR lands the
substrate: verdicts persist to `effect_behavior_cache` / `effect_verdicts`
and discrepancies to the warning channel, but nothing *reads* them yet — no
`analysis_detail` / API / Surface wiring, no merging into `effect_labels`.
Consumption is the scoring work (`SCORING_INVARIANTS.md`), designed
downstream once witnesses exist to read; wiring verdicts into consumer
surfaces here would front-run that design unreviewed. Preview validation
therefore queries the DB directly (see post-push checklist). The one UI
exception is pipeline *observability*, which is operational rather than
score consumption: the /monitor page must learn the new stage (stage
registry + metric chips — Phase 3).

## 4. The five effect classes (v1)

Each class is a **behavioral definition** (the observation *is* the label), a
**recipe**, and a **cacheability** rule (§7). Names never enter a definition.

Where an effect's meaning depends on the surrounding contract, its verdict
splits into a **kernel** (what F itself does — function-local, transfers on
the resolved-function hash) and a **projection** (what that means on this
contract — contract-scoped, transfers only on whole-contract identity).
Cacheability is declared per component, not per class (§7).

### 4.1 Freeze / pause
- **Definition:** calling F, as its gating principal, causes a set of
  previously-succeeding state-changing entry points to now revert.
- **Kernel (function-local):** F flips latch L — the specific storage slot
  (plain or ERC-7201 namespaced) whose guard checks revert when set.
- **Projection (contract-scoped):** the blast radius — which entry points on
  *this* contract are guarded by L. The same mixin kernel yields different
  blast radii on different contracts; the projection never transfers on the
  function hash alone.
- **Recipe (Tier 2):** snapshot fork → record which entry points succeed →
  impersonate principal, call F → re-probe entry points → the newly-reverting
  set is the *observed* blast radius. Warp time by the contract's own
  `MAX_PAUSE_DURATION` constant and re-probe to prove auto-expiry; record the
  duration bound (read from source constant, not hardcoded) as a severity fact.
- **Denominator rule (two-sided fail-closed, §8):** the *scored* blast radius
  is static's predicted guard set (which functions check L — modifier/facts
  data), at claim tier; simulation upgrades confirmed members to witnessed
  tier. The observed revert-set is a **lower bound** — entry points already
  reverting pre-pause on business preconditions are invisible to the diff —
  so it must never become the scored set's denominator. Record the pre-pause
  succeeding set in the witness so consumers see the denominator.
- **Witnesses:** latch-flip kernel, observed blast radius (+ pre-pause
  succeeding set), auto-expiry bound, per-pauser cooldown.
- **Cacheable:** kernel yes (function hash); projection yes, but only on
  whole-contract identity (§7).

### 4.2 Value-out (+ destination shape)
- **Definition:** calling F moves ETH or ERC-20 value out of the contract.
  Destination shape is **three-valued**: *caller-arbitrary* (value can land on
  a caller-controlled address), *storage-determined* (destination read from a
  mutable storage var — whoever can write that var chooses the destination;
  link the writing gate into the control graph, since this composes with
  authority-change into effective arbitrariness), or *immutable-fixed*
  (destination is an immutable/constant). Only the third is benign.
- **Recipe (Tier 1 via `eth_simulateV1` — balance + `Transfer`-event diffs
  need it; Tier 2 where unsupported, per §3 preflight):** call F as principal
  → diff ETH balances + `Transfer` events. Then, for each address-typed param
  that taint says reaches the value sink (`is_parameter` in
  `effects._extract_value_flows`), re-run with an attacker-sentinel in that
  slot → value lands on the sentinel ⇒ caller-arbitrary **proven**.
- **Sentinel failure proves nothing (rule 8.1).** A sentinel probe that moves
  no value is a non-observation — `unknown`, never "fixed" (the sentinel may
  simply not be a valid key when the param is an index into `registry[param]`
  rather than the raw address). The fixed shapes are **universals and belong
  to static**: *immutable-fixed* / *storage-determined* require positive
  static proof of the destination expression. Taint-says-param-reaches-sink +
  sentinel-negative is a §9 discrepancy, not a verdict.
- **Witnesses:** value-moved fact, destination shape + the plane that proved
  it, the concrete destination when fixed/storage-determined.
- **Cacheable:** shape yes (code-determined, function hash); concrete
  destination no (state/immutable — per-deployment metadata, never a cache
  key).

### 4.3 Code-upgrade
- **Definition:** calling F changes the code that executes for the proxy
  (EIP-1967 impl slot or account code changes).
- **Recipe:** Tier 0 first — indexed upgrade **plus** the current-state check
  (§3); history alone proves past capability, not present. Else Tier 1: read
  impl slot, call F as principal with a sentinel impl, re-read → slot changed
  ⇒ proven. The sentinel must survive the proxy's validation: state-override
  the sentinel address with a precomputed stub — plain nonzero code for
  transparent proxies, an ERC-1822 stub whose `proxiableUUID()` returns the
  canonical slot for UUPS (whose `upgradeTo` delegatecalls the new impl to
  check it). A bare address sentinel reverts and proves nothing.
- **Witnesses:** upgradeable fact (tiered historical vs current), gating
  principal.
- **Cacheable:** yes (function-local kernel).

### 4.4 Authority-change
- **Definition:** calling F changes *who* can call some function — the
  before/after of the authorization differential differs.
- **Kernel (function-local):** F mutates the membership of gate G.
- **Projection (contract-scoped):** the concrete authorization delta — which
  entry points change hands — depends on the whole contract's surface.
- **Recipe (Tier 1):** run the existing who-can-call probe → call F as
  principal (e.g. `grantRole`/`setOwner`) → re-run the probe → the delta **is**
  the effect.
- **Witnesses:** gate-mutation kernel, authorization delta.
- **Cacheable:** kernel yes (function hash); delta only on whole-contract
  identity (§7).

### 4.5 Supply (mint / burn)
- **Definition:** calling F changes `totalSupply` (up = mint, down = burn).
- **Recipe (Tier 1 via `eth_simulateV1` — read→call→read needs one simulated
  context; Tier 2 where unsupported):** read `totalSupply` → call F as
  principal → re-read → signed delta is the label. Destination shape as in
  4.2 — sentinel proves caller-arbitrary; sentinel failure is `unknown`,
  never fixed.
- **Witnesses:** supply-delta sign, destination shape.
- **Cacheable:** yes (function-local kernel).

> Out of v1 (documented gap, not silent): `arbitrary-external-call` and
> `hook-update` have fuzzier behavioral definitions; they remain static-only
> until a clean observable is defined. Any function whose only facts are these
> stays in the warning/confidence channel per scoring inv. 1.
>
> **Selfdestruct is excluded by the same bar, for a different reason: its
> observable died.** EIP-6780 (Dencun; live on mainnet and Base since March
> 2024) deletes code/storage only when SELFDESTRUCT runs in the creation
> transaction — on any already-deployed contract it just sweeps the ETH
> balance and leaves code in place, so "account code → empty" can never fire
> and a code-length recipe would confidently report nothing even when the
> opcode executes. Static's existing `selfdestruct_capability` label
> (`summaries.py`) remains the detector, routing to the warning channel; the
> behavioral residue — a full-balance sweep — is a value-out instance and is
> caught by 4.2's balance diff if such a function ever enters the candidate
> set (measured: 0 of 1,211 etherfi effective functions carry the label). A
> trace-based opcode classifier (`debug_traceCall`) is a possible future
> item, gated on a real instance appearing in data.

## 5. Static's retained role (why both planes stay)

Simulation depends on static and cannot replace it:

1. **Universal claims** — only static supports "nothing else can do this" and
   the entire *credit* side of the ledger (WeETH gated exclusively by
   Safe+timelock, `resolved_empty`, one-shot latches).
2. **Candidate set** — static enumeration of entry points / sinks / state
   writes is *which* functions to simulate. Without it the harness fuzzes
   blind.
3. **Parameter selection** — taint (§4.2) says which params matter, turning a
   fuzz campaign into a handful of targeted calls.
4. **Identity selection** — resolved `function_principals` give the exact
   impersonation set (principal + random controls), not a search.
5. **State-independence & offline testability** — static holds across all
   states and runs in the hermetic offline suite; simulation is fork-pinned and
   RPC-bound.

Static's job description narrows from "name the semantics" to "enumerate the
surface, prove the universals, nominate candidates." Retiring a specific
matcher is a per-matcher decision made *after* the harness exists (a matcher
strictly dominated by a behavioral check *and* contributing no universal
claim), never an architecture decision made now.

## 6. Selection and ordering (no value gate)

Simulation targets are chosen by a filter cascade over data we already have,
then **ordered** by value — value never gates.

**Cascade** (etherfi funnel in Appendix A):
1. Must have a sink (`effect_targets`/`sinks` non-empty). Drops views/pure/
   event-only.
2. Skip already-witnessed: a confident claim already resolves the function.
   **You only simulate the blank set** — as matchers improve, the workload
   shrinks.
3. Prefer gated over public (public effects are usually already labeled or
   benign; the expensive unknowns are gated).

**Ordering — value-at-stake, transitive, upper-bounded:**
- Order candidates by **transitive** value-at-stake: the USD a function's
  effect can reach through the control graph (`control_graph_edges` closure +
  proxy-admin links + principal→contract edges), **not** direct balance. The
  $33K Safe that controls $3.2B must sort near the top; direct-balance ordering
  would wrongly bury it.
- Reach is a **conservative upper bound**: any control edge propagates full
  downstream value. This only affects *priority order*, never the score, so
  over-approximation is safe by construction.

**No stop floor (decided).** Because caching (§7) bounds total cost to the
number of *distinct behaviors* (~200 for etherfi, not 265 rows), simulate
**every distinct behavior**. Value-at-stake decides *order only* — what to do
first — never whether to do it. This removes the last `$1M`-style constant from
the design. The only permissible cutoff is a hard resource safety-valve for a
pathological protocol, and if ever hit it must `log()` exactly what was dropped
(no silent truncation).

## 7. Behavioral-hash dedup (provable, name-free)

Contracts share code; simulating per deployment is wasteful. Dedup on a
**provable behavioral identity**, never a name.

**The naming trap (present in this dataset):** the `PausableUntil` mixin source
is byte-identical across 11 contracts (one content hash `f6966b…`), and all six
money contracts share compiler settings (`v0.8.27+commit.40a35a09`, opt on,
1500 runs, prague). Tempting to key on the mixin file hash — **wrong.** The
mixin declares `pauseUntil()` `virtual onlyGuardian` and the source comment
states eETH/weETH *override* it for stricter gating. Same name, same inherited
file, **different gate.** File-hash dedup would merge behaviors that differ.

**The sound key is the hash of the *resolved* function**, in implementability
order:
1. **Primary (verified source): normalized IR/CFG hash of the resolved
   function** — Slither function *after* override resolution + internal-callee
   inlining, with immutable/constant literals and variable names stripped,
   then hashed. Compiled-structure-derived (not names); separates the weETH
   override from the mixin default because it hashes what *executes*;
   leverages the Slither pipeline that already exists.
2. **Fallback (unverified): metadata-stripped whole-runtime-bytecode hash +
   selector.** Sound by construction — identical whole bytecode ⇒ identical
   dispatch ⇒ identical per-selector behavior. It under-dedups (contracts
   sharing F but differing elsewhere hash apart), which costs extra
   simulations but never a wrong transfer. Immutables baked into bytecode
   cause additional safe over-splitting; on verified contracts, mask them via
   the compiler metadata's `immutableReferences` to recover those hits.
3. **Source-content hash of the defining unit** — only sound when the function
   is provably *not* overridden and lives wholly in one hashed file; a fast
   path on top of (1), never a substitute.
4. **Future upgrade, explicitly gated:** per-selector bytecode-region hashing
   (the opcodes the dispatcher jumps to). Requires EVM CFG recovery —
   jump-target resolution, shared internal-function bodies — i.e. a lifter
   this repo does not have. Not a v1 dependency; no recipe may assume it.

**Cacheability rule — scope is per verdict component, not per class:**
- **Function-local kernels → transfer on the resolved-function hash.**
  Latch-flip, gate-mutation, code-change, supply-delta sign, destination
  *shape* — determined by F's own code. Simulate once, reuse across all
  deployments sharing the hash (including cross-chain twins, keyed per
  scoring/multichain content identity).
- **Contract-scoped projections → transfer only on whole-contract identity.**
  Pause blast radius and authorization delta are properties of the *whole
  contract's* entry-point surface, not of F: the same mixin kernel on WeETH
  and Liquifier yields different blast radii. Key = metadata-stripped
  whole-runtime-bytecode hash of the contract (the fallback hash above — one
  hasher serves both levels), so cross-chain twins and unchanged re-runs
  still hit; only genuinely distinct surfaces pay a projection probe.
- **Concrete-value effects are state-determined → never cached.** Exact
  destination address, exact target impl — per-deployment metadata, never a
  cache key.

**Self-audit (mandatory).** The first time two functions share a behavioral
hash, simulate both once and assert the *kernel* verdicts match before
trusting the cache; audit once per (kernel hash, contract-surface hash) pair,
since the projection level is where transfer risk lives. Projections on
different surfaces are *expected* to diverge — divergence there is not a
failure. Scope is first-collision-pair only (later sharers ride the audited
result); an optional cheap insurance is re-auditing every Nth cache hit.
Catches a hashing bug before it silently propagates a wrong verdict across
deployments. This is what lets free cache-hits be *trusted*, not assumed.

**Effect on workload:** the ~108 `PAUSABLE_*_SLOT` blank rows collapse to
~2–3 distinct resolved-pause *kernels* (plain mixin, weETH/eETH override, any
`0.8.9`-era variant), each simulated once. Each distinct contract surface
additionally pays one cheap blast-radius projection probe — which doubles as
a verification of static's predicted guard set; cross-chain twins and
unchanged re-runs pay nothing. "265 candidates" → "~200 distinct behaviors" →
far fewer *paid* simulations once shared kernels across the money set cover
their low-value twins for free.

## 8. Soundness rules (fail-closed everywhere)

**Fail-closed is two-sided here.** (i) Witness side: never assert an
unobserved positive — every rule below withholds rather than fabricates,
consistent with the codebase's posture (netguard, earned-public, the
differential probe). (ii) Score side: never let *missing* evidence improve
the score — for penalty-side facts (a freeze, per scoring inv. 4's risk arm),
an under-observed effect must degrade confidence (scoring inv. 6), never
shrink the scored set. The witness-conservative and score-conservative
directions can point opposite ways (the blast-radius lower bound in §4.1 is
the concrete case); every recipe is audited against both.

1. **Existential only.** Simulation proves "can"; it never proves "can't." A
   non-observation is `unknown`, never a proven-absent. Universals stay static's
   job.
2. **Authorization upgrades need ≥2 distinct random identities all succeeding**,
   block-independence cross-checked (inherited from
   `differential_probe.py` §3.5). A single ambiguous probe never opens
   anything; indeterminate ≠ public.
3. **Compare raw revert data, not decoded semantics.** Two identical revert
   payloads = same gate (conservative; withholds upgrades). Decoding is for the
   transcript only, never drives a verdict.
4. **Precondition reverts fail closed.** For a param that does *not* reach a
   sink, pass a minimal default. If the probe reverts for a *business
   precondition* (not a caller gate), the result is `unknown` for that function
   — never read "reverted" as "not permitted / no effect." When in doubt,
   withhold.
5. **Every verdict carries its tier and its transcript.** A verdict is
   reproducible from (forked block, calls issued, raw results). No verdict
   without a replayable transcript. **Transcripts are artifacts, not
   rows:** they land in the artifact store (MinIO) via the existing
   `store_artifact` / nested-artifacts conventions, and `transcript_ptr`
   in cache/verdict rows is an artifact key — never an inline JSONB blob.
   Content is bounded to the replay minimum (forked block, hardfork,
   anvil/foundry version, calls issued, raw results); retention follows
   the artifact store's existing lifecycle.
6. **Pure given an injected call-batch.** The harness takes a `call_batch`
   callable (thin wrapper over `utils.rpc.eth_call_batch`) so it is testable
   against stubbed wires with recorded transcripts, exactly like the existing
   probe. Fork state fetched once per contract, cached in anvil.
7. **Hardfork pinned and recorded.** The fork asserts the target chain's
   current hardfork and the transcript records it; a fork on stale semantics
   mints witnesses that are wrong for the live chain (EIP-6780 is the
   concrete precedent).
8. **Denominators come from static.** Where a scored set has a denominator
   (blast radius, authorization surface), it is static's universal
   enumeration; simulation only upgrades members' evidence tiers, never
   defines the set (score-side fail-closed).

## 9. Plane-disagreement resolution

When static and simulation disagree, the existential fact wins for *existence*,
but neither plane overrides the other's exclusive competency:

- **Static-positive, simulation-negative** (matcher fired, transition not
  observed): the non-observation never refutes the claim's *truth* (that
  would violate §8 rule 1) — it lowers the **confidence tier** the score
  consumes. The effect stays on the penalty side of the ledger (retaining an
  unconfirmed risk is the conservative direction) but is surfaced in the
  warning channel (scoring inv. 1) with the discrepancy attached, flagging a
  candidate matcher bug or probe-soundness hole. (This is the
  bool-pause-vs-revert-set case.) **Closing rule:** a discrepancy is resolved
  only by a matcher fix, a probe-soundness fix, or a higher-tier witness —
  never auto-dropped and never silently kept.
- **Static-silent, simulation-positive** (blank function, transition
  observed): the simulation witness stands; record the effect at its tier and
  file a candidate new static idiom for vocabulary growth.
- **Both positive:** cross-validated; highest confidence.
- **Universal claims (credit facts):** simulation cannot refute them (it can't
  prove absence), so static's `resolved_empty` / exclusive-gating claims are
  never overridden by a non-observation.

## 10. Implementation invariants

Testable rules the implementation must satisfy:

1. **No name drives an effect.** Every effect verdict traces to a witness: a
   claim witness, an observed state transition + transcript, or an indexed
   event. Name-substring classification stays banned (scoring inv. 2).
2. **Behavioral dedup key is the resolved function** (normalized resolved-IR
   hash; metadata-stripped whole-bytecode + selector for unverified), never a
   declared-name or file hash. The weETH `pauseUntil` override and the mixin
   default must hash differently.
3. **Cache scope matches verdict scope.** Function-local kernels key on the
   behavioral hash; contract-scoped projections (blast radius, authorization
   delta) key additionally on whole-contract identity; concrete values are
   never cache keys. First shared-hash pair is self-audited (§7).
4. **Value orders, never gates.** Every distinct behavior in the blank-gated
   set is simulated; transitive value-at-stake sets order only. Any resource
   cap that drops work must `log()` what it dropped.
5. **Transitive reach, not direct balance**, drives ordering; a control edge
   propagates full downstream value (conservative upper bound).
6. **Fail-closed, both sides:** non-observation ⇒ `unknown`; ambiguous/
   precondition revert ⇒ `unknown`; auth-open needs ≥2 succeeding random
   identities; raw-revert comparison only; sentinel failure never proves
   "fixed"; and missing evidence never improves the score — scored
   denominators come from static (§8 rule 8).
7. **Read-only, keyless:** `eth_call`/state-override/snapshot-revert only; no
   mainnet writes.
8. **Every verdict is tiered and replayable** from its transcript; the harness
   is pure given an injected call-batch and runs against stubbed wires in the
   offline suite.
9. **Both planes retained:** static keeps universals + candidate/param/identity
   generation; simulation adds existential witnesses. Matcher retirement is a
   later per-matcher decision, gated on strict domination + no universal claim.
10. **Duration/bound facts read from source constants** (e.g.
    `MAX_PAUSE_DURATION`), never hardcoded in the harness.
11. **Own lifecycle stage between `policy` and `coverage`** (§3a), per contract
    job, feature-flagged; never folded into `static`. The behavioral-hash cache
    is a persistent table shared across jobs and cross-chain twins; its key is
    code-plane only (no concrete values).
12. **Verdicts are gate-relative.** Cached verdict schema:
    `(behavior_hash, effect_class, gate_ref, verdict, tier, transcript_ptr)`;
    `gate_ref` names the gate structure, never a concrete address. Principal
    binding happens at read time by joining `function_principals` — the state
    plane stays out of the cache by schema, not by discipline.
13. **Tier 0 is historical.** An indexed event discharges a present-tense
    capability claim only in conjunction with a current-state check (§3).
14. **Capabilities are probed, not assumed.** `eth_simulateV1` support is
    checked per chain at stage init and persisted; recipes declare their
    Tier 2 fallback explicitly (§3 preflight). The fork's hardfork is pinned
    and recorded per transcript (§8 rule 7).
15. **Fail-forward stage, transition-gated flag.** The effects stage never
    emits `failed_terminal`: retry exhaustion ⇒ `unknown` verdicts +
    degraded marker + advance to `coverage` (§3a.3). Flag-off ⇒ `policy`
    advances directly to `coverage`; the flag gates the stage transition,
    not just worker processing (§3a.4).
16. **Single-flight fork.** Anvil snapshot/revert is process-global;
    production runs `PSAT_EFFECTS_JOB_CONCURRENCY=1`, and any future
    parallelism requires a per-chain fork mutex — concurrent snapshot users
    on a shared fork are a silent-corruption hazard (§3 preflight).

---

## Appendix A — measured funnel (etherfi, 2026-07-19)

Selection cascade over 756 protocol functions. Rows are independent filters
over the stated denominator — **not** a monotone funnel (691 > 406 because
they filter different things):

| stage | count | of |
|---|---|---|
| all functions | 756 | — |
| gated (not `authority_public`) | 406 | 756 |
| have state-write facts (`effect_targets`) | 691 | 756 |
| **blank (no claim) + facts + gated** — the simulation set | **265** | 756 |
| distinct selectors within that set (rough dedup proxy) | 198 | 265 |
| selectors touching a >$1M contract | 64 | 198 |
| selectors appearing *only* on sub-$1M contracts | 134 | 198 |

(Selector is a coarse proxy — it over-merges same-signature/different-behavior
overrides, so true distinct behaviors ≥ 198; the real behavioral-hash count is
what the harness computes.)

Validation targets confirmed in-set: `pause` / `unpause` / `pauseUntil` on
WeETH ($3.2B), EtherFiRestaker ($221M), LiquidityPool ($55M),
WithdrawRequestNFT ($53M), all `gated + facts + blank`.

Shared-identity evidence for dedup: `PausableUntil.sol` content hash `f6966b…`
byte-identical across 11 jobs; six money contracts share
`v0.8.27+commit.40a35a09`, opt on, 1500 runs, prague. Override hazard: mixin
`pauseUntil()` is `virtual onlyGuardian`, overridden for stricter gating on
eETH/weETH — the reason dedup keys on resolved-function behavior, not file.

## Appendix B — first experiment

The `PausableUntil` family is the natural first cut: one code shape, ~66–108
blank rows collapsing to ~2–3 distinct kernels, the simplest recipe (Tier 2
revert-set diff + time-warp), directly validating the approach against the
exact class static misses. Success criterion: the latch-flip **kernel**
verdict and auto-expiry bound become witnessed effects on the pause functions
that are blank today; the kernel transfers across the 11 sharing contracts;
the blast-radius **projection** is computed per contract surface and matches
static's predicted guard set (a mismatch is a §9 discrepancy to investigate,
not a harness failure); and the dedup self-audit confirms kernel agreement
while observing the expected projection divergence across surfaces.

The experiment doubles as the infra sizing measurement (§3 preflight): record
peak anvil RSS and upstream request counts through eRPC before sizing
production workers.

## Appendix C — key code references

- `services/static/contract_analysis_pipeline/effects.py` — facts plane
  (sinks, `state_writes`, `value_flows`, `is_parameter` taint). Untouched; it
  is the substrate.
- `services/static/contract_analysis_pipeline/summaries.py:_effect_labels` —
  fact-tier label projection (the layer that currently discards blank facts).
- `services/static/claims/matchers/pause.py`,
  `_facts.py:bool_write_targets` / `pause_targets` — the bool-only pause
  matcher and the `declared_type=="bool"` filter that misses ERC-7201.
- `services/resolution/differential_probe.py` — existing eth_call
  from-override authorization probe; the pattern the effect harness extends
  from "who can call" to "what happens when they do".
- `control_graph_edges`, `function_principals`, `contract_balances`,
  `upgrade_events` / `monitored_events` — ordering, identity, value, Tier 0.

---

# Implementation plan & orchestration rules (how to build this)

Status: written for a FRESH orchestrator session with no prior conversation
context — everything needed is this doc plus the repo. Untracked on purpose,
same convention as the multichain follow-up docs; the orchestration process
mirrors MULTICHAIN_RESIDUALS_FOLLOWUP.md / IMPL_RESOLUTION_CHAIN_FOLLOWUP.md.

> **AMENDMENT (2026-07-21) — Fable temporarily unavailable.** The user's
> Fable limit is exhausted for now, so for THIS build every agent (scouts,
> coders, and the Phase-3 reviewer) is pinned to `opus`. Wherever this plan
> calls for a Fable pass or a Fable-pinned reviewer, substitute **Opus 4.8 at
> `xhigh` reasoning effort** in the interim. **CIRCLE BACK:** once the Fable
> limit resets, re-run the single deep Phase-3 review (Agent structure below)
> with a genuine Fable-pinned reviewer over the whole accumulated diff before
> the PR is considered review-complete. Track this in the Progress log.

## Questions policy — ask ONCE, up front

Read this whole doc first. If ANY user input is genuinely needed, ask ALL
questions in a single message at the very beginning, then run autonomously.
Do not pause mid-flow for approvals — this doc pre-makes every known decision.

## Prerequisite state (verify before starting)

- **Branch: create `feat/effects-resolution` off current `main` HEAD.** ALL
  phases land on this ONE branch and ship as ONE PR (user decision — each
  push burns a preview deploy + ~30-min live suite of real credits; nothing is
  pushed until the whole plan is offline-verified).
- Docker postgres/minio up (`docker compose up postgres minio minio-init -d`);
  host Postgres port 5433. Project conventions: CLAUDE.md (test runners,
  netguard, marker-filtered suites, style).
- The local etherfi DB (protocol_id=1) behind Appendix A should exist. If
  absent, Phase 0 notes the gap and works from fixtures; do not block on it.

## Where things live (context a fresh session needs)

- `db/models.py` — `JobStage` (`:60`, insertion point between `policy` and
  `coverage`), `EffectiveFunction` (`effect_labels`/`effect_targets`, `:787`).
  Locate the stage-advance machinery by grepping `JobStage` usages in the
  worker/pipeline runner BEFORE editing — do not guess the progression table.
- `services/resolution/differential_probe.py` — the pattern every harness
  decision extends: injected `call_batch` seam, ≥2-random-identity rule,
  block-independence cross-check, recorded transcripts, and the
  `PSAT_DIFFERENTIAL_PROBE` default-off flag precedent.
- `utils/rpc.py:881` `eth_call_batch` — the wire wrapper to build on.
- Facts plane: `services/static/contract_analysis_pipeline/effects.py`
  (sinks, `is_parameter` taint), `summaries.py:_effect_labels`; claims plane:
  `services/static/claims/` registry + `matchers/_facts.py` (blankness
  semantics — what "no claim" means for the §6 cascade).
- Cross-job cache precedent: the code-plane source-hash cache (PR #155) and
  `bytecode_cache` — mirror their table + alembic conventions for the new
  cache tables. CI has an alembic drift gate; migrations must survive it.
- Ordering/identity/value inputs: `control_graph_edges`,
  `function_principals`, `contract_balances`, `upgrade_events` /
  `monitored_events`.

## Worker conventions — mirror the existing stage workers, don't reinvent

The effects worker is the sixth pipeline stage worker. Every scaffolding
decision is already made by `workers/base.py` and its siblings
(`policy_worker.py` is the closest model — RPC-bound, phase-timed). The
coder's job is a `process()` implementation, not a worker framework.

- **Shape:** subclass `workers.base.BaseWorker` in
  `workers/effects_worker.py`; `stage = JobStage.effects`,
  `next_stage = JobStage.coverage`; module logger
  `logging.getLogger("workers.effects_worker")`; runnable as
  `python -m workers.effects_worker` (same `__main__` pattern as
  siblings); launched from `start_workers.sh` (the `workers` Fly process
  group), single instance per inv. 16.
- **Inherited for free — do NOT reimplement:** lease-based claim,
  stale-job reclaim, the background job-heartbeat thread, SIGTERM
  graceful lease release, the `[BOOT]` banner (stage + RSS + cgroup),
  `StageErrors` attempt history, and per-stage in-process concurrency via
  `PSAT_<STAGE>_JOB_CONCURRENCY` — which is exactly where inv. 16's
  `PSAT_EFFECTS_JOB_CONCURRENCY=1` plugs in. Override `process()` only;
  no custom `_claim_job` (effects needs no readiness predicate —
  coverage's is the exception, not the pattern).
- **Trace context:** `BaseWorker._execute_job` already binds
  `trace_id`/`job_id`/`stage`/`worker_id` (+chain) via
  `bind_trace_context`, and all logs are JSON via
  `utils.logging.JsonFormatter` into Loki. Consequence: log through the
  module logger inside `process()` and correlation comes free; never
  print, never build bespoke log records.
- **Phase timing:** wrap each `process()` sub-step in
  `utils.logging.log_timed_phase`, the canonical facility shared with
  `static_worker`/`resolution_worker`/`policy_worker` (see the phase-timing
  convention comment at the top of `policy_worker.py` — its motivation, the
  opaque 780s job, applies verbatim to fork probes). Expected phases, one
  per pipeline step: `preflight`, `selection`, `cache_lookup`,
  `tier1_probes`, `tier2_fork`, `verdict_write`. Durations fold into the
  `stage_timing` artifact the monitor UI reads.
- **Stage metrics:** counters via `utils.logging.record_stage_metric`,
  same artifact: candidates in/after cascade, cache hits/misses
  (kernel vs projection), verdicts by tier, discrepancies filed, upstream
  request count, peak anvil RSS. These are how the user's post-push
  checklist items 4–5 get read.
- **Degradation:** the inv. 15 fail-forward path uses the existing
  mechanism — `utils.logging.record_degraded` accumulating `StageError`
  entries onto the job row — never a bespoke marker. Per-behavior probe
  failures are caught *inside* `process()`, recorded degraded with
  `unknown` verdicts, and the loop continues to the next behavior; an
  exception escaping `process()` is reserved for whole-stage infra
  failure.
- **Error classification:** escaped exceptions route through
  `workers/retry_policy.classify` — type-only, never message substrings.
  New transient shapes this stage introduces (anvil spawn failure, fork
  RPC timeout) are added to the type tuples there, inheriting the standard
  backoff (30s base, 5 retries). Inv. 15 composes on top: whatever
  `classify` says, the *outcome* of exhaustion (or a terminal verdict) for
  this stage is degrade-and-advance, never `failed_terminal`.
- **Fleet visibility:** pipeline stage workers do NOT register in
  `services/monitoring/process_meta.py:PROCESS_META` /
  `worker_heartbeats` — that roster is for drainers/daemons/watchers.
  Effects is visible the way policy is: jobs table, job heartbeats, boot
  banner, `stage_timings`. Do not invent a fleet entry.

## Phasing (each phase = suite green, committed, resumable)

Same convention as MULTICHAIN_INVARIANTS.md phasing: a phase is DONE only
when the full offline suite is green on committed state and the Progress log
below is updated. Three coding phases after the reality check, sized so each
is ONE dispatch wave with a verifiable done-state. Do not subdivide further:
the per-phase check is a light orchestrator diff pass; the single deep Fable
review happens once, at the end of Phase 3. Token economy is deliberate —
exactly FOUR Opus coder dispatches and ONE reviewer for the whole build.

### Phase 0 — reality check (scouts only, no code)

The spec's references and numbers are from 2026-07-19 and could drift.

1. **Opus scouts** (pinned `opus` explicitly) confirm every Appendix C
   reference and every structural assumption the phases lean on (JobStage
   advance mechanism plus a sweep of ALL other `JobStage` literal
   consumers — `deferred_reconciler.py`, `routers/jobs.py`, `db/queue.py`,
   aggregations/fleet — for stage-shaped assumptions the new enum member
   could break; effects.py fact shapes; the differential-probe seam;
   claims blankness semantics) at branch HEAD; classify each REAL / DRIFTED
   (with corrected location). Structural drift is REPORTED before work
   proceeds; the phase plan is adjusted, not forced.
2. Re-run the Appendix A funnel queries against the local DB; if counts
   drifted, update Appendix A in the first commit (data drift is fine;
   structural drift is a finding).
3. **Capture the flag-off baseline:** run an existing end-to-end offline
   integration fixture and record artifact hashes — the comparison object for
   Phase 1's parity test.
4. **Decide anvil-in-CI:** check whether foundry/anvil exists in the CI
   images (`.github/workflows/`). If not, local-anvil tests get an auto-skip
   marker and CI relies on transcript stubs.

**Exit:** assumptions confirmed/corrected, baseline captured, anvil decision
made, Appendix A refreshed if drifted (commit only if it changed). Progress
log updated.

### Phase 1 — foundations (two parallel Opus coders; zero behavior change flag-off)

Goal: everything schema- and static-side the harness needs, provably inert
with the flag off. Two coders, file-disjoint:

**Coder 1a — identity + schema + stage** (sole owner of `db/models.py` +
alembic this phase):
- §7 hash ladder items 1–3 in a new `services/effects/` package (normalized
  resolved-IR hash: override resolution + internal-callee inlining +
  name/literal stripping; metadata-stripped whole-runtime-bytecode hash +
  selector fallback; source-content fast path with its soundness
  precondition). NO bytecode-region lifter (§7 item 4 is explicitly out).
- Alembic migration: `effect_behavior_cache` (kernel key = (behavior_hash,
  effect_class); projection rows additionally carry contract_surface_hash;
  value = gate-relative verdict per inv. 12 + tier + transcript pointer
  (an artifact-store key per §8.5, never inline JSONB) + self-audit
  bookkeeping) and `effect_verdicts` (per contract-function state-plane
  residue: concrete destinations, current-check results). Additive only.
- `JobStage.effects` between `policy` and `coverage`; `PSAT_EFFECTS_STAGE`
  flag, default-off, gating the `policy` → `effects` *transition* itself
  (flag-off: policy advances straight to `coverage`, per §3a.4 / inv. 15);
  fail-forward retry semantics per inv. 15 (exhaustion ⇒ `unknown` +
  degraded + advance, never `failed_terminal`); worker skeleton mirrors the
  "Worker conventions" section exactly (BaseWorker subclass, `__main__` +
  `start_workers.sh` entry, `log_timed_phase` phases, `record_stage_metric`,
  `record_degraded`, `retry_policy.classify` additions);
  `PSAT_EFFECTS_JOB_CONCURRENCY` default 1 per inv. 16.

**Coder 1b — selection + ordering** (new `services/effects/selection.py`
only): §6 cascade (sink non-empty → blank-claim set only → gated preferred) +
transitive value-at-stake ordering (control-graph closure, conservative
full-value propagation); no value gate; the resource safety-valve `log()`s
exactly what it drops.

**Phase tests:** weETH-override-vs-mixin hashes differ (inv. 2); immutable
masking recovers hits; unverified fallback; migration up/down + drift gate;
**flag-off parity** — the Phase 0 baseline fixture reruns byte-identical
(artifact-hash compare); flag-on zero-candidate pass-through; flag-off
transition skip (policy advances straight to coverage, no effects stage row);
fail-forward exhaustion (forced retry exhaustion ⇒ `unknown` verdicts +
advance, never `failed_terminal` — inv. 15); lifecycle ordering; the
$33K-Safe-controls-$3.2B case sorts above direct-balance order (inv. 5);
dropped-work logging (inv. 4).

**Exit:** full offline suite green on committed state; parity proven;
Progress log updated.

### Phase 2 — the harness (one Opus coder, Tier 1 then Tier 2)

Goal: every recipe produces tiered, transcripted verdicts against stubbed
wires. One coder — Tier 1 and Tier 2 share the harness files, so this is
sequential within a single dispatch, not two.

- Tier 1 core: injected `call_batch` (§8.6); `eth_simulateV1` preflight
  probed + persisted per chain (inv. 14); identity selection from
  `function_principals`; ≥2-random-identity rule; raw-revert comparison;
  precondition-revert → `unknown`; transcript emission (tier + forked block +
  calls + raw results).
- Recipes 4.2–4.5: 4.3 (Tier 0 current-state conjunction + sentinel with
  transparent/UUPS stubs), 4.4 kernel, 4.2 (three-valued shape;
  sentinel-failure → `unknown` + §9 discrepancy; static-proof path for fixed
  shapes), 4.5.
- Tier 2: anvil transport behind an injectable interface (same seam
  discipline as `call_batch`); hardfork pin assert + transcript record
  (§8.7); the 4.1 pause recipe (snapshot → pre-pause succeeding set →
  impersonate + call → revert-set diff → time-warp by source-read
  `MAX_PAUSE_DURATION` → expiry re-probe); the denominator rule joins
  static's predicted guard set (§4.1, §8.8).

**Phase tests:** recorded-transcript stubs per recipe; one negative
fail-closed test per §8 rule (including `registry[param]` sentinel-negative →
`unknown`, bare-sentinel-reverts-proves-nothing, single-identity-never-opens);
a localhost NON-FORKING anvil integration test with checked-in precompiled
fixture bytecode iff Phase 0 allowed it (auto-skip when anvil absent);
netguard untouched.

**Exit:** suite green on committed state; Progress log updated.

### Phase 3 — integration, review, gate (one Opus coder, then close-out)

Goal: wire it end-to-end behind the flag and prove the invariants.

- Coder: cache lookups/writes with kernel-vs-projection scope (inv. 3);
  self-audit on first shared-hash pair (kernel-match assert; projection
  divergence expected, not a failure); verdict persistence to
  `effect_verdicts` + state-plane residue to contract rows; §9 disagreement
  routing into the warning channel with closing-rule bookkeeping; the §10
  invariant-sweep test module (1–16, mirroring the MULTICHAIN_INVARIANTS
  inv-test precedent); full `process()` observability per the "Worker
  conventions" section (all six named phases timed, stage metrics
  populated, degradations via `record_degraded`); **monitor-page stage
  integration** in `site/src/pages/jobStages.js` (+ `PipelineDashboard` /
  `JobDetailPanel` and their tests): `effects` added to `CORE_STAGES`,
  `JOB_STAGE_ORDER`, and `STAGE_COLORS` (the runs-table progress bar
  becomes 7 segments); `METRIC_LABELS` entries for the effects metrics
  catalog so drill-in chips render labeled and ordered instead of falling
  to the raw-key tail; and the stage timeline must NOT synthesize an
  eternal NOT-REACHED `effects` row for flag-off/historical jobs —
  presence-based rendering only (the row appears when the stage shows up
  in the job's server timings or the job actually passed through it).
  Tests: kernel transfers across a twin fixture;
  projection does NOT transfer across different surfaces; self-audit catches
  an injected hash collision; both §9 directions.
- Close-out, run by the orchestrator: the Fable review (Agent structure
  below) over the whole diff; fix findings; the full gate checklist; final
  commit; deliverable.

**Exit:** gate green, deliverable written, Progress log complete. Everything
after this is the user's post-push preview cycle.

### Phase 4 — recipe wiring: prober synthesis + `anvil_factory`, interleaved with live validation (added 2026-07-21)

**Why this phase exists.** Phases 0–3 shipped the *substrate* (stage, cache,
self-audit, persistence, monitor) and the *recipe library* (all five recipes +
the Tier-1/Tier-2 transports), all offline-tested. But the production worker
still classifies **only Tier-0 code-upgrade**: `default_prober`
(`services/effects/orchestrator.py`) returns `[]` for every non-proxy-upgrade
candidate, and `effects_worker.py` sets `anvil_factory=None`. So an ordinary
flag-on run produces **no** pause / value-out / supply / authority verdicts —
the recipes sit uncalled. This was the documented MAJOR-1 deferral: the missing
piece is the **per-class calldata + entry-point synthesizer** (turn static facts
— param types, taint, sinks, resolved principals — into concrete probe calls),
plus turning `anvil_factory` on. It was deferred because it **cannot be validated
offline** — only live chain/fork state proves whether synthesized args satisfy a
real contract's non-pause preconditions (a live run on 2026-07-21 confirmed this:
raw `transfer`/`mint` calls on eETH reverted on rate-limiters/balances; only a
1-wei `transfer` from the WeETH holder succeeded, yielding the blast radius).

**Development style: same as Phases 1–3.** Opus coders as subagents (pinned
`opus`), orchestrator gate, per-phase offline suite green + committed, one PR on
`feat/effects-resolution`, no push, Fable review substituted by Opus 4.8 @ xhigh
until the limit resets (see 2026-07-21 amendment). Difference from the original
build: this phase **interleaves offline coding with a small LIVE validation
loop** run by the orchestrator (the coder builds offline-testable code; the
orchestrator validates a handful of functions live, feeds failures back). This
is a NEW budget beyond the original "four coders + one reviewer".

**Scope — one Opus coder builds the offline-testable core:**
1. **Per-class calldata synthesizer** (new `services/effects/calldata.py`, a PURE
   function over static facts — offline-testable against recorded fixtures, no
   wire): for a `Candidate` + its facts, emit the concrete probe inputs each
   recipe needs. Uses the facts plane already present (`effects.py` sinks/
   value_flows; `summaries.py:461/:498` `is_parameter` taint — Phase-0 finding),
   ABI param types, and resolved `function_principals`.
   - **4.2 value-out (Tier-1):** function calldata with valid default args; the
     taint-identified address param filled with the attacker sentinel; principal
     = resolved caller.
   - **4.5 supply / 4.4 authority (Tier-1):** calldata to call F as the principal;
     supply reads `totalSupply` pre/post; authority re-runs the who-can-call probe.
   - **4.1 pause (Tier-2, the hard one):** pause selector; blast-radius entry
     points = static's predicted `whenNotPaused`/guard set; for EACH entry point
     synthesize calldata that SUCCEEDS pre-pause. Because real contracts gate
     these on more than pause (rate limits, balances, blacklists, allowances),
     the synthesizer must (a) pick valid args from param types/taint, and (b)
     where a precondition needs state, set it up on the fork via anvil cheatcodes
     (`anvil_setBalance`, `anvil_setStorageAt`) — a "fork fixture" helper. Read
     `MAX_PAUSE_DURATION` from source (inv. 10). The observed blast radius is a
     LOWER bound (§4.1); entry points that stay unwitnessed are fine — the scored
     denominator remains static's set.
2. **Wire `default_prober`** (or a new prober) to call the synthesizer and emit a
   `ProbePlan` per applicable class for each candidate (not just Tier-0).
3. **Turn on `anvil_factory`** in `effects_worker._make_seams`: build the fork
   transport `SubprocessAnvil(fork_url=require_rpc_url(chain_id=cid),
   fork_headers=rpc_headers(fork_url), hardfork_name=<per-chain>)` — **eRPC
   must-dos (from the 2026-07-21 eRPC review):** source `fork_url` via
   `require_rpc_url`/`erpc_url_for_chain_id` and `fork_headers` via
   `rpc_headers(fork_url)` — NEVER hand-assemble the header dict (single source
   of truth; a local/explicit fork URL correctly gets no secret). Single-flight
   (inv. 16): one fork per run per chain, snapshot/revert between contracts.
4. **Offline tests** for the synthesizer (recorded-fact fixtures → expected
   calldata/entry-points; sentinel-in-right-slot; pause fork-fixture setup) and
   for the prober emitting the right plans per class. The wire stays stubbed;
   netguard untouched.

**Live validation loop — ORCHESTRATOR ONLY, conservative RPC (the "few functions,
tiny cost" rule):** After each offline-green iteration, the orchestrator validates
against live state using the **eRPC in `.env`** (`require_rpc_url` + `rpc_headers`;
`ERPC_SECRET` never printed), mirroring the 2026-07-21 run:
- **A handful of functions only (≤~5), never a full run**; ONE forking anvil per
  session, snapshot/revert reused; tiny amounts (1 wei) to slip under rate
  limiters; impersonate the RESOLVED principal (`function_principals`) with
  `anvil_setBalance`. Hand-verify each verdict against the real Solidity source
  (pull from MinIO `source_files.storage_key`, bucket `ARTIFACT_STORAGE_BUCKET`).
- **Known gotchas (measured):** `eth_getLogs` returns empty through this eRPC
  endpoint — find holders via known wrappers (WeETH holds eETH) / `balanceOf`
  probing, not logs. Verify the fork's method mix (`getStorageAt`/`getProof`/
  `getCode`) actually routes through eRPC to a full-node upstream (hyperrpc
  can't serve them) — if a fork silently fails, that's the eRPC-routing risk,
  not the code. anvil bypasses the invariant-7 chain-id guard, so construct the
  fork URL via `erpc_url_for_chain_id` at the source.
- **Still-open (track, don't block):** spec §3 "distinct client tag" for cost
  attribution is unimplemented (all traffic uses the `main` eRPC project
  segment); note it for an eRPC-config follow-up.
- A live-validated verdict that disagrees with source is a coder feedback item,
  not a merge; loop until the handful classify correctly (kernel + blast radius +
  auto-expiry for pause; shape for value-out; delta for supply).

**Exit:** synthesizer + prober + `anvil_factory` landed; offline suite green on
committed state; the small live-validation set (incl. ≥1 pause on a money
contract) classifies correctly and is hand-verified against source; Progress log
updated; the §3 client-tag + eRPC routing items recorded. Full-protocol runs and
the sizing measurement remain the user's post-push preview cycle — NOT this phase.

### Resuming a partial run

A fresh session picks up by: (1) reading the Progress log below; (2)
confirming it against `git log --oneline main..feat/effects-resolution`;
(3) re-running the full offline suite — a phase counts as done only if it is
green NOW. Never redo a completed phase; never start a phase whose
predecessor isn't green; on any mismatch between the log and git history,
trust git and correct the log first.

## Phase 0 findings (2026-07-21, four Opus scouts + orchestrator, at HEAD 146edff)

Reality check complete. Verdict: **all structural assumptions confirmed;
Appendix A zero-drift; three benign reference/flag drifts to fix in Phase 1;
one CRITICAL migration mechanic and one worker↔flag coupling hazard surfaced.**
None forces a phase-plan restructure — Phase 1 absorbs each as a concrete task.

**Anvil-in-CI decision: anvil IS available in CI.** The offline test job installs
`foundry-rs/foundry-toolchain@v1` (`_ci-checks.yml:132`, before the test step
:188) and runs `forge --version` — so `anvil`/`cast`/`forge` are on PATH in the
same job that runs `pytest -m "not live"`. anvil 1.5.1-stable is also present
locally. ⇒ A localhost **non-forking** anvil integration test (Phase 2) can run
in CI, not just skip. Still gate it behind an anvil-availability probe so a fresh
clone without foundry auto-skips rather than errors. A FORKING anvil / real RPC
stays user-only (netguard, hard env rule) — unchanged.

**Appendix A drift: NONE.** All seven funnel counts reproduce exactly against the
local `psat` DB (protocol_id=1): 756 / 406 / 691 / 265 / 198 / 64 / 134. Scoping
is simply `effective_functions ef JOIN contracts c ON c.id=ef.contract_id WHERE
c.protocol_id=1` (no run/job column; the DB holds one clean pr-153 preview set).
"blank" = `jsonb_array_length(claims)=0`. All 12 validation targets (pause/
unpause/pauseUntil × WeETH/EtherFiRestaker/LiquidityPool/WithdrawRequestNFT) are
gated+facts+blank as documented. PausableUntil `f6966b…` byte-identical across
11 jobs confirmed at the content-hash level. **No Appendix A edit made.**

**Flag-off baseline captured** (Phase 1 parity comparison object). Fixture:
`tests/test_policy_worker_integration.py::TestProcessStoresAllArtifacts::test_all_three_artifacts_stored`
— runs `PolicyWorker.process()` fully offline (heavy internals stubbed →
deterministic). Confirmed GREEN at HEAD, edge `next_stage = JobStage.coverage`,
3 artifacts, sha256 stable across two runs:
- `effective_permissions`  = `1f4ded7e9220b252f9b976e728b89834abb9efb2dc50072b2792ce97e06a7e6c`
- `resolved_control_graph` = `ae1197b205261339940fff4060d5530716627dd728ad99417396f33347964d29`
- `principal_labels`       = `4819eb558b145332ec3815cba846a43974b60138b0c8b446b1835d56494c8d89`
Capture method: sha256 of `json.dumps(payload, sort_keys=True, default=str)` per
stored artifact. Phase-1 flag-off parity must reproduce this exact set AND keep
`policy.next_stage == coverage` when `PSAT_EFFECTS_STAGE` is off. Companion guard
`tests/test_pipeline_integration.py::test_worker_stage_chain_is_complete` hard-
asserts that edge (:1485) — the coder MUST update it for the flag-dynamic edge.

**Reference verification (Appendix C / "Where things live") — 3 DRIFTS to fix
in Phase 1, everything else REAL at the cited lines:**
- **Ref 1 (correction):** `_extract_value_flows` + the `is_parameter` taint are
  in `summaries.py:461`/`:498`, **not** `effects.py`. `effects.py`'s own
  value-flow fn is `_value_flow_facts` (:574) whose `ValueFlow` TypedDict has NO
  `is_parameter`. The §4.2 "attacker controls value target" selector must read
  **summaries.py's** `value_flows` (dict key written at summaries.py:716), and
  note its `is_parameter` means "dest/token var is itself a fn param," slightly
  narrower than "address-typed param reaching a sink."
- **Ref 4 (inverted precedent):** `PSAT_DIFFERENTIAL_PROBE` now **defaults ON**
  (`getenv(..., "1")` at `differential_probe.py:73`). The spec repeatedly cites
  it as the "default-off flag precedent" — it is no longer. `PSAT_EFFECTS_STAGE`
  should still ship default-OFF (design intent); just don't mirror the sibling's
  current default. All other §seam refs REAL: `call_batch` param :356, ≥2-random
  identities `_RANDOM_IDENTITY_COUNT=2` :64 / `derive_random_identities` :232,
  block-independence `_block_independence_delta` :76, transcript field :90.
- **Ref 6 (no `sinks` column):** `EffectiveFunction` (db/models.py:787) has
  `effect_labels`:796, `effect_targets`:797, `authority_public`:799 (gated),
  `claims`:806 (blank signal) — but **no `sinks` column**. §6 "sink non-empty"
  must use `effect_targets` non-empty (the model has it) or join the effects
  artifact; it cannot read a `sinks` column. Ref 2 (`_effect_labels`
  summaries.py:423) is REAL but now only projects value-flow/selector/sink-kind
  labels (semantic labels moved to the claims registry) — imprecise, not wrong.
  Refs 3/5/7 exact: `_facts.py` bool filter REAL; `eth_call_batch` utils/rpc.py
  :881 REAL; control_graph_edges/function_principals/contract_balances/
  upgrade_events/monitored_events all present with the columns the ordering/
  identity/Tier-0 inputs need.

**Blank-set predicate (RESOLVED for §6):** gate on `claims`, not `effect_labels`
(the latter is a downstream projection of the former). Phase-1 selection:
`array_length(effect_targets,1)>0 AND (claims IS NULL OR jsonb_array_length(claims)=0) AND authority_public=false`.

**JobStage insertion — structural map (Phase 1 must land these together):**
- `JobStage` (`db/models.py:60`) is a `str, Enum`, ordered by source declaration;
  `_satisfy_dependencies` (`workers/base.py:939-941`) uses *relative* enum order
  → **safe** if `effects` is inserted between `policy` and `coverage`. No separate
  ordered progression table; ordering = per-worker `stage`/`next_stage` attrs +
  enum order.
- Advance mechanism: `workers/base.py:430-441` → `advance_job` (`db/queue.py:783`)
  sets stage+queued; `claim_job` (`db/queue.py:653`) drains **stage-exact**;
  `reclaim_stuck_jobs` (`db/queue.py:207`) rescues only `status='processing'`.
  ⇒ **park-forever risk is REAL:** a `stage=effects, status=queued` job with no
  effects worker is never swept (matches §3a.4). Worker must be spawned before
  the flag flips.
- **CRITICAL migration:** `jobstage` is a NATIVE PG enum. Adding a value needs
  `ALTER TYPE jobstage ADD VALUE 'effects' BEFORE 'coverage'`, run
  **non-transactionally** (autocommit block) — precedent
  `alembic/.../c94ca0f7f0b2_*.py:56-60` (`ADD VALUE IF NOT EXISTS 'failed_terminal'`).
  Not a plain column add; the additive dep-table enum mirror survives it
  (`create_type=False`).
- **Flag gates the EDGE, coupled to topology:** `PolicyWorker.next_stage`
  (`workers/policy_worker.py:353`) is a fixed attr; make it flag-dynamic
  (`effects` when `PSAT_EFFECTS_STAGE` on, else `coverage`). Enabling the flag
  without spawning the effects worker parks every job. Wire the worker into
  `start_workers.sh` (~:98/:116), `start_workers_light.sh`, `start_workers_heavy.sh`,
  and `start_local.sh:20` `WORKER_PATTERN`.
- **Latent bug to fix now:** `_convert_impl_job_to_proxy_context`
  (`db/queue.py:856-861`) has a non-exhaustive stage tuple `(resolution, policy,
  coverage, done)`; add `JobStage.effects` or an impl job at `effects` won't
  rewind to static on late proxy linkage.
- Benign: frontend `site/src/pages/jobStages.js:11,16` (`CORE_STAGES`/
  `JOB_STAGE_ORDER` + `STAGE_COLORS`/`METRIC_LABELS`); segment count auto-derives
  (no hardcoded 6). `deferred_reconciler`, `routers/jobs.py`, `routers/fleet.py`,
  done-state checks all SAFE.

**Worker conventions — all REAL & inheritable** (`workers/base.py`): lease claim,
stale reclaim, background heartbeat, SIGTERM release, `[BOOT]` banner,
`StageErrors`, `PSAT_<STAGE>_JOB_CONCURRENCY`; `process()` sole override;
`_execute_job` binds trace. **Default retry-exhaustion outcome = `failed_terminal`**
(`base.py:524-526`) — the effects stage MUST override to degrade-and-advance
(inv. 15). `retry_policy.classify` is type-based; new transient types (anvil
spawn, fork RPC timeout) → `_TRANSIENT_TYPES` tuple (:82-95); backoff base 30s,
5 retries. `utils/logging` symbols all present (`log_timed_phase`,
`record_stage_metric`, `record_degraded`, `bind_trace_context`, `JsonFormatter`).
**Minor drift:** the per-stage artifact key is `stage_timing_<stage>` (i.e.
`stage_timing_effects`), metrics under a `metrics` key, phase durations
`phase_ms_<phase>` — not a single `stage_timing`/`stage_timings`. **Naming:** use
`effects` as canonical (§3a's "simulation"/`stage_timing_simulation` is stale).

**Cache-table pattern to mirror:** `ContractMaterialization` (`db/models.py:1260`)
+ helper `db/contract_materializations.py` (find/upsert, `pg_advisory_xact_lock`
coalescing, `ANALYSIS_SCHEMA_VERSION` bump-to-invalidate); simpler precedents
`BytecodeCache` (:1356) and `MappingEnumerationCache` (:1319). Migration
precedents: `e7a4f1d63b29`, `ccfe335ed565`, `f1a2b3c4d5e6`. New tables need model
+ migration to pass the CI alembic drift gate.

## Progress log (orchestrator: update as each phase completes)

- [x] Phase 0 — reality check (2026-07-21). Notes: anvil-in-CI decision =
      **anvil available in CI** (foundry-toolchain@v1 in offline job) — non-forking
      anvil tests may run, gated behind availability probe; forking/real-RPC stays
      user-only. Appendix A drift = **none** (all 7 counts exact). Baseline
      captured (hashes above). 3 benign ref/flag drifts + CRITICAL native-enum
      migration + worker↔flag coupling documented above for Phase 1. Findings
      committed; Appendix A unchanged so not re-committed.
      **FABLE CIRCLE-BACK (per 2026-07-21 amendment): Phase-3 review ran on Opus
      4.8 @ xhigh while Fable was unavailable — re-run with a real Fable reviewer
      once the limit resets. [ ] not yet done.**
- [x] Phase 1 — foundations (2026-07-21). Two parallel Opus coders (1a schema/
      identity/stage; 1b selection/ordering), file-disjoint. Landed: §7 hash
      ladder items 1–3 (`services/effects/hashing.py`, no lifter); migration
      `d8f3a1c02e47` (`effect_behavior_cache` + `effect_verdicts`, native-enum
      `ADD VALUE 'effects' BEFORE 'coverage'` autocommit); `JobStage.effects`;
      default-off `PSAT_EFFECTS_STAGE` gating the policy→effects edge (flag-
      dynamic `PolicyWorker.next_stage` property); inert fail-forward
      `EffectsWorker` (6-phase scaffolding) wired into all start_workers*.sh +
      start_local.sh; `retry_policy` transient types; `db/queue.py:856` latent-
      bug fix; `services/effects/selection.py` (§6 cascade keyed on `claims` +
      transitive value-at-stake, no gate, safety-valve log). base.py seam
      `_finalize_terminal_failure` (behavior-preserving) enables inv. 15.
      GATE: full offline suite green (4298 passed after allow-list line fix in
      test_log_level_contract.py — a benign shift from 1a's property insert),
      ruff/format clean, pyright clean on all touched+new files, alembic drift
      gate clean. Flag-off parity proven (Phase-0 baseline sha256s reproduce
      exactly). Commit: the single "Effects resolution Phase 1: …" commit on
      `feat/effects-resolution` (verify via `git log --oneline main..HEAD`).
- [x] Phase 2 — harness (2026-07-21). ONE Opus coder. Pure injectable library
      under `services/effects/` (worker left inert — additive-only, flag-off
      parity intact by construction): `simulate.py` (eth_simulateV1 seam),
      `harness.py` (Tier-1 core: injected call_batch, ≥2-identity + block-
      independence, raw-revert compare, precondition→unknown, transcript emit),
      `preflight.py` (inv. 14 capability probe via injectable CapabilityStore —
      no DB table, boundary-preserving), `recipes.py` (4.2 value-out three-valued
      + sentinel→unknown/§9 discrepancy, 4.3 code-upgrade Tier-0-conjunction +
      transparent/UUPS sentinel stubs, 4.4 authority kernel, 4.5 supply),
      `anvil.py` (Tier-2 behind injectable AnvilTransport; `SubprocessAnvil` =
      sole real I/O, non-forking loopback default; hardfork pin + anvil/foundry
      version in transcript; 4.1 pause recipe = revert-set diff + source-read
      `MAX_PAUSE_DURATION` time-warp; denominator from static). Seams: one real-
      I/O impl each (eth_call_batch, eth_simulate_v1, SubprocessAnvil, injected
      TranscriptStore). TESTS: transcript-stub per recipe 4.1–4.5; one negative
      fail-closed test per §8 rule 1–8 + inv.14 + sentinel cases (registry-param
      →unknown, bare-sentinel-proves-nothing); gated non-forking real-anvil
      integration test (checked-in fixture, runs under CI's foundry-toolchain,
      auto-skips without anvil). GATE: full offline suite green (4327 passed, 44
      xfailed), ruff/format/pyright clean on all new files, alembic drift clean
      (no new migration). NO Phase-3 work done (no cache r/w, self-audit,
      persistence, §9 routing, monitor page — worker still inert). Commit: the
      single "Effects resolution Phase 2: …" commit (see `git log main..HEAD`).
- [~] Phase 3 — integration + review + gate (2026-07-21). CODING DONE (one Opus
      coder); REVIEW + final gate in progress. Landed: `effects_worker.process()`
      fully wired (6 phases, injectable seams built lazily from job.request, zero-
      candidate touches no wire); `db/effect_cache.py` (kernel keys on behavior
      hash / projection additionally on contract_surface_hash, inv. 3;
      pg_advisory_xact_lock coalesce) + `effect_verdicts` state-plane persistence;
      §7 self-audit (first shared-hash pair; disagree ⇒ withhold + poison key);
      `services/effects/discrepancies.py` §9 routing both directions via the
      existing `record_degraded`/stage_errors warning channel + closing-rule
      bookkeeping; `services/effects/orchestrator.py` (injectable `Prober` seam,
      conservative `default_prober` = code-upgrade Tier-0 only — Tier-1/Tier-2
      per-class calldata synthesis is the preview follow-up, recipes fail closed
      on thin inputs); monitor-page: `effects` in CORE_STAGES/JOB_STAGE_ORDER/
      STAGE_COLORS/METRIC_LABELS, presence-based timeline (no eternal not-reached
      row), no visual-baseline change; `tests/test_effects_invariants.py` (§10
      sweep 1–16) + cache/worker-integration tests. Coder-reported gates:
      backend 4359 passed, frontend npm 412 + playwright 26e2e/4visual, ruff/
      pyright/alembic-drift clean. DEVIATIONS (documented, review to adjudicate):
      default_prober conservative; behavioral hash uses §7 item-2 bytecode
      fallback (no cheap Slither IR); ProbeContext.block=0 (Tier-0-only inert).
      REVIEW DONE: Opus 4.8 @ max-rigor (Fable unavailable — Agent tool has no
      effort param, so xhigh could not be set literally; RE-RUN with real Fable
      on reset per amendment). Found 1 CRITICAL (Tier-0 historical code-upgrade
      verdict was code-plane cached and would transfer across bytecode twins
      without each deployment's current-state check — inv. 13 / §7 violation)
      → FIXED: `_is_cacheable` now excludes `TIER_HISTORICAL` (Tier-0 is state-
      plane, lives only in `effect_verdicts`) + added state-divergent-twin
      regression test. 2 MAJORs are DISCLOSURES not blockers: (M1) production
      wires ONLY Tier-0 code-upgrade — pause/value-out/authority/supply + Tier-2
      are tested-but-dormant library code, so Appendix B pause witnesses arrive
      only with the preview Tier-1/2 calldata-synthesis follow-up; (M2) pause
      recipe bundles kernel into the projection verdict (no kernel transfer
      across the 11 sharers) — moot in V1, follow-up. Flag-off parity re-verified
      by RUNNING (baseline sha256s match). Commits: Phase-3 code + review-fix
      commit (see `git log main..HEAD`). Deliverable delivered: yes (final
      report in-session).
- [x] Post-P3 live validation (2026-07-21). Drove the shipped `pause_recipe`
      against a LIVE mainnet fork via the eRPC in `.env`: pause KERNEL flips
      `paused()` 0→1 as the resolved principal; blast radius + auto-expiry
      (30-day time-warp) PROVEN on eETH; `eth_simulateV1` confirmed supported
      through eRPC (inv. 14). Caught + fixed a real gap: `SubprocessAnvil` passed
      no fork auth header, so a forking anvil could not authenticate to eRPC —
      added `--fork-header` passthrough (commit `5ad9ed6`, eRPC-reviewed
      FOLLOWS-CONVENTION). Confirmed the MAJOR-1 gap concretely: production wires
      only Tier-0; the per-class calldata synthesis is real remaining work →
      **Phase 4**.
- [ ] Phase 4 — recipe wiring (prober synthesis + `anvil_factory`), interleaved
      with live validation. See the Phase 4 section above. Commits: ____.

## Agent structure

- **You (orchestrator/gate)** run Phase 0, dispatch coders, do a light diff
  sanity pass per phase (not a deep review — that happens once, below), run
  the final gate, and commit. If you are a Fable session, you are the gate.
- **Coders: Opus subagents — exactly FOUR dispatches for the whole build**
  (1a, 1b, 2, 3 per the phasing). Pin the model EXPLICITLY to `opus` on every
  spawn — an unpinned spawn silently inherits the session model and is a
  defect. 1a/1b are the only parallel pair (file-disjoint by construction).
- **Review: ONE Fable-pinned reviewer** (see 2026-07-21 amendment above —
  while Fable is unavailable, run this reviewer as **Opus 4.8 at `xhigh`
  effort**, and re-run it with a real Fable reviewer once the limit resets),
  spawned fresh at the end of
  Phase 3, over the whole accumulated diff (`git diff main..HEAD`) vs this
  spec: per-invariant closure (1–16), fail-closed audit of every recipe in
  BOTH §8 directions, no name-driven verdicts, cache-scope audit (no
  projection transferring on a function hash), worker-conventions
  conformance (BaseWorker scaffolding reused — any bespoke claim/retry/
  logging/heartbeat code in `effects_worker.py` is a finding), flag-off
  parity verified by RUNNING it. Reviewers verify by running (targeted tests, greps), not just
  reading; they may spawn Opus scouts (pinned explicitly) but never Fable.
- Trust subagents' reported pass counts; the gate runs the full suite once on
  the final state.
- Coders sharing the working tree use per-agent isolated test DBs/buckets:
  `PGPASSWORD=psat psql -h localhost -p 5433 -U psat -d postgres -c "DROP
  DATABASE IF EXISTS psat_test_<x>;" -c "CREATE DATABASE psat_test_<x> OWNER
  psat;"`, then `set -a; source .env; set +a;` plus
  `TEST_DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test_<x>`,
  `TEST_ARTIFACT_STORAGE_BUCKET=psat-artifacts-test-<x>`,
  `PSAT_LLM_STUB_DIR=tests/fixtures/scope_extraction/llm_responses`, and
  `-p local_netguard` on the pytest command; never the shared `psat_test`.

## Branch / commit / push

- All work on `feat/effects-resolution`; ONE PR eventually.
- **Commit access: yes. Push/PR access: NO** — the user pushes; pushes are
  batched deliberately.
- At least one commit per phase (more is fine); single-line commit messages
  in repo style. NO AI-attribution trailers/footers on commits or PR text,
  ever.

## Hard environment rules

- NEVER run live tests (`pytest -m live`), the local backend server, or
  anything that hits real paid APIs. Allowed: offline suite + docker
  postgres/minio, `npm run dev` (frontend only, not expected here).
- **Anvil rule (new for this work):** a localhost NON-FORKING anvil (no
  external network) is permitted in tests, subject to the Phase-0 CI
  decision. A FORKING anvil, or any real RPC endpoint, is NEVER run by
  agents — the Appendix B real-fork experiment is the user's post-push
  preview step, not yours. Never weaken netguard to accommodate a test.

## Gate checklist (CI-faithful, before the final commit)

1. `uv run ruff check .` && `uv run ruff format --check .`
2. `uv run pyright` — clean except pre-existing exclusions.
3. Fresh test DB (`DROP DATABASE IF EXISTS psat_test; CREATE DATABASE
   psat_test OWNER psat;` on localhost:5433, docker services up), then the
   full offline suite exactly as CI runs it:
   `PSAT_LLM_STUB_DIR=tests/fixtures/scope_extraction/llm_responses uv run
   python -m pytest -m "not live" -p local_netguard -q`
4. **Alembic drift gate** — migrations ARE expected here (Phase 1); run CI's
   drift check.
5. Frontend: `cd site && npm test` and `npx playwright test`. Frontend
   changes ARE expected, confined to the monitor-page stage integration
   (`jobStages.js`, `PipelineDashboard`, `JobDetailPanel` + their tests).
   If /monitor visual baselines change, regenerate per CLAUDE.md
   (`--update-snapshots`, Linux/WSL only — never macOS) and commit the
   snapshots. Any visual diff OUTSIDE /monitor (Surface, app pages) means
   something is wrong — stop and report.

## Test rules

- The suite is netguard-hermetic; all new wire-touching code ships offline
  stubs (recorded transcripts, the differential-probe pattern).
- Greenfield analogue of test-first: every §8 soundness rule and every §10
  invariant carries an explicit test — fail-closed/negative paths included —
  written WITH its phase, never backfilled in Phase 3. Anything claimed as a
  fix to EXISTING code needs the standard fails-before capture.
- Editing existing tests: representation updates and fixture/helper signature
  extensions fine; no assertion-intent rewrites, no deletions.

## Deliverable

Structured final report: Phase-0 verdicts (per reference/assumption, with
evidence); per-phase diff summary + commit SHAs; every test file touched
with justification; exact gate results (suite counts, ruff/pyright, alembic,
frontend); an invariant-closure table (1–16, each with the test or evidence
that closes it); anything deliberately not done and why; and the user's
post-push preview checklist below, updated with anything learned.

## User post-push validation checklist (preview cycle — NOT the agents' job)

1. Deploy with the effects worker added to `start_workers.sh` FIRST, then
   enable `PSAT_EFFECTS_STAGE` in the preview environment; run etherfi.
   (Flag before worker = jobs advance into a stage nobody drains and park.)
2. Preflight recorded per chain (`eth_simulateV1` support persisted for
   ethereum + base).
3. Appendix B criteria: pause kernels witnessed on the four validation
   targets; blast-radius projection matches static's predicted guard set
   (mismatch = §9 discrepancy to triage, not a rollback); auto-expiry bound
   recorded from source constants. Validate by direct DB query — v1 is
   write-only per §3a; nothing surfaces in the app UI except the /monitor
   stage row.
4. Cache: kernel hit across the 11 `PausableUntil` sharers; self-audit row
   present and passing; no projection transferred across distinct surfaces.
5. Sizing: peak anvil RSS + upstream request counts through eRPC recorded
   (the §3 preflight measurement). 16GB workers make RSS headroom rather
   than a go/no-go; record it for attribution and to validate the §3 cost
   verdict's request estimate.
6. §9 channel: the bool-pause static-positive/sim-negative case, if it fires,
   lands as a warning with the discrepancy attached — not a dropped label.
7. Flag-off prod path unaffected (no stage rows, no timing metrics, parity
   with pre-branch behavior).
