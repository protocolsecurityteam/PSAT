# Scoring Invariants

Design constraints for the protocol-score rework. The current model
(`site/src/protocolScore.js`) and the sketch in `SURFACE_UX_FIX_PLAN.md` §2 are
both superseded by whatever satisfies this list — the plan's findings survive
as evidence, its proposed implementation does not.

Grounded in the local DB (etherfi, protocol_id=1, queried 2026-07-19). The
measured facts behind each invariant are in Appendix A; the short version:
value is 90% concentrated in one contract, one Safe gates 135 functions across
23 contracts, proven audit evidence exists for ~7% of coverage rows, and there
are 12 EOA-gated functions sitting on >$10M contracts — including
`withdrawEther` (claim `flow.out`) on a $221M contract. A good score makes
*that* the headline; the current one buries it under coverage penalties and
name-heuristic noise.

---

## A. What may be scored (epistemics)

### 1. Three-valued logic: proven-good / proven-bad / unknown

Every atomic assessment lands in exactly one of three states, and **unknown
contributes zero to the grade** — it is neither penalty nor credit. Unknowns
roll up into a separate *confidence* figure (inv. 6), never into the score.

- Corollary (ordering): unknown must never rank below proven-bad. The current
  model scores `pre_fix_unpatched` (proven vulnerable) at 0.25 and no-data at
  0.00 — banned by construction, not by spot-fix.
- Corollary (audits): a contract with 8 real audits that we couldn't
  bytecode-match is *unknown*, not 0. Today 18/36 contracts score identically
  whether never-audited or 5-firm-audited (plan §2.2).

### 2. Every scored item has a witness

A deduction or credit must trace to a verifiable fact: a claim with a witness,
a resolved principal with on-chain config (Safe threshold/owners, timelock
delay), a bytecode-equivalence proof, an indexed event. **Name-substring
classification is banned** (`getImplementation()` scored as a severity-1.0
upgrade is the canonical failure). A function with no claims is *unknown* —
it lowers confidence, it does not get a guessed severity.

- **Audits: only the deterministic core is admissible.** A `proven` row is a
  two-part chain and the parts have different trust: (a) the matched sha
  appears **verbatim in the audit PDF** (regex,
  `source_equivalence.py:extract_reviewed_commits`) and deployed source is
  **deterministically equivalent** to repo@sha — hard, and self-validating
  since a hallucinated sha can't match deployed code; (b) the commit *role
  labels* — reviewed scope vs fix vs cited (`classified_commits`) — are
  **LLM-labeled** and hallucinatable. Only (a) may touch the grade, and the
  most it proves is "this audit document references the exact deployed
  code" (a modest credit). Everything built on (b) — including
  `pre_fix_unpatched`, `clean`-vs-`cited_only`, findings, scope, firm — is
  confidence-layer and review-queue material until it gains a
  document-level witness (e.g. a deterministic "fixed in `<sha>`" phrase
  match in the PDF, never an LLM label).
- **Severity facts need witnesses too.** "EOA can trigger `flow.out`" does
  not establish theft: EtherFiRestaker's `withdrawEther` provably hardcodes
  the LiquidityPool as destination, so the proven finding is *operational
  routing power*, not extraction. Deduction severity may only use the proven
  component (destination-arbitrariness, amount bounds, target whitelists);
  the unproven remainder is a confidence gap, not a bigger deduction.
- **`value_router` is static-only, by design — its absence of a fork verdict is
  not a coverage gap.** A routed flow is one the entry caused a *different*
  contract to make by calling it. The entry is neither the source nor the sink,
  so there is no "did value leave *this* contract" for a fork probe to answer,
  and a sentinel planted in the router's ABI would have to land at the *callee's*
  sink to prove anything. A scorer must therefore **not** treat a missing
  `effect_verdicts` row on a `value_router` claim as unresolved evidence, and
  must not discount the claim for lacking one.
  - The direction covers a second shape with the same property: an ERC-20 pull
    in which **neither** party is the analyzed contract (a bridge fee the caller
    pays straight to the endpoint). No contract boundary is crossed, but the
    entry is still neither source nor sink, so the same "nothing for a fork probe
    to answer" reasoning applies. Read `from_is_self` to tell an inbound route
    from an outbound one — a routed claim is not evidence that this unit's assets
    left it.
  - Little is actually lost. The risk of a routed flow lives in the callee, and
    the callee's own function is a candidate in its own right — probed where it
    executes, as itself, with its own principals. The router adds reachability
    ("can this entry get there"), and the dangerous case of that — a route the
    callee provably guards out, e.g. a hardcoded zero amount against
    `if (amount > 0)` — is settled statically and cheaply, with no probe.
  - The bar for revisiting: define what a router verdict *asserts* first. The
    round that added routed flows shipped 16 that could not execute, so a probe
    whose semantics are undecided is a new way to be wrong, not a new witness.
- Data check: only 332/1395 effective functions carry claims today. That 76%
  gap is a confidence number, not 76% of fabricated severities.

### 3. Score capabilities held by principals, not function names

The scoring unit is the **(capability, principal) pair**: who can do what.
Permissionless user-facing functions (`erc20.*`, redeem/deposit flows) are the
product working — they contribute nothing negative (plan §2.3's 81
false-negative examples). Public functions are only findings when the
capability itself is privileged-shaped (upgrade, arbitrary exec, role grant)
and provenly reachable by anyone.

### 4. Dual-use capabilities are scored from both sides

Every credited protective power is also an attack surface against the same
bar. An EOA that can pause is fast emergency response *and* one key that can
freeze $221M — it cannot appear only as a green positive (the current
`buildPauseTooltip` bug). If the model credits a mitigation, it must also
evaluate who controls the mitigation.

## B. How findings compose (aggregation)

### 5. Weakest-path composition; no dilution by averages

Risk composes along control paths as the *weakest link* (min), and the
composite must let **a single catastrophic path fail the grade**. Thirty clean
contracts must not average away a 1/5 Safe with upgrade power over the money
contract. Conversely, severity ordering bounds the other direction: one minor
config finding cannot zero the score.

- If an authority is reachable by two paths, the score uses the weaker one. A
  timelock in front of a 1/1 Safe earns nothing if the Safe can act directly
  (anti-gaming, see inv. 13).

### 6. Grade and confidence are two numbers, never blended

The grade answers "how safe is what we proved?"; confidence answers "how much
did we prove, weighted by value?". The DATA axis — PSAT grading its own
scraper inside a box labeled SECURITY — is the anti-pattern. Confidence is
first-class output ("grade B, assessed over 94% of tracked value") and must be
**monotone in resolution work**: analyzing more can only raise it, so we can
distinguish "protocol got safer" from "we learned more".

- **Third channel: warnings.** Adverse signals that fail the witness bar
  (LLM-only evidence, name-inferred behavior, unresolved principals on
  sensitive-shaped functions) are surfaced as explicit warnings labeled with
  their weakness — "unverified; may be a data-collection gap on our end" —
  never silently dropped and never scored. Each warning carries what would
  promote it to a ledger row (the missing witness) or clear it.

### 7. Value-at-stake scales weight — transitively, on a log scale, with a floor

A finding's weight scales with the USD value it can reach through the control
graph: funds held by the contract itself, plus funds in anything it can
upgrade, drain, or administer (closure over `control_graph_edges`, proxy
admin links, and principal→contract edges).

- Transitive is mandatory, not optional: the top Safe holds ~$33K but gates 23
  contracts including the $3.2B one. Direct-balance weighting scores it as
  dust.
- Log-scaled bands, not raw USD: with 90% of value in one contract, linear
  weighting makes every other finding invisible; and TVL fluctuation must not
  whipsaw the grade.
- Floor: a rug-shaped capability on a currently-empty contract that users
  transact through still scores. Value scales weight; it never gates
  existence of a finding.

### 8. Explicit scoring perimeter

The set of scored entities is a deterministic, defined function of the data —
protocol-attached contracts plus anything that transitively controls
protocol value — not "whatever discovery returned rows for". The DB holds 618
contract rows, 197 protocol-attached, 34 with function analysis; the 68-vs-36
and 36-vs-33-dup confusions are perimeter bugs. Scoring must be idempotent
over duplicate rows (aggregate over `(chain, address)` entity keys).

## C. Traceability (the score explains itself)

### 9. Exact decomposition: score − Σ itemized findings = 0

The composite decomposes exactly into per-finding contributions. Every point
lost cites (contract, capability, principal, value-at-stake, witness); every
point earned cites the protective fact (4/7 Safe, 10-day timelock, clean
proven audit). No residual "model smell" term. This is what makes the score a
product instead of a number: "−12: `withdrawEther` on EtherFiRestaker ($221M)
is gated by a single EOA" is the actual etherfi headline.

### 10. Counterfactual actionability

For every deduction the system can state the change that removes it ("move
`withdrawEther` behind the 4/7 Safe: +N"). If we cannot say what would fix a
finding, it isn't well-defined enough to score. This is also the alerting
product: score deltas are diffs of finding sets, so "B→D because the timelock
was removed from upgrade paths" falls out for free.

## D. Stability and comparability

### 11. Pure function of (persisted inputs, model_version)

Computed in the backend at end-of-pipeline, persisted with `model_version`,
recomputable byte-identically from stored inputs. History retained: "why was
etherfi a C in June" is answerable by replaying the June inputs. Frontend is
purely presentational.

### 12. Re-analysis without on-chain change is a no-op

Re-running the pipeline against an unchanged chain state yields the identical
score: no dependence on discovery order, dedup races, or which cross-chain
twin row won. Every score delta maps to either an on-chain change or a
`model_version` bump — this is what makes score-change alerts trustworthy
rather than noise.

### 13. Invariance to code factoring (anti-gaming)

The score is unchanged by how a protocol splits or merges contracts if the
(capability, principal) set is unchanged — no per-contract count
normalization that rewards monolith deployment or contract splitting. More
generally: publish the rules such that the only way to move the score is to
change actual capability/protection facts. Decoy mitigations (inv. 5's
bypassed timelock), inert renounced functions, or shuffling code between
files must all be no-ops.

### 14. Cross-protocol comparability

Axes mean the same thing for a 3-contract protocol as a 60-contract one, so
the fleet view ("all protocols, sorted by grade") is meaningful. Grade
thresholds are fixed by the model version, not renormalized per protocol.

### 15. Incremental by construction: the score is a fold over a findings ledger

Findings are persisted per `(chain, address)` entity. Analyzing or
re-analyzing a contract upserts only that entity's ledger rows; the composite
and confidence are a cheap deterministic fold over the ledger — never a
whole-protocol recomputation. Consequences:

- **No thrash during progressive analysis.** Because unknown contributes
  zero (inv. 1), a newly analyzed contract moves the *grade* only if it
  carries proven findings; otherwise it only raises *confidence*, which is
  monotone. Mid-pipeline partial states cannot bounce the letter grade.
- **Alerts are ledger diffs.** "B→D" comes with exactly the finding rows
  that appeared/changed, for free. Grade transitions get hysteresis at the
  alert layer, not by fuzzing the score itself.
- Update cost is O(changed entity) + one fold; score history is the ledger's
  append log, which also satisfies inv. 11's replayability.

## E. Faithfulness to available evidence

### 16. No abstraction above an available witness

**AMENDED 2026-07-30** after a nine-lane validation round against the same
snapshot (see B0b). The principle survived; the text did not. What changed: a
testable definition of "consume", normativity moved from the observed corpus to
the producing code contract, one obligation split into four checkable clauses,
and a stability clause added. What was withdrawn: one of the three cited
discriminators, which is itself a `not_determined` field.

Where a witness exists that discriminates a scored quantity, the scorer **must
consume that witness** rather than substitute a coarser proxy. Using a
contract-level aggregate, a per-`claim_id` constant, or a category default in
place of an available row-level fact publishes a precision the evidence does not
support — the same *family* of error as name-inference (inv.2), in whichever
direction the proxy happens to point. The exception is the floor inv.7 requires:
a directional-honest floor is not a proxy for a fact, it is the admission that
the fact is missing.

**What "consume" means.** Reading a column is not consumption, and a normative
register needs a testable obligation. Every REQUIRED entry in Appendix B carries
one or more of four, and conformance is judged against those and nothing else:

- **(a) gate** — must gate the admissibility of a named sibling field.
- **(b) arithmetic** — must enter a severity, weakness, or magnitude computation.
- **(c) cite** — must appear on the published finding row (inv.9).
- **(d) three-state** — must be represented as proven-present / proven-absent /
  `not_determined`, never defaulted, collapsed, or inferred from an absence.

A field carrying none of the four is not REQUIRED; it is CONFIDENCE. `claims[].tier`
is (c)+(d) and explicitly **not** (b) — it says how likely the claim is to be the
*right claim*, not how bad the capability is if the claim is right. Multiplying a
severity by a reliability factor publishes "this is a smaller harm" when the honest
statement is "this may not be the harm". A tier may **withhold** an escalation that
needs a behavioural existence proof (a non-`behavioral_observed` claim must not
reach `caller_arbitrary` severity; `policy_derived` must *block* the B2 static
conjunction); it may never raise anything.

**What "discriminates" means.** A field discriminates iff some reachable state of
it — **including its absence** — would change a published number, a polarity, or a
third state. The test is over the field's domain as its *producer* defines it,
never over the values one corpus happened to emit. `reach_tvl_check` is 41/41 with
one value and fails the test; `input_seeded` is `true` on 39/39 and passes it,
because its absence is a different fact.

**Boundary with inv.1.** inv.1 quantifies over *assessments*; inv.16 quantifies
over the scalars inside one. A proven-`caller_arbitrary` `flow.out` whose reach is
undetermined is not an unknown — it is a proven-bad finding with an undetermined
weight, and inv.7's floor governs it. Therefore:

- A **proven lower bound** on a magnitude is a positive fact, admissible **as a
  floor**: it may raise a weight, never cap one, and must be published with its
  direction (`>= $908,232`), never as a point value.
- Where the *polarity* of the assessment is undetermined, inv.1 wins and the
  contribution is zero.
- A weight floored for want of a witness must still publish the magnitude that
  *is* proven. `value_at_stake_usd: $0` on a finding whose witness proves
  `>= $908,232` is an inv.9 defect even where the weight was already at the band
  floor.

Four separately-testable obligations. `proto-0.1` violated three; `proto-0.2`
still violates 16c — which is why one invariant with one verdict is not enough. A
scorer can claim conformance on one shape while violating another, and
`proto-0.2`'s fix to 16a *introduced* a fresh 16a defect (B1/G2).

- **16a — right entity.** The scored quantity must be the quantity the witness
  measures, about the entity the finding is attributed to. `sweepETH` was priced at
  its contract's whole $471,980 balance while
  `witness.observed.observed_reach_value_usd = 90.97` sat in the same row — a
  5,188× over-valuation. A capability's magnitude is what the witness says it can
  move, never the balance sheet of the thing it lives on. The *fix* can fail 16a
  too: reach is a **holder-closure**, not a contract bound (B1/G2). The entity key
  is `effective_functions.deployment_address` (the runtime address) with **MAX per
  (holder, asset)** — never `SUM` per `contracts` row, which double-counts a proxy
  against its implementation.
- **16b — no constant where a discriminator exists.** `pause.set` carried a flat
  `0.35` across 36 claims while the `pause.unset` recovery principals — resolved on
  all 30 contracts carrying a `pause.set` claim, and per-key rather than
  per-contract — discriminated it completely. A per-`claim_id` constant is
  admissible only for the residue no witness speaks to, and B12 names claim types
  where that is exactly the case. **The symmetric error is worse: the fix must not
  reach for a discriminator that only looks like one.** The first draft of this
  clause cited `duration_bound_source` as "available and discriminating"; it is
  `not_determined` on all 4 rows and B11/T-INDEF says nothing may be concluded from
  it either way, so that citation is **withdrawn**. `pause_effective` and
  `observed_blast_radius` exist on 4 of 36 and cannot speak to the other 32. Cite
  the discriminator that covers the population.
- **16c — monotone in a proven ordinal.** Every `resolved_type='timelock'`
  principal scored weakness `0.15` while `details->>'delay'` is populated on
  **139/139** timelock rows with three distinct values (10d/5d/2d). A 2-day and a
  10-day delay are not the same protection and the difference is proven data. The
  witness supplies the *ordering*, not the *mapping*: the mapping is a model choice
  and must be published with the model version, and an unpopulated delay takes the
  `not_determined` branch rather than the constant. A numeric consequence of
  adopting a monotone weakness function may not be quoted before the function is
  defined — B4b's "~7.35 raw of double-count" spans +0.29 to −10.41 grade points
  depending on an undefined `f(quorum, delay)`.
- **16d — direction-safety.** A consumption that can only *lower* a proven finding
  is not automatically safe; it is safe against over-claim and unsafe against
  under-claim, and under-claim is live (B10.9). A lowering field may fire only on
  its proven-present state. Absence of a lowering witness is `not_determined`, not
  a licence to lower.

Corollaries:

- **A proxy must be directional-honest.** If a witness is absent and a proxy is
  unavoidable, the proxy may not manufacture a positive fact. Absent a reach
  witness on a proven-`caller_arbitrary` flow, the amount is *unknown* — floor
  the weight, publish the proven bound, and warn; do not publish the balance sheet
  as the amount at risk.
- **Bounds are bounds, not point values.** A reach figure accompanied by
  `observed_reach_unvalued_pairs` is a **lower** bound, not an upper one. Treating
  a partial reach as exact is an unproven positive.
- **Proof-strength fields gate their own payload.** `verdict`, `tier`,
  `shape_proved_by`, `reach_determined`, `membership_quality` and
  `amount_kind.tier` each say how strongly the sibling field is established.
  Consuming a payload without its strength gate reads `shape_proved_by='none'`
  as if it were `'simulation'`. **A strength gate not published alongside its
  payload does not discharge this** — B11/T-ACCESSOR's 33 rows publish
  `exact`+`enumerable`, the maximum strength, and record the convention only in
  `details->'trace'[*].basis`.
- **An absence is not a witness, and a mutable now-fact is not an invariant.**
  Publishing a proven negative from a missing row, a missing claim, or a missing
  event requires (i) proof that the recording surface covers the question — for
  event absence, that *every* topic which can write the variable has a warm cursor
  — and (ii) the observation block, so the claim is bounded in time. A capability
  two transactions from being re-enabled is "currently unreachable, re-enablable
  by \<principal\>" with a counterfactual (inv.10), never a dismissal.
- **Consuming more witnesses must not destabilise the grade (inv.12, inv.6).**
  Many of these fields record whether a *probe ran*, not what the chain says:
  `shape_proved_by` flips `none` → `simulation`, `pause_effective` appears, an
  `effect_verdicts` row moves `unknown` → `proven`, all with nothing on-chain
  changed. Fork observations are not even taken at one block (51 distinct blocks in
  the observed run), and `contract_balances` is destructively rewritten every
  monitoring cycle. So every REQUIRED field needs a pinned absence branch
  (`not_determined` → confidence), and a witness *appearing* on a rerun raises
  confidence; it may move the grade only if the newly proven fact is itself
  adverse. A scorer whose grade moves because the pipeline got luckier violates
  inv.12 however faithfully it consumed the new field.
- **The register in Appendix B is normative — as a contract with the producing
  code, not as a census of one corpus.** A scorer that ignores a field, gate, or
  **recomputation** listed there as REQUIRED is non-conforming, and adding a
  coarser substitute for one is a regression even if the aggregate grade looks more
  plausible. But the obligation attaches to the field's *documented producer
  semantics*, which is what every entry was traced to (B14) — never to its
  population on `protocol_id=1`. Two consequences: a documented field that is 0/N
  here is REQUIRED-when-present, including the eight `observed` keys B12 records as
  absent on this run (each verified present in both the projection allowlist and
  the producer); and a low population forbids **calibrating** a rule to the
  observed values, which is what B14's under-5 list means — it does not license
  ignoring the field. Any rule justified by "correct in principle, net-harmful on
  this corpus" must be re-argued on principle or moved upstream as a claim-layer
  defect (inv.14).

---

## Appendix A — what the local data says (etherfi, 2026-07-19)

> **SUPERSEDED WHOLESALE, 2026-07-30 — do not cite figures from this appendix.**
> Every A-vs-B conflict the validation round checked resolved in Appendix B's
> favour. A is a 2026-07-19 snapshot and its headline numbers are wrong on the
> current data: the corpus is **1,168 rows / 478 with claims / 541 claims** (not
> 1395 / 332); balances are **721 rows over 60 balance-carrying contracts totalling
> $4,159,585,666** (not "$3.5B across 21"); WeETH holds **$3,502,642,106 = 84.2%**
> (not $3.17B / 90.4%); **EtherFiRestaker holds $467,568,890, not $221M** — which
> means inv.9's own worked example ("−12: `withdrawEther` on EtherFiRestaker
> ($221M)") must be restated; the timelocks gate **75 / 53 / 11** functions and
> there are **three** of them, not two; and "12 EOA-gated functions on contracts
> >$10M" is **10**, two of which A counts again in a separate bullet. A's
> `pauseUntil` bullet ("no claims / fixing the matcher precedes any pause scoring")
> is also stale — four `pauseUntil` functions carry fork-proven `pause.set` claims
> with blast radii. See B0b/S4 and B0b/R12. Kept for its *reasoning*, which
> survives; its numbers do not.

Facts a candidate design should be tested against:

- **Value concentration:** $3.5B across 21 balance-carrying contracts; WeETH
  holds $3.17B (90.4%). Per-contract averaging is meaningless (→ inv. 5, 7).
- **Authority concentration:** Safe 4/7 `0x2aca...8adc` gates 135 functions
  across 23 contracts; timelocks 10d (`0x9f26...`) and 2d (`0xcd42...`) gate
  81 and 51. The natural attribution unit is the principal (→ inv. 3, 9).
- **Proven negatives already in the data:** 12 EOA-gated functions on
  contracts holding >$10M, including `withdrawEther`, `stEthClaimWithdrawals`,
  `depositIntoStrategy` (all claim `flow.out`) on EtherFiRestaker ($221M),
  and EOA `pauseUntil` on three contracts (→ inv. 4, 9). Source inspection
  (MinIO artifact) shows the Restaker flows are **fixed-destination**
  (`_withdrawEther` → `liquidityPool`, `depositIntoStrategy` → whitelisted
  EigenLayer strategies): operational power, not extraction — the
  destination fact must become a claim witness (→ inv. 2).
- **Single-key freeze surface — currently NOT witnessable:** the
  1/5-threshold Safe (`0x4279...2ee3`) gates exactly
  `pauseUntil`/`blacklistUserUntil` on 13 contracts including WeETH, and
  three EOAs hold `pauseUntil` too — but every `pauseUntil` row has
  **empty effect labels and no claims**. "It pauses" is name-inference,
  inadmissible under inv. 2, so this ships as a warning until the detector
  gap below is fixed (→ inv. 4, 6).
- **Pause detection is bool-flag-only and mostly blind here:**
  `claims/matchers/pause.py` + `_facts.pause_targets` only match a `bool`
  state-write consumed as a mandatory revert gate. Etherfi's
  `PausableUntil` mixin writes a `uint256 pausedUntil` **timestamp** into
  an ERC-7201-style keccak-slot struct, gated by a `block.timestamp`
  comparison — invisible twice over. Measured: 25/30 `pause()` rows, 24/24
  plain `unpause()` rows, and the whole `pauseUntil` family (11 contracts)
  carry no pause claim. Fixing this matcher precedes any pause-related
  scoring. Bonus severity facts once witnessed: `pauseUntil` is bounded
  (8h–30d, auto-expiring, 7d per-pauser cooldown) — materially softer than
  an indefinite freeze, and the duration bound belongs in the witness.
- **The blank-label problem is a projection gap, not a facts gap.**
  **RESTATED 2026-07-28 (Wave 3 D1) — the original figure conflated two
  different facts.** It read: *"260/756 protocol functions (154/406 gated ones)
  have machine-proven state-write facts (`effect_targets` populated) but empty
  labels and empty claims"*. **`effect_targets` populated is not a proven state
  write.** The field is a display list that concatenates state-write variable
  names with dotted external-call heads (`effects._effect_targets_from_sinks`),
  and **501 of its 1,642 populated rows carry only call heads** — on the local
  protocol-1 slice, **156 gated functions** have a populated `effect_targets`
  with no state-write sink under it at all. The proven fact lives in the W0-6
  columns (`state_writes` / `sinks` / `state_changing`), which is what
  `services/effects/selection.py` filter (a) now reads.
  Re-measured on the current local snapshot (protocol 1, 1,179 rows; the
  original 260/756 was an earlier snapshot), the blank-label population is
  **345 rows, 234 of them gated**, and it splits three ways rather than one:
  **219 carry a projected proven state write** (195 of the gated ones)
  and **126 carry no state-write evidence at all** (39 gated): 84 are
  rows whose derived writes the view-contradiction rule withheld (L-15) and 42
  are not covered by an effects record in this projection. **0 are proven
  write-free**, because a call-head-only row earns the `external_contract_call`
  label and so leaves the empty-label population by that route — which is why
  the original criterion looked sound and was not. The *conclusion* below
  (ERC-7201 namespaced storage is the biggest cluster) survives; the
  *criterion* does not, and any recount must use the evidence columns:
  e.g. `invalidateRequest` provably writes the `_requests` mapping; only
  the *semantic* reading ("voids user withdrawals") is unwitnessed. Root
  cause of the biggest cluster: **ERC-7201 namespaced storage**. The top
  blank write-targets are `PAUSABLE_UNTIL_STORAGE_SLOT` (66),
  `PAUSABLE_STORAGE_SLOT` (42), and a tail of `*StorageLocation`
  pseudo-vars — the facts layer records slot writes but matchers consume
  only plain typed state-var writes (`bool_write_targets` requires
  `declared_type == "bool"`), so the entire modern OZ-v5/etherfi
  namespaced-storage world is invisible to Plane 1. Slot constants are
  deterministic (`keccak256(keccak256(id)-1) & ~0xff` +
  `@custom:storage-location` annotations + struct layout in source), so
  slot→(namespace, member) resolution is a witness-grade fix, not a
  heuristic.
- **Change management is provably strong:** 24/27 contracts with
  `upgrade.implementation` claims are timelock-gated (10d/2d); 3 are
  Safe-gated; `RoleRegistry`'s upgrade path is unresolved (unknown →
  confidence, and its transitive reach is large since it defines roles) and
  `UpgradeableBeacon` resolves to a plain contract principal (→ inv. 7).
- **`pre_fix_unpatched` is NOT grade-admissible:** the 5 such rows (EETH,
  EtherFiAdmin, EtherFiNodesManager, EtherFiOracle, WithdrawRequestNFT)
  rest on LLM commit-role labels ("a fix commit exists that wasn't
  deployed") — hallucinatable, so they route to the review queue and the
  confidence layer, not the ledger (→ inv. 2). The hard core that survives
  on all 95 proven rows: deployed code ≡ a commit sha printed verbatim in
  the audit document.
- **Proven positives already in the data:** WeETH ($3.17B) is gated
  exclusively by {safe, timelock}; Safe thresholds/owners and timelock delays
  are fully resolved for the top principals (379 safe rows with details, 135
  timelock rows).
- **Audit evidence is sparse but real:** 1,219 coverage rows; 90 clean+proven
  +high-confidence, 5 `pre_fix_unpatched` (proven adverse), 12 `cited_only`;
  722 are low-confidence `hash_mismatch` — i.e. *unknown* dominates, so
  unknown-as-zero poisons any audit axis (→ inv. 1).
- **Claims coverage:** 332/1395 functions have claims; claim vocabulary
  already distinguishes user flows (`erc20.*`) from privileged capability
  (`upgrade.implementation` 51, `exec.arbitrary` 9, `roles.grant`,
  `authority.replace`) (→ inv. 2, 3).
- **Unknown set is small at the sensitive end:** only 12 sensitive-effect
  non-public functions have no principal rows and aren't `resolved_empty` —
  driving confidence to ~100% is feasible (→ inv. 6).
- **Transitive resolution is half-done:** 54 distinct contract-type
  principals; 26 are themselves analyzed contracts, so principal→contract
  closure has data to walk today (→ inv. 7).
- **Perimeter:** 618 contract rows / 197 protocol-attached / 34 with function
  analysis; 3 duplicate-address rows inflate UI counts (→ inv. 8).

---

## Appendix B — Mandatory witness field register (inv.16)

Field-level specification of what a conforming scorer must represent. Measured on
the local replica of the PR-161 observed run (`protocol_id=1` / etherfi,
2026-07-30) by three independent read-only audits, each of which read the
*producing code path* for every field it recommends. Corpus: 1,168
`effective_functions` rows / 478 with ≥1 claim / **541 claims** / 32 distinct
`claim_id` / **165 distinct JSON paths** under `claims[]`; 274 `effect_verdicts`;
1,200 `function_principals` (870 with `details`); 721 `contract_balances`; 209
`audit_contract_coverage`; 290 `controller_values`; 80 `indexed_event_cursors`.

**REQUIRED** = must be consumed. **GATE** = must be consumed as a precondition on
a sibling field. **CONFIDENCE** = real, not grade-admissible (inv.6). **BANNED** =
must not be used as a witness. Population counts are `populated / applicable`.

### B0. Corrections to the first draft of this appendix

The first draft of this register was written before the audits reported and got
four things wrong. Recorded because the errors are instructive, not just to
retract them:

1. **`flags[].var = 'PAUSABLE_UNTIL_STORAGE_SLOT'` does NOT witness a bounded
   pause.** The first draft claimed it "structurally proves the timestamp-expiry
   mixin". Reading `UNTIL` out of a variable name is **name-substring
   classification on a variable name — banned by inv.2**, and it is the same
   error the register exists to prevent, committed while fixing it. Measured
   refutation: the string appears on **12 `pause.unset` claims and ZERO
   `pause.set` claims** — it is not even present on the side that would need it.
   See B11/T-FREEZE.
2. **`observed_reach_unvalued_pairs` does not undermine F1.** The first draft said
   reach is "a lower bound on 5 rows", implying the scorer's flagship read is
   unsafe. The three-state is clean: of 43 rows, **38 `reach_determined=true`
   (all 38 carry `observed_reach_value_usd`, none carry priced/unvalued keys)** and
   **5 `false` (none carry `observed_reach_value_usd`, 3 carry
   `observed_reach_priced_usd`, 5 carry `unvalued_pairs`)**. F1's substitution is
   safe. The real defect is different — see B1/G2.
3. **The proven blast-radius denominator is `scored_denominator`, and the register
   must not treat `effect_verdicts` as a trove.** All **69** `verdict='proven'`
   rows are faithfully projected into claims and all **205** `unknown` rows are
   orphaned by design. The table is mostly *not* a source of unused fact.
4. **Safe independence was mis-framed.** The first draft said the 1/5-vs-4/7
   overlap "was never computed". It is computable directly from the proven
   `details->'owners'` arrays, and the answer is that they **share 5 owners** —
   but that does *not* retract the freeze recovery credit. See B4/R-OVERLAP.
   **↳ SUPERSEDED by B0b/R1: the non-retraction is false.**

### B0b. Corrections from the validation round (2026-07-30)

Nine independent read-only lanes re-measured this register against the same
snapshot, partitioned to avoid overlap: inv.16 critique; B2 lattice; B1+B8 value;
B5 earned negatives; B4+B4b principals; B3+B6+B7+B9+B10; B11+B12 traps; a
dedicated adversarial refuter; and the coverage gap B14 admits. Unlike the round
that produced this register, **five lanes probed on-chain** (eRPC, every call
pinned to an explicit block, M7 runtime-address rule applied and empirically
validated) and two fetched deployed source from MinIO.

**Where B0b and a table row disagree, B0b governs.** Nothing below is deleted from
the tables; the errors are instructive and several are the register committing the
defect it exists to prevent.

**Headline: the measurement layer held; the inferential layer did not.** Nearly
every population re-measured to the row, every quoted code line was verbatim or
near-verbatim, and the on-chain probes vindicated the pipeline's witnesses at a
rate the B0 record would not predict (50/50 on the Solmate folds, 22/22 on
`owner()==0x0`, 22/22 on the one-shot latch slots, 3/3 on `getMinDelay()`, 9/9 on
Safe threshold+owners, and the anti-decoy fold clean on all three timelocks). What
failed is a specific class: **the step from a measured field to a published
positive fact.** Of the register's eight headline moves, six convert a
`not_determined` into a proven positive, and that is where the validation was
thinnest.

#### S1. The one structural finding — proof strength is computed, then discarded

Three separately-reported defects are one pattern: **this pipeline derives a
proof-strength gate, uses it correctly in-process, and then drops it at the
persistence boundary**, leaving a consumer a bare verdict string whose strength and
as-of height are unrecoverable.

- **One-shot latches.** `one_shot.py:203-300` emits a full typed descriptor
  (`standard`, `slot`, `byte_offset`, `size_bytes`, `value_type`, `expected_version`,
  `role`, `guard`); `one_shot_probe.py` reads all of it correctly; then
  `annotate_capability_one_shot` (`:420-458`) writes only
  `latch_state`/`latch_value`/`latch_target` and **discards the probe transcript,
  including the block and the raw slot word.** Measured: 0 of 1,799
  `effective_functions` rows mention any dropped field; the persisted condition
  objects carry exactly 5 keys on 39/39.
- **Exact empty caller sets.** `solmate_roles.py:212-218` always passes a non-None
  `last_indexed_block`, but `_intersect_finite`/`_union_finite`/
  `_intersect_finite_blacklist` (`capabilities.py:507-550`) rebuild the `finite_set`
  copying only `trace`, **dropping `last_indexed_block` and `empty_reason`**
  (`_attach_conditions` preserves both, deliberately). So T-EMPTYSET's
  "`empty_reason` is NULL on 51/52" is a **serialization bug, not a data property**,
  and no "nobody can call it" row records the block at which it was true.
- **Accessor-convention principals.** T-ACCESSOR's 33 rows publish
  `membership_quality='exact'` + `confidence='enumerable'` — maximum strength,
  byte-identical to a directly-read public getter — with the same `resolver_path` as
  a plain `auto_getter`. The convention is recorded **only** in
  `details->'trace'[*].basis`.

Consequence for §E's third corollary, now written into it: **a strength gate that
is not published alongside its payload does not discharge the obligation.** A
conforming scorer must read the basis (demoting every accessor-NAME arm below the
ABI-forced one), and must treat any verdict whose strength gate was dropped as
carrying the *weakest* branch that could have produced it.

**Vocabulary, as shipped by A3 (2026-07-30).** The basis is now published
top-level as `function_principals.details->>'authority_basis'` as well as in the
trace, and the conflated `internal_accessor_convention` label is split at the
write point by which helper produced the selector:
`standard_namespaced_accessor` (an ERC-7201 accessor-table match) and
`deunderscore_convention` (the leading-underscore convention); `auto_getter` is
renamed `abi_auto_getter`. **Only `abi_auto_getter` is ranked above the rest** —
the name-matched arms are mutually **UNORDERED**, sharing one
`accessor_name_matched` tier, with `accessor_slot_agreement: not_determined` on
each. Any finer ordering is a model choice published with its version and, per
B14 (33 rows / 2 principals / 3 runtime addresses), may only gate, cite or
three-state — never weight. A scorer must seat the legacy literal in the weak
tier too (33 persisted rows carry it) and default an unrecognised label to the
weakest tier.

#### S2. Refutations that change what a scorer may do

**R1 — R-OVERLAP's non-retraction is FALSE, and `proto-0.2` is publishing the bad
credit today.** The register asked whether *one* key can sustain a freeze. Wrong
coalition size. On-chain (block 25643300): the 1/5 Safe `0x427989bb` has exactly 5
owners and **all 5 are owners of the 4/7 `0x2aca7102`** — its signer set is a strict
*subset*. Pausing needs 1 of the 5; denying the 4/7 its quorum needs 4 refusers
(7−4+1). **So 4 keys, all inside the "protective" 4/7, can freeze and hold the
freeze indefinitely.** Verified as the real configuration on 4 contracts where
pause is available to the 1/5 and unpause only to the 4/7: **WeETH
($3,502,642,106), EETH, LiquidityPool ($77,255,816), EtherFiRestaker
($467,568,890)**. `scorer_v2.freeze_severity` compares principal *addresses*, so it
returns `recovery_path_witnessed_independent` and `score_v2.json` publishes the F5
credit over 36 capabilities / 30 contracts. **B13 lists this mechanism under
"Conforming"; move it to non-conforming, over-crediting.**

> Correct rule: independence is a property of **key sets**, not principal
> identities. With owner sets `O_A,O_B`, thresholds `k_A,k_B`, `S = O_A ∩ O_B`: a
> shared coalition can **act as** both when `|S| ≥ max(k_A,k_B)` and can **block**
> both when `|S| ≥ max(n_A−k_A+1, n_B−k_B+1)`. **All three overlapping pairs
> satisfy BOTH** — (4/7,1/5) |S|=5 vs 4 and 5; (3/7,4/8) |S|=5 vs 5 and 5;
> (2/4,2/4) |S|=3 vs 3 and 3. Publish the **minimum coalition size** (4 for the
> WeETH freeze), never a boolean "independent".

~~B10.1's caveat is **empty on this corpus and does not weaken this**: probed on all
9 Safes at 25643300, `getModulesPaginated` returns `[]` with the sentinel and the
guard slot is zero, so k/n is currently exact, not an upper bound.~~
**↳ RETRACTED (2026-07-30, Unit 7A / C1). The Safe-principal population is 19, not
9, and B10.1's caveat is NOT empty.** No plane yields 9:
`select count(distinct lower(address)) from function_principals where
resolved_type='safe'` → **19**; `control_graph_nodes` → 18; protocol-1-scoped
(join `contracts` on `protocol_id=1`) → 11; `monitored_contracts`
`contract_type='safe'` → 11. (An earlier draft cited "`principal_labels` 20"
without stating its query; a re-measure gave 14 by address-join and 80 by
label-match, so the figure is withdrawn — the point stands on the four above.)
Re-probed independently on all 19 at 25643300 via `utils/rpc`:
`modules[SENTINEL_MODULES]`
(`0xcc69885f…792f`) holds the sentinel on **18** and
`0x…2e1b5a40edc922bce489668b11749b8eabd67f6b` on
**`0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca`** (VERSION `1.1.1`, threshold 4) —
**one enabled module**, so **k/n is an upper bound on protection for 1 of 19**.
Guard slot `0x4a204f62…34c8` is zero on **19/19** and the 1.5.0 module-guard slot
`0xb104e0b9…9947` is zero on 19/19. Versions: **`1.4.1` ×9, `1.3.0` ×9, `1.1.1`
×1** — measured twice at 25643300, and the slot-0 singleton agrees with `VERSION()`
on **19/19** against the canonical deployments (`0x41675c09…` 1.4.1 ×9,
`0xd9db270c…` 1.3.0 ×9, `0x34cfac64…` 1.1.1 ×1).
A zero guard word is `proven_zero` only on 1.3.0/1.4.1; on 1.1.1 the slot is
unused storage, so it is `feature_absent`. The corpus-level "k/n is exact" claim
was a negative published from a 9-row subset without the observation block — the
absence-as-proof error this register exists to prevent. The witness is now
persisted per Safe (Appendix B10.1a) with its `probe_block`.
`0x21f73d42`'s reach is 4 `function_principals` rows on 1 contract with
`protocol_id IS NULL`, so **no scored verdict moves**; the correction is to the
register, not to a score. **B14: the module-bearing population is 1 and its reach
4 — neither may calibrate a rule.**

**R2 — B6's entire population table is measured from the field B6 itself forbids.**
Three lanes independently measured `function_principals.details.conditions` and got
`business 2009, time 172, pause 17, reentrancy 10, self_service 6, denylist 5,
one_shot 2` — a **byte-exact seven-for-seven match with B6's published table**. The
mandated source, `effective_functions.conditions`, gives: **`business` 2089 (738
fns), `time` 153 (124), `denylist` 28 (28), `one_shot` 23 (22), `self_service` 15
(12), `pause` 13 (13), `reentrancy` 9 (9), and `permit_sig` 7 (5) — a kind the
register omits entirely.** Mechanism for the "2": 20 of the 21 `open` one-shot
functions have zero principals, so the display copy cannot carry their conditions;
the one `restricted` function has 1 principal carrying 2 copies. **Every one of
B6's seven numbers is wrong, and B5's `one_shot` figure is the correct one** — the
"2 via `kind` vs 22 via `latch_state`" apparent contradiction dissolves: `kind` and
`latch_state` live in the *same* condition object (5 keys on 23/23). Delete B5's
parenthetical "(+22 via `latch_state`)".
T-COND is *understated* by this: on all 32 differing rows the principal copy is a
strict **subset** of the parent (`in_principal_not_parent = 0` on 32/32), because
the parent is a whole-surface fold that synthesises `self_service`.

**R3 — B2's "3 agreements / 0 contradictions" is tautological, and its validation
population is disjoint from its application population.** `calldata.py:1427` calls
`static_destination_shape` and `recipes.py:1527` returns `static_shape, "static"`
verbatim — so the fork's published `immutable_fixed` **is** the recomputation, and
all 3 agreements carry `shape_proved_by='static'`. Agreement tests only that the
claims projection of `value_flows` is faithful on 3 rows. Worse: the rows that
would gain a **new** positive fact have no fork verdict *by definition*, so the
sentinel — the only plane that can refute a false `immutable_fixed` — is **absent
on 11 of 11 by construction**. Also: `_FIXED_TARGET_KINDS` has three members and
**`constant` and `storage_no_setter` occur 0 times**, so the rule is validated on
one third of its own input domain; and all 3 agreements are single-flow,
single-`immutable` rows exercising one path through the predicate.
Downgrade the claim to "a projection-fidelity check, n=3". Independent source
confirmation *does* exist for the two headline rows (below), but not for the rule.

**R4 — the three B2 implementation rules are correct; the rule-to-evidence mapping
is scrambled.** Rule 1 (`several` = a set, take the **worst** member) is verbatim in
`effects.py:2540-2545` and **load-bearing**: best-member mints **4 false
`immutable_fixed`** on user-withdrawal functions (`PriorityWithdrawalQueue`/
`WithdrawRequestNFT` `claimWithdraw`/`batchClaimWithdraw`). Rule 2's rationale is
verbatim at `calldata.py:1096-1105`, **but excluding `value_router` flips zero
functions into a false `immutable_fixed` — the fail-open direction occurs nowhere in
this corpus**, and the exhibit credited to it, `LayerZeroTellerWithRateLimiting.bridge`,
is inverted: the fee is on the *router* leg and the principal (`vault.exit`) on a
**flows-less** leg. **Rule 3 is the one that saves `bridge`, and its population is
14, not 11** (the 11 `policy_derived` `cross_contract_join` claims **plus the 3
`behavioral_observed` flow.out claims with an `observed` block and no `flows`** —
the G3 rows). Skipping instead of blocking makes `bridge` publish `immutable_fixed`
off a LayerZero fee transfer. **Promote rule 3 to primary.**
*Upstream, outside the scorer:* the production predicate reads
`fn.effect_info['value_flows']`, where `bridge` has no `out` flow at all, so **the
real predicate would also return `immutable_fixed` for `bridge`** — only an
unrelated synthesis bail-out at `calldata.py:1395` prevents it.

**R5 — the B2×B8 worked example is arithmetically wrong, and B2 implemented as
written *causes* the over-claim it warns about.** `band($467M)` with sev 0.10 × EOA
0.9 gives **4.86 raw**, so the over-claim is **6.0×, not 4.7×**; 3.78 corresponds to
the $10M–$100M band, i.e. not the stated method. And because `withdrawEther` has no
`observed` block, `reach_usd()` returns `None` and `inst_val = cval` — **setting the
shape to `immutable_fixed` makes the scorer charge the $467.57M balance sheet
automatically**, merging into an EOA ledger key already at raw 0.810. The per-asset
gate must be a **hard precondition on the value substitution**, not prose in a
worked example.
The conflict the register adjudicated is now settled with evidence, and **both
audits were wrong about why**. Deployed source (implementation plane, MinIO):
`liquidityPool` is Solidity `immutable`, constructor-only; the amount is literally
`Math.min(address(this).balance, …)` — the exact form `_is_capped_by_balance`
accepts; and the call carries **empty calldata `("")`**, so it provably cannot move
anything but native ETH. On-chain at the runtime proxy `0x1b7a4c37…`: **0 wei
native, 267,464.48 stETH** (the implementation row `0x51357a70…` holds neither, yet
carries all 7 `contract_balances` rows and the whole $467,568,890.27).
- Audit C's *conclusion* is right and its *evidence path was invalid*: `tvl.py:238`
  gates the native row on `eth_wei > 0` while `:224-227` swallows a failed fetch as
  `0`, so **an absent native row conflates proven-zero with fetch-failure.** C read
  an absence as a proven zero.
- Audit A is a category error.
- **The decisive rule neither stated: the floor is licensed by the destination
  proof, not by the balance snapshot.** Even fully funded, the capability is "sweep
  own ETH to the protocol's own immutable pool" — no loss, no redirection. Honest
  weight **0.810 raw** = 60 × 0.10 × 0.90 × band-floor 0.15. Written the other way
  round ("empty contract ⇒ cheap") the rule licenses the rug-on-an-empty-vault
  failure mode. **An absent native row is `not_determined`, never $0.**

**R6 — G3 is refuted by a field this register already marks REQUIRED, in the same
appendix.** Both G3 rows carry `witness.effect_verdict_id` (138, 142) and those
verdicts carry `concrete_destination` = `0x93c4b944…` (the EigenLayer stETH
strategy) and `0x889edc2e…` (the Lido WithdrawalQueue) — **both matching the
deployed source exactly.** The probe already ran and already recorded the literal
destination; a single join closes it. Restate G3 as *"closable by a scorer join for
these 2 rows; a static flow extraction is still required for a universal"*, since a
`concrete_destination` is an existential and cannot prove `immutable_fixed`. Source
also shows `stEthRequestWithdrawal`'s destination **is** fixed (immutable
`lidoWithdrawalQueue`, withdrawal owner hardcoded `address(this)`) and
`depositIntoStrategy`'s `tokenInfos` mapping **has no setter** (one write, inside an
initializer) — `storage_no_setter` in substance.
**Counter-hazard `concrete_destination` needs and lacks a gate:** on the
`unknown`/`none` branch the stored value is one destination from one probe (the code
says outright that *"an observation of one destination can't prove 'fixed'"*), and it
is **deliberately withheld on `caller_arbitrary`** because on 35/35 such rows it was
the prober's own recipient argument echoed back. Ungated, a scorer reads
`PriorityWithdrawalQueue → 0x0…0` as a proven fixed burn address.

**R7 — B9's `proof_kind` split is wrong; `clean` is exactly as LLM-dependent as
`pre_fix_unpatched`.** `_compute_proof_kind` (`coverage.py:1137-1200`) branches
**only** on `label == "reviewed"` / `label == "fix"` from the LLM
`classified_commits`, and the two values are opposite branches of one `if` over the
same two label sets; the SHA comparison is additionally a fuzzy **7-character
prefix** match. The prompt says so itself (`scope_extraction/_llm.py:123`: *"Label
definitions (CRITICAL — these drive the `proof_kind` column on coverage rows)"*).
Only `unclassified` is LLM-free and it carries no information. **All four values are
BANNED from grade** (inv.2(b)), which costs nothing: `equivalence_status='proven'` +
`matched_commit_sha` (36/36) + `bytecode_keccak_at_match` (36/36 within proven)
establish the deterministic core with no model in the path — which is what
`scorer_v2.py:622-626` already does. The scorer's *behaviour* is right; this
register's *rationale* for it was not. **B14 item 6 drops.**
Two further B9 corrections: `proof_kind` is populated on **36**, not 209/209, with
three of four values at n=1; and the 117/45/10/1 taxonomy is `equivalence_**status**`
— `equivalence_reason` is **free text with 59 distinct values**, so a scorer told to
branch on it gets prose.

**R8 — `bytecode_keccak_at_match` does not prove "deployed right now".**
`bytecode_cache` has **no block number and no `fetched_at`**; `cached_at` spans 1 h
47 m and its maximum is *after* the audit anchor's. Honest form: *"equals the
bytecode cached during this run's ~2 h window."* Not replayable (no block).
**Survives as a deterministic negative generator** going forward, which is the part
worth keeping.

**R9 — B5.5's "the transfer denylist has provably never been written" is not
licensed by the cited evidence, and the licensing field is a union.** `beforeTransfer`
reverts on `fromDenyList[from] || toDenyList[to] || operatorDenyList[operator]`, and
**`AllowTo`/`DenyTo` — the writers of `toDenyList` — have no cursor anywhere**, so
B5's own limit 2 forbids the claim. `toDenyList` is *also* the variable whose
`eth_call` failed, so **neither plane answers it and the register asserts it anyway.**
Separately, `effect_tags.writes[]` is **not a topic→variable map**: all six Allow/Deny
entries carry the identical union `['fromDenyList','operatorDenyList','toDenyList']`
because `_effect_tags_for_signature` (`tracking.py:652-680`) *"unions these across
all emitters of an event signature"* and `denyAll`/`allowAll` write all three. Read
forward it manufactures a proven negative from the wrong event; the sound direction
needs the inverse index (6 topics) plus enrollment of all of them (4). And
`extract_governance_topics:691` deliberately skips `topic0 in ALL_EVENT_TOPICS`, so
it is a routing index, not a proof index.
> **Fourth limit on absence-as-proof, verbatim into any implementation: absence is
> proven for a state variable only if EVERY topic that can write it has a warm
> cursor. Enumerate the write surface, then check enrollment.**
The conclusion happens to be **true** — a genesis-to-head `eth_getLogs` over all six
topics on `[0, 25641245]` in 52 chunks returned **0 logs**, with a positive control
(the same harness returning 233 logs on the RolesAuthority topics, min block
20,265,589, exactly matching the 233 persisted rows). That upgrades this one instance
from code-invariant to data-witnessed and closes limit 1 *for it only*; no other
cursor can be promoted without paying the same RPC cost. Limit 1 otherwise stands,
and the re-enrollment attack is closed: `enroll_event_cursor` is the only creator of
a cursor row anywhere and uses `on_conflict_do_nothing`, so re-enrollment can never
raise a cursor's start. `creation_block` *is* persisted, in `etherscan_cache` for
32/32 enrolled addresses — but that is a TTL cache, and whether these 80 rows were
written by today's code is **UNVERIFIABLE** (no `created_at`).

**R10 — B5.1's admissibility argument covers 50 of 52, and the recommended gate
admits a name-derived empty.** 50 rows carry `trace[0].step='solmate_roles_authority'`;
2 do not — `PriceProvider.claimGovernance` (`empty_reason='empty_by_design'`, a real
`eth_getStorageAt`) and **`RoleRegistry.acceptOwnership`, which carries no trace, no
`empty_reason`, no block and no selector** (`predicate_evaluator.py:783` returns the
strongest earned-negative shape on `if not result_addr`), making it indistinguishable
from a defaulted empty — and `result_addr` is also `""` for a burn address.
`_check_only` has **four** bases, not two.
**A third path can emit an exact+enumerable empty from a name.**
`_pending_ceiling_capability` (`predicate_evaluator.py:1073-1100`) says in its own
docstring: *"it is NOT read-confirmed… What identifies the gate as the accept half of
a 2-step handover is the accessor's `pending` prefix, i.e. an identifier."* Population
**0** here, so latent — but "the empty is *earned*" is false as a general rule, and
**the gate must add `trace[0].basis != 'accessor_name'`.**
**And the emptiness rests on an unstated axiom.** With `owner()==0x0` the owner
disjunct is `{0x0}`, a **singleton, not `∅`**; the pipeline drops `0x0` (verified: a
member on 0 rows). Sound on mainnet — `msg.sender` can never be `0x0` — but a
*modeling convention*, not a witnessed emptiness. Probed: `eth_call setAuthority`
from `0x0`, and with `from` omitted, **does not revert.** State the axiom; and note
that the default-OFF differential prober, enabled without an explicit `from`
override, **inverts this verdict on all 52.**
*What held, strongly:* a 50-row differential against live authority state
(`getRolesWithCapability` + `isCapabilityPublic`, five authorities, block 25642800)
returned **`0x0` and `false` on 50/50, zero mismatches**, and the deployed Solmate
source confirms exactly two disjuncts with no override, no module and no
`msg.sender == address(this)` path. The fold is sound. **The disposition is not a
dismissal, though:** all 10 registries have `authority=0x0` with `owner` = the 4/6
Safe (9) or the 5d timelock (1), so **two transactions re-enable any of the 50**
(`acceptOwnership` needs one). Publish as *"currently unreachable; re-enablable by
\<4/6 Safe\>"* with a counterfactual (inv.10). B13 files this under "under-scoring",
the wrong axis: the grade effect is ~0 either way (inv.1); the real effect is
deleting 11 warnings that state a falsehood. Also **18 of the 52 carry ≥1 claim**,
and the entire material stake is `BoringGovernance` **$44,565,807.56**
(`setShareLocker`) plus the LZ Teller's controls — **the other 7 host contracts hold
$0.**

**R11 — B5.2's "Raises" direction is vacuous, population 0.** Every `pause`/`unpause`
on the 22 zero-owner contracts (12 pairs, 24 rows) has a non-empty exact `finite_set`
with ≥1 resolved principal on **both** sides; **not one contract's only recovery path
was the owner**, and the 10 BoringVaults + BoringGovernance have no pause functions
at all. Strike it or mark it population-0. The "Lowers" direction is real but
**already realised** — `0x0` is a member on 0 rows, so the pipeline drops the dead
disjunct before persisting; listing it as a REQUIRED *new* consumption is redundant.
*What held:* 22 rows / 22 contracts / **$94,026,174.44** exactly, `observed_via='eth_call'`
on all 22 (**not one is an error row**), and `owner()` returned `0x0` on **22/22**
on-chain at block 25642800. Two caveats to carry: the recorded `block_number` is
**not** the evaluation height (`build_control_snapshot` reads at `"latest"`), and
`eth_call_impl_fallback` can manufacture a zero (0 of 22 use it; 3 such rows exist).

**R12 — B3's justification for a freeze floor is dilution by average, banned by
inv.5; and the floor itself resolves an unknown favourably.** "Only 4 of 63 freeze
verdicts are proven, therefore floor `pause.set`" reasons from a corpus-wide rate
across 63 *screening candidates* to the severity of a specific row — and the 4 proven
rows are **the top 4 by value** ($3.50B / $467M / $77M). Floor on the row's own
missing witness, never on an aggregate ratio. Deeper: `FREEZE_REVERSIBLE = 0.05` and
`FREEZE_IRREVERSIBLE = 0.20` are **asserted severities**, not floored weights —
`proto-0.1`'s 0.35 pointed adversarially and `proto-0.2`'s 0.05 points favourably,
and both are the same inv.1 violation with opposite sign. The conforming treatment:
**duration contributes zero to the severity axis** and emits its missing witness,
while the two facts that *are* proven carry weight independently — `pause_effective`
(4 rows) and per-key recovery independence resolved from `pause.unset` principals
(30/30 contracts), now corrected to key-set independence per R1.
Relatedly, **T-PAUSECAND's conclusion is wrong even though its number is right.**
0 of the **32 static** `pause.set` claims has a freeze verdict ✓ — but 4
`behavioral_observed` claims on `pauseUntil` **do**, with `pause_effective=true` and
concrete blast radii, so **Appendix A's "the whole `pauseUntil` family carries no
pause claim / fixing the matcher precedes any pause scoring" is stale and should be
struck.** And "the 59 unknown rows point at screening candidates, not pauses" is
wrong for **24 of 63** (`setPauseUntilDuration` ×12, `pauseUntil` ×8 unknown, 4
proven) — those 20 unknown rows are genuine pause functions carrying **no claims at
all**, a different and more interesting gap.
**`no_blast_radius_observed` (29) does not prove those functions are not freezes.**
`pause_effective=true` *is* present on all 29, but the subjects are ordinary admin
setters with **no claims at all**, `scored_denominator` is **empty on 26 of 29** (so
the negative is vacuous), it shrinks no unknown any consumer holds, and the code's
own next line says *"This is at the bar (correct to leave unknown)."* Keep the
CONFIDENCE classification; drop the characterisation.

**R13 — `scored_denominator` is the right object and not a drop-in replacement.**
The key is present on **63/63** and non-empty on **28** (not "4 proven / 59 unknown"
— availability understated 7×), and the quote is at `anvil.py:356-357`. But: **5 of
33 entries are Solidity source-level type names**, not canonical ABI encodings, and
match no `abi_signature`, so a naive join silently shrinks the denominator;
**`unpauseUntil()` is a member on all 4 rows**, so the recovery path is counted as
frozen surface; and it answers a static/fork **agreement** question, not an economic
one — it disagrees with `value_fns` in **both** directions by up to **3.2×**. Adopt
it (minus the pause/unpause entries, joined on a normalised signature with a hard
error on unmatched entries, published alongside `pre_pause_succeeding` as the
measured live surface) and **label the result a coverage fraction, not a value
fraction.** B3 also omits two populated fields: `pre_pause_succeeding` (63/63) and
`latch_flip` (4/4). Note the probe's caller is an **unauthorized sentinel**, so
`pre_pause_succeeding` is bounded by what a permissionless address can execute and
includes no-ops like `renounceRole()`.

**R14 — the two ~$4.06B timelock figures are the same money.** The 2-day timelock's
16 contracts are a strict **subset** of the 10-day's 24; the $1,754,710 difference is
exactly MembershipManager's balance. Both contain WeETH $3,502,642,106 +
EtherFiRestaker $467,568,890 + LiquidityPool $77,255,816 + WithdrawRequestNFT
$9,478,407. **They may never be summed or shown as independent exposure** —
`score_v2.json`'s exposure metric double-charges $4.057B across findings[3] and
findings[4]. And **B10.4's priority ranking rests on an unwitnessed number**: the
2-day timelock has **6 claims total** across 53 gated functions, **47 functions with
no claims**, **zero `upgrade.implementation` rows**, and its WeETH access is
`recoverERC20`/`recoverERC721`/`recoverETH`/`setPauseUntilDuration`. Attributing
WeETH's $3.50B to it is the `sweepETH` error in a new place. Honest form: *"reach is
`not_determined`, at least $X."* (The 10d figure is defensible — it holds
`upgradeTo`/`upgradeToAndCall`.)

**R15 — B12's negatives: four are wrong.**
- *"Pairing by `flags[].var` changes exactly 1 row"* — it changes **5**. The other 4
  are `EETH`/`EtherFiRestaker`/`LiquidityPool`/`WeETH.pauseUntil`, the **four
  fork-proven pauses**, whose witness has **no `flags` key at all** (they are
  `behavioral_observed`, minted from a verdict and carrying `observed`). The rule
  would promote the best-witnessed pauses in the corpus to `FREEZE_IRREVERSIBLE`
  **off an absent key**. So rejecting it is right for a *principled* reason — joining
  on an absent key converts a `not_determined` into a proven negative — not because
  it is "net-harmful on this corpus". Re-argued on that ground, the inv.14
  corpus-fitting objection dissolves. (Var-matching is admissible later only as a
  *refinement* on rows where both sides carry `flags`, never as the join.)
- *"Nested Safe ownership does not exist — do not spec for it"* — **wrong**, and
  contradicted by the register's own adjacent count (safe 2 of 65). Two
  safe-owns-safe edges and one timelock-owns-safe exist (`0x218b5ec7`, `0x369e6f59`);
  they simply do not sit on a Safe holding function-level authority. And the n=1
  rests on a **third-state collapse**: of the 49 distinct owners of the 11 principal
  Safes, **eoa 27, NOT_DETERMINED 21, contract 1.** Reading 21 not-determined owners
  as EOAs is precisely what this register exists to prevent.
- *`ownership.transfer` flat 0.55, witness featureless* — **wrong.** 1 of 39 carries
  `standard='default_admin_rules'` / `corroboration='default_admin_gate'`, i.e. OZ
  `AccessControlDefaultAdminRules`' **enforced admin-transfer delay** — a witnessed
  severity reducer sitting inside the witness called featureless. *(n=1.)*
- *`timelock.set_delay` "no delay value and no min-delay bound"* — half wrong. The
  new value is genuinely absent ✓, but **both** `updateDelay` functions have exactly
  one principal, the timelock itself, carrying `details->>'delay'` = 432000 / 864000,
  and OZ `updateDelay` is self-gated — so **the current delay bounds how fast it can
  be shortened**, and that bound is witnessed on the same row. *(n=2.)*
- *`upgrade.implementation` "nothing that could refine it"* — inaccurate (`gate` is
  2-valued: uups 48 / proxy_1967 1) but no scorer change follows, since severity is
  already at the 1.0 ceiling.
- *`safe_owner` "0 of 65 owners hold a balance"* — misleading: **64 of 65 have no
  balance row at all** and 61 are EOAs, which `contract_balances` never covers.
  "$0 to the closure" is correct and verified from `build_authority_graph`'s
  protocol-scoped balance load; "0 hold a balance" was not measured.
- *`effect_verdicts` "that is the system working"* — fair, and incomplete. Add that
  the 205 unknowns' `reason` **and the 39 decoded `revert_reason` values** are a
  CONFIDENCE input and a re-probe queue, not zero. B7's "`revert_reason` 39, all
  `unknown`" is **refuted**: it is `unknown` on **none** — 21-way distinct concrete
  values (`custom_error 0x…` ×35 over 18 selectors, `Error('ERC721: invalid token
  ID')` ×3, `empty_revert` ×1), and the ERC-721 one is provably a mis-seeded probe
  rather than a held gate. A decodable 4-byte selector discriminates "the gate
  rejected the caller" from "a business precondition was unmet".
- *What held, and was strengthened:* B12's central negative — **no behavioral
  confirmation of any authority change** — was re-verified against the **raw
  transcripts**, not just the verdict rows: over all 304 blobs, **514 call-groups
  keyed on (to, calldata, label) and 0 groups with mixed success across `from`.** The
  eight absent `observed` keys are each referenced in **both** the projection
  allowlist and the producer, so "never produced on this run" (not "not implemented")
  is correct for all eight.

**R16 — B11 corrections.** All 20 traps are real traps on their core claim. Six
entries need rewriting:
- **T-CHECKONLY**'s stated reason is wrong in the dangerous direction. A `staticcall`
  to `0x0` **succeeds** with empty returndata and Solidity's `→ bool` decode then
  **reverts** — so absent the guard the whole OR would revert and the function would
  be uncallable **by anyone including the owner**, not "the branch is false". The
  correct answer arrives only from Solmate's explicit `address(auth) != address(0) &&`
  conjunct. **And the implied filter is unsafe:** `target_address='0x0'` selects **52**
  nodes, not 50 — the extra 2 are `BoringGovernance.transfer`/`.transferFrom` under an
  **AND** root with `callee_signature='canTransfer(...)'`, a transfer hook, where the
  collapse runs the other way. Gate on **`root kind = OR` AND
  `callee_signature = 'canCall(address,address,bytes4)'`**.
- **T-LABELS** is over-broad: **14 of 138 distinct values = 4,515 of 6,156 label-rows
  (73%)** are `resolved_type`/`relation`-derived and name-independent, separable by a
  deterministic allowlist. Re-file **BANNED → GATE** (the "use the edges" guidance
  still holds, because the clean subset is redundant with them). **New hazard to
  name:** `authority_controller`/`owner_controller` (**211 rows**) are minted by a
  literal `if edge_label == "authority"` on a state-variable name and then drive a
  display name with confidence `"high"` — name inference laundered into a
  high-confidence fact that reads as structural.
- **T-ROLEDEFS**: keep BANNED as a field read, but **strike "already in the authority
  plane"** — `PROPOSER_ROLE`/`EXECUTOR_ROLE`/`CANCELLER_ROLE`/`PAUSER_ROLE`/
  `OPERATING_ADMIN_ROLE` appear **nowhere** in `authority_roles`, `capability_expr`,
  `claims`, `control_graph_edges.label` or `function_principals.details`, by name or
  by keccak. `authority_roles` carries only Solmate numeric ids. The grants **are**
  witnessed and unused: **25 `indexed_event_logs` `RoleGranted`/`RoleRevoked` rows**
  on the 10d and 5d timelocks, hash-keyed. Log it as a coverage gap.
- **T-ACCESSOR**: keep admissible, but "never presented as bytecode-grade" is
  **unachievable through the strength gates** (see S1). Add the `trace[*].basis`
  requirement. Narrowing in its favour: all 33 rows *also* carry
  `live_getter_resolution` and **all 33 resolve to `resolved_type='safe'`**,
  independently probe-confirmed — so **"33 rows are a naming convention" is refuted**;
  zero rest solely on the convention, and the residual is "we may have read the wrong
  getter", not "the principal is a name guess".
- **T-SUMMARIES**: the not-LLM finding is confirmed (`summaries.py`, Slither IR only)
  and agreement is **64/64** — but **partly tautological**, because `:1057-1059` folds
  `_pause_claims(effects)` into `pause_functions`, so a `pause.set` claim *causes*
  `is_pausable=True`. Do not cite it as two detectors agreeing. **The `standards`
  carve-out is refuted**: the `erc20.*` matcher already gates on structural ERC-20
  detection and all 42 `erc20.{transfer,approve,transfer_from}` claims sit on
  ERC20-`standards` contracts, so it is entailed by the `claim_id`. Also the third
  state manifests as an **absent row** (64 summaries for 168 contracts), and
  `standards` omits ERC1155 1 / ERC721 1.
- **T-EXTCALL**: the exclusion is right for all 50 and the $180,590,426,704.62 is
  exact, but the **"51×" does not reproduce** (protocol-1 balances are
  $4,159,585,666.63 → **43.4×**), **31 of the 50 targets ARE protocol-1 contracts**,
  and the **harm mechanism is mis-stated**: `build_authority_graph` loads balances only
  for `protocol_id=1` and *reverses* each edge, so folding this relation in would not
  pull $180B into any closure — it would mint WETH/stETH/Lido as spurious
  **principals over** protocol contracts and add at most $50.6M. The real authority is
  `db/models.py:818-824`.
- **`PRODUCT_CLAIMS` on `claim_id`: withdraw the inv.2 charge, replace it with an
  inv.16 fix.** `erc20.transfer` requires structural `_facts.is_erc20` **and** a
  keccak selector identity (`0xa9059cbb`) — a standard-selector match, which B12
  itself lists as admissible. No name substring is read. But `claim_id` does not prove
  permissionlessness and `authority_openness` does: `erc20.transfer` 13/14 `open`,
  `transfer_from` 13/14, `approve` 14/14. **The 2 exceptions are
  `BoringGovernance.transfer`/`.transferFrom` at `not_determined` — the same two rows
  as T-CHECKONLY's AND-rooted hazard.** Gate on **`claim_id ∈ PRODUCT_CLAIMS AND
  authority_openness = 'open'`**; `not_determined` is not product.

**R17 — `contract_dependencies` carries the T-EXTCALL hazard under a second name,
and B11 is silent about it.** 451 rows, **no jsonb column at all**; 424 of 451 are
`source='dynamic'`, i.e. addresses seen in `debug_trace` CALL/DELEGATECALL/CREATE ops
— a call relation by construction. `relationship_type='regular'`: 61 targets holding
**$180,633,865,079** (ETH2 `DepositContract` $167.79B, `WstETH` $8.49B, `WETH9`
$4.26B). **BANNED**, and the bucket additionally **mixes 5 `protocol_id=1`
Boring-plane contracts (~$92M — exactly the contracts B5 names in the zero-owner
claims) with WETH9**, so the label discriminates nothing. `implementation` (41
targets, **$4.15B**) is a **double-count trap**: WeETH, EtherFiRestaker, LiquidityPool
etc. are already inside the perimeter, so counting the impl edge adds ~$4.06B the
perimeter holds and trips this register's own M7 rule. `library` (44 rows) is
documented-heterogeneous by the pipeline itself. **BANNED as value edges; CONFIDENCE
as code-plane provenance.**

#### S3. New material — one witness, three traps, one anti-gaming finding

- **NEW WITNESS: `predicate_trees.trees.<sig>.leaf.one_shot_latch`** — a complete
  typed storage-slot descriptor on 64 payloads / 31 of 97 bundles, **not persisted**
  (see S1). Content lives in MinIO via `analysis_blob_key`/`predicate_trees_blob_key`
  on the row — **the jsonb columns hold the literal `null`, so B14's "97 populated
  rows" is true but a SQL recursion finds nothing.** For the 3 addresses with no
  materialization row, the payload is recoverable from the per-job
  `predicate_trees` artifact. The full protocol-1 partition: **`storage_layout` 20
  fns (slot 0, offset 0, size 1, `uint8 _initialized`, `expected_version=1`) +
  `oz_v5_namespaced` 2 fns / 3 conds (ERC-7201 slot, offset 0, size 8, `uint64`,
  `expected_version` 1×2 and 2×1)**; `role='version'` on 23/23, `guard` null on
  23/23. **Branch that produced `consumed`: `value >= expected_version` on 23/23;
  `_DISABLED_SENTINELS` 0/23.**
  Status: **REQUIRED (`expected_version` + `size_bytes` sentinel key) / GATE
  (`standard`) / CONFIDENCE (`slot`, `byte_offset`, `variable`, `role`)**. But note the
  earned negative **survives for all 22**: `_initialized` is monotone non-decreasing
  under OZ `Initializable`, so `value >= expected_version` on a `role='version'` latch
  means *this selector's* guard can never pass again, permanently — re-verified
  on-chain at block 25642800 on all 22 runtime proxies (masked slot reads; **22/22
  agree with the persisted `latch_value`, zero sentinels observed**). Two real
  residuals: **contract-level generalisation is unlicensed** (only
  `_disableInitializers()` proves "no initializer can ever run again", and it fired 0
  times in the whole DB), and `_classify_value:275-279` has a **third branch** —
  `consumed if value > 0` when `expected_version` is absent or ≤0 — which would call a
  `reinitializer(5)` function spent while it is armed. It fired 0 times, **but
  `expected_version` is one of the dropped fields, so a consumer cannot tell a
  `value >= expected` verdict from a `value > 0` one.** Restate the decides-column as
  **selector-level**, and require the discriminator be persisted.
  *(`expected_version` is derived from the **modifier**, not a name —
  `one_shot.py:371-381` — so no inv.2 exposure on this path.)*
- **NEW TRAP T-DAPPTX — `dapp_interactions` (2262 rows, all protocol-1).** Columns
  promise transactions (`to_address`, `value`, `data`, `method_selector`,
  `typed_data`, `is_permit`). Contents: **12 distinct `method_selector` values, none a
  4-byte selector** (`'api:https:'`, `'js:41xjh9l'` — truncated JS-bundle filenames);
  `data` is a source URL on 2262/2262 with **0 rows starting `0x`**; `value`/`message`
  NULL 2262/2262; **0 of the (to_address, method_selector) pairs match any
  `effective_functions` (deployment_address, selector)**. A scrape-provenance log
  mis-typed into transaction-shaped columns. **156 rows point at protocol-1 contracts
  — that is the bait.** Same failure mode as T-TARGETS. **BANNED.**
- **NEW TRAP — `effect_transcript_*.anvil_version` / `.foundry_version`.** Populated
  78/304 (exactly the `tier2` transcripts) and **byte-identical on all 78**
  (`anvil.py:180-181` reads `transport.versions()`), so reading them as two agreeing
  sources is fabricated corroboration; 226/304 fork observations carry **no** toolchain
  record. **BANNED as independent provenance; CONFIDENCE as disclosure.**
- **NEW inv.11/12 item — `effect_transcript_*.block_number`: 304/304 populated across
  51 distinct blocks in one run.** Fork verdicts are not pinned to a single block, so
  `model_version` + persisted inputs do not determine them. Either pin per run or
  publish the per-verdict block as part of the witness identity. **CONFIDENCE.**
  **↳ PARTIALLY ADDRESSED (Unit 3).** The 78 `tier2` transcripts were worse than this
  says: their fork was spawned with **no** `--fork-block-number`, so the height they
  record is the preflight pin and *not provably* the height the fork was taken at.
  The fork now carries the pin, and the height + the scope of the pin are published on
  the verdict itself (B7 `witness.block_number` / `witness.block_source`). Two things
  this does **not** buy, stated so nothing reads more into it: the 274 existing rows
  and the 78 `tier2` rows in particular stay `not_determined` — an unpinned fork's
  height is unrecoverable, and nothing is back-filled; and `invocation_pin` does not
  make a run coherent. **The block is deliberately NOT in
  `uq_effect_verdicts_identity`** — adding it converts that upsert into an append, so
  multiple rows per key would exist with no selection rule and a consumer could
  publish an older height's verdict as the current fact. It may only be added together
  with an explicit latest-height-wins rule. A per-run pin remains a separate schema
  decision (`jobs` has no run/batch column).
- **NEW inv.5 anti-gaming finding B4b never states.** The fold proves the 2-day
  timelock's proposer/executor **is Safe 4/7 `0x2aca7102`** — so B4b's "not
  determined" cell is a coverage gap, not an unknowable. And **that same 4/7 directly
  gates 127 function rows across 22 contracts, including all 16 the 2-day timelock
  gates** (WeETH 4 direct / 4 via-timelock, EtherFiRestaker 13/2, LiquidityPool 9/4,
  EtherFiNodesManager 22/3, …). Under inv.5's own corollary the 2-day delay's
  protective value **must be discounted against the undelayed direct path**.
- **B4b's anti-decoy credit is PROVEN in the world and NOT replayable from stored
  inputs.** A complete `RoleGranted`/`RoleRevoked` fold from block 0 → 25643300 on all
  three timelocks: the admin role was granted **to the timelock itself, to nobody
  else, ever, and never revoked**; `hasRole(admin, self)` true on all three; **no
  EXECUTOR grant to `address(0)`** (the classic open-executor decoy); modules and
  guard clean. But `role_definitions` carries only PROPOSER/EXECUTOR/CANCELLER (6
  rows) and **not** `TIMELOCK_ADMIN_ROLE`/`DEFAULT_ADMIN_ROLE`, the role the question
  turns on. **Downgrade to CONFIDENCE under inv.11 until the fold is persisted**, and
  note the proof assumes unmodified OZ `TimelockController` (no bytecode diff run).
  Also: **"disjoint canceller" is false** — the 6/10 proposer and 4/6 canceller share
  **exactly 1 owner** (`0xa195d4a5…`). Capturing the canceller needs 4 of 6, blocking
  it 3; the proposer contributes 1. Publish it as *"1 shared owner; proposer reaches
  neither the act (4) nor the block (3) threshold"*. And B4b Decision 2 needs a **sign
  flip, not an addition** — `proto-0.2` books self-gated `updateDelay` as a
  **deduction** (`timelock.set_delay`, raw 0.405, twice).
- **The B4b collapse is safe and its severity is backwards.** The fold proves the
  6/10 is the **sole** PROPOSER and **sole** EXECUTOR ever, so
  `upgrade.implementation`-by-timelock ⊂ `exec.arbitrary`-by-6/10-through-timelock —
  a **superset relation**, so collapsing cannot under-count. The collapsed row must
  take **`severity = max` (1.0, upgrade)**, not `exec.arbitrary`'s 0.35. And the fix
  belongs in the **aggregation key**, not the severity table: the same collapse on the
  5-day timelock is already hidden by F7, and the 10d instance survives only because
  the 6/10 Safe and the timelock are two different principals.

#### S4. Erratum — counts to use instead

`from_is_self` **152/152 (T 96, F 56)**, not 145/145 (the load-bearing "zero
`flow.out` with `from_is_self=false`" holds) · `target_constraint` sub-fields: **52 of
63 carry `state` only**, guard+binding+pins on 11, `leaf_path` 9, **`pins=true` on
2** · `unvalued_pairs/_reasons/_assets` **5/5/4**, not 5/10/5 ·
~~the two `observed_reach_priced_usd` examples are `BoringVault.manage`, not
`.exit`~~ **— WITHDRAWN. This erratum was itself wrong and B1's original text was
right.** The three rows are `BoringVault.exit` $908,232.04, `BoringVault.exit`
$1,708,327.33 and `PriorityWithdrawalQueue.requestWithdrawWithWeETH` $41,517.24;
re-measured on the claims plane and independently corroborated by `proto-0.3`'s own
`reach_partially_priced` warnings, which name `.exit` twice. Recorded rather than
deleted because B0b governs the tables, so an error here propagates further than
one in a table row. · the
`input_seeded` **$44,938,439 is one of the 10 rows, not all ten** · `flow.out` claims
total **87**, of which **43 carry `observed` and 44 carry none** — every "/43 flow.out"
denominator is really "/43 of 87" · replay output is **17** shape gains (15
`immutable_fixed` + 2 `storage_determined`), of which 11 are attachable by today's
scorer and only **4** land as `immutable_fixed` without the new rung · `sweepETH`
native balance is **$90.97**, exact to the cent, not "$91" — the register understated
its own result · the per-asset method is **n=3**, not n=1, all exact across six orders
of magnitude · "nine `flow.out` rows show a native-vs-sheet gap" → **56 of 87 claim
rows, 19 distinct contracts** · `contract_balances` **60** balance-carrying contracts
(51 with any non-NULL `usd_value`, 38 strictly positive) · `polarity` **75/79**, and
**the 4 missing are exactly the 4 fork-witnessed `pauseUntil` claims** — a scorer
gating on its presence drops the rows B3 exists to promote · `scored_denominator`
present **63/63**, non-empty on **28** · `finite_set` **643**, not 642 (and B5's 52 is
one short of the 53 zero-member rows) · `role_labels`/`enumerable_role_store` **296**,
not 242 · `solmate_roles_authority` **326**, not 261 · event-fold rows **622**, not
503 · one-hop-resolvable `contract` principals **26**, not 24 (12 direct + 14 via
`contracts.implementation`) · OR-row principals **2 across the corpus**, not one ·
`control_graph_edges.notes` echoes `authority_provenance` on **3,778 of 5,030** rows,
not all (0/1043 `safe_owner`, 0/118 `role_principal`, 0/91 `mapping_member`) ·
T-UNATTRIB Safe rows **69** (7 targets), not 61 · T-TARGETS **288 of 1,056** for
protocol 1 (the register's 501/1,642 is unscoped whole-table) · `bytecode_keccak_at_match`
**201/209** (36/36 within proven), not 209/209 · `covered_from_block` **150**, and
`covered_to_block` **12/209 overall / 8 within proven**, the usable closed interval
being **8 rows / 4 contracts sharing one block value** · `classified_commits` **183**
entries, not 102 · **19** proxies upgraded 2026-07-14, not 11 — the fact is *stronger*
than stated · `tracked_topics` **51 contracts / 224 entries / 85 distinct topic0 / 89
distinct write names**; the register's 71 and 173 are **not reproducible** · the
two-plane error rows are **43**, not 19 + 43 · `contract_materializations` is **104
rows (97 ready)**; 41 tables exist, not "~35" · `revert_reason` is `unknown` on
**none** of its 39 rows.
Value figures that reproduced exactly, to the dollar: $4,159,585,666.63 total;
$3,502,642,106 WeETH (**84.2%**); $467,568,890.27 EtherFiRestaker; $94,026,174.44
zero-owner; $79,655,012.88 R-ROOT two-hop; $180,590,426,704.62 external-call targets;
$2,499,843.08 G2 excess; $44,938,439.36; $1,392,348.63.
**Appendix A should be marked superseded wholesale**, not corrected line by line: its
"1395"/"332/1395"/"1179"/"260/756", "$3.5B across 21 balance-carrying contracts",
"$3.17B (90.4%)", "**$221M**" for EtherFiRestaker (which is inv.9's own worked
example and must be restated), "81 and 51" timelock functions, "135 timelock rows",
and "12 EOA-gated functions on contracts >$10M" (actually **10**, two of them
`pauseUntil`, which A counts again separately) are all stale or wrong. B's corpus line
is right: **1,168 rows / 478 with claims / 541 claims**, and 1,168 rows = 1,168
distinct `(address, selector)` pairs, so there is **no inv.8 entity inflation** (but
`deployment_address` is NULL on 468 rows — do not dedup on it).

#### S5. Additional `proto-0.2` defects B13 missed

- **A third "proven-from-an-absence" defect, and it is LIVE, not latent:**
  `freeze_severity:279-281` returns `FREEZE_IRREVERSIBLE,
  "irreversibility_proven_no_unset_claim"` — the word *proven* published from the
  **absence** of a `pause.unset` claim, at 4× `FREEZE_REVERSIBLE`.
- **The F5 credit is computed from a `None` sentinel.** The claim-level call passes
  `pauser_addr=None` (`:414-416`), so `unset_princs - {None}` is trivially non-empty
  and **all 36** rows return `recovery_path_witnessed_independent` — and that vacuous
  result is what the credit publishes, while the per-principal pass emits **23
  `freeze_recovery_not_independent` warnings**. The scorer contradicts itself.
- **The headline finding's exposure is computed from a display-truncated list.**
  `reach_addrs = sorted(reach)[:40]` (`:532`) feeds the exposure loop (`:571-577`)
  while `value_at_stake_usd` uses the untruncated closure. Two findings truncate at
  exactly 40 — the **#1** (`authority.replace`, 4/6, raw 11.03) and **#5**
  (`exec.arbitrary`, 6/10, VaS $4.06B).
- **inv.9's residual is an algebraic identity, not a check.** Both residuals are 0 by
  construction and cannot detect an error in `raw_points`. Worse, **F7 subsumption
  moves 24 rows totalling 57.809 raw points out of `findings` into `subsumed_rows`,
  and the decomposition is taken over `findings` only** — inv.9 "closes" because the
  omitted quantity was never in the total. **The residual must include
  `subsumed_rows`.**
- **F3 publishes a count ratio as a dollar fraction:**
  `frac = len(blast ∩ value_fns)/len(value_fns)` then `inst_val = cval * max(frac,
  0.10)`. Freezing 1 of 2 value functions is not 50% of the value. This is a deeper
  16a defect than the `value_fns` denominator B13 names.
- **`confidence()` is not monotone (inv.6).** `den += band` for every privileged
  function but `num += band` only when claims exist *and* principals resolve, so
  analysing a new contract that yields privileged claims with unresolved principals
  **lowers** confidence.
- **Replay hazards:** no `ORDER BY` in any `load()` query; `findings.sort()` is not
  stable and **real ties exist** (0.81×2, 0.405×3, 0.247×2, 0.157×2); λ weights by
  rank and exposure attributes marginally in rank order under a per-address cap, so a
  tie permutation moves dollars between rows. Float accumulation order also depends on
  fetch order.
- **`PRODUCT_CLAIMS` contains `supply.mint` and `supply.burn`.** Harmless here (every
  such claim is open user flow or contract-gated; no EOA- or Safe-gated mint) but an
  EOA-gated `mintShares` on a $3.5B token would be dropped silently. Add to B12.

#### S6. Revised implementation order

Items **1 and 2 swap.** Timelock delay is the only headline item no lane could break
— a real `eth_call` with a negative-control gate, three distinct values, and no
inference on top (with the honesty caveat that the control rules out only a catch-all
fallback, no selector is recorded, and `0xcd425f…` has no structural corroboration in
the DB at all). The static lattice is the item whose validation evidence was broken,
and it is coupled to a second unbuilt change. Then: **3.** the 52 earned negatives, as
a *reframe* (currently-unreachable + counterfactual), which is the cheapest correct
fix and deletes 11 false warnings; **4.** `controller_values` / R-REGISTRY, which
**under**-reaches — with `authority()==0` proven on all 10 registries, `requiresAuth`
reduces to `msg.sender == owner`, and the owner also holds
`setPublicCapability` (make anything permissionless) and `setRoleCapability` on *any*
target trusting the registry, so "max severity of what the registry gates" is a
**lower** bound; the shape covers **22 contracts**, not 10. **5.** the timelock/
proposer collapse, *after* `f(quorum, delay)` is defined. **6.** the audit item
**drops** (R7). B7 and B8's per-asset split survived every attack and can be built as
written — with the three gates B8 omits: a flow-kind gate **including
`native_transfer_send`**, a `from_is_self` gate, an explicit `not_determined` bucket
for the 5 rows with no `flows` entry, and **absent native row ⇒ `not_determined`,
never $0**. On the 44 no-fork `flow.out` claims the method is applicable to **21** and
yields a number on **6**; the ERC-20 identity gap is **active on 18**, not latent.

### B1. Extraction magnitude — what a fund-out can move

| field | count | status | decides |
|---|--:|---|---|
| `claims[].witness.observed.observed_reach_value_usd` | 38 / 43 flow.out | **REQUIRED** | magnitude, fork-proven. |
| `claims[].witness.observed.reach_determined` | 43/43 (T 38, F 5) | **GATE** | false → magnitude undetermined. |
| `claims[].witness.observed.observed_reach_holders[]` | 43/43, 47 entries | **REQUIRED** | **whose** value the figure is. `claims_bridge.py:288` — the figure is a *holder's* full balance attributed when value provably leaves it, summed over these holders. **10 of the 38 `true` rows name a holder that is not the analyzed contract.** |
| `claims[].witness.observed.observed_reach_assets[]` | 43/43 | **REQUIRED** | which assets. Native ETH is the `0xeeee…eeee` sentinel. |
| `claims[].witness.observed.observed_reach_priced_usd` | 3 / 5 `false` rows | **REQUIRED** | a proven **partial floor** on the `reach_determined=false` branch, where the scorer currently writes `$0`: $908,232.04 and $1,708,327.33 (`BoringVault.exit`), $41,517.24. |
| `claims[].witness.observed.observed_reach_unvalued_pairs[]` / `_reasons[]` / `_assets[]` | 5 / 10 / 5 | **REQUIRED** | the named (holder, asset, reason) triples that could not be priced — all `asset_not_in_recorded_holdings`. `claims_bridge.py:318` requires these be read as **confidence gaps, never as a small reach**. On this branch `[]` is an earned negative; an absent key means the branch never ran. |
| `claims[].witness.observed.shape_proved_by` | 43/43 (`simulation` 36, `none` 4, `static` 3) | **GATE** | `none` = the shape was not proved. |
| `claims[].witness.observed.contract_balance_seeded` | 2 (both `true`) | **REQUIRED** | `claims_bridge.py:236-241`: the contract's own ETH balance was **overridden before the payout**, so the verdict means *"would move value if the contract were funded"* — a code capability, **not a live outflow of present treasury**. Absence must not be read as "the contract is funded". |
| `claims[].witness.observed.input_seeded` | 39 (all `true`; flow.out 18) | **REQUIRED** | `claims_bridge.py:233`: the acting principal **was given** the input asset. Distinguishes unconditional extraction from extraction conditional on holding the asset. 10 of the 18 are `BoringVault`/`BoringGovernance.exit` with `caller_arbitrary` reach to **$44,938,439** — a redemption requiring vault shares, not a drain. **Direction: lowers.** |
| `effect_verdicts.concrete_destination` | **6 / 69 proven**, all `value_out` | **REQUIRED** | the literal destination address; **not projected into claims** — join via `effect_verdict_id`. 3 rows carry a concrete destination while `destination_shape='unknown'`, one of them `0x0…0`. |
| `claims[].witness.observed.reach_tvl_check` | 41/41, **one distinct value** (`within_protocol_tvl`) | CONFIDENCE | discriminates nothing today; would matter only if `exceeds_protocol_tvl` appeared. |

**G2 — the real magnitude defect: reach is a holder-closure, not a contract
bound.** `scorer_v2.py:12` documents `observed_reach_value_usd` as *"a PROVEN
upper bound on what the capability can move"*. It is not bounded by the analyzed
contract's holdings. **3 of 28 rows exceed their own contract's entire balance
sheet by $2,499,843 total**: `LiquidityPool.withdraw` $79,010,396 vs $77,255,816
(2 holders), `BoringGovernance.manage` and `.exit` $44,938,439 vs $44,565,808.
`scorer_v2.py:511` keys value on the *analyzed contract's* address and
`reach_addrs` feeds the per-contract 1.0 exposure cap — both are the wrong entity
on the 10 non-self-holder rows. Fixing this also closes the proxy/impl
double-count (`sweepETH`: holder `0x6db24ee6…` vs own `0x5e226b1d…`).

### B2. Destination and amount shape — the static lattice (largest single miss)

The scorer reads only the fork-observed `observed.*` block. **The static
destination/amount lattice on `witness.flows[]` is entirely unread — and it is
the only plane that can positively *prove* a fixed destination.**
`services/effects/config.py:52`: *"only static can positively PROVE the two fixed
shapes (universals, argued from the source); simulation can only PROVE
`caller_arbitrary` (an existential)."*

| field | count | status | decides |
|---|--:|---|---|
| `claims[].witness.flows[].target_kind.{kind,tier}` | 127 entries on flow.out+value_router, 100% populated. flow.out: `param` 53, **`immutable` 18**, `msg_sender` 6, `several` 4, `indeterminate` 3, `storage_setter` 2 | **REQUIRED** | the static destination shape. `dispositive_ast` = the operand *is* a StateVariable/param/`msg.sender`/literal (Tier 1); `static_trace` = recovered via SSA provenance (Tier 2, still deterministic). Both admissible; only `indeterminate` is not (`effects.py:2460-2552`, `:104`). |
| `claims[].witness.flows[].amount_kind.{kind,tier}` | 152 entries, 100%. Bounded kinds on **19 of 86** flow.out entries: `capped_by_balance` 6, `bounded_by_storage` 5, `balance_delta` 4, `msg_value` 2, `token_identity` 2 | **REQUIRED** | the **amount bound** inv.2 already demands. `capped_by_balance` = *"provably ≤ this contract's own balance… a real upper bound / mitigation"* (`effects.py:144-158`). `token_identity` = exactly one non-fungible token moves — **forbids pricing the row off a fungible balance sheet**. |
| `claims[].witness.flows[].target_constraint.{state,guard,binding,pins,leaf_path}` | 63 entries. flow.out: `not_determined` 43, `constrained` 6 (`external_call_revert` 4, `hash_commitment` 2), `unconstrained_proven` 4. value_router: `unconstrained_proven` 5, `constrained`/`hash_commitment` 5 | **REQUIRED** | three-valued and earned in both directions. Per `flows.py:75-80` **only `unconstrained_proven` licenses the caller-chosen (theft-shaped) reading**; `_facts.py:624-628` — *"a missing tree is NOT proof that no gate exists."* `guard` separates a self-enforcing merkle/hash commitment from `external_call_revert` (only as strong as the external contract). |
| `claims[].witness.flows[].from_is_self` | 145/145 (T 89, F 56) | **REQUIRED** | inv.2 already mandates it. Note: **zero `flow.out` flows have `from_is_self=false`** — all 56 sit on `value_router` / `flow.in`, so there is no lever here today. |
| `claims[].witness.flows[].router_ops[].{selector,callee}` | applicable = the 41 `value_router` claims (41 flow entries). **0/41 populated in this snapshot**; the projection lands with U5/D5 and the stored rows gain the key only when the claims stage re-runs — **and only if that re-run actually recomputes `build_claims`**: a claims stage served from the `ANALYSIS_SCHEMA_VERSION = 5` materialization cache (`db/contract_materializations.py:147`) republishes the stored claims unchanged and leaves the count at 0, so the backfill needs explicit invalidation or a forced rebuild. Producer side already 73/73 routed flows (81 op entries); label corpus 5/5 routed flows, now 5/5 on the claims plane too | **CONFIDENCE** (obligation: **cite**) | **the identity of the call(s) that carry a routed move** — the only identity there is, because a routed flow's own `selector` names the CALLEE's inner transfer, not the call this function makes. Each op is `{selector = keccak4 of the signature the AST records — ABI-canonical where the parameter types lower, the DECLARED interface-typed signature otherwise, callee = the bare AST function name}` (`effects.py:_bare_callee_name` :410-418; emitted at `:3305-3307`). Both shapes are in the pinned data: `enter`/`exit` lower to the EVM selectors `0x39d6ba32`/`0x18457e61`, while `safeTransferFrom(IERC20,address,address,uint256)` stays declared and hashes to **`0x5beae096`**, not the canonical `0xd9fc4b61`. **`callee` is an INTRA-UNIT AST identity and never a resolved on-chain target** — the name is carried precisely because that unlowered case hashes to a selector no dispatch will match, so a consumer may join it to this unit's own functions and to nothing else. |
| `claims[].witness.configures` (+ `set_vars`, `hook_pointer`) | 8/8 `transfer_policy.configure` | **REQUIRED** | the contract the policy **affects**. All 8 name BoringVault (**$1,392,349**) while living on a Teller holding **$0**. Re-points VaS. **Direction: raises.** |
| `claims[].witness.destination_constraint.{guard,binding,pins}` | 5 / 5 / 4 on `exec.arbitrary` | **REQUIRED** | the scorer reads only `.state`. The `hash_commitment` + `pins=true` rows are the four timelock `execute`/`executeBatch` functions — a **genuinely stronger `constrained`** than `EtherFiNodesManager.forwardExternalCall`, whose `constrained` rests on `external_call_revert` (only as strong as the external contract) and which is the one EOA-gated, CONFIRMED-M11 arbitrary-exec finding. Same 0.35 softening today, materially different evidence. |
| `claims[].witness.callee` (+ `sink_id`, `source_tier`) | 11 `cross_contract_join` (flow.in 6, flow.out 5) | **REQUIRED** | where the value actually is — all 11 name BoringVault ($1.39M) from a $0 Teller. Same class as B1/G2, different mechanism. |

**R-ROUTEROPS — three-state, and the absence path is the fail-closed one.**
`router_ops` present with ≥1 op = the carrying call(s) are **proven** (AST, no
inference, no default, no name classification anywhere in the derivation).
**Key absent = `not_determined`**, and it is the single reachable failure state:
the producer recorded nothing, the artifact predates the field, or the flow is
not routed at all — `flows.py:92-93` guards on truthiness, so a missing field and
an empty list collapse into the same key-absent shape and **`[]` is never
emitted**. That matters because an empty list of ops reads as "this routed flow
crosses no call", which would license exactly the transparency the absence
denies. Absence therefore keeps its existing fail-closed meaning, which the
in-process consumer already enforces (`_facts.py:485-529`): a routed flow with no
recorded op makes nothing extra transparent, its router leaf **blocks**, and the
mandatory gate falls to `not_determined` — it can never mint
`unconstrained_proven`. **There is no proven-absent state**: "this routed move
crosses no call" is not representable and must not be inferred from key absence.
The projection is a passthrough of a value the in-process consumer has always
read, so no published verdict inverts; only a consumer holding the persisted
witness alone changes, from `not_determined` to the same AST fact. Ops arrive in
the producer's sort order and the projection preserves it; the order carries no
severity. **Small populations:** none relied on (producer 73/73, applicable
claims 41/41) — but note the end-to-end join the investigation byte-verified
covers **11** of the 41 rows, the remaining 30 failing only on ABI-vs-Slither
signature canonicalization, not on data absence.

**R-STATIC — the computation already exists and is sanctioned.**
`services/effects/calldata.py:1077 static_destination_shape` is a **conjunction**
over every `out` + `value_router` flow: `_FIXED_TARGET_KINDS = {immutable,
constant, storage_no_setter}` ⇒ `immutable_fixed`; those plus `storage_setter`
(`_ADMIN_TARGET_KIND`) ⇒ `storage_determined`; anything else ⇒ no shape. It runs
only inside the effects/verdict stage, so **a function with no fork verdict never
receives a shape even though the static inputs sit in its own claim.**

Replayed over `claims[].witness.flows[]`: **3 agreements / 0 contradictions**
against the 3 rows where the fork independently published `immutable_fixed`, and
**0 contradictions** against the 36 published `caller_arbitrary` rows (all
recompute to `None`). **11 functions gain a proven shape they do not have today;
6 have a scoreable key.** A conforming scorer must run this recomputation before
falling through to a warning.

Three implementation rules, all in the writer's own docs, all fail **open** if
ignored:

1. `kind='several'` is a **set, not a disjunction** — the sites *"may be
   mutually exclusive branches or may all execute in one call"* (`effects.py:2535`).
   Expand `target_kinds` and take the **worst** member. 4 flow.out + 2 value_router.
2. The conjunction **must include `value_router` flows** (`calldata.py:1097`), or a
   router publishes `immutable_fixed` off a fee transfer while forwarding the
   principal to `vault.exit(to,…)`. This bites in the real data:
   `LayerZeroTellerWithRateLimiting.bridge`.
3. A `flow.out`/`value_router` claim with **no `flows` key** must block the
   conjunction, not be skipped — the 11 `policy_derived` `cross_contract_join`
   claims carry `callee`/`sink_id` instead of `flows`, and silence there is not
   evidence.

`storage_determined` needs a **new severity rung** — "redirectable, but only by
whoever holds the setter" (`calldata.py:1055`), an admin fact strictly between
`immutable_fixed` and `caller_arbitrary`. 2 rows here; the rung matters more than
the rows.

**B2×B8 worked example — why all three planes must be read together.** The two
functions Appendix A names as the etherfi headline, `EtherFiRestaker.withdrawEther`
and `.stEthClaimWithdrawals` (EOA-gated), contribute **exactly 0.000** today.
Combining the planes:

- B2 static lattice ⇒ destination is **`immutable_fixed`** (proven) ⇒ operational
  routing, sev 0.10 — not the unscored warning it is now.
- B2 amount lattice ⇒ **`capped_by_balance`** ⇒ ceiling is the contract's own
  balance.
- B2 flow kind ⇒ **`low_level_value_call`** ⇒ **native ETH only**.
- B8 per-asset ⇒ EtherFiRestaker holds **$0.00 native** of its $467,568,890
  (all stETH, plus 6 spam tokens).

So the honest weight is the **band floor**, not `band($467M)`. Scoring the
contract sheet would have published ~3.78 raw where the evidence supports ~0.81 —
a 4.7× over-claim, and precisely the `sweepETH` error in a new place. **No single
plane gives the right answer; the register requires the conjunction.**

**G3 — the one gap no field in `claims[]` can close.**
`EtherFiRestaker.stEthRequestWithdrawal` and `.depositIntoStrategy` each publish a
**proven $467,568,890 reach** (`reach_determined=true`) with
`destination_shape='unknown'`, `shape_proved_by='none'`, and **no `flows` key at
all**. F6 discards the claim entirely, so a proven half-billion-dollar reach behind
an EOA scores **zero** — and the B2 recomputation cannot rescue it, because there
is no static lattice to read. Fixing this needs a probe or an upstream static flow
extraction, **not a scorer change**. Until then it is the single largest honest
`not_determined` on the value axis and belongs in the confidence figure with its
magnitude named.

Note the alignment that makes F6's `continue` defensible today: the 4
`shape_proved_by='none'` rows are **exactly** the 4 `destination_shape='unknown'`
rows, and `claims_bridge.py:252-256` says `none` "means the destination contributes
ZERO severity in either direction: a confidence gap, not a fixed destination and
not a theft-shaped one." F6 is right about *these* rows and wrong about the 44 that
carry a static lattice.

### B3. Freeze severity and scope

| field | count | status | decides |
|---|--:|---|---|
| `claims[].witness.observed.pause_effective` | 4 / 36 pause.set (all `true`) | **REQUIRED** | fork existence proof the latch took effect. Separates the 4 witnessed claims from the 32 static ones. |
| `claims[].witness.observed.observed_blast_radius[]` | 4 / 63 freeze verdicts | **REQUIRED** | which entry points freeze — 1–4 functions, never the whole contract. |
| `effect_verdicts.witness.scored_denominator[]` | **4 proven** (33 entries) / 59 unknown | **REQUIRED** | static's predicted guard set — the **proven denominator** for blast-radius scope. `anvil.py:349`: *"The scored denominator stays static's set; the observed set is a lower bound recorded alongside it."* Replaces the scorer's invented `value_fns` proxy. Not projected into claims. |
| `claims[].witness.observed.duration_bound_source` | 4/4, all `not_determined` | **GATE** | see T-BOUND. |
| `claims[].witness.polarity` | 75/75 (`set` 32, `unset` 43) | **REQUIRED** | recovery direction. |
| `pause.unset` claims + their `function_principals` | 30/30 contracts carrying `pause.set` | **REQUIRED** | the recovery path, resolved **per pauser key**: a pauser that is not the sole unpauser cannot sustain its own freeze. `pause.unset` has **no behavioral witness at all** (no unfreeze recipe exists, `claims_bridge.py:219`) — the static claim is the correct available evidence, but it is not a fork proof, and the spec must say so. |
| `effect_verdicts` freeze rows | 63 total: `pause_froze_entry_points` **4 proven**; `no_blast_radius_observed` 29, `pause_ineffective` 22, `no_live_entry_points_to_freeze` 8 — **all unknown** | see T-FREEZE | |

**Only 4 of 63 freeze verdicts are proven.** That 94%-undetermined evidence base
is the actual justification for a floor severity on `pause.set` — not any
judgement that pausing is benign.

**`no_blast_radius_observed` (29) is the one usable residue** — `anvil.py:333`:
*"pause_effective True + empty blast = a GENUINE no-blast: the pause took effect
yet froze nothing observable."* It proves those 29 restricted state-changing
functions are **not** freezes. **CONFIDENCE only**; shrinks the unknown set
monotonically (inv.6), changes no grade.

### B4. Principal strength

| field | count | status | decides |
|---|--:|---|---|
| `function_principals.details->>'delay'` | **139/139** timelock rows, 0 nulls, 0 zeros | **REQUIRED** | **THREE** timelocks, not two: `0x9f26d4…` **864000s = 10d** (75 fns / 24 contracts / 44 upgrade rows / $4,058,743,866), `0xcd425f…` **172800s = 2d** (53 / 16 / 0 / $4,056,989,156), `0x70a648…` **432000s = 5d** (11 / 3 / 0 / $14,371,162). The 5-day one is **absent from Appendix A**. The 10d and 2d gate **disjoint** function sets yet reach nearly the same value. Proven by a real `eth_call getMinDelay()` → `delay()` fallback, published only after `_duck_type_permitted()` clears a negative-control probe (`tracking.py:788-796`, `:689-697`). Scorer: flat `0.15` for all (`scorer_v2.py:232`). |
| `function_principals.details->>'threshold'` + `jsonb_array_length(details->'owners')` | 454/454 safe rows | REQUIRED (in use) | k/n, on-chain `getOwners()`/`getThreshold()` (`tracking.py:674-685`). **Upper bound on protection only** — see B10.1. |
| `details->'owners'` pairwise intersection | 11 distinct Safes, 11 overlapping pairs | **REQUIRED** | **R-OVERLAP.** Three pairs where the shared owners **alone meet both thresholds**: `0xa000244b` 3/7 ↔ `0xf46d3734` 4/8 share **5**; `0x2aca7102` 4/7 ↔ `0x427989bb` **1/5** share **5**; `0x41dfc53b` 2/4 ↔ `0x71e2d6c3` 2/4 share **3**. Not independent principals: one aggregation unit under inv.13, one weakest-path row under inv.5. The 3/7↔4/8 pair is currently **two separate ledger rows** (raw 10.50 and 9.90). A GIN index exists for this: `ix_function_principals_safe_owners`. **Direction: raises** — removes an implicit diversification credit. **Does NOT retract the freeze recovery credit**: that test asks whether *one* key can sustain a freeze, and one owner of the 1/5 still cannot stop the 4/7 from unpausing. |
| `capability_expr->'members'` cardinality | **perfect 1:1 with `function_principals` on all 642 `finite_set` rows** | **REQUIRED** | breadth. 487 single-holder, 64 two, 25 three, 14 with ≥4 — incl. `AccountantWithRateProviders.pause` and `LayerZeroTellerWithRateLimiting.pause` at **10 holders each**. `max(weakness)` is a sound floor but discards breadth: ten keys that can each freeze is a larger compromise surface than one. **Addition, not correction** — safe to defer without publishing anything false. |
| `details->>'membership_quality'` / `'confidence'` | `exact`/`enumerable` 863; **`lower_bound`/`partial` 7** | **GATE** | an incomplete principal set is not interchangeable with a complete one. |
| `effective_functions.authority_roles` | 824/1168 non-null but **643 are `[]`; only 181 carry a role** (role 8 ×116) | **REQUIRED** | inv.13 aggregation unit: N functions requiring the *same role* on the *same registry* are one capability. `principals[*].resolved_type` is **NULL on all 211** — resolve through `function_principals`. |
| `details->'trace'[*].role_labels` | 242 rows | **REQUIRED** | keccak-id → source constant (`UPGRADE_TIMELOCK_ROLE`, `OPERATION_MULTISIG_ROLE`, `OPERATION_TIMELOCK_ROLE`). Read from the registry, not inferred. |
| `details->'trace'[*].probe_block` / `fold_frontier` / `candidate_count` | 141/454 safe, 108/139 timelock, 47/100 eoa, **0/177 contract** | **REQUIRED** | observation block and fold completeness — inv.11/inv.12 replayability. |
| `controller_values` (`source`, `value`, `resolved_type`, `block_number`, `authority_provenance`, `observed_via`) | 290 rows; `caller_gate` 144 / `call_target` 72 / NULL 74; `block_number` 290/290 | **REQUIRED** | **never queried by the scorer.** `authority_provenance='caller_gate'` means a lowered predicate-tree leaf **provably** gates on that variable. This proves the whole `RolesAuthority`→Boring root: 10 registries with `authority=0x0` and `owner=` Safe 4/6 `0xcea803…` (9 of them) or the **5-day timelock** (1); 9 BoringVaults + BoringGovernance with `owner=0x0, authority=<registry>`. Two-hop closure from the 4/6 Safe: **21 contracts, $79,655,013**. |
| `control_graph_nodes.analysis_state` | `analyzed` 1087, `not_analyzable` 1299, **`attempt_failed` 39**, **`beyond_depth_horizon` 29** (6 of them timelocks), NULL 19 | CONFIDENCE | distinguishes "walked and terminated" from "tried and failed" from "hit the depth limit". Only the latter two can improve — required for inv.6's monotone property. |

**Resolution-provenance tiering (admissibility, not just provenance).** `origin`
and `details->>'source'` are constants (T-ORIGIN); the real provenance is
`details->'trace'[*].step`, and its tiers are not equal in strength:

| step | rows | strength |
|---|--:|---|
| `solmate_roles_authority` | 261 | deterministic event fold (`RoleCapabilityUpdated`/`PublicCapabilityUpdated`/`UserRoleUpdated`) |
| `enumerable_role_store` | 242 | deterministic role-filtered fold vs the runtime; carries `probe_block`, `fold_frontier`, `candidate_count` |
| `live_getter_resolution` | 44 | deterministic `eth_call` of a nullary getter |
| `authority_getter_basis` | 33 | **convention-bound** — see T-ACCESSOR |
| `param_keyed_mapping_enumeration` | 7 | deterministic fold, honestly self-labelled: the **only 7** `lower_bound`/`partial` rows in the table |
| `live_slot_resolution` | 2 | deterministic storage read *(small-N)* |

**503 rows are event folds; 33 are a naming convention.** A conforming scorer must
not present those 33 as equal-strength evidence. **No LLM anywhere in this plane** —
nothing in `function_principals` or `control_graph_edges` is model-generated.

**Value actually reachable per relation** (distinct `to_node` addresses holding
balances), which is why the whitelist matters: `controller_value` 11 of 70 targets
→ **$94,026,175**; `role_principal` 1 of 51 → **$29,976,517**; `safe_owner` 0 of 65
→ **$0**; `mapping_member` 0 of 10 → $0; `controller_value_unattributed` 0 of 15 →
$0; `external_call_target` 11 of 50 → **$180,590,426,705** (excluded).
`control_graph_edges.notes` echoes `authority_provenance` on **every** row and is a
usable secondary check.

**R-REGISTRY.** Ownership of a role registry means the holder can grant itself any
role that registry gates, so its proven severity is the **max severity of anything
the registry gates** (the Boring vaults' arbitrary-call surface), not
`roles.configure`'s 0.55. The 50 `RolesAuthority` OR-rows reduce to **exactly one
principal** with no contract-gated unknown. **Direction: raises** the 4/6 Safe row
(currently the top finding at raw 11.03 — the transitive *value* already reaches,
the *severity* does not); **lowers** it for the one registry owned by the 5-day
timelock, a distinction the scorer cannot currently express.

**Contract-gated paths are more resolvable than the warnings imply.** **24 of the
78** distinct `contract`-typed principals resolve one hop: 12 are protocol
contracts with analyzed functions and their own resolved principals, and 12 are
proxies whose `contracts.implementation` row is fully analyzed with principals
(e.g. `0x308861a4…` → LiquidityPool, 44 fns / 36 principals). The scorer returns
`weakness=None` → warning for all 78.

### B4b. Timelock collapse — constructible for 2 of 3 timelocks

The inv.5 violation in `SCORING_CALIBRATION_REVIEW.md` §7.1 is resolvable today.
The timelocks are themselves analyzed protocol contracts, so
`contracts.address = function_principals.address` links timelock-as-principal to
timelock-as-contract, whose own `schedule`/`execute` gates are resolved principals.

| timelock (delay) | schedule/execute gated by | cancel also | grantRole / updateDelay |
|---|---|---|---|
| `0x9f26d4…` (10d) | Safe **6/10** `0xcdd57d11…` | Safe **4/6** `0x055a8b2b…` | **itself** |
| `0x70a648…` (5d) | Safe **4/6** `0xcea803…` | same 4/6 | **itself** |
| `0xcd425f…` (2d) | **not determined** — `contracts.id=11` has **0 `effective_functions`** | — | — |

Three decisions this enables:

1. **Collapse (inv.5).** `exec.arbitrary` on `EtherFiTimelock.execute/executeBatch`
   (Safe 6/10, raw 7.35) and `upgrade.implementation` by the timelock principal
   (raw 9.00) are the same power through the same delay. One row, weakness =
   f(6/10 quorum, 864000s). Removes ~7.35 raw of double-count and the ~27%
   WeETH exposure double-charge.
2. **Anti-decoy proof (inv.13).** `updateDelay` and `grantRole`/`revokeRole` on both
   analyzed timelocks are gated by **the timelock itself** — the delay cannot be
   shortened nor the proposer set changed without first waiting the full delay. A
   timelock whose role admin is an EOA is a decoy; these provably are not. A
   stateable **credit**.
3. **Veto path.** `cancel` on the 10-day timelock has a **second, disjoint**
   canceller (Safe 4/6). Proven protective fact, unused. *Small-N: 2 rows.*

`role_definitions` independently carries `PROPOSER_ROLE`/`EXECUTOR_ROLE`/
`CANCELLER_ROLE` for both analyzed timelocks; `claims[].witness.standard =
'oz_timelock'` (16 rows) identifies the mechanism without name inference.

### B4c. `role_definitions.role_name` — admission (D6-reject, 2026-07-30)

| field | JSON path / column | pop. | status | three-state | failure path |
|---|---|--:|---|---|---|
| `role_name` | `role_definitions.role_name`; artifact `semantic_control.role_definitions[].role` | 19 rows total, 11 protocol-1 | **CONFIDENCE** (a declared role name, not a holder set) | present = the constant is **proven** to be a key of a set the contract tests membership in / **row absent** = not determined | a leaf the lowering could not classify, a `bytes32` constant whose set descriptor is missing, or a state var not in scope ⇒ **no row**. Absence is never "this contract has no roles" |

**Admission rule (structural, one arm, no identifier is read).** A
`bytes32 constant` operand mints a role name only when it is witnessed as the
**KEY of a persisted mapping the leaf tests membership in**: leaf
`kind == "membership"` **AND** `set_descriptor.kind == "mapping_membership"`
**AND** the operand's `member_path` is empty. That is the in-contract
AccessControl read `_roles[ROLE][account]`, where the lowering saw both the
mapping and the constant indexing it. A non-empty `member_path` means the
constant is a struct BASE being dereferenced, which is what a storage-layout
pointer is.

Measured on the persisted predicate trees of contracts 454 / 599 / 623: 8 real
roles all match, and the 2 ERC-7201 pointers
(`AccessControlDefaultAdminRulesStorageLocation` with `member_path ["_pendingDefaultAdmin"]`,
`OwnableStorageLocation` with `["_owner"]`) match none — they are `equality`
leaves with no set descriptor at all.

**Residual, stated with cause: cross-contract role checks — including a genuine
`registry.hasRole(bytes32,address)` registry — mint no `role_definitions` row.**
An `external_set` descriptor records the callee's signature and selector from
`ir.function.full_name` (`predicates.py:2338`), which is the interface the
**CALLING** contract declared, not a proven property of the deployed callee. A
slot lens, a merkle-tree contract, or a `hasRole` whose body is
`return salts[salt]` and drops its `account` argument entirely all lower to a
byte-identical descriptor when declared under that name, and each was measured
minting an ERC-7201 pointer / merkle root / CREATE2 salt as a role. Argument
position adds no independent witness: `_build_external_bool_leaf` fills
`key_sources` from *every* call argument, so "is an argument of a gate-shaped
view call" stands in for key-ness — a defaulted witness. **Those roles are
`not_determined`, never "no roles".** The excision costs nothing measured: across
all six role-bearing contracts in the persisted corpus every surviving row is
mapping-arm and the `external_set` descriptor count over the 19 rows is **0**, so
the arm's only exhibit was a synthetic test contract — under B14 a rule with
population 0 may not be kept.

`predicate_evaluator._canonical_authority_selector_for_slot` carries a related
refusal so a role key is never re-read as an `owner()`/`governor()` slot locator.
It is deliberately **wider** there (leaf kind + descriptor kind, admitting
`external_set` too): that predicate WITHHOLDS a reroute, so over-matching costs a
resolution, never publishes a wrong address, whereas this rule MINTS a fact and
must be strict.

**Banned as the fix:** the name-suffix guard `_is_storage_layout_constant`
(inv.2 — it classifies on `endswith("_slot")` / `"storagelocation"` and is wrong
in **both** directions); gating on `set_descriptor.storage_var == '_roles'` or on
the presence of `enumeration_hint` — contract 599's five real Lido roles
(`FINALIZE` / `MANAGE_TOKEN_URI` / `ORACLE` / `PAUSE` / `RESUME`) carry
`storage_var: "TMP_1189"` and **no** `enumeration_hint`, so either gate drops
all five.

**Coverage, published as `not_determined` and never as "no roles":** 50
role-keyed gates carry the role as a `view_call` (30) or `parameter` (20) operand
and never reach `role_definitions` at all. `authority_plane_coverage` for the
real names is `not_determined` — they are absent from `effective_functions.authority_roles`,
`capability_expr`, `claims`, `function_principals.details` and
`control_graph_edges.label` by name and by keccak, which is a coverage gap, not
evidence that no such role gates anything. `TIMELOCK_ADMIN_ROLE` is not carried
at all, so B0b's anti-decoy credit stays CONFIDENCE.

**Flips:** ids **1** (contract 454) and **19** (contract 623) stop being written.
No user-visible fact moves — the table has no reader outside its own writer
(`workers/static_worker.py:2003`, which DELETEs the contract's rows and
re-inserts from the fresh analysis, so a re-analysis is the whole deletion
vehicle) and the cross-chain code-plane copier (`db/queue.py:2073-2082`, which
only fills a target that has none). The artifact field is read in-process by
`contract_analysis_pipeline/tracking.py:1103` to build controller tracking hints.
**Residual:** until a donor contract is re-analyzed its pre-fix rows persist, and
`db/queue.py:2073`'s copier will replicate them — including the two ERC-7201
pointer rows — into a never-analyzed target's table on the next cross-chain reuse.

**Small populations (B14 — none may calibrate):** mis-parsed rows **2**;
protocol-1 role-event emitters **3**; the `OPERATING_ADMIN_ROLE` holder set **1**
address; the `TIMELOCK_ADMIN_ROLE` evidence **1** grant log. The five contract-599
role names are **single-witness** (leaf shape only — those addresses have no
cursor, so there is no corroborating fold).

### B5. Earned negatives — proven-inert, not unknown

| fact | count | status | decides |
|---|--:|---|---|
| `capability_expr` `finite_set` + `members=[]` + `membership_quality='exact'` + `confidence='enumerable'` | **52 rows**, all `restricted`, all with 0 principals | **REQUIRED** | **nobody can call it.** The empty is *earned*: `solmate_roles.py:178-197` refuses to emit an exact empty in both failure modes (index-cold → `no_index_cursor` + `deferred_pending_index`; authority-unconfirmed → `authority_unconfirmed_no_role_events`), both falling through to `external_check_only`; read-gap empties get `lower_bound`/`partial` + an `empty_reason`. Measured: **52/52 exact+enumerable, 0 lower_bound.** Cross-verified on `TellerWithMultiAssetSupport.setAuthority`: `trace.roles=[]` **and** `owner=0x0` at block 25641257 — both disjuncts of Solmate `requiresAuth` provably empty. **All 11 `restricted_no_principal` warnings are exactly these rows**, and their `"missing_witness": "principal resolution"` text is **factually wrong** — resolution ran and returned "nobody". inv.13 requires inert functions be no-ops. |
| `controller_values` `source='owner'`, `resolved_type='zero'`, `authority_provenance='caller_gate'` | **22 rows / 22 contracts holding $94,026,174** | **REQUIRED** | `owner == address(0)`, each an `eth_call` at a recorded block. **Lowers:** the owner disjunct is dead, so a resolved role finite_set is the *whole* answer, not a lower bound. **Raises:** where the only recovery/unpause path was the owner, this is the **affirmative** `irreversibility_proven` witness that `freeze_severity()` currently infers from claim *absence*. |
| `effective_functions.conditions` `kind='one_shot'` + `latch_state='consumed'` | **22 rows** (21 open, 1 restricted), all `initialize`-family | **REQUIRED** | a spent initializer is inert. Current impact **zero** (none carry claims) — reported because that is *accidental*, not principled: initializers routinely grant admin roles, and the first `roles.grant` matcher that fires on one produces a catastrophic-shaped **open** finding. This latch is the proven refutation. |
| `indexed_event_cursors.backfill_complete` + `last_indexed_block` (+ `last_indexed_block_hash`) | **80/80 warm**, all at block 25641245, hash on 80/80 | **GATE** | bounds a cursor from **ABOVE only**. Verified in code, not taken from the flag: `_seed_block` seeds `creation_block - 1` and **defers enrollment entirely** when the creation block can't be resolved (`event_log_indexer.py:607`); the zero address is rejected (`:594`); `backfill_complete` is set only at the confirmation-depth-deep head; a reorg rewind deletes logs address-wide and clears the flag on every sibling cursor. It does **not** on its own make absence a proven negative — limits 1, 4 and 5 below must also hold, and on all 80 legacy rows limits 1 and 5 do not. |
| `indexed_event_cursors.first_indexed_block` + `first_indexed_block_basis` | 0/80 today (nullable, no backfill); written on every new enrolment | **GATE** | the covered range's LOWER bound. proven-present = basis `creation_block_minus_one` (all three pinned reads agreed). proven-absent: n/a — this is a bound, not a predicate. `not_determined` = NULL/NULL (predates the column), NULL + basis `not_determined` (witness attempted and failed), or a value with basis `explicit_seed` (a seed, not evidence; population 0). **The revert/failure/absence path is `not_determined`**, and the block is discarded with the basis so no consumer can see a number it may not cite. Consumption: **cite** on any event-absence claim; **gate** for U7B's `holder_set_exhaustive`. |
| `indexed_event_cursors.enrollment_basis` | 0/80 today (NULL = predates); `predicate_tree_hint` or `tracked_topics_asserted` on every new row | **GATE (ALLOW-LIST)** | whether the row carries a variable attribution. Exactness is permitted **only** for `enrollment_basis IS NULL` (predates the column; those 80 rows folded before it existed) or `= 'predicate_tree_hint'` (a static writer hint named this topic as a writer of a specific storage variable). **Everything else is refused**, including `tracked_topics_asserted`, the literal `not_determined` that `enroll_event_cursor` stores when a caller omits the argument, and any token added later — a deny-list on the one token we invented would have failed OPEN on the other two. Enforced at the single `event_logs_pg._cursor_state` choke point via `enrollment_basis_permits_exactness`, and at the two out-of-band cursor readers (`_authority_has_role_store_cursor`, `_authority_backfilled`) via its SQL twin, so a refused cursor cannot masquerade as "the index caught up". **Failure path = anything unrecognised = no exactness.** Consumption: **gate**. |
| `indexed_event_cursors.max_window_log_count` + `window_stats_cap` + `window_stats_basis` | 0/80 counts (NULL); `window_stats_basis='unmeasured_legacy'` stamped on 80/80 by the migration | **GATE** | per-cursor page completeness. proven-present = `complete` (continuous record ∧ max < cap ∧ persisted cap == cap in force). proven-absent = `incomplete` (a page reached its cap). `not_determined` = anything else, **including the shipped default (cap unset), so it is the state of every cursor today**. `unmeasured_legacy` means NEVER MEASURED — it is not lane-D's `coverage: "partial"` (measured and incomplete) — and counts stay NULL rather than 0, which would read as a measured empty page. **Failure/absence path = `not_determined`.** Consumption: **gate** on "no such event exists"; **cite** the residual otherwise. |
| `absence_coverage` object (`services/resolution/absence_coverage.py`; computed, not stored) | per (chain_id, address) | **GATE (CONF payload)** | ceiling, never a licence. Carries `write_surface` (always `null`), `write_surface_basis` (always `not_determined`), `write_surface_asserted` (a caller's echo, under its own key), `enrolled`/`warm`/`missing`, `range_lower_bound(_basis)`, `page_completeness`, `enrollment_complete` (**always false**), `earned_negative_admissible` (**always false**), `blocking_reasons`. The gate ships inside the same object as its payload, so a consumer cannot read the numbers without the verdict. **Small-pop: denylist emitters 4 addresses, 0-cursor subset 3 — B14: cite/gate/three-state only, never calibrate an enrolment threshold. No threshold, ratio or weight is derived anywhere in U10A.** |
| never-emitted events | **25 zero-log warm cursors / 8 addresses** (this register previously said 11/4, which does not reproduce under any join) | **`not_determined` — WITHDRAWN (U10A / D4)** | ~~The transfer denylist has provably never been written since deployment.~~ **Withdrawn, not softened, and for all three denylist variables — `toDenyList`, `fromDenyList` and `operatorDenyList` alike.** The writers are 6 topics across 4 protocol-1 Tellers = 24 (address, topic0) pairs, of which **4 are enrolled** — all 4 on `0x4de413a2` (`AllowFrom`/`DenyFrom`/`AllowOperator`/`DenyOperator`), while `AllowTo`/`DenyTo` have **no cursor at any of the 4 emitters** and the other 3 emitters have **no cursor at all**. 4 of 24 covers no variable's write surface across the emitter set, so the 4 warm zero-log cursors license nothing about `fromDenyList` or `operatorDenyList` either — B5 limit 4 forbids all three. Even those 4 carry an unquantified page residual (limit 5). The conclusion may well be true — an ad-hoc genesis fold returned 0 logs — but that fold is not persisted and so cannot license a replayable claim (inv.11). **The withdrawal is not yet enforced by the resolver, and this row must not be read as if it were.** Those 4 cursors on `0x4de413a2` predate `enrollment_basis`, so they are NULL, so the exactness allow-list still admits them: `event_logs_pg` will keep folding them `enumerable` and can still mint an exact empty over exactly the surface this row declares `not_determined`. Closing that is the limit-1 stated deferral (it demotes all 80 legacy cursors and collapses the 52 exact-empty rows above, which rest on a different basis), not a U10A change. Until it lands, **the register and the resolver disagree, and the register is the one that is right.** The path is additionally blocked today by `event_logs_pg.py:134-136`, which returns `unresolved_event_key` for the param-keyed `toDenyList[to]` shape before `_cursor_state` is ever consulted, so no exact empty is reachable right now; the gap arms only if `predicate_artifacts.py:592-624` starts emitting that hint (U6/D3) **before** the limit-1 deferral lands. |
| `monitored_contracts.monitoring_config.tracked_topics[]` | **224 (address, topic0) pairs / 46 addresses**, all active, all `chain='ethereum'` | **GATE for enrolment; BAN as a topic→variable map** | ~~the topic0 → state-variable map~~ — it is **not** one: `effect_tags.writes[]` is a union across every emitter of a signature (`tracking.py::_effect_tags_for_signature`), so all six Allow/Deny entries carry the identical triple and reading it forward attributes a write to the wrong event. What it IS good for is **enrolment**: `topic0` alone names a durable cursor. Before U10A only **4 of 224** pairs had one, and `enroll_from_completed_jobs` could never mint the rest because it reads only `enumeration_hint` records. `enroll_from_tracked_topics` (U10A) closes that, minting **~220 new pairs over 85 distinct topic0s across all 46 addresses — including all 24/24 denylist pairs**. The per-pass budget bounds the addresses that still NEED a cursor, not the rows inspected, and fully-enrolled addresses are skipped without cost; a budget on rows inspected would have re-walked the head of the id ordering every pass and left the tail (ranks past the limit, 102 active contracts vs a limit of 50) permanently unenrolled while appearing to drain — and which addresses those were would have depended on an ordering nothing records. Those rows carry `enrollment_basis = 'tracked_topics_asserted'`, which is **not on the exactness allow-list**, so they index history and license nothing. |

**Two independent planes can answer the same question — read both before
publishing `not_determined`.** `controller_values` records **19** protocol-1 rows
with `observed_via='eth_call_error'` (`fromDenyList` 5, `toDenyList` 5,
`operatorDenyList` 5, `isSupported` 4) plus 43 rows carrying a `details.error`
(`execution reverted`, `Projected member read is missing struct components`). Those
are explicit read failures — warning material, never a fact. But `fromDenyList` is
**exactly** the variable whose *event* history proves it was never written: the
`eth_call` failed and the event index answers it anyway. A scorer that consults only
the call plane publishes an unknown it already has the evidence to resolve.

**Five limits on absence-as-proof, verbatim into any implementation:**

1. **The lower bound of the covered range is persisted only where it was
   witnessed.** `indexed_event_cursors.first_indexed_block` +
   `first_indexed_block_basis` now exist (U10A). The bound may be cited **only**
   on basis `creation_block_minus_one`, which requires all three pinned reads to
   agree: `eth_getCode` empty at `B−1`, non-empty and not a 0xef0100 (EIP-7702)
   stub at `B`, **and** a genesis-anchored untopiced `eth_getLogs` returning zero
   logs at or below `B−1`. The first two alone prove that *a* deployment landed at
   `B`, not that it was the *first* — CREATE2 over a pre-Cancun-cleared address
   reads identically. Basis `explicit_seed` is a caller's seed, not a witness.
   NULL/NULL = predates the column: **all 80 legacy rows**, deliberately not
   backfilled, because a value recovered now from a cache is not a value that was
   witnessed then. NULL must reach the consumer as "lower bound unknown", never
   as 0.
   **Residual on the third read, stated on the same footing as limit 5's cap.**
   A node that serves `[]` for a range it does not actually index is
   indistinguishable from a proven empty, and the probe persists neither the
   observation nor which upstream answered it. The control that makes the reads
   non-vacuous is that the same harness returned **237 logs** above the creation
   block for the same address while returning 0 below it — evidence that the
   route answers this address at all, not evidence that it answers every range
   completely. So the basis means "no prior incarnation was OBSERVED by one
   unrecorded route at one moment", which is weaker than "no prior incarnation
   exists". It is admissible because every failure direction lands on
   `not_determined`; it is not a proof that survives a lying upstream.
   **STATED DEFERRAL (U10A):** this bound is *published* but is deliberately NOT
   wired into `event_logs_pg`'s exactness gates. Doing so would demote all 80
   legacy cursors and collapse the 52 exact-empty rows in the first row of this
   table, whose empty rests on a different and stronger basis
   (`solmate_roles.py:178-197` refusing an exact empty in both failure modes).
   That is a separate change with its own blast radius and its own panel. What
   U10A *does* gate on is `enrollment_basis` (limit 4), which is scoped to the
   rows U10A itself creates.
2. **No cursor is not evidence of anything.** Cursors exist for only 32 addresses ×
   25 topics — whatever monitoring/resolution enrolled.
3. **Never assert at live head.** `_cursor_covers_block` (`event_logs_pg.py:74`)
   already refuses: the cursor lags head by ≥ `confirmation_depth` + poll
   interval. Absence is proven up to `last_indexed_block`, not to now.
4. **Absence is proven for a state variable only if EVERY topic that can write it
   has a warm cursor. Enumerate the write surface, then check enrollment.** That
   enumeration is **`not_determined` today and no code here changes it**: the
   static pass attaches writer-event hints only to CALLER-keyed mappings
   (`predicate_artifacts.py:592-624`), so a mapping keyed on a function parameter
   gets none; `SemanticControlAnalysis.mapping_writer_events` is declared and
   never populated; and `tracked_topics[].effect_tags.writes[]` is BANNED as a
   topic→variable map (a union across every emitter of a signature). Therefore
   `services/resolution/absence_coverage.py` publishes a **ceiling** —
   `enrollment_complete` — and hard-wires `earned_negative_admissible: False`.
   Supplying `write_surface_topics` populates `enrolled`/`missing`/
   `blocking_reasons` **for reporting only**; it never changes
   `write_surface_basis`, and therefore never changes either verdict. Making the
   verdict reachable requires a proven inverse index and a new adversarial panel.
5. **A page returned at an upstream's result cap is not a proven page.** The
   fetcher now treats a 200-OK page whose length reaches the configured cap as a
   REJECT and bisects it, and records `max_window_log_count` + the
   `window_stats_cap` in force + `window_stats_basis` per cursor. `complete`
   requires a continuous record, a recorded maximum strictly under the cap, and
   that the persisted cap still be the one in force — a cap change collapses the
   verdict to `not_determined` rather than re-grading history. The shipped cap is
   **unset**, so **no cursor is page-complete today and every event-absence
   negative carries an unquantified residual.** Measured 2026-07-30 against the
   deployed eRPC route: `getLogsMaxAllowedRange` = **2,000,000 on the INCLUSIVE
   count** (`toBlock − fromBlock + 1`; 2,000,000 OK, 2,000,001 → `-32012`
   `ErrGetLogsExceededMaxAllowedRange`, `details.requestRange` equal to that
   count), and production's `end = start + MAX_BLOCK_RANGE − 1` yields exactly
   1,000,000, safely under. No result-cap truncation was observed up to 125,629
   logs in one window, and a `fromBlock: 0x0` request bypasses the range guard
   entirely yet stayed byte-identical to a 1M-chunked fold on two real
   populations (1,902 and 3,541 logs), failing LOUD (`-32603` timeout) at ~82k
   rather than truncating. **That is a mutable now-fact about a third party at one
   moment, not an invariant** — which is why the cap is persisted with the counts
   it gated.

### B6. Preconditions

Read from **`effective_functions.conditions`** — *not* from
`function_principals.details.conditions`, which is a display copy (B11/T-COND).
Population: `business` 2009, `time` 172, `pause` 17, `reentrancy` 10,
`self_service` 6, `denylist` 5, `one_shot` 2.

| kind | count | status | decides |
|---|--:|---|---|
| `one_shot` | 2 (+22 via `latch_state`, B5) | **REQUIRED** | fires once; `latch_state` says whether it already has. |
| `time` | 172 | **REQUIRED** | time-gated exercise, carrying the comparison (`_pausedUntil >= block.timestamp`). **This is structure, not a duration bound** — it does not license a numeric bound credit (T-BOUND). |
| `pause` | 17 | **REQUIRED** | the capability is itself blocked while paused — a protective interlock and the other half of inv.4's accounting. |
| `self_service` | 6 | **REQUIRED** | caller may act only on their own position (`caller matches _ownerOf(uint256)`) — not privileged at all (inv.3). |
| `denylist` / `reentrancy` | 5 / 10 | **REQUIRED** | additional proven guards. |
| `business` | 2009 | CONFIDENCE | free-text `require` descriptions; surface per finding for inv.9 traceability, do not branch. |

### B7. Proof-strength gates

| field | count | status |
|---|--:|---|
| `effect_verdicts.verdict` | **`proven` 69 / `unknown` 205** | **GATE** — only `proven` is admissible. All 205 `unknown` are referenced by **zero** claims; all 69 `proven` are referenced. The projection is sound. |
| `effect_verdicts.tier` / `claims[].witness.verdict_tier` | `tier1` 207 / `tier2` 67; in claims `tier1` 65 / `tier2` 4 | **GATE** |
| `effect_verdicts.witness.observation` | `executed` 179 / `reverted` 95 | **GATE** — `config.py:63-80`: on a reverted row `{"value_moved": false}` means **"not measured"**, never "moves no value". An absent key predates the discriminator; treat as unmeasured unless `verdict='proven'`. |
| `claims[].witness.effect_verdict_id` | 69, all distinct | **REQUIRED** — the join key for B1/B3 fields that are not projected. |
| `claims[].tier` | `standard_exact` 353, `idiom_structural` 100, `behavioral_observed` 69, `policy_derived` 19 | **REQUIRED** — currently collected into `witness_tiers` but **never enters the arithmetic**. |
| `effect_verdicts.transcript_ptr` | 274/274 | **REQUIRED** for inv.9 traceability (a MinIO pointer; the fact is inside the blob). |
| `effect_verdicts.witness.revert_reason` | 39, **all `unknown`** | CONFIDENCE |
| `effect_verdicts.witness.block_number` | **0/274 — the key is ABSENT on every existing row** | **CONFIDENCE, three-state; consume as cite + three-state only.** The height the verdict was observed at. Corrects `FIELDS.md` §7's `304/304, 51 distinct blocks`, which was wrong on both location and denominator: `witness`'s key universe across the 274 rows is 20 distinct keys (per-row 2–10), none a block key, and the 304 counted **transcript blobs** (those do carry it — 51 distinct heights, 25640764…25641259, span 495 blocks in one run; 7 jobs carry two heights each, so the pin is per stage INVOCATION). Emitted from now on by `harness._stamp_observation_height`, the single publication point every recipe's `emit()` passes through. **proven-present** = a positive height the probe demonstrably ran at — Tier 1 simulates at `hex(block_number)`, Tier 2 reports the `--fork-block-number` its own fork was spawned with (`anvil.fork_block_pin`). **There is no proven-absent state**: no verdict is observed at no block. **not_determined is the ABSENT key**, and it is the state every failure and absence path lands on — an unpinnable head (`_preflight` yields the `0` sentinel and disables Tier 1), a fork spawned unpinned, a Tier-0 index read (decides from event history, no single height), and a twin's plain cache hit (state-plane, stripped by `DEPLOYMENT_PLANE_KEYS`). **`0` is never published**: it is the failure sentinel and forks at genesis. Never arithmetic and never a gate — a scorer may cite it and must treat its absence as unknown, never as "current". All 274 existing rows stay `not_determined`; the 78 Tier-2 rows' true heights are **unrecoverable** and nothing is back-filled. Small-population: the 4 freeze rows (137/149/173/219) and the 7 two-block jobs are named as instances; the fix is argued from the code contract (an unpassed `--fork-block-number`), not from their count (B14). |
| `effect_verdicts.witness.block_source` | **0/274 — the key is ABSENT on every existing row** | **CONFIDENCE, three-state; consume as cite + three-state only.** The SCOPE the pin above is shared across, published only ever alongside it — a height without its scope cannot be compared across rows, so the pair is stamped and stripped together and neither may be read alone. Closed vocabulary (`config.BLOCK_SOURCES`): `invocation_pin` \| `job_pin` \| `run_pin`; an unrecognized value publishes **nothing** rather than a free-text tag. **proven-present** = the named scope. Only `invocation_pin` is emitted today, and it explicitly does **not** make a run internally coherent (one run spanned 51 heights over 495 blocks); `job_pin`/`run_pin` are reserved and unemitted, because a per-run pin needs a run/batch column `jobs` does not have and is a separate schema decision. **No proven-absent state**; **not_determined is the ABSENT key**, on exactly the same failure paths as `block_number`. Consumption obligation: three-state + cite — two verdicts may be treated as one world state only when both carry the same height **and** a scope that spans them. Same small-population flags, same argument (B14). |

### B8. Value and perimeter — per-asset

`contract_balances` is **per-asset**: 721 rows / 381 distinct tokens / 60
balance-carrying contracts; **702 ERC-20 + 19 native-ETH rows**; `usd_value`
non-null on 289/721; `price_usd` on 721/721. **41 of 60 balance-carrying contracts
hold no native-ETH row at all.** `scorer_v2.py:138-145` reads one
`coalesce(sum(usd_value),0)` per contract and discards the asset dimension.

| field | count | status | decides |
|---|--:|---|---|
| `contract_balances.token_address` (NULL = native ETH) | 702 + 19 | **REQUIRED** | the asset key. Cross with **`claims[].witness.flows[].kind`** — `low_level_value_call` (native) vs `callee_erc20_selector` (ERC-20). A native send provably cannot move an ERC-20 balance. No inference: a join. |
| `token_symbol` / `decimals` / `raw_balance` / `price_usd` | 721 each | **REQUIRED** | unit reconstruction. |
| `fetched_at` | 721/721, spanning **1h40m** (20:00:51 → 21:41:16) | **GATE** | a cross-contract sum is **not a single-block quantity**. `fetched_at` is a WRITE timestamp, not an observation height, and must never be read as one. Directly relevant to inv.11/inv.12 byte-identical replay. **↳ AMENDED (2026-07-30, B1/Unit 4): a `block_number` column now exists, NULL on all 1,617 pre-existing rows, permanently — see B8.1a.** |
| `contracts.is_proxy` / `implementation` / `admin` / `beacon` | admin **1 of 24** eip1967 proxies; beacon 1; implementation 25 (loaded, never used) | **REQUIRED**, with the caveat in B11/T-ADMIN | entity collapse to the runtime address. |

**Method validation:** `CumulativeMerkleDrop.sweepETH` — fork witness $90.97;
contract's **native** balance $91; whole sheet $471,980. **The per-asset partition
reproduces the fork's answer without a fork**, which is what makes it usable on the
rows that have no fork verdict. Nine flow.out rows show a native-vs-sheet gap; the
two EtherFiRestaker headline rows are $0 native against $467,568,890 of sheet.

**Limit for the spec:** for **ERC-20** flows the asset *identity* is not in the
static witness — `sink_ids` carries only a variable name
(`claimFees(ERC20):sink4:external_call:feeAsset.safeTransferFrom`), and
name-based resolution is banned by inv.2. Per-asset pricing is fully deterministic
today **only for the native-vs-ERC-20 split**, not for "which ERC-20".

**Denominator caveat (inv.7).** `tvl_snapshots` reports DeFiLlama
**$3,314,214,193** against `sum(contract_balances.usd_value)` of
**$4,159,585,666**. The **$845M** gap is a wrapped-position double count — WeETH's
$3.50B eETH holding is the same economic value as the eETH its users deposited.
The exposure composition **divides by** this total, so a double-counted
denominator systematically flatters the grade.

### B8.1a. Balance provenance — observation height, observed address, fetch plane (B1/B2, Unit 4)

Two planes, and the separation is the whole substance of the fix.
``contract_balances`` still means what it always meant — **a row is a witnessed
positive quantity** — because `services/effects/selection.py::_asset_holdings_by_deployment`
consumes a row's mere EXISTENCE as *"this deployment holds this asset"*, and that
set feeds the 43 published `flow.out` reach rows. Delivering the three-state as
rows in that table would have published holdings that do not exist: a fix that
closes one gap by widening another. The discriminator therefore lives in
`contract_balance_fetches`, **whose rows are NOT holdings**.

Measured before the change: 1,617 rows, of which **0** are NULL, empty, numeric
zero or non-numeric `raw_balance` — both writers gate their native insert on
`> 0` and `utils/etherscan.py` drops every zero-balance ERC-20 entry. Row
existence was therefore only *accidentally* sound as a holdings witness; the
positive-quantity requirement added to `_asset_holdings_by_deployment` in the
same commit makes it structural, and is a measured no-op on this corpus
(byte-identical reader differential, below).

**`contract_balances` — provenance columns.** Population `0 / 1617` on every one
of them, and that is not a defect: no backfill is possible, because the height
and the observed address were never recorded.

| field | pop. | status | three-state | failure/absence path |
|---|--:|---|---|---|
| `observed_address` | 0/1617 | **REQUIRED** | non-NULL = the address the read was ISSUED against, captured verbatim from the write-point local (`tvl.py` uses `contracts.address`; `resolution_worker.py` uses `request['proxy_address'] or address`). NULL = not_determined. | a failed read writes no holdings row at all, so the column is never a guess. |
| `block_number` | 0/1617 | **GATE** | non-NULL = **this quantity** was read at this height via `Multicall3.getEthBalance` at an explicitly pinned block. NULL = not_determined, permanently. | pinned read raises, `aggregate3` reports `success=False`, **or returns fewer than 32 bytes** → fall back to the unpinned Etherscan path → NULL. A stamped `eth_blockNumber` beside an unpinned answer is BANNED: it asserts the node answered at that head. |
| `price_block_number` | 0/1617, **structurally always NULL** | **CONFIDENCE** + **BANNED substitution** | NULL = the price height is not_determined. No price source in this system carries one, and the same asset diverges up to **20.97%** within one recorded instant. | n/a. DB-enforced by `ck_contract_balances_price_block_null`. A consumer that substitutes `block_number` for it is **non-conformant**: `usd_value`/`price_usd` are never as-of-block facts. |
| `fetch_id` | 0/1617 | **GATE** | the fetch that observed this row. NULL = legacy row, provenance not_determined. | n/a. |

An **ERC-20 row can never carry a `block_number`** (`ck_contract_balances_token_block_null`).
Q1 keeps token quantities on the unpinned Etherscan page, so a fetch that pinned
its native read must not lend that height to its token rows.

**`contract_balance_fetches` — the fetch plane. Rows are not holdings.**

| field | status | three-state | failure/absence path |
|---|---|---|---|
| `native_status` | **GATE** | `proven_zero` — pinned `getEthBalance` returned `0x0` **at** `block_number`; `proven_nonzero`; `fetch_failed`; `not_determined`. | **every** failure lands on `fetch_failed`; an **unpinned zero lands on `not_determined`**, never `proven_zero` — an Etherscan `tag=latest` answer carries no height, so it proves zero at no height. `proven_zero` requires a non-NULL block, DB-enforced (`ck_cbf_proven_zero_requires_block`). |
| `native_status` **paired with** `block_number` | **REQUIRED as a pair** | the status alone is not the fact. `proven_nonzero` + NULL block = *"nonzero at an unrecorded height"*, never an as-of-block quantity. | every consumer routes through `services/monitoring/balance_reads.py::native_balance_fact(status, block)`. Reading the status alone is **BANNED**. |
| `asset_set_status` | **GATE** | `returned_assets`; `returned_empty` — a proven-empty **PAGE**, never *"holds no tokens"*; `at_page_cap`; `fetch_failed`. | `utils/etherscan.py` catches the common `RuntimeError` and returns an empty list, so *"the fetch failed"* and *"holds nothing"* were one shape. They are now two values. **There is no `complete`.** |
| `asset_page_length` | **GATE** | the RAW endpoint entry count, before the `raw_balance > 0` filter. NULL = not_determined. | the filter destroys the page-size signal one line above where it used to be read, so a stored-row count can only ever be a LOWER bound. This is the real witness for the at-cap case. |
| `writer` | **CONFIDENCE** | `tvl` \| `resolution_worker`, a literal at the call site. | which loop issued a read was previously recoverable only by a `fetched_at`-multiplicity heuristic. |

`_completeness_from_fetch(asset_set_status, asset_page_length)` is the single
**total** mapping into `HOLDINGS_COMPLETENESS_STATES`, and it **provably cannot
return a whole/complete state** — no such member exists. `returned_assets` maps to
`not_determined`, not to complete: a page below the cap is consistent with a whole
list AND with the endpoint's own paging. Where several fetches contribute to one
holder, **the weakest value wins** (`at_page_cap` beats `not_determined`), so a
clean sibling cannot launder a capped one.

**`contract_balances_latest` — the read surface.** The destructive per-contract
DELETE is gone; both writers are insert-only. **Every reader is migrated to the
view in the same commit** (`selection.py` ×3, `company_overview.py`, `tvl.py::_read_existing_balances`,
the three `scoring_prototype/` scorers), because a NULL-block row is not
unique-constrained and a naive reader would sum across heights. No unique
constraint is added: NULLs are distinct in a Postgres unique index, so one would
constrain nothing on the Etherscan path and read as a guarantee it does not
provide.

The view resolves, **per row class independently**, the latest fetch that did NOT
fail for that class, and takes its row set **wholesale**. Four properties, each of
which is an absence-as-witness defect if dropped:

1. **Wholesale, not per-asset** — a fetch's rows ARE the set it observed, so an
   asset the holder has sold correctly disappears.
2. **Per row class** — a transient token failure must not withdraw the native
   holding.
3. **Failed fetches never win** — otherwise a failure republishes *"holds nothing"*.
4. **Legacy rows (`fetch_id IS NULL`) remain visible until a NON-FAILED fetch
   exists** for that contract and class — a first fetch that fails must not delete
   1,617 rows of history from the view.

**The writer-side invariant the view depends on:** *a non-failed class status is a
promise that that class's row set was written.* Possibly EMPTY, where empty is
what was observed (`proven_zero`, `returned_empty`, or a page whose every entry
was zero-balance) — but never merely skipped. The view keys on the status, so a
fetch row carrying `proven_nonzero` or `returned_assets` with none of that
class's rows persisted wins the class and **withdraws every prior holding of it**.
The resolution worker used to do exactly that: its halves fail independently, and
an early return on `native_failed or tokens_failed` stamped the SUCCEEDING half's
status while persisting none of its rows. It now persists each half that
succeeded, with no early return. This is **not** fixable in the view — an
EXISTS-guard on the rows would resurrect sold assets (an empty observed set is a
real observation) and would defeat `proven_zero` outright.

**View currency is per `contract_id` and IGNORES `observed_address`.** A contract
fetched at two different addresses publishes whichever writer wrote LAST, not the
union. This is deliberate: it preserves the pre-migration last-writer-wins DELETE
semantics, and per-address currency would publish both addresses' rows at once,
double-counting the 5 proxy/impl pairs inside `build_authority_graph`'s
per-contract sum. The consequence is visible rather than hidden — each row carries
its own `observed_address`.

Retention (`PSAT_BALANCE_HISTORY_DEPTH`, default 10, **rejects < 1**) bounds
insert-only growth by fetch, never by row, and **excludes the latest non-failed
fetch per row class from pruning**. Without that exclusion, `depth` consecutive
failures would CASCADE away exactly the rows the view is publishing.

**Why the absences matter downstream.** `selection.py` keeps INNER-join semantics:
a contract with no current row produces **no** `deployment_balance` key. That is
load-bearing — `recipes.py::_add_reach` publishes
`graph.deployment_balance.get(acting, _ZERO_USD)` as `observed_reach_floor_usd`,
so a `0` entry manufactured by a failed fetch would become a published **$0.00**
floor on a function that may move millions.

**The INNER join defends only the NO-ROW case, and that limit must be stated.**
`coalesce(sum(usd_value), 0)` still yields a `$0.00` `balance` /
`deployment_balance` entry for a contract whose current rows exist but are ALL
unpriced — **22 of the 60 balance keys on this corpus**, `contracts.id 563`
among them. Such a key is indistinguishable, at the consumer, from a contract
proven to hold nothing, and `observed_reach_floor_usd` will publish it as a
floor. Not repaired here: the fix is to carry the priced/unpriced three-state
through the aggregate rather than to collapse it in SQL, which changes
`build_authority_graph`'s published shape and belongs with the consumer work. For the same reason
`tvl.py::_read_existing_balances` now **omits** a contract with no non-failed
fetch rather than emitting `total_usd: 0.0`, and derives `partial=True` instead of
hardcoding `False`: that zero would otherwise enter `TvlSnapshot.total_usd` as a
measurement.

**Entity misattribution (M7/16a) — an OPEN defect, not a withdrawal.** Re-verified
independently at block **25643300**: `contracts.id 544` (AuctionManager
`0x3311c72a…0162b`) holds **0 wei**, while its stored native row —
`19059300000000000000` wei / **$35,904.67** — is exactly the balance of
`jobs.request->>'proxy_address'` `0x00c452af…c4cb9`.

**That figure is still published today.** This unit does not withdraw it, and an
earlier draft of this section claiming otherwise was false:
`graph.balance['0x3311c72a…'] = 35904.67` on the branch, because row `id 2336` is
a legacy row (`fetch_id IS NULL`) and the view's legacy arm serves it. The row is
neither deleted nor re-keyed — no protocol-1 proxy names 544 as its
implementation, and guessing the key is precisely the inference §7 forbids.

**Retirement mechanism, stated rather than assumed.** The new plane supersedes it
on the first production NON-FAILED fetch for contract 544: the legacy arm stops
serving a class as soon as a non-failed fetch exists for it, and the TVL loop
reads 544 at `contracts.address` (never `request['proxy_address']`), where the
pinned read returns 0 wei — `proven_zero`, writing no native row. The $35,904.67
disappears from the published sheet at that point, and the fetch plane records
*why*. Until then the misattribution stands and must be read as one.

`contracts.id 563` (StakingManager) is the second such row and carries **no native
row at all**; its three ERC-20 rows are spam-token airdrops with `usd_value` NULL,
so there is **$0.00** of USD to withdraw there. *Population 2 — B14 bars
calibrating anything on it; each row was decided on its own on-chain evidence.*

**Deferrals carried by this unit, stated with cause.**

* **ERC-20 quantities remain UNPINNED (Q1).** Only the native read moves to the
  pinned `Multicall3` path, so `contract_balances.block_number` is populated on
  native rows only and every ERC-20 row keeps `block_number NULL =
  not_determined`. Cause: re-sourcing token quantities changes 571 published
  money figures per cycle (**15.8%** of stored ERC-20 quantities do not reproduce
  at 25643300), needs its own per-sub-call three-state, and forces `usd_value` to
  be recomputed as pinned-quantity × unpinned-price. Honesty is preserved either
  way — the height is `not_determined`, not guessed — so this is a capability
  deferral, not an epistemic one. The schema is a superset; adding it later needs
  no migration.
* **`tvl.py:348` / `:429` truthiness (Q4).** Both the reader and the refresh loop
  accumulate with `if usd:`, so a genuine PRICED `usd_value == 0` is dropped from
  `contract_total` exactly as an unpriced NULL is — the same null/zero conflation
  `company_overview.py` documents and avoids. Pre-existing, and NOT repaired here:
  it is a defect in the USD accumulation, orthogonal to provenance, and fixing it
  inside this change would move published `total_usd` figures for reasons
  unrelated to the balance three-state. Recorded so the next reader of that
  function does not mistake it for intended behaviour.

**What the reader differential proves, and what it does not.** All three migrated
`selection.py` readers produce **byte-identical** output before and after
(60 `balance` keys, 55 `deployment_balance` keys, 701 `AssetHolding` entries across
55 holders, 34 token holders; md5 `0e28f1ff…`), measured on a writable clone of the
replica. That establishes **the legacy corpus is unchanged** — it is NOT evidence
the new plane is correct, because every new column is NULL on all 1,617 rows and
`completeness` still falls back to the stored-row rule while `asset_page_length` is
NULL. The new plane is exercised only by the synthetic mixed-fetch arms in
`tests/test_native_balance_three_state.py`.

### B9. Audit and change management

| field | count | status | decides |
|---|--:|---|---|
| `equivalence_status='proven'` | 36/209 | REQUIRED (in use) | the admissible core. |
| `proof_kind` within `proven` | `clean` **33**, `pre_fix_unpatched` 1, `post_fix` 1, `unclassified` 1 | **GATE** | the scorer credits all 36 identically. `clean`/`post_fix` creditable; `pre_fix_unpatched` is an LLM role label → warnings; `unclassified` is unknown. |
| `bytecode_keccak_at_match` | **209/209** | **REQUIRED** | joined to `bytecode_cache.code_keccak`, upgrades the credit from *"an audit referenced deployed code at some past time"* to *"the exact bytecode we matched is deployed right now"*. Of 36 `proven`: **33 still match, 0 replaced, 3 no cached bytecode** (→ unknown, not zero). Supplies the deterministic negative the moment a match stops holding. |
| `equivalence_reason` | 209/209 | **REQUIRED** (warnings) | separates three epistemic states the scorer collapses into one: **our-side data gap 162** (`candidate_path_missing` 117 — names the precise repo path whose rename would fix it; `commit_not_found_in_repo` 45), **deployed source provably differs 10** (`hash_mismatch`), **infrastructure 1**. This is inv.6's promote-or-clear requirement, satisfied by an existing column. |
| `covered_from_block` / `covered_to_block` | 151/209 and **8/209** | **REQUIRED** | the only deterministic staleness bound on an audit credit — stops a 2023 audit crediting 2026 code. *Low population: 8 rows.* |
| `matched_commit_sha` | 36/209 (exactly the proven rows) | **REQUIRED** | the sha printed verbatim in the PDF. |
| `upgrade_events` | **120 rows / 24 proxies** on protocol 1; `block_number`/`timestamp`/`tx_hash` **120/120**. **96 of the 120 are upgrades; 24 are deployments** (§B17), across **68 distinct transactions** | **REQUIRED** | deterministic Etherscan `getLogs` scan of `Upgraded`/`AdminChanged`/`BeaconUpgraded` (`upgrade_history.py`). **Every count below was corrected downward on 2026-07-30** — a proxy's own creation emits `Upgraded`, and every one of the 24 proxies has exactly one such row (basis per figure: the receipt rule `to IS NULL AND contractAddress == proxy` proves 18; the two-witness creation pair — Etherscan `getcontractcreation` naming the same tx AND `eth_getCode` at the event block −1 returning `0x` — proves the other 6, all deployed through factory `0x356d1b83…`). **every one of the 24 per-proxy counts drops by exactly one**: **EtherFiNodesManager 18→17** (2023-05-02 → 2026-07-14), **LiquidityPool 17→16**, **Liquifier `0x9ffdf407` 8→7**, **EETH `0x35fa1647` 6→5**, and the three single-row proxies **`0x2b90103c`**, **`0x4a84ba0b`** and **`0x5585996e`** go **1→0**, leaving **96 real upgrade EVENTS across 21 proxies**. Events are not actions: those 96 events are **93 actions** summed per proxy (`0x8f08b704` 6 events / 4 actions and `0xdadef1ff` 5 / 4 — within-transaction swap-and-restores) over **44 distinct non-deployment transactions** protocol-wide. **The published `upgrade_count` is the ACTION count**, because the unit must be an exercise of upgrade authority. Re-measured independently against all 68 receipts: the two arms agree everywhere they overlap — arm 2 proves all 24, arm 1 proves the 18 whose creation was EOA-sent, and no proxy is proven by one arm and refuted by the other. The day figure was also wrong: the single transaction `0xc9c80e5b…` at block 25533308 on 2026-07-14 touched **19** protocol-1 proxies (21 table-wide), **not 11** — and it is **ONE governance action**, so counting it per event inflates it 19×. `tx_hash` is the handle to **who executed** each upgrade; §B17 resolves that and states plainly that **who *authorised* it stays `not_determined` on every row**. |
| **18 contracts with audit rows and zero `proven`** (11 from ≥2 firms, 1 from 4); and `max(proven)` per contract is **1 firm for every contract** while `all_firms` reaches **7** | — | CONFIDENCE | exactly inv.1's audit corollary: these must read *unknown*, not 0. The plan's "18/36 score identically whether never-audited or 5-firm-audited" phenomenon is reproduced on this snapshot. Firm identity is LLM-assisted (`audit_reports_llm.py`) → confidence only. |
| `audit_reports.classified_commits` | 60/67, 102 entries | **BANNED from grade** | the inv.2(b) LLM labels. Note `findings` and `scope_entries` are **0/67** — no audit-findings data exists on this corpus at all. |

### B10. Missing witnesses

1. ~~**Safe modules, guard, and nonce are not probed.**~~ **CLOSED for modules and
   guard (2026-07-30, Unit 7A / C1); the nonce is still unprobed.** The classifier
   now fires two `eth_getStorageAt` plus `VERSION()` after `kind=='safe'` and
   persists the witness under `function_principals.details->'safe_protection'` /
   `control_graph_nodes.details->'safe_protection'` — see **B10.1a**. **A Safe with
   an enabled module is bypassable without meeting the threshold**, so k/n is an
   *upper bound* on protection wherever the module set is not a proven empty.

### B10.1a. `details->'safe_protection'` — the Safe module/guard witness (C1)

Written by `services/resolution/tracking.py::_probe_safe_protection`, fired once
per address classified `safe` (~19 addresses / +3 RPC each, plus one
`eth_blockNumber` to pin the height). All seven keys are always present; each is
its own three-state and **every failure, revert or absence path lands on
`not_determined`**. Nested under one object deliberately: `module_set` is a
mutable now-fact and may not be read apart from its `probe_block` (B0b/S1 —
a strength gate published separately from its payload does not discharge the
obligation).

| field | JSON path | pop. | status | three-state | failure path |
|---|---|--:|---|---|---|
| `probe_block` | `details->'safe_protection'->>'probe_block'` | 19 applicable | **REQUIRED** | integer height every other key was read at / `"not_determined"` | head read failed or the caller passed an unrecognised block tag ⇒ `"not_determined"` **and the probe is suppressed entirely** — no other key can be positive |
| `safe_version` | `…->>'safe_version'` | 19 applicable | **GATE** | the probed contract's **self-reported** `VERSION()` string / `"not_determined"` | call reverted, returned nothing, or failed to decode ⇒ `"not_determined"`. Required to read the guard word; nothing else depends on it. **Self-reported, not proven** — a lookalike could return any string; on this corpus it is corroborated by slot-0 singleton identity matching the canonical Safe deployments at 25643300 on **19/19**, which the probe does not itself read |
| `modules_head` | `…->>'modules_head'` | 19 applicable | **REQUIRED** | the raw 32-byte word at `keccak256(abi.encode(address(0x1), uint256(1)))` / `"not_determined"` | read raised ⇒ `"not_determined"`. **Cite, never enumerate from** |
| `module_set` | `…->'module_set'` | 19 applicable | **REQUIRED**, three-state | `[]` = **proven empty at `probe_block`** (head == sentinel) / `"not_determined"` | any non-sentinel head — including a zero word (mapping entry never written) and a word that is not a left-padded address — and any read failure ⇒ `"not_determined"`. **A non-empty enumerated array is NEVER published here**; it is admissible only from a list walked to the sentinel or a paginated `eth_call` that returned `next == sentinel`, neither of which this probe performs |
| `module_set_basis` | `…->>'module_set_basis'` | 19 applicable | **REQUIRED** (cite) | `"storage_linked_list_terminated"` / `"not_determined"` | not_determined whenever `module_set` is |
| `protection_is_upper_bound` | `…->'protection_is_upper_bound'` | 1 true / 18 not_determined | **GATE** | `true` = **proven**: a module is enabled at `probe_block`, so k/n bounds protection from above; the module address is cited as `modules_head_address` / `"not_determined"` | **never `false`.** Proving k/n exact needs "no module has ever been enabled", which requires a warm `EnabledModule` cursor from the Safe's creation block; absent that it stays `not_determined`, including on a proven-empty head |
| `guard` | `…->>'guard'` | 19 applicable | **REQUIRED**, four-state | `"proven_address"` (+`guard_address`) / `"proven_zero"` — **only** on a release whose deployed singleton carries `GUARD_STORAGE_SLOT` (1.3.0, 1.4.1) / `"feature_absent"` — 1.1.1, where the slot is unused storage and a zero there is not "guard disabled" / `"not_determined"` | word unread, version unknown or outside both verified sets (incl. variant suffixes like `1.3.0+L2`), or a word contradicting the version's feature set ⇒ `"not_determined"` |

**Consumption obligation.** `module_set == []` + its `probe_block` licenses
treating k/n as the protection *at that height only*; `protection_is_upper_bound
== true` **must** demote any k/n-derived protective credit for that Safe;
`guard == "proven_address"` names an additional gate and `"feature_absent"` is a
proven statement about the release, not about a policy. `not_determined` on any
key means the scorer may neither credit nor charge that dimension.

**Small populations (B14 — may gate/cite/three-state, may never calibrate):**
module-bearing Safes **1**; its reach **4** rows on 1 contract, `protocol_id IS
NULL`. Version populations 1.4.1 ×9 / 1.3.0 ×9 / **1.1.1 ×1** — and the 1.1.1
population, the only one on which `guard: feature_absent` is ever reached, is a
single address.

**Monitor half.** `EnabledModule` / `DisabledModule` / `ChangedGuard` are
registered in `GOVERNANCE_EVENT_TOPICS` (so `_scan_topics_union` enrolls every
active Safe) and the two slots are polled as `storage_slot` entries. The poll and
the fold observe **change**; neither publishes membership. A cold cursor on either
module topic keeps "no module has ever been enabled" at `not_determined`.

### B10.1b. `details->'gated_contract_backlink'` — the role-principal pairing witness (C3 / Unit 9)

Written by `services/resolution/tracking.py::probe_declared_vault_backlink`,
fired from the recursive walk's role-principal projection
(`services/resolution/recursive.py::_maybe_probe_backlink`) for a principal whose
`details.source` is `semantic_capability:role_grant` **and** which resolved to an
analyzable contract. Persisted verbatim onto `control_graph_nodes.details` by
`replace_control_graph_rows`. **No migration.**

**Population (measured, not estimated).** **37** marked `control_graph_nodes`
rows / **38** projections (the number of probe firings) over **32** distinct
addresses: **32** distinct M, **17** distinct V. Re-run over all 38 pairs at
block 25643300: **20 publish `true`, 18 `not_determined`** — 17 `not_determined`
if counted over marked rows — and all 18 because the getter does not answer, so
with zero mismatches and zero control failures the mismatch arm is **latent
here**. The row and projection counts differ by one on purpose: a lens keyed on
`details->>'source' = 'semantic_capability:role_grant'` **undercounts firings by
one**, because `_ensure_node`'s last-write-wins merge
(`services/resolution/recursive.py:615-618`) can overwrite the role-grant marker
with a later projection onto the same row — measured on
`(0x70a64840…, 0x6889e57b…)` at `contract_id=471`, whose marker is NULL while its
`role_principal` edge survives. That same merge is why
`gated_contract_address` is published: it makes each verdict name its own
subject rather than depending on a sibling key that can be erased.

**Cost.** +2 RPC per applicable pair (the `vault()` read, plus the negative
control fired only on a match), and `resolve_control_graph` runs in **both** the
resolution stage and the policy refresh, so the realistic figure is **~2× that
per job** — on top of a read the pipeline already performs (see below).

**Why it exists.** The ten `ManagerWithMerkleVerification` contracts hold the
sole `canCall` on a BoringVault's `manage`. This gives the (M, V) pairing a
structural basis instead of a name (inv.2).

**CORRECTION to this unit's own first draft.** It claimed the managers' identity
"was available only as `control_graph_nodes.label`" and that `vault()` was
"probed nowhere in the tree". **Both are false.** The pipeline already reads
`vault()` through the `external_contract` controller path
(`services/resolution/tracking_plan.py:86`), and it is persisted: **32
`control_graph_edges` rows with `relation='controller_value'`, `label='vault'`
across 25 contracts**, plus 15 `controller_values` rows carrying
`block_number`. A grep for the literal string missed it because the selector is
built from the Slither state-variable name rather than written out. Lane C was
substantially right on this point. What this witness adds is therefore **not the
read** but a *verdict*: the equality against the specific V being gated, at a
pinned height, behind a negative control, published as an auditable three-state
alongside the node it describes.

| field | JSON path | pop. | status | three-state | failure path |
|---|---|--:|---|---|---|
| `probe_block` | `details->'gated_contract_backlink'->>'probe_block'` | 37 applicable | **REQUIRED** | integer height every other key was read at | head read failed or an unrecognised block tag ⇒ **the entire key is ABSENT** (the probe returns `None`). There is no "positive with an unstated height" state |
| `backlink_getter` | `…->>'backlink_getter'` | 37 applicable | **REQUIRED** (cite) | the literal probed selector, `"vault()"` | never absent while the object exists |
| `gated_contract_address` | `…->>'gated_contract_address'` | 37 applicable | **REQUIRED** (cite) | the V this verdict is ABOUT — structural, always published, so the row is self-describing | never absent while the object exists |
| `backlink_address` | `…->>'backlink_address'` | 20 / 17 not_determined | **REQUIRED** | the address the getter returned, published **only when it matches** `gated_contract_address` | every other outcome ⇒ `"not_determined"` |
| `negative_control` | `…->>'negative_control'` | 20 / 17 not_determined | **GATE** | `"passed"` — a selector nothing implements reverted or returned nothing | `"failed"` / `"error"` (both reachable **only on a match**), and `"not_determined"` whenever the getter did not answer **or the answer was not V** |
| `declared_vault_matches_gated_contract` | `…->'declared_vault_matches_gated_contract'` | 20 true / 17 not_determined | **REQUIRED**, three-state, **no false state** | `true` — the returned address byte-equals `gated_contract_address` at `probe_block`, control passed | **every** other outcome ⇒ `"not_determined"` |

**Exactly three payload shapes are reachable**, and a reviewer should check
against this list rather than against prose:
1. **absent** — height unpinnable;
2. **not-determined shape** — `backlink_address`, `negative_control` and the
   verdict all `"not_determined"`. Reached by *both* "the getter did not answer"
   and "the getter answered something that is not V", **byte-identically**;
3. **matched shape** — `negative_control` present (`passed` ⇒ verdict `true`;
   `failed`/`error` ⇒ verdict `not_determined`, the answer being worthless
   because the address answers everything).

**What it earns, exactly.** *M declares V as its `vault()` at `probe_block`, with
the nonsense-selector control passed.* That corroborates the **(M, V) PAIRING**
the projection already asserts.

**Consumption obligation.** Cite + gate. `true` licenses citing M as the
structurally-corroborated counterparty of V in place of the label string. It is a
**mutable now-fact** (inv.10) and may not be read apart from its `probe_block`.

**BANS:**

1. **It does not establish M's component TYPE and does not identify M as "the
   manager."** This is not a corner case: of the **20** pairs that publish
   `true`, **10 are not managers** — `0x35dd2463fa7a…` (a LayerZeroTeller),
   `0x417e1ef6…`, `0x4de413a2…`, `0x6ee3aacc…`, `0x8ea0b382…`, `0x929b44db…`,
   `0x99de9e5a…`, `0x9aa79c84…`, `0xd445c65e…`, `0xe238e253…` — Tellers, solvers
   and vaults whose `vault()` is the contract they gate. **Reading this key as a
   type would mis-type half the positive population.**
2. **A mismatch is NOT an earned negative** — a pairing established by some other
   mechanism is not refuted by this getter answering differently. **This is a
   prose ban on the CONSUMER, not a guarantee that the mismatch is
   unknowable.** The witness merely declines to state it: the mismatch payload
   is byte-identical to the never-read payload, so this object carries no
   mismatch signal. The raw address remains available elsewhere and
   deliberately so — `control_graph_edges.relation='controller_value'` with
   `label='vault'` publishes it (32 rows / 25 contracts on this corpus) with
   `controller_values.block_number`. A consumer that joins those planes can
   compute a mismatch; **it may not then publish that mismatch as a disproof of
   the pairing.** A reader must also never treat an ABSENT key as `false`.
3. **"The manager is analysed" must never become "the manage capability is
   bounded."** `manageRoot(strategist)` is a root hash; a root is not a decodable
   permission set, so the strategist's admissible call set stays
   `not_determined` even after every manager is analysed.

**A defect this field already had once, recorded so it is not reintroduced.** The
first implementation recorded `negative_control` *before* testing the equality.
Because the control is fired only once a decodable address is in hand,
`negative_control == "passed"` together with a `not_determined` verdict was
reachable **only** by "M declares a vault and it is not V" — ban 2's earned
negative, published one key over. Withholding `backlink_address` did not close
it. The fix is the byte-identity of shape 2 above, pinned by
`tests/test_policy_perimeter_spawn.py::test_mismatch_payload_is_byte_identical_to_the_never_read_payload`
and mutation-verified.

**Small populations (B14 — may gate/cite/three-state, may never calibrate):**
`true` rows **20** (only 10 of them managers); distinct V **16**; the role-grant
jobless population **19**.

**Verification.** Over all 37 pairs at block **25643300**: 20 `true` / 17
`not_determined`; on the ten manager pairs `vault()` returns the gated contract
**10/10** with the control passing **10/10**. Carry-forward (§9):
`_resolve_probe_block` persists nothing, so this proves stability at 25643300,
not that the observed run read there.

### B10.1c. The perimeter omission ledgers — `selection_summary.not_selected` / `.pre_rank_excluded` / `perimeter_spawn_summary` (C2 + C3 / Unit 9)

A dropped candidate that leaves no record is indistinguishable from a candidate
that never existed. That is the whole of the C2 defect: `contracts.id=11`
(0xcd425f44…, the 2-day timelock gating 53 rows across 16 contracts) ranked
0.3836 at queue positions 42-57 against `analyze_limit=2` and was cut with
nothing but a `record_stage_metric` count to show for it. The targeted fix is
**one job plus a ledger**, never a raised threshold.

| field | JSON path | status | three-state / semantics | failure path |
|---|---|---|---|---|
| `not_selected[]` | artifact `selection_summary` | **REQUIRED** (cite) | one `{address, chain, rank_score, reason}` per **ranked** candidate that did not become a child. `reason` ∈ `budget_exhausted` \| `chain_not_enabled` \| `existing_job` \| `in_cascade_dedupe` | `[]` means "no ranked candidate was dropped" — proven, because the producer enumerates every non-selected ranked entry, including on the budget-already-full early return |
| `pre_rank_excluded[]` | artifact `selection_summary` | **REQUIRED** (cite) | one `{address, chain, reason[, effective_confidence]}` per row removed **before** ranking. `reason` ∈ `below_confidence_threshold` \| `superseded_impl_anchor` | `[]` means "no row was removed upstream of the ranking" |
| `perimeter_spawn_summary` | artifact, policy stage | **REQUIRED** (cite) | `{site, budget, budget_used, spawn_depth, queued[], omitted[], out_of_population[]}` | `omitted` reasons ∈ `budget_exhausted` \| `depth_exhausted` \| `chain_not_enabled` \| `zero_address` \| `invalid_address` |

**Consumption obligation.** Cite. These are what make a population invariant
expressible as **"zero UNLOGGED omissions"** rather than "zero omissions" — a
legitimate budget cut is a correct outcome and must not redden the gate.

**Population of the selection ledgers.** Both cover exactly the rows matching
`Contract.protocol_id == job.protocol_id AND Contract.job_id IS NULL`
(`workers/selection_worker.py:182-185`). **A `contracts` row with
`protocol_id IS NULL` is invisible to BOTH ledgers** — it is never a candidate,
so it is neither selected nor recorded as dropped. An orphaned row is therefore
outside the "nothing was dropped" claim entirely, not covered by it.

**The claim a consumer may make, stated exactly.** Nothing was dropped **iff
`not_selected == [] AND pre_rank_excluded == []`**, and then only within the
population above. `not_selected == []` alone
does NOT support it: two filters run upstream of the ranking (the
`effective_confidence >= 0.3` threshold and the superseded-impl anchor
predicate), and before this unit the first survived only as a count and the
second was applied in SQL, so neither left an enumerable trace.

**The three spawn dispositions PARTITION the node list** — `queued` +
`omitted` + `out_of_population` == every node — and `out_of_population`
(`root_node`, `not_analyzed`, `not_contract_node`, `existing_job`) is the
fail-closed/dedup set, which is NOT an omission and must never be counted as
one.

**Budget accounting.** The budget decrements at `create_job` and nowhere else
(spawn walker), and the budget check is evaluated **after** the chain and dedup
gates (selection walker), so a candidate rejected by any other gate both
consumes no budget and is recorded with the reason that actually applies. The
selection walker originally checked the budget first: nothing was dropped
silently, but every below-the-cut candidate reported `budget_exhausted`
regardless of why it was really ineligible — and the cause is the entire value of
the ledger.

**`PERIMETER_SPAWN_LIMIT` (8) and `PERIMETER_SPAWN_DEPTH_CAP` (2) are NAMED MODEL
CHOICES, not measured reliabilities** (B14: the population is 19 rows, far below
the floor at which calibrating a threshold on observed data is admissible).
`spawn_depth` counts PERIMETER SPAWN GENERATIONS and is carried in the child's
request; it is **not** `control_graph_nodes.depth` — the walk's BFS distance,
which is `1` on all 19 jobless role-grant nodes — and the two must never be read
for each other. Because the width budget (8) is below the jobless population
(19), a single policy refresh drains at most 8: the 30 manager-attributable
`contract_gated_unknown_path` warnings may **not** be asserted to resolve in one
run.
2. **Freeze duration bound.** `auto_expiry` and `duration_bound_seconds` exist on
   all 4 proven freeze verdicts and are populated on **zero**. Until they land the
   bound may not be credited — and indefiniteness may not be assumed.
3. **Blast radius** is populated on 4 of 63 freeze verdicts;
   `no_blast_radius_observed` on 29.
4. **The 2-day timelock's proposer set.** `contracts.id=11` (`0xcd425f…`) has **0
   `effective_functions`** — discovered and classified but never analyzed. It gates
   **53 rows across 16 contracts reaching $4.06B**. The 10d and 5d twins show the
   pipeline resolves this shape completely. **Cheapest fix to the largest remaining
   weakest-path blind spot.**
5. **`ManagerWithMerkleVerification` is not a `contracts` row.** It is the sole
   `canCall` for `BoringVault.manage`, so its own authority cannot be walked.
   **CORRECTED (2026-07-30, Unit 9 / C3):** the "M10-confirmed 60 contract-gated
   warnings" credited the managers with the whole warning class. Measured
   manager-attributable share is **30**, against class totals of **68 / 60 / 64**
   in `score.json` / `score_v2.json` / `score_v3.json` respectively — so 60 was
   the class size in one file, not the managers' contribution. Crediting 60
   over-states their share ~2x. Note also that the perimeter spawn's width budget
   (8) is below the 19-row jobless population, so those 30 cannot be asserted to
   resolve in a single run. B4's `controller_values`
   closes the *registry* half of the Boring plane; this is the other half.
6. **Timelock queue/grace/expiry state.** Only `getMinDelay()` is read — no
   `getTimestamp(id)`, no pending-operation enumeration, no grace period. "Is
   something queued right now" cannot be scored or alerted on.
6b. **The timelock `delay` duck-type control covers FUTURE rows only (2026-07-30,
   Unit 9 / C2).** `details["delay"]` has exactly two writers —
   `services/resolution/tracking.py:913` (`_classify_uncached_batched`) and
   `:1013` (`_classify_uncached`) — and both now sit behind
   `_duck_type_permitted()`, so a catch-all fallback can no longer mint a
   `timelock` with a fabricated delay. That is a **producer invariant on rows
   written after 382d81dc (PR #161)**, not a property of the rows on hand: the
   observed run wrote its jobs between 2026-07-29 19:57:30Z and 21:44:17Z, and
   `_NEGATIVE_CONTROL_SIG` first appears in 382d81dc at 2026-07-30 00:28:56Z.
   **The 53 existing rows carrying `delay=172800` therefore have no control
   witness and no `probe_block` for the delay read** — their
   `trace[0].probe_block` belongs to the `enumerable_role_store` fold on authority
   `0x62247d29…`, not to `getMinDelay()` on `0xcd425f44…` — and it is not even a
   single height: the 53 rows carry **12 distinct values spanning
   25641034–25641184**, of which 25641184 covers **1** row. (An earlier draft of
   this entry quoted 25641184 as though it were the height for all 53.) Until the C2
   job or a re-resolution rewrites them, that delay may **not** be cited as a
   proven ordinal. (Re-measured at 25643300: `getMinDelay()` = 172800 and both a
   bogus nullary and a same-name-different-arity selector revert — the control
   passes today, which is evidence about the contract, not about the rows.)
7. **No block witness on `details`** for Safe threshold/owners or timelock delay.
   Recoverable via `controller_values.block_number` (290/290) or
   `details->'trace'[*].probe_block`, but a config fact published without its
   observation block is under-witnessed.
8. **Extraction ceilings from rate limits** — see T-RATELIMIT; the witness
   explicitly refuses a severity conclusion.
9. **Restaking / position value.** `contract_balances` misses EigenLayer-restaked
   ETH behind `EtherFiNodes`, so `forwardExternalCall` (EOA, arbitrary exec,
   on-chain-CONFIRMED M11) floors to the lowest band. **The only gap in this
   register that causes *under*-scoring.**
10. **`router_ops` is dropped by the claims projection entirely** (0 of 152 flows),
    and `sink_ids=[]` on 25 of 41 `value_router` claims. Per `effects.py:193-204`
    `router_ops` is the *only* identity of the carrying call. `value_router` is
    correctly `NOT_SCORED` today, but the router plane cannot be scored later
    without a projection change.
    **↳ Half-closed (U5/D5, 2026-07-30): the projection now publishes
    `router_ops` (`flows.py:92-93`) — see B2/R-ROUTEROPS for the registered
    field and its three-state. The measured `0 of 152` stands for this snapshot;
    the 41 applicable rows gain the key on re-analysis, not retroactively. The
    `sink_ids=[]` half is untouched and still open.**

### B11. Traps — present, plausible-looking, not witnesses

| trap | why it fails |
|---|---|
| **T-FREEZE** — `flags[].var = 'PAUSABLE_UNTIL_STORAGE_SLOT'` | Reading "UNTIL" as "time-bounded, auto-expiring" is **name-substring classification on a variable name**, banned by inv.2. Measured: the string appears on **12 `pause.unset` claims and ZERO `pause.set` claims**. Slot constants *are* deterministic, so slot→(namespace, member) resolution is a witness-grade fix — but that is a pipeline change, not a field read. |
| **T-BOUND** — `duration_bound_seconds` without `auto_expiry` | `claims_bridge.py:198-201`: trust it as a severity **reducer only when `auto_expiry is True`**; `auto_expiry is False` means the fork **contradicted** the static constant, so the bound is *not* a mitigation. `scorer_v2.py`'s `FREEZE_AUTO_EXPIRY` branch tests only `duration_bound_seconds is not None` + `duration_bound_source` — **dead on this corpus but one populated field away from a live inv.2 violation.** |
| **T-INDEF** — `duration_bound_source = 'not_determined'` or absent | *Not* "indefinite". `no_time_reference` is the distinct value meaning **PROVEN indefinite latch = most severe freeze**, and it does **not appear** on this corpus. All 4 rows are `not_determined`: nothing may be concluded either way. |
| **T-PAUSEINEFF** — `pause_effective = false` (22 rows) | All `verdict='unknown'`, `observation='reverted'`. `anvil.py:207-216`: *"a revert here means the resolved pauser cannot enact the pause… The freeze was then NEVER TESTED, so an empty blast radius would be INDETERMINATE."* Must not be mined as "the pause doesn't work". |
| **T-PAUSECAND** — `effect_verdicts.function_id` on freeze rows | The 59 unknown freeze rows point at **screening candidates** (`setDepositors`, `addAsset`, `addToWhitelist`, `setRateLimitConfig`, `lzReceive`…), not pauses. **Zero of the 32 static `pause.set` claims has any `freeze_pause` verdict**, so there is **nothing in `effect_verdicts` to close Appendix A's pause-witness gap.** |
| **T-PARAMDERIV** — `amount_kind.kind = 'param_derived'` | Reads like "amount comes from a parameter" (a bound *and* a caller-control fact). `effects.py:155-157` forecloses both: *"NOT a bound, NOT proof of caller control."* Worse, `amount_param_index` on such a row is the slot that **fed the conversion**, not the amount (`:185-188`). |
| **T-COND** — `function_principals.details.conditions` | A **display copy**: byte-identical to the parent `effective_functions.conditions` on **707/870** rows, differing on 32, absent on 131. Largest part of the payload; reads like a per-principal fact. Read `effective_functions.conditions`. |
| **T-EXTCALL** — `control_graph_edges.relation='external_call_target'` | Verified not a control edge (`tracking.py:1084-1096`, `recursive.py:1386-1394`; all 1352 carry `authority_provenance=call_target`). **Exclusion is load-bearing at 51×**: the 50 distinct targets (WETH, stETH, Lido, the ETH2 deposit contract, the Curve stETH pool) hold **$180,590,426,705**. Including them makes every real finding invisible. |
| **T-UNATTRIB** — `controller_value_unattributed` | 198 rows, 15 targets, **$0** — excluding it costs nothing and the third-state semantics forbid including it. But 61 rows point at Safes and 23 at timelocks: real principals whose authority relation was never established. **Confidence item, not a zero.** |
| **T-EMPTYSET** — `capability_expr.members = []` alone | An empty with `lower_bound`/`partial` is a **read gap** (1 such row). Gate on `membership_quality='exact' AND confidence='enumerable'`, never on emptiness. `empty_reason` is **NULL on 51/52** of the exact empties, so `empty_reason IS NOT NULL` is not a usable filter. |
| **T-CHECKONLY** — `external_check_only` child with `target_address='0x0'` | All 50 `RolesAuthority` OR-rows publish this as not-determined, while `controller_values` independently proves `authority=0x0` on those registries. A check against the zero address can never pass, so the OR collapses to `{owner}` exactly. The published shape **understates what is proven**; reconciling them is what unlocks R-REGISTRY. |
| **T-ADMIN** — `contracts.admin` as the proxy-admin closure seed | Populated on **1 of 24** eip1967 proxies; `beacon` 1; `implementation` loaded and never used. The closure is effectively inert here — don't count it as covering upgrade authority, and don't read its emptiness as "no proxy admins exist". |
| **T-ORIGIN** — `function_principals.origin` / `details->>'source'` | Single-valued on all 870 rows (`semantic_capability:finite_set` / `semantic_predicate_capability_resolver`); `principal_type` uniformly `controller`. **No discriminating information.** Real provenance is `details->'resolver_path'` / `details->'trace'[*].step`. |
| **T-LABELS** — `principal_labels.label` / `display_name` / `confidence` / most of `labels` | Name-derived: `principal_enrichment.py:465-475` mints labels as `f"controller_{_slug(edge.label)}"` where `edge.label` is the **state-variable name** — which is how `controller_unpauser` exists. Scoring "this principal can unpause" off it is exactly the inv.2 ban. `confidence ∈ {high,medium,low}` is **display-name confidence, not evidential**. The faithful subset restates `control_graph_edges.relation`; use the edges. |
| **T-RATELIMIT** — `severity_weight = 0` + a mandatory proven rate limiter | A **prohibition, not a weight.** `capacity.state`, `refill_rate.state` and `bounds_total_extraction.state` are **all `not_determined`** (10/10) while `mandatory.state='proven'`, and the witness's own `interpretation` says: *"capacity == 0: a freeze — a pause in disguise. **not_determined on either: no severity conclusion may be drawn.**"* Crediting it as a mitigation over-claims against an explicit refusal. Live temptation: it is mandatory on `stEthRequestWithdrawal`, a **$467M** function. |
| **T-OLDIMPL** — `upgrade_events.old_impl` | NULL on **120/120 by construction** (`upgrade_history.py:598`): *"'not recorded', not 'no predecessor existed'."* Do not diff implementation chains from it. |
| **T-CHECKPASSED** — `effect_verdicts.current_check_passed` | **0/274 populated.** Never written on this corpus. |
| **T-PRICE** — `contract_balances.price_usd` | No provenance column, and **432/721 rows have `price_usd=0.00` with `usd_value=NULL`** (212 spam symbols). `sum(usd_value)` is correct only because `usd_value` is NULL; nothing distinguishes "worthless spam" from "price lookup failed", so using `price_usd` directly would silently price real holdings at zero. |
| **T-ROLEDEFS** — `role_definitions.role_name` | Mis-parses ERC-7201 storage-slot constants as roles (`AccessControlDefaultAdminRulesStorageLocation`, `OwnableStorageLocation`). The 9 real rows are standard OZ/Timelock names already in the authority plane. |
| **T-TARGETS** — `effective_functions.effect_targets` | Display projection concatenating state-write variable names with dotted call heads; **501 of 1,642** populated rows carry only call heads. Use `state_writes` / `sinks` / `state_changing`. (Searched for the analogous shape inside `claims[]` — **none recurs**: `sink_ids` are structured identifiers, `flows[]` typed objects, `observed_blast_radius` canonical ABI signatures.) |
| **T-ACCESSOR** — accessor-name bases (33 persisted rows, label `internal_accessor_convention`; written as `deunderscore_convention` / `standard_namespaced_accessor` since A3) | The returned address is a real `eth_call` result, but the *binding* is a name match: when the gate is `msg.sender == _owner` the resolver reads the public `owner()` getter assuming it fronts the same storage. Fail-closed to a whitelist, so a tight convention — **admissible with a stated residual, never presented as bytecode-grade.** The ERC-7201 arm is an EXACT-name table match and so reads authoritative; it is seated in the SAME weak tier, unordered against the convention arm, and both publish `accessor_slot_agreement: not_determined`. |
| **T-SUMMARIES** — `contract_summaries` | §4's *verdict* (corroboration only) is right but its stated *reason* is wrong: these are **IR-derived from the Slither AST, not LLM** (`summaries.py`), and `is_pausable` is genuinely three-valued. The real reason to keep them off the grade is **redundancy**: `is_pausable=true` agrees with "has a `pause.set` claim" on **all 30**, zero disagreement either way. The cited split-proxy under-reporting is **not observable on this corpus**. The one non-redundant field is `standards` (ERC165 15, ERC20 14, ERC2612 13), a witness for inv.3's product-vs-privileged split — today `PRODUCT_CLAIMS` treats `erc20.transfer` as product on `claim_id` alone, one step from name inference. |

### B12. Negative results — do not go looking here

- **Four claim types carry a flat severity and their witnesses contain nothing
  that could refine it.** The gap is upstream in the matcher, not in the scorer:
  `upgrade.implementation` (49, sev 1.0 — keys: `kind`, `selector`, `gate`,
  `explained_delegatecall_sink_ids`), `authority.replace` (32, 0.75 — `kind`,
  `selector`, `standard`, `write_target`, `authority_gate_vars`),
  `roles.configure` (30, 0.55 — `kind`, `selector`, `standard`),
  `ownership.transfer` (39, 0.55 — plus `corroboration`). Relatedly,
  **`timelock.set_delay` (2 claims) carries no delay value and no min-delay
  bound** — the witness cannot distinguish shortening a 10-day timelock to 10 days
  from shortening it to zero.
- **All 101 `authority_change` verdicts are `unknown`** (39
  `mutation_call_reverted` — *"a precondition revert, not a proven absence of
  effect"*; 62 `no_authorization_delta_observed`, whose detector is fail-closed by
  design and therefore conflates "provably did not open" with "ambiguous").
  There is **no behavioral confirmation of any authority change** in this corpus;
  the top of the ledger rests on static tiers alone. That is admissible — but it
  is not a fork proof.
- **Pairing `pause.set` with `pause.unset` by `flags[].var` instead of by
  contract** — checked and **rejected**. It changes exactly **1 row**
  (`LiquidityPool.initializeOnUpgradeV2`, no matching unset latch), and that row is
  one of the two known false-positive `pause.set` claims, so the only effect would
  be to promote a false positive from the floor to `FREEZE_IRREVERSIBLE`. Correct
  in principle, net-harmful on this corpus.
- **Nested Safe ownership does not exist on this corpus — do not spec for it.** Of
  the 65 `safe_owner` targets: eoa 61, safe 2, contract 1, timelock 1. Restricted
  to the 11 Safes that actually appear as function principals, exactly **one**
  non-EOA owner exists (`0xf46d3734`'s owner `0xc03e742e…`, a contract). The
  "owner-is-another-safe / nested quorum" hypothesis is **not supported** here.
  Worth handling for other protocols; there is nothing to calibrate against at n=1.
- **`safe_owner` is a genuine relation but inert for value** (0 of 65 owners hold a
  balance, contributing exactly $0 to the closure). Its value is the B4 overlap
  analysis, not the closure. Latent hazard: because one owner does **not** satisfy
  a k-of-n threshold, treating it as a full control edge would over-attribute if any
  owner ever were value-bearing.
- **`bytecode_cache.selfdestructed_at` is 0/367 populated** — it would have been a
  real fact; it is not there.
- **Nothing in `claims[]` on protocol 1 is LLM-labeled.** Every field traces to an
  AST classification, an SSA trace, a standard-selector match, an event fold, or a
  fork observation. The inadmissible LLM labels live in the audit tables.
- **`effect_behavior_cache`** (167) is verified **additive-zero**: 0 of 155 cache
  hashes lack an `effect_verdicts` row.
- **Eight documented `observed` keys are absent from every claim** (0 rows each):
  `observed_reach_floor_usd`, `reach_indeterminate`, `observed_reach_rejected_usd`,
  `protocol_tvl_usd`, `gate_mutation`, `historical`, `current_capability`,
  `current_check_passed`. The projection *would* carry them; they were never
  produced on this run. `observed_reach_floor_usd` matters most — it is the
  documented fix for "$0 reach on a zero-balance router that can move millions".
- **`effect_verdicts` was the highest-expected-value target and largely did not pay
  out.** 205 of 274 rows are `unknown` and orphaned by design; the freeze verdicts
  attach to screening candidates; and the effects layer's own comments pre-empt
  every adverse reading. **That is the system working** — the discipline had
  already withheld what wasn't proven. The trap-avoidance value here exceeds the
  extraction value, which is the most important thing to carry forward.

### B13. Conformance deltas for the current prototype

`scoring_prototype/scorer_v2.py` (`proto-0.2`) against this register:

**Non-conforming, under-scoring (grade-moving):**
- **F6 discards the entire static destination lattice** (B2). Two EOA-gated
  functions on a $467M contract contribute 0.000. Must run
  `static_destination_shape` before warning — with the `several`, `value_router`
  and missing-`flows` rules, and the per-asset conjunction (B2×B8) so the weight
  lands at the floor rather than `band($467M)`.
- `controller_values` never queried (B4) — 50 OR-rows resolvable to one principal;
  `owner=0x0` proven on 22 contracts holding $94M.
- 52 `resolved_empty` earned negatives published as unknown, 11 of them with a
  factually wrong `missing_witness` (B5).
- `observed_reach_priced_usd` floors to $0 where a proven partial floor exists (B1).
- `configures` / `callee` VaS re-attribution ignored (B2).

**Non-conforming, over-scoring:**
- Flat timelock weakness ignoring `delay` — **three** distinct delays (B4).
- Timelock/proposer double-count, ~7.35 raw (B4b).
- Safe owner-overlap ignored: two ledger rows that share 5 signers (B4).
- All 36 `proven` audit rows credited identically, ignoring `proof_kind` and
  `bytecode_keccak_at_match` (B9).
- `value_at_stake_usd` and `raw_points` published uncapped against a
  holder-closure reach (B1/G2).

**Latent inv.2 violations (dead today, one field from live):**
- `FREEZE_AUTO_EXPIRY` branch lacks the `auto_expiry` gate (T-BOUND).
- F1b's `$0` fallback lacks the `contract_balance_seeded` gate (B1).

**Invented proxies to replace:** F3's blast-radius denominator (use
`scored_denominator`, B3); `value_fns` as a value-bearing-entrypoint proxy.

**Conforming:** `reach_determined` gate (B1); per-key freeze recovery resolution
(B3); `verdict='proven'` admissibility gate (B7); `external_call_target` exclusion
(T-EXTCALL); `duration_bound_source` handling (T-INDEF).

### B14. Coverage of this register, and what to implement first

**How this register was produced.** Three independent read-only audits of the same
snapshot, partitioned to avoid overlap: (A) claim witnesses on
`effective_functions.claims` — exhaustive programmatic recursion over all 541
claims / 165 JSON paths; (B) principals, authority and the control graph —
`function_principals` (870 `details` rows), `capability_expr`, `authority_roles`,
`conditions`, all 6 `control_graph_edges` relations, `controller_values`,
`control_graph_nodes`, `principal_labels`, `role_definitions`, proxy columns; (C)
the ~35 tables the scorer never opens. **Every field recommended above was traced
to the code that writes it**, and no count is estimated.

**Known coverage gap.** `contract_materializations.analysis` / `tracking_plan` /
`predicate_trees` (97 populated rows) was checked for population but **not
jsonb-recursed**. It is the upstream analyzer artifact that `effective_functions`
and `contract_summaries` are projected from, so its facts reach a scorer through
those — but it is the one place a further unused witness could still be hiding.
`contract_dependencies` (451 rows) was covered at column level only.

**No on-chain re-verification was performed.** Every "proven" in this register
means *the pipeline's own witness is a deterministic on-chain read or event fold,
established by reading the producing code path*. If the load-bearing ones are to be
re-probed at a pinned block, the highest-value three are: `getMinDelay()` on all
three timelocks; `owner()` on BoringGovernance `0x86b5780b` and BoringVault
`0xf0bb2086` (the $44.6M and $30.0M zero-owner claims in B5); and
`getOwners()`/`getThreshold()` on `0x2aca7102` and `0x427989bb` (the 5-shared-owner
pair in B4). Apply the M7 rule — **resolve the runtime address first**:
`0x86b5780b` and the Tellers are direct deployments (`is_proxy=false`, 0 proxies
pointing at them, verified), but `RoleRegistry 0x3b44a093` and `PriceProvider
0x28a6e7eb` each have a proxy pointing at them and would give false negatives if
probed directly.

**Implementation order.** Ranked by grade impact per unit of work, not by
interest:

1. **Timelock delay** (B4) — 139/139 populated, three distinct delays, changes the
   weakness function, and is the exact input `SCORING_CALIBRATION_REVIEW.md` §6
   names as the blocker on adopting the exposure composition.
2. **The static destination lattice** (B2) — the only change that moves the grade
   on this corpus; makes this document's own stated headline scoreable for the
   first time; the computation already exists at `calldata.py:1077`; validates at
   3 agreements / 0 contradictions. **Must be paired with the B8 per-asset
   conjunction** or it lands 4.7× too heavy.
3. **Timelock/proposer collapse** (B4b) — removes ~7.35 raw of double-count and the
   ~27% WeETH exposure double-charge; the top item on the calibration review's own
   remaining-gaps list.
4. **`controller_values` owner chain** (B4/R-REGISTRY) — $79.66M currently
   unassessed; closes the registry half of the Boring plane.
5. **52 `resolved_empty` earned negatives** (B5) — the *cheapest correct fix*: it
   deletes 11 warnings that state a falsehood about our own evidence.
6. **Audit `proof_kind` + `bytecode_keccak_at_match` + `equivalence_reason`** (B9) —
   209/209 populated; turns a binary into the three-valued structure inv.1 demands.

Everything else in this register is correctness scaffolding whose effect on *this*
corpus is approximately zero — worth wiring because several items (B2's
`token_identity`, `contract_balance_seeded`, T-BOUND, T-RATELIMIT) are precisely
the guards that stop the next `sweepETH`-class over-valuation, but none is a
finding that can be banked today. **Rows flagged under 5 anywhere in this
register** (do not build a scoring rule on them alone): `contracts.admin` 1,
`beacon` 1, `secondary_implementations` 1, nested non-EOA Safe owner 1,
`empty_reason='empty_by_design'` 1, read-gap empty finite_set 1,
`live_slot_resolution` 2, timelock veto-canceller 2, `contract_balance_seeded` 2,
`storage_determined` 2, `observed_reach_priced_usd` 3, live `isPaused` reads 3,
proven freeze verdicts 4, `concrete_destination` 6,
`param_keyed_mapping_enumeration` 7, `covered_to_block` 8.

### B15. One-shot latch witness — the S1 strength gate, published (A1 / Unit 1)

Closes the first bullet of **B0b/S1** ("proof strength is computed, then
discarded") for the one-shot plane. `annotate_capability_one_shot`
(`one_shot_probe.py`) now writes a `latch_witness` object beside
`latch_state`/`latch_value`/`latch_target` on every `kind='one_shot'` condition
in `effective_functions.conditions`. **No verdict changes** — `latch_state` and
`latch_value` reproduce byte-exactly on the 6 recoverable protocol rows re-run
through the production path at block 25643300. Only strength metadata is added.

**JSON path:** `effective_functions.conditions[] where kind='one_shot' →
.latch_witness`. Served verbatim by `analysis_detail.py:434-436`.

**Population (as of the PR-161 replica, 2026-07-30):** 0/39 today — the keys
appear on the **next resolution pass only**; already-stored rows keep the 5-key
shape. Realized bases once repopulated, measured by loading each contract's job
`predicate_trees` artifact through the resolver's own path
(`get_artifact(session, analysis_job.id, "predicate_trees")`,
`capability_resolver.py:320`/`:333`) and keying the tree by the artifact's
`canonical_signatures` map: **`guard` 6 · `version_ge` 32 · `sentinel` 0 ·
`value_gt_zero` 0 · zero-decisive-descriptor 0**, over 38 functions / 39
conditions. Feeding those descriptors back through `_classify_value` with each
row's stored `latch_value` reproduces the stored `latch_state` on **39/39**.

**Absence is the third state.** An absent `latch_witness` means no latch was
read — an RPC failure, an unreadable slot, a tree with no decisive latch, or a
row persisted before this change. It is **not** evidence about the oracle. Per
B0b/S1's own rule, a consumer MUST read such a row as the **weakest** branch that
could have produced its `latch_state`. Every failure, revert and absence path in
the producer lands here or on `latch_basis: not_determined`; none lands on a
positive or a negative.

| field | JSON path (under `.latch_witness`) | population | status | three-state — and where failure lands | consumption obligation |
|---|---|--:|---|---|---|
| `latch_basis` | `.latch_basis` | 1/1 whenever the witness exists | **GATE** | Four-valued discriminator `sentinel` / `version_ge` / `value_gt_zero` / `guard`, plus **`not_determined`**. Proven-present = that oracle decided `latch_state`. There is no proven-absent. **A guard the evaluator cannot fold, i.e. any classification failure, lands on `not_determined`** — never on a branch label; the row's `latch_state` is then `indeterminate` too. Witness absent ⇒ weakest branch. | **gate + cite.** Gate the inertness credit on it; cite it in the finding. **No ordering over the four bases may be published or assumed** — see the small-pop bar below. |
| `probe_block` | `.probe_block` | present only when the pass pinned a height | **GATE** | Proven-present = the read happened at exactly this height. **Absent = the read used `latest` and has no reproducible height** (the `"latest"` path publishes no block rather than an unreplayable one) — the observation is then not replayable and must not be credited (inv.11/12). | **gate + cite.** Required for any inertness credit; see the permanence rule below. |
| `probe_address` | `.probe_address` | present whenever the witness exists | **REQ** | The address the read was issued against — the **runtime** deployment address, never `contracts.address`. No absent state while a witness exists. | **cite.** Without it `slot` + `raw_word` are not replayable. |
| `raw_word` / `read_kind` / `getter_selector` | `.raw_word`, `.read_kind`, `.getter_selector` | with the witness; `getter_selector` only when `read_kind='getter'` | CONF / trace | `raw_word` is the word the read returned, verbatim from the probe transcript — `hex(word)` (unpadded) on the storage arm, the getter's 66-char `0x`-prefixed return prefix on the getter arm, so compare it numerically, not as a string. `read_kind` names WHICH read produced it (`storage` \| `getter`), so a getter answer is never attributed to `slot`. Unreadable ⇒ no witness at all. | **cite.** Replay input: reissue `read_kind` at `probe_address`/`probe_block` and expect `raw_word`. |
| `standard` | `.standard` | with the witness | **GATE** | The producer's latch family (`storage_layout`, `oz_v5_namespaced`, `namespaced_slot_constant`, `structural_scalar_latch`, `unstructured_slot_latch`). Proven from the descriptor's construction, not from a name. | **gate.** With `latch_basis` this is what stops `latch_value` being read as an OZ version on every row — see the mis-typing note. |
| `slot` | `.slot` | with the witness | **REQ** | The descriptor's storage location. Keccak-anchored or layout-derived; absent when the descriptor had none. | **cite.** |
| `byte_offset` / `size_bytes` | `.byte_offset`, `.size_bytes` | `guard`-family rows often have neither | **GATE** | The byte range decoded out of `raw_word`. **Absent = the producer had no range**, so `latch_value` is the whole 32-byte word. Absence is load-bearing: the `_disableInitializers` sentinel test is `_DISABLED_SENTINELS[size_bytes]`, so **255 is a sentinel only for a 1-byte latch** and a range-less descriptor can never reach the `sentinel` basis. | **gate + three-state.** Never read a bare 255 / 2^64-1 as `_disableInitializers` without `size_bytes`. |
| `value_type` | `.value_type` | absent on `unstructured_slot_latch` | CONF | The declared Solidity type of the location, when the producer had one. **Does NOT resolve the `latch_value` mis-typing on its own** — it is absent exactly where the ambiguity is worst (Lido's Aragon `initializationBlock`, `standard='unstructured_slot_latch'`, publishes no type). The pair that resolves it is `standard` + `latch_basis`. | **cite + three-state.** |
| `role` | `.role` | `version` on the standard arms only | CONF | The static pass's **claim** that this location holds the persistent version member (it is what `_latch_may_decide` keys on). Proven-present = the pass asserted it; there is no independent verification of the claim. Absent on every structural candidate. | **cite.** Never a substitute for `latch_basis`. |
| `variable` | `.variable` | with the witness | CONF | The producer-side identifier the descriptor was built from. **Its referent depends on `standard`:** a state-variable name for `storage_layout` / `oz_v5_namespaced` / `structural_scalar_latch`; the nullary **getter** name for the `unstructured_slot_latch` getter arm; the **modifier** name for the `unstructured_slot_latch` modifier arm (Lido's real value is `"onlyInit"`, a modifier — not a state variable). | **cite only.** Never gate, classify or type anything on it — that is inv.2 name inference. |
| `guard.operator` / `guard.constant` | `.guard.operator`, `.guard.constant` | on `guard`-basis rows | **REQ** (when `latch_basis='guard'`) | The polarity-folded ALLOW predicate that decided. `constant` is **absent** for the `falsy`/`truthy` operators, which take none — never a defaulted 0. | **gate + cite.** This is the only thing separating rows with identical published triples: FiatTokenV2_2's `initializeV2`/`_V2_1`/`_V2_2` are all `consumed` at `latch_value=3` behind guards `eq 0` / `eq 1` / `eq 2`. |
| `expected_version` + `expected_version_basis` | `.expected_version`, `.expected_version_basis` | both or neither, never one | CONF **with residual** | Published **only as a pair**. Two bases: `oz_reinitializer_argument_literal` (the AST literal argument of `reinitializer(n)`) and `oz_initializer_modifier_standard_constant` (the constant 1 implied by `initializer` — **not a value read from the source**). Both arms match the closed `INITIALIZER_MODIFIERS` **name** set: that is the residual, and it is why the integer may never be presented as compiler-forced. **A descriptor with no basis (every row persisted before this change) publishes NEITHER key** — not a bare integer. A non-literal `reinitializer(someVar)` publishes neither. | **cite.** May be cited beside a `version_ge` basis; may never be **inferred from `latch_value`** (banned, §7/A1). |

**Permanence — `latch_state='consumed'` is a mutable now-fact, not an invariant.**
`latch_target='db_linked_proxy'` on **39/39** rows: every latched contract is read
through a proxy, so a `reinitializer(n+1)` shipped by whoever controls the upgrade
re-opens the initializer. The witness therefore publishes the observation
(`probe_address`, `probe_block`) and the register states the obligation: a consumer
MUST present the credit as **"consumed at block `<probe_block>` on `<probe_address>`;
re-openable by the upgrade authority of that proxy"**, never as a static protection
constant. **The principal who can re-open is `not_determined` in this producer** —
it is not published, and no consumer may substitute one. Permanence is *never*
proven here, not even by the `sentinel` basis: failing to detect a proxy is not
proof that none exists.

**Consumer defect this register now names.** `site/src/protocolScore.js:239`
(`if (isInertOneShot(action.fn)) return 0.95;`) credits `consumed` as permanent
inertness with no block and no counterfactual — an inv.10 violation and the exact
shape this entry forbids. `site/src/oneShot.js` and
`site/src/surface/layout/guardSummary.js:116-121` read `latch_state` only. **Not
fixed by Unit 1** (JS is out of its scope); recorded here as the register's
standing obligation on whoever writes the scorer.

**Small-population bar (B14) — none of these may calibrate a weight.** `guard`
basis **6 rows, 0 at protocol_id=1**; `sentinel` **0**; `value_gt_zero` **0**;
Aragon-block-number-typed `latch_value` **1 row** (ef 2120, Lido); bool-typed
`latch_value` **1 row** (ef 786, FiatTokenV2_2). The protocol-1 population is
**22 rows, all `version_ge`**. Every flagged one is under ~5, so each may
**gate / cite / three-state** and **none may calibrate**. In
particular: because `sentinel` and `value_gt_zero` have zero realized rows and
`guard` six, **no reliability ORDERING over the four bases is measurable on this
corpus** — any ordering a scorer adopts is a named model choice carrying its own
version, never a measured strength.

**Corrections to prior register claims, from this unit.**
- B0b/S1's anchors: `one_shot.py:203-300` → the producer is `_latch_location`
  **`one_shot.py:215-300`** (`:203` is its call site); `annotate_capability_one_shot`
  `:420-458` → **`:422-459`**.
- B0b/S1 states the descriptor emits a `guard` key. It does **not**: the A-spine
  `_latch_location` never emits `guard`, and `role='version'` only on its two
  standard arms. `guard` comes from the separate structural-candidate detector
  (`one_shot.py:567`, `:611`, `:638`). The aggregate key list was assembled from
  two different producers.
- "The sentinel branch is recoverable because `latch_value ∈ {255, 2^64-1}` is the
  post-mask value" is **false in general** — see `size_bytes` above. Realized
  sentinel population is **0**.
- `FIELDS.md` §6's "`expected_version` / `standard` / `size_bytes` are dropped at
  persistence" is fixed forward by this entry, but only from the next resolution
  pass; it remains true of every currently stored row.
- **Lane-A's "descriptor recovered for 32 of 38; 6 not recoverable at all"
  (protocol-1 ef 479, 480, 1456, 2745; protocol NULL ef 2018, 2019) is
  WITHDRAWN.** It was measured through `contract_materializations`, which is not
  the surface the resolver reads: three of those four protocol-1 addresses have
  no row there at all, and `EigenStrategy`'s trees are keyed by Slither
  `full_name` (`initialize(IERC20)`, `initialize(IEigen,IERC20)`) rather than by
  the canonical `abi_signature` the `effective_functions` row carries. Loading
  each contract's **job** `predicate_trees` artifact instead, and keying through
  the artifact's own `canonical_signatures` map, yields a signature-exact
  decisive descriptor for **all 38** functions — including both `EigenStrategy`
  overloads and `CumulativeMerkleDrop.initializeLayerZero` (`expected_version` 2
  against its stored `latch_value` 2). Re-measured this unit: **0** functions
  with zero decisive descriptors. The withdrawn claim was absence-as-witness
  without proven coverage of the recording surface — the exact shape §4's
  reject-list names — and it also answers lane-A's own could-not-verify #7
  (`full_name` variant, not genuinely absent).
- Consequently: **no one_shot row is blocked on re-analysis for want of a
  descriptor.** Residual, stated honestly: whether a given row actually gains its
  `latch_witness` depends on **when that job is next re-resolved** — a
  scheduling fact this unit does not control and did not measure. Until a row is
  re-resolved it keeps the 5-key shape and must be read as the weakest branch,
  which is the same obligation as any absent witness.

### B16. Caller-set currency and accessor basis — the S1 strength gates, published (A2 + A3 / Unit 2)

Closes the second and third bullets of **B0b/S1** for the caller-set plane: the
event-fold height and the emptiness reason were computed at the adapter leaf and
**dropped by every finite combinator**, and the accessor basis was published only
inside `details->'trace'[*].basis`. Both are re-publication of facts the producer
already had; **nothing here is a new inference and no read was added.**

**Populations are PROSPECTIVE.** On the PR-161 replica 250 of 1,799 rows carry any
`last_indexed_block` and **0 carry more than one height leaf**, so the MIN
combinator and both `exact_as_of` arms are 0-population on stored data; the 33
basis rows carry the pre-split label. Every field below materializes on the **next
resolution pass**. Stored rows keep their current shape and, per the rule this
appendix already states, must be read as the weakest branch.

#### B16.1 Fold height and exactness (`effective_functions.capability_expr`)

| field | JSON path | population | status | three-state — and where failure lands | consumption obligation |
|---|---|--:|---|---|---|
| `last_indexed_block` | `.last_indexed_block` (any node) | 250/1799 today, at leaves only | **GATE** | Proven-present = **MIN** over every operand's fold height — a **STALENESS FLOOR**, not an as-of. There is no proven-absent. **Absent = `not_determined`**, and that is where *every* fail-closed arm lands: any operand without a height (an unpinned live `owner()` read is blockless by construction) makes the whole result blockless. `min`-of-present is **banned**. | **arithmetic + three-state** via `capability_currency` (`current`/`stale`/`not_determined`, `lag_blocks` never 0 by default). |
| `exact_as_of` | `.exact_as_of` | 0 today (prospective) | **GATE** | Three states, all distinguishable. An **int** requires ALL FOUR conditions, as built: (1) every operand carries a height, (2) all those heights are EQUAL (one instant), (3) the result's own quality is `exact` (a `lower_bound` set is exact at no height; for a cofinite the quality read is `blacklist_quality`), and (4) on the subtractive paths — `finite ∩ cofinite`, which has no structural-AND diversion — the emptiness is INHERITED, never created by the operation. The literal **`"not_determined"`** = heights present but heterogeneous, OR any operand already carrying that refusal — an *earned* refusal, **recorded before conditions (3) and (4) are even tested** (see the laundering note). **Key absent** = never computed: a leaf, or an operand with no height at all. | **gate + cite.** The only height admissible as an "the set was exactly this at block B" claim. |
| `empty_reason` | `.empty_reason` | 1 of 52 protocol-1 empties today | **GATE** | Propagated **only on INHERITED emptiness** — an operand that was already empty carries its own reason through. Emptiness *created* by an operation (`{X} − {X}` on the blacklist path) mints **no** reason; absent = `not_determined`. Two already-empty operands that disagree resolve to absent, not to whichever came first. | **gate.** Never `is not None` — see B16.3's allow-list. |

**Why MIN may not be promoted to an as-of** (this is the load-bearing correction
in this entry, and it withdraws the argument the original A2 plan rested on):
both fold families publish **state-AT-h with revocations already applied**
(`adapters/enumerable_role_store.py`, `adapters/solmate_roles.py`). For
`intersect(A@h1, B@h2)` with `h1 < h2`, an address revoked from B in `(h1, h2]`
is absent from the published B, so the published intersection can be empty while
the true intersection at `h1` was not — "empty at MIN" is **false**, not merely
unproven. On the subtractive paths (`finite − blacklist`, and both `negate`
arms) the argument **inverts**: the published set is a *subset* of the true set
at MIN. Hence `exact_as_of` exists only for the equal-heights case, and a
consumer may **never** substitute `last_indexed_block` for it.

**The refusal is recorded FIRST — a defect the adversarial round caught in the
first cut of this work.** Heterogeneous operand heights collapse to a single MIN
in `last_indexed_block`, so a result carrying one height and no `exact_as_of` is
byte-indistinguishable from a leaf. The first implementation returned early for
an unlicensed (created-empty) or non-`exact` result *before* testing
heterogeneity, leaving exactly that shape — and the next combinator read "all
heights equal" and minted the as-of the first operation had refused. Three
working launderings existed: `intersect(intersect(fold@b1, blacklist@b1'), fold@b1)`
→ `exact_as_of: b1` (false — at b1 the true set was non-empty); `negate` of that
same created empty → a cofinite "everyone" dated b1; and
`intersect(fold@b1, union(fold@b1, lower_bound blacklist@b2))` → `{[A],
exact_as_of: b1}` (false — the denylist that let A survive was observed at b2).
The refusal is therefore published regardless of licensing and regardless of
quality: it is the weakest state, so publishing it can never over-claim, while
omitting it can. All three are pinned as tests.

**A premise this rests on, stated so it can be re-measured rather than assumed.**
`min_indexed_block` (`repos/event_logs_pg.py`) gates on `backfill_complete` for
every topic but **not** on the cursors being at the same height, and returns
their MIN — so an adapter leaf's `last_indexed_block`
(`enumerable_role_store.py`, `solmate_roles.py`) is *itself* already a MIN across
topics. If those cursors diverged, a single leaf would carry the same
heterogeneity this entry refuses at the combinators, one level below where it is
checked. Measured on the PR-161 replica: **32 (chain_id, event_address) cursor
groups, 25 of them multi-topic, 0 with any spread** (`min(last_indexed_block) !=
max(...)`), all 25 `backfill_complete`, and 80 cursors carrying exactly **1
distinct height**. So the premise holds here — but it is a property of this
replica's indexing state, not an invariant of the code, and it must be
re-measured before any claim that a leaf height denotes one instant.

**Ten mint sites, nine propagating.** `capabilities.py` rebuilds a capability at
ten places; nine now carry provenance through `_carry_fold_provenance`
(`intersect`/`union` of finite and of cofinite, `finite ∩ blacklist`,
`finite ∪ blacklist`, and all three `negate` arms). The tenth —
`negate(external_check_only)` — is a **deliberate non-site**: its operand is a
probe interface that never carries a height, so there is nothing to propagate
and nothing to date. A test asserts that arm emits neither key, so the omission
cannot later read as an oversight. `negate` carries the height but **not**
`empty_reason`: why a set is empty says nothing about why its complement is.

#### B16.2 The live read's own provenance (`.trace[]`)

| field | JSON path | population | status | three-state — and where failure lands | consumption obligation |
|---|---|--:|---|---|---|
| `observed_at_block` | `.trace[*].observed_at_block` on `live_getter_resolution` / `live_slot_resolution` | 0 today (prospective) | **GATE** | Proven-present = the `eth_call` / `eth_getStorageAt` was pinned to exactly this height. **Absent = the read went to `"latest"`** and has no reproducible height (`block` is `None` on the controller-read path, as `FIELDS.md` §4 records) — publishing a head here would stamp a bounded claim onto an unbounded read. | **gate + cite.** Required for inv.11/12 replay and for B16.3's credit. |
| the trace itself on an empty result | `.trace[0]` | 0 today; **4 stored rows have no trace at all** | **REQ** | An exact-empty from a live read now carries `{step, selector\|slot, contract}`. Before this, the strongest earned negative in the system was published bare: 4 rows (ef 192, 797, 1151, 1613) are unreconstructible, and one of them — EACAggregatorProxy, whose `pendingOwner()` **reverts** on mainnet — provably did not come from the zero branch at all. | **gate.** |
| `read_address` | `.trace[*].read_address` | 0 realized | CONF | Recorded only on the burn arm, so the "this address is unspendable" characterization is checkable downstream instead of taken on trust. | **cite.** |

**`empty_reason` vocabulary, extended and narrowed.** Added: `owner_read_zero`
and `slot_read_zero` — each says only *what was read*, at a stated block.
Added `owner_read_burn_address` for a `0x…dEaD` read, which is now **split off
from the zero shape**: `0x0` can never be `msg.sender` on mainnet, which is what
makes a zero read a real "nobody", whereas `0x…dEaD` is an ordinary address
merely *believed* keyless — a convention, not a proof. That arm publishes a
`lower_bound`/`partial` empty, never `exact`/`enumerable`, and never earns the
credit. **Removed:** the slot reader no longer stamps `empty_by_design` from a
**default argument value** (`zero_empty_reason="empty_by_design"`); the
parameter is gone. Classifying an emptiness as an intended accept-side ceiling
rests on the accessor's `pending` prefix — an identifier — and that claim stays
where it discloses its basis (`_pending_ceiling_capability`, whose trace records
`basis: "accessor_name"`).

**Burn-vs-zero on stored rows is NOT determinable.** The 4 provenance-less
exact-empties carry no contract and no selector, so which branch produced them
cannot be reconstructed: they are **≤4 candidate rows, split not determinable
from persisted data**. Only re-resolution settles it. (An earlier draft of this
work claimed "0 rows realized" for the burn arm; that claim is withdrawn — it
was absence-as-witness.)

**`capability_currency` moves, in the honest direction.** Propagation gives a
FOLDED ROOT a height it did not have, so rows move `not_determined` →
`current`/`stale` — that is the intended gain (`analysis_detail.py`, the served
`capability_currency`, needs no change to produce it). Two second-order effects,
stated rather than discovered later: (1) because the MIN is taken across
operands, a composition of two folds can read `stale` where either operand alone
would have read `current`, and (2) a combinator node's MIN can become the tree's
lowest height, so a row already reading `current` off a surviving sibling can
move to `stale`. Both are the honest direction — a composition really is only as
current as its least-current operand — and both are **measured-unlikely**: the
within-one-job cursor spread is 203 blocks against a 1,000-block staleness
threshold, and on this replica all 80 cursors sit at a single height. Unmeasured,
because it needs a resolution replay: how many rows actually move.

**The burn arm is REAL, not hypothetical.** Solady's `TopUp` / `TopUpV2` hold
`owner() == 0x…dEaD` on mainnet, and the repo's own verbatim fixture
(`tests/fixtures/contracts/authority/solady/`) exercises exactly that path. So
this is a **value change on a live shape**, not an armed-but-unrealized branch:
that gate previously published `membership_quality='exact'` — "provably nobody
can call this" — and now publishes `lower_bound` + `owner_read_burn_address`.
Consequences: no principal is minted either way (unchanged, and that was already
correct), but such a row no longer reads as `resolved_empty` and can no longer
earn the credit. The direction is conservative: an unproven negative becomes an
honest unknown.

**Its measured corpus impact is nevertheless 0 rows.** The four `TopUp` /
`TopUpV2` / `TopUpDest` contract rows on the replica carry **0
`effective_functions`** between them, and **no** stored `capability_expr` has
`0x…dEaD` as a `finite_set` member — the burn address does not appear anywhere
in any stored `capability_expr`; a loose `dead` substring match returns 23
trees, 21 of them the word `deadline` in time conditions. So the code path is real and fixture-exercised while the
persisted blast radius is nil — which is why this is registered as a behaviour
change with a stated 0-row impact rather than as a row-flipping correction.

#### B16.3 The earned-negative gate (`analysis_detail` → `exact_empty_credit`)

An empty caller set is the strongest earned negative the resolver publishes, and
the shipped consumers award it on `membership_quality == "exact" && members == []`
alone — a shape a provenance-less empty satisfies exactly as well as a
read-confirmed one. The gate is now **served beside the payload** rather than
re-derived downstream.

**There are TWO consumer credit paths, and a scorer that switches only the first
changes nothing.** `isResolvedEmptyFunction` is
`fn?.status === "resolved_empty" || isExactEmptyCapability(fn?.capability_expr)`
in BOTH shipped consumers (`site/src/protocolScore.js:138-140`,
`site/src/surface/layout/guardSummary.js:82-84`). The second disjunct is the
capability-shape derivation this entry replaces; **the first is a column**, and
per the Q1 adjudication `status` is deliberately UNCHANGED by this unit —
measured: **86/86** of the affected rows carry `status='resolved_empty'`. So a
consumer that adopts `exact_empty_credit` while leaving the `status` disjunct in
place awards exactly the same credit it did before. Both disjuncts must be
replaced together.

**The gate answers at the ROOT only; there is no recursion.** Measured
distribution over the 86: `{not_determined: 85, not_applicable: 1}` — the single
`not_applicable` is the one row whose root `kind` is `AND` (85 roots are
`finite_set`). A nested exact-empty under an `AND`/`OR` is therefore NOT assessed
by this field, which is why the consumer rule is **"award credit only on
`earned`"** and never **"withhold credit only on `not_determined`"**:
`not_applicable` means *this field did not look*, not *there is nothing here*.
Recursing the gate would require deciding what an earned negative means under a
disjunction, which this unit does not settle.

| verdict | meaning |
|---|---|
| `earned` | **all four** hold: `exact` + `enumerable`; a trace step from an **allow-listed** coverage-proving producer; an **observation block**; and an **allow-listed** read-confirmed `empty_reason`. The payload carries `{block, block_source, empty_reason}` so the gate travels with its witness. |
| `not_determined` | anything short of that, with `missing[]` naming which requirement failed. **Withholds** a credit; never asserts that a caller exists. |
| `not_applicable` | not an empty finite_set. |

Three allow-lists, because a presence check fails open:
- **coverage-proving steps** = `{solmate_roles_authority, enumerable_role_store,
  live_getter_resolution, live_slot_resolution}` — the two folds refuse to fold
  at all without a `backfill_complete` cursor (`no_index_cursor` → deferred), the
  two reads are single pinned calls that are their own surface. Any other step,
  present or future, reads `not_determined`.
- **read-confirmed reasons** = `{owner_read_zero, slot_read_zero}`. Excluded with
  cause: `empty_by_design` (name-derived classification), `unreadable_revert` /
  `unreadable_empty` / `not_read` / `bad_input` (failure states — a failure may
  never license a credit), `owner_read_burn_address` (convention, not proof).
- **observation block** = a trace `observed_at_block`, or an `exact_as_of` int.
  **`last_indexed_block` is NOT admissible** — admitting the MIN here would
  launder the refuted "empty at MIN" arm back in through the consumer.

**Measured blast radius (reproducible predicate).** Applying the repo's own
`project_capability_surface` / `capability_surface_openness` /
`_is_resolved_empty_capability` to all 1,799 `effective_functions` rows carrying a
`capability_expr` on the PR-161 replica: **86 rows** are `restricted` resting
SOLELY on the resolved-empty branch (no public path, no principal rows) — 52
protocol-1 / 34 protocol-NULL; 82 carry a `solmate_roles_authority` step (50 of
them protocol-1), 4 are zero-trace; and **86/86 carry no `last_indexed_block`
anywhere in the tree**. Under this gate **0 of the 86 are `earned` today**.
That is why the gate is a **separate served field and does NOT change `status`
or `authority_openness`**: folding it into `status` would withdraw `restricted`
from all 86 — including 50 protocol-1 empties whose emptiness was chain-verified
5/5 at block 25643300 — which trades an over-claim for a much larger
under-claim. The credit is withheld at the consumer, where it can be re-earned
by re-resolution, not erased from the surface.

**Withdrawal, stated precisely.** The plan named ef 192, 1613, 797 and 1151 as
losing an `empty_by_design` credit. Re-measured: **only ef 192 carries
`empty_by_design`** (it is the single node with that reason in all 1,799 trees,
and it is the trace-less default-argument shape); ef 797, 1151 and 1613 carry
**no `empty_reason` at all**. All four fail this gate regardless — on the
missing trace and the missing block — so all four read `not_determined` until
re-resolved. ef 192 may re-earn the credit honestly once re-resolved, since its
producing path now publishes a slot read with its block.

#### B16.4 Small-population bar (B14)

`empty_reason` present on **1 of 52** protocol-1 empties · zero-trace empties
**4 corpus / 2 protocol-1** · burn arm **≤4 candidates, split not determinable** ·
`slot_name_keyword` **0 rows** · A3 = 33 rows but only **2 distinct principals /
3 runtime addresses** · realizable height candidates: **≤25** blockless
`enumerable_role_store` nodes, of which **8** carry two fold steps (the shape
where both operands provably carried a height). Every one of these is at or
under the bar: they may **gate, cite or three-state**, and **none may calibrate a
weight or a threshold**. The `abi_auto_getter` rename touches **0** persisted
rows; the de-underscore split touches all 33.
### B17. Upgrade executor fold — who executed, and the deployments that were never upgrades (C4 / Unit 8)

`upgrade_events` carries no sender, no receipt and no trace, so before this the
corpus could not answer "who executed this upgrade" *or* "how many upgrade
actions were there". The fold adds the transaction's own receipt as a second
instrument, one `eth_getTransactionReceipt` per **distinct** `tx_hash` (68 for
protocol 1, 107 table-wide, one-time — a mined receipt is immutable).

**Tables:** `upgrade_transactions` keyed `(chain_id, tx_hash)` — which IS the
`governance_action_id` — and `contract_creation_witnesses` keyed
`(chain_id, address)`. `upgrade_events` gains a nullable `chain_id` as the link
half of a composite MATCH SIMPLE foreign key. **Row existence is the coverage
discriminator:** a row means a receipt was read and decoded; no row means never
read or read failed. Nullable columns on `upgrade_events` were rejected for
exactly this reason — `executor_kind IS NULL` would conflate "not fetched" with
"fetched and undetermined", which is a defaulted witness.

**Producer:** `services/discovery/upgrade_history.py::fold_upgrade_transactions`,
called from `workers/static_worker.py` after `project_to_events` in its own
failure domain. **Readers:** `upgrade_action_counts` /
`governance_actions_for` / `event_is_deployment` / `top_level_msg_sender` /
`executor_call_targeted_proxy` (same module); the published payload is
`company_overview` `contracts[].upgrade_count` + `.upgrade_count_basis`.

| field | JSON / column path | pop. (PR-161 replica) | status | three-state | failure path |
|---|---|--:|---|---|---|
| `governance_action_id` | `(upgrade_transactions.chain_id, .tx_hash)` — the PAIR, returned by `governance_actions_for` as `set[tuple[int, str]]` | 68 tx / 120 events | **REQ** (arithmetic) | present = this action's id · — · absent row = no receipt fact | no row. The bare hash is **not** the id: the same 32 bytes can name a different transaction on another chain, and a bare-hash union across contracts merges them (the aliasing class #158 closed). A contract whose chain resolves to nothing contributes no pair — a chain-scoped key cannot be minted without a chain — while its per-contract COUNT is unaffected |
| `executor_kind` | `.executor_kind` | 3-valued, never NULL | **REQ** (gate + cite) | `timelock_routed` / `safe_direct` are each proven · there is no proven-absent polarity · `not_determined` carries every other case | **`not_determined`** on: receipt unfetchable · `status=0x0` · neither marker · marker emitter unclassified · planes disagreeing · two distinct marker emitters · log set not provably complete |
| `executor_address` | `.executor_address` | populated iff kind positive | **REQ** (cite) | the marker's emitter · — · NULL | NULL |
| `executor_classification_source` / `executor_classified_type` | `.executor_classification_*` | populated iff kind positive | **GATE** | which persisted plane typed the emitter, and as what · — · NULL | NULL. A CHECK constraint makes the gate **inseparable** from the payload |
| `executor_classification_block` | `.executor_classification_block` | **0 rows today** | **REQ** (three-state) | the height the classifier probed at · — · NULL = not determined | NULL. Populated going forward by B10.1a's `safe_protection.probe_block` |
| `executor_call_targets` | `.executor_call_targets` (JSONB) | gated on `timelock_routed` | **REQ** (cite) | the `target` word of each `CallExecuted` · — · SQL NULL | NULL — and `executor_call_targeted_proxy()` returns `not_determined`, never `false`, for a `safe_direct` tx |
| `receipt_log_set_complete_for_tx` | `.receipt_log_set_complete_for_tx` | computed per row | **GATE** | `true` = the receipt carries every stored `Upgraded` for this tx, AND its `logsBloom` is **usable** (present, well-formed, and confirming an `Upgraded` log the array actually carries — the positive control that rules out an all-zero bloom), AND that usable bloom agrees with the array about `CallExecuted` · `false` = any of the three fails · — | **An absent, malformed or all-zero bloom is `false`, not a pass.** The bloom is a REQUIRED witness for the absence arm, not a consistency check that silence satisfies: with no bloom there is nothing to contradict, and a contradiction-only rule mints `safe_direct` from a receipt whose logs were pruned. `false` withdraws every marker-**absence** inference, which is the entire basis of `safe_direct` |
| `is_contract_creation` / `created_contract_address` / `receipt_to` / `receipt_from` | `.` same | 68/68 | **GATE** | verbatim receipt facts; `receipt_to IS NULL` is the FACT "contract creation", told apart from "unknown" by the row existing | absent row |
| `receipt_upgraded_counts` | `.receipt_upgraded_counts` (JSONB) | 68/68 | **GATE** | the receipt's OWN `Upgraded`-log count per emitting proxy | — . Exists because the projected rows cannot witness their own under-projection: with one of two logs stored, the stored pair count reads "one event" and the deployment guard would exclude a transaction that also carried a real implementation change. The guard reads the LARGER of the two. Latent — 0 live instances on this corpus |
| `block_number` / `block_hash` | `.` same | 68/68 | **GATE** (cite) | the observation coordinates | — |
| **derived** `is_deployment` | `event_is_deployment(...)` per (tx, proxy) | **24 of 120** | **REQ** (arithmetic + cite) | proven by **either** arm — receipt (`to IS NULL AND contractAddress == proxy`, 18) or the **two-witness** creation pair (`creation_tx_hash == tx_hash` AND `code_absent_at_probe` at `event_block − 1`, 6) · — · anything less | **`false`, and the event stays COUNTED.** Neither witness alone is admitted; disagreement is not determined. A (tx, proxy) pair with **more than one** event is never excluded (a within-tx swap-and-restore is not a plain creation), where "more than one" is the LARGER of the stored pair count and `receipt_upgraded_counts` |
| **derived** `top_level_msg_sender` | `top_level_msg_sender(...)` | 4 tx | **CONF** | `receipt.from`, published **only** where `receipt.to == proxy`; the claim is "was msg.sender in the TOP-LEVEL frame" and nothing more · — · every other tx | `None`. **Never** consumed as "who authorised" |
| **derived** `direct_upgrade_witnessed_at_block` | basis `.direct_upgrade_witnessed_at_block` | per proxy | **CONF** (cite) | "a direct-Safe path WAS exercised, at block B" · — · no `safe_direct` tx | `None`. Licenses no claim about the path being open now |
| `upgrade_count` | `contracts[].upgrade_count` | per contract | **REQ** (arithmetic) | an **UPPER BOUND** on real upgrades — proven deployments removed, unproven events kept · — · **`None`, including post-exclusion zero** | `None`. See the zero rule below |
| `upgrade_count_basis` | `contracts[].upgrade_count_basis` | per contract | **GATE** (cite) | `events_total` / `tx_facts_present` / `events_unlinked` / `events_without_tx_hash` / `deployments_excluded` / `executor_kinds` | — |
| `authorising_eoa` | `upgrade_count_basis.authorising_eoa` | **0/68 ever** | **BAN** | never proven · never disproven · **always `not_determined`** | the literal string is published so the refusal reaches the consumer instead of being an omission it could fill in |
| `timelock_is_decoy` | `upgrade_count_basis.timelock_is_decoy` | **0/24 ever** | **BAN** | — · — · **always `not_determined`** | no column, no computation |
| `recorded_event_coverage` | `upgrade_count_basis.recorded_event_coverage` | per contract | **GATE** | — · — · **always `not_determined`** | only the ERC-1967 topics are folded and `old_impl` is NULL 191/191, so "no event" never licenses "no upgrade" |

**Consumption consequence, stated per §8.** `upgrade_count` is read by the
prototype consumer as a pure PRESENCE check in four places —
`site/src/protocolScore.js:332` (half of a proxy's `observability` term),
`:405` (one of the `is_proxy` completeness checks), `:836` and `:865` (the
`incompleteProxies` count and its "proxy metadata incomplete" example list).
Publishing `None` for the three proxies whose only stored event is their own
deployment therefore **removes their observability credit and adds them to the
coverage-gap list**. That is the honest direction — the credit was being paid
for a row that recorded a creation, not an upgrade — but it is a real grade
movement and it is the reason this field is registered rather than quietly
changed. Note also what the consumer cannot see: `upgrade_count == null` now
collapses "no upgrade data at all" with "the only event was a proven
deployment", and **only `upgrade_count_basis` separates them**. Nothing reads
that sidecar today; a consumer that wants the distinction must.

**The zero rule (why `upgrade_count` is `None`, not `0`).** The number is
RENDERED as literal "N upgrades" (`site/src/surface/canvas/ContractNode.jsx:78`
and `:87`, `site/src/surface/lanes/EntityCard.jsx:151`), so a published `0` reads
as an earned negative. After excluding proven deployments, three proxies reach
zero — and zero there means only *"no non-deployment event was recorded"*, over a
recording surface that is itself unwitnessed. The aggregation therefore publishes
`None`; the reader renders nothing.

**Two bans, restated because both have a populated field sitting right next to
them.** (1) `authorising_eoa` from `tx.from`: the 11 `ExecutionSuccess`-bearing
transactions on one Safe were submitted by **five distinct senders** (re-measured
over all 68 receipts), so `tx.from` names the submitter, never the signer set —
including the 4 transactions where `receipt.to == proxy`, where the narrower
`top_level_msg_sender` is published instead and an `eoa_one_hop` executor kind is
**not** (a top-level frame is not the upgrade site, and the guard's operand is an
AST fact no receipt can reach). (2) `timelock_is_decoy` from the observation that
zero direct upgrades follow each proxy's first timelock-routed one: that is an
absence of observed bypass, not proof that no bypass exists.

**The 68-transaction partition, re-measured from the receipts (2026-07-30):**
18 contract-creation receipts · 23 carrying `CallExecuted` · 15 carrying
`ExecutionSuccess` with no `CallExecuted` · 4 with neither and `receipt.to ==
the proxy` · 8 with neither and `receipt.to` an intermediary (`0x356d1b83…` 6,
`0xdbf6be12…` 2 — the first six are the factory deployments arm 2 catches, the
last two stay `not_determined`). The 15 `ExecutionSuccess` emitters are
`0xf155a263…` ×11 (**unclassified on every plane ⇒ `not_determined`**),
`0xf46d3734…` ×3 and `0xa000244b…` ×1.

**Small populations (B14 — may gate / cite / three-state, never calibrate a
weight):** 4 one-hop transactions · 2 mediating intermediaries (6 tx + 2 tx) ·
3 `safe_direct` transactions by `0xf46d3734` and 1 by `0xa000244b` · 8 dual-class
proxies · 3 within-tx swap-and-restore pairs. Corpus-bound even where above 5:
24 deployments, 23 timelock-routed, 15 `ExecutionSuccess`-bearing, 24 proxies,
1 protocol, 1 chain.

**Stated limitations.** (a) `eth_getTransactionReceipt` takes no block parameter,
so unlike every other chain read here it **cannot be pinned by parameter**; the
observed heights (10743414–25533308) are final beyond any plausible reorg depth
and `block_hash` is stored so a reorg is *detectable* rather than merely trusted.
(b) The classification plane carries no height on any current row, so
`executor_kind` asserts "the emitter is typed a Safe/timelock **by our
classifier**", **not** "…and it was one at the upgrade's block" — proving that
would need an archive `eth_getCode` at 2023-2026 blocks, which is out of scope
here. (c) **The migration backfills no `chain_id` at all.** `upgrade_events.chain_id`
is written only by the fold, and only for transactions whose receipt fact row
exists — so it starts NULL on all 191 existing rows and the composite FK stays
disabled for them (MATCH SIMPLE). That is strictly more conservative than a
derived backfill: no row is linked on an inferred chain. Where the column IS
written it is the chain the fold read on. Consequence for this corpus:
`contracts.chain` is `'ethereum'` on every row, so nothing here exercises an
unresolvable-chain arm.
(d) The foreign key's delete rule is **NO ACTION**, not `SET NULL`. `SET NULL`
on a composite key nulls *every* column in it, which would destroy `tx_hash` —
the row's only handle on its own transaction — to preserve referential
tidiness. NO ACTION instead refuses to delete a receipt fact that events still
reference; the normal lifecycle never needs to (`Contract` deletes cascade to
the events, i.e. the child side).

### B18. Role holder plane — the lower bound a fold cannot fake (D6-accept / Unit 7B)

`role_definitions` could name a role and `function_principals` could name an
address, but nothing joined the two: `effective_functions.authority_roles`,
`capability_expr`, `claims` and `control_graph_edges.label` match the real role
names — and their keccaks — **zero** times. This plane closes that, keyed
`(chain_id, registry_address, role_hash)` in the new table
`role_holder_planes`.

**Two surfaces, and neither does the other's job.** The
`RoleGranted`/`RoleRevoked` fold PROPOSES candidates; a pinned
`hasRole(bytes32,address)` (`0x91d14854`) read WITNESSES each one. Only the read
can put an address in `holders`. That asymmetry is the whole design: a fold that
misses grants, mis-orders revokes or stops early yields a **smaller** lower
bound, never a wrong one. What the fold's incompleteness costs is completeness,
and completeness is published separately and permanently as `not_determined`.

Because the fold only proposes, candidates are drawn from every address that
ever *appears* for a role — granted and revoked alike. An address the fold
believes revoked whose `hasRole` returns true is **admitted**; the read proves
it. This does not conflate administering a role with holding it: OZ expresses
"may administer X" as membership in a *different* `bytes32`, hence a different
primary key.

| field | column | pop. | status | three-state | failure path |
|---|---|--:|---|---|---|
| `holders` | `role_holder_planes.holders` | 11 protocol-1 `(registry, role_hash)` keys / 3 registries | **REQUIRED** | proven-present = a **LOWER BOUND**, each member independently witnessed / proven-absent **unreachable by design** / `not_determined` = NULL | revert, transport failure, cold-or-missing cursor on either topic, unpinnable probe block, or zero confirmations ⇒ **NULL**. **Never `[]`** — a DB CHECK makes the empty array unrepresentable | three-state + cite. **`len(holders)` is a FLOOR, never a count** |
| `holders_basis` | `.holders_basis` | 11 | **GATE** | `pinned_has_role_confirmed` / `not_determined` | any failure ⇒ `not_determined` | gate |
| `holder_set_exhaustive` | `.holder_set_exhaustive` | 11 | **GATE** | **always `not_determined`**, CHECK-pinned | unconditional | gate. A consumer may **never** read `holders` as complete |
| `as_of_block` | `.as_of_block` | 11 | **REQUIRED** | present iff `holders` non-NULL | `holders` NULL ⇒ NULL | cite (inv.10 — a mutable now-fact carries its height) |
| `as_of_block_hash` | `.as_of_block_hash` | best-effort | **CONF** | the pinned block's hash **when readable** | the hash read failing leaves the height standing and the hash **NULL** — only replay-after-reorg is weaker | cite |
| `cursor_first_indexed_block` (+ basis) | `.cursor_first_indexed_block` | **0/11 witnessed** | **GATE** | proven only at basis `creation_block_minus_one` | NULL, `not_determined` **or `explicit_seed`** ⇒ NULL + `not_determined` | cite |
| `cursor_last_indexed_block` | `.cursor_last_indexed_block` | 11 | **CONF** | upper bound only; the weaker of the two topics | missing cursor ⇒ NULL + `coverage: partial` | cite. **Never a lower-bound witness** |
| `cursor_enrollment_bases` | `.cursor_enrollment_bases` | 11 | **CONF** | recorded verbatim per topic | — | cite. Recorded, **not depended on** — see below |
| `cursor_page_completeness` | `.cursor_page_completeness` | **`not_determined` on all** | **GATE** | from U10A `page_completeness` | — | cite (the residual) |
| `coverage` | `.coverage` | 11 | **GATE** | `lower_bound` / `partial`. **Never `complete`** | cold cursor or NULL holders ⇒ `partial` | gate |
| `role_name` | `.role_name` | **10/11** (8 `keccak_preimage` + 2 `accesscontrol_default_admin_literal`) | **CONFIDENCE** | proven-present = a proven preimage / NULL = key absent, `not_determined` | keccak mismatch, or the zero-word arm without an answered `hasRole` ⇒ NULL | **cite only. Never gates, never keys anything** |
| `role_name_basis` | `.role_name_basis` | 11 | **GATE** | `keccak_preimage` / `accesscontrol_default_admin_literal` / `not_determined` | mismatch ⇒ `not_determined` | gate on `role_name` |
| `candidate_count`, `unconfirmed_candidate_count` | `.candidate_count` … | 11 | **CONF** | integers, or **NULL when `holders` is NULL** | — | cite (the floor's visible residual) |
| `fold_chain_disagreements` | `.fold_chain_disagreements` | 11 | **CONF** | array = the disagreements observed among the candidates whose reads COMPLETED / **NULL = `not_determined`** | withheld row ⇒ **NULL, never `[]`** | cite. Cause is `not_determined` |

**What `holders` proves, stated exactly:** *this address's own `hasRole`
predicate returned true at `as_of_block`.* That is a behavioural read of deployed
code, not a claim about the layout of `_roles` — and it is the right predicate
anyway, because `hasRole` is the same virtual function `_checkRole` dispatches
to, so an override that fools this read fools the gate identically. This is what
separates this ACCEPT from the `external_set` arm B4c excised: there the callee's
interface was the **calling** contract's declaration with nothing corroborating
it; here the canonical OZ topic0 emitted **by that address** and **that address's
own predicate** independently name the same `(role, account)` pair.

**What `role_name` proves:** that a preimage of `role_hash` is the string S — a
total, publicly verifiable mathematical fact. It does **not** prove this registry
declares a constant named S. That is why the candidate pool may be drawn from
anywhere (it is `role_definitions.role_name`, corpus-wide, uncoupled from the
contract) without weakening the result: the keccak check is the witness, the pool
is only a generator. It is also why the pool safely contains D6-reject's
mis-parsed ERC-7201 pointers, which persist until their contract is re-analysed —
their hashes match nothing.

**A role may GAIN a name later, and that is not instability in a proven field.**
The pool is whatever `role_definitions` currently holds, so analysing an
unrelated contract that declares a matching constant can move a row from
`role_name_basis: not_determined` to `keccak_preimage`. Nothing already
published changes: a name, once attached, is a proven preimage and stays true,
and the hash — the identity — never moves. The absence is honestly
`not_determined` throughout, never "this role is unnamed", which is exactly the
state that makes a later arrival an addition rather than a correction. A
consumer must therefore not cache `role_name`'s ABSENCE as a fact.

**Identity is the hash, and only one hash space is in play.** Rows are minted
from the OZ topic pair **literally**, not from
`role_store_standards.spec_by_topic0()`. That map also carries Solady's
`RoleSet(address,uint256,bool)` (`0xaddc47d7…`, `role_topic_index=2` where OZ
uses 1), measured at **125 logs and 40 distinct role words on `0x62247d29…`
(contract 507, protocol-1), which carries ONE `RoleSet` cursor** (the 5 warm
`RoleSet` cursors in the corpus are spread across 5 different addresses). Folding it here would have widened the
plane from 11 keys to 51 — and the failure is not a mere miscount: on that
registry `hasRole(bytes32,address)` **succeeds**, returning a genuine zero word
(while `hasAnyRole`/`rolesOf` revert), because a Solady `uint256` role cast into
the OZ `bytes32` mapping reads its **zero default**. Those 40 rows would each be
a fully-successful, zero-confirmation probe over roles that *do* have holders —
`[]` by another name across 78% of the plane, and a default standing in for a
witness. Solady logs therefore mint **no row**, and row-absence means
`not_determined`.

**`holder_set_exhaustive` is a deferral with cause, not an impossibility.** OZ's
`AccessControlEnumerable` getter would be a genuine on-chain exhaustive witness,
and `role_store_standards` already declares it — but measured at block 25643300,
`getRoleMemberCount(bytes32)` and `getRoleMember(bytes32,uint256)` **both revert
on 4/4** role registries and `supportsInterface(0x5a05180f)` is **false on 4/4**
(interface id derived, not trusted). Under B14 an arm with population 0 may not
be built — the same reasoning that excised B4c's `external_set` arm. The CHECK
constraint is therefore **deliberately stricter than plan §6**, which deferred
only "until D4(a)+(c) land": an enumerable registry, or the proven inverse index
`absence_coverage` lacks, would each license a real value here, and a future unit
must revisit the constraint rather than assume it was derived from something
weaker.

**What U10A's interface does and does not do here.** `earned_negative_admissible`
is consulted **only to refuse** (it is hard-wired False). `enrollment_basis`'s
exactness allow-list — `{None, 'predicate_tree_hint'}` — governs whether a cursor
may support an **exact empty**, and this plane never claims one; the basis is
therefore *recorded and cited*, not depended on, so a `tracked_topics_asserted`
cursor still supports a lower bound. Coldness (`backfill_complete` false or a
missing cursor on either topic) **does** withhold every floor for that registry:
the candidate set is then knowingly partial, and a floor published from it invites
a reader to treat its size as a count.

**The residual counters may not reconstruct the banned empty set.** "N probed,
every read completed, none confirmed" *is* `[]`, written in three columns. So
both counters are NULL exactly when `holders` is NULL, and — the subtler leak,
caught in test — the `accesscontrol_default_admin_literal` name arm is withheld
on a withheld row **even where the reads did complete**, because publishing it
beside a NULL holder set would signal that every call succeeded. The keccak arm
is unaffected: a preimage says nothing about whether any call was answered. A
row where every read returned false and a row where every read reverted are
**byte-identical**, on purpose.

**Disagreements are recorded and never attributed.** `as_of_block` sits above
`cursor_last_indexed_block` (25643300 vs 25641245 — a 2,055-block window), so
"the fold missed a log" and "the state changed after the cursor stopped" are
indistinguishable. The permitted keys are exactly
`{registry, role_hash, address, fold_state, chain_state}`; no key naming a cause
may be added. Should a future run close that window by pinning the two heights
equal, non-attribution must still survive on principle — a cursor is an upper
bound on what was **read**, never a proof of what was **emitted**.

**Replay.** `as_of_block` is pinned at `head − DEFAULT_CONFIRMATION_DEPTH` (12)
and its **block hash is persisted when readable** (a failed hash read keeps the
height and stores NULL — it is best-effort, not guaranteed), so a reorg is
detectable rather than merely trusted where the hash landed. This also closes plan §9's carry-forward that
`_resolve_probe_block` persists nothing. An unpinnable height withholds the probe
entirely; it is never retried against `"latest"`.

**Verified on-chain at block 25643300:** the full protocol-1 differential is
**20 probes / 20 agreeing / 0 disagreements / 0 reverts**, covering every
candidate in the appearance set including all 6 revoked addresses (lane-D
reported 12/12 over the active set only). The four corpus registries carrying
warm role cursors and **zero** role logs — `0x5585996e` and `0xd5edf773`
(both protocol-1), USDC `0xa0b86991`, `0xb8765ed7` — have `hasRole` **reverting
on all four**, and correctly yield **no rows at all**.

**Not wired, and the populations are MEASURED, NOT PERSISTED.** Nothing calls
`resolve_role_holder_planes` or `persist_role_holder_planes` outside the tests;
`RoleHolderPlane` has no producer in `workers/` or `services/` and the table is
empty in every environment. Every count in this entry — 11 keys / 3 registries,
10/11 named, 20/20 pinned agreement — was measured by running the resolver
in-process against the local replica and the pinned chain reads, **not** read
back out of the table. This is a **deferral with cause**: plan §1.1 forbids
running the orchestrator or a full pipeline, so a worker wiring could not be
validated end-to-end here, and shipping an unvalidated call site would put an
unexercised writer on a production path. The schema, the resolver and the
constraints are complete and exercised; only the invocation is outstanding, and
it must arrive with its own single-phase verification. **Until then no consumer
may treat an absent row as evidence of anything** — the table being empty is a
statement about wiring, not about roles.

**Flips:** none. This plane only adds rows; no existing published fact changes.
`services/chat/data.py::role_holders` is a *different* plane (function-authority
derived, per `capability_role_grants`) and is deliberately **not** rewired here —
repointing it would change a published fact without a panel scoped to that change.

**Small populations (B14 — none may calibrate a rule, weight or threshold):**
protocol-1 role-event emitters **3** (4 corpus-wide; 8 addresses carry role
cursors); the `OPERATING_ADMIN_ROLE` holder set **1** address; the
`TIMELOCK_ADMIN_ROLE` evidence **1** grant log; AccessControlEnumerable
registries **0**. No ratio, threshold or weight is derived anywhere in this unit.
`TIMELOCK_ADMIN_ROLE` carries **no** `role_definitions` row, so no preimage
candidate exists and its `role_name` is absent — B0b's anti-decoy credit stays
**CONFIDENCE**. That falls out of the pool rather than being special-cased, and
must not be "fixed" by adding the name to a hardcoded list.

### B19. Per-node restaking position — `restaking_positions` (D1 / Unit 10B)

Per **enumerated node instance**, at a recorded block. Not per `contracts` row,
and never on the beacon implementation. Every figure below is a read pinned at
block **25643300**, reproduced independently three times.

**The plane is separate from `contract_balances` on purpose, and structurally.**
The live EtherFiNode instances are BeaconProxy deployments with **no `contracts`
row** (measured: zero for the probed node and for its pod), while
`contract_balances.contract_id` is `NOT NULL`. Delivering this witness as balance
rows would have required minting a `contracts` row per node, after which
`services/effects/selection.py::_asset_holdings_by_deployment` would read the
share quantity as a **holding of a deployment** and `build_authority_graph` would
sum it — closing one gap by widening another. Every spot-balance reader joins
`contract_balances(_latest).contract_id` to `contracts.id`, so a restaking row is
invisible to all seven of them by construction rather than by filter.
`contract_balances`, `contract_balance_fetches` and `contract_balances_latest`
are **unchanged**; **no reader was modified**, and a test asserts that no module
outside this plane imports the model.

**There is no USD column anywhere on this plane**, so a share quantity cannot
enter a dollar figure even by accident.

#### What a published `0` means — and what it does not

`eigenlayer_beacon_shares_wei = 0` under basis `eigenlayer_beacon_shares` means
**zero EigenLayer beaconChainETH withdrawable shares** at `block_number`. It is
**not** "this node holds nothing". Measured over the 26 enumerated nodes at
25643300: every one has an EigenPod and reads **0 shares**, while those 26 pods
hold **374.148164612 ETH** between them — pod
`0x7474b357106e509918cd1db47c40a7d0d775d4c7` (node `0xf538ac2790…`) holding
**exactly 320 ETH**. Summing this column over the whole enumerated set yields
**0 wei** against that. Node and pod **execution-layer native balances are
`not_determined` on this plane**, and the consensus-layer residual is
`not_determined` and **unbounded above** (post-Pectra a validator may hold up to
2048 ETH). The column carries its scope in its name for exactly this reason, and
the meaning is stored as a `COMMENT ON COLUMN`, not only here.

#### Field register

| field | status | three-state | failure / revert / absence path |
|---|---|---|---|
| `block_number` | **REQ** | always present; every read of the row was ISSUED at it | head unresolvable ⇒ **no row is written at all**. There is no unpinned path on this plane |
| `block_hash` | **REQ** | the reorg witness (inv.11/12) | header unreadable ⇒ no row. Without it a replay "at block N" cannot tell it is on the same chain history |
| `eigenpod_basis` | **GATE** | `proven_pod_cross_read` — `getEigenPod()` and `ownerToPod()` both decode a full 66-char word, both non-zero and **equal**, AND `hasPod()` decodes to **exactly 1**; `no_eigenpod_proven` — **all three** legs decode a full word and are zero/zero/false; `not_determined` | `"0x"`, `success=false`, a return that is not 66 chars, a `hasPod` word that is neither 0 nor 1, or any disagreement, on **any** leg ⇒ `not_determined`. **Two of three legs never suffices**: `proven_pod_cross_read` is requirement (i) of the shares arm and every downstream gate keys off it |
| `eigenpod` | **CONF** | the cross-read address; NULL under either other basis | DB-enforced both ways (`ck_rp_no_pod_has_no_address`, `ck_rp_pod_cross_read_has_address`) |
| `eigenlayer_beacon_shares_wei` | **REQ** | integer (may be 0) under `eigenlayer_beacon_shares`; **0** under `no_eigenpod_proven` (a distinct proven-zero); NULL = not_determined | any transport/decode failure ⇒ `read_failed` + NULL; any unlicensed shape ⇒ `not_determined` + NULL. **Never 0** |
| `shares_basis` | **GATE** | `eigenlayer_beacon_shares` \| `no_eigenpod_proven` (both OBSERVING) \| `read_failed` \| `not_determined` (both NON-OBSERVING, NULL quantity) | `read_failed` = transport or decode failed; `not_determined` = transport succeeded but the evidence does not license a value. Reading the quantity without this column is **non-conformant** |
| `shares_strategy` | **GATE** | the strategy read from `EigenPodManager.beaconChainETHStrategy()` **at the same block**; NULL under every non-observing basis | strategy read fails ⇒ **no shares read is licensed at all** ⇒ `not_determined`. A literal is **BANNED**: the near-miss `0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` answers `[0]/[0]` with success, indistinguishable from the true `0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeebeac0` in any elided form |
| `deposit_shares_wei` | **CONF** | `EigenPodManager.podOwnerDepositShares`, **`int256`, may be negative**, stored signed and unclamped; NULL = not_determined | verified on EPM implementation `0xd22dd829779adbf3869fb224f703452f7f95e9db`. `stakerDepositShares` is the `uint256` one — do not confuse them. Unsigned decoding of a negative publishes ~1.15e77 |
| `cross_read_agreement` | **GATE** | `agree` — withdrawable == DM deposit == EPM deposit; `disagree_within_invariant` — withdrawable ≤ every present deposit leg (publishes **with the flag**: slashing and queued withdrawals produce this legitimately); `inconsistent` — withdrawable above a present deposit leg, or a negative deposit beside a positive withdrawable ⇒ **the quantity is SUPPRESSED**; `not_determined` | an **absent** deposit leg is `not_determined`, never `inconsistent`: absence is not disagreement, and conflating them would suppress a proven read |
| `active_validator_count`, `last_checkpoint_timestamp` | **CONF** | integers; NULL = not_determined | **NULL unless `eigenpod_basis = 'proven_pod_cross_read'`** (DB-enforced). Without that gate a `last_checkpoint_timestamp` of 0 — a real "never checkpointed" witness — could be minted against an address never proven to have a pod. A returned `0` under a proven pod **is** a witness and is stored as `0` |
| `consensus_layer_residual` | **BAN-as-number** | **always present, always the string `not_determined`** | unreachable by any other value, DB-enforced. Consuming it as `0`, or omitting the key, is non-conformant |
| `node_set_completeness` | **GATE** | **`not_determined` only**, DB-enforced | the fold proves a node EXISTS and can never prove one does not. Any cross-node aggregate is a **floor** (`>= X wei`), never a total, and no earned negative is licensed |
| `manager_contract_id` | **CONF** | the `contracts` row whose **ADDRESS EQUALS** the emitting `event_address` — the proxy (`0x8b71140a…`, `contracts.id 531`), **not** the implementation row that carries the manager's name (`0xcf5928ea…`, id 591) | pinning to the implementation would repeat the implementation-vs-proxy keying defect B8.1a documents. Provenance only: never "this contract holds the position" |

#### The four-way partition, and the two arms that are deliberate under-claims

A **zero** is admitted only under full three-way agreement, because zero is
exactly what a wrong input manufactures. Two consequences are intended, and are
recorded so a later reader does not "fix" them:

1. **Zero with a failed EPM deposit leg** ⇒ requirement (iii) is unevaluable ⇒
   `not_determined`. A `0` cannot be published.
2. **Withdrawable 0 against a positive deposit leg** (the fully-slashed shape)
   fails the equality and publishes nothing.

A **nonzero** with a failed EPM leg is the opposite call: it publishes as a
single-source quantity with `deposit_shares_wei` NULL and
`cross_read_agreement = not_determined`. `inconsistent` does **not** fire there.

`disagree_within_invariant` paired with a `0` is **unreachable by construction**
(a zero requires `agree`), and a test pins that.

**What requirement (iii) does NOT do.** It is defence-in-depth, not the guard
against the wrong-strategy or non-staker shapes: measured, a wrong strategy on
any of the 26 returns 0/0/0 and a non-staker (`0x…deadbeef`) returns DM `[0,0]`
with EPM `0` — equality **holds** in both. What actually rejects them is **(i)**,
the identity cross-read (a non-staker is codeless, so `getEigenPod()` returns
`"0x"` and fails the 66-char rule) together with the **witnessed strategy**.

#### `restaking_positions_latest` — the read surface

Per **`(chain_id, node_address)`** — the chain is in the key because the same
address on two chains is two entities (#158) — the most recent **OBSERVING** row
wins, ordered `block_number DESC, id DESC` so the order is **total**. Both
non-observing bases are excluded from winning: letting `read_failed` **or**
`not_determined` win would withdraw a proven position on the strength of a
non-observation.

**Absence from this view is `not_determined`, never "no position".** With both
failure classes excluded, a node whose every row is non-observing does not appear
at all — so a consumer that read a missing row as `0` would reintroduce, at the
projection layer, the absent-row-as-`$0` shape B8.1a exists to close.

Retention (`PSAT_RESTAKING_HISTORY_DEPTH`, default 10, **rejects < 1**) bounds
insert-only growth and **never prunes the latest observing read**.

#### Constraints are a backstop, not control flow

`services/monitoring/restaking_reads.py` decides the basis first and maps every
violating shape to NULL / `not_determined` **before** a row is constructed; a
CHECK firing in production would be a producer bug. Two Postgres traps are
handled deliberately: a CHECK evaluating to NULL **passes**, so every arm is
written NULL-safe; and one level up, the OR-joined arms are fail-closed **only
because `shares_basis`, `eigenpod_basis` and `cross_read_agreement` are NOT
NULL** — a NULL basis would make every arm NULL, and an OR of NULLs is NULL.
`ck_rp_basis_matches_value` is **one arm per basis**, each pinning the basis AND
the value together, so an unrecognised basis satisfies no arm.

#### Enumeration

A cold event fold with its own cursor:
`(chain_id, 0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f, PubkeyLinked(bytes32,address,uint256,bytes))`,
topic0 `0x5e525a525cf73653f769c8305dc71a68b85b0e62e3cc5258fe187ff9fd3e5cb9`,
node in `topics[2]`. Measured: 33 logs / **26 distinct nodes** in the 200,000
blocks before 25643300. `EigenPodManager.PodDeployed` is not usable — it is
EigenLayer-wide (`numPods()` = 34,704) and scoped to no protocol; BeaconProxy
creation emits nothing. The emitter is identified by a **log witness** (one
`eth_getLogs` carrying the protocol's whole address set and the topic filter),
never by `contract_name` and never by an ABI declaration. Enrollment is
**code-asserted**, so the cursor carries the `tracked_topics_asserted` coverage
ceiling: enrolled, never complete, licensing no absence claim.

**Stated deferral (measured).** `0x8b71140a…` already carries two warm cursors at
block 25641245 with `backfill_complete = true`, on
`UserAllowedForwardedEigenpodCallsUpdated` (`0x1bb6cfc6…`) and
`UserAllowedForwardedExternalCallsUpdated` (`0x2a1547b8…`) — the forwarded-call
allowlist topics for `effective_functions.id` 1184 and 2038.
`index_event_group_step` takes `start = min(last_indexed_block)` over the group's
**active** cursors, so a cold cursor seeded at 17174452 (proxy creation 17174453)
drags the shared window back over **8,468,848 blocks = 17 windows** at a
500,000-block span — roughly **one pass** at the 50-window per-cursor budget. The
siblings do **not** regress (the advance is guarded by `window_end > last`) and
`backfill_complete` is cleared only by a reorg rewind; the cost is that those two
stop **advancing** for that period while still reporting themselves complete —
the stale-warm shape. Accepted as a bounded, measured deferral rather than
papered over with a later seed no read witnesses. A test asserts the
no-regression and no-reset properties.

#### Consumption obligation, and the one banned consumption

**Cite and three-state only.** No arithmetic into any USD total, any
`value_at_stake`, or any reach floor. A cross-node aggregate is a floor carrying
its direction (`>= X wei`), its `shares_basis` and `node_set_completeness`.

`effective_functions.id` **1184** (`EtherFiNode.forwardExternalCall`,
`contracts.id 569` — **the beacon implementation**, whose own `getEigenPod()`
returns a 32-byte zero) and **2038** (`EtherFiNodesManager.forwardExternalCall`)
**stay `reach = not_determined`**. This unit writes nothing to
`effective_functions`, `recipes.py`, or any reach projection.

Licensing that consumption needs a **destination witness** that
`forwardExternalCall` reaches the EigenLayer withdrawal path. **Neither row has
one, but they do not have the same state, and the difference matters enough to
state exactly.** Measured on the replica:

* ef **1184** — `witness.destination_constraint` is `{"state": "not_determined"}`;
* ef **2038** — `{"state": "constrained", "guard": "external_call_revert",
  "binding": "operand", "leaf_path": [1], "pins": null}`.

`constrained` on 2038 is **not** a destination witness. The guard is
`external_call_revert`: it witnesses that the function propagates a failure of
the call it makes, which constrains what happens *if* the call reverts. It says
nothing about **where** the call goes — `pins` is `null`, so no destination is
pinned at all, and a revert-propagation guard is compatible with every possible
callee. The conclusion is therefore unchanged for both rows, and this paragraph
previously asserted `not_determined` for both, which was false for 2038.

Attaching the position to either row is **inv.16a's sweepETH error — the
5,188× over-valuation — recurring in a new place**.

#### Deferral: the plane has no production writer yet

**Stated with its cause.** Nothing in this repository calls `read_positions`,
`persist_positions` or `enroll_restaking_fold` on a schedule; every public symbol
of both new modules has exactly two references, its definition and its
`__all__`. No `PubkeyLinked` cursor exists on the replica, and **no row of this
plane is published anywhere today**.

That is deliberate, not an oversight. Wiring a periodic writer is the one part of
this unit that cannot be verified under the constraint that forbids running the
orchestrator or a full pipeline end-to-end, so shipping it would have meant
shipping the only unexercised code in the unit. The strictly-smaller provable
core is the witness and its schema, both of which ARE exercised. The
consequence to state plainly: the "3 reads/node/cycle steady-state" and "its own
cursor" in the unit's spec describe a cycle that **does not yet run**, and the
structural exclusion from every spot-balance reader is currently absolute for the
trivial reason that the plane is empty. The remaining work is the periodic step
and its enrollment call, nothing in the witness itself.

**Small populations (B14).** 1 `EtherFiNode` `contracts` row (569); 2
`forwardExternalCall` consumer rows (1184, 2038); the lane's original single
probed node. **Nothing here calibrates any rule, weight or threshold** — every
field is cite / gate / three-state. (The node population itself is ≥26, but that
changes nothing: no rule is calibrated on it either.)

### B20. Flow asset identity and destination identity — the two names a name could not give (D2 + D3 / Unit 6)

Two sibling gaps, one instrument: a published string carried an *identifier* where
the consumer needed an *identity*. `witness.sink_ids` named the receiver of every
ERC-20 move (**217** entries across ALL protocol-1 claims — the `flow.out`
subset FIELDS §3 counts is **107** of those; **0 of either are an address**)
and a `storage_setter`
destination named nothing at all. Both facts were derived by the static stage and
discarded one line later. Neither is recovered by resolving the name — that is
inv.2 — and neither publishes an address on this plane.

#### B20.1 Receiver identity — `claims[].witness.sink_receivers{}` / `sinks[].receiver`

Keyed **by sink id**, not listed per flow: one flow key (kind, selector,
direction, `from_is_self`, origin) can cover two sinks moving two different
assets, and a bare list leaves the consumer unable to say which receiver carried
which move. The map's keys are always a subset of the same witness's `sink_ids`,
so the join never dangles. Emitted for the high-level/library call arm only —
the one that resolves its head past casts; a low-level `.call` sink and every
non-call sink leave the key **absent**, which means *never computed* and fails
every precondition below exactly as `not_determined` does.

| field | status | three-state | failure / revert / absence path |
|---|---|---|---|
| `binding` | **GATE** | `parameter` \| `state_variable` \| `local` \| `not_determined` | **`not_determined` is reached by four distinct paths**, all of them fail-closed: the cast walk never resolved the head (temporary / mapping or array element / tuple); the head is a kind this plane does not describe (`SolidityVariable`, a literal `Constant`); Slither raised while reading the declaration; or two contributing sites **disagreed**. `not_determined_reason` separates them. Decided by `isinstance`, **never by `visibility`** — a `LocalVariable` answers `visibility="internal"`, `is_immutable=False`, `is_constant=False` identically to an internal state variable, so visibility would publish a caller's argument as this contract's storage |
| `param_scope` | **GATE** | `entry_point` \| `internal_helper`; NULL unless `binding=parameter` | the sink walk is transitive. A formal of an internal helper is a real parameter of the unit walked but **occupies no ABI slot of the entry point**, and whether the entry's own argument reaches it is a dataflow question this walk does not ask. Measured live on 3 of the 18 rows (`AssetRecovery._recoverERC20/_recoverERC721` behind `WeETH.recoverERC20/recoverERC721`, `EETH.recoverERC721`) |
| `param_index` | **CONF (cite)** | the entry's ABI slot; NULL otherwise | emitted **only** under `param_scope=entry_point`. A guessed slot addresses the wrong argument |
| `binding=state_variable` requires the declaration to be **OWNED** | **GATE** | the arm is taken only when `resolved.contract` is the analysed contract or one of its bases; otherwise `not_determined` + `foreign_declaration` | the sink walk recurses into library calls, so a library's own `public constant` arrives as a valid `StateVariable`. It is **inlined at every call site**, it is not this unit's storage, and its accessor is **not in this contract's ABI** — a pinned read at the deployment address would revert or hit a fallback. It also defeats the fold **silently**: the same identifier declared on both the contract and a library, holding two different addresses, yields BYTE-IDENTICAL descriptors (same name ⇒ same visibility, mutability and minted selector), so two distinct assets read as one agreed receiver |
| `mutability` | **CONF** | `constant` \| `immutable_in_implementation` \| `mutable`; NULL unless `binding=state_variable` | a **DECLARATION CLASS**, explicitly NOT "a writer exists" — that is B20.2's question, answered on its own evidence. `immutable_in_implementation` is spelled the long way because an `immutable` is inlined into the IMPLEMENTATION's bytecode: behind a proxy it is **not** an invariant of the address a consumer prices against, and 7 of the 10 state-variable rows are proxied |
| `visibility` | **CONF** | Slither's declared visibility; NULL unless `binding=state_variable` | descriptive only. It may not decide anything — see `binding` |
| `auto_getter_selector` | **GATE** | keccak4 of the accessor solc mints; NULL otherwise | emitted only when `binding=state_variable` **AND** `visibility="public"` **AND** the getter takes **no arguments**, decided from the **declared type** (`solidity_signature`, solc's own `export_nested_types_from_variable` rule) and never from the identifier. `uint256[] public amounts` is read by `amounts(uint256)`=`0x45f0a44f` while `amounts()` hashes to `0x6beaeeae`; `mapping(address=>uint256) public balances` is `balances(address)`=`0x27e235e3` against `balances()`'s `0x7bb98a68`. **A library call's receiver is its first argument and may be any type**, so this arm is reachable, and four bytes collide. A parameterised getter cannot be read without choosing a key, and choosing one is not a witness — so it yields NULL |
| `variable` | **CONF (display / identity only)** | the AST identifier | **BANNED as a resolution basis.** `variable + "()"` is precisely the inv.2 shape this descriptor replaces; the selector above is licensed by the type, and by nothing else |
| `receiver_provenance` | **GATE** | `caller_named` \| `contract_state_unresolved` \| `not_determined` | `caller_named` requires `binding=parameter AND param_scope=entry_point`. **Named for the RECEIVER, not the asset, because the receiver often is not one**: a library-math call binds a `uint256` quantity as its receiver, and **7 of the 20** caller-named corpus rows are that shape. Under the old name, `redeem(address to, IERC20 withdrawAsset, uint256 shareAmount)` published `asset_identity: caller_named` beside `param_index: 2` — coherent-looking and false, since the asset is slot 1. The register is normative (inv.16), so the token IS the published fact; the fix is the token, not a type filter (a filter would add an inference and discard real provenance). `contract_state_unresolved` is structural — this plane resolves **no address**, so the token carries its own incompleteness rather than sitting beside a selector that looks like a resolution |
| `not_determined_reason` | **CONF (diagnostic, no consumption obligation)** | `unresolved_head` \| `unsupported_variable_kind` \| `foreign_declaration` \| `fold_disagreement`; key absent otherwise | so that "the sites conflicted" and "the head never resolved" stop being the same published value, and a future editor cannot resolve the ambiguity by guessing |

**Consumption obligation — FIELDS §3's `token_identity` precondition becomes
decidable rather than assumed.** It is satisfied ONLY by
`receiver_provenance = contract_state_unresolved` **plus** a resolved address **plus**
an `asset_identity_invariant` that is not `not_determined` — none of which this
plane publishes. It **FAILS** for `caller_named` (there is no single asset to
price against), for `not_determined`, and for an absent `receiver` key. The 4
entry-parameter rows therefore lose any pricing resting on a single-asset
assumption. That is a demotion, in the honest direction.

**No address, and no `asset_identity_invariant`, is published here.** Resolving
`auto_getter_selector` by a pinned `eth_call` needs a resolution-plane writer
that also knows whether `deployment_address` is a proxy; until that exists, an
address would have to be published without the bound that makes it readable.

#### B20.2 Destination identity — `claims[].witness.flows[].target_*`

| field | status | three-state | failure / revert / absence path |
|---|---|---|---|
| `target_variable` | **CONF (cite)** | the AST identifier of the state variable the destination reads | published only when `target_kind.kind` NAMES a state variable (`constant`, `immutable`, `storage_setter`, `storage_no_setter`) **and** every contributing site named the same DECLARATION — compared on the canonical `Contract.var`, **never on the bare identifier**. Two contracts in one call graph may each declare `recipient` with separate setters and separate values; agreeing on the string would publish the scalar over two destinations and skip the member list a consumer is told to take the worst of. A mapping/array **element** never emits one: it classifies by its base's mutability, but the base is one address where there is one per key |
| `target_variables` | **CONF** | the distinct declarations when the sites named more than one, **canonical** (`Contract.var`) because bare names cannot tell them apart — which is exactly why the list exists | two setter-backed variables both fold to `storage_setter`, so agreement on the KIND is not agreement on the destination. Present **exactly** where the scalar is absent for that reason, so no member can be read as the whole |
| `target_writer_signatures` | **CONF (cite) — a FLOOR** | the signatures WITHIN the analysed compilation unit that write `target_variable` | the derived claim is "redirectable **at least by** these writers' principals" — **never** the closed set. `[]` is emitted **only** under `storage_no_setter`, where the kind itself is the completed-scan negative; the key is **ABSENT** when no callable writer was attributed (a storage-pointer-aliased origin, or a variable written only by Slither's synthetic declaration-site initialiser). Absent and `[]` are different and must not be conflated |
| `target_writer_scan_complete` | **GATE** | mirrors the existing setter-scan soundness flag | published in the SAME dict and at the same time as the payload it qualifies, never separately. `false` means an assembly `sstore`, a `delegatecall`, or an unresolved alias made the write attribution non-exhaustive — the listed writers are *some* of them |
| `target_writer_absent_reason` | **CONF (diagnostic, no consumption obligation)** | `declaration_initialiser_only` \| `alias_unattributed`; emitted only under `storage_setter` with no named writer | the two absences carry **opposite** risk and must not both read as a bare missing key: an initialiser-only destination is effectively fixed short of an upgrade, while an unattributed storage-pointer alias is a real writer this pass could not name and may be reachable by anyone. A `constant`/`immutable` is not in the setter map at all and emits nothing here — its kind already answers the question |
| `writer_surface_closed` | **GATE** | **the string `not_determined`, and no other value** | type-enforced (`Literal["not_determined"]` on the producing TypedDict, rejected by the type checker CI runs) rather than DB-enforced, because this unit has no migration to hang a CHECK on. **It cannot become dynamic here**: this stage analyses ONE compilation unit while the deployed address may be a proxy (upgrade-extensible write surface) or one of several implementations (a sibling's writers are outside the unit). Both D3 rows are exactly that — ef 423's `deployment_address` `0x8f08b704…` ≠ `contracts.address` `0xd2b8c78a…` (a secondary implementation of `contracts.id` 461), ef 2748's `0x89e45081…` ≠ `0x6bf6acd4…`. A dynamic value needs a resolution-plane writer that can prove neither holds |

**Slither's synthetic `slitherConstructorVariables` /
`slitherConstructorConstantVariables` keep contributing setter MEMBERSHIP and are
never published as writers.** Dropping them from membership would turn a variable
with a declaration-site initialiser and no setter into a proven "fixed
destination" it was never proven to be — a newly minted earned negative.
Publishing one as a writer would name a function nobody can invoke as the
principal that can redirect the destination. Membership is therefore
**byte-identical** to before this unit; only the value list is new.

**Small populations (B14).** D2: the entry-parameter bucket is **4 rows** (423,
2194, 2328, 2578) — below the ~5 bar once the 3 helper-formal rows are correctly
excluded; `local` is **1** (2310, no provable arm, publishes `not_determined`);
`fold_disagreement` is **0** on the 18 (measured). Populations are per SINK once
the descriptor rides every high-level call, and the `constant` class is **not**
empty at that granularity — a `bytes32`/`private` constant receiver was measured
on a real transitive walk. D3: **2 rows**. Everything here is gate / cite /
three-state; **nothing calibrates a rule, weight or threshold.**
