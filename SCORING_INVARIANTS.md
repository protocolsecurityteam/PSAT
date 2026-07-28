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

---

## Appendix A — what the local data says (etherfi, 2026-07-19)

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
