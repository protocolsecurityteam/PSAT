# Scorer discipline contract — non-negotiables for every scorer-build agent

Distilled from `SCORER_INTEGRATION_STRATEGY.md` (the authoritative build spec),
`SCORING_INVARIANTS.md`, and `scoring_prototype/FIELDS.md`. If this page conflicts
with those docs, the docs win — **surface the conflict, never improvise around it**.
The §-references below are into `SCORER_INTEGRATION_STRATEGY.md`.

## 1. Three-state discipline (the prime directive)
Every field is one of **proven-present / proven-absent / `not_determined`** — three
distinct states, preserved end-to-end. `not_determined` is NEVER read as a positive,
NEVER collapsed into a default, NEVER "absence means open" or "absence means zero."
Every `not_determined` / absent branch **fails closed to not-scored**. A name, a row's
existence, a default, or a silent fallback never stands in for a witness.

## 2. The banned defect class (§6, §8)
**Severity must never be escalated by the ABSENCE of a constraint witness.** Severity
is either (a) built up from proven components starting at 0 (the `pause.set` pattern),
or (b) a capability-class constant reflecting what the claim's *proven existence*
licenses, refined **only downward** by mitigating witnesses (the
`upgrade.implementation` pattern). The canonical anti-pattern: the prototype's `else`
that graded a `not_determined` delegatecall/exec `destination_constraint` as
`destination_unconstrained` severity 1.0 — a −30λ, F→C **false positive**
(`scorer_v3.py:1700`). An `indeterminate`/`unresolved_operand`/`not_determined`
destination fails to `not_determined` and does not enter the grade. `flow.out`
(`scorer_v3.py:1495-1676`) is the model to copy: unproven caller ⇒ row withheld;
unproven destination ⇒ warning + `continue`.

## 3. Value axis
Value is **MAX per (entity, asset), never SUM** — two functions reaching the same
vault charge it once. Entity keys are **chain-scoped `(chain, address)`** (#158
twin-aliasing must not re-enter). Absent native balance: `native_status` decides
proven-zero vs `not_determined`; fetch-failed is not counted and never read as zero.
Unpriceable value (no `flow_asset_addresses` identity) falls to the unpriced branch —
a confidence hit, not a zero.

## 4. Principal units
Per-`(chain, address)` — **no cross-chain collapse** (§7.4): a Safe at the same
address on two chains is two units; merging without an owner-set proof asserts an
unproven identity. k/n is an **upper bound** on protection (`safe_protection` can
withhold the demotion, never raise). `role_holder_planes.holders` is a **lower
bound**; `len(holders)` is never a count; it may raise breadth concern, never lower it.

## 5. Signals reference, they do not resolve (§0, §1)
Distilled signal rows carry **references** (principal ids, entity keys), never
resolved copies — the fold does all cross-contract resolution (units, MAX-per-entity,
subsumption) because only it sees the whole protocol. A distilled `not_determined`
stays `not_determined` — never a distilled default.

## 6. Planes move numbers only per the §7.1 table
The plane-by-plane table in §7.1 is a **ruling**, not a suggestion: term touched,
action (cap/floor/annotate/exclude), and the fail-closed branch, per plane. Notables:
`consensus_layer_residual` never enters arithmetic; `upgrade_transactions` is
provenance-only in v1 and counts go through `upgrade_action_counts` /
`governance_actions_for` (never `COUNT(upgrade_events.id)`; post-exclusion zero is
`None`, never `0`); `gated_contract_backlink` is reach-gate only (never types M; a
mismatch is not an earned negative); a `consumed` latch is re-openable via the proxy's
upgrade authority, never a permanent credit.

## 7. Served gates are called, never re-derived
`exact_empty_credit` comes from `services/policy/capability_surface.py:137` via the
serve path — re-deriving it in the scorer is banned (B16.3).

## 8. Constants are provisional (§7.2)
All model constants live in **one named parameter block**, emitted in every score
document; `model_version = "1.0.0-provisional"`; any constant change bumps the
version. The B14 population-zero arms (W3 `reach_indeterminate` floor, B20.2
`target_variable`, the `constant`/`storage_no_setter` target kinds) are flagged
*uncalibrated* in the document itself.

## 9. Determinism and replay (inv. 11/12)
The fold is pure, read-only, deterministic: stable `ORDER BY` on every query, no
wall-clock/randomness in scoring logic, same DB state ⇒ byte-identical document
(modulo `computed_at`). Every score row carries the provenance block.

## 10. Process rules
- Verify your worktree's base first: `SCORER_INTEGRATION_STRATEGY.md`,
  `SCORING_INVARIANTS.md`, `SCORER_DISCIPLINE_CONTRACT.md`, and
  `scoring_prototype/FIELDS.md` must exist at your repo root. If any is missing you
  are on a stale base — STOP and report.
- `scoring_prototype/scorer_v3.py` is a **read-only diagnostic oracle**. Never edit
  it, never port it line-by-line; `services/scoring/` is a fresh implementation.
- Commit on your worktree branch with clear messages; no AI attribution trailers.
  Never push.
- On any contradiction between spec docs: stop that thread and report it in your
  final summary instead of picking a side silently.
