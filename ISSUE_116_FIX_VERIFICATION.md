# Post-merge verification spec — #116 event `topic0` ABI canonicalization

**Purpose.** A living acceptance-criteria doc for the fix that corrects the
event `topic0` derivation in the static pipeline (issue #116). An event's
`topic0` must be `keccak(canonical-ABI-signature)`, where every non-elementary
parameter collapses to its ABI head (contract/interface -> `address`, enum ->
`uint8`, user-defined value type -> its underlying elementary type, array
`T[]` -> `canonical(T)[]`, struct -> the parenthesized member tuple). The two
`topic0` producers instead keccak'd Slither's *declared* type names (`IGem`,
`Vat.Status`, `IGem[]`, `PoolId`), so the topic0 matched **zero** on-chain logs.
Downstream that meant the privileged-mapping allowlist enumerated **EMPTY** with
`status=complete` and the runtime watch plan subscribed to a **dead** topic0 —
i.e. the tool **UNDER-reported** who holds a privilege (the worst failure class
for a security tool). This doc says what to observe on the **next live run** to
confirm the corrected topic0 reaches the chain and enumerates real members.

> **Status:** committed `60b9d8a` (`fix(static): canonicalize event topic0 ABI
> signature for interface/enum/array/struct/UDVT args (#116)`) on branch
> `wt/issue-116`, **not pushed**. Fill in PR # / preview URL when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state**. After the PR deploys to a preview env and
   a fresh analysis run executes, confirm each check below and mark it
   **PASS / FAIL**, reporting any FAIL with the actual observed value.
2. **This is NOT aggregation-only.** Unlike the Surface controls fix, #116
   changes an artifact computed at **static-analysis time** (the event `topic0`
   baked into the predicate artifacts + the control tracking plan). The
   corrected topic0 therefore appears **only after the affected contracts are
   re-analyzed** (re-compiled and re-planned). Serving old data will not show
   the change — schedule a re-run of the static + resolution stages for the
   target protocol.
3. **The deterministic pin is the co-land test, not a corpus count.** The
   canonicalizer's correctness is proven address-independently by
   `tests/test_event_topic0_canonicalization.py`, which compiles the five
   production event shapes with **real Slither** and asserts
   `topic0 == keccak(canonical) == the REAL on-chain topic0` (Seaport
   `OrderFulfilled`, Uniswap-v4 `Initialize`, ERC-1155 `TransferBatch`,
   Maker-style `Rely`). Green there = the fix is correct regardless of which
   contracts the live corpus happens to contain.
4. **Corpus impact is protocol-dependent — measure it, don't assume it.** Only
   contracts that emit an event with a **non-elementary** parameter feeding a
   privileged mapping or a controller-write watch are affected. Elementary-only
   events (OZ `RoleGranted`/`RoleRevoked` = `(bytes32,address,address)`,
   `OwnershipTransferred` = `(address,address)`, ERC-20/1155 transfers) are
   **byte-identical** before/after and see **no change**. Use the Appendix A
   audit script against the live corpus to enumerate exactly which events
   diverge; do not fail solely because a given protocol has zero affected
   events (that just means it had no non-elementary event params).

### Where the topic0 flows (the two producers → DB → resolution)

- **Producer 1 — mapping-membership allowlist.**
  `mapping_events.discover_mapping_writer_events` -> `WriterEventSpec.event_signature`
  -> `predicate_artifacts.py:565` `topic0 = keccak(event_signature)` (stored in
  the contract's predicate-artifact event hints) -> at resolution,
  `services/resolution/mapping_enumerator.py:347/660`
  `enumerate_mapping_allowlist` derives the same topic0 and calls
  `getLogs(contract_address, topic0)`. Wrong topic0 -> `principals=[]`,
  `status="complete"` (see the `EnumerationResult` docstring: "silent [] would
  drop authorized addresses").
- **Producer 2 — runtime event watch plan.**
  `tracking._event_reference` -> `AssociatedEvent{signature, topic0}` (topic0 =
  `keccak(signature)`, `tracking.py:225`) -> `associated_events` ->
  `resolution/tracking_plan.build_control_tracking_plan` -> `EventWatch.events`
  -> the `event_log_indexer` scans by `(chain_id, event_address, topic0)`,
  writing observed logs to `indexed_event_logs` and cursors to
  `indexed_event_cursors` (`db/models.py`). Wrong topic0 -> the watcher
  subscribes to a topic that never fires -> controller writes never observed.

### Environment / how to query

- **Static, deterministic (primary):** run the co-land test in the worktree venv
  (see the repo `CLAUDE.md` for env). It needs solc **>= 0.8.20** available to
  solc-select (the SOURCE pragma is `^0.8.19`, but the shared corpus tests pin
  newer). Example: `SOLC_VERSION=0.8.27 ... pytest -m "not live"
  tests/test_event_topic0_canonicalization.py -q`.
- **Corpus impact (which live contracts changed):** Appendix A `event_topic0_audit.py`
  — compiles a contract (source path or Etherscan address) and prints, per event,
  the declared-name topic0 (old/buggy) vs the canonical topic0 (new) and whether
  they diverge. Run it against the live-run corpus to get the true affected set.
- **On-chain confirmation (topic0 is real):** `eth_getLogs` with **only** the
  canonical `topic0` over a recent block range returns **> 0** logs; the same
  query with the declared-name topic0 returns **0**. (No address needed — a
  topic0 uniquely identifies the event across all emitters.)
- **DB, post-run:** `indexed_event_cursors` / `indexed_event_logs` gain rows
  keyed by the **canonical** topic0 for affected watched contracts.

### Global regression guards (apply to the whole change)

- CI green: `ruff check` / `ruff format --check` / `pyright` / offline `pytest`
  (`-m "not live"`, **never** `-k "not live"`) / frontend / diff-cover >= 70%.
- The already-landed **function-selector** canonicalization
  (`project_selector_canonicalization_fix`) is untouched and still green.
- **Elementary-only events are byte-identical** — no watched topic0 that was
  previously correct may change (that would be a *regression*, not this fix).
- No already-enumerated allowlist member is **lost**; the only movement is
  `EMPTY -> real members` for non-elementary-param events.

---

## Change 1 — recursive canonical ABI type at both `topic0` producers

- **Commit:** `60b9d8a` `fix(static): canonicalize event topic0 ABI signature for
  interface/enum/array/struct/UDVT args (#116)`
- **Branch / PR:** `wt/issue-116` -> PR **#____**
- **Files:**
  - `services/static/contract_analysis_pipeline/mapping_events.py` — `_abi_type`
    (recursive canonicalizer) + `_event_metadata` (build signature from
    `arg_types`; fall back to `full_name` only when the event has no params).
  - `services/static/contract_analysis_pipeline/tracking.py` — `_abi_type`
    (same recursive canonicalizer; fixed-array length now `length_value`, the
    folded literal, not `length`, an `Expression`).
  - `tests/test_event_topic0_canonicalization.py` — co-land regression (new).
- **What it does:** replaces both `_abi_type` copies with one recursive rule that
  uses `isinstance` against Slither base classes
  (`Contract`/`Enum`/`Structure`/`ArrayType`/`TypeAlias`/`UserDefinedType`)
  instead of `type(x).__name__` string equality. The string check was exactly
  what missed the concrete subclasses `EnumContract`/`EnumTopLevel`/
  `TypeAliasContract`, and it had no array/struct/UDVT recursion. Now:
  contract/interface -> `address`, enum -> `uint8`, UDVT -> its underlying
  elementary type, `T[]` -> `canonical(T)[]`, `T[N]` -> `canonical(T)[N]` (via
  `length_value`), struct -> `(canonical members...)`, recursing so nested shapes
  (`IGem[][2]`, struct-of-interface, array-of-struct) canonicalize fully.

### Expected data — real/faithful anchors (before -> after)

Ground-truth before/after, validated on **real on-chain logs** in the settlement
proof (the topic0 constants are pinned in the co-land test):

| Event (real contract) | Param shape | Declared-name topic0 (OLD, buggy) | Canonical topic0 (NEW) | On-chain logs OLD -> NEW |
|---|---|---|---|---|
| Seaport `OrderFulfilled` | enum + struct + `address payable` + dynamic arrays | `0x8c8d6c55…` | `0x9d9af8e38d66c62e…cdcb6f31` | **0 -> 5** |
| Uniswap-v4 `Initialize` | `PoolId`/`Currency` UDVTs + `IHooks` interface | `0x7c67cd8e…` | `0xdd466e674ea557f5…838d6438` | **0 -> 5** |
| Maker-style `Rely(IGem)` | interface scalar | `keccak("Rely(IGem)")` (dead) | `0xdd0e34038ac38b2a…8b385a60` (`Rely(address)`) | dead -> canonical |
| ERC-1155 `TransferBatch` | elementary-only (`address×3,uint256[]×2`) | `0x4a39dc06…` | `0x4a39dc06…` (**identical**) | 3 -> 3 (no-op) |

`TransferBatch` is the **no-op control**: its canonical signature already equals
`Event.full_name`, so its topic0 is unchanged — proof that elementary-only events
do not move.

> Corpus counts (how many privileged mappings / watched controllers flip from
> empty to populated) are **protocol-specific**; derive them per run with the
> Appendix A audit script. The anchors above are the invariant before/after.

### Detailed invariants (verify each)

**A. The canonicalizer is exact for every non-elementary shape.** For each of
Seaport `OrderFulfilled`, Uniswap-v4 `Initialize`, Maker `Rely`, and the
fixed/nested-array anchor, **both** producers emit the canonical signature and
`keccak(signature)` equals the pinned real on-chain topic0. (This is exactly the
co-land test's assertion set.)

**B. Both producers agree.** For every event,
`mapping_events._event_metadata(ev)["signature"] ==` the signature underlying
`tracking._event_reference(ev)["topic0"]`. The two paths (allowlist enumeration
vs runtime watch) can never subscribe to different topics for the same event.

**C. Elementary-only events are byte-identical.** For any event whose params are
all elementary, `canonical == Event.full_name` and topic0 is unchanged. No
previously-correct watched topic0 moves.

**D. Direction is strictly fail-closed (toward correct), never toward public.**
The only movement is a topic0 that matched **nothing** now matching the **real**
event. For a **whitelist**-gated mapping this turns an empty allowlist into the
**real set of authorized callers** (adds previously-missed privilege holders —
the under-report the issue is about). For a **denylist**-gated mapping it turns
an empty (=> everyone, falsely public) list into **everyone-minus-real-members**
(more restrictive). In neither direction does a guarded capability newly become
public, and no previously-enumerated member is dropped.

**E. Uniqueness — no cross-event contamination.** A canonical topic0 =
`keccak(name + canonical params)` uniquely identifies the event; enumeration is
additionally scoped by `(contract_address, topic0)`. The corrected topic0 cannot
match an unrelated event (the only collision risk is a keccak collision, i.e.
negligible and identical to any correct implementation).

**F. Fixed-array length fix (tracking.py only).** `IGem[2]` -> `address[2]` and
`IGem[][2]` -> `address[][2]`, i.e. the length comes from `length_value` (the
folded literal), not `length` (a Slither `Expression` whose `str()` would
poison the signature).

### How to verify

1. **Static (deterministic, no chain).** Run
   `tests/test_event_topic0_canonicalization.py` under solc >= 0.8.20. Expect all
   parametrized cases green: `test_mapping_events_topic0_is_canonical`,
   `test_tracking_topic0_is_canonical`, the revert-proof
   `test_declared_name_signatures_would_miss_onchain_logs`, the no-op
   `test_elementary_only_event_is_byte_identical`, and the unit
   `test_abi_type_collapses_each_non_elementary_shape`.
2. **Corpus impact.** Run `event_topic0_audit.py` (Appendix A) over the live-run
   corpus (source dir or address list). It prints every event whose declared-name
   topic0 diverges from the canonical one — that divergence set **is** the set of
   contracts #116 affects. For each divergence, capture `(contract, event, old
   topic0, new topic0)`.
3. **On-chain confirmation.** For a captured divergence, `eth_getLogs` with the
   **canonical** topic0 (topic0-only, recent range) returns `> 0`; the same query
   with the **declared-name** topic0 returns `0`.
4. **End-to-end (after a re-run).** For a privileged mapping whose writer event
   has a non-elementary param, confirm `enumerate_mapping_allowlist` /
   principal-history for that mapping is now **non-empty** (was `[]` with
   `status=complete`), and that `indexed_event_cursors` has a row for the
   canonical topic0 of the watched contract.

### Regression signals — FAIL if any of these

- The co-land test fails, or an elementary-only event's topic0 **changes**
  (Invariant C broken → the fix perturbed a byte-identical case).
- Any privileged-mapping allowlist that was **non-empty** before is now empty, or
  any previously-enumerated member disappears (a real capability was dropped —
  the opposite of this fix's direction).
- Any capability/verdict flips from **gated -> public** as a result of this
  change (Invariant D broken; this fix must only ever add restriction /
  attribution).
- The two producers disagree for some event (Invariant B broken).
- A fixed-array event serializes with a Slither `Expression` in its signature
  (e.g. `address[<slither.core…Literal object…>]`) → the `length_value` fix
  regressed.

### On-chain sanity (recommended, not required)

Pick one affected event on a real deployment (Seaport `OrderFulfilled` on Seaport
1.1, or Uniswap-v4 `Initialize` on the v4 `PoolManager`) and confirm the
canonical topic0 pinned in the co-land test returns real logs via `eth_getLogs`,
while the declared-name topic0 returns none. This is the exact old-vs-new
behavior the settlement proof recorded (0 -> 5 logs).

### Known follow-ups carried by this change (not regressions)

- **Stale cursor rows.** `indexed_event_cursors` / `indexed_event_logs` are keyed
  by topic0, so a re-run with the corrected topic0 creates **new** cursor rows;
  the old dead-topic0 cursors become harmless orphans (they never fired and never
  will). Not a correctness issue; a cleanup could prune them later.
- **`function`-type event params (DEFERRED, fail-closed).** A `FunctionType`
  event param falls to `str()` (dead topic0). Vanishingly rare; under-report
  direction; trivially additive later.
- **`tracking._type_kind` / `_type_components` (DEFERRED, fail-soft, out of #116
  scope).** These still use `type(x).__name__ in {"Enum","EnumContract"}` /
  `{"Structure","StructureContract"}` string sets that miss
  `EnumTopLevel`/`StructureTopLevel`. Same root *class*, but a different output:
  they affect the controller `type_kind` **metadata label only**, NOT topic0
  (which flows through `_abi_type` via `_event_signature`). Worth folding into the
  same shared-canonicalizer PR, but it drops no allowlist member.
- **Two copies, not one shared helper.** The two `_abi_type` bodies are now
  identical; consolidating them into one `shared.py` helper is an engineering
  nicety (prevents future drift), not a correctness gap. If a later commit does
  it, add it as its own `## Change` section.

---

## Out of scope / open

- **Corpus headline counts.** #116 has no fixed "N mappings recovered" number —
  it depends entirely on how many non-elementary-param events the analyzed
  protocols emit. Report the per-run affected set from Appendix A rather than a
  target integer.

---

## Appendix A — reproduction / audit script (`event_topic0_audit.py`)

Reuses the **real** producers to show, per event, the declared-name topic0 (the
old/buggy value) vs the canonical topic0 (the fix), flagging divergences — the
exact set of events #116 changes. Runs on any Solidity source file/dir; no chain
access needed for the divergence report.

```python
"""Audit event topic0: declared-name (OLD) vs canonical (NEW) for every event.

Usage:
  PYTHONPATH=<repo> SOLC_VERSION=0.8.27 \
    uv run python event_topic0_audit.py path/to/Contract.sol [More.sol ...]

Prints one row per event; DIVERGES marks the events whose topic0 the #116 fix
corrects (interface/enum/array/struct/UDVT params). Elementary-only events show
SAME (byte-identical no-op). For on-chain confirmation of a DIVERGES row, run
eth_getLogs with the NEW topic0 (returns >0) and the OLD one (returns 0).
"""
from __future__ import annotations

import sys

from eth_utils.crypto import keccak
from slither import Slither

# The canonical producer (both modules are identical; tracking exposes the
# whole-signature helper directly).
from services.static.contract_analysis_pipeline.tracking import _event_signature as canonical_signature


def _topic0(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()


def audit(paths: list[str]) -> int:
    diverging = 0
    for path in paths:
        sl = Slither(path)
        for contract in sl.contracts:
            for ev in contract.events:
                declared = ev.full_name  # OLD producer output (declared names)
                canonical = canonical_signature(ev)  # NEW producer output
                old_t0, new_t0 = _topic0(declared), _topic0(canonical)
                flag = "SAME" if old_t0 == new_t0 else "DIVERGES"
                if flag == "DIVERGES":
                    diverging += 1
                print(f"[{flag}] {contract.name}.{ev.name}")
                print(f"    declared : {declared}  {old_t0}")
                print(f"    canonical: {canonical}  {new_t0}")
    print(f"\n{diverging} event(s) diverge -> topic0 corrected by #116")
    return diverging


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: event_topic0_audit.py <Contract.sol> [more...]")
    audit(sys.argv[1:])
```

> To exercise it without fetching anything, point it at the co-land test's inline
> `Probe` contract (interface/enum/UDVT/array/struct events) — every non-`Transfer`
> event reports `DIVERGES`, `TransferBatch` reports `SAME`. Against a live-corpus
> source tree it enumerates precisely which deployed contracts #116 fixes.
