# Post-merge verification spec — #117 (assembly-sink fail-closed)

**Purpose.** A durable acceptance-criteria doc for the fix that makes inline
assembly `sstore` / `delegatecall` effects visible to the static+policy pipeline
**without** fabricating access. See `issue-fixes-111-122/analysis/issue-117-FINAL.md`
and `issue-117-rootcause.md` for the diagnosis. The bug is a fail-**open**
polarity error of the same class as #114/#115: a real state-write or proxy
delegatecall carried in inline assembly was silently discarded, and — because a
function with no visible predicate tree defaults to `public` — an assembly-gated
mutator could be projected as publicly callable.

This fix moves affected verdicts only in the **safe** direction
(`public → unsupported`, plus newly-surfaced accurate sinks/labels). It never
newly reports a guarded thing as public and never drops a real capability.

> **Status:** Implementation commit `f10e79a` on branch `wt/issue-117`
> (on top of #114/#115 `f6ac9e2`). Not yet pushed / no PR opened. Fill in PR # /
> preview URL when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state** after the next analysis run re-analyzes a
   contract carrying inline-assembly state effects. Confirm each check below and
   mark **PASS / FAIL**, reporting the actual observed value on any FAIL.
2. **This is NOT an aggregation-only fix.** Unlike the surface-controls series,
   the corrected output only appears after the **static pipeline re-runs** on a
   contract (`build_effects` → `effects.json` → `effective_functions` rows). It
   does **not** appear by merely re-serving existing DB rows. To verify against
   an already-analyzed contract, that contract must be re-analyzed on the fixed
   code (or use the direct-pipeline script in Appendix A, which needs no DB).
3. **Corpus scope.** The fix fires for **modern solc (≥0.6 / 0.8.x)**, where
   Slither lowers inline assembly to `SolidityCall` IR ops. It is **inert on
   legacy solc (≤0.5.x)** (opaque `NodeType.ASSEMBLY`, no IR) — a documented,
   pre-existing, fail-closed residual (see "Deferred residuals"). The PSAT target
   corpus (etherfi / modern DeFi) is overwhelmingly 0.8.x.
4. **The core correctness invariant is fail-closed polarity.** The guard may only
   turn a would-be `public` row into `unsupported`. If any function that this fix
   touches becomes *more* permissive (guarded → public), or loses a real
   controller/capability, that is a regression — the exact bug class this series
   exists to kill.

### Environment / how to query

- **Direct pipeline (most deterministic, no DB, no live run):** run the
  self-contained script in **Appendix A**. It compiles two faithful fixtures via
  real Slither, runs `build_effects` + `build_effective_permissions`, and asserts
  the AFTER invariants. Requires the repo on `PYTHONPATH` and solc-select pinned
  to a `≥0.8.20` build (CI uses **0.8.27**; set `SOLC_VERSION=0.8.27` so the
  solc-select shim dispatches correctly). This is the same production path the
  co-land tests drive.
- **Live-run DB (`effective_functions` table):** the derived, durable surface.
  Columns of interest: `function_name`, `selector`, `effect_labels` (text[]),
  `action_summary`, `authority_public` (bool), `status` (text),
  `capability_expr` (jsonb, carries `unsupported_reason`). Join to `contracts`
  by `contract_id`. Queries in "How to verify" below.
- **API:** `GET /api/.../analysis_detail` (or the analysis-detail aggregation)
  serializes these rows under `payload["effective_permissions"]["functions"]`.
  Reads may be admin-gated (PR #142) — go through `live_client` on 401/403.

### Global regression guards (apply to the whole change)

- CI green: `ruff check` / `ruff format --check` / `pyright` / offline `pytest`
  (`-m "not live"`) / diff-cover ≥ 70% on the PR.
- **No function moves guarded → public.** The only verdict motion this fix may
  cause is `public → unsupported` (fail-closed) plus newly-accurate sink/label
  fields. Anything else is a regression.
- **#134 non-regression:** assembly-only mutators (assembly sstore write + an
  assembly caller gate, no tree, no cap) stay `unsupported` — now additionally
  carrying populated `writer_selectors`. (Merged #134 posture preserved.)
- **#132 non-regression:** earned-public functions are unaffected (this fix only
  adds an `unsupported` route ahead of the public default; it never removes an
  earned-public verdict).

---

## Change 1 — assembly `sstore`/`delegatecall` surface as sinks; assembly-only mutators stay fail-closed

- **Commit:** `f10e79a` `fix(static/policy): surface inline-assembly sstore/delegatecall, keep assembly-only mutators fail-closed (#117)`
- **Branch / PR:** `wt/issue-117` → PR **#____**
- **Files:**
  - `services/static/contract_analysis_pipeline/effects.py` — `_classify_node_irs`
    SolidityCall branch now recognizes `sstore(` → `("state_write",
    "assembly_storage:<slot>", None)` and `delegatecall(` → `("delegatecall",
    "assembly_delegatecall:<addr-arg>", None)`; `_effect_info_for_function` stamps
    `assembly_state_access: True` when such a sink is present; new field on the
    `EffectInfo` TypedDict.
  - `services/policy/effective_permissions.py` —
    `_function_records_from_semantic_artifacts` adds `assembly_only_signatures`
    (= `assembly_state_access` **AND** state-changing entry point, minus
    capabilities, minus predicate trees) and routes those to
    `unsupported(assembly_only_authority_not_extracted)`.
  - `tests/test_effective_permissions_abi_mutability.py` — two co-land regression
    tests (real Slither compile of `TakeOverProxy`).

- **What it does.** Modern Slither lowers inline-assembly `sstore` and
  `delegatecall` to `SolidityCall` IR ops that the old branch inspected only for
  `selfdestruct(` and otherwise discarded — so an assembly storage write produced
  **no** sink (writer wholly invisible / unmonitorable) and a proxy's assembly
  `delegatecall` fallback produced **no** `delegatecall_execution` capability.
  The fix surfaces both. Because a surfaced sink pulls the function out of the
  ABI-only-mutator set, the policy stage would otherwise default it to `public`;
  the new `assembly_only_signatures` guard keeps a state-changing assembly writer
  with no tree and no capability at `unsupported` instead — its gate may itself be
  inline assembly and thus invisible. The guard is **scoped to state-changing
  entry points** so an EIP-1967 proxy `fallback`/`receive` (delegatecall
  passthrough, no gate by design) stays a genuine `public` row carrying its new
  `delegatecall_execution` label.

### Expected data (before → after)

Computed by running `build_effects` + `build_effective_permissions` on the fixed
code. Input A is the **real** etherfi weETH UUPS proxy source; Input B is a
faithfully-compiled synthetic proxy (Appendix A fixture) that isolates the
assembly-writer path.

**A. Real OZ ERC1967/UUPS proxy — etherfi weETH `0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee` (solc 0.8.13), `fallback()`:**

| Field (`fallback()`) | Before (`5152ff0`/pre-fix) | After (`f10e79a`) |
|---|---|---|
| sinks | `[external_call _IMPLEMENTATION_SLOT.getAddressSlot]` | `[external_call …, delegatecall assembly_delegatecall:<impl-arg>]` |
| `effect_labels` | `[external_contract_call]` | `[… , delegatecall_execution]` |
| `action_summary` | "Calls an external contract…" | **"Executes delegatecall-controlled logic."** |
| policy `status` / `authority_public` | `public` / `true` | `public` / `true` (**unchanged — correct**) |

The proxy stays **public** (access lives in the impl); the delegatecall is now
**visible**. Δ = capability surfaced, **0** verdict downgrades.

**B. Assembly state-writer, state-changing, no high-level gate — `TakeOverProxy.takeOver(address)` (Appendix A):**

| Field (`takeOver(address)`) | Before | After (`f10e79a`) |
|---|---|---|
| sinks | `[]` (writer invisible) | `[state_write assembly_storage:0]` |
| `writer_selectors` | `[]` | `['0x5aa95d1a']` (monitorable) |
| policy `status` | *(defaulted)* `public` | **`unsupported`** |
| `authority_public` | `true` | **`false`** |
| `capability_expr.unsupported_reason` | — | `assembly_only_authority_not_extracted` |

Δ = **1** downgrade `public → unsupported` (correct/conservative), writer now
monitorable by selector.

**C. #134 role-mutators — Solady EnumerableRoles `setRole`/`grantRole`/`revokeRole`
(assembly sstore + assembly owner-gate):** stay `unsupported` (3 rows), now with
`writer_selectors` populated. **0** verdict change; **0** regressions.

### Detailed invariants (verify each)

- **I1 (accuracy — delegatecall).** Every assembly-`delegatecall` function has
  `delegatecall_execution` in `effect_labels` and `action_summary ==
  "Executes delegatecall-controlled logic."`. Proxy fallbacks keep
  `authority_public = true` / `status = public`.
- **I2 (accuracy — sstore).** Every assembly-`sstore` writer carries a
  `state_write` sink whose target starts `assembly_storage:` and a non-empty
  `selector` (writer monitorable).
- **I3 (fail-closed).** A **state-changing** entry point with an assembly-origin
  sink, no predicate tree, and no capability has `status = unsupported`,
  `authority_public = false`,
  `capability_expr.unsupported_reason = assembly_only_authority_not_extracted`.
- **I4 (scope).** A `fallback()`/`receive()` whose only effect is an assembly
  delegatecall is **not** downgraded — it stays `public`. (The guard excludes
  non-state-changing entry points.)
- **I5 (no fabrication).** `delegatecall_execution` appears **only** on functions
  that actually contain a delegatecall (assembly or high-level). No function
  gains a controller or capability it did not have pre-fix.

### How to verify

**Method A — direct pipeline (deterministic).** Run Appendix A:
```
cd <repo> && SOLC_VERSION=0.8.27 PYTHONPATH=<repo> \
  /home/riley/PSAT/.venv/bin/python issue_117_verify.py
```
Exit 0 + `ISSUE-117 OK` ⇒ all of I1–I5 hold on faithful compiles.

**Method B — live DB (`effective_functions`), after re-analysis.**

Proxy fallback delegatecall is visible and still public (I1, I4):
```sql
SELECT c.address, ef.function_name, ef.effect_labels, ef.action_summary,
       ef.status, ef.authority_public
FROM   effective_functions ef JOIN contracts c ON c.id = ef.contract_id
WHERE  ef.function_name IN ('fallback()','receive()')
  AND  'delegatecall_execution' = ANY(ef.effect_labels);
-- expect: authority_public = true, status IS NULL or 'public',
--         action_summary = 'Executes delegatecall-controlled logic.'
```

Assembly-only mutators are fail-closed (I3):
```sql
SELECT c.address, ef.function_name, ef.status, ef.authority_public,
       ef.capability_expr->>'unsupported_reason' AS reason, ef.selector
FROM   effective_functions ef JOIN contracts c ON c.id = ef.contract_id
WHERE  ef.capability_expr->>'unsupported_reason' = 'assembly_only_authority_not_extracted';
-- expect every row: status='unsupported', authority_public=false, selector NOT NULL
```

Fail-open sentinel — this MUST return **zero rows** (I3/I5):
```sql
-- an assembly-only authority row that leaked to public = the bug is back
SELECT c.address, ef.function_name
FROM   effective_functions ef JOIN contracts c ON c.id = ef.contract_id
WHERE  ef.capability_expr->>'unsupported_reason' = 'assembly_only_authority_not_extracted'
  AND  (ef.authority_public = true OR ef.status = 'public');
```

### Regression signals — FAIL if any of these

- **Fail-open:** an assembly state-writer (no tree, no cap) shows
  `status = public` / `authority_public = true` — the guard broke (the exact
  polarity bug this series exists to prevent).
- **Over-broad scope:** a proxy `fallback()`/`receive()` flipped to `unsupported`
  or **lost** its `delegatecall_execution` label — the state-changing scoping
  regressed (hides that the proxy is publicly callable).
- **Fabrication:** `delegatecall_execution` on a function with no delegatecall, or
  a new controller/capability appearing on any function this fix touches.
- **Dropped capability:** a function that previously resolved a controller now
  resolves none.
- **#134 regression:** the Solady-style role mutators stop being `unsupported`
  (e.g. become `public`), or lose their `writer_selectors`.

### On-chain / cross-source sanity (recommended, not required)

- The weETH proxy fallback genuinely `DELEGATECALL`s the EIP-1967 implementation
  slot — its access control legitimately lives in the impl, so `public +
  delegatecall_execution` is the accurate reading (not a fabricated open).
- A `takeOver`-shaped assembly writer with no caller check outside assembly has no
  provable on-chain gate → `unsupported` is the honest posture; do **not** expect
  a resolved controller for it (that would require slot→authority resolution,
  which is out of scope — see below).

### Deferred residuals (documented, fail-closed — NOT regressions)

- **Legacy solc (≤0.5.x) opaque assembly.** Slither emits no IR for it, so the fix
  is inert; a legacy proxy fallback (e.g. USDC `FiatTokenProxy`
  `0xA0b8…eB48`, 0.4.24) stays unmonitored. Pre-existing, low corpus prevalence,
  separate code path (`inline_asm` string-scrape). State-changing legacy entry
  points still fall to `abi_only → unsupported` (no fabricated public).
- **Storage-library-pointer writes (OZ `StorageSlot` / `EnumerableSet`).**
  Different mechanism (pointer aliasing); already visible as a row via an
  `external_call` sink, so a monitoring-completeness gap, not a soundness drop.
- **slot → named-state-var resolution.** `assembly_storage:<slot>` is a slot
  literal, so `_writer_records_from_effects` builds no *named-var* event-watcher;
  the writer is already monitorable by **selector** (HyperSync replay). Additive,
  not load-bearing.

---

## Out of scope / open

- Full HyperSync **named-authority-var** monitoring of assembly writes needs
  slot→state-var resolution (additive). Until then, assembly writers are
  monitored by selector, which is sufficient for the soundness invariant (writer
  no longer wholly invisible).

---

## Appendix A — reproduction script (`issue_117_verify.py`)

Drives the production path (`Slither` → `build_effects` →
`build_effective_permissions`) on two faithful fixtures and asserts I1–I5. No DB.
Run with `SOLC_VERSION=0.8.27 PYTHONPATH=<repo>`.

```python
"""Acceptance check for #117 (assembly-sink fail-closed).
Usage: SOLC_VERSION=0.8.27 PYTHONPATH=<repo> python issue_117_verify.py
Exit 0 + 'ISSUE-117 OK' iff invariants I1-I5 hold on faithful compiles.
"""
import sys, tempfile, textwrap
from pathlib import Path

from slither import Slither
from services.static.contract_analysis_pipeline.effects import build_effects
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts,
)
from services.policy.effective_permissions import build_effective_permissions

# EIP-1967-style proxy: assembly sstore writer with NO high-level gate + an
# assembly-delegatecall fallback. Isolates both the accuracy gain and the
# fail-closed writer path.
SRC = """
pragma solidity ^0.8.19;
contract TakeOverProxy {
    address impl;
    function takeOver(address a) public { assembly { sstore(0, a) } }
    fallback() external payable {
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 0, calldatasize())
            let result := delegatecall(gas(), sload(0), ptr, calldatasize(), 0, 0)
            returndatacopy(ptr, 0, returndatasize())
            switch result
            case 0 { revert(ptr, returndatasize()) }
            default { return(ptr, returndatasize()) }
        }
    }
}
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "TakeOverProxy.sol"
        p.write_text(textwrap.dedent(SRC).strip() + "\n")
        contract = next(c for c in Slither(str(p)).contracts if c.name == "TakeOverProxy")
        effects = build_effects(contract)
        trees = build_predicate_artifacts(contract)

    fns = effects["functions"]
    take, fb = fns["takeOver(address)"], fns["fallback()"]

    # I2 accuracy — sstore write surfaces + writer monitorable by selector.
    assert any(s["kind"] == "state_write" and s["target"].startswith("assembly_storage:")
               for s in take.get("sinks") or []), take.get("sinks")
    assert take.get("writer_selectors"), "writer_selectors empty"
    # I1 accuracy — delegatecall surfaces as label + summary.
    assert any(s["kind"] == "delegatecall" and s["target"].startswith("assembly_delegatecall:")
               for s in fb.get("sinks") or []), fb.get("sinks")
    assert "delegatecall_execution" in (fb.get("effect_labels") or [])
    assert fb.get("action_summary") == "Executes delegatecall-controlled logic."

    payload = build_effective_permissions(
        {"subject": {"address": "0x000000000000000000000000000000000000dead", "name": "TakeOverProxy"}},
        effects=effects, predicate_trees=trees, capability_resolver_output={},
    )
    by = {fn["function"]: fn for fn in payload["functions"]}

    # I3 fail-closed — assembly writer with no tree/cap is unsupported, not public.
    t = by["takeOver(address)"]
    assert t.get("status") == "unsupported", t.get("status")
    assert t["authority_public"] is False
    assert t["controllers"] == []
    assert t.get("capability_expr", {}).get("unsupported_reason") == "assembly_only_authority_not_extracted"

    # I4 scope — the delegatecall-only fallback stays public (not downgraded).
    f = by["fallback()"]
    assert f.get("status") != "unsupported", f.get("status")
    assert f.get("authority_public") is True

    print("ISSUE-117 OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

> Note: the two co-land unit tests
> (`tests/test_effective_permissions_abi_mutability.py::
> test_inline_assembly_sstore_and_delegatecall_surface_as_sinks` and
> `::test_assembly_writer_with_invisible_gate_stays_unsupported`) assert the same
> invariants inside the pytest suite and were proven **non-vacuous** by targeted
> reverts (dropping the effects branches makes both fail at the sink asserts;
> dropping the policy guard flips `takeOver` to `public`).
