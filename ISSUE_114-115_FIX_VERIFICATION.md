# Post-merge verification spec — #114 (guard-uncertain public-default gate) + #115 (multi-statement revert-gate recall)

**Purpose.** A living acceptance-criteria doc for the coupled fix that stops the
static→policy pipeline from mis-reporting a privileged, multi-statement-guarded
function as **public**. These are fail-OPEN polarity bugs (a guarded function
looked permissionless). This doc states what to observe on the **next analysis
run** to confirm the fix landed, the **fail-closed invariants** that must hold,
and what a **re-broken** state looks like. See the settlement docs for the full
investigation: `issue-fixes-111-122/analysis/issue-114-FINAL.md`,
`issue-114-FINAL2.md`, `issue-114-REALINSTANCE.md`, `issue-115-FINAL.md`.

> **Status:** committed locally on branch `wt/issue-114-115`
> (implementation commit `f6ac9e2`), **not pushed**. Fill in PR # / preview URL
> when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state**. After the PR deploys to a preview env and
   the live-tests job runs, confirm each `## Change` section against the preview
   API / DB. Mark each check **PASS / FAIL** and report any FAIL with the actual
   observed value.
2. **THIS IS NOT AGGREGATION-ONLY.** Both #114 and #115 change the **static
   analysis stage** (`RevertDetector` → `predicate_artifacts` →
   `effective_permissions`). The corrected verdicts appear only after the
   **static + resolution stages re-run** on a contract — serving the *existing*
   `effective_functions` rows will show the old (pre-fix) verdicts. To verify,
   re-analyze a target contract (re-enqueue its job) or run the faithful local
   reproduction in **Appendix A** (no DB, no network).
3. **FAIL-CLOSED is the whole point.** Every verdict this fix moves goes
   public → guarded / `unsupported` (safe). The fix must **NEVER newly report a
   guarded function as public** and must **never drop a real capability**. The
   single most important regression check is the **monotonicity invariant** (G1
   below): no function flips *toward* public.
4. **Numbers, not adjectives.** Over-broadening was measured at **0** on the real
   etherfi/mainnet corpus (the rejected broad first-cut flipped **7/7**
   genuinely-public functions). When absolute counts differ on another DB, verify
   the *invariants* and re-derive counts with the scripts here — do not fail on a
   raw integer mismatch the invariants explain.

### Environment / how to query

- **Where the verdict lives (DB):** table `effective_functions`
  (`db/models.py::EffectiveFunction`), columns `status`, `authority_public`,
  `capability_expr` (JSONB), keyed by `contract_id` + `abi_signature` /
  `function_name`. A function the fix corrects shows `status='unsupported'` (or a
  guarded capability) with `authority_public=false` — never `status='public'` /
  `authority_public=true`.
- **Where it surfaces (API):** `GET {preview_url}/api/.../analysis_detail`
  (`services/aggregations/analysis_detail.py`) emits `effective_permissions` with
  per-function `status` / `authority_public` / `capability_expr`. Ops/company
  reads may be admin-gated (PR #142); go through the live-tests `live_client` if
  you get 401/403.
- **The static marker (#114):** the predicate artifact carries a top-level
  `guard_extraction_uncertain: [<full_name>, …]` list **only** for functions that
  remain tree-less after a caller-EQ/NEQ guard could not be lowered. On the real
  corpus this list is **empty** (the marker is a defensive backstop; #115 makes
  the common case land in `trees` instead).
- **Most deterministic check:** the faithful single-contract pipeline run in
  **Appendix A** (real Slither + real `build_predicate_artifacts` +
  `build_effects` + `build_effective_permissions`), and the co-land test suite in
  **Appendix C**. Neither needs the prod DB.

### Global regression guards (apply to every change)

- **G1 — monotonic toward closed (THE keystone).** Diff `effective_functions`
  before vs after the re-analysis. **No function may flip `status`
  → `public`** or `authority_public` `false→true`. Every status delta must be in
  the set {`public`→`unsupported`, `public`→a guarded capability,
  unchanged}. A single `*`→`public` flip caused by this change is a FAIL.
- **G2 — who-can-call preserved.** For every function that already had a
  resolved authority/principal set, that set is **unchanged**. #115 adds only
  *non-authority* business/reentrancy gate leaves; it must never add, remove, or
  alter an authority leaf (`caller_authority` / `delegated_authority` / role).
- **G3 — no real capability dropped.** No function loses an existing authority
  leaf or principal. (The only gate #115 removes vs the old scan is the
  *both-arms-revert* case = an unconditional revert, which is not an access gate.)
- **G4 — marker is narrow.** `guard_extraction_uncertain` may list a signature
  **only** if that signature is absent from `trees`. A function present in both
  `trees` and the marker list is a FAIL (the residual filter broke).
- **CI green:** `ruff check` / `ruff format --check` / `pyright` / offline
  `pytest -m "not live"` / diff-cover ≥ 70% on the PR. Live-tests job green.

---

## Change 1 — #115: multi-statement revert-gate recall

- **Commit:** `f6ac9e2`
- **Branch / PR:** `wt/issue-114-115` → PR #____
- **Files:** `services/static/contract_analysis_pipeline/revert_detect.py`
  (the gate-detection rewrite), `tests/test_revert_detector.py`,
  `tests/test_predicate_builder.py` (end-to-end builder).
- **What it does:** `RevertDetector._scan_node` replaced its **one-hop son scan**
  (which inspected only the IF's direct successors for a `revert`) with an
  **"exactly one branch always reverts"** CFG walk (new `_branch_always_reverts`).
  Slither lowers a multi-statement guard body `if (C) { emit/assign…; revert; }`
  into a chain of `EXPRESSION` nodes, so the revert sits **≥2 hops** below the IF
  and the one-hop scan missed it → no gate → `build_predicate_tree` returns
  `None` → the policy defaulted the function to **public** (fail-open). The walk
  treats revert nodes as sinks, is cycle-safe, preserves polarity, and emits **no**
  gate when both branches revert (unconditional revert) or a branch escapes via an
  unbounded loop.

### Expected data — real, faithfully-compiled inputs

**(a) Gate-level recovery — REAL Kelp rsETH source** (`LRTConfigRoleChecker.onlyRole`
= `if(!hasRole(role,msg.sender)){ string memory roleStr = …; revert …; }`, the
genuine separate-statement access idiom). RSETH impl
`0x7159107483e623707c18c6e06cbc095bd0717783`:

| function | gates BEFORE (one-hop) | gates AFTER (always-reverts) |
|---|---:|---:|
| `pause()` | 1 | **3** |
| `mint(address,uint256)` | 4 | **6** |
| `burnFrom(address,uint256)` | 4 | **6** |

The recovered gate is the dropped multi-statement `onlyRole` access guard. These
three functions **do NOT flip public→unsupported** (each carries a secondary
HEAD-caught `whenNotPaused` / balance `require`, so they were already `in_trees`);
the recovery changes *why* they are guarded, never the verdict — consistent with
G1/G2.

**(b) Corpus over-broadening — 7 real mainnet contracts, 656 functions.**
**18 functions** change at the gate level (2.7%); the **authority/principal
conclusion changes in 0 of them**. Deltas are: assembly call-success reverts
(`if iszero(call(...)){revert}` — Aave v3 Pool ×7), Solady reentrancy `tload`/
`sload` checks (WeETH ×9), and one spurious both-arms-revert gate *removed* (ENS
`_checkOnERC721Received` ×2, fn stays guarded via its remaining opaque gate). All
added leaves are `authority_role=business`; the `delegated_authority` onlyOwner
leaf on WeETH.recover* is **unchanged**.

### Invariants to verify

- **G1/G2/G3 hold** across the re-analyzed contract set (the keystone).
- On any contract containing the `LRTConfigRoleChecker` / `EigenpieConfigRoleChecker`
  multi-statement `onlyRole` idiom, the guarded state-changers gain gates but keep
  their existing `status` (they had secondary gates) — recovery is authority-neutral.
- A function whose **sole** revert path is the multi-statement caller/role guard
  (rare in the wild; faithfully constructed in Appendix A as `s3`/`s4`/`s5`) flips
  `public` → `unsupported` (this is the actual #114 bite; see Change 2).

### How to verify

1. **Gate level (real contract):** run Appendix B against the re-analyzed
   contract, or compile the Kelp `LRTConfigRoleChecker` family and run
   `RevertDetector(fn).run()` per function, asserting the gate counts in table (a).
2. **Policy level / corpus:** capture `effective_functions` (`status`,
   `authority_public`, authority leaves of `capability_expr`) **before** the
   re-analysis, re-analyze, capture **after**, and assert G1/G2/G3 hold over the
   diff.
3. **Unit/integration:** Appendix C (`tests/test_revert_detector.py`,
   `tests/test_predicate_builder.py`).

### Regression signals — FAIL if any of these

- Any function flips `status`→`public` or `authority_public` `false→true`
  (**G1** — a NEW fail-open; the exact bug class this fixes).
- A function with a multi-statement caller/role guard as its sole revert path is
  reported `public` (the recall regressed back to the one-hop scan).
- An authority leaf is added/removed/changed on any function (**G2/G3** — #115 is
  authority-neutral; an authority delta means the walk over/under-reaches).
- Two gates emitted for a `if(outer){ if(flag){revert;} }` shape (Shape-B
  over-attribution) or zero gates for `if(outer){ if(flag){emit;} revert; }`
  (Shape-A fail-open) — both are pinned by Appendix C tests.

### On-chain / cross-source sanity (optional)

Open RSETH impl `0x7159107483e623707c18c6e06cbc095bd0717783` on Etherscan;
confirm `LRTConfigRoleChecker.onlyRole` has the `string memory roleStr = …;`
statement **before** `revert CallerNotLRTConfigAllowedRole(roleStr)` (the
separate-statement shape the one-hop scan dropped).

---

## Change 2 — #114: guard-uncertain public-default gate

- **Commit:** `f6ac9e2`
- **Branch / PR:** `wt/issue-114-115` → PR #____
- **Files:** `services/static/contract_analysis_pipeline/predicates.py`
  (emit marker), `services/static/contract_analysis_pipeline/predicate_artifacts.py`
  (collect residual marker), `services/policy/effective_permissions.py`
  (consume marker), `tests/test_effective_permissions.py`,
  `tests/test_pipeline_profiling.py` +
  `tests/test_predicate_artifacts_entry_point_dedup.py` (test-double kwargs).
- **What it does:** a **narrow, fail-closed backstop** for the residual guard
  shapes #115 still cannot lower into a tree. `build_predicate_tree` gained an
  optional `uncertain_out` set; when a function has gates but produces **no tree**
  and at least one un-modeled gate condition is a **direct `msg.sender`/`tx.origin`
  EQ/NEQ against a non-constant**, its `full_name` is marked
  `guard_extraction_uncertain`. `predicate_artifacts` carries **only the residual**
  markers (`guard_uncertain − set(trees)`); `effective_permissions` flips **only
  marked** signatures to `unsupported` instead of defaulting them to public. Value
  comparisons (`require(amt>0)`), order checks (`balance>=x`), and mapping-index
  reads (`balances[msg.sender]>=x`) are excluded **by construction** — keeping the
  marker false-positive-free on public surfaces.

### Expected data — real corpus + faithful construction

| metric (5–7 real verified contracts) | value |
|---|---:|
| `guard_extraction_uncertain` markers emitted | **0** |
| functions where a gate exists but tree is `None` (marker-reachable) | **0 / 124** |
| genuinely-public functions flipped public→unsupported | **0** |
| — contrast: the REJECTED broad boundary (FIX-A) on this corpus | **7 / 7 FP** |

The rejected broad cut flipped `WETH9.transfer`, `WeETH.wrapWithPermit`, and
`Liquifier` ×5 — all genuinely public. The shipped marker flips **none** of them.
On the real corpus the marker is **inert** (0 emitted): #115 makes the common
caller-guard land in `trees`, so the policy's pre-existing
`signature ∈ predicate_trees → unsupported` branch already routes it away from
public. The marker is the *defensive* layer that catches a future builder
regression toward fail-open.

**Faithful policy-level flip** (Appendix A, `Shapes.sol`, the actual #114 bug
through the real policy pipeline):

| function | guard | BEFORE | AFTER |
|---|---|---|---|
| `s3()` | `if(msg.sender!=owner){ emit; revert; }` | `public` | **`unsupported`** |
| `s4()` | `if(!isAdmin[msg.sender]){ emit; revert; }` | `public` | **`unsupported`** |
| `s5()` | `if(msg.sender!=owner){ x=0; revert(); }` | `public` | **`unsupported`** |
| `s7()` | none (genuinely public) | `public` | `public` (unchanged) |

### Invariants to verify

- **G4** — `guard_extraction_uncertain` lists only tree-less signatures.
- The marker flips **only** listed signatures; an unmarked tree-less sink with a
  resolver still defaults `public` (Appendix C
  `test_guard_extraction_uncertain_marker_absent_defaults_public`).
- A flipped function carries `capability_expr.unsupported_reason ==
  "guard_extraction_uncertain"` and `authority_public != true`.
- **No genuinely-public function is flipped** (the s7 control; `WETH9.transfer`).

### How to verify

1. **Marker presence (DB/artifact):** for a re-analyzed contract, inspect the
   predicate artifact's top-level `guard_extraction_uncertain` (expected empty on
   the etherfi corpus). For any signature listed, confirm it is **absent** from
   `trees` (G4) and its `effective_functions.status='unsupported'` with
   `capability_expr->>'unsupported_reason' = 'guard_extraction_uncertain'`.
   ```sql
   SELECT function_name, status, authority_public,
          capability_expr->>'unsupported_reason' AS reason
   FROM effective_functions
   WHERE contract_id = :cid
     AND capability_expr->>'unsupported_reason' = 'guard_extraction_uncertain';
   ```
2. **Policy-level flip + no over-broadening:** Appendix A — assert `s3/s4/s5`
   are not `public` and `s7` stays `public`.
3. **Unit:** Appendix C (`tests/test_effective_permissions.py`).

### Regression signals — FAIL if any of these

- A genuinely-public function (e.g. `WETH9.transfer`, the `s7` control) flips to
  `unsupported` → over-broadening returned (the rejected FIX-A boundary).
- `guard_extraction_uncertain` lists a signature that is also in `trees`
  (**G4** broke — the residual filter `guard_uncertain − set(trees)` regressed).
- A marked signature is still served `public` / `authority_public=true` (the
  policy gate is not consuming the marker).
- The marker fires on a value/order/mapping-index comparison (e.g. a
  `require(amt>0)`-only function appears in the list) → the
  `_gate_condition_is_caller_eq_neq` discriminator widened.

### On-chain / cross-source sanity (optional)

If any real contract ever emits a non-empty `guard_extraction_uncertain`, open it
on Etherscan and confirm the listed function has a genuine caller/role check
(`msg.sender == X` / `hasRole(role, msg.sender)`) the builder could not lower —
i.e. it is a missed access guard, **not** a value/permissionless function.

---

## Out of scope / open (track here; not regressions)

- **Gate-LESS caller guards.** A real caller check #115 still cannot lift into any
  gate (an unrecognized modifier idiom, or some inline-asm caller compare not
  caught by the pre-existing assembly-revert Case 5) leaves no gate to inspect, so
  the marker cannot catch it and it stays fail-open. This residual is strictly
  smaller than the pre-fix state; the only discriminator that would catch it
  (FIX-A's body re-scan) is the measured **7/7-FP** boundary that was correctly
  rejected. Closing it requires a precise extractor, not a broader policy default.
- **Disjunctive guards** `revert iff (A∧B)` are under-approximated by the AND-only
  predicate algebra (kept as the inner leaf) — pre-existing, over-restrictive
  (safe direction), a separate algebra change.

---

## Appendix A — faithful single-contract reproduction (`repro_114_115.py`)

Compiles a contract carrying the multi-statement caller/role guards plus a
genuinely-public sink, and runs the **real** static→policy pipeline (no DB, no
network). Asserts the #114 policy flip and 0 over-broadening on the public control.
Run with the worktree on `PYTHONPATH` and the repo's Slither/solc available.

```python
"""Faithful #114+#115 repro: real Slither + real static->policy pipeline.
Usage: PYTHONPATH=<worktree> python repro_114_115.py
"""
import os, tempfile, subprocess, sys
from pathlib import Path
from slither import Slither
from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts
from services.static.contract_analysis_pipeline.effects import build_effects
from services.policy.effective_permissions import build_effective_permissions

SRC = """
pragma solidity ^0.8.19;
contract Shapes {
    address public owner;
    mapping(address => bool) public isAdmin;
    uint256 public x;
    event Denied(address caller);
    // s3: multi-statement owner guard (revert 2 hops below the IF) -> #115/#114
    function s3() external { if (msg.sender != owner) { emit Denied(msg.sender); revert(); } x = 1; }
    // s4: multi-statement mapping-ACL guard
    function s4() external { if (!isAdmin[msg.sender]) { emit Denied(msg.sender); revert(); } x = 2; }
    // s5: assign-then-revert owner guard
    function s5() external { if (msg.sender != owner) { x = 0; revert(); } x = 3; }
    // s7: genuinely public (no guard) -> must stay public
    function s7() external { x = 7; }
}
"""

def main():
    d = Path(tempfile.mkdtemp())
    (d / "Shapes.sol").write_text(SRC)
    subprocess.run(["solc-select", "use", "0.8.19"], capture_output=True)
    os.chdir(d)
    sl = Slither("Shapes.sol")
    c = next(x for x in sl.contracts if x.name == "Shapes")

    arts = build_predicate_artifacts(c)
    trees = arts.get("trees", {})
    marker = arts.get("guard_extraction_uncertain", [])
    predicate_trees = {"schema_version": "semantic", "trees": trees}
    if marker:
        predicate_trees["guard_extraction_uncertain"] = marker

    effects = build_effects(c)  # {"schema_version": ..., "functions": {...}}
    target = {"subject": {"address": "0x" + "11" * 20, "name": "Shapes"},
              "semantic_control": {"semantic_functions": []}}
    # capability_resolver_output={} => resolver ran, no caps => the public-default
    # population (the exact branch the fix gates).
    payload = build_effective_permissions(
        target, capability_resolver_output={}, effects=effects,
        predicate_trees=predicate_trees,
    )
    status = {f["function"]: (f.get("status"), f.get("authority_public"))
              for f in payload["functions"]}
    print("guard_extraction_uncertain:", marker)
    for sig in sorted(status):
        print(f"  {sig:24} status={status[sig][0]:<12} authority_public={status[sig][1]}")

    # ASSERTIONS (fail-closed): guarded fns not public; the control stays public.
    for sig in ("s3()", "s4()", "s5()"):
        st, pub = status[sig]
        assert st != "public" and pub is not True, f"FAIL-OPEN: {sig} -> {status[sig]}"
    st7, pub7 = status["s7()"]
    assert st7 == "public" and pub7 is True, f"OVER-BROADENED public control: s7 -> {status['s7()']}"
    print("OK: s3/s4/s5 fail-closed, s7 public preserved.")

if __name__ == "__main__":
    sys.exit(main())
```

Expected output: `s3()/s4()/s5()` print `status=unsupported` (or a guarded
capability) with `authority_public` not `True`; `s7()` prints `status=public
authority_public=True`; on this contract the marker is unnecessary because #115
lands the guard in `trees` (the assertion checks the verdict, not the mechanism).
On **pre-fix** code, `s3/s4/s5` print `status=public authority_public=True`
(the bug) and the script raises `FAIL-OPEN`.

## Appendix B — gate-level recall check (real contract)

Per-function gate count via the real `RevertDetector`, to confirm #115 recovers
the dropped multi-statement gate (e.g. the Kelp `onlyRole` family).

```python
from slither import Slither
from services.static.contract_analysis_pipeline.revert_detect import RevertDetector
sl = Slither("<path-or-address>")          # compile the verified source
c  = next(x for x in sl.contracts if x.name == "<ContractName>")
for fn in c.functions_entry_points:
    gates = RevertDetector(fn).run()
    n = sum(1 for g in gates if g.kind in ("if_revert", "custom_revert"))
    print(f"{fn.full_name:40} if/custom_revert gates = {n}")
# Kelp rsETH impl 0x7159107483e623707c18c6e06cbc095bd0717783:
#   pause()   -> 3 (was 1)   mint(address,uint256) -> 6 (was 4)
#   burnFrom(address,uint256) -> 6 (was 4)
```

## Appendix C — the co-land test suite (offline, authoritative)

```bash
cd <worktree>
set -a; source /home/riley/PSAT/.env; set +a
export PSAT_LLM_STUB_DIR=<worktree>/tests/fixtures/scope_extraction/llm_responses
PYTHONPATH=<worktree> python -m pytest -m "not live" \
  tests/test_revert_detector.py \
  tests/test_predicate_builder.py \
  tests/test_effective_permissions.py \
  tests/test_earned_public.py \
  tests/test_corpus_real_patterns.py \
  tests/test_inlined_helper_revert_gates.py \
  tests/test_predicate_evaluator.py \
  tests/test_reentrancy_pause.py \
  tests/test_namespaced_access_control_recall.py \
  tests/test_standards_coverage.py \
  tests/test_predicate_artifacts_entry_point_dedup.py \
  tests/test_pipeline_profiling.py \
  tests/test_generic_extensions_xfail.py -q
# Expected: 193 passed.
```

Key co-land tests and what each pins:
- `test_revert_detector.py::test_multi_statement_emit_then_revert_is_recovered`
  / `…assign_then_revert…` — #115 recall (revert ≥2 hops below the IF).
- `…::test_revert_after_nested_if_emits_one_outer_gate` — Shape A (no fail-open).
- `…::test_revert_inside_nested_if_attributes_to_inner_only` — Shape B
  (no over-attribution).
- `…::test_both_branches_revert_emits_no_if_gate` — unconditional revert is not
  a gate.
- `…::test_branch_always_reverts_unbounded_cycle_escapes_not_guard` — loop
  hardening (no fabricated gate).
- `test_predicate_builder.py::test_multi_statement_caller_guard_yields_caller_authority_leaf`
  — #115→#114 end-to-end: the guard becomes a `caller_authority` equality leaf.
- `test_effective_permissions.py::test_guard_extraction_uncertain_marker_absent_defaults_public`
  — control: unmarked tree-less sink still defaults public.
- `…::test_guard_extraction_uncertain_marker_flips_only_marked_to_unsupported`
  — #114 policy gate: only marked sigs go `unsupported`, with the explicit reason.
