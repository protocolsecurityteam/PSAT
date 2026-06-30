# Post-merge verification spec — #111/#112 cold caller-keyed comparison thresholds

**Purpose.** A durable acceptance-criteria doc for the fix that closes the
caller-keyed-**threshold** fail-open: an admin-curated `map[msg.sender] >= K`
gate rendered **PUBLIC** when its holder set was empty (#112, exact-empty) or
the enumeration was cold / unsupported / no-adapter (#111), fabricating open
access to an authorization. The fix routes such a gate to **GATED** while
leaving genuine self-service thresholds (a caller's own balance/points, which
anyone can acquire) **PUBLIC**. This doc states what to observe on the next
live resolution run to confirm the bug stays fixed and nothing was
over-broadened.

> **Status:** committed on branch `wt/issue-111-112`
> (implementation commit `3e597794f767fa1fbd7b3cbdea7e1c434fee3270`), **not
> pushed**. Fill in PR # / preview URL when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state** of the resolution stage. After the PR
   deploys to a preview env and a fresh etherfi resolution run completes,
   confirm each invariant below against the run's persisted artifacts
   (`contract_materializations.predicate_trees`, `effective_functions`) and/or
   by re-running the self-contained scripts in the appendices. Mark every check
   **PASS / FAIL** and report any FAIL with the actual observed value.

2. **This is a resolution-stage fix, not aggregation-only.** Unlike the
   Surface-controls FP-gate, the corrected verdicts only appear after the
   contract is **re-resolved** (re-fetched → re-Slithered → writer-gate →
   evaluate). Serving old `effective_functions` rows will NOT show the change;
   you must look at a run produced by the new code (or run the appendix scripts,
   which execute the real pipeline in-process).

3. **Materiality caveat — the fix fires 0× on the etherfi corpus.** The
   targeted vulnerable shape (an admin-curated **constant** caller-keyed
   threshold) is **absent from etherfi** — measured, see Expected Data §A. On
   etherfi the corpus therefore proves the fix's **precision** (it over-gates
   none of the 45 real self-service thresholds) but **cannot exercise its
   recall** (no real production function changes verdict). The recall benefit —
   the actual #111/#112 flip — is exercised on a **faithfully compiled**
   admin-tier contract (Appendix B), not on hand-forced output. Do **not**
   conclude "fix did nothing" from an unchanged etherfi surface; that is the
   *expected* precision result. If a *different* protocol in a later run
   contains an admin-tier constant threshold, §B's flip must be visible there.

4. **Polarity is the whole point — FAIL-CLOSED only.** Every verdict this fix
   moves goes PUBLIC→GATED (safe) or stays put. It must **never** newly render a
   guarded function PUBLIC, and must **never** drop a real caller. A regression
   in the dangerous direction (a promoted admin threshold reading PUBLIC again)
   is the #111/#112 bug returning; see Regression Signals.

### Environment / how to query

- **Real pipeline path** (what the appendix scripts and the live worker both
  run): Slither compile → `build_predicate_tree` →
  `apply_writer_gate_pass` (Part A lives here, in `_maybe_promote_leaf`) →
  `evaluate_tree` / `_evaluate_leaf` (Part B, the `kind == "comparison"` branch)
  → `capability_to_dict` → `project_capability_surface`
  (`services/policy/capability_surface.py`; `surface.authority_public` is the
  rendered GATED/PUBLIC bit).
- **Persisted artifacts (preview/prod DB):**
  - `contract_materializations.predicate_trees` (JSONB) — per-leaf
    `authority_role` + `basis`. A leaf promoted by Part A carries
    `authority_role == "caller_authority"` and a basis string
    `"threshold-promote: <var> writers are authority-gated"`.
  - `effective_functions.authority_public` (Boolean) — the per-function
    rendered public/gated bit. A gated promoted threshold ⇒ `authority_public =
    False`.
- **Feature flag:** the earned-public default must be on
  (`PSAT_AUTHORITY_EARNED_PUBLIC=1`, `earned_public_enabled()`); the comparison
  branch's new logic is under that flag. With the flag off, the legacy
  conditional-universal path runs and the fix is inert (matching pre-#132
  behaviour) — note the flag state when reporting.

### Global regression guards (apply to the whole change)

- CI green: `ruff check` / `ruff format --check` / `pyright` (CI runs
  `uv run pyright` repo-wide, `typeCheckingMode = basic`) / offline
  `pytest -m "not live"` / frontend / diff-cover ≥ 70% on the PR.
- **No already-merged partial fix regresses:** #132 (earned-public default —
  `tests/test_earned_public.py` whole file green), #134 (assembly-only
  unsupported rows — `tests/test_effective_permissions_abi_mutability.py`), #107
  (deferred reconciler — `tests/test_deferred_resolution_reconcile.py`,
  `tests/test_cold_index_deferral_selfheal.py`).
- The two subsumed point-fix basis tags still flow:
  `caller_keyed_time_allowlist` and `caller_keyed_membership_allowlist` remain in
  `CALLER_GATE_BASIS_TAGS` and are still emitted by `caller_gate_basis` (a
  promoted **time** allowlist must keep its time tag, not become a generic
  threshold tag).

---

## Change — gate cold caller-keyed comparison thresholds by writer-gate verdict (#111/#112)

- **Commit:** `3e59779` `fix(resolution): gate cold caller-keyed comparison thresholds by writer-gate verdict (#111/#112)`
- **Branch / PR:** `wt/issue-111-112` → PR #____
- **Files:**
  - `services/static/contract_analysis_pipeline/writer_gate.py`
    (`_maybe_promote_leaf` Path 2 — **Part A**)
  - `services/resolution/predicate_evaluator.py` (`_evaluate_leaf`,
    `kind == "comparison"` branch — **Part B**)
  - `tests/test_earned_public.py` (5 co-land tests)

### What it does

The discriminator between a **genuine authority set** and a **self-service
threshold** for a caller-keyed comparison leaf is the writer-gate's
`_classify_writers` verdict (are the keyed mapping's writers themselves
authority-gated?). That signal already separates the two cleanly on real
compiled contracts and is the same classifier trusted for 1-key membership
allowlists — it was simply **not wired** for comparison leaves.

- **Part A (static promotion).** For a 1-key caller-keyed comparison threshold
  (`map[msg.sender] >= K`), consult `_classify_writers`. When it returns
  `promote` / `promote_self_admin` (writers are admin-gated ⇒ value cannot be
  self-acquired), promote the leaf `business → caller_authority` with basis
  `threshold-promote: <var> writers are authority-gated`. The pre-existing
  additive M-of-N counter shape (`_is_authority_derived_counter`) is preserved
  as the second promotion path.
- **Part B (evaluator, role-aware fail-closed).** A comparison leaf only reaches
  the comparison branch as `caller_authority` / `delegated_authority` (Part A
  already judged it admin-curated). Drop the role-blind
  `is_permissionless_caller_shape` re-open. Enumerate the descriptor; honor a
  populated `finite_set` (restricted holders) **or** an authoritative empty
  (`membership_quality == "exact"` / `empty_reason == "empty_by_design"` →
  resolved-empty). Otherwise fail **CLOSED** to
  `external_check_only(basis=[caller_gate_basis(leaf)])` →
  `caller_tainted_authority_unresolved` (∈ `CALLER_GATE_BASIS_TAGS`, which
  `_is_root_authority_blocker` renders GATED) — never `conditional_universal`
  public.

Self-service thresholds stay `role=business`, never reach the edited branch, and
keep opening to public when cold (handled in the side-condition block above the
comparison branch).

### Expected data

**§A — Precision on the real etherfi corpus (56 contracts; measured via the real
`fetch → Slither → build_predicate_artifacts_with_pause_info`, which runs
`apply_writer_gate_pass`).** Input: the etherfi corpus on the 6/1-style clone
used in FINAL2.

| Metric (etherfi corpus) | Value |
|---|---:|
| caller-keyed comparison leaves swept | 45 (across 10 contracts) |
| …that reference `msg.sender` (self-service thresholds) | 6 |
| …that acquire a `set_descriptor` (precondition to Path-2) | **0** |
| …single-caller-keyed descriptor-bearing | **0** |
| …**PROMOTED** to `caller_authority` by the fix | **0** |
| over-broadening rate | **0 / 45 = 0.0%** |

Root reason (structural, not a corpus accident): the `set_descriptor` that
gates Path-2 is built **only for `map[msg.sender] >= CONSTANT`**. Every one of
the 6 real msg.sender thresholds is `map[msg.sender] >= PARAMETER` (a runtime
quantity check: `balanceOf[msg.sender] >= wad`, `value <= allowed[from][msg.sender]`,
`currentAllowance >= amount`, …) → no descriptor → cannot promote. So the fix
over-gates **none** of them, and (honest corollary) fires **0×** on etherfi.

**§B — Recall on a faithfully compiled admin-tier contract** (real Slither
compile of the contract below; the four infra states are exercised by feeding
the production adapter's own warm / exact-empty / cold response shapes — the
legitimate way, not hand-forced verdicts). This is the decisive #111/#112 flip.

```solidity
// ADMIN-CURATED tier — genuine authority (setTier is onlyOwner; a caller
// cannot self-acquire its level). Gate: require(tier[msg.sender] >= 2).
mapping(address => uint256) public tier;
function setTier(address a, uint256 t) external { require(msg.sender==owner); tier[a]=t; }
function gated() external { require(open); require(tier[msg.sender] >= 2); }
```

| ADMIN-CURATED `tier[msg.sender] >= 2` | BEFORE (`41822ec`) | AFTER (fix) |
|---|---|---|
| static role | `business` | **`caller_authority`** |
| warm (2 holders) | finite_set → GATED | finite_set → GATED (restricted holders) |
| exact-empty (nobody) | cond_univ → **PUBLIC** (#112) | finite_set([],exact) → **GATED** (resolved_empty) |
| cold / unsupported | cond_univ → **PUBLIC** (#111) | external_check_only → **GATED** (`caller_tainted_authority_unresolved`) |
| cold / no-adapter | cond_univ → **PUBLIC** (#111) | external_check_only → **GATED** (`caller_tainted_authority_unresolved`) |

```solidity
// SELF-SERVICE — permissionless (points are self-acquirable via earn()).
mapping(address => uint256) public points;
function earn() external { points[msg.sender] += 1; }
function gated() external { require(open); require(points[msg.sender] >= 5); }
```

| SELF-SERVICE `points[msg.sender] >= 5` | BEFORE | AFTER |
|---|---|---|
| static role | `business` | `business` (unchanged) |
| exact-empty / cold / no-adapter | cond_univ → PUBLIC | cond_univ → **PUBLIC** (correct, preserved) |

Decisive flip: **ADMIN cold PUBLIC→GATED while SELF cold stays PUBLIC.**

**§C — Discriminator generality** (real Slither + writer-gate; Appendix C).

| case | shape | role after gate | verdict |
|---|---|---|---|
| OwnerTier | `tier[s]>=2`, `setTier onlyOwner` | `caller_authority` | genuine auth promoted |
| RoleTier | `tier[s]>=2`, setter gated by OZ `hasRole` | `caller_authority` | genuine auth promoted |
| PureSelf | `points[s]>=5`, only self `+=` | `business` | self-service stays public |
| OpenRegister | `credit[s]>=3`, ungated external writer | `business` | self-acquirable stays public |
| MixedBalance | `balances[s]>=100`, self `deposit` + admin `mint` | `caller_authority` | bounded fail-CLOSED FP (see residual) |

### Invariants to verify

- **I1 (precision, real data).** On the etherfi run, **0** caller-keyed
  comparison leaves are promoted by the fix; the per-`msg.sender` self-service
  thresholds keep `authority_role == "business"` and their functions keep
  `authority_public == True` (unchanged from before the fix). No
  `effective_functions` row flips True→False due to this change.
- **I2 (recall, faithful synthetic).** The admin-tier contract's `gated()`:
  static role `caller_authority`; warm/exact-empty/cold/no-adapter all render
  `authority_public == False`; cold/no-adapter carry basis exactly
  `["caller_tainted_authority_unresolved"]`.
- **I3 (self-service preserved).** The self-service contract's `gated()`: role
  stays `business`; cold/empty render `authority_public == True`
  (`conditional_universal`).
- **I4 (fail-closed only).** Across I1–I3, no verdict moves GATED→PUBLIC and no
  caller/holder is dropped from a populated warm enumeration.
- **I5 (subsumed tags intact).** A promoted caller-keyed **time** allowlist still
  tags `caller_keyed_time_allowlist`; a 1-key membership allowlist still tags
  `caller_keyed_membership_allowlist` (not the generic threshold tag).

### How to verify

1. **Co-land tests (fastest signal):**
   ```
   PYTHONPATH=<worktree> PSAT_LLM_STUB_DIR=<worktree>/tests/fixtures/scope_extraction/llm_responses \
     <venv>/bin/python -m pytest -m "not live" tests/test_earned_public.py -q \
     -k "threshold or self_service or caller_keyed"
   ```
   Expect the 5 #111/#112 tests green:
   `test_admin_curated_threshold_promotes_to_caller_authority`,
   `…_cold_fails_closed` (revert-proof for **both** parts),
   `…_exact_empty_is_resolved_not_public`,
   `…_warm_enumerates_restricted_holders`,
   `test_self_service_threshold_stays_public_when_cold`.
2. **Precision on real data (I1):** run Appendix A against the target DB's
   etherfi run (or fetch the corpus). Assert promoted-count == 0 and
   over-broadening == 0/45. If a later protocol *does* contain an admin tier,
   Appendix A lists each promoted leaf — confirm each is a genuine admin-curated
   mapping (writer is `onlyOwner`/`hasRole`-gated), not a balance.
3. **Recall on the faithful synthetic (I2/I3):** run Appendix B. Assert the §B
   table exactly (admin flips to GATED on all four infra states; self stays
   PUBLIC).
4. **Live DB cross-check (I1/I2):** in `contract_materializations.predicate_trees`
   for the run, find leaves whose `basis` contains
   `"threshold-promote:"` ending `"writers are authority-gated"`; for each,
   confirm the owning `effective_functions` row has `authority_public == False`,
   and that the mapping is admin-written (not self-keyed). On etherfi expect
   **zero** such leaves (precision); any present must be genuine admin tiers
   rendering GATED.

```sql
-- Live: any caller-keyed THRESHOLD promoted by the fix (etherfi: expect 0 rows).
SELECT cm.contract_id, cm.predicate_trees
FROM contract_materializations cm
WHERE cm.predicate_trees::text LIKE '%threshold-promote:%writers are authority-gated%';
```

### Regression signals — FAIL if any of these

- **Dangerous (the bug returns).** An admin-curated constant caller-keyed
  threshold renders `authority_public = True` (PUBLIC) on exact-empty or
  cold/no-adapter. Causes to check: Part B's `is_permissionless_caller_shape`
  re-open was reintroduced into the comparison branch; or Part A's `promote`
  branch was removed/reordered so the leaf stays `business` and falls to the
  L380 business path.
- **Authoritative empty mis-handled.** A `finite_set([], membership_quality !=
  "exact")` (a *lower-bound* empty, i.e. "we couldn't confirm anyone") rendering
  PUBLIC — it must fall through to the fail-closed `external_check_only`, GATED.
  (Only `exact` / `empty_by_design` may resolve-empty.)
- **Over-broadening past the measured 0%.** Appendix A reports any
  `map[msg.sender] >= PARAMETER` self-service threshold promoted to
  `caller_authority` (descriptor leaking onto a non-constant threshold), or the
  etherfi promoted-count rising above 0 without a genuine admin tier behind it.
  This is fail-CLOSED/safe but a precision regression — investigate the
  `_find_index_value_pair` / `_is_mask_operand` constant-only narrowing.
- **Real caller dropped.** A warm populated holder set rendering empty/gated
  with no members (Part B failing to return the populated `finite_set`).
- **Tag drift.** A promoted time/membership allowlist losing its specific tag
  (`caller_keyed_time_allowlist` / `caller_keyed_membership_allowlist`) and
  reading the generic `caller_tainted_authority_unresolved` — dashboards/tests
  keyed on the specific tags break.
- Any #132/#134/#107 guard suite (Global guards) goes red.

### On-chain / cross-source sanity (optional)

For any leaf Appendix A reports as promoted on a real run: read the keyed
mapping's setter on-chain. If the setter is gated by `onlyOwner` / `hasRole` /
an authority check, the GATED rendering is correct (a caller cannot self-acquire
the level). If the mapping is writable by a self-keyed `+=`/ungated external
writer, the leaf should have stayed `business` (PUBLIC) — a false promote;
confirm against `_classify_writers`. Cross-check the gated function's holder set
against the on-chain mapping if warm.

### Residual scope / known follow-ups (not regressions)

- **MixedBalance bounded false-promote (fail-CLOSED).** A *constant*-threshold
  caller-keyed balance with **both** a self-acquirable writer (`deposit`) **and**
  an admin writer (`mint onlyOwner`) classifies `promote` → over-gates though
  anyone can buy in. Direction is PUBLIC→GATED (never fabricates access); it is
  the identical false-promote profile already shipped for 1-key membership
  (Path 1); requires a literal-constant threshold; **0 occurrences in the etherfi
  corpus.** Acceptable.
- **ExternalWriterTier residual fail-open MISS (pre-existing).** A genuine admin
  tier whose writer is cross-contract / proxy-split / Solmate (no in-contract
  writer ⇒ `writers` empty ⇒ `_maybe_promote_leaf` early-returns) stays
  `business` → cold PUBLIC. This is the deferred **systemic authority
  under-resolution** class; it was `business → public` before the fix too — not
  introduced or worsened here.
- **Self-service WARM over-restriction (separate, safe polarity).** A
  self-acquirable threshold whose holder set is *warm* still renders GATED via
  the D.1 enumerate-as-restricted in the L380 business block. Fail-CLOSED,
  pre-exists, unchanged by this fix. The open question only requires self-service
  *cold* cells to stay public (preserved by I3).

---

## Out of scope / open

- **Recall unexercised on etherfi.** The targeted vulnerable shape is absent
  from etherfi (§A), so no real etherfi function changes verdict. Demonstrating
  the live recall benefit needs a run over a protocol that actually ships an
  admin-curated **constant** caller-keyed threshold. Until then, the faithful
  synthetic (Appendix B) is the recall proof and "Safes/surface unchanged on
  etherfi" is the **expected** precision result, not a miss.

---

## Appendix A — corpus precision sweep (`sweep_caller_threshold.py`)

Runs the real pipeline over fetched contracts and reports every caller-keyed
comparison leaf and whether the fix promoted it. Over-broadening = promoted ÷
caller-keyed. Expect 0 promoted on etherfi.

```python
"""Sweep caller-keyed comparison leaves through the real writer-gate.
Usage: PYTHONPATH=<repo> PSAT_AUTHORITY_EARNED_PUBLIC=1 \
       <venv>/bin/python sweep_caller_threshold.py <contracts_dir>
where <contracts_dir> holds the fetched/scaffolded *.sol sources for the run.
"""
import os, sys, glob
os.environ.setdefault("PSAT_AUTHORITY_EARNED_PUBLIC", "1")
from slither import Slither
from services.static.contract_analysis_pipeline.predicates import build_predicate_tree
from services.static.contract_analysis_pipeline.writer_gate import apply_writer_gate_pass

CALLER = ("msg_sender", "tx_origin", "signature_recovery")

def leaves(t):
    if t is None: return []
    if t.get("op") == "LEAF": return [t["leaf"]] if t.get("leaf") else []
    out = []
    for ch in t.get("children") or []: out += leaves(ch)
    return out

total = caller_keyed = descriptor_bearing = promoted = 0
promoted_rows = []
for src in glob.glob(sys.argv[1] + "/**/*.sol", recursive=True):
    try:
        sl = Slither(src)
    except Exception:
        continue
    for c in sl.contracts:
        trees = {}
        for fn in c.functions:
            if fn.is_constructor: continue
            trees[fn.full_name] = build_predicate_tree(fn)
        apply_writer_gate_pass(c, trees)
        for full_name, t in trees.items():
            for leaf in leaves(t):
                if leaf.get("kind") != "comparison": continue
                total += 1
                desc = leaf.get("set_descriptor") or {}
                keys = desc.get("key_sources") or []
                is_caller = len(keys) == 1 and (keys[0].get("source") in CALLER)
                if is_caller: caller_keyed += 1
                if desc: descriptor_bearing += 1
                if leaf.get("authority_role") in ("caller_authority", "delegated_authority") \
                   and any("threshold-promote" in b and "authority-gated" in b
                           for b in (leaf.get("basis") or [])):
                    promoted += 1
                    promoted_rows.append((c.name, full_name, desc.get("storage_var")))

print(f"comparison leaves={total} caller_keyed={caller_keyed} "
      f"descriptor_bearing={descriptor_bearing} promoted={promoted}")
print(f"over-broadening = {promoted}/{caller_keyed} = "
      f"{(promoted/caller_keyed*100 if caller_keyed else 0):.1f}%")
for r in promoted_rows:
    print("  PROMOTED:", r, "-> confirm the mapping's writer is authority-gated")
```

## Appendix B — synthetic recall proof (real Slither, the decisive flip)

This is exactly what the co-land tests assert; reproduce stand-alone with:

```
PYTHONPATH=<worktree> PSAT_LLM_STUB_DIR=<worktree>/tests/fixtures/scope_extraction/llm_responses \
  <venv>/bin/python -m pytest -m "not live" \
  tests/test_earned_public.py -q -k "admin_curated_threshold or self_service_threshold"
```

The five tests embed the §B contracts, compile them with real Slither, run the
real writer-gate + evaluator + `project_capability_surface`, and feed the
production adapter's warm / `finite_set([], exact)` / cold (`None` adapter)
response shapes. They assert the §B table: admin `gated()` →
`authority_public == False` on all four infra states (cold basis exactly
`["caller_tainted_authority_unresolved"]`); self-service `gated()` →
`authority_public == True` when cold. Reverting **either** Part A or Part B
re-opens the admin gate and fails `…_cold_fails_closed`.

## Appendix C — discriminator generality probe

Five real-compiled contracts spanning owner-setter / role-setter / pure-self /
open-register / mixed-writer (the §C table). Run the same `build_predicate_tree`
+ `apply_writer_gate_pass` and print `authority_role` per `privileged()`
comparison leaf; expect OwnerTier & RoleTier → `caller_authority`, PureSelf &
OpenRegister → `business`, MixedBalance → `caller_authority` (the documented
bounded fail-CLOSED FP). Observed on commit `3e59779`:

```
RoleTier       caller_authority   (genuine auth promoted)
MixedBalance   caller_authority   (bounded fail-CLOSED FP)
PureSelf       business           (self-service stays public)
OwnerTier      caller_authority   (genuine auth promoted)
OpenRegister   business           (self-acquirable stays public)
```
