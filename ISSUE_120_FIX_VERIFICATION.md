# Post-run verification spec — #120 (if/else `return true` polarity: AND all dominating deny-IF negations)

**Purpose.** A living acceptance-criteria doc for the fix to
`services/static/contract_analysis_pipeline/predicates.py :
_build_if_else_returns_or_children`. That builder lifts a bool-returning
authority provider's if/else chain (DSAuth/Solmate `isAuthorized`, denylist /
whitelist gates, custom `isAuthorized`) into an OR of per-path predicates that
resolution turns into a per-function capability verdict. The old code (a)
hard-coded `polarity=allowed_when_true` against the **closest** preceding IF —
inverting early-deny shapes — and (b) emitted an always-true `business` leaf when
no IF was found. Both are **fail-open polarity errors**: a guarded thing was
reported as (wrongly) allowed-iff-blocked, or as public. This doc says what to
observe on the **next full analysis run** to confirm the fix landed and did not
regress anything.

> **Status.** Branch `wt/issue-120`, fix commit **`eebb997`**
> (`fix(static/predicates): #120 if/else return-true polarity — AND all
> dominating deny-IF negations`). Committed locally, **not pushed**. Fill in
> PR # / preview URL when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state**. After the PR deploys to a preview env and
   the affected contracts are **re-analyzed + re-resolved**, confirm each check
   below against the preview artifacts / API and mark **PASS / FAIL**; report any
   FAIL with the actual observed value.
2. **This fix is NOT aggregation-only.** It changes the `predicate_trees`
   artifact emitted by the **static-analysis** stage. Existing `predicate_trees`
   rows in a DB were produced by the OLD code and still carry the buggy leaves
   until their job is **re-analyzed**; the corrected verdicts appear only after a
   fresh analysis + a resolution pass consumes the new trees. A pure
   re-aggregation (serving existing data) will show **no change** — that is
   expected, not a miss.
3. **Ground-truth caveat.** The load-bearing before→after is the **faithful
   per-shape corpus** in *Change 1 → Expected data* (each row is a real
   `solc 0.8.19` + real Slither + real `build_return_predicate_tree` run — see
   `tests/test_predicate_builder.py::test_issue120_*`). Run-level etherfi counts
   were **not** pre-enumerated (the affected shapes are contract-specific);
   **measure them on the actual run** with Appendix B and verify the *invariants*
   / *direction*, do not fail on an absolute count.
4. **The core safety invariant (this whole audit's theme):** the fix may only
   move a verdict in the **fail-closed / correct** direction — it must **never
   newly report a genuinely-guarded function as public/permissionless**, and must
   **never drop a real guard**. A denylist-only or permissionless gate correctly
   becoming public-minus-set is *correct semantics*, not a fail-open; a
   **positive-authority** gate (`hasRole` / `requiresAuth` / owner / a captured
   `require`/revert guard) turning public is the regression to hunt.

### Environment / how to query

- **Predicate trees (most deterministic):** the builder's output is stored as the
  per-job `predicate_trees` artifact
  (`db.queue.store_artifact(session, job_id, "predicate_trees", data={"trees": …})`),
  read back with `db.queue.get_artifact(session, job_id, "predicate_trees")`
  (transparently handles inline-Postgres vs object-storage bodies). Appendix B
  scans every such artifact for the structural invariants.
- **Resolution / surface verdict:** `resolve_contract_capabilities(session,
  address=…, chain_id=1, job_id=…)` → `out[sig]`, then
  `services.policy.capability_surface.project_capability_surface(cap)` +
  `capability_surface_status(cap, surface)` → `"public"` / not. This is the
  live-observable per-function verdict.
- **Faithful unit corpus:** `tests/test_predicate_builder.py::test_issue120_*`
  (compiles real Solidity through the real builder — reproduces the per-shape
  table exactly). Appendix A is a standalone probe on any `.sol` + function.
- **Real-pipeline E2E canaries:** `tests/test_cofinite_denylist_e2e.py` drives the
  real resolver → surface against committed real-etherfi fixtures.

### Global regression guards (apply to the whole change)

- CI green: `ruff check` / `ruff format --check` / `pyright` / offline `pytest`
  (`-m "not live"`) / frontend / diff-cover ≥ 70% on the PR.
- Live-tests job green (sticky comment header `psat-live-tests`).
- **Do not regress already-merged partial fixes:** #132 (earned-public), #134
  (assembly-only `unsupported` rows), #107 (deferred reconciler). The DSAuth /
  Solmate allow-chains and every positive-authority gate must be **byte-identical /
  status-identical** before→after (see canaries).
- The fix only ever **(i) narrows** a `return true` child (positive AND of all
  dominating guards) or **(ii) emits `unsupported`** (fail-closed). It never emits
  a lone public-minus-set (`falsy`/`ne`) child where a positive guard was dropped,
  and never an always-true `business` leaf.

---

## Change 1 — #120 `return true` polarity: AND all dominating deny-IF negations

- **Commit:** `eebb997` `fix(static/predicates): #120 if/else return-true polarity — AND all dominating deny-IF negations`
- **Branch / PR:** `wt/issue-120` → PR #____
- **Files:** `services/static/contract_analysis_pipeline/predicates.py`
  (`_build_if_else_returns_or_children` rewritten + CFG helpers
  `_node_terminates_control`, `_callee_always_reverts`,
  `_forward_reachable_node_ids`, `_branch_value_is_only_true`,
  `_node_has_unclassified_call`, `_guards_contain_opening`),
  `tests/test_predicate_builder.py` (10 co-land `test_issue120_*` cases).
- **What it does:** for each literal `return true` path of a bool authority
  provider, builds the **conjunction of every dominating guard** via CFG
  forward-reachability over all IFs in the function:
  - reachable from `IF.son_true` only → AND the condition **positively**
    (`allowed_when_true`);
  - reachable from `IF.son_false` only → the else / fall-through: if the true-son
    is an **allow** branch (`{True}`) → **skip** (that allow is its own OR-child;
    keeps DSAuth byte-identical); otherwise it is a **deny** → AND the **negation**
    (`allowed_when_false` → `falsy` membership);
  - reachable from both (post-join) / neither (off-path) → skip.
  Standalone `require(cond)`/`assert(cond)` a return **dominates** are ANDed as
  positive guards. `revert` / `throw` / `require(false)` / `assert(false)` **and a
  call to a provably always-reverting helper** are CFG **sinks** (their leaked
  structural `son`→ENDIF edge is cut) so a deny branch never leaks its guard.
  A `return true` with **no** attributable guard → **fail-closed**
  `unsupported<unattributable_return_true>` (never the old `business` leaf); an
  **unmodelable** dominating guard (IF/require whose condition doesn't model, or an
  unclassified mid-body call on the path) coexisting with a cofinite `falsy`/`ne`
  opening → **fail-closed** `unsupported` (never the lone public-minus-set child).
  Non-literal tail returns (`return expr`, e.g. DSAuth `return
  authority.canCall(...)`) are **unchanged** (deferred, §"Out of scope").

### Expected data — faithful per-shape corpus (real `solc 0.8.19` + Slither + builder)

Each row is a `tests/test_predicate_builder.py::test_issue120_*` case; "BEFORE" =
`main` (`_build_if_else_returns_or_children` closest-IF + empty-business-leaf).

| # | shape (auth provider body) | BEFORE (`main`) | AFTER (`eebb997`) | direction |
|---|---|---|---|---|
| 1 | `if(blocked[s]) return false; return true;` | `membership:truthy[blocked]` (allowed ⇔ s∈blocked — **inverted**) | `membership:falsy[blocked]` (allowed ⇔ s∉blocked) | inversion FIXED |
| 2 | `if(a[s]) return false; if(b[s]) return false; return true;` | `membership:truthy[b]` (drops `!a`, **fabricates** access for a) | `AND(falsy[a], falsy[b])` | **no fabrication** |
| 3 | `return true;` (no IF) | `comparison:truthy business` operands=[] (**public**) | `unsupported<unattributable_return_true>` | fail-closed |
| 4 | verbatim Maker `DSAuth.isAuthorized` (this / owner / authority==0→false / else canCall) | `OR(eq[this], eq[owner], external_bool:truthy[canCall])` | **identical** | **byte-identical** |
| 5 | `if(a[s]) return true; if(b[s]) return false; return true;` | `OR(truthy[a], truthy[b])` (**wrong** tail) | `OR(truthy[a], falsy[b])` = a ∨ ¬b | correct |
| 6 | `if(!auth[s]) revert(); if(b[s]) return false; return true;` | `falsy[b]` = **public minus b** (drops `!auth`) | `AND(truthy[auth], falsy[b])` | no fabrication |
| 7 | `require(wl[s]); if(bl[s]) return false; return true;` | `falsy[bl]` = **public minus bl** (drops `require(wl)`) | `AND(truthy[wl], falsy[bl])` | no fabrication |
| 8 | `if(!authA[s]) revert(); if(!authB[s]) revert(); return true;` | (both guards leak) | `AND(truthy[authA], truthy[authB])` | recall + no fabrication |
| 9 | `if(!auth[s]) revert(); return true;` | (revert misread as allow) | `membership:truthy[auth]` | correct |
| 10 | `if(!auth[s]) _deny(); if(b[s]) return false; return true;` (`_deny` reverts; internal/library) | `falsy[b]` = **public minus b** | `AND(truthy[auth], falsy[b])` | no fabrication |
| 11 | `if(!auth[s]) g.enforce(s); …` (external, revert unprovable) | `falsy[b]` = **public minus b** | `unsupported` (fail-closed backstop) | fail-closed |

**Real-data anchors (byte-identical regression bar):**
- Verbatim Maker **`DSAuth.isAuthorized`** (ds-auth, deployed at thousands of
  addresses): `OR(eq[this], eq[owner], external_bool:truthy[canCall])` →
  **BEFORE == AFTER, byte-identical** (its `return true` paths are `son_true`
  allows, so they stay positive equalities; the dropped null-authority guard
  leaves `canCall` an external_bool — the deferred non-literal shape, untouched).
- Repo fixture `tests/fixtures/contracts/composed/auth_modifier_controller.sol`
  (genuine Solmate `Auth.isAuthorized`, expression form) → **BEFORE == AFTER**
  (non-literal path untouched).

### Expected data — resolution / surface (real-pipeline E2E canaries)

`tests/test_cofinite_denylist_e2e.py` (real resolver → surface on committed real
etherfi fixtures). These pin the **polarity boundary** the fix must not cross:

| function | gate shape | expected status | why |
|---|---|---|---|
| `NodeOperatorManager.registerNodeOperator` | `require(!registered[caller])` (denylist-only) | **public** | permissionless self-registration; cofinite → open |
| `BoringVault.transfer` / `transferFrom` | inlined Teller `beforeTransfer` denylist | **public** (`cofinite_blacklist`, denylist surfaced as `conditions`) | denylist-only gate |
| `WeETH.recoverERC20/721/ETH` | `if(!hasRole(...)) revert` (positive) | **NOT public** (gated) | positive role gate — polarity boundary |
| `RolesAuthority.setUserRole` | Solmate `requiresAuth` (positive `canCall`/owner) | **NOT public** | positive gate |
| `Accountant` admin (`updateExchangeRate`, …) | Solmate `requiresAuth` | **NOT public** | positive gate |

### Detailed invariants (verify each)

**A. The old always-true business leaf is GONE.** No leaf anywhere in any
re-analyzed `predicate_trees` artifact carries `basis` containing
`"literal_true_return"` (the marker of the old `authority_role="business",
operator="truthy", operands=[]` leaf). Post-fix that path is
`unsupported<unattributable_return_true>`. → Appendix B `literal_true_return` == 0.

**B. New fail-closed rows are the safe direction (public → gated).** Every no-IF /
unattributable `return true` now yields `unsupported_reason ==
"unattributable_return_true"`. Its count ≥ 0 and is purely a
**public→gated/degraded** move (safe). → Appendix B lists them.

**C. No fabricated lone opening.** For any `return true` child that the builder
constructed with a *positive* dominating guard (an `IF.son_true` edge, a
`require`, or a revert/helper-sink negation), the resulting AND contains that
positive `truthy` conjunct — a cofinite `falsy`/`ne` never survives **alone** when
a positive guard existed on its path. (A **lone** cofinite `falsy` is *only* legit
for a genuine denylist-only / permissionless provider, e.g. shape 1 or
`registerNodeOperator` — Appendix B lists lone-cofinite trees for denylist-legit
review, it is **not** an automatic fail.)

**D. Multi-deny ANDs every negation.** A provider with N dominating deny-IFs
yields an AND of N `falsy` conjuncts (shape 2: `AND(falsy[a], falsy[b])`), never a
single deny's `falsy` alone. No principal in an earlier deny set is re-admitted.

**E. DSAuth / Solmate allow-chains and positive gates unchanged.** Shape 4/5 and
the four E2E positive-gate canaries are byte-identical / status-identical
before→after: no manufactured `falsy`, no `unsupported` introduced, no
gated→public flip.

**F. Direction of any status flip.** Re-resolving the corrected trees may flip a
**denylist-only / permissionless** provider gated(inverted-finite)→public — that
is the *correct* semantics (shapes 1, 2 project to public-minus-set). Every
gated→public flip must be a genuine denylist/permissionless gate; **zero**
positive-authority gates flip to public.

### How to verify

1. **Unit corpus (deploys nothing):** run
   `tests/test_predicate_builder.py::test_issue120_*` on the deployed code — all
   10 pass ⇒ the per-shape table above holds (real compile + real builder).
2. **Real-pipeline E2E:** run `tests/test_cofinite_denylist_e2e.py` — the denylist
   headline stays `public`; the three positive-gate canaries stay non-public
   (invariant E). This is the resolution → surface end-to-end check.
3. **Live artifacts (after re-analysis):** run **Appendix B** against the target DB.
   Assert: `literal_true_return` leaves **== 0** (invariant A); every
   lone-cofinite tree it lists is a real denylist/permissionless provider
   (invariant C/F — spot-check with Appendix A / on-chain); note the
   `unattributable_return_true` count (invariant B, informational).
4. **Before/after status diff (strongest run-level check):** capture
   `capability_surface_status` per `(address, sig)` on the pre-fix run and the
   re-analyzed run; assert **no positive-authority gate flips gated→public**
   (invariant F). Every gated→public flip must resolve to `kind ==
   "cofinite_blacklist"` / a denylist-only or permissionless gate.
5. **Spot-reproduce any suspect provider:** feed its verified source + the
   provider function name to **Appendix A** and read the leaf polarity directly.

### Regression signals — FAIL if any of these

- A **positive-authority** gate (`hasRole` / `requiresAuth` / owner / a captured
  `require`/revert/helper guard) newly resolves **public** — a real guard was
  dropped (the exact fail-open this audit targets). E.g. an E2E canary
  (WeETH.recover / RolesAuthority.setUserRole / Accountant admin) goes `public`.
- Any tree contains a **lone** cofinite `falsy`/`ne` child whose provider is **not**
  a genuine denylist-only / permissionless gate (a dropped positive guard).
- Any leaf still carries `basis ⊇ {"literal_true_return"}` or an always-true
  `business` `operands=[]` leaf survives (invariant A violated — old code path).
- A **multi-deny** provider emits a single deny's `falsy` instead of the AND of all
  (`AND(falsy[a], falsy[b])`) — a re-admitted denied principal (invariant D).
- **DSAuth / Solmate** allow-chain changed (a manufactured `falsy`, an
  `unsupported`, or a lost equality) — the byte-identical bar broke (#132/#134).
- A previously-resolved capability **disappears** or a real controller/principal is
  **dropped** (a narrowing that removed a genuine right rather than a fabricated one).

### On-chain / cross-source sanity (recommended, not required)

For any provider that flips gated→public, confirm on-chain that the gate really is
a **denylist / permissionless self-service** (anyone not on a blocklist may call)
and not a positive allowlist/role gate: read the gating state var (the
`blocked`/`registered`/`denylist` mapping) and confirm the function's modifier /
body has no positive `hasRole` / `onlyOwner` / `requiresAuth` guard. If a flipped
function turns out to have a real positive guard the builder failed to capture,
that is a fail-open regression (invariant F) — not acceptable.

### Known follow-ups carried by this change (not regressions)

- **Non-literal tail return after a deny-IF** (`if(blocked[x]) return false; return
  hasRole[x];`) is **DEFERRED** and left exactly as `main` behaves (the non-literal
  Return branch is untouched). It is a real, **pre-existing** fail-open in a
  distinct sub-shape (non-literal return expression, not a literal-polarity bug),
  in direct tension with the byte-identical-DSAuth bar (DSAuth `else return
  authority.canCall(...)` is this shape). Verified BEFORE == AFTER on
  `denyThenRole`. Tracked separately; not part of #120.

---

## Out of scope / open (track here; not regressions)

- **Run-level etherfi counts.** The set/number of etherfi functions whose verdict
  changes is contract-specific and **not** pre-computed here — DSAuth/Solmate are
  byte-identical or non-literal (untouched), so the observable delta may be small.
  Measure it on the actual run (Appendix B + the before/after status diff); do not
  treat a small or zero delta as a miss.
- **The deferred non-literal-tail fail-open** (above) — a separate design that
  preserves the byte-identical-DSAuth bar (negate only data/ACL deny-IFs, not
  null-authority revert guards).

---

## Appendix A — predicate-tree probe (`probe_120.py`)

Compiles a Solidity source and prints the flattened `build_return_predicate_tree`
leaves for one function — reproduces the per-shape table on any faithful input.

```python
"""Probe the #120 predicate builder on a single provider function.
Usage: PYTHONPATH=<repo> python probe_120.py <file.sol> <functionName>
"""
import sys
from slither import Slither
from services.static.contract_analysis_pipeline.predicates import build_return_predicate_tree

sl = Slither(sys.argv[1])
fn = next(f for c in sl.contracts for f in c.functions if f.name == sys.argv[2])
tree = build_return_predicate_tree(fn)


def leaves(t):
    if not isinstance(t, dict):
        return
    if t.get("op") == "LEAF":
        yield t.get("leaf") or {}
    else:
        for ch in t.get("children") or []:
            yield from leaves(ch)


print("top op:", (tree or {}).get("op"))
for le in leaves(tree):
    print(
        {
            "kind": le.get("kind"),
            "operator": le.get("operator"),
            "storage_var": (le.get("set_descriptor") or {}).get("storage_var"),
            "authority_role": le.get("authority_role"),
            "unsupported_reason": le.get("unsupported_reason"),
            "basis": le.get("basis"),
        }
    )
```

## Appendix B — live `predicate_trees` invariant scan (`scan_120.py`)

Scans every `predicate_trees` artifact in a DB and reports the #120 invariants.
Run against the **re-analyzed** target DB (old artifacts still carry buggy leaves).

```python
"""Scan predicate_trees artifacts for the #120 invariants.
Usage: PYTHONPATH=<repo> DATABASE_URL=<target> python scan_120.py
Reports: (A) literal_true_return leaves must be 0; (B) unattributable_return_true
count (public->gated, informational); (C) lone-cofinite trees for denylist review.
"""
from db.models import Artifact, SessionLocal
from db.queue import get_artifact


def leaves(t):
    if not isinstance(t, dict):
        return
    if t.get("op") == "LEAF":
        yield t.get("leaf") or {}
    else:
        for ch in t.get("children") or []:
            yield from leaves(ch)


literal_true = []          # (A) must be empty
unattributable = 0         # (B) informational (public -> gated)
lone_cofinite = []         # (C) manual denylist-legit review

with SessionLocal() as s:
    rows = s.query(Artifact.job_id).filter(Artifact.name == "predicate_trees").all()
    for (job_id,) in rows:
        art = get_artifact(s, job_id, "predicate_trees") or {}
        trees = (art.get("trees") if isinstance(art, dict) else None) or {}
        for sig, tree in trees.items():
            ls = list(leaves(tree))
            for le in ls:
                if "literal_true_return" in (le.get("basis") or []):
                    literal_true.append((str(job_id), sig))
                if le.get("kind") == "unsupported" and le.get("unsupported_reason") == "unattributable_return_true":
                    unattributable += 1
            has_falsy = any(le.get("kind") == "membership" and le.get("operator") in ("falsy", "ne") for le in ls)
            has_truthy = any(le.get("kind") == "membership" and le.get("operator") == "truthy" for le in ls)
            if has_falsy and not has_truthy:
                lone_cofinite.append((str(job_id), sig))

print(f"(A) literal_true_return leaves (MUST be 0): {len(literal_true)}")
for r in literal_true[:50]:
    print("    ", r)
print(f"(B) unattributable_return_true unsupported leaves (public->gated, info): {unattributable}")
print(f"(C) lone-cofinite trees (review each is a real denylist/permissionless gate): {len(lone_cofinite)}")
for r in lone_cofinite[:100]:
    print("    ", r)
```

> Note: (A) is a hard PASS/FAIL (must be 0). (B) is informational — a higher count
> just means more no-IF providers correctly fell to gated. (C) is a **review list**,
> not a failure: a lone cofinite is legitimate for a real denylist-only /
> permissionless gate (e.g. `registerNodeOperator`); confirm each entry's provider
> has no dropped positive guard (Appendix A / on-chain), per invariant C/F.
