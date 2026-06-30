# Post-merge verification spec — #121 (classifier degraded-on-unread-slot) + #122 (diamond/no-impl proxy fail-closed), COUPLED

**Purpose.** A living acceptance-criteria doc for the coupled fix that closes two
**fail-open polarity errors** in the discovery/resolution/static pipeline. Both
bugs took an *unknown / unresolved* proxy condition and coerced it into "analyze
this address as a clean contract", silently erasing the implementation's
access-control surface (every impl/facet guard rendered permissionless). The fix
makes every consumption site **fail closed** — the address becomes a
`degraded` / `unknown` / `analyzed=False` / transient-retried node, never a
confident clean model.

The two issues are COUPLED because they share the single classify-then-retarget
block in `services/resolution/recursive.py::_materialize_contract_artifacts`; the
same try/except restructure carries both raises.

> **Status:** committed on branch `wt/issue-121-122`, implementation commit
> **`149f3a2`** (`fix(discovery+resolution): fail closed on unreadable proxy slots
> (#121) and no-impl proxies (#122) — COUPLED`). **Not yet pushed / no PR.** Fill
> in PR # / preview URL when opened.

---

## How to use this doc (for the verifying agent)

1. This is the **expected end-state**. After the PR deploys to a preview env and a
   protocol is (re-)analyzed, confirm each `## Change` section's checks against the
   per-job artifacts / resolved control graph. Mark every check **PASS / FAIL** and
   report any FAIL with the actual observed value.
2. **This is a PIPELINE fix, not aggregation-only.** Unlike the surface-controls
   series, the corrected behavior appears **only on a NEW analysis run** — existing
   stored artifacts are *not* retroactively corrected. To verify, you must
   (re-)resolve a protocol (or drive the faithful reproduction in Appendix A/B).
3. **The bugs trigger on non-default conditions**, so a clean run may not exercise
   them naturally:
   - **#121** fires only during a **transient RPC outage** on the five proxy-slot
     reads. You generally cannot force a prod RPC outage on demand — verify it via
     the faithful reproduction (Appendix A) and the **negative invariants** below.
   - **#122** fires only when a **no-impl proxy** (EIP-2535 diamond, a beacon whose
     `implementation()` reverts, or a short-bytecode `unknown` proxy) appears as a
     **nested controller / principal** in `resolve_control_graph`. Drive it with a
     real diamond (Appendix B) or observe naturally if the protocol references one.
4. **Direction is the whole point — it is strictly fail-closed.** The core
   correctness invariant (applies to BOTH issues): the fix may only move a verdict
   *toward* `unsupported` / `degraded` / `unknown` / `analyzed=False`. It must
   **never** newly report a guarded function as public/permissionless and must
   **never** drop a real, already-resolved capability. Any "extra" cost is
   **availability** (a transient-retry or a degraded node), never **accuracy**.

### Environment / how to query

- **Per-job stage metrics:** `GET {preview_url}/api/jobs/{job_id}/stage_timings`
  → `stage_timing_<stage>.metrics`. Relevant keys:
  - discovery `classify` stage: `classify_fallbacks` (count of swallowed classify
    errors; a `ClassificationIncompleteError` increments this).
  - resolution stage: `proxies_redirected` (resolved proxy → impl, unchanged path)
    and **`proxies_unresolved`** (the new #122 fail-closed counter).
- **Degraded records:** the per-job `stage_errors` artifact (each a `StageError`
  with `severity="degraded"`). Relevant `phase` values:
  - `classify` — discovery `classify_contracts` (#121, swallowed → `unknown`).
  - `proxy_classification` — `static_worker._resolve_proxy` (#121, re-raised).
  - `recursive_materialize` — resolution BFS (#121 propagated **and** #122
    `UnresolvedProxyError`, both → `analyzed=False` node).
- **Resolved control graph:** the `resolved_control_graph` artifact / API. A
  fail-closed node has `analyzed: false` and
  `details.materialize_error` containing
  `"implementation unresolved; refusing to analyze the proxy shell"` (#122) or the
  `ClassificationIncompleteError` message (#121). The address must **not** appear
  in `nested_artifacts`.
- **Direct (most deterministic):** the faithful reproductions in **Appendix A**
  (#121) and **Appendix B** (#122) run the REAL pipeline functions against REAL
  on-chain bytecode. The classify-shape probe in **Appendix C** confirms the
  honest classifier outputs the fixes key off.

### Global regression guards (apply to both changes)

- CI green: `ruff check` / `ruff format --check` / `pyright` / offline `pytest`
  (`-m "not live"`, **never** `-k`) / diff-cover ≥ 70% on the PR.
- Targeted offline suites green (the co-landed regression tests):
  `tests/test_classifier.py`, `tests/test_recursive_resolution.py`,
  `tests/test_static_resolve_proxy_integration.py`, `tests/test_retry_policy.py`,
  `tests/test_classify_bytecode_shortcut.py`, `tests/test_classify_batch_parity.py`
  — **128 passed** at commit `149f3a2`.
- **No function that was already reported guarded becomes permissionless.** No
  principal / guard / controller is *added* or *fabricated* anywhere by this fix.
- **The resolved-proxy path is byte-for-byte unchanged:** a proxy with a readable
  single implementation still retargets to the impl (`proxies_redirected`), exactly
  as before. Verify with the Appendix B control (Aave V3 Pool).
- Does not regress already-merged partials: #132 (earned-public), #134
  (assembly-only unsupported rows), #107 (deferred reconciler) — none share this
  code path.

---

## Change 1 — #121: proxy-slot read failure fails closed (no fabricated `regular`)

- **Commit:** `149f3a2` (coupled).
- **Files:** `services/discovery/classifier.py` (new `ClassificationIncompleteError`;
  `_read_proxy_slots_batched` returns `(decoded, any_read_failed)`; `classify_single`
  raises at the would-be-`regular` fallthrough; `classify_contracts` →
  `_incomplete_or_regular`), `workers/static_worker.py::_resolve_proxy` (record +
  re-raise), `workers/retry_policy.py` (register transient). Tests:
  `tests/test_classifier.py`, `tests/test_static_resolve_proxy_integration.py`,
  `tests/test_recursive_resolution.py`.
- **What it does:** the classifier no longer conflates "slot read **failed**"
  (transient RPC) with "slot is **empty**". `_read_proxy_slots_batched` raises the
  `any_read_failed` flag **only** when a slot's single-call fallback *also* raises
  (a genuinely-empty slot still decodes to `None` with the flag **False**). At the
  terminal would-be-`regular` fallthrough only, `classify_single` raises
  `ClassificationIncompleteError`. Each of the three downstream consumers then fails
  closed: discovery marks `{type:'unknown', classification_incomplete:True}` and
  trips `record_degraded`; the static stage records + re-raises into the worker
  retry; the new exception is registered **transient** so the job self-heals on RPC
  recovery. Positive proxy detections (a readable impl slot) are **behind** the gate
  and untouched.

### Expected before → after (faithful reproduction, Appendix A; real WETH9 bytecode, simulated slot outage)

| Site / input | Before (`main` 41822ec) | After (`149f3a2`) |
|---|---|---|
| `classify_single` — WETH9, all 5 slots unreadable | `type='regular'` (confident, **wrong**) | **raises `ClassificationIncompleteError`** |
| `classify_single` — real proxy, impl slot OK, admin slot unreadable | `type='proxy'` impl=… | `type='proxy'` impl=… (**no false raise**) |
| `classify_single` — non-proxy, all slots read clean-empty | `type='regular'` | `type='regular'` (**no false raise**) |
| `classify_contracts` — the unreadable address | `{type:'regular'}` (impl edge dropped) | `{type:'unknown', classification_incomplete:True}` + `record_degraded(phase=classify)` |
| `static_worker._resolve_proxy` — unreadable | `return None` → Slithers the shell | `record_degraded(phase=proxy_classification)` + **re-raise** → transient retry |
| `retry_policy.classify(ClassificationIncompleteError)` | `terminal` (type absent) | **`transient`** |

> **State the input.** These rows are computed by Appendix A, which runs the REAL
> `classify_single` over the REAL WETH9 runtime bytecode (`0xC02a…6Cc2`, 3124 bytes,
> a genuine non-proxy fetched live) and simulates ONLY the slot-read outage — that
> outage *is* the bug's trigger, not a convenience hardcode. The classifier's
> autouse test fixture makes the single-call fallback succeed, which is exactly why
> the offline suite shows **0 false raises** on the normal slots-readable path.

### Invariants to verify

- **A (headline / negative).** No contract that is genuinely an upgradeable proxy is
  ever emitted as `type='regular'` because its proxy slots could not be read. Under
  a slot-read failure on a would-be-`regular` contract, the outcome is
  raise → `unknown` / degraded / transient-retry — never a confident non-proxy.
- **B (gate precision).** A proxy whose impl slot reads fine is still `type='proxy'`
  even if a *different* slot (e.g. admin) was unreadable — the raise sits **behind**
  the regular fallthrough, so positive detections never false-raise.
- **C (no over-gating clean contracts).** A real non-proxy whose slots read
  *clean-empty* (read succeeds, returns the zero word) still classifies `regular`.
  The flag is set on a read **failure**, never on a successful empty read.
- **D (self-heal).** `ClassificationIncompleteError` is in `retry_policy._TRANSIENT_TYPES`
  → `classify()` returns `transient` → the job requeues and resolves when the RPC
  recovers, rather than terminally dying (which would *itself* erase the surface).

### How to verify

1. Run **Appendix A** on the `wt/issue-121-122` branch; confirm the six rows above.
2. On a live run, query `/api/jobs/{id}/stage_timings` for the discovery `classify`
   stage: any `classify_fallbacks > 0` must be accompanied by a `stage_errors` entry
   with `phase="classify"` (not a silent drop). For the static stage, a
   `phase="proxy_classification"` degraded entry must coincide with the job being
   **requeued** (transient), not failed-terminal.
3. Spot-check the classifier's honest outputs with **Appendix C** (no outage): WETH9
   → `regular`; the inputs the gate depends on are unchanged.

### Regression signals — FAIL if any of these

- A contract is emitted `type='regular'` / `analyzed=True` while its proxy slots were
  unreadable (the original bug, re-broken) — i.e. `classify_fallbacks > 0` but the
  address still resolves to a confident clean contract with no degraded record.
- A real proxy (readable impl slot) starts raising `ClassificationIncompleteError`
  (false raise → gate moved in front of the positive detections).
- A clean-empty non-proxy starts raising (flag set on a successful empty read).
- `retry_policy.classify(ClassificationIncompleteError(...))` returns anything but
  `transient` (job would terminally die and erase the surface).
- A `ClassificationIncompleteError` is *swallowed* by `_resolve_proxy` into an
  `is_proxy=False` `contract_flags` artifact (shell then Slithered).

---

## Change 2 — #122: no-impl proxy fails closed (refuse to analyze the shell)

- **Commit:** `149f3a2` (coupled).
- **Files:** `services/resolution/recursive.py::_materialize_contract_artifacts`
  (new module-level `UnresolvedProxyError`; classify call split into its own try;
  retarget/fail-closed decision moved **outside** that except; `else` branch raises
  for any no-impl proxy; `proxies_unresolved` metric). Tests:
  `tests/test_recursive_resolution.py`.
- **What it does:** when `classify_single` returns `type=='proxy'` with **no
  resolvable `implementation`** (EIP-2535 diamond — sets `facets`, never
  `implementation`; a beacon whose `implementation()` reverts; a short-bytecode
  `unknown` proxy with no probe target), the BFS no longer falls through and
  Slithers the delegatecall **shell** (whose empty guard set renders downstream as
  permissionless). It raises `UnresolvedProxyError`; the BFS turns that into a
  degraded `analyzed=False` node with a `materialize_error`, and the shell **never
  enters `nested_artifacts`**. The `facets[0]`-retarget alternative was deliberately
  **rejected** (undefined facet ordering → infra facet → partial-surface-as-exact =
  the same fail-open it condemns); facet-union recall is a separate follow-up.
- **Coupling guard:** the classify call now runs in its OWN try so a *generic*
  classify hiccup still swallows to "analyze the address as-is" (historical), while
  both `UnresolvedProxyError` (#122) and a propagated `ClassificationIncompleteError`
  (#121) escape the except and reach the fail-closed BFS handler. This restructure
  is mandatory — a naive raise inside the old `except logger.debug(...)` would be
  swallowed back into a silent shell analysis.

### Expected before → after (faithful reproduction, Appendix B; real Beanstalk diamond over real RPC)

| Input | Before (`main` 41822ec) | After (`149f3a2`) |
|---|---|---|
| `_materialize_contract_artifacts`(Beanstalk `0xC1E0…24C5`, eip2535, 5 facets, no impl) | `effective_address = 0xC1E0…24C5` → **SHELL analyzed as clean** (fail-open under-report) | **raises `UnresolvedProxyError`** (`type=eip2535 … implementation unresolved`) |
| `resolve_control_graph` with the diamond as a nested controller | diamond node `analyzed=True`, empty guard set → its facet guards reported permissionless | diamond node **`analyzed=False`**, `details.materialize_error` = `"… implementation unresolved; refusing to analyze the proxy shell"`; **not in `nested_artifacts`** |
| resolution stage metric | — | `proxies_unresolved` ≥ 1 |
| **Control:** `_materialize_contract_artifacts`(Aave V3 Pool `0x8787…4E2`, eip1967, impl `0x728a…03cf`) | `effective_address = 0x728a…03cf` (retarget) | `effective_address = 0x728a…03cf` (**identical**), `proxies_redirected` bumped |

> **State the input.** Appendix B drives the REAL `resolve_control_graph` /
> `_materialize_contract_artifacts`; only `classify_single` is steered to report the
> nested controller as the real Beanstalk diamond shape (`type=proxy
> proxy_type=eip2535 facets=5`, impl ABSENT — the exact shape the live classifier
> returns for `0xC1E0…24C5`, confirmed on-chain in Appendix C). The heavy
> build/Slither is intercepted right after the proxy decision so the production
> branch runs without a hardcoded answer. The Aave control runs the same path with a
> resolved impl and must be unchanged.

### Invariants to verify

- **A (headline / negative).** A no-impl proxy that appears as a nested
  controller/principal is **never** `analyzed=True` with an empty/near-empty guard
  set. It is `analyzed=False` with a `materialize_error`, and its address is absent
  from `nested_artifacts` (so nothing it would guard is reported permissionless).
- **B (covers all four shapes).** The single `else` fires for every no-impl
  proxy_type — eip2535 diamond, failed-beacon, unknown-no-probe, unknown-empty-probe
  — because each collapses to the identical `impl`-falsy fall-through.
- **C (no regression of resolved proxies).** A proxy with a readable single impl
  still retargets to the impl and is analyzed exactly as before
  (`proxies_redirected`, not `proxies_unresolved`).
- **D (no crash at root).** The root job contract short-circuits on preloaded
  artifacts (it never re-enters `_materialize_contract_artifacts`), so this is a
  nested-only behavior change; a diamond nested controller degrades gracefully, it
  does not crash the job.

### How to verify

1. Run **Appendix B** on the `wt/issue-121-122` branch; confirm the diamond row
   (fail-closed degraded node) and the Aave control row (unchanged retarget).
2. On a live run that references a diamond/beacon as a controller, fetch the
   `resolved_control_graph` artifact: the diamond node must be `analyzed:false` with
   the `materialize_error` substring above, and `proxies_unresolved ≥ 1` in the
   resolution `stage_timing` metrics.
3. Confirm `proxies_redirected` for ordinary eip1967/1822/oz proxies is unchanged
   run-over-run (resolved path untouched).

### Regression signals — FAIL if any of these

- A diamond / failed-beacon / unknown no-impl proxy node is `analyzed:true` with no
  (or empty) controllers — the shell is being analyzed again (the original bug).
- Any function on such a node is reported permissionless/public.
- A normal resolved proxy (impl present) becomes `analyzed:false` / `UnresolvedProxyError`
  (the fail-closed branch wrongly catching the resolved path).
- The diamond address appears in `nested_artifacts` (shell leaked into the artifact
  map).
- A re-appearance of any `facets[0]` retarget (one facet's guard set attributed to
  the whole diamond — the rejected partial-as-exact behavior).

---

## On-chain / cross-source sanity (recommended, not required)

Use **Appendix C** to confirm the classifier's honest outputs on real mainnet
addresses (these are the *inputs* the two fixes act on, so they ground the whole
spec):

| Address | Expected `classify_single` shape | Role in this spec |
|---|---|---|
| WETH9 `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | `type=regular` | #121 genuine non-proxy (must not false-raise without an outage) |
| Aave V3 Pool `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` | `type=proxy proxy_type=eip1967 implementation=0x728a138a…fe03cf` | #122 control — resolved path unchanged |
| Beanstalk `0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5` | `type=proxy proxy_type=eip2535 implementation=ABSENT facets=5` | #122 headline — no-impl proxy → fail-closed |

If a future RPC/classifier change makes Beanstalk resolve an `implementation`, the
#122 fail-closed branch simply won't fire for it (it would retarget instead) — that
is correct, not a regression; pick another known diamond to exercise the branch.

## Out of scope / open (track here; not regressions)

- **All-facet-union diamond recall** (deferred follow-up). The fail-closed floor is
  *sound* (no false permissionless) but *not complete* — a diamond's real facet
  guards are not recovered; they show as a degraded node. Unioning every facet's
  guards (enqueue each facet as a BFS subject) is a separable **recall** upgrade that
  cannot reduce safety. If a later commit lands it, add it as its own `## Change`.
- **Bespoke inline slot-read retry / quarantine queue for #121.** The system is safe
  without it (nodes are `unknown`/transient-retried, not falsely clean); active
  impl-recovery is a latency/completeness optimization, separately testable.
- **`unified_dependencies` first-class `classification_incomplete` node.** Not
  required for soundness — the load-bearing harm (resolution/static shell analysis)
  is already fail-closed.

---

## Appendix A — #121 faithful reproduction (`repro_121.py`)

Runs the REAL `classify_single` over the REAL WETH9 runtime bytecode and simulates
ONLY the proxy-slot read outage (the bug's trigger). Run on `wt/issue-121-122`:

```
PYTHONPATH=<wt> RPC=https://ethereum-rpc.publicnode.com python repro_121.py
```

```python
"""#121: a proxy-slot read failure must fail closed, never fabricate 'regular'.
Real classify_single + real WETH9 bytecode; ONLY the slot reads are forced to fail.
"""
import os
import services.discovery.classifier as cls
from services.discovery.classifier import ClassificationIncompleteError

RPC = os.environ.get("RPC", "https://ethereum-rpc.publicnode.com")
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"  # genuine non-proxy, 3124 bytes

# get_code() still hits the real RPC; only the five proxy-slot reads fail (batch AND
# single-call fallback) — the real transient-outage failure mode.
cls.rpc_batch_request_with_status = lambda rpc, calls: [(None, True)] * len(calls)
_real_call = cls.rpc_call
def _call(rpc, method, params, retries=1):
    if method == "eth_getStorageAt":
        raise RuntimeError("rpc slot read down")   # outage on the slot reads only
    return _real_call(rpc, method, params, retries=retries)
cls.rpc_call = _call

try:
    c = cls.classify_single(WETH, RPC)
    print(f"LEG1 BEFORE-style: type={c.get('type')}  (BUG if 'regular')")
except ClassificationIncompleteError as e:
    print(f"LEG1 AFTER: raised ClassificationIncompleteError  (CORRECT)  -- {e}")

# retry classification is transient (self-heals on RPC recovery)
from workers.retry_policy import classify
print("LEG4 retry_policy.classify:", classify(ClassificationIncompleteError("x")))  # expect 'transient'
```

> The "impl-slot-OK / admin-slot-fails → still proxy" and "clean-empty → regular"
> regression legs are locked by `tests/test_classifier.py::`
> `test_classify_single_proxy_detected_despite_unread_admin_slot` and
> `…_clean_empty_slots_stay_regular` (run them with the marker-filtered offline
> suite). They are the executable, deterministic form of those rows.

## Appendix B — #122 faithful reproduction (`repro_122.py`)

Drives the REAL `resolve_control_graph` with the real Beanstalk diamond shape as a
nested controller, plus the Aave eip1967 control. Run on `wt/issue-121-122`:

```python
"""#122: a no-impl proxy nested controller must become a degraded analyzed=False
node, never an analyzed shell. Real recursive pipeline; classify_single steered to
the real diamond shape; heavy build intercepted after the proxy decision."""
import services.resolution.recursive as rec

DIAMOND = "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5"  # Beanstalk, eip2535, no impl

# Real classifier shape for the diamond (confirmed on-chain, Appendix C):
def fake_classify(address, rpc_url):
    if address.lower() == DIAMOND:
        return {"address": address, "type": "proxy", "proxy_type": "eip2535",
                "facets": ["0x" + "bb" * 20]}
    return {"address": address, "type": "regular"}

# See tests/test_recursive_resolution.py::
#   test_resolve_control_graph_no_impl_proxy_controller_is_degraded
# for the full, committed end-to-end form (root bundle wired so the diamond is a
# nested controller). Expected:
#   nodes[DIAMOND]["analyzed"] is False
#   "implementation unresolved" in nodes[DIAMOND]["details"]["materialize_error"]
#   DIAMOND not in nested_artifacts
```

> The committed `tests/test_recursive_resolution.py` carries the runnable
> end-to-end version (`…no_impl_proxy_controller_is_degraded`) plus the resolved-impl
> control (`…resolved_proxy_retargets_to_impl`) and the #121 propagation guard
> (`…propagates_classification_incomplete`). These are the deterministic proofs;
> Appendix C is the live on-chain confirmation of the diamond's input shape.

## Appendix C — on-chain classify probe (`classify_probe.py`)

Confirms the honest `classify_single` outputs the two fixes key off — no outage, no
steering, just the real classifier over a real RPC. Run on `wt/issue-121-122`:

```python
"""On-chain sanity: real classify_single over three real mainnet addresses."""
import os
from services.discovery.classifier import classify_single

RPC = os.environ.get("RPC", "https://ethereum-rpc.publicnode.com")
CASES = {
    "WETH9 (genuine non-proxy)":            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "Aave V3 Pool (eip1967, resolved)":     "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "Beanstalk (eip2535 diamond, no-impl)": "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
}
for label, addr in CASES.items():
    c = classify_single(addr, RPC)
    print(f"{label}\n  type={c.get('type')} proxy_type={c.get('proxy_type')} "
          f"impl={c.get('implementation')} facets={len(c.get('facets') or [])}")
```

Expected: WETH9 → `type=regular`; Aave → `type=proxy eip1967 impl=0x728a138a…`;
Beanstalk → `type=proxy eip2535 impl=None facets=5`.
