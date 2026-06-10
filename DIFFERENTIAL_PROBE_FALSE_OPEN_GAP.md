# Known limitation: the differential probe is blind to false-opens

**Status:** known gap, not yet fixed. The differential probe (see
`DIFFERENTIAL_PROBE_IMPLEMENTATION.md`) drives the *false-gate* direction toward
zero with on-chain proof, but it **structurally cannot catch false-opens** — and
false-opens are the dangerous direction. This document explains why, gives the
current numbers, lists the offending functions, and records exact
reproduce/verify steps so the next person (likely future-you) can pick it up.

All numbers below were measured on branch `fix/open-function-false-opens` against
the 56-contract / 711-row labeled corpus; the on-chain checks ran against the eRPC
mainnet archive route around block 25290093.

---

## 1. The limitation in one paragraph

A **false-open** is a function the static pipeline classifies as **public**
(`conditional_universal`) when the deployed contract actually gates it. The
differential probe only ever runs on the **"gated, principals unknown"** queue
(`external_check_only`) — that is its trigger (`_should_differential_probe`). A
false-open has already escaped into the *public* bucket before the probe runs, and
the probe never inspects that bucket. So it can't catch what it never looks at.
This is a **scope** problem, not a capability problem: the same probe, aimed at the
public set, *would* catch these (they all bounce a random caller on-chain).

---

## 2. Why it happens (root-cause chain)

The earned-public "fail closed" default (`PSAT_AUTHORITY_EARNED_PUBLIC`) only fires
when a caller gate is **detected but unresolved** — those land in the gated-unknown
queue, where they are safe and probeable. These false-opens are gates that
extraction **never detected at all**:

```
hard-to-trace gate (param-keyed mapping / struct-arg external call / multisig
  signature verification / helper-wrapped membership)
    → static extraction finds NO caller-taint
      → empty predicate tree
        → "no gate detected → public" (conditional_universal)
          → NOT in the gated-unknown queue
            → _should_differential_probe == False → probe never runs
              → false-open survives
```

You cannot fail-closed on a gate you never saw. The earned-public refactor moved
*detected-but-unresolved* gates to fail closed; an **undetected** gate still
produces an empty tree that defaults open.

---

## 3. Current numbers (the residual)

| direction | rate | meaning |
|---|---|---|
| **false-open** (dangerous) | **4 / 171 = 2.3%** of gated (0.56% of all 711) | labeled gated, pipeline says public |
| false-gate (safe) | 13 / 536 = 2.4% of public | labeled public, pipeline says gated |

The 4 false-opens are the *hard tail* of extraction — none are inline
assembly or otherwise Slither-fundamental (see §6):

| cid | address | function | selector | gate that was missed | class |
|---|---|---|---|---|---|
| 281 | `0xd22dd829779adbf3869fb224f703452f7f95e9db` | `recordBeaconChainETHBalanceUpdate` | `0xa1ca780b` | `ownerToPod[podOwner] == msg.sender` (param-keyed mapping) | caller_eq_external |
| 285 | `0x1a44076050125825900e736c501f859c50fe728c` | `verify` | `0xa825d747` | `isValidReceiveLibrary(…, msg.sender)` (struct arg + external call) | caller_eq_external |
| 293 | `0xbe010a7e3686fdf65e93344ab664d065a0b02478` | `executeTransaction` | `0x8e6725bd` | OneSig `canExecuteTransaction(msg.sender)` (merkle+ECDSA signer set) | multisig_threshold |
| 342 | `0x5eefe6f65a280a6f1eb1fdff36ab9e2af6f38462` | `submitReport` | `0x27487524` | `committeeMembers[msg.sender]` via a helper | allowlist_membership |

---

## 4. How to reproduce / verify (the part to come back to)

### 4.1 Get the current false-open / false-gate rates (no RPC)

This is a compile-and-evaluate pass under the null adapter — **zero RPC**, a few
minutes of CPU. Services (postgres) must be up.

```bash
set -a; source .env; set +a
# Compile + evaluate every corpus contract once (no toggles = current pipeline):
uv run python scripts/authority_audit/ab.py --jobs 8 --label current_static
# Score the verdicts against the human labels:
uv run python scripts/authority_audit/corpus_metrics.py out/ab_current_static.json --side new
```

Expected (the lines that matter):

```
ab_current_static.json [new] vs corpus (711 rows, 4 unmatched):
  false-open: 4/171 = 2.3%
  false-gate: 13/536 = 2.4%

  false-open rows (labeled gated, predicted public):
    [281] recordBeaconChainETHBalanceUpdate(address,uint256,int256)  caller_eq_external
    [285] verify(Origin,address,bytes32)                             caller_eq_external
    [293] executeTransaction(OneSig.Transaction,bytes32,uint256,bytes) multisig_threshold
    [342] submitReport(IEtherFiOracle.OracleReport)                  allowlist_membership
```

> The corpus's `workingtree_public` field is STALE (it showed 27 apparent
> false-opens). Always re-derive the current number with the pass above — do not
> trust the stored field.

### 4.2 Confirm a false-open is in the "public" bucket (no RPC)

```bash
set -a; source .env; set +a
uv run python scripts/authority_audit/harness.py 281 | grep recordBeaconChainETHBalanceUpdate
```

Expected — it is classified PUBLIC, which is why the probe skips it:

```
  PUBLIC public         conditional_universal  recordBeaconChainETHBalanceUpdate(address,uint256,int256)
```

### 4.3 Confirm the probe trigger skips it (no RPC)

```bash
uv run python -c "
from services.resolution.capabilities import CapabilityExpr, Condition
from services.resolution.capability_resolver import _should_differential_probe
pub = CapabilityExpr.conditional_universal(Condition(kind='business', description='no gate'))
print(_should_differential_probe(pub))   # -> False
"
```

### 4.4 Confirm it IS gated on-chain (the probe would catch it) — uses RPC

The probe machinery, pointed directly at the function, shows the deployed contract
rejects a random caller. `probe_audit.py` runs `run_differential_probe` on every
corpus row of a contract regardless of its static verdict:

```bash
set -a; source .env; set +a
uv run python scripts/authority_audit/probe_audit.py --contract-id 281 --block 25290093
```

`recordBeaconChainETHBalanceUpdate` reports `attribution=caller_rejected_consistent`
(both random callers revert with the same custom error `0x25c2dae2`). Raw form:

```python
# from = two deterministic random addresses; to = 0xd22dd8…e9db; block 25290093
from 0x6f6f7fd5…1085: success=False revert=0x25c2dae2…
from 0x43527afb…95b1: success=False revert=0x25c2dae2…
attribution(one-sided): caller_rejected_consistent   # i.e. gated on-chain
```

That is the proof of the gap: the probe *correctly* sees this function is gated —
it just never runs on it in production because the static stage filed it under
"public," not "gated, unknown."

### 4.5 (Optional) read the actual gate to confirm the label

```bash
uv run python scripts/authority_audit/onchain.py source 0xd22dd829779adbf3869fb224f703452f7f95e9db | less
# look for: modifier onlyEigenPod(address podOwner) { require(ownerToPod[podOwner] == msg.sender, ...); }
```

---

## 5. The fix: aim the probe at the public set (unbuilt "second pipe")

The probe is wired to one pipe (the gated-unknown queue). The unbuilt extension is
to also probe **statically-public** functions and flag the ones that reject a
random caller as suspected false-opens.

- **Where:** the resolver loop in `services/resolution/capability_resolver.py`
  (`resolve_contract_capabilities`), next to the existing
  `_maybe_differential_probe` hook — but triggered on `conditional_universal`
  (public) verdicts instead of `external_check_only`, behind its own flag.
- **What it produces:** a *flag*, not an automatic downgrade. A statically-public
  function whose random caller bounces is a **suspected** missed gate; surface it
  for review (and/or downgrade to `external_check_only` so the conservative
  default takes over).
- **Why a flag, not an auto-fix — the certainty asymmetry:**
  - *Opening* (current pipe): a random caller **succeeding** is near-proof of
    openness → high-certainty automatic upgrade (validated: 0 wrong over 711).
  - *False-open detection* (this pipe): a random caller **bouncing** is ambiguous
    — it could be a hidden auth gate (a real false-open) OR a zero-arg business
    precondition. So it is a high-confidence detector, not an auto-eliminator. The
    4 here bounce on caller identity with ACL-style errors, so they would be strong
    flags; a function that bounces with "Incorrect Deposit Amount" would not.
- **Why it is the right next step:** bounded cost (reuses `eth_call_batch`,
  `synthesize_calldata`, `attribute` — all built and validated), and it is
  **shape-agnostic**: it would flag the param-keyed-mapping, multisig, and even the
  inline-assembly gates that static analysis cannot see (§6), without writing a
  single new extraction pattern.
- **Cost:** ~1 `eth_call` batch per statically-public function; the corpus has
  ~530 public rows, i.e. the same scale as the Phase-3 probe audit that already ran
  fine. Probe lazily + cache by `(chain, address, selector, block)` (the existing
  `_PROBE_CACHE`).

---

## 6. What is NOT worth doing (data-backed)

- **Broad "model more ACL shapes" in the static extractor:** the false-open rate is
  already low (2.3%) and the common shapes (`onlyOwner`, `hasRole`, Solmate
  `requiresAuth`, Lido `_auth`) are already handled. The 4 stragglers are distinct
  one-offs with no dominant cluster — poor ROI versus the probe-as-detector, which
  catches all shapes at once. Reconsider only if a single pattern (e.g.
  param-keyed mapping) is shown to recur across many contracts.
- **The inline-assembly / dynamic-dispatch Slither floor:** **zero** of the 4
  false-opens are assembly. Solving a hard, below-Slither problem with no
  demonstrated incidence is premature. The probe-as-detector covers assembly gates
  behaviorally anyway, which is the better hedge.

---

## 7. One-line summary for the changelog

> Differential probe cannot catch false-opens: they classify as `public`
> (empty extraction tree → fails open), so they never enter the
> `external_check_only` queue the probe inspects. Residual 4/171 (2.3%) of gated
> functions; all gated on-chain. Fix = run the probe over the statically-public set
> as a behavioral false-open detector (flag, not auto-downgrade). Verify with
> §4 (`ab.py` + `corpus_metrics.py`, `harness.py 281`, `probe_audit.py
> --contract-id 281`).
