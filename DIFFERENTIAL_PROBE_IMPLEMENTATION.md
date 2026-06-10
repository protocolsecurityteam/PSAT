# Differential on-chain probe — implementation summary

Implements `DIFFERENTIAL_PROBE_PLAN.md` (Phases 0–4) on top of the earned-public
refactor (`d47d00c`). The probe converts a "gated, principals unknown"
(`external_check_only`) heuristic verdict into an *observed* one by asking the
deployed contract — via `eth_call` with a varying `from` — whether the gate
actually discriminates on the caller.

**Status: ON by default (`PSAT_DIFFERENTIAL_PROBE`, `=0` is the kill-switch).** The
Phase-3 corpus gate is green (below) — 0 label-disagreeing public upgrades — which
is the bar the plan set for enabling, so the default was flipped ON. The offline
suite forces the flag OFF for hermeticity (`tests/conftest.py`,
`_force_differential_probe_off`, mirroring the Multicall3 precedent), and is
byte-identical to pre-feature with it off (`netguard` confirms zero external
connects). The probe remains strictly additive: a synthesis miss / unreachable RPC
/ non-archive node keeps the static verdict.

## What landed

| area | file |
|---|---|
| revert-preserving batch primitive + shared ABI encode/decode | `utils/rpc.py` (`eth_call_batch`, `EthCallResult`, `encode_address_word`, `decode_bool_word`) |
| materializer de-forked onto the shared helpers | `services/resolution/external_check_materializer.py` |
| the probe (calldata synth, attribution, one/two-sided, §3.5 cross-checks) | `services/resolution/differential_probe.py` |
| resolution wiring + §3.6 verdict landing + cache | `services/resolution/capability_resolver.py` |
| unit tests (attribution table, synthesis, recorded real transcripts, wiring, cache) | `tests/test_differential_probe.py`, `tests/test_differential_probe_wiring.py`, `tests/test_eth_call_batch.py` |
| corpus audit + replay + A/B toggle | `scripts/authority_audit/probe_audit.py`, `probe_replay.py`, `toggles_differential_probe.py` |
| recorded transcripts + results | `scripts/authority_audit/PHASE0_HANDPROBE.md`, `PROBE_AUDIT_RESULTS.md` |

## One correction to the plan (§3.5.3)

The plan said to batch the differential probes through **Multicall3**. That is
unsound here: `aggregate3` makes each sub-call's `msg.sender` the Multicall3
contract, which **erases the `from`** the probe must discriminate on. The probe
instead uses a **JSON-RPC array batch** of per-`from` `eth_call`s (`eth_call_batch`)
— one round trip, one pinned block, same node — which gives the §3.5 consistency
without the `msg.sender` rewrite. (Multicall3 stays correct for the
*materializer*, which passes the candidate as an explicit ABI arg, not via
`msg.sender`.)

## Soundness gate (Phase 3, §6.4)

`probe_audit.py` over all 711 corpus rows @ block 25289222:

- **DISAGREEING public upgrades: 0** (the single number that authorizes the flag),
  both overall and in the 164-row production-probed (static-gated) population.
- 186 correct public upgrades, 114 gated confirmations, 206 indeterminate.
- Every verdict carries a transcript and **replays** at its pinned block
  (`probe_replay.py`, verified on a public upgrade and a gated confirmation).

The public-upgrade direction (the feature's value: catching residual false-gates)
is sound — 186/186 correct. The one-sided gated *confirmation* is a deliberately
weak signal (it can't separate an auth gate from a zero-arg business precondition
without a principal); it **never flips a verdict**, and in the production-probed
population its over-fire rate is ~10%. See `PROBE_AUDIT_RESULTS.md`.

## Cost model (§4)

- Per gated-unknown function: **1** `eth_call_batch` (2 random `from`s in one
  request); **2** only when the first batch says candidate-public and the §3.5.1
  block-independence re-probe runs. Measured: ~1 batch/function average (only ~3 of
  164 needed the second).
- Probed **lazily** — only `external_check_only` caller-gate verdicts (the
  gated-unknown queue), never every function. Cold-index `deferred_pending_index`
  verdicts are skipped (overwriting them would freeze the Veda self-heal race).
- **Cached** per `(chain, address, selector, block)` for the resolution process,
  so re-resolving a contract in-process costs nothing.
- **Fails safe**: no RPC / non-archive node / blocknum read failure → probing is
  skipped for the pass (the static verdict stands); any probe exception is
  swallowed. The probe can never make resolution worse than today (§7.1).

## Rollout (§4 Phase 4)

1. Phase-3 gate green → **default flipped ON** (`=0` kill-switch kept for one
   release, the #130 / earned-public precedent). NOTE: the §6.5 flag-off/on diff is
   measured by `probe_audit.py` (the corpus confusion matrix), NOT by `ab.py
   --toggles toggles_differential_probe` — the A/B harness uses the null adapter and
   never runs the live resolver path the probe is wired into, so it cannot observe
   the probe's effect (it only confirms the static path is unchanged).
2. Optional follow-ups that raise coverage (the honest residual, §8): thread
   caller-correlated arg indices from the predicate tree into
   `synthesize_calldata(..., caller_correlated_indices=)`; two-sided probing with a
   resolved principal; recompile for canonical ABI signatures to cut the 114
   synthesis misses.
