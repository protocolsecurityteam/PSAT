"""Tier-2 anvil fork transport + the freeze/pause recipe.

Tier 2 is reserved for effects that need SEQUENCING or TIME — proving a freeze's
blast radius and that it auto-expires at the contract's own
``MAX_PAUSE_DURATION`` — which ``eth_call``/``eth_simulateV1`` cannot express.
The fork lives behind the injectable :class:`AnvilTransport` interface, the same
seam discipline as ``call_batch``/``Simulate``: exactly one place
(:class:`SubprocessAnvil`) does real subprocess + localhost JSON-RPC I/O;
everything else takes the transport injected and is tested against a stub.

Hard rules honored here: the hardfork is PINNED and ASSERTED and recorded per
transcript (post-Cancun EIP-6780 is why a stale fork mints wrong witnesses); the
anvil/foundry version is recorded per transcript; fork access is single-flight
(snapshot/revert is process-global, the worker runs
``PSAT_EFFECTS_JOB_CONCURRENCY=1``); ``MAX_PAUSE_DURATION`` is READ FROM SOURCE by
the caller and passed in, never hardcoded. Agents NEVER run a FORKING
anvil or real RPC — that is the user's preview step; the offline integration test
uses a local NON-FORKING anvil with a checked-in fixture.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from services.clients.rpc import EthCallResult
from services.effects.config import (
    BLOCK_SOURCE_INVOCATION_PIN,
    DURATION_BOUND_NOT_DETERMINED,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_VALUE_OUT,
    OBSERVATION_EXECUTED,
    OBSERVATION_REVERTED,
    SCOPE_KERNEL,
    SCOPE_PROJECTION,
    SHAPE_CALLER_ARBITRARY,
    TIER_FORK,
)
from services.effects.exceptions import AnvilSpawnError, ForkRpcTimeoutError
from services.effects.harness import (
    Discrepancy,
    ObservedEffect,
    SimContext,
    TranscriptStore,
    emit,
    new_transcript,
    proven,
    unknown,
)
from utils.memory import rss_bytes_for_pid

logger = logging.getLogger(__name__)

# How much of anvil's output a spawn/startup failure can quote back, and how long
# ``close`` waits on the drain thread before giving up on it (the thread is a
# daemon, so a wedged read can never hold the process open).
_OUTPUT_TAIL_LINES = 40
_DRAIN_JOIN_TIMEOUT_S = 2.0
_TRANSACTION_RECEIPT_TIMEOUT_S = 15.0
_TRANSACTION_RECEIPT_POLL_INTERVAL_S = 0.05

# Post-Cancun forks that carry EIP-6780 (and later) semantics. A fork pinned to
# anything earlier can mint witnesses wrong for the live chain.
POST_CANCUN_HARDFORKS = frozenset({"cancun", "prague", "osaka"})


@dataclass(frozen=True)
class ForkFixture:
    """One piece of fork state a probe needs before it can be meaningful — a
    funded caller, a storage slot holding a precondition. Applied INSIDE the
    recipe's snapshot so it is reverted with everything else.

    ``kind`` is ``set_balance`` (``address``/``value``) or ``set_storage_at``
    (``address``/``slot``/``value``). An unknown kind is ignored, never guessed.

    A ``set_storage_at`` fixture MAY carry a read-back spec (``verify_to`` +
    ``verify_calldata`` + ``verify_expected``): after the slot is written, the
    contract's OWN getter is called and its 32-byte word compared to
    ``verify_expected``. What this proves is that the getter NOW echoes the
    seeded word — the precondition the probe will read is satisfied. It does
    not prove the write is what the getter reads: a wrong-slot write is kept
    when the getter already returned the expected word (e.g. an earlier seed
    satisfied it). That is safe — seeds are constants of the pre/post diff, so
    a stray write can only shrink the observed lower bound, never flip an
    entry point across the pause — but the guarantee is precondition-holds,
    not write-landed. Absent (all ``None``) ⇒ the fixture is applied as-is,
    exactly as before."""

    kind: str
    address: str
    value: str
    slot: str | None = None
    verify_to: str | None = None
    verify_calldata: str | None = None
    verify_expected: str | None = None


@dataclass(frozen=True)
class EntryPoint:
    """One state-changing entry point to probe for the blast-radius diff.

    ``key`` is a stable identity (selector or ``name`` — never used to CLASSIFY,
    only to label which points reverted); ``calldata`` + ``from_addr`` are the
    probe call. ``to`` defaults to the recipe's contract when ``None``.
    ``fixtures`` is the fork state THIS probe needs to be able to succeed
    pre-pause (gas for its caller, a balance/allowance slot); carried per entry
    point so it stays inspectable and tunable, applied once with the rest."""

    key: str
    calldata: str
    from_addr: str | None = None
    to: str | None = None
    fixtures: tuple["ForkFixture", ...] = ()


class AnvilTransport(Protocol):
    """Fork transport seam. ``call`` is read-only (``eth_call``); ``send``
    executes an impersonated tx against the LOCAL fork only (never mainnet)."""

    def hardfork(self) -> str: ...

    def versions(self) -> dict[str, str]: ...

    def snapshot(self) -> str: ...

    def revert(self, snapshot_id: str) -> bool: ...

    def impersonate(self, address: str) -> None: ...

    def stop_impersonate(self, address: str) -> None: ...

    def call(self, tx: dict[str, Any]) -> EthCallResult: ...

    def send(self, tx: dict[str, Any]) -> str: ...

    def increase_time(self, seconds: int) -> None: ...

    def mine(self) -> None: ...

    def set_balance(self, address: str, value: str) -> None: ...

    def set_storage_at(self, address: str, slot: str, value: str) -> None: ...


def fork_block_pin(transport: AnvilTransport) -> int | None:
    """The height ``transport``'s fork was PROVABLY pinned at, else ``None``.

    Deliberately an optional capability rather than a member of
    :class:`AnvilTransport`: a transport that cannot answer — any stub, an older
    forking spawn, a fork taken at the upstream's spawn-time head — yields
    ``None``, and the recipe then publishes no observation height at all. That is
    the not_determined state; the alternative (falling back to the preflight pin)
    is exactly the defect this exists to close, since an unpinned fork's real
    height is unrecoverable rather than merely unrecorded."""
    getter = getattr(transport, "fork_block_number", None)
    if not callable(getter):
        return None
    try:
        value = getter()
    except Exception:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def assert_post_cancun(transport: AnvilTransport) -> str:
    """Assert the fork's hardfork carries post-Cancun semantics and return it for
    the transcript. Raises ``ValueError`` on a stale fork — a witness minted
    on pre-Cancun semantics is unsafe, so we fail rather than record it."""
    hf = transport.hardfork().strip().lower()
    if hf not in POST_CANCUN_HARDFORKS:
        raise ValueError(
            f"fork hardfork {hf!r} is not post-Cancun ({sorted(POST_CANCUN_HARDFORKS)}) — refusing to probe"
        )
    return hf


def pause_recipe(
    *,
    transport: AnvilTransport,
    store: TranscriptStore,
    ctx: SimContext,
    contract_address: str,
    principal: str,
    pause_calldata: str,
    entry_points: Sequence[EntryPoint],
    predicted_guard_set: Sequence[str],
    max_pause_duration: int | None,
    duration_bound_source: str = DURATION_BOUND_NOT_DETERMINED,
    gate_ref: str = "",
    fixtures: Sequence[ForkFixture] = (),
) -> ObservedEffect:
    """Freeze/pause: snapshot → record the pre-pause SUCCEEDING entry-point
    set → impersonate principal + call F → re-probe → the newly-reverting set is
    the OBSERVED blast radius (a LOWER bound) → warp time by the source-read
    ``max_pause_duration`` → re-probe for auto-expiry. snapshot/revert isolates
    the probe. The SCORED denominator is static's ``predicted_guard_set``;
    simulation only upgrades observed members to witnessed tier and
    NEVER becomes the denominator — the pre-pause succeeding set is recorded so
    consumers see it."""
    hardfork = assert_post_cancun(transport)
    # The height the FORK was taken at, which is the height this recipe observes —
    # not the caller's preflight pin, which the fork only shares when it was
    # actually spawned with it. An unpinned fork therefore records no height and
    # names no pin scope, and both witness keys stay absent.
    fork_block = fork_block_pin(transport)
    ctx = SimContext(
        chain_id=ctx.chain_id,
        block=fork_block if fork_block is not None else ctx.block,
        hardfork=hardfork,
        anvil_version=transport.versions().get("anvil"),
        foundry_version=transport.versions().get("foundry"),
        block_source=BLOCK_SOURCE_INVOCATION_PIN if fork_block is not None else None,
    )
    tr = new_transcript(ctx, feature="pause", tier=TIER_FORK, effect_class=EFFECT_CLASS_FREEZE_PAUSE)
    tr["contract_address"] = contract_address.lower()
    tr["predicted_guard_set"] = sorted(predicted_guard_set)
    tr["max_pause_duration"] = max_pause_duration
    tr["duration_bound_source"] = duration_bound_source

    snap = transport.snapshot()
    try:
        # Fixtures go inside the snapshot and before the pre-pause probe: an entry
        # point that reverts for an unfunded caller / unmet precondition would
        # silently shrink the observed blast radius (which the diff treats as
        # "pause did not freeze it").
        _apply_fixtures(transport, [*fixtures, *(fx for ep in entry_points for fx in ep.fixtures)], tr)
        pre_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "pre_pause")

        # Verify the pause can actually take effect before
        # reading the freeze. An ``eth_call`` of the pauser from the principal runs
        # the same EVM logic a ``send`` would, so a revert here means the resolved
        # pauser cannot enact the pause on this forked state (missing authority, an
        # active per-pauser cooldown, an unmet precondition). The freeze was then
        # NEVER TESTED, so an empty blast radius would be INDETERMINATE — reported as
        # its own ``pause_ineffective`` unknown with the raw revert, never conflated
        # with a genuine "pause froze nothing" (an empty
        # ``observed_blast_radius`` ≠ no-freeze). This split is what lets the live
        # cycle tell the recoverable ineffective-pause verdicts from the correct
        # no-blast ones instead of seeing one undifferentiated pile of empties.
        pause_probe = transport.call({"from": principal, "to": contract_address, "data": pause_calldata})
        tr["results"].append(
            {"label": "pause_effectiveness", "success": pause_probe.success, "revert": pause_probe.revert_data}
        )
        if not pause_probe.success:
            tr["pause_effective"] = False
            tr["pre_pause_succeeding"] = sorted(pre_succeeding)
            tr["observed_blast_radius"] = []
            return emit(
                store,
                unknown(
                    EFFECT_CLASS_FREEZE_PAUSE,
                    tier=TIER_FORK,
                    scope=SCOPE_PROJECTION,
                    gate_ref=gate_ref,
                    reason="pause_ineffective",
                    details={
                        # The pause call itself REVERTED, so the freeze was never
                        # tested: the empty blast radius below describes a probe
                        # that did not happen, not a pause that froze nothing.
                        "observation": OBSERVATION_REVERTED,
                        "pause_effective": False,
                        "pre_pause_succeeding": sorted(pre_succeeding),
                        "observed_blast_radius": [],
                        "scored_denominator": sorted(str(g) for g in predicted_guard_set),
                    },
                    transcript=tr,
                ),
            )
        tr["pause_effective"] = True

        transport.impersonate(principal)
        try:
            transport.send({"from": principal, "to": contract_address, "data": pause_calldata})
            transport.mine()
        finally:
            transport.stop_impersonate(principal)

        post_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "post_pause")
        observed_blast = pre_succeeding - post_succeeding

        auto_expiry: bool | None = None
        if max_pause_duration is not None and observed_blast:
            # The caller passes the latch's declared MAXIMUM. The live window is
            # whatever the contract's own duration state (or its MIN fallback)
            # says, which is always ≤ that maximum — so warping past the max is a
            # sound over-warp, and a latch that has NOT expired by then is
            # genuinely indefinite. An indefinite latch passes ``None`` and is
            # never warped at all.
            transport.increase_time(max_pause_duration + 1)
            transport.mine()
            expiry_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "post_expiry")
            # Auto-expiry proven iff every point the pause froze succeeds again.
            auto_expiry = observed_blast.issubset(expiry_succeeding)
    finally:
        transport.revert(snap)

    tr["pre_pause_succeeding"] = sorted(pre_succeeding)
    tr["observed_blast_radius"] = sorted(observed_blast)
    tr["auto_expiry"] = auto_expiry

    predicted = {str(g) for g in predicted_guard_set}
    # A member observed reverting that static did NOT predict = static under-
    # enumerated its guard set: a discrepancy (vocabulary growth), not a
    # harness failure. The reverse (predicted-but-not-observed) is EXPECTED —
    # business preconditions hide points from the diff — so it is not flagged.
    unpredicted = observed_blast - predicted
    disc = (
        Discrepancy(
            kind="observed_guard_not_predicted",
            effect_class=EFFECT_CLASS_FREEZE_PAUSE,
            detail={"unpredicted_members": sorted(unpredicted)},
        )
        if unpredicted
        else None
    )

    if not pre_succeeding:
        # NOTHING WAS LIVE TO FREEZE. Every entry point we could synthesize was
        # already reverting on its own precondition before the pause, so
        # ``observed_blast = pre - post`` is empty by construction and measures
        # the probe set, not the pause. Distinct from the branch below, where
        # points WERE live and the pause left them alone — that is a real
        # observation about the latch; this is the absence of one.
        #
        # Deliberately its own reason so it stays OUT of
        # ``_CACHEABLE_UNKNOWN_REASONS``: the emptiness is a property of this
        # deployment's state at this block (an unfunded caller, an unmet
        # business precondition), not of the bytecode, so transferring it would
        # publish "this pause froze nothing" to every twin on the strength of a
        # surface that happened to be dead here.
        return emit(
            store,
            unknown(
                EFFECT_CLASS_FREEZE_PAUSE,
                tier=TIER_FORK,
                scope=SCOPE_PROJECTION,
                gate_ref=gate_ref,
                reason="no_live_entry_points_to_freeze",
                details={
                    "observation": OBSERVATION_EXECUTED,
                    "pause_effective": True,
                    "pre_pause_succeeding": [],
                    "observed_blast_radius": [],
                    "scored_denominator": sorted(predicted),
                },
                transcript=tr,
                discrepancy=disc,
            ),
        )
    if not observed_blast:
        return emit(
            store,
            unknown(
                EFFECT_CLASS_FREEZE_PAUSE,
                tier=TIER_FORK,
                scope=SCOPE_PROJECTION,
                gate_ref=gate_ref,
                reason="no_blast_radius_observed",
                details={
                    # The pause ran. The empty blast radius below is therefore a
                    # measurement, which is exactly what separates this row from
                    # the reverted one above.
                    "observation": OBSERVATION_EXECUTED,
                    # pause_effective True + empty blast = a GENUINE no-blast: the
                    # pause took effect yet froze nothing observable. This is at the
                    # bar (correct to leave unknown), and distinct from the
                    # pause_ineffective branch above where the freeze was untested.
                    "pause_effective": True,
                    "pre_pause_succeeding": sorted(pre_succeeding),
                    "observed_blast_radius": [],
                    "scored_denominator": sorted(predicted),
                },
                transcript=tr,
                discrepancy=disc,
            ),
        )

    eff = proven(
        EFFECT_CLASS_FREEZE_PAUSE,
        tier=TIER_FORK,
        scope=SCOPE_PROJECTION,
        gate_ref=gate_ref,
        reason="pause_froze_entry_points",
        details={
            "observation": OBSERVATION_EXECUTED,
            # Kernel witness (latch flip caused reverts) + projection witness
            # (which points). The scored denominator stays static's set;
            # the observed set is a lower bound recorded alongside it.
            "latch_flip": True,
            "pause_effective": True,
            "observed_blast_radius": sorted(observed_blast),
            "pre_pause_succeeding": sorted(pre_succeeding),
            "scored_denominator": sorted(predicted),
            "auto_expiry": auto_expiry,
            "duration_bound_seconds": max_pause_duration,
            # Which of the three states that ``None`` is (see
            # ``config.DURATION_BOUND_*``). Published on the SAME row as the bound
            # because the pair is the fact: ``None`` + ``no_time_reference`` is a
            # proven-indefinite freeze, ``None`` + ``not_determined`` is an
            # unmeasured window, and while only the bound was published every
            # unmeasured window rendered as the proven-indefinite one.
            "duration_bound_source": duration_bound_source,
        },
        transcript=tr,
    )
    eff.discrepancy = disc
    return emit(store, eff)


def _uint_return(result: EthCallResult) -> int | None:
    if not result.success or not result.return_data:
        return None
    try:
        return int(result.return_data, 16)
    except ValueError:
        return None


def timelock_execute_recipe(
    *,
    transport: AnvilTransport,
    store: TranscriptStore,
    ctx: SimContext,
    contract_address: str,
    principal: str,
    schedule_calldata: str,
    execute_calldata: str,
    delay_seconds: int,
    gate_ref: str = "",
    fixtures: Sequence[ForkFixture] = (),
    sentinel_address: str | None = None,
    witness_token: str | None = None,
    witness_calldata: str | None = None,
) -> ObservedEffect:
    """Tier-2 timelock: schedule → advance time → execute, the sequence Tier-1
    cannot reach (``eth_simulateV1`` issues ONE block with no ``blockOverrides``, so
    it can never satisfy a delayed operation's ``block.timestamp`` gate — every
    ``execute`` reverts ``TimelockUnexpectedOperationState`` there).

    Reuses ``pause_recipe``'s fork machinery: snapshot/revert isolation,
    an impersonated principal, and ``increase_time`` to advance past the operation
    delay. The scheduled inner operation is an ERC-20 ``transfer`` to a sentinel on
    a token the timelock provably holds (synthesised upstream from measured
    holdings), so a positive sentinel-balance delta after ``execute`` proves
    the timelock forwards value to a PROPOSER-CHOSEN destination — a
    ``caller_arbitrary`` outflow, the exact shape an arbitrary-call executor has.

    Fail-closed at every step: a ``schedule`` or ``execute`` revert is its own
    unknown carrying the raw revert, never conflated with "executes nothing"; an
    execution that moves no value to the sentinel stays ``no_value_observed``.

    NONE of this recipe's verdicts may be cached or transferred on the behavioural
    hash — not because of their tier (``_is_cacheable`` excludes only
    ``TIER_HISTORICAL``, and a proven verdict / a ``no_value_observed`` are
    otherwise cacheable), but because EVERY one of them is STATE-DEPENDENT: it
    rests on state this probe manufactured on the fork (the scheduled operation
    landing, ``block.timestamp`` advancing past the delay), which is not a
    code-plane structural fact a bytecode twin inherits. So each verdict carries
    ``state_dependent=True``, which ``_is_cacheable`` refuses outright."""
    hardfork = assert_post_cancun(transport)
    # The height the FORK was taken at, which is the height this recipe observes —
    # not the caller's preflight pin, which the fork only shares when it was
    # actually spawned with it. An unpinned fork therefore records no height and
    # names no pin scope, and both witness keys stay absent.
    fork_block = fork_block_pin(transport)
    ctx = SimContext(
        chain_id=ctx.chain_id,
        block=fork_block if fork_block is not None else ctx.block,
        hardfork=hardfork,
        anvil_version=transport.versions().get("anvil"),
        foundry_version=transport.versions().get("foundry"),
        block_source=BLOCK_SOURCE_INVOCATION_PIN if fork_block is not None else None,
    )
    tr = new_transcript(ctx, feature="timelock", tier=TIER_FORK, effect_class=EFFECT_CLASS_VALUE_OUT)
    tr["contract_address"] = contract_address.lower()
    tr["delay_seconds"] = delay_seconds

    def _unknown(reason: str, **details: Any) -> ObservedEffect:
        eff = unknown(
            EFFECT_CLASS_VALUE_OUT,
            tier=TIER_FORK,
            scope=SCOPE_KERNEL,
            gate_ref=gate_ref,
            reason=reason,
            details={"observation": OBSERVATION_REVERTED, **details},
            transcript=tr,
        )
        eff.state_dependent = True
        return emit(store, eff)

    def _witness() -> int | None:
        if witness_token is None or witness_calldata is None:
            return None
        return _uint_return(transport.call({"to": witness_token, "data": witness_calldata}))

    snap = transport.snapshot()
    try:
        _apply_fixtures(transport, fixtures, tr)
        witness_before = _witness()

        transport.impersonate(principal)
        try:
            # An ``eth_call`` runs the same EVM logic ``send`` would, so a revert here
            # is the resolved proposer being unable to schedule on this forked state
            # (missing PROPOSER_ROLE, an operation already pending) — the sequence was
            # never testable, recorded with its raw revert.
            schedule_probe = transport.call({"from": principal, "to": contract_address, "data": schedule_calldata})
            tr["results"].append(
                {"label": "schedule", "success": schedule_probe.success, "revert": schedule_probe.revert_data}
            )
            if not schedule_probe.success:
                return _unknown("timelock_schedule_reverted", schedule_revert=schedule_probe.revert_data)
            transport.send({"from": principal, "to": contract_address, "data": schedule_calldata})
            transport.mine()

            # THE Tier-1 impossibility: before the delay elapses ``execute`` must
            # revert on the operation-not-ready gate. Observing that revert here, then
            # its success after the warp, is what proves the recipe advanced time
            # rather than side-stepped the gate.
            premature = transport.call({"from": principal, "to": contract_address, "data": execute_calldata})
            tr["results"].append(
                {"label": "execute_premature", "success": premature.success, "revert": premature.revert_data}
            )

            transport.increase_time(delay_seconds + 1)
            transport.mine()

            execute_probe = transport.call({"from": principal, "to": contract_address, "data": execute_calldata})
            tr["results"].append(
                {"label": "execute", "success": execute_probe.success, "revert": execute_probe.revert_data}
            )
            if not execute_probe.success:
                return _unknown("timelock_execute_reverted", execute_revert=execute_probe.revert_data)
            transport.send({"from": principal, "to": contract_address, "data": execute_calldata})
            transport.mine()
        finally:
            transport.stop_impersonate(principal)

        witness_after = _witness()
    finally:
        transport.revert(snap)

    moved = witness_before is not None and witness_after is not None and witness_after > witness_before
    if not moved:
        eff = unknown(
            EFFECT_CLASS_VALUE_OUT,
            tier=TIER_FORK,
            scope=SCOPE_KERNEL,
            gate_ref=gate_ref,
            # Two different facts, and a consumer must be able to tell them apart.
            # With no witness asset the timelock held NOTHING for the operation to
            # move, so "moved nothing" would be a statement about our inability to
            # measure rather than about the contract. With
            # an asset, the operation really did execute and move none of it.
            reason="no_value_observed" if witness_token is not None else "timelock_holds_no_witness_asset",
            details={
                # The delayed operation EXECUTED (the point Tier-1 cannot reach);
                # it simply moved nothing to the sentinel we could witness.
                "observation": OBSERVATION_EXECUTED,
                "value_moved": False,
                "timelock_executed": True,
                "witness_asset_held": witness_token is not None,
            },
            transcript=tr,
        )
        # State-dependent (schedule landed + time advanced): must not transfer on
        # the kernel hash, even though ``no_value_observed`` is otherwise cacheable.
        eff.state_dependent = True
        return emit(store, eff)
    eff = proven(
        EFFECT_CLASS_VALUE_OUT,
        tier=TIER_FORK,
        scope=SCOPE_KERNEL,
        gate_ref=gate_ref,
        reason="value_moved",
        details={
            "observation": OBSERVATION_EXECUTED,
            "value_moved": True,
            "timelock_executed": True,
            # The scheduled operation targeted a sentinel the PROPOSER chose, and
            # the timelock forwarded value to it — a caller/proposer-arbitrary
            # destination, proved by the sentinel balance delta (simulation).
            "destination_shape": SHAPE_CALLER_ARBITRARY,
            "shape_proved_by": "simulation",
        },
        concrete={"destination": sentinel_address} if sentinel_address else {},
        transcript=tr,
    )
    # State-dependent: a proven value_moved from schedule→warp→execute is as
    # untransferable as its reverts — it rests on state THIS probe manufactured.
    eff.state_dependent = True
    return emit(store, eff)


def _has_verify_spec(fx: ForkFixture) -> bool:
    return fx.verify_to is not None and fx.verify_calldata is not None and fx.verify_expected is not None


def _apply_fixtures(transport: AnvilTransport, fixtures: Sequence[ForkFixture], transcript: dict[str, Any]) -> None:
    """Apply the fork-state fixtures, recording each in the transcript so a replay
    reproduces the same starting state. A cheatcode that fails is recorded and
    skipped — a missing fixture can only shrink the observed radius (a lower
    bound), never manufacture one.

    Plain fixtures are applied first; storage fixtures carrying a read-back spec
    are applied AFTER so their getter observes the final gas/balance state. Each
    verified write goes under an inner snapshot: if the contract's own getter does
    not echo the seeded word, the write is reverted (never left half-applied) and
    recorded ``readback: failed``. A kept write records ``readback: ok``."""
    plain = [fx for fx in fixtures if not _has_verify_spec(fx)]
    verified = [fx for fx in fixtures if _has_verify_spec(fx)]

    applied: list[dict[str, Any]] = []
    for fx in plain:
        entry: dict[str, Any] = {"kind": fx.kind, "address": fx.address, "slot": fx.slot, "value": fx.value}
        try:
            if fx.kind == "set_balance":
                transport.set_balance(fx.address, fx.value)
            elif fx.kind == "set_storage_at" and fx.slot is not None:
                transport.set_storage_at(fx.address, fx.slot, fx.value)
            else:
                entry["skipped"] = "unknown_kind"
        except Exception as exc:  # noqa: BLE001 - recorded, never fatal
            entry["error"] = str(exc)
        applied.append(entry)

    for fx in verified:
        applied.append(_apply_verified_fixture(transport, fx))

    if applied:
        transcript["fixtures"] = applied


def _apply_verified_fixture(transport: AnvilTransport, fx: ForkFixture) -> dict[str, Any]:
    """Apply one read-back-verified storage fixture. The write is kept only if the
    contract's own getter echoes ``verify_expected`` afterwards (the precondition
    holds — not proof this particular write is what the getter reads; see
    ``ForkFixture``); otherwise the inner snapshot is reverted so the failed write
    leaves no state behind. Never raises."""
    entry: dict[str, Any] = {"kind": fx.kind, "address": fx.address, "slot": fx.slot, "value": fx.value}
    if fx.kind != "set_storage_at" or fx.slot is None:
        entry["skipped"] = "unknown_kind"
        return entry
    inner = transport.snapshot()
    try:
        transport.set_storage_at(fx.address, fx.slot, fx.value)
        res = transport.call({"to": fx.verify_to, "data": fx.verify_calldata})
        ok = res.success and _word_eq(res.return_data, fx.verify_expected)
    except Exception as exc:  # noqa: BLE001 - a failed read-back only drops the fixture
        entry["error"] = str(exc)
        ok = False
    if ok:
        entry["readback"] = "ok"
        return entry
    transport.revert(inner)
    entry["readback"] = "failed"
    logger.info(
        "effects fork: dropped storage fixture at %s slot %s (read-back mismatch)",
        fx.address,
        fx.slot,
    )
    return entry


def _word_eq(return_data: str | None, expected: str | None) -> bool:
    """A direct getter returns exactly one 32-byte word; compare its low 32 bytes
    to the seeded word, ignoring 0x-prefix and case."""
    if not isinstance(return_data, str) or not isinstance(expected, str):
        return False
    got = return_data[2:] if return_data.lower().startswith("0x") else return_data
    want = expected[2:] if expected.lower().startswith("0x") else expected
    if len(got) < 64 or len(want) < 64:
        return False
    return got[-64:].lower() == want[-64:].lower()


def _succeeding_set(
    transport: AnvilTransport,
    entry_points: Sequence[EntryPoint],
    contract_address: str,
    transcript: dict[str, Any],
    label: str,
) -> set[str]:
    succeeding: set[str] = set()
    for ep in entry_points:
        tx: dict[str, Any] = {"to": ep.to or contract_address, "data": ep.calldata}
        if ep.from_addr is not None:
            tx["from"] = ep.from_addr
        res = transport.call(tx)
        transcript["results"].append(
            {"label": label, "entry_point": ep.key, "success": res.success, "revert": res.revert_data}
        )
        if res.success:
            succeeding.add(ep.key)
    return succeeding


# ---------------------------------------------------------------------------
# The single real-I/O transport. Spawns a localhost anvil; NEVER a forking anvil
# or real RPC from an agent (the fork-url path is the user's preview step).
# ---------------------------------------------------------------------------


def _build_anvil_cmd(
    anvil_bin: str,
    port: int,
    hardfork_name: str,
    fork_url: str | None,
    fork_headers: Mapping[str, str] | None,
    fork_block_number: int | None = None,
) -> list[str]:
    # ``--silent`` stays: measured on anvil 1.5.1 it suppresses the startup banner
    # and the per-RPC line, NOT the fatal startup errors (a bad fork URL and a
    # taken port both print verbatim under it). So the failure account this
    # subprocess is piped for survives, while the tail keeps naming the cause
    # instead of 40 ``eth_call`` lines — and the banner's dev private keys +
    # mnemonic never reach a log line or an exception message.
    cmd = [anvil_bin, "--port", str(port), "--hardfork", hardfork_name, "--silent"]
    if fork_url is not None:
        cmd += ["--fork-url", fork_url]
        # Unpinned, anvil forks at whatever head the upstream serves AT SPAWN, so
        # the state a Tier-2 verdict was observed against is neither recorded nor
        # reproducible. The pin is the caller's already-resolved preflight height;
        # ``0`` is that preflight's failure sentinel and would fork at GENESIS, so
        # only a positive height is ever passed and an unpinnable head leaves the
        # fork unpinned (and its height unpublished) rather than pinning a lie.
        if isinstance(fork_block_number, int) and not isinstance(fork_block_number, bool) and fork_block_number > 0:
            cmd += ["--fork-block-number", str(fork_block_number)]
        # eRPC (the production upstream) authenticates via a header, not the URL —
        # without this the fork upstream is unauthenticated and every lazy
        # getStorageAt/getCode fails. anvil applies each --fork-header to its fork
        # RPC requests.
        for key, value in (fork_headers or {}).items():
            cmd += ["--fork-header", f"{key}: {value}"]
    return cmd


class SubprocessAnvil:
    """Real anvil transport: one subprocess, localhost JSON-RPC (loopback, so the
    netguard allows it). Non-forking by default (offline integration test); a
    ``fork_url`` (+ optional ``fork_headers`` for an authenticated upstream like
    eRPC) is accepted for the user's preview step but agents never pass one.
    """

    def __init__(
        self,
        *,
        port: int = 8546,
        hardfork_name: str = "prague",
        fork_url: str | None = None,
        fork_headers: Mapping[str, str] | None = None,
        fork_block_number: int | None = None,
        anvil_bin: str = "anvil",
        startup_timeout: float = 20.0,
    ) -> None:
        self._url = f"http://127.0.0.1:{port}"
        self._hardfork = hardfork_name
        cmd = _build_anvil_cmd(anvil_bin, port, hardfork_name, fork_url, fork_headers, fork_block_number)
        # The height actually on the command line, not the one asked for: a
        # non-forking spawn and a rejected (non-positive) pin both leave this
        # ``None``, and ``fork_block_number()`` is what a recipe publishes from.
        self._fork_block: int | None = fork_block_number if "--fork-block-number" in cmd else None
        # Bounded so a chatty long-lived fork cannot grow the job's memory; it
        # holds only what a spawn/startup failure needs to be explainable.
        self._output_tail: deque[str] = deque(maxlen=_OUTPUT_TAIL_LINES)
        self._drain: threading.Thread | None = None
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                # One undecodable byte must not kill the drain: ``text=True``
                # defaults to strict, and a dead drain leaves the pipe unread
                # until anvil blocks writing into a full 64K buffer — holding the
                # port with a process nothing is reading.
                errors="replace",
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            raise AnvilSpawnError(f"failed to spawn anvil: {exc}") from exc
        # Everything from here on can leave a live process behind, so it all sits
        # under the cleanup guard: a failed ``Thread.start`` would leave the pipe
        # undrained (the backpressure deadlock above), and ``_anvil_version`` does
        # its own subprocess work that can raise.
        try:
            self._drain = threading.Thread(target=self._drain_output, name="anvil-log-drain", daemon=True)
            self._drain.start()
            self._foundry_version = _anvil_version(anvil_bin)
            self._wait_ready(startup_timeout)
        except BaseException:
            # A fork that never became usable must not leave its process (and the
            # drain thread reading it) behind for the rest of the job. A cleanup
            # failure must not replace the startup failure — that one carries the
            # returncode and the output tail the caller needs.
            try:
                self.close()
            except Exception:
                pass
            raise

    # -- lifecycle ---------------------------------------------------------

    def _drain_output(self) -> None:
        """Read anvil's merged stdout+stderr to EOF, logging each line and keeping
        the tail for error reporting. Runs for the life of the process: an
        undrained pipe would block anvil once its 64K buffer filled."""
        stream = self._proc.stdout
        if stream is None:  # pragma: no cover - stdout is always a pipe here
            return
        try:
            for raw in stream:
                line = raw.rstrip("\n")
                if not line:
                    continue
                self._output_tail.append(line)
                logger.log(logging.DEBUG, "%s", line, extra={"source": "anvil"})
        except BaseException as exc:
            # Either ``close`` pulled the fd (the normal end) or the read failed
            # for a reason we did not anticipate. Either way nothing will drain
            # this pipe again, so the stream is closed rather than left half-read:
            # anvil's next write then fails loudly instead of blocking forever on
            # a full buffer with the port still held.
            logger.debug("anvil drain stopped", extra={"source": "anvil", "exc_type": type(exc).__name__})
            try:
                stream.close()
            except Exception:
                pass

    def output_tail(self) -> list[str]:
        """The most recent drained output lines (bounded); empty before any output."""
        return list(self._output_tail)

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Deliberately NOT paired with ``record_degraded``: fork-close
                # cleanup is a resource side-effect (port/memory), not a
                # degradation of the stage's verdict output — the same exemption
                # class as ``effects_worker``'s allow-listed close handler.
                logger.warning(
                    "anvil did not exit on SIGTERM; escalating to SIGKILL",
                    extra={"source": "anvil", "pid": self._proc.pid, "terminate_timeout_s": 5},
                )
                self._proc.kill()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # An unreapable process is the caller's problem to notice via
                    # the port, not a reason for ``close`` itself to raise into a
                    # finally block.
                    logger.warning(
                        "anvil still present after SIGKILL",
                        extra={"source": "anvil", "pid": self._proc.pid},
                    )
        # The pipe hits EOF once the process is gone, so the drain thread ends on
        # its own; joining bounded (and closing the fd) keeps many open/close
        # cycles per job from accumulating threads or descriptors.
        drain = self._drain
        self._drain = None
        # ``ident`` is None until the thread actually started — joining one that
        # never started raises, and this must not mask the failure that brought
        # us here nor skip the fd cleanup below.
        if drain is not None and drain.ident is not None:
            drain.join(timeout=_DRAIN_JOIN_TIMEOUT_S)
            if drain.is_alive():
                # The process survived even SIGKILL, so the reader is still
                # blocked in ``read`` holding the buffer lock: ``close()`` would
                # wait on that lock forever and hang the job thread. The fd
                # leaks with the unkillable process — the lesser of the two, and
                # the WARNING above already named it.
                return
        if self._proc.stdout is not None:
            try:
                self._proc.stdout.close()
            except (ValueError, OSError):  # pragma: no cover - already closed
                pass

    def __enter__(self) -> SubprocessAnvil:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def rss_mb(self) -> int | None:
        """Resident set size of the anvil subprocess in whole MB, or ``None``
        when the answer is NOT KNOWN: the process has exited (poll reaps it, so
        a reused pid is never sampled) or ``/proc`` did not answer (unreadable,
        non-Linux host). ``rss_bytes_for_pid`` collapses both of those into
        ``0``, and publishing that as a measurement would say a fork used no
        memory when nothing measured it. A live process always reports a
        positive ``VmRSS``, so a zero read here IS the unreadable case.

        Never raises — RSS sampling must not fail a probe."""
        if self._proc.poll() is not None:
            return None
        measured = rss_bytes_for_pid(self._proc.pid)
        return measured // (1024 * 1024) if measured > 0 else None

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last_probe_error: Exception | None = None
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                returncode = self._proc.returncode
                # The drain thread may still be flushing the dying process's last
                # lines — those are exactly the ones that name the cause.
                drain = self._drain
                if drain is not None:
                    drain.join(timeout=_DRAIN_JOIN_TIMEOUT_S)
                tail = self.output_tail()
                logger.warning(
                    "anvil exited during startup",
                    extra={"source": "anvil", "returncode": returncode, "output_tail": tail},
                )
                raise AnvilSpawnError(
                    f"anvil exited during startup (returncode={returncode}): {' | '.join(tail) or '<no output>'}"
                ) from last_probe_error
            try:
                self._rpc("web3_clientVersion", [])
                return
            except Exception as exc:
                last_probe_error = exc
                time.sleep(0.1)
        tail = self.output_tail()
        logger.warning(
            "anvil did not become ready in time",
            extra={
                "source": "anvil",
                "startup_timeout_s": timeout,
                "last_probe_error": type(last_probe_error).__name__ if last_probe_error is not None else None,
                "output_tail": tail,
            },
        )
        # The last probe error is the closest thing to a cause the startup loop
        # holds; chaining it keeps it out of the discard pile.
        raise ForkRpcTimeoutError(
            f"anvil did not become ready in time: {' | '.join(tail) or '<no output>'}"
        ) from last_probe_error

    # -- transport surface -------------------------------------------------

    def hardfork(self) -> str:
        return self._hardfork

    def fork_block_number(self) -> int | None:
        return self._fork_block

    def versions(self) -> dict[str, str]:
        return {"anvil": self._foundry_version, "foundry": self._foundry_version}

    def snapshot(self) -> str:
        return str(self._rpc("evm_snapshot", []))

    def revert(self, snapshot_id: str) -> bool:
        return bool(self._rpc("evm_revert", [snapshot_id]))

    def impersonate(self, address: str) -> None:
        self._rpc("anvil_impersonateAccount", [address])
        # Fund the impersonated account so gas never masks an authorization gate.
        self._rpc("anvil_setBalance", [address, hex(10**19)])

    def stop_impersonate(self, address: str) -> None:
        self._rpc("anvil_stopImpersonatingAccount", [address])

    def call(self, tx: dict[str, Any]) -> EthCallResult:
        try:
            result = self._rpc("eth_call", [tx, "latest"])
        except _RpcError as exc:
            return EthCallResult(False, "0x", exc.revert_data, exc.message)
        return EthCallResult(True, result if isinstance(result, str) else "0x", None, None)

    def send(self, tx: dict[str, Any]) -> str:
        return str(self._rpc("eth_sendTransaction", [tx]))

    def deploy(self, from_addr: str, creation_bytecode: str) -> str:
        """Deploy ``creation_bytecode`` from an unlocked account and return the
        new contract address. Used only by the offline integration test's fixture
        setup on a non-forking anvil."""
        tx_hash = self._rpc("eth_sendTransaction", [{"from": from_addr, "data": creation_bytecode}])
        deadline = time.monotonic() + _TRANSACTION_RECEIPT_TIMEOUT_S
        while time.monotonic() < deadline:
            receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
            if isinstance(receipt, dict):
                contract_address = receipt.get("contractAddress")
                if isinstance(contract_address, str):
                    return contract_address
                raise ForkRpcTimeoutError(f"anvil deployment receipt for {tx_hash} has no contract address")
            time.sleep(_TRANSACTION_RECEIPT_POLL_INTERVAL_S)
        raise ForkRpcTimeoutError(f"anvil deployment receipt for {tx_hash} did not become available")

    def accounts(self) -> list[str]:
        return list(self._rpc("eth_accounts", []))

    def set_balance(self, address: str, value: str) -> None:
        self._rpc("anvil_setBalance", [address, value])

    def set_storage_at(self, address: str, slot: str, value: str) -> None:
        self._rpc("anvil_setStorageAt", [address, slot, value])

    def increase_time(self, seconds: int) -> None:
        self._rpc("evm_increaseTime", [hex(seconds)])

    def mine(self) -> None:
        self._rpc("evm_mine", [])

    # -- wire --------------------------------------------------------------

    def _rpc(self, method: str, params: list[Any]) -> Any:
        import requests

        try:
            resp = requests.post(
                self._url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            raise ForkRpcTimeoutError(f"anvil rpc {method} failed: {exc}") from exc
        if isinstance(payload, dict) and payload.get("error"):
            err = payload["error"]
            data = err.get("data") if isinstance(err, dict) else None
            revert = data if isinstance(data, str) and data.startswith("0x") else None
            raise _RpcError(str(err.get("message") if isinstance(err, dict) else err), revert)
        return payload.get("result") if isinstance(payload, dict) else None


class _RpcError(Exception):
    def __init__(self, message: str, revert_data: str | None) -> None:
        super().__init__(message)
        self.message = message
        self.revert_data = revert_data


def _anvil_version(anvil_bin: str) -> str:
    try:
        out = subprocess.run([anvil_bin, "--version"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip().splitlines()[0] if out.stdout else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def anvil_available(anvil_bin: str = "anvil") -> bool:
    """Whether a local anvil binary exists — gate for the offline integration
    test so a clone without foundry auto-skips rather than errors."""
    try:
        subprocess.run([anvil_bin, "--version"], capture_output=True, timeout=10, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
