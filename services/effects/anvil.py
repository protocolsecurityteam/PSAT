"""Tier-2 anvil fork transport and the freeze/pause recipe.

Tier 2 is for effects needing sequencing or time (a freeze's blast radius and auto-expiry at the contract's own
``MAX_PAUSE_DURATION``), which ``eth_call``/``eth_simulateV1`` can't express. Only :class:`SubprocessAnvil` does real
I/O; everything else takes an injected :class:`AnvilTransport`.

The hardfork is pinned, asserted and recorded per transcript (pre-Cancun EIP-6780 semantics mint wrong witnesses), as is
the anvil version. Fork access is single-flight (snapshot/revert is process-global; ``PSAT_EFFECTS_JOB_CONCURRENCY=1``).
``MAX_PAUSE_DURATION`` is read from source by the caller. Agents never run a forking anvil or real RPC; the offline test
uses a local non-forking anvil.
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

# Output quoted back on spawn failure, and the drain-thread join timeout (the thread is a daemon).
_OUTPUT_TAIL_LINES = 40
_DRAIN_JOIN_TIMEOUT_S = 2.0
_TRANSACTION_RECEIPT_TIMEOUT_S = 15.0
_TRANSACTION_RECEIPT_POLL_INTERVAL_S = 0.05

# Forks with EIP-6780 semantics; earlier ones mint witnesses wrong for the live chain.
POST_CANCUN_HARDFORKS = frozenset({"cancun", "prague", "osaka"})


@dataclass(frozen=True)
class ForkFixture:
    """Fork state a probe needs to be meaningful (a funded caller, a precondition slot), applied inside the recipe's
    snapshot.

    ``kind`` is ``set_balance`` (``address``/``value``) or ``set_storage_at`` (``address``/``slot``/``value``); unknown
    kinds are ignored.

    A ``set_storage_at`` may carry a read-back spec (``verify_to``, ``verify_calldata``, ``verify_expected``): after
    writing, the contract's own getter must return ``verify_expected``. That proves the precondition holds, not that
    this write is what the getter reads; a stray write can only shrink the observed lower bound.
    """

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

    ``key`` only labels which points reverted, never classifies. ``to`` defaults to the recipe's contract. ``fixtures``
    is the state this probe needs to succeed pre-pause, kept per entry point for inspection.
    """

    key: str
    calldata: str
    from_addr: str | None = None
    to: str | None = None
    fixtures: tuple["ForkFixture", ...] = ()


class AnvilTransport(Protocol):
    """Fork transport seam. ``call`` is read-only; ``send`` executes an impersonated tx against the local fork only."""

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
    """The height ``transport``'s fork was provably pinned at, else ``None``.

    An optional capability, not part of :class:`AnvilTransport`: stubs and unpinned forks return ``None`` and the recipe
    publishes no height. Falling back to the preflight pin would be wrong, since an unpinned fork's height is
    unrecoverable.
    """
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
    """Assert the fork is post-Cancun and return the hardfork for the transcript; raises ``ValueError`` otherwise."""
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
    """Freeze/pause probe.

    Snapshot, record the pre-pause succeeding entry points, call F as the principal, re-probe: the newly reverting set
    is the observed blast radius (a lower bound). Then warp by the source-read ``max_pause_duration`` and re-probe for
    auto-expiry. The scored denominator stays static's ``predicted_guard_set``; the observed set only upgrades members
    to witnessed.
    """
    hardfork = assert_post_cancun(transport)
    # The fork's own height, not the preflight pin; an unpinned fork records neither.
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
        # Inside the snapshot and before the pre-pause probe, or an unfunded point would silently shrink the blast
        # radius.
        _apply_fixtures(transport, [*fixtures, *(fx for ep in entry_points for fx in ep.fixtures)], tr)
        pre_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "pre_pause")

        # ``eth_call`` the pause first: a revert means the pauser can't enact it on this state, so the freeze was never
        # tested. That's reported as ``pause_ineffective`` with the raw revert, distinct from a pause that froze
        # nothing.
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
                        # The pause reverted, so the empty radius describes a probe that didn't happen.
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
            # Warping past the declared maximum is a sound over-warp; a latch still active then is indefinite.
            # Indefinite latches pass ``None`` and aren't warped.
            transport.increase_time(max_pause_duration + 1)
            transport.mine()
            expiry_succeeding = _succeeding_set(transport, entry_points, contract_address, tr, "post_expiry")
            # Auto-expiry is proven iff every frozen point succeeds again.
            auto_expiry = observed_blast.issubset(expiry_succeeding)
    finally:
        transport.revert(snap)

    tr["pre_pause_succeeding"] = sorted(pre_succeeding)
    tr["observed_blast_radius"] = sorted(observed_blast)
    tr["auto_expiry"] = auto_expiry

    predicted = {str(g) for g in predicted_guard_set}
    # Observed but unpredicted means static under-enumerated its guard set (a discrepancy). Predicted but unobserved is
    # expected (business preconditions hide points).
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
        # Nothing was live to freeze: every entry point already reverted on its own precondition, so the empty diff
        # measures the probe set, not the pause. Its own reason, kept out of ``_CACHEABLE_UNKNOWN_REASONS`` because it's
        # a property of this deployment's state.
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
                    # The pause ran, so the empty radius is a measurement.
                    "observation": OBSERVATION_EXECUTED,
                    # A genuine no-blast: the pause took effect and froze nothing observable.
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
            # Kernel witness (latch flip) plus projection witness (which points); the observed set is a lower bound
            # beside static's denominator.
            "latch_flip": True,
            "pause_effective": True,
            "observed_blast_radius": sorted(observed_blast),
            "pre_pause_succeeding": sorted(pre_succeeding),
            "scored_denominator": sorted(predicted),
            "auto_expiry": auto_expiry,
            "duration_bound_seconds": max_pause_duration,
            # Which ``None`` this is (see ``config.DURATION_BOUND_*``): with ``no_time_reference`` it's a
            # proven-indefinite freeze, with ``not_determined`` an unmeasured window.
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
    """Tier-2 timelock: schedule, advance time, execute.

    ``eth_simulateV1`` issues one block with no ``blockOverrides``, so it can never pass a delayed operation's timestamp
    gate. This reuses ``pause_recipe``'s fork machinery. The inner operation is an ERC-20 ``transfer`` to a sentinel on
    a token the timelock provably holds, so a sentinel balance gain after ``execute`` proves a proposer-chosen
    destination (``caller_arbitrary``).

    Fail-closed: ``schedule`` or ``execute`` reverts are their own unknowns with the raw revert; no sentinel movement
    stays ``no_value_observed``.

    Every verdict sets ``state_dependent=True`` so ``_is_cacheable`` refuses it: they rest on state this probe
    manufactured (the schedule, the time warp), not on the bytecode.
    """
    hardfork = assert_post_cancun(transport)
    # The fork's own height, not the preflight pin; an unpinned fork records neither.
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
            # A revert means the proposer can't schedule on this state (no PROPOSER_ROLE, already pending); never
            # testable.
            schedule_probe = transport.call({"from": principal, "to": contract_address, "data": schedule_calldata})
            tr["results"].append(
                {"label": "schedule", "success": schedule_probe.success, "revert": schedule_probe.revert_data}
            )
            if not schedule_probe.success:
                return _unknown("timelock_schedule_reverted", schedule_revert=schedule_probe.revert_data)
            transport.send({"from": principal, "to": contract_address, "data": schedule_calldata})
            transport.mine()

            # Before the delay, ``execute`` must revert; seeing that and then success after the warp proves the gate was
            # passed, not side-stepped.
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
            # Distinct: with no witness asset the timelock held nothing to move (our inability to measure); with one,
            # the operation executed and moved none.
            reason="no_value_observed" if witness_token is not None else "timelock_holds_no_witness_asset",
            details={
                # Executed (unreachable in Tier 1) but moved nothing we could witness.
                "observation": OBSERVATION_EXECUTED,
                "value_moved": False,
                "timelock_executed": True,
                "witness_asset_held": witness_token is not None,
            },
            transcript=tr,
        )
        # Rests on the schedule and time warp; must not transfer on the kernel hash.
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
            # Proven by the sentinel balance delta.
            "destination_shape": SHAPE_CALLER_ARBITRARY,
            "shape_proved_by": "simulation",
        },
        concrete={"destination": sentinel_address} if sentinel_address else {},
        transcript=tr,
    )
    eff.state_dependent = True
    return emit(store, eff)


def _has_verify_spec(fx: ForkFixture) -> bool:
    return fx.verify_to is not None and fx.verify_calldata is not None and fx.verify_expected is not None


def _apply_fixtures(transport: AnvilTransport, fixtures: Sequence[ForkFixture], transcript: dict[str, Any]) -> None:
    """Apply fork-state fixtures, recording each so replays start from the same state.

    Failed cheatcodes are recorded and skipped (can only shrink the radius).

    Plain fixtures go first; read-back-verified storage fixtures after, each under an inner snapshot that's reverted if
    the getter doesn't echo the word (``readback: failed``), else ``readback: ok``.
    """
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
    """Apply one read-back-verified storage fixture; kept only if the getter echoes ``verify_expected`` (see
    ``ForkFixture``), else reverted. Never raises.
    """
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
    """Compare a getter's 32-byte word to the seeded word, ignoring 0x prefix and case."""
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


# The single real-I/O transport: a localhost anvil. Forking is the user's preview step, never an agent's.


def _build_anvil_cmd(
    anvil_bin: str,
    port: int,
    hardfork_name: str,
    fork_url: str | None,
    fork_headers: Mapping[str, str] | None,
    fork_block_number: int | None = None,
) -> list[str]:
    # ``--silent`` hides the banner and per-RPC lines but not fatal startup errors (anvil 1.5.1), so the tail names the
    # cause and the dev keys never reach logs.
    cmd = [anvil_bin, "--port", str(port), "--hardfork", hardfork_name, "--silent"]
    if fork_url is not None:
        cmd += ["--fork-url", fork_url]
        # Pin to the caller's preflight height so the observed state is reproducible. ``0`` is the preflight failure
        # sentinel and would fork at genesis, so only positive heights are passed.
        if isinstance(fork_block_number, int) and not isinstance(fork_block_number, bool) and fork_block_number > 0:
            cmd += ["--fork-block-number", str(fork_block_number)]
        # eRPC authenticates via a header; without it every lazy fork read fails.
        for key, value in (fork_headers or {}).items():
            cmd += ["--fork-header", f"{key}: {value}"]
    return cmd


class SubprocessAnvil:
    """Real anvil transport: one subprocess on loopback JSON-RPC.

    Non-forking by default; ``fork_url`` (and ``fork_headers``) is for the user's preview step only.
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
        # The height actually on the command line; ``None`` for non-forking or rejected pins.
        self._fork_block: int | None = fork_block_number if "--fork-block-number" in cmd else None
        # Bounded so a long-lived fork can't grow memory.
        self._output_tail: deque[str] = deque(maxlen=_OUTPUT_TAIL_LINES)
        self._drain: threading.Thread | None = None
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                # Strict decoding would kill the drain on one bad byte, and an unread pipe blocks anvil once the buffer
                # fills.
                errors="replace",
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            raise AnvilSpawnError(f"failed to spawn anvil: {exc}") from exc
        # Everything below can leave a live process behind, so it's all under the cleanup guard.
        try:
            self._drain = threading.Thread(target=self._drain_output, name="anvil-log-drain", daemon=True)
            self._drain.start()
            self._foundry_version = _anvil_version(anvil_bin)
            self._wait_ready(startup_timeout)
        except BaseException:
            # Don't leave a failed fork's process behind; a cleanup failure mustn't replace the startup error.
            try:
                self.close()
            except Exception:
                pass
            raise

    def _drain_output(self) -> None:
        """Drain anvil's merged output to EOF, logging lines and keeping the tail.

        An undrained pipe blocks anvil at 64K.
        """
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
            # Nothing will drain this pipe again, so close it: anvil's next write fails loudly instead of blocking with
            # the port held.
            logger.debug("anvil drain stopped", extra={"source": "anvil", "exc_type": type(exc).__name__})
            try:
                stream.close()
            except Exception:
                pass

    def output_tail(self) -> list[str]:
        return list(self._output_tail)

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Not paired with ``record_degraded``: close cleanup is a resource side effect, not a verdict
                # degradation.
                logger.warning(
                    "anvil did not exit on SIGTERM; escalating to SIGKILL",
                    extra={"source": "anvil", "pid": self._proc.pid, "terminate_timeout_s": 5},
                )
                self._proc.kill()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Don't raise into a finally block.
                    logger.warning(
                        "anvil still present after SIGKILL",
                        extra={"source": "anvil", "pid": self._proc.pid},
                    )
        # Bounded join and fd close so repeated open/close doesn't leak threads or descriptors.
        drain = self._drain
        self._drain = None
        # Joining a never-started thread raises.
        if drain is not None and drain.ident is not None:
            drain.join(timeout=_DRAIN_JOIN_TIMEOUT_S)
            if drain.is_alive():
                # Survived SIGKILL: the reader holds the buffer lock, so ``close()`` would hang. Leak the fd instead.
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
        """Resident set size of the anvil process in MB, or ``None`` when unknown (exited, or ``/proc`` unreadable).

        ``rss_bytes_for_pid`` returns ``0`` for those, and a live process always has positive RSS, so zero means
        unreadable. Never raises.
        """
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
                # The drain may still be flushing the last lines, which name the cause.
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
        # Chain the last probe error as the likely cause.
        raise ForkRpcTimeoutError(
            f"anvil did not become ready in time: {' | '.join(tail) or '<no output>'}"
        ) from last_probe_error

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
        """Deploy ``creation_bytecode`` from an unlocked account; for offline test fixtures on a non-forking anvil."""
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
    """Whether a local anvil binary exists, so the offline test skips without foundry."""
    try:
        subprocess.run([anvil_bin, "--version"], capture_output=True, timeout=10, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
