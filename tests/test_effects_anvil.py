"""Tier-2 fork recipe tests (EFFECTS_RESOLUTION_SPEC §4.1, §8.7, §8.8).

The pause recipe is exercised two ways: against a stubbed ``AnvilTransport``
(hermetic, always runs) for the revert-set-diff logic and the §8 rules, and
against a real LOCAL NON-FORKING anvil with a checked-in fixture (gated behind an
anvil-availability probe — auto-skips on a clone without foundry). A forking
anvil / real RPC is NEVER used here (that is the user's preview step).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.effects.anvil import (
    EntryPoint,
    SubprocessAnvil,
    _build_anvil_cmd,
    anvil_available,
    assert_post_cancun,
    pause_recipe,
    timelock_execute_recipe,
)
from services.effects.config import (
    SCOPE_KERNEL,
    SCOPE_PROJECTION,
    SHAPE_CALLER_ARBITRARY,
    TIER_FORK,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import SimContext
from utils.rpc import EthCallResult
from workers.effects_worker import _is_cacheable

CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
CTX = SimContext(chain_id=1, block=1, hardfork="prague")

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "effects" / "pausable_fixture.json").read_text())


class RecordingStore:
    def __init__(self) -> None:
        self.stored: list[dict] = []

    def __call__(self, transcript: dict) -> str:
        self.stored.append(transcript)
        return f"artifact://transcript/{len(self.stored)}"


class StubAnvil:
    """Models a pausable contract on a fork: ``guarded`` entry points revert while
    paused-and-unexpired; ``send(pause_calldata)`` flips the latch; ``increase_time``
    past the duration auto-expires it. snapshot/revert restore the latch state."""

    def __init__(
        self, *, guarded: set[str], pause_calldata: str, duration: int | None, hardfork: str = "prague"
    ) -> None:
        self._guarded = guarded
        self._pause_calldata = pause_calldata
        self._duration = duration
        self._hf = hardfork
        self.paused = False
        self.time = 0
        self.expiry: int | None = None
        self._snaps: dict[str, tuple] = {}
        self._n = 0
        self.impersonated: list[str] = []
        self.log: list[str] = []
        self.balances: dict[str, str] = {}
        self.storage: dict[tuple[str, str], str] = {}

    def hardfork(self) -> str:
        return self._hf

    def versions(self) -> dict[str, str]:
        return {"anvil": "anvil 1.5.1-stable", "foundry": "anvil 1.5.1-stable"}

    def snapshot(self) -> str:
        self._n += 1
        sid = f"0x{self._n}"
        self._snaps[sid] = (self.paused, self.time, self.expiry)
        return sid

    def revert(self, snapshot_id: str) -> bool:
        self.paused, self.time, self.expiry = self._snaps[snapshot_id]
        return True

    def impersonate(self, address: str) -> None:
        self.impersonated.append(address)

    def stop_impersonate(self, address: str) -> None:
        self.log.append(f"stop:{address}")

    def call(self, tx: dict) -> EthCallResult:
        data = tx.get("data", "")
        frozen = self.paused and (self.expiry is None or self.time < self.expiry)
        if data in self._guarded and frozen:
            return EthCallResult(False, "0x", "0x" + "paused".encode().hex(), "paused")
        return EthCallResult(True, "0x", None, None)

    def send(self, tx: dict) -> str:
        if tx.get("data") == self._pause_calldata:
            self.paused = True
            self.expiry = None if self._duration is None else self.time + self._duration
        return "0xhash"

    def increase_time(self, seconds: int) -> None:
        self.time += seconds

    def mine(self) -> None:
        pass

    def set_balance(self, address: str, value: str) -> None:
        self.balances[address.lower()] = value

    def set_storage_at(self, address: str, slot: str, value: str) -> None:
        self.storage[(address.lower(), slot.lower())] = value


GUARDED = "0xc2985578"  # foo()
UNGATED = "0xffffffff"
PAUSE = "0x8456cb59"


def _entry_points():
    return [EntryPoint(key="foo", calldata=GUARDED), EntryPoint(key="ping", calldata=UNGATED)]


# ---------------------------------------------------------------------------
# §4.1 pause — recorded-transcript recipe test
# ---------------------------------------------------------------------------


def test_pause_recipe_observes_blast_radius_and_expiry():
    transport = StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=3600)
    store = RecordingStore()
    eff = pause_recipe(
        transport=transport,
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=3600,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.scope == SCOPE_PROJECTION
    assert eff.tier == TIER_FORK
    assert eff.details["observed_blast_radius"] == ["foo"]
    assert eff.details["latch_flip"] is True
    assert eff.details["auto_expiry"] is True
    assert eff.details["duration_bound_seconds"] == 3600
    # Snapshot was reverted; principal impersonation was scoped + released.
    assert transport.paused is False
    assert transport.impersonated == [PRINCIPAL]
    # Transcript records anvil version + hardfork (§8.7).
    tr = store.stored[-1]
    assert tr["hardfork"] == "prague"
    assert tr["anvil_version"] == "anvil 1.5.1-stable"


def test_pause_recipe_no_blast_radius_is_unknown():
    # A latch that guards nothing in the probed set → no observation → unknown.
    transport = StubAnvil(guarded=set(), pause_calldata=PAUSE, duration=None)
    eff = pause_recipe(
        transport=transport,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=None,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "no_blast_radius_observed"
    # A GENUINE no-blast: the pause took effect but froze nothing observable.
    assert eff.details["pause_effective"] is True
    # The pause RAN, so the empty blast radius is a measurement.
    assert eff.details["observation"] == "executed"


class IneffectivePauseAnvil(StubAnvil):
    """Models a pauser the principal cannot enact: the pause calldata reverts on
    ``call`` (missing authority / an active cooldown), so ``send`` never flips the
    latch. Everything else inherits from :class:`StubAnvil`."""

    def call(self, tx: dict) -> EthCallResult:
        if tx.get("data") == self._pause_calldata:
            return EthCallResult(False, "0x", "0x" + "cooldown".encode().hex(), "cooldown")
        return super().call(tx)

    def send(self, tx: dict) -> str:  # the pause tx would revert on-chain: no flip
        return "0xhash"


def test_pause_recipe_ineffective_pause_is_distinct_unknown():
    # §1 A2 follow-up: the resolved pauser cannot enact the pause on this fork state
    # → the freeze was never tested → a DISTINCT indeterminate unknown, never
    # conflated with a genuine "pause froze nothing".
    transport = IneffectivePauseAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    store = RecordingStore()
    eff = pause_recipe(
        transport=transport,
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=None,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "pause_ineffective"
    assert eff.details["pause_effective"] is False
    assert eff.details["observed_blast_radius"] == []
    # The pause call REVERTED, so the empty radius above describes a probe that
    # never happened — the discriminator every consumer of ``witness`` joins on.
    assert eff.details["observation"] == "reverted"
    # The scored denominator (static's set) is preserved for the consumer.
    assert eff.details["scored_denominator"] == ["foo"]
    # The pause was never sent → the snapshot was still reverted, latch untouched.
    assert transport.paused is False
    # The raw revert is recorded on the transcript for the live cycle.
    assert any(r.get("label") == "pause_effectiveness" and r["success"] is False for r in store.stored[-1]["results"])


def test_pause_recipe_proven_records_pause_effective():
    transport = StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=3600)
    eff = pause_recipe(
        transport=transport,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=3600,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["pause_effective"] is True
    assert eff.details["observation"] == "executed"


class DeadSurfaceAnvil(StubAnvil):
    """Every entry point already reverts on its OWN precondition — an unfunded
    caller, an unmet business rule — pause or no pause. The pause itself enacts
    fine. Nothing was live to freeze."""

    def call(self, tx: dict) -> EthCallResult:
        if tx.get("data") == self._pause_calldata:
            return EthCallResult(True, "0x", None, None)
        return EthCallResult(False, "0x", "0x" + "precondition".encode().hex(), "precondition")


def test_a_dead_entry_point_surface_is_not_a_cacheable_no_blast():
    """``observed_blast = pre - post``, so an empty PRE set makes the empty radius
    true by construction: it measures the probe set, not the latch. Sharing the
    ``no_blast_radius_observed`` reason let that transfer on the behavioral hash,
    publishing "this pause froze nothing" to every bytecode twin on the strength
    of a surface that happened to be dead at this block."""
    eff = pause_recipe(
        transport=DeadSurfaceAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=None,
    )

    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "no_live_entry_points_to_freeze"
    assert eff.details["pre_pause_succeeding"] == []
    assert not _is_cacheable(eff)
    # The scored denominator is still static's set, as on every other pause row.
    assert eff.details["scored_denominator"] == ["foo"]


def test_a_live_surface_the_pause_leaves_alone_is_still_a_cacheable_no_blast():
    """The control the split exists for: points WERE live and the pause froze
    none of them. That IS an observation about the latch, and a twin inherits it."""
    eff = pause_recipe(
        transport=StubAnvil(guarded=set(), pause_calldata=PAUSE, duration=None),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=None,
    )

    assert eff.reason == "no_blast_radius_observed"
    assert eff.details["pre_pause_succeeding"]
    assert _is_cacheable(eff)


def test_every_pause_row_carries_an_observation_discriminator():
    """The fork tier writes ``witness=details`` through the same worker path as
    every other effect class, so it owes the same discriminator. It did not: a
    pause probe that REVERTED published ``{"pause_effective": false,
    "observed_blast_radius": []}`` with nothing in the payload to say the freeze
    was never tested. ``pause_effective`` happened to separate the two, but that
    is a class-local stand-in for a contract stated stage-wide."""

    def _run(transport):
        return pause_recipe(
            transport=transport,
            store=RecordingStore(),
            ctx=CTX,
            contract_address=CONTRACT,
            principal=PRINCIPAL,
            pause_calldata=PAUSE,
            entry_points=_entry_points(),
            predicted_guard_set=["foo"],
            max_pause_duration=None,
        )

    rows = [
        _run(StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)),  # proven
        _run(StubAnvil(guarded=set(), pause_calldata=PAUSE, duration=None)),  # ran, froze nothing
        _run(IneffectivePauseAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)),  # reverted
    ]

    assert {row.details["observation"] for row in rows} == {"executed", "reverted"}
    for row in rows:
        # An empty blast radius is only readable as a measurement on a row that ran.
        if row.details.get("observed_blast_radius") == []:
            assert row.details["observation"] in ("executed", "reverted")
        if row.details["observation"] == "reverted":
            assert row.verdict == VERDICT_UNKNOWN


# ---------------------------------------------------------------------------
# §9.5 Tier-2 timelock — schedule → advance time → execute
# ---------------------------------------------------------------------------

SCHEDULE = "0x01d5062a"  # schedule(...)
EXECUTE = "0x134008d3"  # execute(...)
SENTINEL = "0x" + "ee" * 20
TOKEN = "0x" + "44" * 20
WITNESS = "0x70a08231" + SENTINEL[2:].rjust(64, "0")  # balanceOf(sentinel)
TIMELOCK_DELAY = 172800  # 2 days
NOT_READY = "0x5ead8eb5"  # TimelockUnexpectedOperationState(bytes32,bytes32)
UNAUTHORIZED = "0xe2517d3f"  # AccessControlUnauthorizedAccount(address,bytes32)


class TimelockAnvil:
    """Models an OZ TimelockController on a fork: ``schedule`` records a pending
    operation whose ``execute`` reverts ``TimelockUnexpectedOperationState`` until
    ``delay`` seconds pass; a ready ``execute`` runs the inner op (a transfer that
    credits the sentinel). snapshot/revert restore the whole state machine."""

    def __init__(self, *, delay: int, proposer_ok: bool = True, moves_value: bool = True, hardfork: str = "prague"):
        self.delay = delay
        self.proposer_ok = proposer_ok
        self.moves_value = moves_value
        self._hf = hardfork
        self.time = 0
        self.ready: int | None = None
        self.sentinel_balance = 0
        self._snaps: dict[str, tuple] = {}
        self._n = 0
        self.impersonated: list[str] = []

    def hardfork(self) -> str:
        return self._hf

    def versions(self) -> dict:
        return {"anvil": "anvil 1.5.1-stable", "foundry": "anvil 1.5.1-stable"}

    def snapshot(self) -> str:
        self._n += 1
        sid = f"0x{self._n}"
        self._snaps[sid] = (self.time, self.ready, self.sentinel_balance)
        return sid

    def revert(self, sid: str) -> bool:
        self.time, self.ready, self.sentinel_balance = self._snaps[sid]
        return True

    def impersonate(self, address: str) -> None:
        self.impersonated.append(address)

    def stop_impersonate(self, address: str) -> None:
        pass

    def increase_time(self, seconds: int) -> None:
        self.time += seconds

    def mine(self) -> None:
        pass

    def set_balance(self, address: str, value: str) -> None:
        pass

    def set_storage_at(self, address: str, slot: str, value: str) -> None:
        pass

    def call(self, tx: dict) -> EthCallResult:
        data = tx.get("data", "")
        if data == WITNESS:
            return EthCallResult(True, "0x" + self.sentinel_balance.to_bytes(32, "big").hex(), None, None)
        if data == SCHEDULE:
            if not self.proposer_ok:
                return EthCallResult(False, "0x", UNAUTHORIZED + "00" * 32, "unauthorized")
            return EthCallResult(True, "0x", None, None)
        if data == EXECUTE:
            if self.ready is None or self.time < self.ready:
                return EthCallResult(False, "0x", NOT_READY + "00" * 32, "not ready")
            return EthCallResult(True, "0x", None, None)
        return EthCallResult(True, "0x", None, None)

    def send(self, tx: dict) -> str:
        data = tx.get("data", "")
        if data == SCHEDULE and self.proposer_ok:
            self.ready = self.time + self.delay
        elif data == EXECUTE and self.ready is not None and self.time >= self.ready and self.moves_value:
            self.sentinel_balance += 1000
        return "0xhash"


def _timelock(transport, **kw):
    return timelock_execute_recipe(
        transport=transport,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        schedule_calldata=SCHEDULE,
        execute_calldata=EXECUTE,
        delay_seconds=TIMELOCK_DELAY,
        sentinel_address=SENTINEL,
        witness_token=TOKEN,
        witness_calldata=WITNESS,
        **kw,
    )


def test_timelock_schedule_advance_execute_proves_a_caller_arbitrary_move():
    transport = TimelockAnvil(delay=TIMELOCK_DELAY)
    store = RecordingStore()
    eff = timelock_execute_recipe(
        transport=transport,
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        schedule_calldata=SCHEDULE,
        execute_calldata=EXECUTE,
        delay_seconds=TIMELOCK_DELAY,
        sentinel_address=SENTINEL,
        witness_token=TOKEN,
        witness_calldata=WITNESS,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.tier == TIER_FORK
    assert eff.scope == SCOPE_KERNEL
    assert eff.details["value_moved"] is True
    assert eff.details["destination_shape"] == SHAPE_CALLER_ARBITRARY
    assert eff.details["shape_proved_by"] == "simulation"
    # STATE-DEPENDENT (schedule landed + time advanced), so it must NEVER transfer
    # on the kernel hash — even though a proven verdict is otherwise cacheable.
    assert eff.state_dependent is True
    assert not _is_cacheable(eff)
    # The premature execute (before the warp) must have reverted on the not-ready
    # gate — that is what proves the recipe ADVANCED time rather than side-stepping.
    labels = {r["label"]: r for r in store.stored[-1]["results"]}
    assert labels["execute_premature"]["success"] is False
    assert labels["execute"]["success"] is True
    assert transport.impersonated == [PRINCIPAL]


def test_timelock_premature_execute_reverts_not_ready_proving_the_delay_gate():
    """The Tier-1 impossibility made explicit: before the warp the operation is not
    ready, so ``execute`` reverts with the not-ready selector. Observing that revert
    and its later success is what proves the recipe advanced time."""
    store = RecordingStore()
    timelock_execute_recipe(
        transport=TimelockAnvil(delay=TIMELOCK_DELAY),
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        schedule_calldata=SCHEDULE,
        execute_calldata=EXECUTE,
        delay_seconds=TIMELOCK_DELAY,
        witness_token=TOKEN,
        witness_calldata=WITNESS,
    )
    prem = {r["label"]: r for r in store.stored[-1]["results"]}["execute_premature"]
    assert prem["success"] is False
    assert prem["revert"].startswith(NOT_READY)


def test_timelock_schedule_rejection_is_its_own_unknown():
    transport = TimelockAnvil(delay=TIMELOCK_DELAY, proposer_ok=False)
    eff = _timelock(transport)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "timelock_schedule_reverted"
    assert eff.details["schedule_revert"].startswith(UNAUTHORIZED)
    # Never cacheable — a Tier-2 fork verdict is state-plane.
    assert not _is_cacheable(eff)


def test_timelock_execution_that_moves_nothing_stays_unknown_but_records_execution():
    transport = TimelockAnvil(delay=TIMELOCK_DELAY, moves_value=False)
    eff = _timelock(transport)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "no_value_observed"
    assert eff.details["timelock_executed"] is True
    assert eff.details["observation"] == "executed"
    # The soundness invariant: no_value_observed is in _CACHEABLE_UNKNOWN_REASONS,
    # but a TIMELOCK no_value_observed is state-dependent (it required schedule +
    # time advance), so it must NOT be cacheable — else it transfers a
    # "moves nothing" negative to a bytecode twin whose op was never scheduled.
    assert eff.state_dependent is True
    assert not _is_cacheable(eff)
    # It HELD the asset and moved none of it — the other half of the distinction
    # the next test pins.
    assert eff.details["witness_asset_held"] is True


def test_a_timelock_holding_no_asset_says_so_rather_than_moving_nothing():
    """The measured case on mainnet: a timelock holds authority, not funds, so
    there is no asset for a scheduled operation to move. Reporting that as
    "executed, moved nothing" would state a fact about the CONTRACT when the fact
    is about our inability to witness one (§0.0.4) — the sequence still ran, and
    the row has to say which of the two it observed."""
    transport = TimelockAnvil(delay=TIMELOCK_DELAY, moves_value=False)
    eff = timelock_execute_recipe(
        transport=transport,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        schedule_calldata=SCHEDULE,
        execute_calldata=EXECUTE,
        delay_seconds=TIMELOCK_DELAY,
        sentinel_address=SENTINEL,
        witness_token=None,
        witness_calldata=None,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "timelock_holds_no_witness_asset"
    assert eff.details["witness_asset_held"] is False
    # The delayed execution path itself still ran, which is the thing Tier 1
    # cannot reach and the thing this row is entitled to claim.
    assert eff.details["timelock_executed"] is True
    assert eff.details["observation"] == "executed"
    assert not _is_cacheable(eff)


# ---------------------------------------------------------------------------
# fork-header wiring — eRPC (and any authenticated upstream) needs a header, not
# URL auth. Non-forking spawns carry no fork flags.
# ---------------------------------------------------------------------------


def test_build_anvil_cmd_nonforking_has_no_fork_flags():
    cmd = _build_anvil_cmd("anvil", 8546, "prague", None, {"X-ERPC-Secret-Token": "s"})
    assert "--fork-url" not in cmd and "--fork-header" not in cmd


# ---------------------------------------------------------------------------
# rss_mb — anvil subprocess RSS sampling (feeds peak_anvil_rss_mb)
# ---------------------------------------------------------------------------


def _anvil_with_proc(proc: object) -> SubprocessAnvil:
    """A SubprocessAnvil whose only wired dependency is ``_proc`` — no real
    subprocess spawned, so ``rss_mb`` is exercised in isolation."""
    anvil = SubprocessAnvil.__new__(SubprocessAnvil)
    anvil._proc = proc  # type: ignore[attr-defined]
    return anvil


def test_rss_mb_positive_for_live_pid_zero_when_exited():
    import os

    class _LiveProc:
        pid = os.getpid()

        def poll(self):
            return None  # still running

    class _DeadProc:
        pid = os.getpid()

        def poll(self):
            return 0  # exited

    # A live process reports a non-negative MB figure (positive on Linux, 0 on a
    # non-Linux host where /proc is absent) and never raises.
    assert _anvil_with_proc(_LiveProc()).rss_mb() >= 0
    # An exited process is never sampled (guards against a reused pid) → 0.
    assert _anvil_with_proc(_DeadProc()).rss_mb() == 0


@pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH")
def test_rss_mb_on_real_subprocess():
    """A live NON-FORKING anvil reports positive RSS; 0 once closed."""
    anvil = SubprocessAnvil(port=8548, hardfork_name="prague")
    try:
        assert anvil.rss_mb() > 0
    finally:
        anvil.close()
    assert anvil.rss_mb() == 0


def test_build_anvil_cmd_forking_passes_auth_header():
    cmd = _build_anvil_cmd("anvil", 8600, "prague", "https://erpc/main/evm/1", {"X-ERPC-Secret-Token": "sec"})
    assert cmd[cmd.index("--fork-url") + 1] == "https://erpc/main/evm/1"
    assert cmd[cmd.index("--fork-header") + 1] == "X-ERPC-Secret-Token: sec"


# ---------------------------------------------------------------------------
# §8 rule 7 — hardfork pinned + recorded
# ---------------------------------------------------------------------------


def test_section8_rule7_stale_hardfork_refused():
    class Stale(StubAnvil):
        def hardfork(self) -> str:
            return "shanghai"

    transport = Stale(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    with pytest.raises(ValueError, match="not post-Cancun"):
        pause_recipe(
            transport=transport,
            store=RecordingStore(),
            ctx=CTX,
            contract_address=CONTRACT,
            principal=PRINCIPAL,
            pause_calldata=PAUSE,
            entry_points=_entry_points(),
            predicted_guard_set=["foo"],
            max_pause_duration=None,
        )


def test_assert_post_cancun_accepts_current_forks():
    class T(StubAnvil):
        def __init__(self, hf):
            super().__init__(guarded=set(), pause_calldata=PAUSE, duration=None, hardfork=hf)

    assert assert_post_cancun(T("cancun")) == "cancun"
    assert assert_post_cancun(T("prague")) == "prague"


# ---------------------------------------------------------------------------
# §8 rule 8 — the scored denominator is static's set, never the observed one
# ---------------------------------------------------------------------------


def test_section8_rule8_scored_denominator_is_static_not_observed():
    # Observe a guarded point ("foo") that static did NOT predict; predicted set is
    # {"bar"}. The scored denominator MUST stay static's set, and the surprise is a
    # §9 discrepancy (recorded, not routed).
    transport = StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    eff = pause_recipe(
        transport=transport,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["bar"],
        max_pause_duration=None,
    )
    assert eff.details["observed_blast_radius"] == ["foo"]
    assert eff.details["scored_denominator"] == ["bar"]
    assert eff.discrepancy is not None
    assert eff.discrepancy.kind == "observed_guard_not_predicted"
    assert eff.discrepancy.detail["unpredicted_members"] == ["foo"]


# ---------------------------------------------------------------------------
# Read-back-verified storage fixtures (_apply_fixtures)
# ---------------------------------------------------------------------------


class VerifyStub(StubAnvil):
    """Scripted transport for the verified-application path: ``call`` returns a
    fixed word (or raises), and reverts are recorded. Inherits the full
    :class:`AnvilTransport` surface from :class:`StubAnvil`."""

    def __init__(self, *, echo: str = "0x", raise_on_call: bool = False) -> None:
        super().__init__(guarded=set(), pause_calldata="0x", duration=None)
        self.echo = echo
        self.raise_on_call = raise_on_call
        self.snaps: list[str] = []
        self.reverted: list[str] = []

    def snapshot(self) -> str:
        sid = super().snapshot()
        self.snaps.append(sid)
        return sid

    def revert(self, snapshot_id: str) -> bool:
        self.reverted.append(snapshot_id)
        return super().revert(snapshot_id)

    def call(self, tx: dict) -> EthCallResult:
        if self.raise_on_call:
            raise RuntimeError("node error")
        return EthCallResult(True, self.echo, None, None)


def _verified_fixture(value: str):
    from services.effects.anvil import ForkFixture

    return ForkFixture(
        kind="set_storage_at",
        address=CONTRACT,
        value=value,
        slot="0x5",
        verify_to=CONTRACT,
        verify_calldata="0xabcdefff",
        verify_expected=value,
    )


def test_verified_fixture_kept_when_getter_echoes():
    from services.effects.anvil import _apply_fixtures

    word = "0x" + "00" * 31 + "07"
    transport = VerifyStub(echo=word)
    tr: dict = {}
    _apply_fixtures(transport, [_verified_fixture(word)], tr)
    assert transport.storage[(CONTRACT, "0x5")] == word  # write kept
    assert transport.reverted == []  # inner snapshot NOT reverted
    assert tr["fixtures"][0]["readback"] == "ok"


def test_verified_fixture_dropped_when_getter_returns_wrong_word():
    from services.effects.anvil import _apply_fixtures

    seed = "0x" + "00" * 31 + "07"
    transport = VerifyStub(echo="0x" + "00" * 31 + "01")  # wrong word
    tr: dict = {}
    _apply_fixtures(transport, [_verified_fixture(seed)], tr)
    # The inner snapshot is reverted with its own id, undoing the write.
    assert transport.reverted == transport.snaps
    assert tr["fixtures"][0]["readback"] == "failed"


def test_verified_fixture_dropped_when_readback_call_raises():
    from services.effects.anvil import _apply_fixtures

    seed = "0x" + "00" * 31 + "07"
    transport = VerifyStub(raise_on_call=True)
    tr: dict = {}
    _apply_fixtures(transport, [_verified_fixture(seed)], tr)
    assert transport.reverted == transport.snaps
    assert tr["fixtures"][0]["readback"] == "failed"
    assert "error" in tr["fixtures"][0]


def test_verified_fixtures_are_applied_after_plain_ones():
    from services.effects.anvil import ForkFixture, _apply_fixtures

    word = "0x" + "00" * 31 + "07"
    transport = VerifyStub(echo=word)
    plain = ForkFixture(kind="set_balance", address=PRINCIPAL, value="0x64")
    tr: dict = {}
    _apply_fixtures(transport, [_verified_fixture(word), plain], tr)
    # Order in the transcript: plain first, then the verified storage write.
    assert [f["kind"] for f in tr["fixtures"]] == ["set_balance", "set_storage_at"]
    assert transport.balances == {PRINCIPAL: "0x64"}


def test_forkfixture_backward_compatible_defaults():
    from services.effects.anvil import ForkFixture, _has_verify_spec

    fx = ForkFixture(kind="set_balance", address=PRINCIPAL, value="0x1")
    assert fx.verify_to is None and fx.verify_calldata is None and fx.verify_expected is None
    assert _has_verify_spec(fx) is False
    assert _has_verify_spec(_verified_fixture("0x" + "00" * 32)) is True


# ---------------------------------------------------------------------------
# Localhost NON-FORKING anvil integration — GATED behind availability
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH")
def test_pause_revert_set_diff_on_real_nonforking_anvil():
    """Deploy the checked-in pausable fixture to a fresh NON-FORKING anvil and
    prove the revert-set diff end-to-end: foo() succeeds pre-pause, reverts
    post-pause, and its key is exactly the observed blast radius."""
    with SubprocessAnvil(port=8547, hardfork_name="prague") as anvil:
        owner = anvil.accounts()[0]
        addr = anvil.deploy(owner, FIXTURE["creation_bytecode"])
        eff = pause_recipe(
            transport=anvil,
            store=RecordingStore(),
            ctx=SimContext(chain_id=31337, block=1, hardfork="prague"),
            contract_address=addr,
            principal=owner,
            pause_calldata=FIXTURE["selectors"]["pause"],
            entry_points=[
                EntryPoint(key="foo", calldata=FIXTURE["selectors"]["foo"]),
                EntryPoint(key="owner", calldata=FIXTURE["selectors"]["owner"]),
            ],
            predicted_guard_set=["foo"],
            max_pause_duration=None,
        )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["observed_blast_radius"] == ["foo"]
    # owner() is a plain getter — never in the blast radius.
    assert "owner" in eff.details["pre_pause_succeeding"]
    assert eff.discrepancy is None
