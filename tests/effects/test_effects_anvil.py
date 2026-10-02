"""The pause recipe runs against a stubbed ``AnvilTransport`` and, when foundry is installed, a local non-forking
anvil.

A forking anvil or real RPC is never used.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.clients.rpc import EthCallResult
from services.effects.anvil import (
    EntryPoint,
    SubprocessAnvil,
    anvil_available,
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
from tests.support.effects_stubs import GUARDED, PAUSE, UNGATED, RecordingStore, StubAnvil
from workers.effects_worker import _is_cacheable

pytestmark = pytest.mark.anvil

CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
CTX = SimContext(chain_id=1, block=1, hardfork="prague")

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures" / "effects" / "pausable_fixture.json").read_text())


def _entry_points():
    return [EntryPoint(key="foo", calldata=GUARDED), EntryPoint(key="ping", calldata=UNGATED)]


# ---------------------------------------------------------------------------
# pause — recorded-transcript recipe test
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
        duration_bound_source="guard_constant",
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.scope == SCOPE_PROJECTION
    assert eff.tier == TIER_FORK
    assert eff.details["observed_blast_radius"] == ["foo"]
    assert eff.details["latch_flip"] is True
    assert eff.details["auto_expiry"] is True
    assert eff.details["duration_bound_seconds"] == 3600
    assert eff.details["duration_bound_source"] == "guard_constant"
    assert transport.paused is False
    assert transport.impersonated == [PRINCIPAL]
    tr = store.stored[-1]
    assert tr["hardfork"] == "prague"
    assert tr["anvil_version"] == "anvil 1.5.1-stable"


def test_pause_recipe_no_blast_radius_is_unknown():
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
    assert eff.details["pause_effective"] is True
    assert eff.details["observation"] == "executed"


class IneffectivePauseAnvil(StubAnvil):
    """The pause calldata reverts, so the latch never flips."""

    def call(self, tx: dict) -> EthCallResult:
        if tx.get("data") == self._pause_calldata:
            return EthCallResult(False, "0x", "0x" + "cooldown".encode().hex(), "cooldown")
        return super().call(tx)

    def send(self, tx: dict) -> str:  # the pause tx would revert on-chain: no flip
        return "0xhash"


def test_pause_recipe_ineffective_pause_is_distinct_unknown():
    # A2 follow-up: the resolved pauser cannot enact the pause on this fork state
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
    assert eff.details["observation"] == "reverted"
    assert eff.details["scored_denominator"] == ["foo"]
    assert transport.paused is False
    assert any(r.get("label") == "pause_effectiveness" and r["success"] is False for r in store.stored[-1]["results"])


class DeadSurfaceAnvil(StubAnvil):
    """Every entry point reverts on its own precondition, pause or not."""

    def call(self, tx: dict) -> EthCallResult:
        if tx.get("data") == self._pause_calldata:
            return EthCallResult(True, "0x", None, None)
        return EthCallResult(False, "0x", "0x" + "precondition".encode().hex(), "precondition")


def test_a_dead_entry_point_surface_is_not_a_cacheable_no_blast():
    """An empty pre-set makes the empty radius true by construction, so it must not transfer to bytecode twins."""
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
    assert eff.details["scored_denominator"] == ["foo"]


# ---------------------------------------------------------------------------
# Tier-2 timelock — schedule → advance time → execute
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
    """``execute`` reverts until ``delay`` passes."""

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

    def versions(self) -> dict[str, str]:
        return {"anvil": "anvil 1.5.1-stable", "foundry": "anvil 1.5.1-stable"}

    def snapshot(self) -> str:
        self._n += 1
        sid = f"0x{self._n}"
        self._snaps[sid] = (self.time, self.ready, self.sentinel_balance)
        return sid

    def revert(self, snapshot_id: str) -> bool:
        self.time, self.ready, self.sentinel_balance = self._snaps[snapshot_id]
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
    # State-dependent, so it must never transfer on the kernel hash.
    assert eff.state_dependent is True
    assert not _is_cacheable(eff)
    # Proves the recipe advanced time.
    labels = {r["label"]: r for r in store.stored[-1]["results"]}
    assert labels["execute_premature"]["success"] is False
    assert labels["execute"]["success"] is True
    assert transport.impersonated == [PRINCIPAL]


def test_timelock_schedule_rejection_is_its_own_unknown():
    transport = TimelockAnvil(delay=TIMELOCK_DELAY, proposer_ok=False)
    eff = _timelock(transport)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "timelock_schedule_reverted"
    assert eff.details["schedule_revert"].startswith(UNAUTHORIZED)
    assert not _is_cacheable(eff)


def test_timelock_execution_that_moves_nothing_stays_unknown_but_records_execution():
    transport = TimelockAnvil(delay=TIMELOCK_DELAY, moves_value=False)
    eff = _timelock(transport)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "no_value_observed"
    assert eff.details["timelock_executed"] is True
    assert eff.details["observation"] == "executed"
    # no_value_observed is normally cacheable, but a timelock one required schedule + warp.
    assert eff.state_dependent is True
    assert not _is_cacheable(eff)
    assert eff.details["witness_asset_held"] is True


# eRPC needs a header, not URL auth.


@pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH")
def test_rss_mb_on_real_subprocess():
    anvil = SubprocessAnvil(port=8548, hardfork_name="prague")
    try:
        measured = anvil.rss_mb()
        assert measured is not None and measured > 0
    finally:
        anvil.close()
    assert anvil.rss_mb() is None


# ---------------------------------------------------------------------------
# hardfork pinned + recorded
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# the scored denominator is static's set, never the observed one
# ---------------------------------------------------------------------------


class VerifyStub(StubAnvil):
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


@pytest.mark.parametrize(
    "stub_kwargs, kept, readback, has_error",
    [
        pytest.param({"echo": "0x" + "00" * 31 + "07"}, True, "ok", False, id="kept-when-getter-echoes"),
        # CRITICAL: an unverified seed is reverted with its own inner snapshot id, never trusted.
        pytest.param(
            {"echo": "0x" + "00" * 31 + "01"}, False, "failed", False, id="dropped-when-getter-returns-wrong-word"
        ),
        pytest.param({"raise_on_call": True}, False, "failed", True, id="dropped-when-readback-call-raises"),
    ],
)
def test_verified_fixture_readback(stub_kwargs, kept, readback, has_error):
    from services.effects.anvil import _apply_fixtures

    word = "0x" + "00" * 31 + "07"
    transport = VerifyStub(**stub_kwargs)
    tr: dict = {}
    _apply_fixtures(transport, [_verified_fixture(word)], tr)
    assert not kept or transport.storage[(CONTRACT, "0x5")] == word  # a verified write is kept
    assert transport.reverted == ([] if kept else transport.snaps)
    assert tr["fixtures"][0]["readback"] == readback
    assert ("error" in tr["fixtures"][0]) is has_error


@pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH")
def test_pause_revert_set_diff_on_real_nonforking_anvil():
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
    assert "owner" in eff.details["pre_pause_succeeding"]
    assert eff.discrepancy is None
