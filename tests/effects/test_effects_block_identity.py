"""The height an effects verdict was observed at, and its honest absence.

``_build_anvil_cmd`` never passed ``--fork-block-number``, so Tier-2 forks sat at an unrecorded head (PR-161:
274 verdicts, 0 with ``block_number``). ``0`` is not a height, so failure arms assert the keys are absent.
"""

from __future__ import annotations

from typing import Any

import pytest

from db.effect_cache import (
    DEPLOYMENT_PLANE_KEYS,
    code_plane_details,
)
from services.effects import recipes
from services.effects.anvil import (
    EntryPoint,
    _build_anvil_cmd,
    fork_block_pin,
    pause_recipe,
)
from services.effects.claims_bridge import _observed_summary
from services.effects.config import (
    BLOCK_SOURCE_INVOCATION_PIN,
    BLOCK_SOURCES,
    DURATION_BOUND_NOT_DETERMINED,
    EFFECT_CLASS_FREEZE_PAUSE,
    VERDICT_PROVEN,
)
from services.effects.harness import SimContext, new_transcript
from services.effects.orchestrator import ProbeContext
from tests.support.effects_stubs import (
    GUARDED,
    PAUSE,
    RecordingStore,
    ScriptedSimulate,
    StubAnvil,
    ok,
    transfer_log,
    uint_ret,
)
from workers.effects_worker import EffectsWorker, _Seams

pytestmark = pytest.mark.anvil

PINNED_BLOCK = 25643300
CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20


class PinnedStubAnvil(StubAnvil):
    """``None`` models a fork at an unrecorded head."""

    def __init__(self, *, fork_block: int | None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fork_block = fork_block

    def fork_block_number(self) -> int | None:
        return self._fork_block


def _entry_points() -> list[EntryPoint]:
    return [EntryPoint(key="foo", calldata=GUARDED)]


def _pause(transport: Any, ctx: SimContext, store: RecordingStore):
    return pause_recipe(
        transport=transport,
        store=store,
        ctx=ctx,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=None,
    )


def _stub_seams(*, block_number: Any = None) -> _Seams:
    from unittest.mock import MagicMock

    from services.effects.preflight import InMemoryCapabilityStore

    store = InMemoryCapabilityStore()
    store.set_simulate_support(1, True)
    return _Seams(
        simulate=MagicMock(),
        transcript_store=RecordingStore(),
        capability_store=store,
        chain_id=1,
        block_number=block_number,
    )


def test_a_forking_spawn_pins_the_block_on_the_command_line():
    assert _build_anvil_cmd("anvil", 8546, "prague", "http://upstream", None, PINNED_BLOCK) == [
        "anvil",
        "--port",
        "8546",
        "--hardfork",
        "prague",
        "--silent",
        "--fork-url",
        "http://upstream",
        "--fork-block-number",
        "25643300",
    ]


def test_the_pin_survives_the_authenticated_upstream_form():
    assert _build_anvil_cmd(
        "anvil", 8600, "prague", "https://erpc/main/evm/1", {"X-ERPC-Secret-Token": "sec"}, PINNED_BLOCK
    ) == [
        "anvil",
        "--port",
        "8600",
        "--hardfork",
        "prague",
        "--silent",
        "--fork-url",
        "https://erpc/main/evm/1",
        "--fork-block-number",
        "25643300",
        "--fork-header",
        "X-ERPC-Secret-Token: sec",
    ]


@pytest.mark.parametrize("unpinnable", [None, 0, -1, False])
def test_an_unpinnable_head_forks_unpinned_rather_than_at_genesis(unpinnable):
    """``0`` is ``_preflight``'s failure sentinel; forking at it would record genesis as the observation height."""
    cmd = _build_anvil_cmd("anvil", 8546, "prague", "http://upstream", None, unpinnable)
    assert cmd == ["anvil", "--port", "8546", "--hardfork", "prague", "--silent", "--fork-url", "http://upstream"]


def test_a_non_forking_spawn_never_pins():
    # A pin on the empty-chain offline anvil would claim state it lacks.
    assert _build_anvil_cmd("anvil", 8546, "prague", None, {"X": "y"}, PINNED_BLOCK) == [
        "anvil",
        "--port",
        "8546",
        "--hardfork",
        "prague",
        "--silent",
    ]


def test_the_worker_spawns_its_fork_at_the_preflight_pin(monkeypatch):
    """The factory is built before the head is pinned and called after."""
    spawns: list[dict[str, Any]] = []

    class _FakeAnvil:
        def __init__(self, **kwargs: Any) -> None:
            spawns.append(kwargs)
            self._pin = kwargs.get("fork_block_number")

        def fork_block_number(self) -> Any:
            return self._pin

        def close(self) -> None:
            pass

    monkeypatch.setattr("services.effects.anvil.SubprocessAnvil", _FakeAnvil)
    monkeypatch.setattr("services.clients.rpc.rpc_headers", lambda url, extra=None: {})
    monkeypatch.setenv("PSAT_EFFECTS_FORK", "1")

    worker = EffectsWorker()
    seams = _stub_seams(block_number=lambda: PINNED_BLOCK)
    seams.anvil_factory = worker._anvil_factory(1, "http://rpc.example/1")
    supported, block = worker._preflight(seams, {})
    assert (supported, block) == (True, PINNED_BLOCK)

    from workers.effects_worker import _Counters

    ctx = worker._probe_context(seams, supported, block, _Counters())
    assert ctx.anvil_factory is not None
    ctx.anvil_factory()
    assert spawns[0]["fork_block_number"] == PINNED_BLOCK

    # A stale pin would fork the next job at a block it never observed.
    worker._close_anvil()
    assert worker._fork_block_pin is None


def test_a_failed_head_pin_leaves_the_fork_unpinned(monkeypatch):
    """Fail closed: no height rather than the ``0`` sentinel."""
    from utils.logging import degraded_errors_var

    spawns: list[dict[str, Any]] = []

    class _FakeAnvil:
        def __init__(self, **kwargs: Any) -> None:
            spawns.append(kwargs)
            self._pin = kwargs.get("fork_block_number")

        def fork_block_number(self) -> Any:
            return self._pin

        def close(self) -> None:
            pass

    monkeypatch.setattr("services.effects.anvil.SubprocessAnvil", _FakeAnvil)
    monkeypatch.setattr("services.clients.rpc.rpc_headers", lambda url, extra=None: {})
    monkeypatch.setenv("PSAT_EFFECTS_FORK", "1")

    def _boom() -> int:
        raise RuntimeError("upstream refused eth_blockNumber")

    worker = EffectsWorker()
    seams = _stub_seams(block_number=_boom)
    seams.anvil_factory = worker._anvil_factory(1, "http://rpc.example/1")

    errors: list = []
    token = degraded_errors_var.set(errors)
    try:
        supported, block = worker._preflight(seams, {})
    finally:
        degraded_errors_var.reset(token)

    assert supported is False
    assert block == 0
    assert any(getattr(e, "phase", None) == "effects_block_pin" for e in errors)

    from workers.effects_worker import _Counters

    ctx = worker._probe_context(seams, supported, block, _Counters())
    assert ctx.simulate_supported is False
    assert ctx.anvil_factory is not None
    ctx.anvil_factory()
    assert spawns[0]["fork_block_number"] is None


def test_tier1_publishes_the_pinned_height_and_the_scope_of_the_pin():
    ctx = ProbeContext(
        chain_id=1,
        block=PINNED_BLOCK,
        hardfork="prague",
        simulate=ScriptedSimulate(),
        simulate_supported=True,
        transcript_store=RecordingStore(),
    ).sim_context()
    from services.effects.simulate import SimResult

    res = SimResult(
        calls=(ok(uint_ret(1)), ok(logs=[transfer_log(CONTRACT, "0x" + "00" * 20, PRINCIPAL, 1)]), ok(uint_ret(2)))
    )
    store = RecordingStore()
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=store,
        ctx=ctx,
        token_address=CONTRACT,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["block_number"] == PINNED_BLOCK
    assert eff.details["block_source"] == BLOCK_SOURCE_INVOCATION_PIN
    assert eff.witness_payload["block_number"] == PINNED_BLOCK
    assert store.stored[0]["block_number"] == PINNED_BLOCK
    assert store.stored[0]["block_source"] == BLOCK_SOURCE_INVOCATION_PIN


def test_an_unpinnable_head_publishes_no_height_on_tier1():
    """A ``block_number`` of 0 would read as genesis."""
    ctx = ProbeContext(
        chain_id=1,
        block=0,
        hardfork="prague",
        simulate=ScriptedSimulate(),
        simulate_supported=False,
        transcript_store=RecordingStore(),
    ).sim_context()
    assert ctx.block_source is None
    tr = new_transcript(ctx, feature="supply", tier="tier1", effect_class="supply")
    assert "block_source" not in tr
    from services.effects.harness import emit, proven

    eff = emit(RecordingStore(), proven("supply", tier="tier1", details={}, transcript=tr))
    assert "block_number" not in eff.details
    assert "block_source" not in eff.details


def test_tier0_publishes_no_height_because_it_observed_no_single_block():
    """``ctx.block`` is a bystander for Tier 0, so stamping it would publish a height nothing was read at."""
    ctx = ProbeContext(
        chain_id=1,
        block=PINNED_BLOCK,
        hardfork="prague",
        simulate=ScriptedSimulate(),
        simulate_supported=True,
        transcript_store=RecordingStore(),
    ).sim_context()
    eff = recipes.code_upgrade(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=ctx,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x",
        sentinel_address="0x" + "ee" * 20,
        sentinel_override=None,
        impl_before=None,
        indexed_upgrade=True,
        current_impl_nonzero=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert "block_number" not in eff.details
    assert "block_source" not in eff.details


def test_tier2_publishes_the_height_the_fork_was_actually_pinned_at():
    transport = PinnedStubAnvil(fork_block=PINNED_BLOCK, guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    assert fork_block_pin(transport) == PINNED_BLOCK
    store = RecordingStore()
    # The fork's own pin is the witness, not the preflight number.
    eff = _pause(transport, SimContext(chain_id=1, block=PINNED_BLOCK - 495, hardfork="prague"), store)
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["block_number"] == PINNED_BLOCK
    assert eff.details["block_source"] == BLOCK_SOURCE_INVOCATION_PIN
    assert store.stored[0]["block_number"] == PINNED_BLOCK


@pytest.mark.parametrize("fork_block", [None, 0])
def test_an_unpinned_fork_publishes_height_not_determined_never_zero(fork_block):
    """The shape of the 78 existing Tier-2 rows, whose real height is unrecoverable."""
    transport = PinnedStubAnvil(fork_block=fork_block, guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    assert fork_block_pin(transport) is None
    eff = _pause(transport, SimContext(chain_id=1, block=PINNED_BLOCK, hardfork="prague"), RecordingStore())
    assert eff.verdict == VERDICT_PROVEN
    assert "block_number" not in eff.details
    assert "block_source" not in eff.details
    assert eff.details.get("block_number") != 0


def test_a_transport_that_cannot_answer_publishes_nothing():
    # Absence of the capability is absence of the witness, not a licence to use ``ctx.block``.
    transport = StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    assert fork_block_pin(transport) is None
    eff = _pause(transport, SimContext(chain_id=1, block=PINNED_BLOCK, hardfork="prague"), RecordingStore())
    assert "block_number" not in eff.details
    assert "block_source" not in eff.details


def test_a_raising_transport_publishes_nothing():
    class _Raising(PinnedStubAnvil):
        def fork_block_number(self) -> int | None:
            raise RuntimeError("rpc down")

    transport = _Raising(fork_block=PINNED_BLOCK, guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    assert fork_block_pin(transport) is None


def test_the_height_never_rides_the_behavioral_cache_onto_a_twin():
    """The observation height is world state, not a property of the bytecode."""
    assert "block_number" in DEPLOYMENT_PLANE_KEYS
    assert "block_source" in DEPLOYMENT_PLANE_KEYS
    stripped = code_plane_details(
        {"latch_flip": True, "block_number": PINNED_BLOCK, "block_source": BLOCK_SOURCE_INVOCATION_PIN}
    )
    assert stripped == {"latch_flip": True}


def test_the_claims_consumer_receives_the_height_or_its_absence():
    class _V:
        id = 1
        effect_class = EFFECT_CLASS_FREEZE_PAUSE
        verdict = VERDICT_PROVEN
        tier = "tier2"
        behavior_hash = None
        current_check_passed = None

        def __init__(self, witness: dict[str, Any]) -> None:
            self.witness = witness
            self.observed_residue = None

    carried = _observed_summary(_V({"pause_effective": True, "block_number": PINNED_BLOCK, "block_source": "run_pin"}))
    assert carried["block_number"] == PINNED_BLOCK
    assert carried["block_source"] == "run_pin"
    blank = _observed_summary(_V({"pause_effective": True}))
    assert "block_number" not in blank
    assert "block_source" not in blank


@pytest.mark.parametrize("bad_block", [0, -1, None, "25643300", True])
def test_the_publication_point_refuses_a_height_that_is_not_one(bad_block):
    """The stamp is the last gate before the witness; a string or ``True`` is not a block."""
    from services.effects.harness import _stamp_observation_height, proven

    eff = proven(
        "supply",
        tier="tier1",
        details={},
        transcript={"block_number": bad_block, "block_source": BLOCK_SOURCE_INVOCATION_PIN},
    )
    _stamp_observation_height(eff)
    assert eff.details == {}


def test_the_pin_scope_vocabulary_is_closed():
    assert BLOCK_SOURCES == ("invocation_pin", "job_pin", "run_pin")
    ctx = SimContext(chain_id=1, block=PINNED_BLOCK, hardfork="prague", block_source="head_minus_12")
    assert "block_source" not in new_transcript(ctx, feature="f", tier="tier1", effect_class="supply")


# All four proven freeze rows have a window their own holder can raise (read at block 25643300), so the window bounds
# one call, not the freeze.
FREEZE_ROWS = (
    ("0x1b7a4c3797236a1c37f8741c0be35c2c72736fff", 172800),
    ("0x308861a430be4cce5502d0a12724771fc6daf216", 86400),
    ("0x35fa164735182de50811e8e2e824cfb9b6118ac2", 28800),
    ("0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee", 28800),
)

BANNED_BOUND_KEYS = (
    "auto_expiry_source",
    "duration_bound_source",
    "expiry_observed_within_seconds",
    "expiry_ladder_exhausted_seconds",
    "declared_ceiling_seconds",
)


@pytest.mark.parametrize("address,readable_window", FREEZE_ROWS)
def test_a_readable_window_is_still_published_as_not_determined(address, readable_window):
    """The etherfi ``pauseUntil`` shape: readable on-chain and still not a bound."""
    transport = PinnedStubAnvil(
        fork_block=PINNED_BLOCK, guarded={GUARDED}, pause_calldata=PAUSE, duration=readable_window
    )
    eff = pause_recipe(
        transport=transport,
        store=RecordingStore(),
        ctx=SimContext(chain_id=1, block=PINNED_BLOCK, hardfork="prague"),
        contract_address=address,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=_entry_points(),
        predicted_guard_set=["foo"],
        max_pause_duration=None,
        duration_bound_source=DURATION_BOUND_NOT_DETERMINED,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["auto_expiry"] is None
    assert eff.details["duration_bound_seconds"] is None
    assert eff.details["duration_bound_source"] == DURATION_BOUND_NOT_DETERMINED
    assert transport.warped == 0
    for key in BANNED_BOUND_KEYS:
        if key == "duration_bound_source":
            continue
        assert key not in eff.details
    assert eff.details["duration_bound_source"] != "fork_observed_recovery"
