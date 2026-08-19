"""The height an effects verdict was observed at, and the honest absence of it.

Two defects are pinned here.

**The fork was never pinned.** ``_build_anvil_cmd`` passed ``--fork-url`` and no
``--fork-block-number``, so a Tier-2 anvil forked at whatever head the upstream
served AT SPAWN while the transcript recorded the preflight's height — a height
that is not provably the height the fork was taken at. Measured on the PR-161
run: 274 ``effect_verdicts``, **0** carrying a ``block_number`` (the key was
absent from ``witness`` entirely), and the 304 transcript blobs spanning 51
distinct heights over 495 blocks in one run. The argv assertions below are exact
LIST compares rather than membership checks precisely so an edit that drops the
pin fails here instead of silently restoring the unrecorded head.

**Zero is not a height.** ``_preflight`` returns ``block = 0`` when the head
cannot be pinned; ``0`` forks at GENESIS and would read as a real height. Every
failure arm below therefore asserts the two witness keys are ABSENT — not ``0``,
not ``None`` — which is the not_determined state a consumer must read as "this
verdict's observation height is unknown". Nothing is back-filled onto the 78
existing Tier-2 rows: an unpinned fork's true height is unrecoverable, not merely
unrecorded.

The B5 section pins a LABEL and nothing else. The four proven ``freeze_pause``
rows (``effect_verdicts`` 137/149/173/219, all ``pauseUntil()``) publish
``auto_expiry``/``duration_bound_seconds`` null with
``duration_bound_source = 'not_determined'``, and that must stay a confidence gap
in both directions: the window is mutable (``setPauseUntilDuration(uint256)``
dispatches on all four) and re-pause is unbounded, so no observed window bounds
the freeze and no bound may be published as a severity reducer.
"""

from __future__ import annotations

from pathlib import Path
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

# The reference height every pinned read in the investigation reproduces at.
PINNED_BLOCK = 25643300
CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20


class PinnedStubAnvil(StubAnvil):
    """A stub fork that can answer what height it was pinned at — the optional
    capability :func:`fork_block_pin` reads. ``None`` models the fork we shipped
    until now: forked, but at an unrecorded head."""

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


# ---------------------------------------------------------------------------
# B3 — the anvil command line. Exact list compares, on purpose.
# ---------------------------------------------------------------------------


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
    # The production spawn carries eRPC's auth header; the pin must not be
    # dropped by whichever argument was added last.
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
    """``0`` is ``_preflight``'s failure sentinel. Passing it would fork at block
    0 and then RECORD 0 as the observation height — a wrong answer with a real
    height's shape. The flag is omitted instead."""
    cmd = _build_anvil_cmd("anvil", 8546, "prague", "http://upstream", None, unpinnable)
    assert cmd == ["anvil", "--port", "8546", "--hardfork", "prague", "--silent", "--fork-url", "http://upstream"]


def test_a_non_forking_spawn_never_pins():
    # No fork, no fork height: the offline integration anvil starts from an empty
    # chain, and a pin there would be a claim about a state it does not have.
    assert _build_anvil_cmd("anvil", 8546, "prague", None, {"X": "y"}, PINNED_BLOCK) == [
        "anvil",
        "--port",
        "8546",
        "--hardfork",
        "prague",
        "--silent",
    ]


def test_the_worker_spawns_its_fork_at_the_preflight_pin(monkeypatch):
    """The factory is BUILT before the head is pinned and CALLED after, so the
    plumbing that carries the pin across that gap is what this holds."""
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
    monkeypatch.setattr("utils.rpc.rpc_headers", lambda url, extra=None: {})
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

    # The pin dies with the fork: the next job pins its own head, and a stale one
    # would spawn a fork at a block that job never observed.
    worker._close_anvil()
    assert worker._fork_block_pin is None


def test_a_failed_head_pin_leaves_the_fork_unpinned(monkeypatch):
    """FAIL-CLOSED. The seam raises ⇒ Tier 1 is off ⇒ the fork is spawned with no
    height rather than with the ``0`` sentinel."""
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
    monkeypatch.setattr("utils.rpc.rpc_headers", lambda url, extra=None: {})
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


# ---------------------------------------------------------------------------
# B3 — what reaches the witness.
# ---------------------------------------------------------------------------


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
    # The simulation ran at hex(block_number), so the recorded height IS the
    # observation height — byte-exact, and the scope says how far it is shared.
    assert eff.details["block_number"] == PINNED_BLOCK
    assert eff.details["block_source"] == BLOCK_SOURCE_INVOCATION_PIN
    assert eff.witness_payload["block_number"] == PINNED_BLOCK
    assert store.stored[0]["block_number"] == PINNED_BLOCK
    assert store.stored[0]["block_source"] == BLOCK_SOURCE_INVOCATION_PIN


def test_an_unpinnable_head_publishes_no_height_on_tier1():
    """The ``0`` sentinel names no scope, so both keys are absent — the third
    state. A ``block_number`` of 0 would read as genesis."""
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
    """Tier 0 decides from an indexed event history plus a current-state check
    (``observation: not_run``). ``ctx.block`` is a bystander there, so stamping it
    would publish a height nothing was read at."""
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
    # The caller's ctx carries a DIFFERENT height on purpose: the fork's own pin
    # is the witness, and the preflight number must not stand in for it.
    eff = _pause(transport, SimContext(chain_id=1, block=PINNED_BLOCK - 495, hardfork="prague"), store)
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["block_number"] == PINNED_BLOCK
    assert eff.details["block_source"] == BLOCK_SOURCE_INVOCATION_PIN
    assert store.stored[0]["block_number"] == PINNED_BLOCK


@pytest.mark.parametrize("fork_block", [None, 0])
def test_an_unpinned_fork_publishes_height_not_determined_never_zero(fork_block):
    """This is the shape of the 78 existing Tier-2 rows. Their real height is
    unrecoverable, so the honest published value is nothing at all."""
    transport = PinnedStubAnvil(fork_block=fork_block, guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    assert fork_block_pin(transport) is None
    eff = _pause(transport, SimContext(chain_id=1, block=PINNED_BLOCK, hardfork="prague"), RecordingStore())
    assert eff.verdict == VERDICT_PROVEN
    assert "block_number" not in eff.details
    assert "block_source" not in eff.details
    assert eff.details.get("block_number") != 0


def test_a_transport_that_cannot_answer_publishes_nothing():
    # The plain stub has no ``fork_block_number`` at all — absence of the
    # capability is absence of the witness, not a licence to use ``ctx.block``.
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
    """One deployment's observation height is a world state, not a property of
    the bytecode. Served from the cache it would tell a twin its verdict was
    observed at a block it was never probed at."""
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
    # Absent on the witness ⇒ absent on the projection. A consumer must not be
    # handed a height the verdict does not have.
    blank = _observed_summary(_V({"pause_effective": True}))
    assert "block_number" not in blank
    assert "block_source" not in blank


@pytest.mark.parametrize("bad_block", [0, -1, None, "25643300", True])
def test_the_publication_point_refuses_a_height_that_is_not_one(bad_block):
    """Belt-and-braces on the stamp itself. ``new_transcript`` already refuses to
    certify these, but the stamp is the last gate before the witness and must not
    depend on its caller having been careful — a stringly height or a ``True``
    that ``isinstance(_, int)`` would accept is not a block."""
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
    # An unrecognized source is not a source: the stamp is gated on membership,
    # so a typo'd or invented scope publishes nothing rather than a free-text tag.
    assert BLOCK_SOURCES == ("invocation_pin", "job_pin", "run_pin")
    ctx = SimContext(chain_id=1, block=PINNED_BLOCK, hardfork="prague", block_source="head_minus_12")
    assert "block_source" not in new_transcript(ctx, feature="f", tier="tier1", effect_class="supply")


# ---------------------------------------------------------------------------
# B5 — a label, and nothing that touches severity.
# ---------------------------------------------------------------------------

# The four proven freeze rows, and the on-chain facts that keep their window
# not_determined. Read at block 25643300 and reproduced by the adversarial pass:
# pauseUntilDuration() answers 172800 / 86400 / 28800 / 28800 and
# setPauseUntilDuration(uint256) DISPATCHES on all four (it reverts with guard
# data 0xadb09821, where a bogus selector reverts with none). A window its own
# holder can raise, on a latch nothing stops re-arming, bounds one call and not
# the freeze — so none of it may be published as a bound.
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
    """The etherfi ``pauseUntil`` shape. The window is READABLE on-chain
    (``readable_window`` seconds at 25643300) and is still not a bound on the
    freeze, so the recipe warps nothing and publishes no expiry either way."""
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
        # What the static plane hands over for these rows: no ceiling it can prove.
        max_pause_duration=None,
        duration_bound_source=DURATION_BOUND_NOT_DETERMINED,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["auto_expiry"] is None
    assert eff.details["duration_bound_seconds"] is None
    assert eff.details["duration_bound_source"] == DURATION_BOUND_NOT_DETERMINED
    # No warp was attempted: an unmeasured window is not probed into a number.
    assert transport.warped == 0
    for key in BANNED_BOUND_KEYS:
        if key == "duration_bound_source":
            continue
        assert key not in eff.details
    # And nothing that would let a consumer read a mitigation out of it.
    assert eff.details["duration_bound_source"] != "fork_observed_recovery"


def test_the_inspector_calls_an_unread_window_not_determined():
    """The rendered LABEL for the four rows above. Pinned here as well as in
    ``site/src/claimsVocab.test.js`` because the Python side is what decides the
    three-state the string is chosen from, and the two must not drift apart."""
    vocab = (Path(__file__).resolve().parents[2] / "site" / "src" / "claimsVocab.js").read_text()
    assert 'value: "window not determined"' in vocab
    # POSITIVE CONTROL: the proven-indefinite sentence is a PROVEN positive about
    # a different state (``no_time_reference``) and must survive intact — the
    # not_determined rename must not be applied by erasing a proven label.
    assert 'value: "indefinite latch (no self-recovery bound)"' in vocab
    assert "not determined (no freeze window read)" not in vocab
