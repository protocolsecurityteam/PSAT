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

from services.effects.anvil import EntryPoint, SubprocessAnvil, anvil_available, assert_post_cancun, pause_recipe
from services.effects.config import SCOPE_PROJECTION, TIER_FORK, VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext
from utils.rpc import EthCallResult

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
