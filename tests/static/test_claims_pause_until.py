"""Timestamp pause latches (``pausedUntil``) on the production static stack, over compiled fixtures in
``fixtures/contracts/pause/pause_until_*.sol``.

The positives are etherfi's ERC-7201 ``PausableUntil`` and a plain-storage latch. Each negative is pause-shaped except
for one conjunct of ``_facts.timestamp_latches``, so dropping that conjunct turns it into a false ``pause.set``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")

pytestmark = pytest.mark.compile

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "pause"
SOLC_VERSION = "0.8.27"

PAUSE_IDS = frozenset({"pause.set", "pause.unset"})

# The witness ``pauseUntil()`` carries; ``tests/discovery/test_membership_principal_witnesses.py`` admits a principal
# on exactly this claim.
NAMESPACED_FLAG = {"var": "PAUSABLE_UNTIL_STORAGE_SLOT", "member": "pausedUntil", "latch": "timestamp"}
PLAIN_FLAG = {"var": "pausedUntil", "member": None, "latch": "timestamp"}

Artifacts = tuple[Any, Mapping[str, Any], Mapping[str, Any], Mapping[str, list[Any]]]

NEGATIVES = {
    "TimelockEta": "mapping-keyed eta read only by execute",
    "TimelockGetterEta": "OZ v4 timelock eta read through getters, cleared by cancel",
    "PerUserCooldown": "per-account cooldown mapping",
    "RateLimitInterval": "the gated entry point re-arms the latch itself",
    "NamespacedRateLimit": "the gated entry point's modifier re-arms the namespaced latch",
    "DeadlineSale": "the gate opens while the timestamp is ahead of the clock",
    "SaleWindow": "another entry point is open only while the timestamp is ahead",
    "VestingCliff": "a bare clock stamp read with an offset",
    "VestingScheduled": "the latch is read with an offset",
    "VestingLock": "only the constructor arms it",
    "StakingRewardsPeriod": "the period can only run out, nothing clears it",
    "CommitApplyCancel": "the gated reader applies the value the armer staged",
    "ClockStampGuard": "the writer stamps the bare clock, never ahead of it",
    "DelayedAdminTransfer": "the reader requires the schedule set and clears it",
    "ArmedSchedule": "the reader requires the schedule set",
    "OneShotPauseUntil": "only the initializer arms it",
    "NoOtherReader": "no other entry point is gated by it",
    "UnguardedPauseUntil": "anyone can arm it",
    "BlockNumberGate": "armed in seconds, compared against the block number",
    "NamespacedMemberAlias": "only a per-user member of the same name is armed",
    "NamespacedTwoSlots": "only another namespace's member of the same name is armed",
    "NamespacedRebindRateLimit": "the gated entry point re-arms through a pointer it may rebind",
    "NamespacedLoopRebindRateLimit": "the gated entry point re-arms through a pointer rebound after use in a loop",
}


def _artifacts(fixture: str, contract: str) -> Artifacts:
    from slither import Slither

    from services.static.claims import build_claims
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts_with_pause_info,
    )
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract
    from tests.support.label_corpus import _solc_select_binary

    solc = _solc_select_binary(SOLC_VERSION)
    if not solc.exists():  # pragma: no cover - only when the pinned solc is absent
        pytest.skip(f"solc {SOLC_VERSION} not installed via solc-select")
    subject = _select_subject_contract(Slither(str(FIXTURES_DIR / fixture), solc=str(solc)), contract)
    assert subject is not None, contract
    trees, _pause_info = build_predicate_artifacts_with_pause_info(subject)
    effects = build_effects(subject)
    claims = build_claims(subject, effects, trees)["functions"]
    return subject, effects, trees, claims


@pytest.fixture(scope="module")
def namespaced() -> Artifacts:
    return _artifacts("pause_until_namespaced.sol", "NamespacedPauseUntil")


@pytest.fixture(scope="module")
def plain() -> Artifacts:
    return _artifacts("pause_until_plain.sol", "PlainPauseUntil")


def _pause_claims(claims: Mapping[str, list[Any]], signature: str) -> dict[str, dict]:
    rows = [c for c in claims[signature] if c["claim_id"] in PAUSE_IDS]
    by_id = {c["claim_id"]: c for c in rows}
    assert len(by_id) == len(rows), rows
    return by_id


def test_pause_until_arms_the_namespaced_latch(namespaced):
    claims = _pause_claims(namespaced[3], "pauseUntil()")
    assert set(claims) == {"pause.set"}
    assert claims["pause.set"]["tier"] == "idiom_structural"
    assert claims["pause.set"]["witness"] == {"kind": "pause_flag", "flags": [NAMESPACED_FLAG], "polarity": "set"}


def test_unpause_until_clears_the_member_not_a_bool_alias(namespaced):
    """Writing 0 to the member used to read as a bool ``false`` of the whole slot."""
    claims = _pause_claims(namespaced[3], "unpauseUntil()")
    assert set(claims) == {"pause.unset"}
    assert claims["pause.unset"]["tier"] == "idiom_structural"
    assert claims["pause.unset"]["witness"] == {"kind": "pause_flag", "flags": [NAMESPACED_FLAG], "polarity": "unset"}


def test_the_bool_latch_beside_it_is_unchanged(namespaced):
    bool_flag = {"var": "PAUSABLE_STORAGE_SLOT", "member": None}
    assert _pause_claims(namespaced[3], "pause()")["pause.set"]["witness"]["flags"] == [bool_flag]
    assert _pause_claims(namespaced[3], "unpause()")["pause.unset"]["witness"]["flags"] == [bool_flag]


@pytest.mark.parametrize("signature", ["setPauseUntilDuration(uint256)", "transfer(address,uint256)"])
def test_the_window_setter_and_the_victims_claim_nothing(namespaced, signature):
    assert _pause_claims(namespaced[3], signature) == {}


def test_plain_latch_set_unset_and_both(plain):
    claims = plain[3]
    assert _pause_claims(claims, "pauseFor(uint64)")["pause.set"]["witness"] == {
        "kind": "pause_flag",
        "flags": [PLAIN_FLAG],
        "polarity": "set",
    }
    assert set(_pause_claims(claims, "pauseFor(uint64)")) == {"pause.set"}
    # ``delete`` clears the latch.
    unset = _pause_claims(claims, "unpause()")
    assert set(unset) == {"pause.unset"}
    assert unset["pause.unset"]["witness"]["flags"] == [PLAIN_FLAG]
    both = _pause_claims(claims, "setPause(bool,uint64)")
    assert set(both) == {"pause.set", "pause.unset"}
    assert {c["tier"] for c in both.values()} == {"idiom_structural"}
    for signature in ("deposit()", "withdraw(uint256)"):
        assert _pause_claims(claims, signature) == {}


def test_the_oz_pausable_abi_over_a_timestamp_latch_stays_idiom_tier():
    """The standard tier rests on the OZ Pausable ABI, which describes a bool flag."""
    claims = _artifacts("pause_until_plain.sol", "OzAbiPauseUntil")[3]
    pause = _pause_claims(claims, "pause()")["pause.set"]
    assert (pause["tier"], pause["witness"]["flags"]) == ("idiom_structural", [PLAIN_FLAG])
    assert _pause_claims(claims, "unpause()")["pause.unset"]["tier"] == "idiom_structural"


@pytest.mark.parametrize("contract", sorted(NEGATIVES), ids=sorted(NEGATIVES))
def test_timestamp_state_that_is_not_a_pause_claims_nothing(contract):
    _subject, _effects, _trees, claims = _artifacts("pause_until_negatives.sol", contract)
    minted = {sig: sorted(c["claim_id"] for c in rows if c["claim_id"] in PAUSE_IDS) for sig, rows in claims.items()}
    assert {sig: ids for sig, ids in minted.items() if ids} == {}, NEGATIVES[contract]


def test_an_element_write_never_writes_the_scalar():
    """Leaves can name a mapping bare (OZ v4 ``TimelockController`` reads ``_timestamps`` through getters), so the eta
    write must stay an element write, never an arm or a clear of a scalar of that name."""
    from services.static.claims.context import ClaimContext
    from services.static.claims.matchers import _facts

    subject, effects, trees, _claims = _artifacts("pause_until_negatives.sol", "TimelockEta")
    ctx = ClaimContext(subject, effects, trees)
    assert _facts.latch_writes(ctx, "schedule(bytes32)", ("eta", None)) == frozenset()
    assert _facts._may_write(ctx, "schedule(bytes32)", ("eta", None))


def test_the_pause_window_stays_not_determined(namespaced, plain):
    """etherfi's window is state (``$.pauseUntilDuration``) and the plain one a parameter: neither may surface as a
    bound the scorer would read as auto-expiry.
    """
    from services.effects import calldata as cd

    latches = ((namespaced, "PAUSABLE_UNTIL_STORAGE_SLOT"), (plain, "pausedUntil"))
    for (_subject, effects, trees, _claims), latch in latches:
        facts = cd.ContractFacts(
            address="0x" + "00" * 20,
            job_id=None,
            effects=effects.get("functions") or {},
            trees=trees.get("trees") or {},
            canonical_signatures=trees.get("canonical_signatures") or {},
        )
        assert cd.read_max_pause_duration(facts, {latch}) == (None, "not_determined")


def test_the_witness_readers_parse_the_timestamp_flag(namespaced):
    """``summaries._pause_claims`` (``is_pausable``, ``pause_functions``) and the effects plane's latch pairs read the
    flag as they read a bool one."""
    from services.static.claims import attach_claims_to_effects
    from services.static.contract_analysis_pipeline.summaries import _pause_claims as summary_pause_claims

    subject, effects, trees, claims = namespaced
    attached = {"functions": {sig: dict(record) for sig, record in effects["functions"].items()}}
    attach_claims_to_effects(attached, {"functions": claims})
    pause_fns, unpause_fns, flags = summary_pause_claims(attached)
    assert {"pause()", "pauseUntil()"} <= pause_fns
    assert {"unpause()", "unpauseUntil()"} <= unpause_fns
    assert "PAUSABLE_UNTIL_STORAGE_SLOT.pausedUntil" in flags

    from services.effects.calldata.trees import guarded_functions

    victims = guarded_functions(trees["trees"], {("PAUSABLE_UNTIL_STORAGE_SLOT", "pausedUntil")})
    assert "transfer(address,uint256)" in victims
