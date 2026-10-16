"""Bool pause claims follow the value a gate reverts on (``fixtures/contracts/pause/gate_polarity.sol``).

A write is ``pause.set`` when it writes the value another entry point's mandatory gate reverts on, and ``pause.unset``
when it writes the other value of a flag something can set to the blocking one. The writer's own gate never counts.
"""

from __future__ import annotations

import pytest

from tests.static.test_claims_pause_until import PAUSE_IDS, _artifacts

pytest.importorskip("slither")

pytestmark = pytest.mark.compile

FIXTURE = "gate_polarity.sol"


def _minted(contract: str) -> dict[str, set[str]]:
    claims = _artifacts(FIXTURE, contract)[3]
    minted = {sig: {c["claim_id"] for c in rows if c["claim_id"] in PAUSE_IDS} for sig, rows in claims.items()}
    return {sig: ids for sig, ids in minted.items() if ids}


def _flag(var: str) -> list[dict[str, str | None]]:
    return [{"var": var, "member": None}]


@pytest.mark.parametrize(
    ("contract", "why"),
    [
        ("MigrationFlag", "the only write unblocks the reader"),
        ("ForceTimer", "starting the timer unblocks the shutdown"),
        ("SelfTrippedKillSwitch", "only the writer reads the flag"),
        ("SelfCheckOnly", "only the writer reads the flag"),
    ],
)
def test_a_write_that_blocks_no_other_entry_point_claims_nothing(contract, why):
    assert _minted(contract) == {}, why


def test_closing_an_open_flag_is_the_pause():
    assert _minted("OpenCloseFlag") == {"closeStaking()": {"pause.set"}, "openStaking()": {"pause.unset"}}


def test_gates_comparing_with_a_bool_literal_read_their_reverting_value():
    assert _minted("EqualityGates") == {
        "freeze()": {"pause.set"},
        "thaw()": {"pause.unset"},
        "halt()": {"pause.set"},
        "goLive()": {"pause.unset"},
    }


def test_lowering_a_flag_the_victims_require_is_the_pause():
    assert _minted("InvertedKillSwitch") == {"deactivate()": {"pause.set"}}
    rows = _artifacts(FIXTURE, "InvertedKillSwitch")[3]["deactivate()"]
    claim = next(c for c in rows if c["claim_id"] == "pause.set")
    assert claim["witness"] == {"kind": "pause_flag", "flags": _flag("active"), "polarity": "set"}


def test_a_one_way_kill_switch_keeps_its_pause():
    assert _minted("OneWayKillSwitch") == {"disableRegistration()": {"pause.set"}}


def test_toggles_gated_by_each_other_keep_their_claims():
    assert _minted("PlainPausable") == {"pause()": {"pause.set"}, "unpause()": {"pause.unset"}}


def test_a_getter_negated_at_the_call_keeps_its_reverting_value():
    assert _minted("GetterGatedFlag") == {"closePool()": {"pause.set"}, "openPool()": {"pause.unset"}}


def test_a_getter_gate_under_a_negated_call_reads_its_reverting_value():
    assert _minted("GetterPausable") == {"pause()": {"pause.set"}, "unpause()": {"pause.unset"}}


@pytest.mark.parametrize(
    ("contract", "setter", "unsetter"),
    [
        ("ParameterComparedFlag", "lock()", "unlock()"),
        ("TwoSidedFlag", "pause()", "unpause()"),
    ],
)
def test_an_undetermined_blocking_value_keeps_the_written_value_reading(contract, setter, unsetter):
    """A gate against a parameter, or entry points blocked on either value, don't fix which value pauses; the claim
    falls back to reading ``true`` as the pause."""
    assert _minted(contract) == {setter: {"pause.set"}, unsetter: {"pause.unset"}}


def test_gate_reads_carry_the_reverting_value():
    from services.static.claims.context import ClaimContext
    from services.static.claims.matchers import _facts

    subject, effects, trees, _claims = _artifacts(FIXTURE, "EqualityGates")
    reads = _facts.gate_read_reverting_values(ClaimContext(subject, effects, trees))
    assert reads[("frozen", None)] == {"transfer(address,uint256)": frozenset({True})}
    assert reads[("live", None)] == {"transfer(address,uint256)": frozenset({False})}

    subject, effects, trees, _claims = _artifacts(FIXTURE, "ParameterComparedFlag")
    reads = _facts.gate_read_reverting_values(ClaimContext(subject, effects, trees))
    assert reads[("locked", None)] == {"act(address,uint256,bool)": frozenset({None})}

    subject, effects, trees, _claims = _artifacts(FIXTURE, "GetterPausable")
    reads = _facts.gate_read_reverting_values(ClaimContext(subject, effects, trees))
    assert reads[("_paused", None)] == {"transfer(address,uint256)": frozenset({True})}

    subject, effects, trees, _claims = _artifacts(FIXTURE, "GetterGatedFlag")
    reads = _facts.gate_read_reverting_values(ClaimContext(subject, effects, trees))
    assert reads[("_open", None)] == {"stake(address,uint256)": frozenset({False})}
