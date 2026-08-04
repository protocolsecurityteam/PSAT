"""Differential replay of the recorded 2026-08-01 monitoring scan window.

The fixture pins what the watcher published for that window before the witness
taxonomy landed: 446 rows, every one of them a ``state_changed:<controller_id>``
minted from an event occurrence with no witness behind it. These tests state
the ADDED/REMOVED story against that recording and keep it from drifting.

Liveness matters as much as the counts here: "0 rows, 446 removed" is also what
a broken fixture produces, so ``test_member_witness_qualification_republishes_
the_transfers`` runs the same logs through the same path with one spec
qualified and requires the rows back.
"""

from __future__ import annotations

import copy

import pytest

from db.models import Job
from services.monitoring.event_topics import (
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    classify_witness_tier,
)
from tests.monitoring_replay import baseline_identities, build_replay, load_replay_fixture

TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
GOV_TOKEN = "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb"


def test_fixture_carries_the_audited_window():
    """A fixture that lost its logs or its baseline must fail here, not pass
    downstream as a green zero-diff."""
    fixture = load_replay_fixture()
    assert len(fixture["logs"]) == 446
    assert len(fixture["baseline_event_identities"]) == 446
    assert len(baseline_identities(fixture)) == 446
    assert len(fixture["contracts"]) == 3
    assert fixture["window"] == {
        "chain": "ethereum",
        "chain_id": 1,
        "from_block": 25657762,
        "to_block": 25661204,
    }


def test_recorded_baseline_was_444_balances_and_2_locked():
    """The shape of what the pre-taxonomy run published, pinned from the
    recording so the differential below is read against a stated baseline
    rather than an implied one."""
    by_type: dict[str, int] = {}
    for _addr, event_type, _tx, _li, _hist in load_replay_fixture()["baseline_event_identities"]:
        by_type[event_type] = by_type.get(event_type, 0) + 1
    assert by_type == {
        "state_changed:state_variable:_balances": 444,
        "state_changed:state_variable:locked": 2,
    }


def test_replay_publishes_nothing_unwitnessed(db_session):
    """The differential: 446 REMOVED, 0 ADDED.

    Every recorded row was an occurrence of an open-path writer on a
    controller that cannot be read back — activity tier — so the honest
    publication for this window is nothing at all.
    """
    env = build_replay(db_session)
    env.run()

    produced = env.persisted_identities()
    expected = baseline_identities(env.fixture)

    added = produced - expected
    removed = expected - produced

    assert added == set()
    assert len(removed) == 446
    assert produced == set()

    # No row survives under either unwitnessed stem.
    assert not any(et.startswith(("state_changed:", "controller_changed:")) for _a, et, _t, _l in produced)


def test_replay_classifies_every_window_spec(db_session):
    """Per-spec adjudication of the differential.

    ``_balances`` and ``locked`` are activity — neither controller has a
    poll-decodable read spec, so no verification read exists to witness them.
    ``locked`` is the Solmate reentrancy guard: it is ``private``, exposes no
    getter, and is therefore not readable until F8 adds the analyzer-derived
    storage-slot emitter. The two ``authority_updated`` specs stay
    self_describing (canonical family, signature-corroborated) — they emitted
    no logs in this window, which is why nothing was ADDED.
    """
    fixture = load_replay_fixture()
    tiers: dict[str, set[str]] = {}
    for contract in fixture["contracts"]:
        config = contract["monitoring_config"] or {}
        plan = [entry for entry in (config.get("polling_plan") or []) if isinstance(entry, dict)]
        fields = {entry.get("field") for entry in plan}
        sources = {entry.get("source") for entry in plan}
        for spec in config.get("tracked_topics") or []:
            controller_id = spec.get("controller_id") or ""
            state_var = controller_id.split(":", 1)[1] if ":" in controller_id else controller_id
            tier = classify_witness_tier(
                event_type=spec.get("event_type"),
                controller_id=controller_id,
                inputs=spec.get("inputs"),
                effect_tags=spec.get("effect_tags"),
                member_witness=spec.get("member_witness"),
                writer_openness=spec.get("writer_openness"),
                poll_decodable=(f"analyzer:{controller_id}" in sources) or (state_var in fields),
            )
            tiers.setdefault(tier, set()).add(spec["event_type"])

    assert tiers[WITNESS_TIER_SELF_DESCRIBING] == {"authority_updated"}
    assert WITNESS_TIER_HINT not in tiers
    assert "state_changed:state_variable:_balances" in tiers[WITNESS_TIER_ACTIVITY]
    assert "state_changed:state_variable:locked" in tiers[WITNESS_TIER_ACTIVITY]


def test_replay_queues_no_reanalysis(db_session):
    """Invariant 5: none of these writes touch a control slot. Pinned so a
    taxonomy change cannot widen the trigger set as a side effect."""
    env = build_replay(db_session)
    env.run()
    assert db_session.query(Job).count() == 0


@pytest.mark.parametrize("openness", ["restricted", "open", "not_determined", None])
def test_member_witness_qualification_republishes_the_transfers(db_session, openness):
    """Liveness + the G3 interface, on the real logs.

    The same 388 Transfer logs that publish nothing as activity publish again
    the moment the spec carries a member witness AND a proven-restricted
    writer. Anything weaker than ``restricted`` — including the absent third
    state — leaves them silent, which is invariant 4 measured on real traffic
    rather than on a synthetic spec.
    """
    fixture = copy.deepcopy(load_replay_fixture())
    for contract in fixture["contracts"]:
        if contract["address"] != GOV_TOKEN:
            continue
        for spec in contract["monitoring_config"]["tracked_topics"]:
            if spec["topic0"] == TRANSFER_TOPIC0:
                spec["member_witness"] = {"key_position": 0, "direction": "set"}
                if openness is not None:
                    spec["writer_openness"] = openness

    from tests.monitoring_replay import ReplayEnv

    env = ReplayEnv(db_session, fixture).seed()
    env.run()
    produced = env.persisted_identities()

    if openness == "restricted":
        assert len(produced) == 388
        assert {et for _a, et, _t, _l in produced} == {"state_changed:state_variable:_balances"}
    else:
        assert produced == set()
