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
from services.monitoring.salience import (
    BASIS_QUALIFIED_MEMBER_CHANGE,
    BASIS_TRACKED_CONFIG_EVENT,
    SALIENCE_ALERT,
    SALIENCE_BASIS_VALUES,
    SALIENCE_NOTABLE,
    SALIENCE_VALUES,
)
from tests.support.monitoring_replay import baseline_identities, build_replay, load_replay_fixture

TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
GOV_TOKEN = "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb"


def test_replay_publishes_nothing_unwitnessed(db_session):
    """The differential: 446 REMOVED, 0 ADDED. Every recorded row was an open-path writer on
    an unreadable controller (activity tier), so the honest publication is nothing."""
    env = build_replay(db_session)
    env.run()

    produced = env.persisted_identities()
    expected = baseline_identities(env.fixture)

    added = produced - expected
    removed = expected - produced

    assert added == set()
    assert len(removed) == 446
    assert produced == set()

    # Every REMOVED row was an unwitnessed stem — i.e. the differential
    # removed exactly the claims the taxonomy exists to stop making, and not
    # some canonical event that got caught in the demotion. (Asserting the
    # absence of such a stem in ``produced`` would be vacuous: it is empty.)
    assert all(et.startswith("state_changed:") for _a, et, _t, _l in removed)


def test_replay_reproduces_all_446_recorded_rows_when_every_spec_publishes(db_session):
    """The pre-taxonomy behaviour, reproduced in-suite: forcing each spec back to
    ``self_describing`` must reproduce the recording identity-for-identity (all 446 rows,
    all five event shapes). Load-bearing liveness proof: without it "0 produced / 446
    removed" is indistinguishable from a fixture whose logs stopped decoding."""
    fixture = copy.deepcopy(load_replay_fixture())
    for contract in fixture["contracts"]:
        for spec in contract["monitoring_config"].get("tracked_topics") or []:
            spec["witness_tier"] = WITNESS_TIER_SELF_DESCRIBING

    from tests.support.monitoring_replay import ReplayEnv

    env = ReplayEnv(db_session, fixture).seed()
    env.run()

    produced = env.persisted_identities()
    expected = baseline_identities(fixture)
    assert produced - expected == set()
    assert expected - produced == set()
    assert len(produced) == 446

    by_type: dict[str, int] = {}
    for _addr, event_type, _tx, _li in produced:
        by_type[event_type] = by_type.get(event_type, 0) + 1
    assert by_type == {
        "state_changed:state_variable:_balances": 444,
        "state_changed:state_variable:locked": 2,
    }

    # All five decoded ABI shapes in the window actually round-tripped —
    # Transfer/Approval/DelegateVotesChanged on two tokens, Enter/Exit on one,
    # Deposit on the teller — so no shape is silently contributing zero.
    topics_seen = {log["topics"][0] for log in fixture["logs"]}
    assert len(topics_seen) == 6

    # Salience census (c) on the same run: all 446 rows must carry a level AND a non-empty basis. They
    # are ``self_describing`` so ``notable``; none collapse, since the routine arms need inputs
    # (``signal_class``, ``safe_exec`` status) no row here has.
    rated = env.persisted_salience()
    assert len(rated) == 446
    assert all(level in SALIENCE_VALUES for _et, level, _basis in rated)
    assert all(basis and set(basis) <= SALIENCE_BASIS_VALUES for _et, _level, basis in rated)

    by_level: dict[str | None, int] = {}
    for _event_type, level, _basis in rated:
        by_level[level] = by_level.get(level, 0) + 1
    assert by_level == {SALIENCE_NOTABLE: 446}
    assert {basis for _et, _level, basis in rated} == {(BASIS_TRACKED_CONFIG_EVENT,)}


def test_replay_classifies_every_window_spec(db_session):
    """Per-spec adjudication. ``_balances`` and ``locked`` are activity (no poll-decodable
    read spec; ``locked`` is a private Solmate reentrancy guard). F7 closes that residual
    from the other end (a latch restored within one call is no controller on re-analysis),
    but the PERSISTED row pinned here still has it. The two ``authority_updated`` specs stay
    self_describing and emitted no logs, which is why nothing was ADDED."""
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
    """None of these writes touch a control slot. Pinned so a
    taxonomy change cannot widen the trigger set as a side effect."""
    env = build_replay(db_session)
    env.run()
    assert db_session.query(Job).count() == 0


@pytest.mark.parametrize("openness", ["restricted", "open", "not_determined", None])
def test_member_witness_qualification_republishes_the_transfers(db_session, openness):
    """Liveness + the G3 interface on real logs: the 388 Transfer logs publish again once the
    spec carries a member witness AND a proven-restricted writer; anything weaker (including
    the absent third state) stays silent. The injected record names the
    mapping whose entry moved, since a record naming none promotes nothing and would test
    the refusal, not liveness."""
    fixture = copy.deepcopy(load_replay_fixture())
    for contract in fixture["contracts"]:
        if contract["address"] != GOV_TOKEN:
            continue
        for spec in contract["monitoring_config"]["tracked_topics"]:
            if spec["topic0"] == TRANSFER_TOPIC0:
                spec["member_witness"] = {
                    "mapping_name": "_balances",
                    "key_position": 0,
                    "direction": "set",
                }
                spec["event_type"] = "member_changed:_balances"
                if openness is not None:
                    spec["writer_openness"] = openness

    from tests.support.monitoring_replay import ReplayEnv

    env = ReplayEnv(db_session, fixture).seed()
    env.run()
    produced = env.persisted_identities()

    if openness == "restricted":
        assert len(produced) == 388
        assert {et for _a, et, _t, _l in produced} == {"member_changed:_balances"}
        # Census (c) on the qualified arm: a member change is a first-class
        # control-plane fact and every republished row says so, with its basis.
        rated = env.persisted_salience()
        assert len(rated) == 388
        assert {(level, basis) for _et, level, basis in rated} == {(SALIENCE_ALERT, (BASIS_QUALIFIED_MEMBER_CHANGE,))}
    else:
        assert produced == set()
