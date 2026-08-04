"""Differential baseline for the recorded 2026-08-01 monitoring scan window.

Pins what the watcher published for that window so every taxonomy change is
measured as ADDED/REMOVED against a real run. The fixture's provenance and the
window derivation are documented in ``tests/monitoring_replay.py``.
"""

from __future__ import annotations

from db.models import Job
from tests.monitoring_replay import baseline_identities, build_replay, load_replay_fixture


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


def test_replay_reproduces_the_recorded_446_events(db_session):
    env = build_replay(db_session)
    env.run()

    produced = env.persisted_identities()
    expected = baseline_identities(env.fixture)

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


def test_replay_queues_no_reanalysis(db_session):
    """Invariant 5: none of these writes touch a control slot, so the recorded
    run spawned no jobs. Pinned so a taxonomy change cannot widen the trigger
    set as a side effect."""
    env = build_replay(db_session)
    env.run()
    assert db_session.query(Job).count() == 0
