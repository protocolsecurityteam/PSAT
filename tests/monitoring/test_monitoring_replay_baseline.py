"""Differential replay of the recorded 2026-08-01 scan window: 446 unwitnessed ``state_changed`` rows.

"0 rows, 446 removed" is also what a broken fixture produces, so the qualified-spec test requires the rows
back.
"""

from __future__ import annotations

import copy

import pytest

from services.monitoring.salience import (
    BASIS_QUALIFIED_MEMBER_CHANGE,
    SALIENCE_ALERT,
)
from tests.support.monitoring_replay import load_replay_fixture

TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
GOV_TOKEN = "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb"


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
        rated = env.persisted_salience()
        assert len(rated) == 388
        assert {(level, basis) for _et, level, basis in rated} == {(SALIENCE_ALERT, (BASIS_QUALIFIED_MEMBER_CHANGE,))}
    else:
        assert produced == set()
