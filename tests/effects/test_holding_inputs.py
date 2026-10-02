from __future__ import annotations

from db.models import ContractBalance, ContractBalanceFetch
from services.effects.selection import (
    select_candidates,
)
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _contract, _fn, _principal, _protocol
from utils.balance_status import (
    ASSET_SET_STATUS_RETURNED_ASSETS,
    BALANCE_WRITER_TVL,
)


def _fetch(session, contract, *, observed: str, chain_id: int = 1) -> ContractBalanceFetch:
    row = ContractBalanceFetch(
        contract_id=contract.id,
        chain_id=chain_id,
        observed_address=observed,
        native_status="not_determined",
        asset_set_status=ASSET_SET_STATUS_RETURNED_ASSETS,
        writer=BALANCE_WRITER_TVL,
    )
    session.add(row)
    session.flush()
    return row


def _row(session, contract, fetch, token: str | None, usd, *, observed: str) -> None:
    session.add(
        ContractBalance(
            contract_id=contract.id,
            fetch_id=fetch.id,
            token_address=token,
            raw_balance="1000000000000000000",
            decimals=18,
            usd_value=usd,
            observed_address=observed,
        )
    )


@requires_postgres
def test_selected_candidates_keep_two_priced_tokens_and_resource_cap(db_session):
    p = _protocol(db_session, "original-analysis-caps")
    deployment = ADDR(0x5401)
    c = _contract(db_session, p.id, deployment)
    for i in range(3):
        fn = _fn(db_session, c.id, name=f"withdraw{i}", selector=f"0xdd00001{i}", effect_targets=["S"])
        _principal(db_session, fn.id, ADDR(0x5499))
    fetch = _fetch(db_session, c, observed=deployment)
    for token, usd in [(ADDR(0x5411), 1000), (ADDR(0x5412), 100), (ADDR(0x5413), 10), (ADDR(0x5414), None)]:
        _row(db_session, c, fetch, token, usd, observed=deployment)
    db_session.flush()
    funnel = {}
    candidates = select_candidates(db_session, p.id, resource_cap=1, funnel=funnel)
    assert len(candidates) == 1
    assert candidates[0].input_token_addresses == (ADDR(0x5411).lower(), ADDR(0x5412).lower())
    assert len(candidates[0].value_holders) == 4  # Holdings evidence retains unpriced assets.
    assert funnel["cap_dropped"] == 2
    assert "deferred_candidates" not in funnel
