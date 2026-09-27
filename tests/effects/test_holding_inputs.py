"""Positive holdings remain analysis inputs even when their price is unknown."""

from __future__ import annotations

from db.models import ContractBalance, ContractBalanceFetch
from services.effects.selection import (
    _asset_holdings_by_deployment,
    _token_holdings_by_contract,
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
def test_unpriced_positive_holdings_remain_observed_assets(db_session):
    """Unknown price must not erase a witnessed positive token balance."""
    p = _protocol(db_session, "holdings-record")
    deployment = ADDR(0x5101)
    c = _contract(db_session, p.id, deployment)
    first, second, third = ADDR(0x5111), ADDR(0x5112), ADDR(0x5113)
    fetch = _fetch(db_session, c, observed=deployment)
    for token in (first, second, third):
        _row(db_session, c, fetch, token, None, observed=deployment)
    db_session.flush()

    by_asset = {h.asset: h for h in _asset_holdings_by_deployment(db_session, p.id)[deployment.lower()]}
    assert set(by_asset) == {first.lower(), second.lower(), third.lower()}
    assert all(holding.usd_value is None for holding in by_asset.values())


@requires_postgres
def test_unpriced_holdings_are_offered_to_security_candidates(db_session):
    """A missing token price does not suppress a candidate or its asset witnesses."""
    p = _protocol(db_session, "unpriced-holders")
    deployment = ADDR(0x5201)
    c = _contract(db_session, p.id, deployment)
    first, second, third, fourth = ADDR(0x5211), ADDR(0x5212), ADDR(0x5213), ADDR(0x5214)
    fn = _fn(db_session, c.id, name="withdraw", selector="0xdd000001", effect_targets=["S"])
    _principal(db_session, fn.id, ADDR(0x5299))
    fetch = _fetch(db_session, c, observed=deployment)
    for token in (first, second, third, fourth):
        _row(db_session, c, fetch, token, None, observed=deployment)
    db_session.flush()

    cand = next(x for x in select_candidates(db_session, p.id) if x.selector == "0xdd000001")
    presented = {h.asset for h in cand.value_holders}
    assert presented == {first.lower(), second.lower(), third.lower(), fourth.lower()}


@requires_postgres
def test_priced_holdings_are_offered_as_input_tokens_in_value_order(db_session):
    """Token inputs remain ordered by measured value without a classification pass."""
    p = _protocol(db_session, "priced-inputs")
    deployment = ADDR(0x5301)
    c = _contract(db_session, p.id, deployment)
    large, small = ADDR(0x5311), ADDR(0x5312)
    fetch = _fetch(db_session, c, observed=deployment)
    _row(db_session, c, fetch, large, 9_000.0, observed=deployment)
    _row(db_session, c, fetch, small, 100.0, observed=deployment)
    db_session.flush()

    assert _token_holdings_by_contract(db_session, p.id, 10) == {c.id: (large.lower(), small.lower())}
