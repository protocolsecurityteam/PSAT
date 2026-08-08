"""Delivery shape is carried on every holding, and only ``fan_out_all`` is withheld.

§10.6.9's acceptance test on the selection plane: a holding whose every recorded
delivery was a mass distribution must not be PRESENTED as a position the protocol
holds, while the record of it stays and stays labelled. The two facts are separate
and both are tested here, because a disposition that removed the row would be an
unwitnessed deletion — and this plane reads a record's mere existence as "this
deployment holds this asset".

Nothing here is a claim about worth. Two demonstrably real tokens on this corpus are
airdrop-delivered (uniETH at fan-out 101, HEX at 199/399/399); the published state
says how the balance arrived and nothing else.
"""

from __future__ import annotations

from db.models import ContractBalance, ContractBalanceFetch, TokenDeliveryEvidence
from services.effects.selection import (
    _asset_holdings_by_deployment,
    _merged_delivery_shape,
    _token_holdings_by_contract,
    select_candidates,
)
from tests.conftest import ADDR, requires_postgres
from tests.test_effects_selection import _contract, _fn, _principal, _protocol
from utils.balance_status import (
    ASSET_SET_STATUS_RETURNED_ASSETS,
    BALANCE_WRITER_TVL,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
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


def _evidence(session, *, holder: str, token: str, shape: str, chain_id: int = 1, fan_out: int = 400) -> None:
    session.add(
        TokenDeliveryEvidence(
            chain_id=chain_id,
            holder_address=holder.lower(),
            token_address=token.lower(),
            scanned_from_block=0,
            measured_through_block=1_000,
            deliveries=[{"tx": "0x01", "log_index": 0, "fan_out": fan_out, "fan_out_basis": "receipt"}],
            delivery_count=1,
            unreadable_deliveries=0,
            min_fan_out=fan_out,
            fan_out_threshold_k=25,
            delivery_shape=shape,
            basis="own-history scan 0..1000",
        )
    )


@requires_postgres
def test_the_record_survives_disposition_and_carries_the_shape(db_session):
    """(a) stored and returned, (b) labelled. The exclusion happens elsewhere."""
    p = _protocol(db_session, "dispo-record")
    deployment = ADDR(0x5101)
    c = _contract(db_session, p.id, deployment)
    junk, real, unknown = ADDR(0x5111), ADDR(0x5112), ADDR(0x5113)
    fetch = _fetch(db_session, c, observed=deployment)
    for token in (junk, real, unknown):
        _row(db_session, c, fetch, token, None, observed=deployment)
    _evidence(db_session, holder=deployment, token=junk, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    _evidence(db_session, holder=deployment, token=real, shape=DELIVERY_SHAPE_HAS_DIRECT_DELIVERY, fan_out=1)
    db_session.flush()

    by_asset = {h.asset: h for h in _asset_holdings_by_deployment(db_session, p.id)[deployment.lower()]}
    assert set(by_asset) == {junk.lower(), real.lower(), unknown.lower()}
    assert by_asset[junk.lower()].delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL
    # The earned negative and the gap are DIFFERENT states, and neither is disposed.
    assert by_asset[real.lower()].delivery_shape == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
    assert by_asset[unknown.lower()].delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED


@requires_postgres
def test_only_the_airdrop_delivered_asset_leaves_the_value_holder_set(db_session):
    """(c) not presented as a holding — at the point membership means exactly that."""
    p = _protocol(db_session, "dispo-holders")
    deployment = ADDR(0x5201)
    c = _contract(db_session, p.id, deployment)
    junk, real, unknown = ADDR(0x5211), ADDR(0x5212), ADDR(0x5213)
    fn = _fn(db_session, c.id, name="withdraw", selector="0xdd000001", effect_targets=["S"])
    _principal(db_session, fn.id, ADDR(0x5299))
    fetch = _fetch(db_session, c, observed=deployment)
    for token in (junk, real, unknown):
        _row(db_session, c, fetch, token, None, observed=deployment)
    _evidence(db_session, holder=deployment, token=junk, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    _evidence(db_session, holder=deployment, token=real, shape=DELIVERY_SHAPE_HAS_DIRECT_DELIVERY, fan_out=1)
    db_session.flush()

    cand = next(x for x in select_candidates(db_session, p.id) if x.selector == "0xdd000001")
    presented = {h.asset for h in cand.value_holders}
    assert junk.lower() not in presented
    # FAIL-CLOSED in the other direction: an earned negative and an unmeasured pair
    # are both presented. Only the proven all-quantifier withholds a row.
    assert {real.lower(), unknown.lower()} <= presented


@requires_postgres
def test_a_priced_airdrop_delivered_token_is_not_offered_as_an_input_token(db_session):
    """The token-argument list is read as "tokens this contract holds a position in".

    The price filter answers a different question and cannot answer this one, so the
    delivery shape is applied here too. The balance row is untouched.
    """
    p = _protocol(db_session, "dispo-inputs")
    deployment = ADDR(0x5301)
    c = _contract(db_session, p.id, deployment)
    junk, real = ADDR(0x5311), ADDR(0x5312)
    fetch = _fetch(db_session, c, observed=deployment)
    _row(db_session, c, fetch, junk, 9_000.0, observed=deployment)
    _row(db_session, c, fetch, real, 100.0, observed=deployment)
    _evidence(db_session, holder=deployment, token=junk, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    db_session.flush()

    assert _token_holdings_by_contract(db_session, p.id, 10) == {c.id: (real.lower(),)}


@requires_postgres
def test_the_evidence_is_keyed_on_the_account_the_read_was_issued_against(db_session):
    """``observed_address``, never ``contracts.address``.

    162 of this protocol's token rows are read against an address other than the
    contract's own; keying the lookup on the contract would answer not_determined for
    every one of them and hide exactly the accounts the census flags.
    """
    p = _protocol(db_session, "dispo-observed")
    contract_address = ADDR(0x5401)
    observed = ADDR(0x5402)
    c = _contract(db_session, p.id, contract_address)
    token = ADDR(0x5411)
    fetch = _fetch(db_session, c, observed=observed)
    _row(db_session, c, fetch, token, None, observed=observed)
    _evidence(db_session, holder=observed, token=token, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    db_session.flush()

    holdings = _asset_holdings_by_deployment(db_session, p.id)[contract_address.lower()]
    assert [h.delivery_shape for h in holdings] == [DELIVERY_SHAPE_FAN_OUT_ALL]


class TestTheMergeAcrossAccountsIsUnanimous:
    """One (holder, asset) can be contributed to by several accounts' rows."""

    def test_unanimous_fan_out_disposes(self):
        assert _merged_delivery_shape([DELIVERY_SHAPE_FAN_OUT_ALL] * 3) == DELIVERY_SHAPE_FAN_OUT_ALL

    def test_one_unmeasured_sibling_keeps_the_holding_presented(self):
        assert (
            _merged_delivery_shape([DELIVERY_SHAPE_FAN_OUT_ALL, DELIVERY_SHAPE_NOT_DETERMINED])
            == DELIVERY_SHAPE_NOT_DETERMINED
        )

    def test_an_earned_negative_outranks_a_gap(self):
        assert (
            _merged_delivery_shape([DELIVERY_SHAPE_NOT_DETERMINED, DELIVERY_SHAPE_HAS_DIRECT_DELIVERY])
            == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
        )

    def test_an_empty_contribution_set_is_never_vacuously_unanimous(self):
        assert _merged_delivery_shape([]) == DELIVERY_SHAPE_NOT_DETERMINED
