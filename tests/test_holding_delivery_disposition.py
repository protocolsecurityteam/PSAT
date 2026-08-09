"""Every holding is labelled, and only the full disposition conjunction is withheld.

§10.6.9's acceptance test on the selection plane: a holding must not be PRESENTED as
a position the protocol holds when the evidence says it is not one, while the record
of it stays and stays labelled. The two facts are separate and both are tested here,
because a disposition that removed the row would be an unwitnessed deletion — and
this plane reads a record's mere existence as "this deployment holds this asset".

The predicate is the scorer's, not a weaker one. Delivery shape ALONE withholds
nothing: applying it alone was measured pulling 39 rows of HEX, WETH and base USDC
out of the presented holdings while the score spared every one of them through the
protocol-reference conjunct. A row leaves the claim only when it is unpriced AND
``fan_out_all`` AND ``absent_from_universe``; anything else — including a MISSING
reference row — keeps it presented.

Nothing here is a claim about worth. Two demonstrably real tokens on this corpus are
airdrop-delivered (uniETH at fan-out 101, HEX at 199/399/399); the published state
says how the balance arrived and nothing else.
"""

from __future__ import annotations

from db.models import ContractBalance, ContractBalanceFetch, TokenDeliveryEvidence, TokenProtocolReference
from services.effects.selection import (
    _asset_holdings_by_deployment,
    _merged_delivery_shape,
    _merged_reference_shape,
    _token_holdings_by_contract,
    disposed_from_holdings,
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
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
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


def _reference(session, *, protocol_id: int, token: str, shape: str, chain_id: int = 1) -> None:
    session.add(
        TokenProtocolReference(
            protocol_id=protocol_id,
            chain_id=chain_id,
            token_address=token.lower(),
            reference_shape=shape,
            universe_addresses=3,
            basis="universe of 3 addresses, chain-blind",
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

    _reference(db_session, protocol_id=p.id, token=junk, shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE)
    _reference(db_session, protocol_id=p.id, token=real, shape=TOKEN_REFERENCE_IN_UNIVERSE)
    db_session.flush()

    by_asset = {h.asset: h for h in _asset_holdings_by_deployment(db_session, p.id)[deployment.lower()]}
    assert set(by_asset) == {junk.lower(), real.lower(), unknown.lower()}
    assert by_asset[junk.lower()].delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL
    assert by_asset[junk.lower()].reference_shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE
    # The earned negative and the gap are DIFFERENT states, and neither is disposed.
    assert by_asset[real.lower()].delivery_shape == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
    assert by_asset[real.lower()].reference_shape == TOKEN_REFERENCE_IN_UNIVERSE
    assert by_asset[unknown.lower()].delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    # No reference row was written for this pair, and the absence reads as the gap.
    assert by_asset[unknown.lower()].reference_shape == TOKEN_REFERENCE_NOT_DETERMINED


@requires_postgres
def test_only_the_fully_disposed_asset_leaves_the_value_holder_set(db_session):
    """(c) not presented as a holding — at the point membership means exactly that.

    Four assets, all four airdrop-delivered or unmeasured, and exactly ONE of them
    disposed. ``spared`` is the S5 regression in miniature: airdrop-delivered and in
    the protocol's own universe, which is the shape HEX, WETH and base USDC have.
    """
    p = _protocol(db_session, "dispo-holders")
    deployment = ADDR(0x5201)
    c = _contract(db_session, p.id, deployment)
    junk, real, unknown, spared = ADDR(0x5211), ADDR(0x5212), ADDR(0x5213), ADDR(0x5214)
    fn = _fn(db_session, c.id, name="withdraw", selector="0xdd000001", effect_targets=["S"])
    _principal(db_session, fn.id, ADDR(0x5299))
    fetch = _fetch(db_session, c, observed=deployment)
    for token in (junk, real, unknown, spared):
        _row(db_session, c, fetch, token, None, observed=deployment)
    _evidence(db_session, holder=deployment, token=junk, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    _evidence(db_session, holder=deployment, token=real, shape=DELIVERY_SHAPE_HAS_DIRECT_DELIVERY, fan_out=1)
    _evidence(db_session, holder=deployment, token=spared, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    _reference(db_session, protocol_id=p.id, token=junk, shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE)
    _reference(db_session, protocol_id=p.id, token=spared, shape=TOKEN_REFERENCE_IN_UNIVERSE)
    db_session.flush()

    cand = next(x for x in select_candidates(db_session, p.id) if x.selector == "0xdd000001")
    presented = {h.asset for h in cand.value_holders}
    assert junk.lower() not in presented
    # FAIL-CLOSED in three directions: an earned negative, a pair nobody measured, and
    # a mass-distributed token the protocol's OWN discovery names are all presented.
    assert {real.lower(), unknown.lower(), spared.lower()} <= presented


@requires_postgres
def test_a_mass_distributed_token_in_the_universe_is_never_pulled_from_the_holdings(db_session):
    """The S5 regression, pinned on the plane it was measured on.

    ``fan_out_all`` with no universe verdict at all, and ``fan_out_all`` with an
    explicit ``in_universe``: both stay presented. Only the pair the producer
    measured ABSENT comes out, which is the scorer's own predicate.
    """
    p = _protocol(db_session, "dispo-universe")
    deployment = ADDR(0x5501)
    c = _contract(db_session, p.id, deployment)
    unmeasured, in_universe, absent = ADDR(0x5511), ADDR(0x5512), ADDR(0x5513)
    fetch = _fetch(db_session, c, observed=deployment)
    for token in (unmeasured, in_universe, absent):
        _row(db_session, c, fetch, token, None, observed=deployment)
        _evidence(db_session, holder=deployment, token=token, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    _reference(db_session, protocol_id=p.id, token=in_universe, shape=TOKEN_REFERENCE_IN_UNIVERSE)
    _reference(db_session, protocol_id=p.id, token=absent, shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE)
    db_session.flush()

    by_asset = {h.asset: h for h in _asset_holdings_by_deployment(db_session, p.id)[deployment.lower()]}
    disposed = {
        asset
        for asset, h in by_asset.items()
        if disposed_from_holdings(
            delivery_shape=h.delivery_shape, reference_shape=h.reference_shape, usd_value=h.usd_value
        )
    }
    assert disposed == {absent.lower()}


@requires_postgres
def test_a_priced_airdrop_delivered_token_is_still_offered_as_an_input_token(db_session):
    """A PRICED reading is never disposed — the disposition's own first conjunct.

    The token-argument list is read as "tokens this contract holds a position in",
    and every row on it is priced above zero by the query. A dollar figure was
    determined for this holding; withdrawing it on evidence about how the token
    ARRIVED would delete a measured position from the probe's input.
    """
    p = _protocol(db_session, "dispo-inputs")
    deployment = ADDR(0x5301)
    c = _contract(db_session, p.id, deployment)
    airdropped, real = ADDR(0x5311), ADDR(0x5312)
    fetch = _fetch(db_session, c, observed=deployment)
    _row(db_session, c, fetch, airdropped, 9_000.0, observed=deployment)
    _row(db_session, c, fetch, real, 100.0, observed=deployment)
    _evidence(db_session, holder=deployment, token=airdropped, shape=DELIVERY_SHAPE_FAN_OUT_ALL)
    # Both other conjuncts hold too, and the price alone still spares the row.
    _reference(db_session, protocol_id=p.id, token=airdropped, shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE)
    db_session.flush()

    assert _token_holdings_by_contract(db_session, p.id, 10) == {c.id: (airdropped.lower(), real.lower())}


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


class TestTheReferenceMergeSparesOnAnyHit:
    """One (holder, asset) can be read on several chains, each with its own verdict."""

    def test_one_chain_naming_the_address_spares_the_holding(self):
        assert (
            _merged_reference_shape([TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE, TOKEN_REFERENCE_IN_UNIVERSE])
            == TOKEN_REFERENCE_IN_UNIVERSE
        )

    def test_absence_needs_unanimity(self):
        assert (
            _merged_reference_shape([TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE] * 3) == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE
        )

    def test_one_unmeasured_chain_withdraws_the_absence(self):
        assert (
            _merged_reference_shape([TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE, TOKEN_REFERENCE_NOT_DETERMINED])
            == TOKEN_REFERENCE_NOT_DETERMINED
        )

    def test_an_empty_contribution_set_is_never_vacuously_absent(self):
        assert _merged_reference_shape([]) == TOKEN_REFERENCE_NOT_DETERMINED


class TestTheDispositionPredicateIsTheScorers:
    """Three conjuncts, and each one alone spares the row.

    Pinned as a unit because this predicate is the single definition both the
    holdings plane and the overview payload read: presentation applying a WEAKER one
    is exactly the divergence that pulled 39 real rows off the page.
    """

    def test_all_three_conjuncts_dispose(self):
        assert disposed_from_holdings(
            delivery_shape=DELIVERY_SHAPE_FAN_OUT_ALL,
            reference_shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
            usd_value=None,
        )

    def test_a_priced_reading_is_never_disposed(self):
        assert not disposed_from_holdings(
            delivery_shape=DELIVERY_SHAPE_FAN_OUT_ALL,
            reference_shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
            usd_value=0.0,
        )

    def test_an_address_the_protocol_names_is_never_disposed(self):
        assert not disposed_from_holdings(
            delivery_shape=DELIVERY_SHAPE_FAN_OUT_ALL,
            reference_shape=TOKEN_REFERENCE_IN_UNIVERSE,
            usd_value=None,
        )

    def test_a_missing_reference_row_keeps_the_holding_presented(self):
        assert not disposed_from_holdings(
            delivery_shape=DELIVERY_SHAPE_FAN_OUT_ALL,
            reference_shape=TOKEN_REFERENCE_NOT_DETERMINED,
            usd_value=None,
        )

    def test_a_direct_delivery_is_never_disposed(self):
        assert not disposed_from_holdings(
            delivery_shape=DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
            reference_shape=TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
            usd_value=None,
        )
