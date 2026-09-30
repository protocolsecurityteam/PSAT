
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from db.models import Contract, ContractBalance, ContractBalanceFetch, ControlGraphNode, Protocol
from services.effects.selection import _asset_holdings_by_deployment, _token_holdings_by_contract
from services.monitoring.balance_reads import ObservationSubject
from services.scoring import planes as P
from tests.conftest import requires_postgres

pytestmark = requires_postgres
TOKEN_A = "0x" + "a1" * 20
TOKEN_B = "0x" + "b2" * 20
TOKEN_C = "0x" + "c3" * 20


def make_subject(session, entity=False):
    protocol = Protocol(name="partial-consumer-" + uuid.uuid4().hex)
    session.add(protocol)
    session.flush()
    contract = Contract(protocol_id=protocol.id, address="0x" + uuid.uuid4().hex + "11" * 4, chain="ethereum")
    session.add(contract)
    session.flush()
    subject = ObservationSubject.of_contract(contract)
    if entity:
        address = "0x" + uuid.uuid4().hex + "22" * 4
        session.add(ControlGraphNode(contract_id=contract.id, address=address, resolved_type="eoa"))
        subject = ObservationSubject.of_entity("ethereum", address)
    return protocol, subject


def add_fetch(session, subject, status, when, *, scanned=False):
    fetch = ContractBalanceFetch(
        **subject.columns(),
        observed_address=subject.address,
        chain_id=1,
        block_number=100 if scanned else None,
        native_status="proven_zero" if scanned else "unattempted",
        asset_set_status=status,
        asset_set_source="chain_log_sweep" if scanned else "etherscan_pages",
        sweep_status="completed" if scanned else "unattempted",
        swept_from_block=0 if scanned else None,
        swept_through_block=100 if scanned else None,
        typed_assets=[] if scanned else None,
        writer="tvl",
        fetched_at=when,
    )
    session.add(fetch)
    session.flush()
    return fetch


def add_token(session, subject, fetch, token, value):
    session.add(
        ContractBalance(
            **subject.columns(),
            fetch_id=fetch.id,
            token_address=token,
            raw_balance="100",
            decimals=0,
            usd_value=value,
            observed_address=subject.address,
            fetched_at=fetch.fetched_at,
        )
    )
    session.flush()


@pytest.mark.parametrize("entity", [False, True])
@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("partial_order", ["newer", "same_time_newer_id", "older", "same_time_older_id"])
def test_partial_coverage_preserves_amounts_and_existing_ceiling_gate(db_session, entity, empty, partial_order):
    protocol, subject = make_subject(db_session, entity)
    now = datetime.now(timezone.utc)
    partial = None
    if partial_order == "same_time_older_id":
        partial = add_fetch(db_session, subject, "at_page_cap", now)
    accepted = add_fetch(db_session, subject, "returned_empty" if empty else "returned_assets", now, scanned=True)
    if not empty:
        add_token(db_session, subject, accepted, TOKEN_A, 150)
    if partial is None:
        offset = {"newer": 1, "same_time_newer_id": 0, "older": -1}[partial_order]
        partial = add_fetch(db_session, subject, "at_page_cap", now + timedelta(hours=offset))
    add_token(db_session, subject, partial, TOKEN_B, 10_000)
    db_session.commit()

    plane = P.load_value_plane(db_session, protocol.id)
    key = "ethereum::" + subject.address
    newer = partial_order in ("newer", "same_time_newer_id")
    assert plane.asset_set_is_truncated(key) is newer
    if newer:
        assert P.ceiling_for(plane, key) == (None, P.CEILING_ASSET_LIST_TRUNCATED)
        assert key not in plane.asset_set_proven_complete
        assert plane.sheet_state(key) != P.SHEET_PROVEN_EMPTY
    else:
        assert P.ceiling_for(plane, key)[0] == (0 if empty else 150)
    if not empty:
        assert plane.total(key) == 150  # Partial dollars never inflate accepted totals.
        if not entity:
            holdings = _asset_holdings_by_deployment(db_session, protocol.id)[subject.address]
            assert len(holdings) == 1 and holdings[0].usd_value == 150
            assert holdings[0].completeness == ("at_page_cap" if newer else "not_determined")


def test_partial_identities_obey_original_richest_first_order_and_two_token_cap(db_session):
    protocol, subject = make_subject(db_session)
    now = datetime.now(timezone.utc)
    accepted = add_fetch(db_session, subject, "returned_assets", now - timedelta(hours=1))
    partial = add_fetch(db_session, subject, "at_page_cap", now)
    add_token(db_session, subject, accepted, TOKEN_A, 100)
    add_token(db_session, subject, accepted, TOKEN_B, 10)
    add_token(db_session, subject, partial, TOKEN_C, 10_000)
    add_token(db_session, subject, partial, TOKEN_A, 100)  # Duplicate identity cannot consume the cap.
    add_token(db_session, subject, partial, "0x" + "dd" * 20, None)  # Original price gate still applies.
    db_session.commit()
    assert subject.contract_id is not None
    assert _token_holdings_by_contract(db_session, protocol.id, 2)[subject.contract_id] == (TOKEN_C, TOKEN_A)
