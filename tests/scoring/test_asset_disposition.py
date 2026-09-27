"""Retired delivery data is not read or applied to current balance scoring."""

from sqlalchemy import event

from db.models import ContractBalance, TokenDeliveryEvidence
from services.scoring import planes as P
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _contract, _protocol


@requires_postgres
def test_stored_delivery_classification_does_not_change_holdings(db_session):
    protocol = _protocol(db_session, "retired-score-disposition")
    address, token = ADDR(0x9901), ADDR(0x9902)
    contract = _contract(db_session, protocol.id, address)
    db_session.add_all(
        [
            ContractBalance(
                contract_id=contract.id,
                observed_address=address,
                token_address=token,
                raw_balance="100",
                usd_value=None,
            ),
            ContractBalance(
                contract_id=contract.id, observed_address=address, token_address=None, raw_balance="100", usd_value=1000
            ),
            TokenDeliveryEvidence(
                chain_id=1,
                holder_address=address,
                token_address=token,
                delivery_shape="fan_out_all",
                scanned_from_block=0,
                measured_through_block=100,
                delivery_count=1,
                deliveries=[{"tx": "0x01", "log_index": 1, "fan_out": 400}],
                basis="legacy classification",
                min_fan_out=400,
                fan_out_threshold_k=25,
            ),
        ]
    )
    db_session.flush()
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        plane = P.load_value_plane(db_session, protocol.id)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    key = f"ethereum::{address}"
    assert plane.per_asset_state[key][token] == P.ASSET_UNPRICED
    assert plane.total(key) == 1000
    assert plane.asset_disposition == {}
    assert "asset_disposition" not in plane.provenance
    assert not any("token_delivery_evidence" in sql or "token_protocol_references" in sql for sql in statements)
