"""The last upgrade excludes proven deployments as the count does, and is published only when one row is provably the
latest.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import UpgradeEvent, UpgradeTransaction
from services.aggregations.company_overview import build_company_overview
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


def _proxy(session):
    p = _add_protocol(session, f"last-upgrade-{uuid.uuid4().hex[:8]}")
    addr = _addr("px").lower()
    job = _add_job(session, address=addr, protocol_id=p.id, name="Proxy", is_proxy=True)
    contract = _add_contract(session, address=addr, job=job, protocol_id=p.id, is_proxy=True, contract_name="Proxy")
    return p, contract


def _deployment(session, contract, *, block: int, ts: datetime) -> None:
    tx_hash = "0x" + uuid.uuid4().hex * 2
    session.add(
        UpgradeTransaction(
            chain_id=1,
            tx_hash=tx_hash,
            block_number=block,
            block_hash="0x" + "b" * 64,
            tx_status=1,
            receipt_from=_addr("deployer"),
            receipt_to=None,
            created_contract_address=contract.address,
            is_contract_creation=True,
            executor_kind="not_determined",
            receipt_log_set_complete_for_tx=True,
            receipt_upgraded_counts={contract.address: 1},
        )
    )
    session.flush()
    session.add(
        UpgradeEvent(
            contract_id=contract.id,
            proxy_address=contract.address,
            new_impl=_addr("i0"),
            tx_hash=tx_hash,
            chain_id=1,
            block_number=block,
            timestamp=ts,
            source="backfill",
        )
    )


def _event(session, contract, *, block=None, ts=None, source: str | None = "backfill"):
    session.add(
        UpgradeEvent(
            contract_id=contract.id,
            proxy_address=contract.address,
            new_impl=_addr("i"),
            block_number=block,
            timestamp=ts,
            tx_hash=("0x" + uuid.uuid4().hex * 2) if block is not None else None,
            source=source,
        )
    )


def _entry(session, protocol, contract):
    payload = build_company_overview(session, protocol.name)
    return next(e for e in payload["contracts"] if e["address"] == contract.address)


def test_a_deployment_is_not_the_last_upgrade(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, block=100, ts=datetime(2024, 1, 1, tzinfo=timezone.utc))
    _deployment(db_session, c, block=50, ts=datetime(2023, 1, 1, tzinfo=timezone.utc))
    db_session.commit()
    entry = _entry(db_session, p, c)
    assert (entry["last_upgrade_block"], entry["last_upgrade_state"]) == (100, "established")


def test_a_deployment_only_history_has_no_last_upgrade(db_session):
    p, c = _proxy(db_session)
    _deployment(db_session, c, block=50, ts=datetime(2023, 1, 1, tzinfo=timezone.utc))
    db_session.commit()
    entry = _entry(db_session, p, c)
    assert entry["upgrade_count"] is None
    assert entry["last_upgrade_block"] is None
    assert entry["last_upgrade_timestamp"] is None
    assert entry["last_upgrade_state"] is None


def test_a_block_only_row_beside_a_time_only_row_is_not_ordered(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, block=900, source="event_scan")
    _event(db_session, c, ts=datetime(2025, 1, 1, tzinfo=timezone.utc), source="poll")
    db_session.commit()
    entry = _entry(db_session, p, c)
    assert entry["last_upgrade_state"] == "not_determined"
    assert entry["last_upgrade_block"] is None
    assert entry["last_upgrade_timestamp"] is None


def test_a_newer_block_without_a_time_outranks_an_older_timed_block(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, block=500, ts=datetime(2024, 1, 1, tzinfo=timezone.utc))
    _event(db_session, c, block=900, source="event_scan")
    db_session.commit()
    entry = _entry(db_session, p, c)
    assert (entry["last_upgrade_block"], entry["last_upgrade_timestamp"]) == (900, None)
    assert entry["last_upgrade_state"] == "established"


def test_a_single_unplaceable_row_is_still_the_latest(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, source=None)
    db_session.commit()
    entry = _entry(db_session, p, c)
    assert entry["last_upgrade_state"] == "established"
    assert (entry["last_upgrade_block"], entry["last_upgrade_timestamp"]) == (None, None)


def test_an_unplaceable_row_beside_others_is_not_ordered(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, block=500, ts=datetime(2024, 1, 1, tzinfo=timezone.utc))
    _event(db_session, c, source=None)
    db_session.commit()
    assert _entry(db_session, p, c)["last_upgrade_state"] == "not_determined"
