"""``upgrade_count_basis.recorded_count_relation`` claims no more than the counters prove about the count."""

from __future__ import annotations

import uuid

import pytest

from db.models import UpgradeEvent, UpgradeTransaction
from schemas.upgrade_history import UPGRADE_FETCH_COMPLETE, UPGRADE_FETCH_ERROR
from services.aggregations.company_overview import build_company_overview
from services.discovery.upgrade_history import upgrade_action_counts
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


def _proxy(session, status):
    p = _add_protocol(session, f"count-relation-{uuid.uuid4().hex[:8]}")
    addr = _addr("px").lower()
    job = _add_job(session, address=addr, protocol_id=p.id, name="Proxy", is_proxy=True)
    contract = _add_contract(session, address=addr, job=job, protocol_id=p.id, is_proxy=True, contract_name="Proxy")
    contract.upgrade_history_status = status
    session.commit()
    return p, contract


def _linked(session, contract, block, *, deployment=False):
    tx_hash = "0x" + uuid.uuid4().hex * 2
    session.add(
        UpgradeTransaction(
            chain_id=1,
            tx_hash=tx_hash,
            block_number=block,
            block_hash="0x" + "b" * 64,
            tx_status=1,
            receipt_from=_addr("sender"),
            receipt_to=None if deployment else contract.address,
            created_contract_address=contract.address if deployment else None,
            is_contract_creation=deployment,
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
            new_impl=_addr("i"),
            tx_hash=tx_hash,
            chain_id=1,
            block_number=block,
            source="backfill",
        )
    )


def _unlinked(session, contract, block):
    session.add(
        UpgradeEvent(
            contract_id=contract.id,
            proxy_address=contract.address,
            new_impl=_addr("i"),
            tx_hash="0x" + uuid.uuid4().hex * 2,
            block_number=block,
            source="backfill",
        )
    )


def _poll(session, contract):
    session.add(
        UpgradeEvent(contract_id=contract.id, proxy_address=contract.address, new_impl=_addr("i"), source="poll")
    )


def _entry(session, protocol, contract):
    payload = build_company_overview(session, protocol.name)
    return next(e for e in payload["contracts"] if e["address"] == contract.address)


@pytest.mark.parametrize(
    ("status", "rows", "count", "relation"),
    [
        pytest.param(UPGRADE_FETCH_COMPLETE, ["linked", "linked"], 2, "exact", id="complete-all-linked"),
        pytest.param(UPGRADE_FETCH_COMPLETE, ["linked", "unlinked"], 2, "upper_bound", id="complete-unlinked"),
        pytest.param(UPGRADE_FETCH_COMPLETE, ["linked", "poll"], 2, "upper_bound", id="complete-no-tx-hash"),
        pytest.param(UPGRADE_FETCH_ERROR, ["linked"], None, "not_determined", id="errored"),
        pytest.param(None, ["linked"], 1, "not_determined", id="legacy-no-status"),
        pytest.param(UPGRADE_FETCH_COMPLETE, [], None, "not_determined", id="complete-zero-events"),
        pytest.param(UPGRADE_FETCH_COMPLETE, ["deployment"], None, "not_determined", id="complete-deployment-only"),
        pytest.param(UPGRADE_FETCH_ERROR, [], None, "not_determined", id="errored-zero-events"),
    ],
)
def test_recorded_count_relation(db_session, status, rows, count, relation):
    p, c = _proxy(db_session, status)
    for i, kind in enumerate(rows):
        block = 100 + i
        if kind == "linked":
            _linked(db_session, c, block)
        elif kind == "deployment":
            _linked(db_session, c, block, deployment=True)
        elif kind == "unlinked":
            _unlinked(db_session, c, block)
        else:
            _poll(db_session, c)
    db_session.commit()

    entry = _entry(db_session, p, c)
    assert entry["upgrade_count"] == count
    basis = entry["upgrade_count_basis"]
    assert basis["recorded_count_relation"] == relation
    assert basis["history_fetch_status"] == (status or "not_determined")
    assert basis["events_total"] == len(rows)
    assert basis["deployments_excluded"] == rows.count("deployment")
    assert basis["recorded_event_coverage"] == "not_determined"


def test_no_status_and_no_events_publishes_no_basis(db_session):
    p, c = _proxy(db_session, None)
    entry = _entry(db_session, p, c)
    assert entry["upgrade_count"] is None
    assert entry["upgrade_count_basis"] is None


def test_completed_empty_fetches_join_only_when_asked(db_session):
    _p, c = _proxy(db_session, UPGRADE_FETCH_COMPLETE)
    assert c.id not in upgrade_action_counts(db_session, [c.id])
    assert c.id in upgrade_action_counts(db_session, [c.id], with_completed_empty=True)
