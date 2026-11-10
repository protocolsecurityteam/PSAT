"""An upgrade figure is exact or established only when every event it relies on is proven a deployment or proven not
one; an event the deployment test merely failed to prove stays undecided.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from db.models import ContractCreationWitness, UpgradeEvent, UpgradeTransaction
from schemas.upgrade_history import UPGRADE_FETCH_COMPLETE
from services.aggregations.company_overview import build_company_overview
from services.discovery.upgrade_history import governance_actions_for, upgrade_action_counts
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


def _proxy(session):
    p = _add_protocol(session, f"decided-{uuid.uuid4().hex[:8]}")
    addr = _addr("px").lower()
    job = _add_job(session, address=addr, protocol_id=p.id, name="Proxy", is_proxy=True)
    c = _add_contract(session, address=addr, job=job, protocol_id=p.id, is_proxy=True, contract_name="Proxy")
    c.upgrade_history_status = UPGRADE_FETCH_COMPLETE
    session.commit()
    return p, c


def _event(session, c, block, *, creation=False, upgraded_logs=1):
    """An ``Upgraded`` event with its receipt: a factory call, or (``creation``) the tx that created the proxy."""
    tx = "0x" + uuid.uuid4().hex * 2
    session.add(
        UpgradeTransaction(
            chain_id=1,
            tx_hash=tx,
            block_number=block,
            block_hash="0x" + "b" * 64,
            tx_status=1,
            receipt_from=_addr("eoa"),
            receipt_to=None if creation else _addr("factory").lower(),
            created_contract_address=c.address if creation else None,
            is_contract_creation=creation,
            executor_kind="not_determined",
            receipt_log_set_complete_for_tx=True,
            receipt_upgraded_counts={c.address: upgraded_logs},
        )
    )
    session.flush()
    for _ in range(upgraded_logs):
        session.add(
            UpgradeEvent(
                contract_id=c.id,
                proxy_address=c.address,
                new_impl=_addr("i"),
                tx_hash=tx,
                chain_id=1,
                block_number=block,
                source="backfill",
            )
        )
    return tx


def _creation_witness(session, c, tx, *, probe_block, code_absent=True):
    session.add(
        ContractCreationWitness(
            chain_id=1,
            address=c.address,
            creation_tx_hash=tx,
            code_probe_block=probe_block,
            code_absent_at_probe=code_absent,
        )
    )


def _figures(session, p, c):
    session.commit()
    e = next(x for x in build_company_overview(session, p.name)["contracts"] if x["address"] == c.address)
    basis = e["upgrade_count_basis"]
    return (
        e["upgrade_count"],
        basis["recorded_count_relation"],
        basis["events_deployment_undecided"],
        e["last_upgrade_state"],
        e["last_upgrade_block"],
    )


def test_a_factory_deployment_without_a_creation_witness_is_undecided(db_session):
    p, c = _proxy(db_session)
    tx = _event(db_session, c, 100)
    assert _figures(db_session, p, c) == (1, "upper_bound", 1, "not_determined", None)
    # The exclusion and the count are untouched: the scorer still reads one action.
    assert upgrade_action_counts(db_session, [c.id])[c.id]["count"] == 1
    assert governance_actions_for(db_session, [c.id]) == {(1, tx)}


def test_a_witnessed_factory_creation_decides_every_other_tx(db_session):
    p, c = _proxy(db_session)
    creation_tx = _event(db_session, c, 50)
    _creation_witness(db_session, c, creation_tx, probe_block=49)
    _event(db_session, c, 100)
    assert _figures(db_session, p, c) == (1, "exact", 0, "established", 100)


def test_a_creation_receipt_decides_every_other_tx(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, 50, creation=True)
    _event(db_session, c, 100)
    assert _figures(db_session, p, c) == (1, "exact", 0, "established", 100)


def test_a_creation_hash_without_the_empty_code_probe_decides_nothing(db_session):
    p, c = _proxy(db_session)
    _event(db_session, c, 100)
    _creation_witness(db_session, c, "0x" + uuid.uuid4().hex * 2, probe_block=99, code_absent=False)
    assert _figures(db_session, p, c) == (1, "upper_bound", 1, "not_determined", None)


def test_an_event_in_the_creation_tx_not_proven_the_deployment_is_undecided(db_session):
    p, c = _proxy(db_session)
    # Two Upgraded logs in the creation tx: not a plain deployment, so the exclusion doesn't fire.
    _event(db_session, c, 50, creation=True, upgraded_logs=2)
    assert _figures(db_session, p, c) == (1, "upper_bound", 2, "not_determined", None)


def _poll(session, c, *, old_impl):
    session.add(
        UpgradeEvent(
            contract_id=c.id,
            proxy_address=c.address,
            old_impl=old_impl,
            new_impl=_addr("i"),
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source="poll",
        )
    )


def test_a_poll_detected_change_from_a_seen_implementation_is_decided(db_session):
    p, c = _proxy(db_session)
    _poll(db_session, c, old_impl=_addr("seen"))
    count, relation, undecided, state, block = _figures(db_session, p, c)
    # Hashless, so still an upper bound on the count; the change itself is not the deployment.
    assert (count, relation, undecided, state, block) == (1, "upper_bound", 0, "established", None)


def test_a_poll_row_with_no_recorded_predecessor_is_undecided(db_session):
    p, c = _proxy(db_session)
    _poll(db_session, c, old_impl=None)
    assert _figures(db_session, p, c) == (1, "upper_bound", 1, "not_determined", None)
