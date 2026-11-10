"""Query budget: upgrade history is read once per overview build, and the inventory's analysis states batch."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import event

from db.models import Protocol, UpgradeEvent, UpgradeTransaction
from services.aggregations.company_overview import all_addresses_for_protocol, build_company_overview
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr

pytestmark = requires_postgres


@contextmanager
def _statements(session):
    seen: list[str] = []
    engine = session.get_bind()

    def capture(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", capture)


def _protocol_with_proxies(session, n):
    p = _add_protocol(session, f"budget-{uuid.uuid4().hex[:8]}")
    for i in range(n):
        addr = _addr(f"px{i}").lower()
        job = _add_job(session, address=addr, protocol_id=p.id, name="Proxy", is_proxy=True)
        c = _add_contract(session, address=addr, job=job, protocol_id=p.id, is_proxy=True, contract_name="Proxy")
        tx_hash = "0x" + uuid.uuid4().hex * 2
        session.add(
            UpgradeTransaction(
                chain_id=1,
                tx_hash=tx_hash,
                block_number=100 + i,
                block_hash="0x" + "b" * 64,
                tx_status=1,
                receipt_from=_addr("sender"),
                receipt_to=addr,
                is_contract_creation=False,
                executor_kind="not_determined",
                receipt_log_set_complete_for_tx=True,
                receipt_upgraded_counts={addr: 1},
            )
        )
        session.flush()
        session.add(
            UpgradeEvent(
                contract_id=c.id,
                proxy_address=addr,
                new_impl=_addr("i"),
                block_number=100 + i,
                timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
                tx_hash=tx_hash,
                chain_id=1,
                source="backfill",
            )
        )
    session.commit()
    return p


def _upgrade_reads(statements):
    return [s for s in statements if "FROM upgrade_events" in s or "FROM upgrade_transactions" in s]


def test_overview_reads_upgrade_events_once(db_session):
    p = _protocol_with_proxies(db_session, 3)
    with _statements(db_session) as seen:
        build_company_overview(db_session, p.name)
    # One event read plus one receipt-fact read, shared by the count and the last upgrade.
    assert len(_upgrade_reads(seen)) == 2


def test_inventory_analysis_states_do_not_scale_with_rows(db_session):
    counts = []
    for n in (2, 6):
        p = _protocol_with_proxies(db_session, n)
        protocol = db_session.get(Protocol, p.id)
        with _statements(db_session) as seen:
            rows = all_addresses_for_protocol(db_session, protocol)
        assert len(rows) == n
        counts.append(len(seen))
    assert counts[0] == counts[1]
