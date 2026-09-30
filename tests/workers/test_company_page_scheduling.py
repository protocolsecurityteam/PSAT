"""Debounced rebuilds: quiet period, minimum interval, and maximum wait."""

from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select, text, update

from db.models import CompanyPageRevision as Revision
from db.models import CompanyPageSnapshot as Page
from db.models import Contract, ContractSummary
from services import company_pages as pages
from tests.aggregations.test_company_page_revisions import root_contract
from tests.aggregations.test_prepared_company_pages import prepared as prepared
from tests.aggregations.test_prepared_company_pages import request, source
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr
from workers import company_pages as worker

pytestmark = requires_postgres


@pytest.fixture
def paced(prepared, monkeypatch):
    for group in ("STRUCTURAL", "SUMMARY"):
        for setting in ("QUIET", "MIN_INTERVAL", "MAX_WAIT"):
            monkeypatch.delenv(f"PSAT_COMPANY_{group}_{setting}_S")
    session, protocol, factory = prepared
    builds = MagicMock(wraps=worker.build_company_overview)
    monkeypatch.setattr(worker, "build_company_overview", builds)
    return session, protocol, factory, builds


def advance(session, seconds):
    shift = timedelta(seconds=seconds)
    session.execute(
        update(Page).values(
            source_started_at=Page.source_started_at - shift,
            functions_source_started_at=Page.functions_source_started_at - shift,
            summary_source_started_at=Page.summary_source_started_at - shift,
        )
    )
    session.execute(update(Revision).values(changed_at=Revision.changed_at - shift))
    session.commit()


def write(session, protocol, value):
    session.execute(update(Contract).where(Contract.protocol_id == protocol.id).values(contract_name=value))
    session.commit()


def drain(factory):
    while worker.refresh_one(factory) == "prepared":
        pass


def test_continuous_writes_rebuild_at_max_wait_and_never_faster_than_min_interval(paced):
    session, protocol, factory, builds = paced
    assert pages.timing("overview") == (120, 300, 900)
    drain(factory)
    builds.reset_mock()
    rebuilt_at = []
    for elapsed in range(20, 1201, 20):
        write(session, protocol, f"write {elapsed}")
        advance(session, 20)
        drain(factory)
        if builds.call_count > len(rebuilt_at):
            rebuilt_at.append(elapsed)
    assert rebuilt_at == [900]
    assert builds.call_count == 1


@pytest.mark.parametrize("last_write,expected", [(250, 370), (10, 300)])
def test_rebuild_waits_for_quiet_and_min_interval_after_writes_stop(paced, last_write, expected):
    session, protocol, factory, builds = paced
    drain(factory)
    builds.reset_mock()
    advance(session, last_write)
    write(session, protocol, "last write")
    rebuilt_at = None
    for elapsed in range(last_write + 10, 501, 10):
        advance(session, 10)
        drain(factory)
        if builds.call_count and rebuilt_at is None:
            rebuilt_at = elapsed
    assert rebuilt_at == expected
    assert builds.call_count == 1


def test_borrowed_dependency_write_respects_quiet_period(paced):
    session, protocol, factory, builds = paced
    contract = root_contract(session, protocol)
    impl_address = _addr("borrowed")
    contract.is_proxy = True
    contract.implementation = impl_address
    other = _add_protocol(session, "borrowed-owner")
    impl_job = _add_job(session, address=impl_address, protocol_id=other.id)
    impl = _add_contract(session, address=impl_address, job=impl_job, protocol_id=other.id)
    drain(factory)
    recorded = session.execute(select(Page.source_revisions).where(Page.protocol_id == protocol.id)).scalar_one()
    assert f"contract:{impl.id}" in recorded
    advance(session, 300)
    builds.reset_mock()
    session.add(ContractSummary(contract_id=impl.id, has_timelock=True))
    session.commit()
    assert source(session, protocol.name) == "prepared-stale"
    rebuilt_at = None
    for elapsed in range(10, 201, 10):
        advance(session, 10)
        drain(factory)
        if protocol.name in [c.args[1] for c in builds.call_args_list] and rebuilt_at is None:
            rebuilt_at = elapsed
    assert rebuilt_at == 120


def test_late_commit_with_early_change_time_stays_dirty_until_rebuilt(paced, monkeypatch):
    session, protocol, factory, _ = paced
    drain(factory)
    advance(session, 300)
    with factory() as late:
        late.execute(update(Contract).where(Contract.protocol_id == protocol.id).values(contract_name="late"))
        late.execute(
            text(
                "UPDATE company_page_revisions SET changed_at = changed_at - interval '1 hour' "
                "WHERE transaction_id = txid_current()"
            )
        )
        monkeypatch.setenv("PSAT_COMPANY_BUILD_REVISION", "during-late-write")
        assert worker.refresh_one(factory) == "prepared"
        assert source(session, protocol.name) == "prepared"
        late.commit()
    response = pages.read_response(session, request(), protocol.name)
    assert response is not None
    assert response.headers["x-psat-response-source"] == "prepared-stale"
    assert response.headers["x-psat-stale-reason"] == "data"
    assert worker.refresh_one(factory) == "idle"
    advance(session, 300)
    assert worker.refresh_one(factory) == "prepared"
    assert source(session, protocol.name) == "prepared"
