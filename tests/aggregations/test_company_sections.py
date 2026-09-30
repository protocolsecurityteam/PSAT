"""Section invalidation, multi-consumer claims, and public/operator read parity."""

import gzip
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from db.models import CompanyPageSnapshot as Page
from db.models import Contract, EffectiveFunction, PendingEffectsWork, TvlSnapshot
from services import company_pages as pages
from tests.aggregations.test_company_page_revisions import ready, root_contract
from tests.aggregations.test_prepared_company_pages import prepared as prepared
from tests.aggregations.test_prepared_company_pages import request, source
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr
from workers import company_pages as worker

pytestmark = requires_postgres


def test_summary_changes_do_not_rebuild_structure_or_functions(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    row = session.get(Page, f"protocol:{protocol.id}")
    original = (row.overview_gzip, row.functions_gzip, row.source_started_at, row.functions_source_started_at)
    overview = MagicMock(side_effect=AssertionError("summary update cannot rebuild overview"))
    functions = MagicMock(side_effect=AssertionError("summary update cannot rebuild functions"))
    monkeypatch.setattr(worker, "build_company_overview", overview)
    monkeypatch.setattr(worker, "build_functions_for_protocol", functions)
    session.add(TvlSnapshot(protocol_id=protocol.id, total_usd=123))
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    session.expire_all()
    row = session.get(Page, f"protocol:{protocol.id}")
    assert (row.overview_gzip, row.functions_gzip, row.source_started_at, row.functions_source_started_at) == original
    summary = json.loads(gzip.decompress(row.summary_gzip))
    assert summary["tvl"]["total_usd"] == 123
    assert "tvl" not in json.loads(gzip.decompress(row.overview_gzip))
    assert worker.refresh_one(factory) == "idle"


def test_pending_effects_state_invalidates_summary_without_graph_work(prepared):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    function = EffectiveFunction(contract_id=contract.id, function_name="withdraw")
    session.add(function)
    session.commit()
    assert worker.refresh_one(factory) == "prepared"
    pending = PendingEffectsWork(
        protocol_id=protocol.id,
        contract_id=contract.id,
        function_id=function.id,
        deployment_address=contract.address,
        chain_id=1,
        effect_family="asset_pull",
    )
    session.add(pending)
    ready(session)
    assert source(session, protocol.name, "summary") == "prepared-stale"
    assert source(session, protocol.name) == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    response = pages.read_response(session, request(), protocol.name, section="summary")
    assert response is not None
    assert json.loads(bytes(response.body))["analysis_pending_balance_effects"]["incomplete"] == 1
    pending.state = "complete"
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    response = pages.read_response(session, request(), protocol.name, section="summary")
    assert response is not None
    assert json.loads(bytes(response.body))["analysis_pending_balance_effects"]["incomplete"] == 0


def test_consumers_skip_busy_company_and_build_another(prepared, monkeypatch):
    session, protocol, factory = prepared
    other = _add_protocol(session, "second-company")
    address = _addr("second")
    job = _add_job(session, address=address, protocol_id=other.id)
    _add_contract(session, address=address, job=job, protocol_id=other.id)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    session.execute(update(Contract).values(contract_name="changed"))
    ready(session)
    started = Event()
    release = Event()
    original = worker.build_company_overview
    calls = []

    def build(source, name):
        calls.append(name)
        if name == protocol.name:
            started.set()
            assert release.wait(10)
        return original(source, name)

    monkeypatch.setattr(worker, "build_company_overview", build)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(worker.refresh_one, factory)
        try:
            assert started.wait(10)
            assert worker.refresh_one(factory) == "prepared"
            assert calls == [protocol.name, other.name]
            assert worker.refresh_one(factory) == "idle"
        finally:
            release.set()
        assert first.result(timeout=10) == "prepared"


@pytest.mark.parametrize("suffix", ["", "/functions", "/summary"])
def test_empty_and_dirty_reads_never_fall_back_for_any_reader(prepared, monkeypatch, suffix):
    import api
    from routers import company, deps

    session, protocol, factory = prepared
    monkeypatch.setattr(deps, "SessionLocal", factory)
    monkeypatch.setattr(api.app, "middleware_stack", None)
    monkeypatch.setattr(company, "build_company_overview", MagicMock(side_effect=AssertionError("inline build")))
    monkeypatch.setattr(company, "build_functions_for_protocol", MagicMock(side_effect=AssertionError("inline build")))
    client = TestClient(api.app)
    for headers in ({}, {"Cookie": "session=test", "Cache-Control": "no-cache"}):
        response = client.get(f"/api/company/{protocol.name}{suffix}", headers=headers)
        assert response.status_code == 503
        assert response.json()["code"] == "company_preparing"
        assert response.headers["cache-control"] == "private, no-store"
    assert worker.refresh_one(factory) == "prepared"
    for headers in ({}, {"Cookie": "session=test", "Cache-Control": "no-cache"}):
        response = client.get(f"/api/company/{protocol.name}{suffix}", headers=headers)
        assert response.status_code == 200
        assert response.headers["x-psat-response-source"] == "prepared"


def test_explicit_admin_refresh_is_authorized_and_uses_shared_builder(prepared, monkeypatch):
    import api
    from routers import deps

    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    monkeypatch.setattr(deps, "SessionLocal", factory)
    monkeypatch.setattr(deps, "ADMIN_KEY", "test-admin")
    monkeypatch.setattr(api.app, "middleware_stack", None)
    client = TestClient(api.app)
    monkeypatch.delitem(api.app.dependency_overrides, deps.require_admin_key, raising=False)
    path = f"/api/company/{protocol.name}/refresh"
    assert client.post(path).status_code == 401
    assert pages.read_response(session, request(), protocol.name) is not None
    assert client.post(path, headers={"X-PSAT-Admin-Key": "test-admin"}).status_code == 202
    session.rollback()
    for section in pages.SECTIONS:
        assert source(session, protocol.name, section) == "prepared-stale"
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "idle"


def test_unrelated_deploys_reuse_but_builder_changes_serve_stale_until_rebuilt(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    monkeypatch.setenv("GIT_SHA", "documentation-only-deploy")
    ready(session)
    assert worker.refresh_one(factory) == "idle"
    assert source(session, protocol.name) == "prepared"
    monkeypatch.setenv("PSAT_COMPANY_BUILD_REVISION", "new-builder")
    for section in pages.SECTIONS:
        response = pages.read_response(session, request(), protocol.name, section=section)
        assert response is not None
        assert response.headers["x-psat-response-source"] == "prepared-stale"
        assert response.headers["x-psat-stale-reason"] == "code"
    assert worker.refresh_one(factory) == "prepared"
    for section in pages.SECTIONS:
        assert source(session, protocol.name, section) == "prepared"


@pytest.mark.parametrize("company", ["unresolved-company", "Prepared Example"], ids=["no-protocol", "alias"])
def test_company_string_without_a_protocol_row_gets_no_page(prepared, company):
    from fastapi import HTTPException

    from services.aggregations import CompanyNotFound
    from services.aggregations.company_overview.payload import build_company_summary

    session, protocol, factory = prepared
    # A company run's jobs carry the requested spelling before, or instead of,
    # the Protocol row's name; their completed children must not form a page.
    address = _addr("company-tagged")
    root = _add_job(session, address=address, company=company)
    _add_contract(session, address=address, job=root)
    child_address = _addr("company-tagged-child")
    child = _add_job(session, address=child_address, company=company, request={"parent_job_id": str(root.id)})
    _add_contract(session, address=child_address, job=child)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "idle"
    assert session.scalars(select(Page.company_name)).all() == [protocol.name]
    for section in pages.SECTIONS:
        with pytest.raises(HTTPException) as caught:
            pages.prepared_or_pending(session, request(), company, section=section)
        assert caught.value.status_code == 404
    with pytest.raises(CompanyNotFound):
        worker.build_company_overview(session, company)
    with pytest.raises(CompanyNotFound):
        build_company_summary(session, company)


def test_protocol_without_completed_members_does_not_wait_forever(prepared):
    from fastapi import HTTPException

    session, _, _ = prepared
    empty = _add_protocol(session, "not-analyzed")
    with pytest.raises(HTTPException) as caught:
        pages.prepared_or_pending(session, request(), empty.name)
    assert caught.value.status_code == 404


@pytest.mark.parametrize("evidence", ["transaction", "creation"])
def test_upgrade_evidence_changes_only_invalidate_overview(prepared, evidence):
    from db.models import ContractCreationWitness, UpgradeEvent, UpgradeTransaction

    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    tx_hash = "0x" + "a" * 64
    transaction = UpgradeTransaction(
        chain_id=1,
        tx_hash=tx_hash,
        block_number=10,
        block_hash="0x" + "b" * 64,
        tx_status=1,
        receipt_from=_addr("sender"),
        receipt_to=contract.address,
        is_contract_creation=False,
        executor_kind="not_determined",
        receipt_log_set_complete_for_tx=True,
        receipt_upgraded_counts={contract.address: 1},
    )
    session.add(transaction)
    session.flush()
    session.add(
        UpgradeEvent(
            contract_id=contract.id,
            proxy_address=contract.address,
            tx_hash=tx_hash,
            chain_id=1,
            block_number=10,
            source="event_scan",
        )
    )
    session.commit()
    assert worker.refresh_one(factory) == "prepared"
    if evidence == "transaction":
        transaction.tx_status = 0
    else:
        session.add(
            ContractCreationWitness(
                chain_id=1,
                address=contract.address,
                creation_tx_hash=tx_hash,
                creation_block=10,
                code_probe_block=9,
                code_absent_at_probe=True,
            )
        )
    ready(session)
    assert source(session, protocol.name) == "prepared-stale"
    assert source(session, protocol.name, "functions") == "prepared"
    assert source(session, protocol.name, "summary") == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    assert source(session, protocol.name) == "prepared"


def test_renames_into_another_stale_cache_name_do_not_block_publication(prepared):
    session, protocol, factory = prepared
    other = _add_protocol(session, "second-company")
    address = _addr("rename")
    job = _add_job(session, address=address, protocol_id=other.id)
    _add_contract(session, address=address, job=job, protocol_id=other.id)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    other.name = "third-company"
    session.commit()
    protocol.name = "second-company"
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "idle"
    for identity in (protocol, other):
        response = pages.read_response(session, request(), identity.name)
        assert response is not None
        assert json.loads(bytes(response.body))["protocol_id"] == identity.id


def test_publication_sql_error_records_backoff_and_releases_claim(prepared, monkeypatch):
    from sqlalchemy import text

    session, protocol, factory = prepared

    def fail(write, _name):
        write.execute(text("SELECT 1 / 0"))

    original = worker.enqueue_purge
    monkeypatch.setattr(worker, "enqueue_purge", fail)
    assert worker.refresh_one(factory) == "failed"
    assert worker.refresh_one(factory) == "idle"
    row = session.get(Page, f"protocol:{protocol.id}")
    assert row.attempts == 1 and row.overview_gzip is None
    monkeypatch.setattr(worker, "enqueue_purge", original)
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
