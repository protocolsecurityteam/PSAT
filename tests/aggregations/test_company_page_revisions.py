"""Transactional invalidation, shared dependencies, and public/private reuse."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Table, delete, event, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import visitors

from db.models import CompanyPageRevision as Revision
from db.models import CompanyPageSnapshot as Page
from db.models import (
    Contract,
    ContractBalance,
    ContractSummary,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStatus,
    TokenDeliveryEvidence,
    TvlSnapshot,
)
from services import company_pages as pages
from tests.aggregations.test_prepared_company_pages import prepared as prepared
from tests.aggregations.test_prepared_company_pages import request
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr
from workers import company_pages as worker

pytestmark = requires_postgres


def ready(session):
    session.execute(update(Page).values(next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    session.commit()


def root_contract(session, protocol):
    return session.execute(select(Contract).where(Contract.protocol_id == protocol.id)).scalar_one()


def test_reconciler_bookkeeping_never_rebuilds_or_enqueues_a_purge(prepared, monkeypatch):
    from db.models import CompanyPagePurge
    from services.monitoring.reconciler import EnrollmentClaim, _finish_success

    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    session.execute(delete(CompanyPagePurge))
    ready(session)
    response = pages.read_response(session, request(), protocol.name)
    assert response is not None
    original = response.body
    tokens = session.execute(select(Revision.key, Revision.token).order_by(Revision.key)).all()
    builder = MagicMock(side_effect=AssertionError("Bookkeeping must not rebuild"))
    monkeypatch.setattr(worker, "build_company_overview", builder)
    for _ in range(3):
        _finish_success(session, EnrollmentClaim(protocol.id, datetime.now(timezone.utc), 0, uuid4()))
        assert worker.refresh_one(factory) == "idle"
        response = pages.read_response(session, request(), protocol.name)
        assert response is not None and response.body == original
    assert session.execute(select(Revision.key, Revision.token).order_by(Revision.key)).all() == tokens
    assert session.execute(select(CompanyPagePurge)).first() is None
    builder.assert_not_called()


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE protocols SET name=name",
        "UPDATE contracts SET contract_name=contract_name, job_id=job_id",
        "UPDATE jobs SET request=request, updated_at=updated_at",
        "UPDATE contract_summaries SET has_timelock=has_timelock",
        "UPDATE protocols SET official_domain='bookkeeping.example'",
        "UPDATE jobs SET detail='heartbeat only'",
        "UPDATE contracts SET rank_score=0.25, compiler_version='bookkeeping'",
    ],
)
def test_irrelevant_or_identical_updates_leave_revision_tokens_unchanged(prepared, sql):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    session.add(ContractSummary(contract_id=contract.id, has_timelock=False))
    session.commit()
    assert worker.refresh_one(factory) == "prepared"
    ready(session)
    tokens = session.execute(select(Revision.key, Revision.token).order_by(Revision.key)).all()
    session.execute(text(sql))
    session.commit()
    assert session.execute(select(Revision.key, Revision.token).order_by(Revision.key)).all() == tokens
    assert worker.refresh_one(factory) == "idle"
    assert pages.read_response(session, request(), protocol.name) is not None


@pytest.mark.parametrize("operation", ["contract", "child", "completed_job", "signals"])
def test_independent_contract_writers_do_not_share_a_protocol_lock(prepared, operation):
    session, protocol, factory = prepared
    first = root_contract(session, protocol)
    address = _addr("independent")
    job = _add_job(session, address=address, protocol_id=protocol.id)
    second = _add_contract(session, address=address, job=job, protocol_id=protocol.id)
    reanalysis = _add_job(session, address=first.address, protocol_id=protocol.id, status=JobStatus.queued)
    assert worker.refresh_one(factory) == "prepared"
    # Match static-cache copying: flush the pointer change, then retain that
    # transaction while external work would run. No external call in this test.
    with factory() as copying, factory() as independent:
        copying.execute(update(Contract).where(Contract.id == first.id).values(job_id=reanalysis.id))
        copying.flush()
        independent.execute(text("SET LOCAL lock_timeout = '500ms'"))
        if operation == "contract":
            independent.execute(update(Contract).where(Contract.id == second.id).values(contract_name="Changed"))
        elif operation == "child":
            independent.add(ContractSummary(contract_id=second.id, has_timelock=True))
        elif operation == "signals":
            from types import SimpleNamespace

            from tests.scoring.test_scoring_schema import _row

            independent.add(
                _row(SimpleNamespace(job=job, protocol=protocol, contract=second), deployment_address=second.address)
            )
        else:
            independent.execute(update(Job).where(Job.id == job.id).values(name="Changed job"))
        independent.commit()  # Must finish while copying is still uncommitted.
        assert pages.read_response(session, request(), protocol.name) is None
        copying.rollback()
    # The company check is a read-only digest, never a producer-written row.
    assert session.get(Revision, f"protocol:{protocol.id}") is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    assert pages.read_response(session, request(), protocol.name) is not None


def test_new_member_committed_during_build_is_not_lost_from_protocol_fingerprint(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    session.execute(update(Contract).values(contract_name="Start new build"))
    ready(session)
    original = worker.build_functions_for_protocol

    def build(source, name):
        with factory() as concurrent:
            concurrent.add(Contract(address=_addr("new-member"), nominated_protocol_id=protocol.id))
            concurrent.commit()
        return original(source, name)

    monkeypatch.setattr(worker, "build_functions_for_protocol", build)
    assert worker.refresh_one(factory) == "prepared"
    assert pages.read_response(session, request(), protocol.name) is None
    monkeypatch.setattr(worker, "build_functions_for_protocol", original)
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    assert pages.read_response(session, request(), protocol.name) is not None


def test_mixed_bulk_update_only_touches_actually_changed_rows(prepared):
    session, protocol, factory = prepared
    first = root_contract(session, protocol)
    address = _addr("unchanged")
    job = _add_job(session, address=address, protocol_id=protocol.id)
    second = _add_contract(session, address=address, job=job, protocol_id=protocol.id)
    key = f"protocol:{protocol.id}:contract:{second.id}"
    before = session.get(Revision, key).token
    session.execute(
        text("UPDATE contracts SET contract_name=CASE WHEN id=:id THEN 'Changed' ELSE contract_name END"),
        {"id": first.id},
    )
    session.commit()
    assert session.execute(select(Revision.token).where(Revision.key == key)).scalar_one() == before


def test_response_bearing_deployer_change_invalidates_and_rebuilds(prepared):
    import json

    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    assert worker.refresh_one(factory) == "prepared"
    deployer = _addr("new-deployer")
    contract.deployer = deployer
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    response = pages.read_response(session, request(), protocol.name)
    assert response is not None
    data = json.loads(bytes(response.body))
    assert data["contracts"][0]["deployer"] == deployer
    assert data == worker.build_company_overview(session, protocol.name)


@pytest.mark.parametrize("header", ["Cookie", "X-PSAT-Admin-Key", "Authorization", "CF-Access-Jwt-Assertion", "Origin"])
def test_operator_credentials_do_not_change_prepared_data(prepared, header):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    for functions in (False, True):
        public = pages.read_response(session, request(), protocol.name, functions=functions)
        operator = pages.read_response(
            session, request({header: "test"}, operator=True), protocol.name, functions=functions
        )
        assert operator is not None and public is not None
        assert operator.body == public.body


@pytest.mark.parametrize("headers", [{"Cookie": "session=x"}, {"Origin": "https://snif.sh"}])
def test_shared_preparation_still_has_private_http_headers(prepared, monkeypatch, headers):
    import api
    from routers import company, deps

    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    monkeypatch.setattr(deps, "SessionLocal", factory)
    monkeypatch.setattr(api.app, "middleware_stack", None)
    builder = MagicMock(side_effect=AssertionError("Must reuse preparation"))
    monkeypatch.setattr(company, "build_company_overview", builder)
    response = TestClient(api.app).get(f"/api/company/{protocol.name}", headers=headers)
    assert response.status_code == 200
    assert response.headers["x-psat-response-source"] == "prepared"
    assert response.headers["cache-control"] == "private, no-store"
    assert "x-psat-fresh-until" not in response.headers
    builder.assert_not_called()


def test_bulk_updates_coalesce_and_unrelated_protocol_does_not_dirty(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    other = _add_protocol(session, "unrelated")
    address = _addr("other")
    job = _add_job(session, address=address, protocol_id=other.id)
    _add_contract(session, address=address, job=job, protocol_id=other.id)
    assert pages.read_response(session, request(), protocol.name) is not None
    key = f"protocol:{protocol.id}:contract:{root_contract(session, protocol).id}"
    before = session.get(Revision, key).token
    for i in range(20):
        session.execute(
            update(Contract).where(Contract.protocol_id == protocol.id).values(contract_name=f"Revision {i}")
        )
    changed = session.execute(select(Revision.token).where(Revision.key == key)).scalar_one()
    assert changed != before
    session.execute(update(Contract).where(Contract.protocol_id == protocol.id).values(contract_name="Final"))
    assert session.execute(select(Revision.token).where(Revision.key == key)).scalar_one() == changed
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None
    # Prepare the unrelated company, then rebuild the one dirty company once.
    ready(session)
    builder = MagicMock(wraps=worker.build_company_overview)
    monkeypatch.setattr(worker, "build_company_overview", builder)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    for _ in range(10):
        assert worker.refresh_one(factory) == "idle"
    assert [c.args[1] for c in builder.call_args_list].count(protocol.name) == 1


@pytest.mark.parametrize("operation", ["insert", "update", "delete"])
def test_raw_sql_child_writes_invalidate_without_python_hooks(prepared, operation):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    if operation != "insert":
        session.add(ContractSummary(contract_id=contract.id, has_timelock=False))
        session.commit()
    assert worker.refresh_one(factory) == "prepared"
    sql = {
        "insert": "INSERT INTO contract_summaries (contract_id, has_timelock) VALUES (:id, true)",
        "update": "UPDATE contract_summaries SET has_timelock = true WHERE contract_id = :id",
        "delete": "DELETE FROM contract_summaries WHERE contract_id = :id",
    }[operation]
    session.execute(text(sql), {"id": contract.id})
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None


def test_borrowed_and_missing_implementations_invalidate_owner(prepared):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    impl_address = _addr("implementation")
    contract.is_proxy = True
    contract.implementation = impl_address
    session.commit()
    assert worker.refresh_one(factory) == "prepared"
    dependencies = session.execute(select(Page.source_revisions)).scalar_one()
    assert f"address:{impl_address}" in dependencies
    other = _add_protocol(session, "implementation-owner")
    impl_job = _add_job(session, address=impl_address, protocol_id=other.id)
    impl = _add_contract(session, address=impl_address, job=impl_job, protocol_id=other.id)
    assert pages.read_response(session, request(), protocol.name) is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    session.add(ContractSummary(contract_id=impl.id, has_timelock=True))
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None


def test_function_principal_changes_and_cascaded_deletes_invalidate(prepared):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    function = EffectiveFunction(contract_id=contract.id, function_name="changeOwner")
    session.add(function)
    session.flush()
    principal = FunctionPrincipal(function_id=function.id, address=_addr("owner"))
    session.add(principal)
    session.commit()
    assert worker.refresh_one(factory) == "prepared"
    principal.resolved_type = "safe"
    session.commit()
    assert pages.read_response(session, request(), protocol.name, functions=True) is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    session.execute(delete(EffectiveFunction).where(EffectiveFunction.id == function.id))
    session.commit()
    assert pages.read_response(session, request(), protocol.name, functions=True) is None


def test_tvl_and_pending_member_inventory_changes_invalidate(prepared):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    session.add(TvlSnapshot(protocol_id=protocol.id, total_usd=123))
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    session.add(Contract(address=_addr("candidate"), nominated_protocol_id=protocol.id))
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None


def test_balance_and_missing_delivery_evidence_track_the_observed_holder(prepared):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    holder = _addr("different-observed-holder")
    token = _addr("token")
    assert worker.refresh_one(factory) == "prepared"
    balance = ContractBalance(contract_id=contract.id, token_address=token, raw_balance="100", observed_address=holder)
    session.add(balance)
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    dependencies = session.execute(select(Page.source_revisions)).scalar_one()
    assert dependencies[f"holder:{holder}"] is None
    session.add(
        TokenDeliveryEvidence(
            chain_id=1,
            holder_address=holder,
            token_address=token,
            scanned_from_block=0,
            measured_through_block=1,
            deliveries=[],
            delivery_count=0,
            fan_out_threshold_k=25,
            basis="test",
        )
    )
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None
    ready(session)
    assert worker.refresh_one(factory) == "prepared"
    session.execute(delete(ContractBalance).where(ContractBalance.id == balance.id))
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None


def test_moving_a_member_invalidates_both_protocols(prepared):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    other = _add_protocol(session, "destination")
    address = _addr("destination")
    job = _add_job(session, address=address, protocol_id=other.id)
    _add_contract(session, address=address, job=job, protocol_id=other.id)
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "prepared"
    contract.protocol_id = other.id
    session.commit()
    assert pages.read_response(session, request(), protocol.name) is None
    assert pages.read_response(session, request(), other.name) is None


def test_input_read_tables_have_transactional_triggers(prepared):
    session, protocol, factory = prepared
    read_tables = set()

    def capture(conn, cursor, statement, parameters, context, executemany):
        compiled = context.compiled
        if compiled and getattr(compiled.statement, "is_select", False):
            read_tables.update(node.name for node in visitors.iterate(compiled.statement) if isinstance(node, Table))

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert worker.refresh_one(factory) == "prepared"
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    audited = {
        "contracts",
        "jobs",
        "protocols",
        "contract_summaries",
        "controller_values",
        "control_graph_nodes",
        "control_graph_edges",
        "effective_functions",
        "function_principals",
        "principal_labels",
        "upgrade_events",
        "contract_balances",
        "contract_balance_fetches",
        "tvl_snapshots",
        "function_score_signals",
        "token_protocol_reference",
        "token_delivery_evidence",
    }
    assert read_tables - {"company_page_snapshots", "company_page_revisions", "contract_balances_latest"} <= audited
    triggers = session.execute(
        text("""SELECT c.relname, t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        WHERE t.tgname LIKE 'psat_page_%' AND t.tgenabled = 'O'""")
    ).all()
    for table in audited:
        assert {name for rel, name in triggers if rel == table} == {
            f"psat_page_{event}" for event in ("insert", "update", "delete", "truncate")
        }


def test_invalidation_failure_rolls_back_source_write(prepared):
    session, protocol, factory = prepared
    contract = root_contract(session, protocol)
    old_name = contract.contract_name
    session.execute(
        text("ALTER TABLE company_page_revisions ADD CONSTRAINT test_reject_revision CHECK (false) NOT VALID")
    )
    with pytest.raises(IntegrityError, match="test_reject_revision"):
        session.execute(update(Contract).where(Contract.id == contract.id).values(contract_name="must roll back"))
    session.rollback()  # also removes the deliberately failing test constraint
    assert session.get(Contract, contract.id).contract_name == old_name
