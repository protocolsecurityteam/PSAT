"""Prepared response correctness against an isolated local PostgreSQL database."""

import gzip
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import Request
from sqlalchemy import event, select, text, update
from sqlalchemy.orm import sessionmaker

from db.models import CompanyPageSnapshot as Page
from db.models import Protocol
from services import company_pages as pages
from tests.conftest import requires_postgres
from tests.support.overview_builders import _add_contract, _add_job, _add_protocol, _addr
from workers import company_pages as worker

pytestmark = requires_postgres


@pytest.fixture
def prepared(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_PREPARED_COMPANY_PAGES", "1")
    protocol = _add_protocol(db_session, "prepared-example")
    address = _addr("prepared")
    job = _add_job(db_session, address=address, protocol_id=protocol.id)
    _add_contract(db_session, address=address, job=job, protocol_id=protocol.id)
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    return db_session, protocol, factory


def request(headers=None, query=b"", operator=False):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/company/prepared-example",
            "query_string": query,
            "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
            "state": {"edge_operator": operator},
        }
    )


def bodies(session):
    row = session.execute(select(Page.overview_gzip, Page.functions_gzip)).one()
    return [json.loads(gzip.decompress(b)) for b in row]


def test_real_build_pair_matches_live_and_imports_snapshot(prepared):
    session, protocol, factory = prepared
    seen = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "SET TRANSACTION SNAPSHOT" in statement:
            seen.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert worker.refresh_one(factory) == "prepared"
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert seen, "Parallel prefetch must import the source transaction snapshot"
    overview, functions = bodies(session)
    assert overview == worker.build_company_overview(session, protocol.name)
    assert functions == {"functions": worker.build_functions_for_protocol(session, protocol.name)}
    assert worker.refresh_one(factory) == "idle"


@pytest.mark.parametrize("functions", [False, True])
@pytest.mark.parametrize("encoding", ["gzip", "br, gzip;q=0.8", "identity", "gzip;q=0"])
def test_prepared_get_reads_one_blob_and_never_writes(prepared, functions, encoding):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    session.rollback()
    session.execute(text("SET TRANSACTION READ ONLY"))
    response = pages.read_response(session, request({"Accept-Encoding": encoding}), protocol.name, functions=functions)
    assert response is not None
    data = response.body
    if response.headers.get("content-encoding") == "gzip":
        data = gzip.decompress(data)
    assert isinstance(json.loads(bytes(data)), dict)
    assert response.headers["x-psat-response-source"] == "prepared"
    assert response.headers["vary"] == "Accept-Encoding"
    assert response.headers["x-psat-prepared-at"]


@pytest.mark.parametrize(
    "headers,query,operator",
    [
        ({"Cookie": "session=x"}, b"", False),
        ({"X-PSAT-Admin-Key": "x"}, b"", False),
        ({"Authorization": "Bearer x"}, b"", False),
        ({"CF-Access-Jwt-Assertion": "x"}, b"", False),
        ({"Origin": "https://snif.sh"}, b"", False),
        ({"Cache-Control": "no-cache"}, b"", False),
        ({}, b"fresh=1", False),
        ({}, b"", True),
    ],
)
def test_credentialed_and_explicit_fresh_reads_bypass_without_db_access(headers, query, operator, monkeypatch):
    monkeypatch.setenv("PSAT_PREPARED_COMPANY_PAGES", "1")
    session = MagicMock()
    assert pages.read_response(session, request(headers, query, operator), "example") is None
    session.execute.assert_not_called()


@pytest.mark.parametrize("change", ["age", "future", "version", "rename", "missing", "disabled"])
def test_invalid_or_expired_preparations_fall_back(prepared, monkeypatch, change):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    if change == "disabled":
        monkeypatch.setenv("PSAT_PREPARED_COMPANY_PAGES", "0")
    elif change == "rename":
        session.execute(update(Protocol).where(Protocol.id == protocol.id).values(name="renamed"))
    else:
        values = {
            "age": {"source_started_at": datetime.now(timezone.utc) - timedelta(seconds=61)},
            "future": {"source_started_at": datetime.now(timezone.utc) + timedelta(seconds=60)},
            "version": {"version": "old-deploy"},
            "missing": {"overview_gzip": None},
        }[change]
        session.execute(update(Page).values(**values))
    session.commit()
    assert pages.read_response(session, request(), "prepared-example") is None


def make_due(session):
    session.execute(
        update(Page).values(next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1), dirty_token=uuid.uuid4())
    )
    session.commit()


def test_failed_second_half_retains_pair_and_backs_off(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    old = bodies(session)
    make_due(session)

    def fail(*args):
        raise RuntimeError("functions unavailable")

    monkeypatch.setattr(worker, "build_functions_for_protocol", fail)
    assert worker.refresh_one(factory) == "failed"
    assert bodies(session) == old
    assert session.execute(select(Page.attempts)).scalar_one() == 1
    assert worker.refresh_one(factory) == "idle"


def test_mark_during_build_survives_atomic_publication(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    make_due(session)
    original = worker.build_functions_for_protocol

    def build(source, name):
        with factory() as concurrent:
            pages.mark_dirty(concurrent, protocol.id)
            concurrent.commit()
        return original(source, name)

    monkeypatch.setattr(worker, "build_functions_for_protocol", build)
    assert worker.refresh_one(factory) == "prepared"
    dirty, built = session.execute(select(Page.dirty_token, Page.built_token)).one()
    assert dirty != built


def test_worker_is_single_flight_and_refreshes_periodically(prepared):
    session, protocol, factory = prepared
    with factory() as lease:
        lease.execute(text("SELECT pg_advisory_xact_lock(210031, 0)"))
        assert worker.refresh_one(factory) == "leased"
    assert worker.refresh_one(factory) == "prepared"
    session.execute(
        update(Page).values(
            source_started_at=datetime.now(timezone.utc) - timedelta(seconds=35),
            next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
    )
    session.commit()
    assert worker.refresh_one(factory) == "prepared"


def test_unanalyzed_protocol_hints_do_not_spend_the_build_budget(prepared):
    session, protocol, factory = prepared
    empty = _add_protocol(session, "not-analyzed")
    pages.mark_dirty(session, empty.id)
    session.commit()
    assert worker.refresh_one(factory) == "prepared"
    assert worker.refresh_one(factory) == "idle"
    assert session.execute(select(Page.attempts).where(Page.protocol_id == empty.id)).scalar_one() == 0


def test_dirty_hint_rolls_back_with_producer(prepared):
    session, protocol, factory = prepared
    pages.mark_dirty(session, protocol.id)
    session.rollback()
    assert session.execute(select(Page)).first() is None


@pytest.mark.parametrize("encoding", ["gzip", "identity", "gzip;q=0", "*;q=1"])
def test_full_api_serves_prepared_bytes_without_building_and_falls_back(prepared, monkeypatch, encoding):
    from fastapi.testclient import TestClient

    import api
    from routers import company, deps

    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    expected = bodies(session)
    monkeypatch.setattr(deps, "SessionLocal", factory)
    monkeypatch.setattr(api.app, "middleware_stack", None)
    overview = MagicMock(return_value={"company": protocol.name, "contracts": []})
    functions = MagicMock(return_value={})
    monkeypatch.setattr(company, "build_company_overview", overview)
    monkeypatch.setattr(company, "build_functions_for_protocol", functions)
    client = TestClient(api.app)
    for index, suffix in enumerate(("", "/functions")):
        response = client.get(f"/api/company/{protocol.name}{suffix}", headers={"Accept-Encoding": encoding})
        assert response.status_code == 200
        assert response.json() == expected[index]
        assert response.headers.get("content-encoding") == ("gzip" if pages.accepts_gzip(encoding) else None)
        assert response.headers["x-psat-response-source"] == "prepared"
        assert "x-psat-fresh-until" not in response.headers
        ttl = int(response.headers["cache-control"].split("s-maxage=")[1].split(",")[0])
        assert 0 < ttl < 60
    overview.assert_not_called()
    functions.assert_not_called()
    session.execute(update(Page).values(source_started_at=datetime.now(timezone.utc) - timedelta(seconds=61)))
    session.commit()
    response = client.get(f"/api/company/{protocol.name}")
    assert response.status_code == 200
    assert response.headers["x-psat-response-source"] == "live"
    overview.assert_called_once()


def test_overview_and_functions_share_repeatable_read_snapshot(prepared, monkeypatch):
    session, protocol, factory = prepared
    # Publish first so the background's seed insert is not holding a new row.
    assert worker.refresh_one(factory) == "prepared"
    make_due(session)

    def overview(source, name):
        before = source.execute(select(Protocol.official_domain).where(Protocol.id == protocol.id)).scalar_one()
        with factory() as concurrent:
            concurrent.execute(update(Protocol).where(Protocol.id == protocol.id).values(official_domain="new.example"))
            concurrent.commit()
        return {"domain": before}

    def functions(source, name):
        return {
            "domain": source.execute(select(Protocol.official_domain).where(Protocol.id == protocol.id)).scalar_one()
        }

    monkeypatch.setattr(worker, "build_company_overview", overview)
    monkeypatch.setattr(worker, "build_functions_for_protocol", functions)
    assert worker.refresh_one(factory) == "prepared"
    assert bodies(session) == [{"domain": None}, {"functions": {"domain": None}}]


def test_schema_version_and_name_change_rebuild(prepared, monkeypatch):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    session.execute(update(Page).values(next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    session.execute(update(Protocol).where(Protocol.id == protocol.id).values(name="renamed"))
    session.commit()
    monkeypatch.setenv("GIT_SHA", "new-version")
    assert worker.refresh_one(factory) == "prepared"
    assert pages.read_response(session, request(), "renamed") is not None
    assert pages.read_response(session, request(), "prepared-example") is None


@pytest.mark.parametrize(
    "header,expected",
    [
        ("gzip;q=0,*;q=1", False),
        ("*;q=1", True),
        ("gzip;q=nan", False),
        ("gzip;q=garbage", False),
        ("gzip;q=2", False),
        ("", False),
    ],
)
def test_gzip_negotiation(header, expected):
    assert pages.accepts_gzip(header) == expected


def test_encode_is_bounded_and_json_equivalent(monkeypatch):
    assert json.loads(gzip.decompress(pages.encode({"unicode": "é"}))) == {"unicode": "é"}
    monkeypatch.setattr(pages, "MAX_JSON_BYTES", 3)
    with pytest.raises(ValueError, match="JSON size"):
        pages.encode({"large": "data"})
    monkeypatch.setattr(pages, "MAX_JSON_BYTES", 1000)
    monkeypatch.setattr(pages, "MAX_GZIP_BYTES", 1)
    with pytest.raises(ValueError, match="gzip size"):
        pages.encode({})


@pytest.mark.parametrize("body", [b"invalid gzip", gzip.compress(b"x" * 100)])
def test_identity_decode_corruption_or_oversize_falls_back(prepared, monkeypatch, body):
    session, protocol, factory = prepared
    assert worker.refresh_one(factory) == "prepared"
    session.execute(update(Page).values(overview_gzip=body))
    session.commit()
    monkeypatch.setattr(pages, "MAX_JSON_BYTES", 10)
    assert pages.read_response(session, request({"Accept-Encoding": "identity"}), protocol.name) is None


def test_failed_hint_does_not_abort_producer_transaction(prepared):
    session, protocol, factory = prepared
    pages.mark_dirty(session, -1)  # deliberately violates the cache's FK
    session.execute(update(Protocol).where(Protocol.id == protocol.id).values(official_domain="valid.example"))
    session.commit()
    assert (
        session.execute(select(Protocol.official_domain).where(Protocol.id == protocol.id)).scalar_one()
        == "valid.example"
    )


def test_producer_hints_are_connected_and_disabled_flag_is_safe(prepared, monkeypatch):
    from services.monitoring.enrollment import mark_enrollment_dirty
    from services.scoring.dirty import mark_protocol_score_dirty

    session, protocol, factory = prepared
    assert mark_protocol_score_dirty(session, protocol.id, "manual")
    first = session.execute(select(Page.dirty_token)).scalar_one()
    mark_enrollment_dirty(session, protocol.id, "governance_rotation")
    second = session.execute(select(Page.dirty_token)).scalar_one()
    assert first != second
    monkeypatch.setenv("PSAT_PREPARED_COMPANY_PAGES", "0")
    pages.mark_dirty(session, protocol.id)
    assert session.execute(select(Page.dirty_token)).scalar_one() == second
    session.rollback()


@pytest.mark.parametrize("mode", ["prepared", "disabled", "failure"])
def test_supervised_loop_reports_heartbeat_and_honors_stop(monkeypatch, mode):
    from threading import Event

    stop = Event()
    beats = []
    monkeypatch.setattr(worker, "enabled", lambda: mode != "disabled")

    def refresh():
        if mode == "failure":
            raise RuntimeError("database unavailable")
        return "prepared"

    def heartbeat(*args, **kwargs):
        beats.append(kwargs)
        stop.set()

    monkeypatch.setattr(worker, "refresh_one", refresh)
    monkeypatch.setattr(worker, "record_heartbeat", heartbeat)
    worker.run(stop)
    assert len(beats) == 1
    assert beats[0]["status"] == ("error" if mode == "failure" else "running")
