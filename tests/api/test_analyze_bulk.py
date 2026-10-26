"""``POST /api/analyze/bulk``: each row is a single address+company submission, a refused row is that row's
result, and the W5 actor names whoever authenticated.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_postgres

SAME_ORIGIN = {"Origin": "http://testserver"}


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture()
def protocol(db_session):
    from db.models import Protocol

    row = Protocol(name=f"bulk-{uuid.uuid4().hex[:8]}")
    db_session.add(row)
    db_session.commit()
    return row


@pytest.fixture(autouse=True)
def _chains(monkeypatch):
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")


@pytest.fixture()
def labels(db_session):
    from db.models import AddressLabel

    written: list[str] = []
    yield written
    db_session.rollback()
    if written:
        db_session.query(AddressLabel).filter(AddressLabel.address.in_(written)).delete()
        db_session.commit()


def _job(db_session, job_id: str):
    from db.models import Job

    return db_session.query(Job).filter_by(id=uuid.UUID(job_id)).one()


@requires_postgres
def test_per_row_outcomes_in_input_order(api_client, db_session, protocol):
    good, base_good, other = _addr(), _addr(), _addr()
    rows = [
        {"address": good, "chain": "ethereum", "name": "Vault"},
        {"address": "0x" + "zz" * 20, "chain": "ethereum"},
        {"address": other, "chain": "base-sepolia"},
        {"address": other, "chain": "arbitrum"},
        {"address": good.upper().replace("0X", "0x"), "chain": "mainnet"},
        {"address": f"  {base_good} ", "chain": " base "},
        {"address": base_good, "chain": "Base"},
    ]
    resp = api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": rows})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    results = body["results"]
    assert [r["row"] for r in results] == list(range(len(rows)))
    assert [r["status"] for r in results] == [
        "queued",
        "rejected",
        "rejected",
        "rejected",
        "duplicate",
        "queued",
        "duplicate",
    ]
    assert (body["queued"], body["rejected"], body["duplicate"]) == (2, 3, 2)
    assert "20-byte hex" in results[1]["reason"]
    assert "unknown chain" in results[2]["reason"]
    assert "PSAT_SUPPORTED_CHAIN_IDS" in results[3]["reason"]
    assert results[4]["duplicate_of"] == 0 and results[4]["job_id"] is None
    assert results[6]["duplicate_of"] == 5

    job = _job(db_session, results[0]["job_id"])
    assert job.protocol_id == protocol.id and job.address == good
    assert _job(db_session, results[5]["job_id"]).chain_id == 8453


@requires_postgres
def test_row_matches_a_single_submission(api_client, db_session, protocol):
    from services.discovery.membership_gate import HUMAN_ASSERTION_REQUEST_KEY

    single_addr, bulk_addr = _addr(), _addr()
    single = api_client.post(
        "/api/analyze", json={"address": single_addr, "company": protocol.name, "name": "N", "chain": "base"}
    )
    bulk = api_client.post(
        "/api/analyze/bulk",
        json={"company": protocol.name, "rows": [{"address": bulk_addr, "chain": "base", "name": "N"}]},
    )
    assert single.status_code == 200 and bulk.status_code == 200
    a = _job(db_session, single.json()["job_id"])
    b = _job(db_session, bulk.json()["results"][0]["job_id"])

    def shape(job):
        request = {k: v for k, v in job.request.items() if k != "address"}
        request[HUMAN_ASSERTION_REQUEST_KEY] = {**request[HUMAN_ASSERTION_REQUEST_KEY], "asserted_at": None}
        return request, job.protocol_id, job.chain_id, job.stage, job.name, job.company

    assert shape(a) == shape(b)


@requires_postgres
def test_unknown_company_404s_and_queues_nothing(api_client, db_session):
    from db.models import Job

    addr = _addr()
    resp = api_client.post(
        "/api/analyze/bulk", json={"company": f"nope-{uuid.uuid4().hex[:8]}", "rows": [{"address": addr}]}
    )
    assert resp.status_code == 404
    assert db_session.query(Job).filter_by(address=addr).count() == 0


@requires_postgres
def test_row_cap(api_client, protocol):
    rows = [{"address": _addr(), "chain": "ethereum"} for _ in range(501)]
    assert api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": rows}).status_code == 422
    assert api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": []}).status_code == 422


@requires_postgres
def test_oversized_cells_are_row_results_not_a_failed_request(api_client, db_session, protocol, labels):
    from db.models import AddressLabel

    long_named = _addr()
    labels.append(long_named)
    rows = [
        {"address": "0x" + "a" * 5000, "chain": "ethereum"},
        {"address": _addr(), "chain": "c" * 5000},
        {"address": long_named, "chain": "ethereum", "name": "n" * 5000},
    ]
    resp = api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": rows})
    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert [r["status"] for r in results] == ["rejected", "rejected", "queued"]
    assert "20-byte hex" in results[0]["reason"] and "unknown chain" in results[1]["reason"]
    assert results[2]["label"] == "skipped_too_long"
    assert _job(db_session, results[2]["job_id"]).name == "n" * 5000
    assert db_session.query(AddressLabel).filter_by(address=long_named).count() == 0


@requires_postgres
def test_copy_of_a_refused_row_is_judged_on_its_own(api_client, protocol, monkeypatch):
    from routers import jobs

    real = jobs.submit_analysis
    calls = {"n": 0}

    def flaky_first(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise jobs.AnalyzeRejected(400, "refused once")
        return real(*args, **kwargs)

    monkeypatch.setattr(jobs, "submit_analysis", flaky_first)
    addr = _addr()
    rows = [{"address": addr, "chain": "ethereum"}, {"address": addr, "chain": "mainnet"}, {"address": addr}]
    results = api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": rows}).json()["results"]
    assert [(r["status"], r["duplicate_of"]) for r in results] == [
        ("rejected", None),
        ("queued", None),
        ("duplicate", 1),
    ]


@requires_postgres
def test_a_failed_label_write_leaves_the_row_queued(api_client, db_session, protocol, monkeypatch, labels):
    from routers import jobs

    # Past the length guard, so Postgres itself refuses the over-long name inside the savepoint.
    monkeypatch.setattr(jobs, "_LABEL_NAME_MAX", 10_000)
    first, second = _addr(), _addr()
    labels.extend([first, second])
    rows = [{"address": first, "name": "n" * 300}, {"address": second, "name": "B"}]
    resp = api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": rows})
    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert [(r["status"], r["label"]) for r in results] == [("queued", "not_set"), ("queued", "set")]
    for r in results:
        assert _job(db_session, r["job_id"]).status.value == "queued"


def test_preview_label_limit_matches_the_label_column():
    import re
    from pathlib import Path

    from db.models import AddressLabel

    source = (Path(__file__).resolve().parents[2] / "site/src/bulkImport/csv.js").read_text()
    match = re.search(r"export const LABEL_NAME_MAX = (\d+);", source)
    assert match is not None
    assert int(match.group(1)) == AddressLabel.name.type.length


@requires_postgres
def test_name_becomes_a_label_only_where_none_shows(api_client, db_session, protocol, labels):
    from db.models import AddressLabel

    fresh, chain_named, globally_named, refused = _addr(), _addr(), _addr(), _addr()
    labels.extend([fresh, chain_named, globally_named, refused])
    db_session.add_all(
        [
            AddressLabel(address=chain_named, chain="ethereum", name="Curated"),
            AddressLabel(address=globally_named, chain=None, name="Curated global"),
        ]
    )
    db_session.commit()
    rows = [
        {"address": fresh, "chain": "mainnet", "name": " From CSV "},
        {"address": chain_named, "chain": "ethereum", "name": "From CSV"},
        {"address": globally_named, "chain": "ethereum", "name": "From CSV"},
        {"address": refused, "chain": "arbitrum", "name": "From CSV"},
        {"address": _addr(), "chain": "ethereum"},
    ]
    results = api_client.post("/api/analyze/bulk", json={"company": protocol.name, "rows": rows}).json()["results"]
    assert [r["label"] for r in results] == ["set", "kept_existing", "kept_existing", None, None]

    def names(address):
        return {(row.chain, row.name) for row in db_session.query(AddressLabel).filter_by(address=address).all()}

    db_session.expire_all()
    assert names(fresh) == {("ethereum", "From CSV")}
    assert names(chain_named) == {("ethereum", "Curated")}
    assert names(globally_named) == {(None, "Curated global")}
    assert names(refused) == set()


def _real_auth(monkeypatch):
    import api
    from routers import deps

    monkeypatch.setattr(deps, "ADMIN_KEY", "bulk-test-key")
    monkeypatch.setenv("PSAT_ADMIN_EMAILS", "boss@example.com")
    for name in ("FLY_APP_NAME", "PSAT_EDGE_MODE"):
        monkeypatch.delenv(name, raising=False)
    # The conftest bypass reinstalls both overrides for the next test.
    for dep in (deps.require_admin, deps.admin_actor):
        api.app.dependency_overrides.pop(dep, None)


def _sign_in_admin(db_session, client):
    from services.auth.sessions import SESSION_COOKIE, create_session, upsert_neon_user

    user = upsert_neon_user(
        db_session,
        neon_auth_id=f"neon-{uuid.uuid4().hex[:8]}",
        email="boss@example.com",
        email_verified=True,
        display_name=None,
        avatar_url=None,
    )
    token = create_session(db_session, user)
    db_session.commit()
    client.cookies.set(SESSION_COOKIE, token)
    return user


def _actor(db_session, job_id: str) -> str:
    from services.discovery.membership_gate import HUMAN_ASSERTION_REQUEST_KEY

    return _job(db_session, job_id).request[HUMAN_ASSERTION_REQUEST_KEY]["actor"]


@requires_postgres
def test_w5_actor_is_the_signed_in_account(api_client, db_session, protocol, monkeypatch):
    _real_auth(monkeypatch)
    user = _sign_in_admin(db_session, api_client)
    single = api_client.post("/api/analyze", json={"address": _addr(), "company": protocol.name}, headers=SAME_ORIGIN)
    bulk = api_client.post(
        "/api/analyze/bulk", json={"company": protocol.name, "rows": [{"address": _addr()}]}, headers=SAME_ORIGIN
    )
    assert single.status_code == 200, single.text
    assert bulk.status_code == 200, bulk.text
    assert _actor(db_session, single.json()["job_id"]) == f"account:{user.id}"
    assert _actor(db_session, bulk.json()["results"][0]["job_id"]) == f"account:{user.id}"
    assert "@" not in _actor(db_session, single.json()["job_id"])


@requires_postgres
def test_w5_actor_is_the_key_when_the_key_authenticated(api_client, db_session, protocol, monkeypatch):
    _real_auth(monkeypatch)
    _sign_in_admin(db_session, api_client)
    headers = {**SAME_ORIGIN, "X-PSAT-Admin-Key": "bulk-test-key"}
    single = api_client.post("/api/analyze", json={"address": _addr(), "company": protocol.name}, headers=headers)
    bulk = api_client.post(
        "/api/analyze/bulk", json={"company": protocol.name, "rows": [{"address": _addr()}]}, headers=headers
    )
    assert _actor(db_session, single.json()["job_id"]) == "admin_api_key"
    assert _actor(db_session, bulk.json()["results"][0]["job_id"]) == "admin_api_key"


@requires_postgres
def test_bulk_and_company_list_require_admin(api_client, protocol, monkeypatch):
    _real_auth(monkeypatch)
    body = {"company": protocol.name, "rows": [{"address": _addr()}]}
    assert api_client.post("/api/analyze/bulk", json=body, headers=SAME_ORIGIN).status_code == 401
    assert api_client.get("/api/companies").status_code == 401
    assert api_client.get("/api/config").status_code == 401


@requires_postgres
def test_admin_actor_refuses_when_no_actor_was_recorded(api_client, protocol):
    import api
    from routers import deps

    # ``require_admin`` stays bypassed, so nothing records who authenticated.
    api.app.dependency_overrides.pop(deps.admin_actor, None)
    body = {"company": protocol.name, "rows": [{"address": _addr()}]}
    assert api_client.post("/api/analyze/bulk", json=body).status_code == 401
    assert api_client.post("/api/analyze", json={"address": _addr(), "company": protocol.name}).status_code == 401


@requires_postgres
def test_company_list_includes_protocols_without_jobs(api_client, db_session, protocol):
    from db.models import Job

    assert db_session.query(Job).filter_by(protocol_id=protocol.id).count() == 0
    names = api_client.get("/api/companies").json()
    assert protocol.name in names
    assert names == sorted(names, key=str.lower)


@requires_postgres
def test_config_lists_enabled_chains_and_every_accepted_spelling(api_client):
    from utils.chains import UnknownChainError, chain_by_name

    config = api_client.get("/api/config").json()
    assert config["enabled_chains"] == ["ethereum", "base"]
    spellings = config["chain_spellings"]
    assert spellings["mainnet"] == "ethereum" and spellings["arbitrum one"] == "arbitrum"
    for spelling, canonical in spellings.items():
        assert chain_by_name(spelling).name == canonical
    with pytest.raises(UnknownChainError):
        chain_by_name("avalanche c-chain")
    assert "avalanche c chain" not in spellings
