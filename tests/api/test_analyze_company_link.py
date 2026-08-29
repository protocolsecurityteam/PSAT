"""/api/analyze optional company linking: an address submission naming a
company resolves to the EXISTING Protocol row (lookup-only) and stamps
``protocol_id`` + an attributed W5 human assertion on the job request
(membership gate, invariant 14) — never a source tag. The gate consumes the
assertion at nomination time. Address-only submissions stay standalone;
company-only submissions keep minting their protocol in discovery.
"""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@requires_postgres
def test_analyze_with_company_links_existing_protocol(api_client, db_session):
    from db.models import Job, Protocol

    proto = Protocol(name=f"linkco-{uuid.uuid4().hex[:10]}")
    db_session.add(proto)
    db_session.commit()

    resp = api_client.post("/api/analyze", json={"address": _addr(), "name": "t", "company": proto.name})
    assert resp.status_code == 200, resp.text

    job = db_session.query(Job).filter_by(id=resp.json()["job_id"]).one()
    assert job.protocol_id == proto.id
    # W5 rides the request as an attributed assertion — never a source tag.
    assertion = job.request.get("human_assertion")
    assert isinstance(assertion, dict)
    assert assertion["actor"] == "admin_api_key"
    assert isinstance(assertion["asserted_at"], str) and assertion["asserted_at"]
    assert "inventory" not in (job.request.get("discovery_sources") or [])

    from services.discovery.membership_gate import human_assertion_from_request

    parsed = human_assertion_from_request(job.request)
    assert parsed is not None and parsed.actor == "admin_api_key"


@requires_postgres
def test_analyze_company_match_is_case_insensitive(api_client, db_session):
    from db.models import Job, Protocol

    base_name = f"caseco-{uuid.uuid4().hex[:10]}"
    proto = Protocol(name=base_name)
    db_session.add(proto)
    db_session.commit()

    resp = api_client.post("/api/analyze", json={"address": _addr(), "name": "t", "company": base_name.upper()})
    assert resp.status_code == 200, resp.text
    job = db_session.query(Job).filter_by(id=resp.json()["job_id"]).one()
    assert job.protocol_id == proto.id


@requires_postgres
def test_analyze_with_unknown_company_404s(api_client, db_session):
    from db.models import Job

    addr = _addr()
    resp = api_client.post(
        "/api/analyze", json={"address": addr, "name": "t", "company": f"nope-{uuid.uuid4().hex[:8]}"}
    )
    assert resp.status_code == 404
    assert "Company not found" in resp.json()["detail"]
    assert db_session.query(Job).filter_by(address=addr).count() == 0


@requires_postgres
def test_analyze_address_only_stays_unlinked(api_client, db_session):
    from db.models import Job

    resp = api_client.post("/api/analyze", json={"address": _addr(), "name": "t"})
    assert resp.status_code == 200, resp.text
    job = db_session.query(Job).filter_by(id=resp.json()["job_id"]).one()
    assert job.protocol_id is None
    assert not (job.request.get("discovery_sources") or [])


@requires_postgres
def test_analyze_normalizes_address_case(api_client, db_session):
    """A checksummed submission stores the lowercase address, so every exact-
    match consumer (spawn dedup, listing joins) sees one canonical form."""
    from db.models import Job

    lower = _addr()
    resp = api_client.post("/api/analyze", json={"address": lower[:2] + lower[2:].upper(), "name": "t"})
    assert resp.status_code == 200, resp.text
    job = db_session.query(Job).filter_by(id=resp.json()["job_id"]).one()
    assert job.address == lower
    assert job.request["address"] == lower


@requires_postgres
def test_analyze_company_only_submission_unaffected(api_client, db_session):
    """Company-only submissions mint/resolve their protocol during discovery —
    no ingress lookup, no 404 for a company that doesn't exist yet."""
    from db.models import Job

    name = f"newco-{uuid.uuid4().hex[:10]}"
    resp = api_client.post("/api/analyze", json={"company": name})
    assert resp.status_code == 200, resp.text
    job = db_session.query(Job).filter_by(id=resp.json()["job_id"]).one()
    assert job.protocol_id is None  # discovery attaches it later
