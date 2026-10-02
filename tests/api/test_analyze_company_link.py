"""/api/analyze optional company linking: an address submission naming a
company resolves to the EXISTING Protocol row (lookup-only) and stamps
``protocol_id`` + an attributed W5 human assertion on the job request
(explicit membership approval) — never a source tag. The gate consumes the
assertion at nomination time. Address-only submissions stay standalone;
company-only submissions keep minting their protocol in discovery.
"""

from __future__ import annotations

import uuid

from tests.conftest import requires_postgres


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


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
