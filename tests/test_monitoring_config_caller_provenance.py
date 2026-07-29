"""A caller-authored ``monitoring_config`` may not read as an analysis result.

``services/monitoring/enrollment._build_monitoring_config`` gives
``monitored_contracts.monitoring_config`` a three-way tracking-plan discriminant,
stated in its own docstring:

* ``tracked_topics`` present            — the analysis produced a plan;
* ``tracking_plan_not_determined``      — the plan was not read; the token says why;
* NEITHER key                           — the plan WAS read and named nothing.
  "Absent key = we read the plan; the empty ``tracked_topics`` is then a finding
  and may be relied on."

``POST /api/protocols/{id}/monitoring`` and ``PATCH /api/monitored-contracts/{id}``
never called that builder — they stored the caller's dict verbatim — so every
caller-enrolled row landed in the third bucket. On the PR-161 preview all 3
``enrollment_source='surface_alert'`` rows carried neither key, i.e. read as
"the analysis looked and found nothing to track" for contracts no tracking-plan
artifact was ever consulted for.

The sibling that gives it teeth: ``unified_watcher._scan_topics_union`` unions
``monitoring_config->'tracked_topics'`` over every active row into the live scan
filter, and nothing checked where those topics came from.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select, text

from db.models import MonitoredContract, Protocol
from routers.monitored import CALLER_SUPPLIED_TRACKING_PLAN

ADDR = "0x" + "7d" * 20
TOPIC0 = "0x" + "e1" * 32


@pytest.fixture
def protocol_id(db_session):
    protocol = Protocol(name="caller_provenance_co")
    db_session.add(protocol)
    db_session.commit()
    try:
        yield protocol.id
    finally:
        db_session.rollback()
        db_session.execute(text("DELETE FROM monitored_contracts WHERE protocol_id = :p"), {"p": protocol.id})
        db_session.execute(text("DELETE FROM protocols WHERE id = :p"), {"p": protocol.id})
        db_session.commit()


@pytest.fixture
def admin_headers(monkeypatch):
    from routers import deps

    monkeypatch.setattr(deps, "ADMIN_KEY", "test-admin-key")
    return {"X-PSAT-Admin-Key": "test-admin-key"}


@pytest.fixture(autouse=True)
def _no_wire(monkeypatch):
    """``_current_head_block`` seeds the cursor over RPC; the offline suite is
    hermetic, so stub the one call these routes make."""
    from routers import monitored

    monkeypatch.setattr(monitored, "rpc_request", lambda *a, **k: hex(21_000_000))


def _post(api_client, protocol_id: int, admin_headers: dict[str, str], config: dict[str, Any] | None):
    return api_client.post(
        f"/api/protocols/{protocol_id}/monitoring",
        json={
            "address": ADDR,
            "chain": "ethereum",
            "contract_type": "proxy",
            "monitoring_config": config,
            "needs_polling": False,
            "is_active": True,
        },
        headers=admin_headers,
    )


def test_caller_enrolled_row_is_stamped_not_silently_proven_absent(api_client, db_session, protocol_id, admin_headers):
    """The positive case: a plain flags-only config — the exact shape the live
    fixtures and the Surface alert UI send — comes back carrying the provenance
    token, so no reader can take its missing ``tracked_topics`` for a finding."""
    resp = _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True, "watch_ownership": True})
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["enrollment_source"] == "surface_alert"
    assert body["monitoring_config"]["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN
    # The caller's own flags are untouched.
    assert body["monitoring_config"]["watch_upgrades"] is True
    assert body["monitoring_config"]["watch_ownership"] is True

    row = db_session.execute(
        select(MonitoredContract).where(MonitoredContract.id == uuid.UUID(body["id"]))
    ).scalar_one()
    db_session.refresh(row)
    assert row.monitoring_config["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN


def test_null_monitoring_config_is_stamped_too(api_client, protocol_id, admin_headers):
    """``monitoring_config`` is optional; the omitted case stored ``None``, which
    reads as proven-absent just as loudly as ``{}``."""
    resp = _post(api_client, protocol_id, admin_headers, None)
    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"] == {"tracking_plan_not_determined": CALLER_SUPPLIED_TRACKING_PLAN}


def test_a_forged_reason_token_cannot_survive_the_route(api_client, protocol_id, admin_headers):
    """A caller naming an analyzer reason gets the route's own token instead —
    the route owns this key. Overwrite rather than reject so that reading a
    stamped row and writing it back still works."""
    resp = _post(
        api_client,
        protocol_id,
        admin_headers,
        {"watch_pause": True, "tracking_plan_not_determined": "plan_not_readable"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"]["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN


def test_caller_supplied_tracked_topics_are_rejected(api_client, protocol_id, admin_headers):
    """``tracked_topics`` is an analysis output that feeds the live scan filter.
    422, not a silent drop — a discarded list would tell the caller those topics
    are being scanned."""
    resp = _post(api_client, protocol_id, admin_headers, {"tracked_topics": [{"topic0": TOPIC0}]})
    assert resp.status_code == 422, resp.text
    assert "tracked_topics" in resp.text


def test_patch_applies_the_same_two_rules(api_client, protocol_id, admin_headers):
    """PATCH replaces the config wholesale, so it is the same door."""
    created = _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True})
    assert created.status_code == 200, created.text
    contract_id = created.json()["id"]

    forged = api_client.patch(
        f"/api/monitored-contracts/{contract_id}",
        json={"monitoring_config": {"watch_pause": True, "tracking_plan_not_determined": "contract_not_analyzed"}},
        headers=admin_headers,
    )
    assert forged.status_code == 200, forged.text
    assert forged.json()["monitoring_config"]["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN
    assert forged.json()["monitoring_config"]["watch_pause"] is True

    topics = api_client.patch(
        f"/api/monitored-contracts/{contract_id}",
        json={"monitoring_config": {"tracked_topics": [{"topic0": TOPIC0}]}},
        headers=admin_headers,
    )
    assert topics.status_code == 422, topics.text


def test_rejected_topics_never_reach_the_live_scan_filter(api_client, db_session, protocol_id, admin_headers):
    """The consequence the rejection exists for, asserted end to end against the
    query the scanner actually runs (``_scan_topics_union``)."""
    from services.monitoring.unified_watcher import _scan_topics_union

    assert _post(api_client, protocol_id, admin_headers, {"tracked_topics": [{"topic0": TOPIC0}]}).status_code == 422
    assert _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True}).status_code == 200

    assert TOPIC0 not in _scan_topics_union(db_session)
