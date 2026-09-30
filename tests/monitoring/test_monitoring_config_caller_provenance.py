"""A caller-authored ``monitoring_config`` may not read as an analysis result.

The routes stored caller dicts verbatim, so caller-enrolled rows looked like analyzer output. Analyzer-owned keys
the monitor acts on are also rejected: ``tracked_topics`` feeds the scan filter and ``polling_plan`` becomes
eth_call / eth_getStorageAt.
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
SLOT = "0x" + "0" * 63 + "7"
_PLAN_ENTRY = {"kind": "storage_slot", "slot": SLOT, "field": "owner", "type_kind": "address"}


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
    resp = _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True, "watch_ownership": True})
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["enrollment_source"] == "surface_alert"
    assert body["monitoring_config"]["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN
    assert body["monitoring_config"]["watch_upgrades"] is True
    assert body["monitoring_config"]["watch_ownership"] is True

    row = db_session.execute(
        select(MonitoredContract).where(MonitoredContract.id == uuid.UUID(body["id"]))
    ).scalar_one()
    db_session.refresh(row)
    assert row.monitoring_config["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN


def test_null_monitoring_config_is_stamped_too(api_client, protocol_id, admin_headers):
    """``None`` would read as proven-absent like ``{}``."""
    resp = _post(api_client, protocol_id, admin_headers, None)
    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"] == {"tracking_plan_not_determined": CALLER_SUPPLIED_TRACKING_PLAN}


def test_a_forged_reason_token_cannot_survive_the_route(api_client, protocol_id, admin_headers):
    """Overwrite rather than reject, so a stamped row can be written back."""
    resp = _post(
        api_client,
        protocol_id,
        admin_headers,
        {"watch_pause": True, "tracking_plan_not_determined": "plan_not_readable"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"]["tracking_plan_not_determined"] == CALLER_SUPPLIED_TRACKING_PLAN


# Rejected, not dropped: a drop would tell the caller the value is acted on. ``scan_gaps`` survives config rebuilds, so
# a forged entry would outlive every enrollment.
@pytest.mark.parametrize(
    ("key", "payload"),
    [
        pytest.param("tracked_topics", [{"topic0": TOPIC0}], id="tracked_topics"),
        pytest.param("polling_plan", [_PLAN_ENTRY], id="polling_plan"),
        pytest.param(
            "scan_gaps",
            [{"from_block": 9_400_001, "to_block": 25_662_000, "reason": "unfloored_runaway"}],
            id="scan_gaps",
        ),
    ],
)
def test_caller_supplied_analyzer_owned_keys_are_rejected(api_client, protocol_id, admin_headers, key, payload):
    resp = _post(api_client, protocol_id, admin_headers, {key: payload})
    assert resp.status_code == 422, resp.text
    assert key in resp.text


def test_rejected_polling_plan_never_reaches_the_wire_or_the_event_stream(
    api_client, db_session, protocol_id, admin_headers
):
    """The poller would read a caller-chosen slot and mint a provenance-free event."""
    from services.monitoring.unified_watcher import _rpc_call_for_entry

    assert _rpc_call_for_entry(ADDR, _PLAN_ENTRY) == ("eth_getStorageAt", [ADDR, SLOT, "latest"])

    assert _post(api_client, protocol_id, admin_headers, {"polling_plan": [_PLAN_ENTRY]}).status_code == 422
    assert _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True}).status_code == 200

    rows = db_session.execute(select(MonitoredContract).where(MonitoredContract.protocol_id == protocol_id)).scalars()
    for row in rows:
        db_session.refresh(row)
        assert "polling_plan" not in (row.monitoring_config or {})


def test_the_watch_flags_stay_caller_settable(api_client, protocol_id, admin_headers):
    """``watch_*`` booleans only gate notification."""
    resp = _post(
        api_client,
        protocol_id,
        admin_headers,
        {"watch_upgrades": False, "watch_ownership": True, "watch_pause": True, "watch_roles": True},
    )
    assert resp.status_code == 200, resp.text
    config = resp.json()["monitoring_config"]
    assert config["watch_upgrades"] is False
    assert config["watch_ownership"] is True
    assert config["watch_pause"] is True
    assert config["watch_roles"] is True


def test_patch_applies_the_same_two_rules(api_client, protocol_id, admin_headers):
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

    for key, payload in (
        ("tracked_topics", [{"topic0": TOPIC0}]),
        ("polling_plan", [_PLAN_ENTRY]),
        ("scan_gaps", [{"from_block": 1, "to_block": 2, "reason": "unfloored_runaway"}]),
    ):
        resp = api_client.patch(
            f"/api/monitored-contracts/{contract_id}",
            json={"monitoring_config": {key: payload}},
            headers=admin_headers,
        )
        assert resp.status_code == 422, resp.text
        assert key in resp.text


def test_rejected_topics_never_reach_the_live_scan_filter(api_client, db_session, protocol_id, admin_headers):
    from services.monitoring.unified_watcher import _scan_topics_union

    assert _post(api_client, protocol_id, admin_headers, {"tracked_topics": [{"topic0": TOPIC0}]}).status_code == 422
    assert _post(api_client, protocol_id, admin_headers, {"watch_upgrades": True}).status_code == 200

    assert TOPIC0 not in _scan_topics_union(db_session)
