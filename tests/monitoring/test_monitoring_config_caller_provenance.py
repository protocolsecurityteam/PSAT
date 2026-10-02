"""A caller-authored ``monitoring_config`` may not read as an analysis result.

The routes stored caller dicts verbatim, so caller-enrolled rows looked like analyzer output. Analyzer-owned keys
the monitor acts on are also rejected: ``tracked_topics`` feeds the scan filter and ``polling_plan`` becomes
eth_call / eth_getStorageAt.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text

from db.models import Protocol
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


# Rejected, not dropped: a drop would tell the caller the value is acted on. ``scan_gaps`` survives config rebuilds, so
# a forged entry would outlive every enrollment.


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
