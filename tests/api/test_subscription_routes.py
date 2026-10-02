from __future__ import annotations

import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from tests.conftest import requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def api_client(db_session):

    @contextmanager
    def fake_session_local():
        yield db_session

    with patch("routers.deps.SessionLocal", fake_session_local):
        from fastapi.testclient import TestClient

        import api

        yield TestClient(api.app)


def _create_protocol(session, name="__test_proto__"):
    from db.models import Protocol

    proto = Protocol(name=name)
    session.add(proto)
    session.commit()
    session.refresh(proto)
    return proto


@pytest.mark.parametrize(
    ("name", "body", "expected_filter"),
    [
        pytest.param(
            "__test_proto__",
            {"event_filter": {"event_types": ["upgraded", "paused"]}},
            {"event_types": ["upgraded", "paused"]},
            id="valid_filter",
        ),
        pytest.param("__test_no_filter__", {}, None, id="no_filter"),
        # Technically valid: subscribe to nothing.
        pytest.param(
            "__test_empty_filter__", {"event_filter": {"event_types": []}}, {"event_types": []}, id="empty_list"
        ),
    ],
)
def test_subscribe_accepts_event_filter(api_client, db_session, name, body, expected_filter):
    proto = _create_protocol(db_session, name=name)
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={"discord_webhook_url": "https://discord.com/api/webhooks/1/abc", **body},
    )
    assert resp.status_code == 200
    assert resp.json()["event_filter"] == expected_filter


def _create_monitored_contract(session, address="0x" + "a1" * 20, protocol_id=None):
    from db.models import MonitoredContract

    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address.lower(),
        chain="ethereum",
        contract_type="proxy",
        monitoring_config={"watch_upgrades": True, "watch_ownership": True},
        last_known_state={},
        last_scanned_block=100,
        needs_polling=False,
        is_active=True,
        enrollment_source="manual",
        protocol_id=protocol_id,
    )
    session.add(mc)
    session.commit()
    session.refresh(mc)
    return mc


def test_patch_404_for_missing_contract(api_client):
    resp = api_client.patch(
        f"/api/monitored-contracts/{uuid.uuid4()}",
        json={"is_active": False},
    )
    assert resp.status_code == 404


@patch("services.monitoring.enrollment.enroll_protocol_contracts")
def test_re_enroll_calls_enrollment(mock_enroll, api_client, db_session):
    proto = _create_protocol(db_session, name="__test_reenroll__")

    mc = _create_monitored_contract(
        db_session,
        address="0x" + "d4" * 20,
        protocol_id=proto.id,
    )
    mock_enroll.return_value = [mc]

    resp = api_client.post(f"/api/protocols/{proto.id}/re-enroll")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "enrolled"
    assert body["protocol_id"] == proto.id
    assert body["contracts_enrolled"] == 1
    assert len(body["contracts"]) == 1
    assert body["contracts"][0]["address"] == mc.address

    mock_enroll.assert_called_once()
    call_args = mock_enroll.call_args
    assert call_args[0][1] == proto.id  # protocol_id
