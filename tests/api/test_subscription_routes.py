"""Integration tests for the protocol-subscription and monitored-contract routes.

Covers protocol subscription event_filter validation and the monitored-contract
PATCH / re-enroll endpoints.

All tests run without live services — PostgreSQL for the DB, the enrollment call
patched.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from tests.conftest import requires_postgres

pytestmark = requires_postgres


# ---------------------------------------------------------------------------
# Protocol subscription event_filter validation
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(db_session):
    """FastAPI test client wired to the in-memory SQLite session."""

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


def test_subscribe_valid_event_filter(api_client, db_session):
    """A well-formed event_filter is accepted."""
    proto = _create_protocol(db_session)
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={
            "discord_webhook_url": "https://discord.com/api/webhooks/1/abc",
            "event_filter": {"event_types": ["upgraded", "paused"]},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["event_filter"] == {"event_types": ["upgraded", "paused"]}


def test_subscribe_no_event_filter(api_client, db_session):
    """Omitting event_filter is valid (subscribe to everything)."""
    proto = _create_protocol(db_session, name="__test_no_filter__")
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={"discord_webhook_url": "https://discord.com/api/webhooks/2/def"},
    )
    assert resp.status_code == 200
    assert resp.json()["event_filter"] is None


def test_subscribe_string_event_types_rejected(api_client, db_session):
    """event_types as string instead of list is rejected."""
    proto = _create_protocol(db_session, name="__test_str_filter__")
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={
            "discord_webhook_url": "https://discord.com/api/webhooks/3/ghi",
            "event_filter": {"event_types": "upgraded"},
        },
    )
    assert resp.status_code == 422


def test_subscribe_typo_field_rejected(api_client, db_session):
    """event_filter with wrong key (no 'event_types') is rejected."""
    proto = _create_protocol(db_session, name="__test_typo_filter__")
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={
            "discord_webhook_url": "https://discord.com/api/webhooks/4/jkl",
            "event_filter": {"typo_field": ["upgraded"]},
        },
    )
    assert resp.status_code == 422


def test_subscribe_unknown_event_type_rejected(api_client, db_session):
    """An unrecognized event type in the list is rejected."""
    proto = _create_protocol(db_session, name="__test_bad_type__")
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={
            "discord_webhook_url": "https://discord.com/api/webhooks/5/mno",
            "event_filter": {"event_types": ["upgraded", "nonexistent_event"]},
        },
    )
    assert resp.status_code == 422


def test_subscribe_empty_event_types_list_accepted(api_client, db_session):
    """An empty event_types list is technically valid (subscribe to nothing)."""
    proto = _create_protocol(db_session, name="__test_empty_filter__")
    resp = api_client.post(
        f"/api/protocols/{proto.id}/subscribe",
        json={
            "discord_webhook_url": "https://discord.com/api/webhooks/6/pqr",
            "event_filter": {"event_types": []},
        },
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# PATCH /api/monitored-contracts/{id}
# ---------------------------------------------------------------------------


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


def test_patch_monitoring_config(api_client, db_session):
    """PATCH updates monitoring_config while leaving other fields untouched."""
    mc = _create_monitored_contract(db_session)
    new_config = {"watch_upgrades": False, "watch_ownership": True, "watch_pause": True}
    resp = api_client.patch(
        f"/api/monitored-contracts/{mc.id}",
        json={"monitoring_config": new_config},
    )
    assert resp.status_code == 200
    body = resp.json()
    # The caller's keys round-trip; the route additionally stamps
    # ``tracking_plan_not_determined`` so a caller-authored config cannot read as
    # a tracking plan the analysis produced (routers/monitored, and
    # tests/test_monitoring_config_caller_provenance.py for that rule itself).
    assert {k: body["monitoring_config"].get(k) for k in new_config} == new_config
    assert body["monitoring_config"]["tracking_plan_not_determined"] == "config_supplied_by_caller"
    assert body["is_active"] is True  # unchanged
    assert body["needs_polling"] is False  # unchanged


def test_patch_is_active(api_client, db_session):
    """PATCH can deactivate monitoring."""
    mc = _create_monitored_contract(db_session, address="0x" + "b2" * 20)
    resp = api_client.patch(
        f"/api/monitored-contracts/{mc.id}",
        json={"is_active": False},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


def test_patch_needs_polling(api_client, db_session):
    """PATCH can enable polling."""
    mc = _create_monitored_contract(db_session, address="0x" + "c3" * 20)
    resp = api_client.patch(
        f"/api/monitored-contracts/{mc.id}",
        json={"needs_polling": True},
    )
    assert resp.status_code == 200
    assert resp.json()["needs_polling"] is True


def test_patch_404_for_missing_contract(api_client):
    """PATCH returns 404 for nonexistent contract."""
    resp = api_client.patch(
        f"/api/monitored-contracts/{uuid.uuid4()}",
        json={"is_active": False},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/protocols/{id}/re-enroll
# ---------------------------------------------------------------------------


def test_re_enroll_404_for_missing_protocol(api_client):
    """Re-enroll on nonexistent protocol returns 404."""
    resp = api_client.post("/api/protocols/999999/re-enroll")
    assert resp.status_code == 404


@patch("services.monitoring.enrollment.enroll_protocol_contracts")
def test_re_enroll_calls_enrollment(mock_enroll, api_client, db_session):
    """Re-enroll calls enroll_protocol_contracts and returns result."""
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
