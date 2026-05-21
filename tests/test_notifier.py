"""Integration tests for the Discord notification pipeline.

Tests the full chain: scan/poll detects upgrade → notifier queries subscriptions
→ Discord webhook POST. Also covers protocol subscription event_filter validation.

All tests run without live services — PostgreSQL for DB, mocked RPC
and mocked requests.post for Discord.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from conftest import ADDR, _add_proxy, _add_subscription, _make_log, _topic_for, requires_postgres

from db.models import ProxySubscription, ProxyUpgradeEvent
from services.discovery.upgrade_history import UPGRADED_TOPIC0
from services.monitoring.notifier import notify_upgrades
from services.monitoring.proxy_watcher import poll_for_upgrades, scan_for_upgrades

pytestmark = requires_postgres

# ---------------------------------------------------------------------------
# Helper: mock RPC that returns a single log
# ---------------------------------------------------------------------------


def _rpc_returning_log(log, latest_block=100):
    """Return an rpc_request side_effect that serves one log."""
    return lambda url, method, params: (
        hex(latest_block) if method == "eth_blockNumber" else [log] if method == "eth_getLogs" else None
    )


# ---------------------------------------------------------------------------
# Integration: scan/poll → notify
# ---------------------------------------------------------------------------


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_request")
def test_scan_triggers_discord_notification(mock_rpc, mock_discord, db_session):
    """Full chain: scanner detects Upgraded event → notifier POSTs to Discord."""
    mock_discord.return_value = MagicMock(ok=True)

    proxy = _add_proxy(db_session, ADDR(1), label="Aave Pool", last_known_impl=ADDR(10), last_scanned_block=90)
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/111/aaa")

    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0x" + "de" * 32)
    mock_rpc.side_effect = _rpc_returning_log(log)

    events = scan_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    mock_discord.assert_called_once()
    embed = mock_discord.call_args[1]["json"]["embeds"][0]
    assert "Aave Pool" in embed["title"]
    field_values = {f["name"]: f["value"] for f in embed["fields"]}
    assert ADDR(1) in field_values["Proxy"]
    assert ADDR(11).lower() in field_values["New Implementation"].lower()


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_batch_request")
def test_poll_triggers_discord_notification(mock_batch, mock_discord, db_session):
    """Poller detects implementation change via storage slot → Discord webhook."""
    mock_discord.return_value = MagicMock(ok=True)

    proxy = _add_proxy(db_session, ADDR(1), label="Compound cUSDC", last_known_impl=ADDR(10), needs_polling=True)
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/222/bbb")

    zero = "0x" + "0" * 64
    mock_batch.return_value = ["0x" + "0" * 24 + ADDR(11)[2:]] + [zero] * 7

    events = poll_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    mock_discord.assert_called_once()
    assert "Compound cUSDC" in mock_discord.call_args[1]["json"]["embeds"][0]["title"]


# ---------------------------------------------------------------------------
# Fan-out and targeting
# ---------------------------------------------------------------------------


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_request")
def test_multiple_subscribers_all_notified(mock_rpc, mock_discord, db_session):
    """Two webhooks on the same proxy — both get called."""
    mock_discord.return_value = MagicMock(ok=True)

    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), last_scanned_block=90)
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/1/alice")
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/2/bob")

    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0x" + "ff" * 32)
    mock_rpc.side_effect = _rpc_returning_log(log)

    events = scan_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    assert mock_discord.call_count == 2
    urls = {c[0][0] for c in mock_discord.call_args_list}
    assert urls == {"https://discord.com/api/webhooks/1/alice", "https://discord.com/api/webhooks/2/bob"}


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_request")
def test_only_subscribers_of_upgraded_proxy_notified(mock_rpc, mock_discord, db_session):
    """Proxy B's subscriber is not pinged when only proxy A upgrades."""
    mock_discord.return_value = MagicMock(ok=True)

    proxy_a = _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), last_scanned_block=90)
    proxy_b = _add_proxy(db_session, ADDR(2), last_known_impl=ADDR(20), last_scanned_block=90)
    _add_subscription(db_session, proxy_a, "https://discord.com/api/webhooks/a/sub")
    _add_subscription(db_session, proxy_b, "https://discord.com/api/webhooks/b/sub")

    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0x" + "aa" * 32)
    mock_rpc.side_effect = _rpc_returning_log(log)

    events = scan_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    assert mock_discord.call_count == 1
    assert mock_discord.call_args[0][0] == "https://discord.com/api/webhooks/a/sub"


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_request")
def test_webhook_failure_does_not_crash_scan_loop(mock_rpc, mock_discord, db_session):
    """Discord down — event still persisted, no crash."""
    mock_discord.side_effect = Exception("Discord is down")

    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), last_scanned_block=90)
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/broken/url")

    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0x" + "cc" * 32)
    mock_rpc.side_effect = _rpc_returning_log(log)

    events = scan_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    db_session.refresh(proxy)
    assert proxy.last_known_implementation == ADDR(11).lower()


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_request")
def test_one_bad_webhook_doesnt_block_others(mock_rpc, mock_discord, db_session):
    """First webhook fails, second still gets called."""
    call_log = []

    def discord_side_effect(url, **kwargs):
        call_log.append(url)
        if "broken" in url:
            raise Exception("timeout")
        return MagicMock(ok=True)

    mock_discord.side_effect = discord_side_effect

    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10), last_scanned_block=90)
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/broken/one")
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/good/two")

    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(95), tx="0x" + "dd" * 32)
    mock_rpc.side_effect = _rpc_returning_log(log)

    events = scan_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    assert len(call_log) == 2
    assert "https://discord.com/api/webhooks/good/two" in call_log


# ---------------------------------------------------------------------------
# Edge case: null webhook URL
# ---------------------------------------------------------------------------


@patch("services.monitoring.notifier.requests.post")
def test_subscription_without_webhook_url_is_skipped(mock_discord, db_session):
    """A subscription with discord_webhook_url=None is not called."""
    proxy = _add_proxy(db_session, ADDR(1), last_known_impl=ADDR(10))
    sub = ProxySubscription(id=uuid.uuid4(), watched_proxy_id=proxy.id, discord_webhook_url=None, label="no-url")
    db_session.add(sub)
    db_session.commit()

    evt = ProxyUpgradeEvent(
        id=uuid.uuid4(),
        watched_proxy_id=proxy.id,
        block_number=100,
        tx_hash="0x" + "ab" * 32,
        old_implementation=ADDR(10),
        new_implementation=ADDR(11),
        event_type="upgraded",
    )
    evt.watched_proxy = proxy
    db_session.add(evt)
    db_session.commit()

    notify_upgrades(db_session, [evt])
    mock_discord.assert_not_called()


# ---------------------------------------------------------------------------
# Embed format
# ---------------------------------------------------------------------------


@patch("services.monitoring.notifier.requests.post")
@patch("services.monitoring.proxy_watcher.rpc_request")
def test_embed_format_complete(mock_rpc, mock_discord, db_session):
    """Discord embed has all expected fields with correct values."""
    mock_discord.return_value = MagicMock(ok=True)

    proxy = _add_proxy(db_session, ADDR(1), label="Lido stETH", last_known_impl=ADDR(10), last_scanned_block=90)
    _add_subscription(db_session, proxy, "https://discord.com/api/webhooks/1/x")

    tx_hash = "0x" + "ef" * 32
    log = _make_log(ADDR(1), UPGRADED_TOPIC0, _topic_for(ADDR(11)), block=hex(12345), tx=tx_hash)
    mock_rpc.side_effect = _rpc_returning_log(log, latest_block=13000)

    events = scan_for_upgrades(db_session, "http://localhost:8545")
    notify_upgrades(db_session, events)

    embed = mock_discord.call_args[1]["json"]["embeds"][0]
    field_map = {f["name"]: f["value"] for f in embed["fields"]}

    assert "Lido stETH" in embed["title"]
    assert embed["color"] == 0xFF9900
    assert ADDR(1) in field_map["Proxy"]
    assert "ethereum" == field_map["Chain"]
    assert "upgraded" == field_map["Event"]
    assert ADDR(11).lower() in field_map["New Implementation"].lower()
    assert ADDR(10) in field_map["Old Implementation"]
    assert "12345" == field_map["Block"]
    assert tx_hash in field_map["Tx"]


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
    assert body["monitoring_config"] == new_config
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
