
from __future__ import annotations

from tests.live.conftest import LiveClient


def test_protocol_monitoring_listing_shape(company_protocol_id: int, live_client: LiveClient):
    rows = live_client.protocol_monitoring(company_protocol_id)
    assert isinstance(rows, list)
    for row in rows[:5]:
        for key in ("id", "address", "chain", "contract_type", "is_active"):
            assert key in row, f"protocol monitoring row missing {key!r}: {row}"


def test_protocol_subscriptions_listing_shape(company_protocol_id: int, live_client: LiveClient):
    subs = live_client.protocol_subscriptions(company_protocol_id)
    assert isinstance(subs, list)
    for sub in subs[:5]:
        for key in ("id", "protocol_id", "discord_webhook_url"):
            assert key in sub, f"protocol subscription missing {key!r}: {sub}"
        assert sub["protocol_id"] == company_protocol_id


def test_protocol_events_listing_shape(company_protocol_id: int, live_client: LiveClient):
    events = live_client.protocol_events(company_protocol_id, limit=20)
    assert isinstance(events, list)
    for ev in events[:5]:
        for key in ("id", "monitored_contract_id", "event_type", "detected_at"):
            assert key in ev, f"protocol event missing {key!r}: {ev}"


def test_protocol_tvl_shape(company_protocol_id: int, live_client: LiveClient):
    body = live_client.protocol_tvl(company_protocol_id, days=7)
    assert body["protocol_id"] == company_protocol_id
    assert isinstance(body.get("protocol_name"), str)
    assert "current" in body and isinstance(body["current"], dict)
    assert "history" in body and isinstance(body["history"], list)


def test_protocol_tvl_unknown_protocol_returns_404(live_client: LiveClient):
    r = live_client._session.get(
        live_client._url("/api/protocols/999999999/tvl"),
        timeout=15,
    )
    assert r.status_code == 404, f"unknown protocol id should 404, got {r.status_code}: {r.text[:200]}"
