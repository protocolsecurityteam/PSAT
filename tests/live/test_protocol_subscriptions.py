"""Protocol-level subscription mutations: create/delete roundtrip + admin re-enroll."""

from __future__ import annotations

from typing import Any

import pytest
import requests

from tests.live.conftest import LiveClient

TEST_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/0/psat-live-test-protocol-never-delivered"
# The subscriptions API runs the webhook through ``sanitize_url`` on read, so the
# token segment comes back masked while the id segment survives.
TEST_DISCORD_WEBHOOK_REDACTED = "https://discord.com/api/webhooks/0/<redacted>"


@pytest.fixture
def protocol_subscription(
    company_protocol_id: int,
    live_client: LiveClient,
    request,
) -> dict[str, Any]:
    # Function-scoped: the endpoint doesn't dedupe on (protocol_id, webhook_url) so rows would accumulate.
    payload = {
        "discord_webhook_url": TEST_DISCORD_WEBHOOK,
        "label": "psat-live-test",
        "event_filter": {"event_types": ["upgraded"]},
    }
    sub = live_client.subscribe_protocol(company_protocol_id, payload)
    assert sub.get("id"), f"subscribe_protocol response missing id: {sub}"

    def _cleanup():
        try:
            live_client.delete_protocol_subscription(sub["id"])
        except requests.HTTPError:
            pass

    request.addfinalizer(_cleanup)
    return sub


def test_protocol_subscription_created(protocol_subscription, company_protocol_id: int):
    assert protocol_subscription["protocol_id"] == company_protocol_id
    assert protocol_subscription["discord_webhook_url"] == TEST_DISCORD_WEBHOOK_REDACTED
    assert protocol_subscription["label"] == "psat-live-test"
    # event_filter must roundtrip verbatim; the request validator could mangle it.
    assert protocol_subscription.get("event_filter") == {"event_types": ["upgraded"]}


def test_protocol_subscription_listed(
    protocol_subscription,
    company_protocol_id: int,
    live_client: LiveClient,
):
    subs = live_client.protocol_subscriptions(company_protocol_id)
    ids = {s["id"] for s in subs}
    assert protocol_subscription["id"] in ids


def test_protocol_subscription_delete_roundtrip(
    company_protocol_id: int,
    live_client: LiveClient,
):
    # Not the fixture — avoids racing the finalizer.
    payload = {"discord_webhook_url": TEST_DISCORD_WEBHOOK, "label": "psat-live-test-ephemeral"}
    sub = live_client.subscribe_protocol(company_protocol_id, payload)
    live_client.delete_protocol_subscription(sub["id"])

    remaining = live_client.protocol_subscriptions(company_protocol_id)
    assert sub["id"] not in {s["id"] for s in remaining}


def test_protocol_subscribe_unknown_protocol_404(live_client: LiveClient):
    r = live_client._session.post(
        live_client._url("/api/protocols/999999999/subscribe"),
        json={"discord_webhook_url": TEST_DISCORD_WEBHOOK},
        timeout=15,
    )
    assert r.status_code == 404, f"subscribing to unknown protocol should 404, got {r.status_code}"


def test_re_enroll_protocol(company_protocol_id: int, live_client: LiveClient):
    """Shape-only: exact contract counts depend on live-RPC classification. Skip on 502/503."""
    try:
        body = live_client.re_enroll_protocol(company_protocol_id, chain="ethereum")
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code in (502, 503):
            pytest.skip(
                f"re-enroll failed with {exc.response.status_code} (RPC reachability): {exc.response.text[:200]}"
            )
        raise
    assert body["status"] == "enrolled"
    assert body["protocol_id"] == company_protocol_id
    assert isinstance(body.get("contracts"), list)
    assert isinstance(body.get("contracts_enrolled"), int)


def test_re_enroll_unknown_protocol_404(live_client: LiveClient):
    r = live_client._session.post(
        live_client._url("/api/protocols/999999999/re-enroll"),
        params={"chain": "ethereum"},
        timeout=30,
    )
    assert r.status_code == 404, f"re-enroll on unknown protocol should 404, got {r.status_code}"
