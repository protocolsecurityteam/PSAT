from __future__ import annotations

from typing import Any

import pytest
import requests

from tests.live.conftest import LiveClient

TEST_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/0/psat-live-test-protocol-never-delivered"
# ``sanitize_url`` masks the token segment on read.
TEST_DISCORD_WEBHOOK_REDACTED = "https://discord.com/api/webhooks/0/<redacted>"


@pytest.fixture
def protocol_subscription(
    company_protocol_id: int,
    live_client: LiveClient,
    request,
) -> dict[str, Any]:
    # The endpoint doesn't dedupe, so rows would accumulate.
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


def test_protocol_subscription_created(protocol_subscription, company_protocol_id: int, live_client: LiveClient):
    assert protocol_subscription["protocol_id"] == company_protocol_id
    assert protocol_subscription["discord_webhook_url"] == TEST_DISCORD_WEBHOOK_REDACTED
    assert protocol_subscription["label"] == "psat-live-test"
    assert protocol_subscription.get("event_filter") == {"event_types": ["upgraded"]}

    subs = live_client.protocol_subscriptions(company_protocol_id)
    assert protocol_subscription["id"] in {s["id"] for s in subs}


def test_protocol_subscription_delete_roundtrip(
    company_protocol_id: int,
    live_client: LiveClient,
):
    payload = {"discord_webhook_url": TEST_DISCORD_WEBHOOK, "label": "psat-live-test-ephemeral"}
    sub = live_client.subscribe_protocol(company_protocol_id, payload)
    live_client.delete_protocol_subscription(sub["id"])

    remaining = live_client.protocol_subscriptions(company_protocol_id)
    assert sub["id"] not in {s["id"] for s in remaining}


def test_re_enroll_protocol(company_protocol_id: int, live_client: LiveClient):
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


@pytest.mark.parametrize(
    ("path", "request_kwargs", "timeout"),
    [
        pytest.param(
            "/api/protocols/999999999/subscribe",
            {"json": {"discord_webhook_url": TEST_DISCORD_WEBHOOK}},
            15,
            id="subscribe",
        ),
        pytest.param("/api/protocols/999999999/re-enroll", {"params": {"chain": "ethereum"}}, 30, id="re_enroll"),
    ],
)
def test_unknown_protocol_404(live_client: LiveClient, path, request_kwargs, timeout):
    r = live_client._session.post(live_client._url(path), timeout=timeout, **request_kwargs)
    assert r.status_code == 404, f"{path} on unknown protocol should 404, got {r.status_code}"
