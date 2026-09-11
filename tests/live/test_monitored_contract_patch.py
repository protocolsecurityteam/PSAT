"""PATCH /api/monitored-contracts/{id}. Row created via POST /api/protocols/{id}/monitoring."""

from __future__ import annotations

from typing import Any

import pytest

from tests.live.conftest import LiveClient

# Distinct from other live tests so concurrent runs don't collide on (address, chain).
USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

_INITIAL_CONFIG = {"watch_upgrades": True, "watch_ownership": True}


@pytest.fixture(scope="module")
def monitored_contract(
    company_protocol_id: int,
    live_client: LiveClient,
) -> dict[str, Any]:
    """Upsert a MonitoredContract for USDC under the test protocol.

    No admin DELETE exists for /api/monitored-contracts, so this fixture
    relies on the (address, chain) uniqueness constraint to make re-runs
    idempotent — the POST handler upserts when a row already exists.
    """
    payload = {
        "address": USDC_ADDRESS.lower(),
        "chain": "ethereum",
        "contract_type": "proxy",
        "monitoring_config": _INITIAL_CONFIG,
        "needs_polling": False,
        "is_active": True,
    }
    return live_client.upsert_protocol_monitoring(company_protocol_id, payload)


def _caller_keys(config: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """The caller's own keys out of a stored config.

    Compared as a subset rather than for equality because the route stamps
    ``observation_plan_not_determined="config_supplied_by_caller"`` into every
    caller-supplied config (``routers/monitored._stamp_caller_supplied``): a
    config no analyzer produced must not read as "the tracking plan was read and
    named nothing", which is what the absent key means on the auto-enrollment
    path. The caller's keys still round-trip untouched.
    """
    return {key: config.get(key) for key in expected}


def test_monitored_contract_initial_state(monitored_contract):
    assert monitored_contract["is_active"] is True
    assert _caller_keys(monitored_contract["monitoring_config"], _INITIAL_CONFIG) == _INITIAL_CONFIG
    assert monitored_contract["monitoring_config"]["observation_plan_not_determined"] == "config_supplied_by_caller"
    # Surface alert is the enrollment source set by routers/monitored.py for
    # ad-hoc POST /api/protocols/{id}/monitoring inserts.
    assert monitored_contract["enrollment_source"] == "surface_alert"


def test_monitored_contract_patch_monitoring_config(
    monitored_contract,
    live_client: LiveClient,
):
    new_config = {"watch_upgrades": False, "watch_ownership": True, "extra_flag": "test-marker"}
    updated = live_client.patch_monitored_contract(monitored_contract["id"], {"monitoring_config": new_config})
    assert _caller_keys(updated["monitoring_config"], new_config) == new_config

    # Read-back via listing guards against a PATCH that echoes without committing.
    rows = live_client.list_monitored_contracts(chain="ethereum")
    persisted = next((r for r in rows if r.get("id") == monitored_contract["id"]), None)
    assert persisted is not None, f"PATCH'd row {monitored_contract['id']} disappeared from listing"
    assert _caller_keys(persisted["monitoring_config"], new_config) == new_config
    assert persisted["monitoring_config"]["observation_plan_not_determined"] == "config_supplied_by_caller"


def test_monitored_contract_patch_toggle_active(
    monitored_contract,
    live_client: LiveClient,
):
    # Toggle off then back on so later tests don't observe an inactive row.
    off = live_client.patch_monitored_contract(monitored_contract["id"], {"is_active": False})
    assert off["is_active"] is False

    on = live_client.patch_monitored_contract(monitored_contract["id"], {"is_active": True})
    assert on["is_active"] is True


def test_monitored_contract_patch_needs_polling(
    monitored_contract,
    live_client: LiveClient,
):
    original = monitored_contract.get("needs_polling", False)
    flipped = live_client.patch_monitored_contract(monitored_contract["id"], {"needs_polling": not original})
    assert flipped["needs_polling"] is (not original)
    live_client.patch_monitored_contract(monitored_contract["id"], {"needs_polling": original})


def test_monitored_contract_patch_unknown_id_404(live_client: LiveClient):
    # Valid UUID format (handler casts via uuid.UUID — bad format would 422, not 404).
    missing_uuid = "00000000-0000-0000-0000-000000000000"
    r = live_client._session.patch(
        live_client._url(f"/api/monitored-contracts/{missing_uuid}"),
        json={"is_active": False},
        timeout=15,
    )
    assert r.status_code == 404, f"unknown contract id should 404, got {r.status_code}: {r.text[:200]}"
