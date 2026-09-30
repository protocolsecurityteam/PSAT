"""Base (chain 8453) second-chain live analogs.

Phase-2 gate L2 evidence; runs ONLY in the CI preview (never a dev box) and skips the whole module on a
mainnet-only deployment (prod stays mainnet-only; only the preview sets ``PSAT_SUPPORTED_CHAIN_IDS=1,8453``, see
pr.yml).
The server exposes no allowlist endpoint and a 400 can't be told from an unrelated error, so the gate is up-front:
``PSAT_LIVE_SUPPORTED_CHAIN_IDS`` (mirror of the deploy's), else a positive probe for Base in ``/api/health/monitoring``
chains. The enrollment fixture also skips on an unsupported-chain 400 as defense in depth.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import requests

from tests.live.conftest import LiveClient

BASE_CHAIN = "base"
BASE_CHAIN_ID = 8453
ETHEREUM_CHAIN = "ethereum"

# MonitoredContract rows leak across runs, so the (address, chain) identity must stay stable.
WEETH_BASE_ADDRESS = "0x04C0599Ae5A44757c0af6F9eC3b93da8976c150A"

_BASE_CONFIG = {"watch_upgrades": True, "watch_ownership": True}


def _declared_supported_chain_ids() -> set[int] | None:
    raw = os.environ.get("PSAT_LIVE_SUPPORTED_CHAIN_IDS")
    if raw is None or not raw.strip():
        return None
    ids: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if token.isdigit():
            ids.add(int(token))
    return ids


def _base_present_in_health_chains(live_client: LiveClient) -> bool:
    """503 is a valid body when an unrelated daemon is stale."""
    try:
        r = live_client._session.get(live_client._url("/api/health/monitoring"), timeout=15)
    except Exception:
        return False
    if r.status_code not in (200, 503):
        return False
    chains = (r.json() or {}).get("chains") or []
    return any(c.get("chain_id") == BASE_CHAIN_ID or c.get("name") == BASE_CHAIN for c in chains)


@pytest.fixture(scope="module", autouse=True)
def _require_base_enabled(live_client: LiveClient):
    """Depends only on ``live_client`` so it fires before the expensive company fixtures."""
    declared = _declared_supported_chain_ids()
    if declared is not None:
        if BASE_CHAIN_ID not in declared:
            pytest.skip(
                f"Base ({BASE_CHAIN_ID}) absent from PSAT_LIVE_SUPPORTED_CHAIN_IDS={sorted(declared)} "
                "— mainnet-only deployment"
            )
        return
    if not _base_present_in_health_chains(live_client):
        pytest.skip(
            "Base support unconfirmed. Set PSAT_LIVE_SUPPORTED_CHAIN_IDS=1,8453 on the live-tests "
            "job for a Base-enabled preview (mirror of the deploy's PSAT_SUPPORTED_CHAIN_IDS), or "
            "run against a deployment already reporting Base under /api/health/monitoring chains."
        )


@pytest.fixture(scope="module")
def base_monitored_contract(
    company_protocol_id: int,
    live_client: LiveClient,
) -> dict[str, Any]:
    payload = {
        "address": WEETH_BASE_ADDRESS.lower(),
        "chain": BASE_CHAIN,
        "contract_type": "proxy",
        "monitoring_config": _BASE_CONFIG,
        "needs_polling": False,
        "is_active": True,
    }
    try:
        return live_client.upsert_protocol_monitoring(company_protocol_id, payload)
    except requests.HTTPError as exc:
        resp = exc.response
        if resp is not None and resp.status_code == 400:
            pytest.skip(f"deployment rejected Base enrollment (allowlist): {resp.text[:200]}")
        raise


def test_base_monitored_contract_chain_roundtrips(base_monitored_contract):
    # The chain field must round-trip as 'base' — the whole point of the
    # second-chain data-model check.
    assert base_monitored_contract["chain"] == BASE_CHAIN
    assert base_monitored_contract["address"] == WEETH_BASE_ADDRESS.lower()
    assert base_monitored_contract["is_active"] is True
    # The route stamps ``tracking_plan_not_determined`` into caller configs, so compare the caller's keys as a subset.
    stored = base_monitored_contract["monitoring_config"]
    assert {k: stored.get(k) for k in _BASE_CONFIG} == _BASE_CONFIG
    assert stored["tracking_plan_not_determined"] == "config_supplied_by_caller"


def test_base_monitored_contract_listed_by_chain(
    base_monitored_contract,
    live_client: LiveClient,
):
    # Guards against a POST that echoes 'base' without committing it.
    base_rows = live_client.list_monitored_contracts(chain=BASE_CHAIN)
    persisted = next((r for r in base_rows if r.get("id") == base_monitored_contract["id"]), None)
    assert persisted is not None, "base-enrolled contract missing from chain='base' listing"
    assert persisted["chain"] == BASE_CHAIN

    eth_rows = live_client.list_monitored_contracts(chain=ETHEREUM_CHAIN)
    assert base_monitored_contract["id"] not in {r.get("id") for r in eth_rows}


def test_same_address_distinct_across_chains(
    base_monitored_contract,
    company_protocol_id: int,
    live_client: LiveClient,
):
    eth_payload = {
        "address": WEETH_BASE_ADDRESS.lower(),
        "chain": ETHEREUM_CHAIN,
        "contract_type": "proxy",
        "monitoring_config": _BASE_CONFIG,
        "needs_polling": False,
        "is_active": True,
    }
    eth_row = live_client.upsert_protocol_monitoring(company_protocol_id, eth_payload)

    assert eth_row["id"] != base_monitored_contract["id"], (
        "same address on two chains collapsed to a single monitored row"
    )
    assert eth_row["chain"] == ETHEREUM_CHAIN
    assert base_monitored_contract["chain"] == BASE_CHAIN
    assert eth_row["address"] == base_monitored_contract["address"]


def test_fleet_exposes_base_by_chain(
    base_monitored_contract,
    live_client: LiveClient,
):
    """`/api/fleet` carries a per-chain breakdown (WI-D); the indexer ``by_chain`` is checked tolerantly (Base
    may be idle)."""
    r = live_client._session.get(live_client._url("/api/fleet"), timeout=30)
    r.raise_for_status()
    body = r.json()

    watchers = body.get("watchers") or {}
    by_chain = watchers.get("by_chain")
    assert isinstance(by_chain, list), "fleet watchers.by_chain missing or not a list"

    base_entry = next(
        (e for e in by_chain if e.get("chain") == BASE_CHAIN or e.get("chain_id") == BASE_CHAIN_ID),
        None,
    )
    assert base_entry is not None, f"base absent from fleet watchers.by_chain: {by_chain}"
    assert base_entry.get("monitored_contracts", 0) >= 1

    indexer = next(
        (d for d in body.get("daemons", []) if isinstance(d.get("work"), dict) and "by_chain" in d["work"]),
        None,
    )
    if indexer is not None:
        assert isinstance(indexer["work"]["by_chain"], list)


def test_monitoring_health_exposes_chains(
    base_monitored_contract,
    live_client: LiveClient,
):
    """`/api/health/monitoring` carries per-chain staleness (WI-D).

    Shape-tolerant: Base may be absent or idle; 503 is accepted (returned when any daemon is stale, still with
    ``chains``).
    """
    r = live_client._session.get(live_client._url("/api/health/monitoring"), timeout=15)
    assert r.status_code in (200, 503), f"unexpected /api/health/monitoring status {r.status_code}: {r.text[:200]}"
    body = r.json()

    chains = body.get("chains")
    assert isinstance(chains, list), "monitoring health missing chains list"

    base_entry = next(
        (c for c in chains if c.get("chain_id") == BASE_CHAIN_ID or c.get("name") == BASE_CHAIN),
        None,
    )
    if base_entry is not None:
        for key in ("chain_id", "name", "indexer", "monitoring", "stale"):
            assert key in base_entry, f"base health entry missing '{key}': {base_entry}"
