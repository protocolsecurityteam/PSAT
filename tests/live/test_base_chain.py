"""Base (chain 8453) second-chain live analogs — MULTICHAIN_INVARIANTS.md inv. 2/4/14.

These are the Phase-2 gate's L2 evidence: second-chain analogs of the
monitored-contract / enrollment / per-chain-observability live tests. They run
ONLY in the CI preview environment (never from a dev box, per the Phase-2
execution-environment rule) and are gated on the deployed server actually
supporting Base. On a mainnet-only deployment the whole module skips cleanly —
prod stays mainnet-only; only the Base-enabled preview sets
``PSAT_SUPPORTED_CHAIN_IDS=1,8453`` (see .github/workflows/pr.yml deploy step).

The deployed server exposes no allowlist read endpoint. The enrollment/analyze
edges now DO consult the allowlist (they reject an unsupported chain with HTTP
400), but that rejection can't be the primary gate: the module skip must fire
before the expensive company fixtures run, and it can't distinguish a real
"Base unsupported" 400 from an unrelated request error. The gate is therefore
explicit and up-front: the live-tests runner declares the deployed allowlist via
``PSAT_LIVE_SUPPORTED_CHAIN_IDS`` (mirror of the deploy's
``PSAT_SUPPORTED_CHAIN_IDS``). When that is unset we fall back to a positive
server probe — Base showing up in ``/api/health/monitoring`` chains means the
deployment is already exercising Base — and otherwise skip. The Base enrollment
fixture then treats a server-side unsupported-chain 400 as a clean skip too, a
defense-in-depth layer for a mainnet-only preview that slips past both.
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

# etherfi's canonical weETH deployment on Base. Stable (address, chain) identity —
# MonitoredContract rows leak across runs (no admin DELETE; the (address, chain)
# unique key makes the upsert idempotent), so this must never be randomized.
WEETH_BASE_ADDRESS = "0x04C0599Ae5A44757c0af6F9eC3b93da8976c150A"

_BASE_CONFIG = {"watch_upgrades": True, "watch_ownership": True}


def _declared_supported_chain_ids() -> set[int] | None:
    """Runner-side mirror of the deployed ``PSAT_SUPPORTED_CHAIN_IDS`` allowlist.

    Returns None when unset/blank so the caller can fall back to a server probe;
    otherwise the parsed decimal id set (non-integers ignored, like the backend's
    own parser in ``utils/chains.supported_chain_ids``)."""
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
    """Positive-only probe: does the deployed server already report Base under
    ``/api/health/monitoring`` chains? 503 is a valid body here (an unrelated
    daemon may be stale) — the per-chain ``chains`` list is present either way."""
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
    """Skip the whole module unless the deployment supports Base.

    Autouse + module-scoped and dependent only on the session ``live_client`` so
    it fires before the expensive company fixtures — a mainnet-only preview skips
    without ever triggering an analysis run.
    """
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
    """Upsert a Base-chain MonitoredContract for weETH under the test protocol.

    Mirrors ``test_monitored_contract_patch.monitored_contract`` but on
    ``chain='base'``; the (address, chain) uniqueness constraint makes re-runs
    idempotent since no admin DELETE exists.
    """
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
        # Defense in depth: a mainnet-only deployment now rejects a Base
        # enrollment with HTTP 400 (allowlist enforcement). If the up-front
        # module gate somehow passed on a Base-less deployment, skip cleanly
        # rather than fail — this module never asserts against a chain the
        # server has not enabled.
        resp = exc.response
        if resp is not None and resp.status_code == 400:
            pytest.skip(f"deployment rejected Base enrollment (allowlist): {resp.text[:200]}")
        raise


def test_base_monitored_contract_chain_roundtrips(base_monitored_contract):
    # The chain field must round-trip as 'base' — the whole point of the
    # second-chain data-model check (inv. 2).
    assert base_monitored_contract["chain"] == BASE_CHAIN
    assert base_monitored_contract["address"] == WEETH_BASE_ADDRESS.lower()
    assert base_monitored_contract["is_active"] is True
    assert base_monitored_contract["monitoring_config"] == _BASE_CONFIG


def test_base_monitored_contract_listed_by_chain(
    base_monitored_contract,
    live_client: LiveClient,
):
    # Read-back via the chain-filtered listing guards against a POST that echoes
    # 'base' without committing it under that chain.
    base_rows = live_client.list_monitored_contracts(chain=BASE_CHAIN)
    persisted = next((r for r in base_rows if r.get("id") == base_monitored_contract["id"]), None)
    assert persisted is not None, "base-enrolled contract missing from chain='base' listing"
    assert persisted["chain"] == BASE_CHAIN

    # The same row must NOT surface under the ethereum-filtered listing — chain is
    # a real filter dimension, not cosmetic.
    eth_rows = live_client.list_monitored_contracts(chain=ETHEREUM_CHAIN)
    assert base_monitored_contract["id"] not in {r.get("id") for r in eth_rows}


def test_same_address_distinct_across_chains(
    base_monitored_contract,
    company_protocol_id: int,
    live_client: LiveClient,
):
    """Cross-chain identity: the SAME address on 'ethereum' vs 'base' is two rows.

    A data-model assertion of the ``(address, chain)`` unique key — it does not
    claim weETH-on-Base exists at this address on mainnet; the ethereum row is a
    deliberate collision probe on a stable (address, chain) singleton.
    """
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
    # Same address string, different chain — the address matches, the identity does not.
    assert eth_row["address"] == base_monitored_contract["address"]


def test_fleet_exposes_base_by_chain(
    base_monitored_contract,
    live_client: LiveClient,
):
    """`/api/fleet` carries a per-chain breakdown (inv. 4, WI-D).

    Base was just enrolled active, so it must appear in the monitoring
    ``by_chain`` rollup; the indexer's ``by_chain`` is shape-checked tolerantly
    because Base may be indexer-idle in a fresh preview.
    """
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

    # Indexer rollup: present and list-shaped, tolerant of an idle (cursor-less) Base.
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
    """`/api/health/monitoring` carries a per-chain staleness breakdown (inv. 4, WI-D).

    Shape-tolerant: an idle chain must not fail the test, so Base is allowed to be
    absent or present-and-idle. When present, the documented per-chain shape must
    hold. 503 is an accepted status — the endpoint 503s when any daemon is stale
    while still returning the ``chains`` list.
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
