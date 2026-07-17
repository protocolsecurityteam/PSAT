"""M1.1 item 4 — second-chain threading proof for the monitoring daemons.

Every existing monitoring test drives chain-``ethereum`` (chain 1) inputs and so
only proves mainnet stays unchanged. These tests drive a chain-``base`` (8453)
input through each threaded path and assert the *base* eRPC route / chain id is
what actually reaches the wire — the thing M1.1 makes true:

  - ``poll_for_state_changes`` sends a base contract's batch to the base RPC URL
  - ``scan_for_events`` reads head + getLogs for a base cohort on the base RPC URL
  - ``refresh_contract_balances`` passes chain_id 8453 to the Etherscan balance calls
  - ``enroll_protocol_contracts`` keys a base proxy's WatchedProxy on ``chain="base"``
    and seeds its block from the base RPC

Only the wire is stubbed (``rpc_batch_request`` / ``rpc_request`` / the Etherscan
balance helpers) — never the production classes — matching the hermetic offline
suite.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from db.models import (
    Contract,
    MonitoredContract,
    Protocol,
    WatchedProxy,
)

ERPC_BASE = "https://erpc.test"
BASE_URL = f"{ERPC_BASE}/main/evm/8453"  # base = chain id 8453
MAINNET_SEED = "http://mainnet-seed"


def _addr(prefix: str) -> str:
    return "0x" + (prefix * 40)[:40]


# ---------------------------------------------------------------------------
# chain_rpc helper
# ---------------------------------------------------------------------------


def test_rpc_for_chain_mainnet_verbatim_second_chain_resolves(monkeypatch):
    from services.monitoring.chain_rpc import chain_id_for, rpc_for_chain

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)

    # Mainnet keeps the incoming URL byte-for-byte (chain-1 behavior unchanged).
    assert rpc_for_chain("ethereum", MAINNET_SEED) == MAINNET_SEED
    assert chain_id_for("ethereum") == 1

    # A second chain resolves its OWN eRPC route from the registry.
    assert rpc_for_chain("base", MAINNET_SEED) == BASE_URL
    assert chain_id_for("base") == 8453


# ---------------------------------------------------------------------------
# poll_for_state_changes — per-chain RPC selection
# ---------------------------------------------------------------------------


def test_poll_sends_base_contract_to_base_rpc(db_session, monkeypatch):
    from services.monitoring.unified_watcher import poll_for_state_changes

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)

    plan = [{"field": "trackedAddr", "kind": "getter_call", "selector": "0xaa000001", "type_kind": "address"}]
    db_session.add(
        MonitoredContract(
            id=uuid.uuid4(),
            address=_addr("b"),
            chain="base",
            contract_type="regular",
            monitoring_config={"polling_plan": plan},
            last_known_state={},
            last_scanned_block=0,
            needs_polling=True,
            is_active=True,
        )
    )
    db_session.commit()

    seen_urls: list[str] = []

    def _mock(url, calls):
        seen_urls.append(url)
        return [None] * len(calls)

    monkeypatch.setattr("services.monitoring.unified_watcher.rpc_batch_request", _mock)
    poll_for_state_changes(db_session, MAINNET_SEED)

    assert seen_urls == [BASE_URL]


# ---------------------------------------------------------------------------
# scan_for_events — per-chain RPC selection (head read + getLogs)
# ---------------------------------------------------------------------------


def test_scan_reads_base_cohort_on_base_rpc(db_session, monkeypatch):
    from services.monitoring.unified_watcher import scan_for_events

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)

    db_session.add(
        MonitoredContract(
            id=uuid.uuid4(),
            address=_addr("c"),
            chain="base",
            contract_type="regular",
            monitoring_config={"watch_ownership": True},
            last_known_state={},
            last_scanned_block=0,
            enrollment_block=0,
            needs_polling=False,
            is_active=True,
        )
    )
    db_session.commit()

    head_urls: list[str] = []
    getlogs_urls: list[str] = []

    def _head_rpc(url, method, params, *a, **kw):
        head_urls.append(url)
        return "0x100"  # head = 256; confirmed head 244 > cursor 0 → one window scans

    def _getlogs_rpc(url, method, params, *a, **kw):
        getlogs_urls.append(url)
        return []  # no logs

    monkeypatch.setattr("services.monitoring.unified_watcher.rpc_request", _head_rpc)
    monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", _getlogs_rpc)

    scan_for_events(db_session, MAINNET_SEED)

    # Head reads and getLogs both hit the base route, never the mainnet seed.
    assert head_urls and all(u == BASE_URL for u in head_urls)
    assert getlogs_urls and all(u == BASE_URL for u in getlogs_urls)


# ---------------------------------------------------------------------------
# TVL — per-contract chain id on the Etherscan balance calls
# ---------------------------------------------------------------------------


def test_tvl_refresh_passes_contract_chain_id(db_session, monkeypatch):
    from services.monitoring.tvl import refresh_contract_balances

    proto = Protocol(name="__mc_tvl__")
    db_session.add(proto)
    db_session.flush()
    db_session.add(
        Contract(
            address=_addr("d"),
            chain="base",
            protocol_id=proto.id,
            contract_name="BaseVault",
        )
    )
    db_session.commit()

    seen_chain_ids: list[int] = []

    def _bal(address, chain_id=1):
        seen_chain_ids.append(chain_id)
        return 0

    def _tokens(address, chain_id=1):
        seen_chain_ids.append(chain_id)
        return []

    monkeypatch.setattr("utils.etherscan.get_eth_balance", _bal)
    monkeypatch.setattr("utils.etherscan.get_token_balances", _tokens)
    monkeypatch.setattr("utils.etherscan.get_eth_price", lambda *a, **kw: None)

    refresh_contract_balances(db_session, proto.id)

    assert seen_chain_ids == [8453, 8453]


# ---------------------------------------------------------------------------
# Enrollment — WatchedProxy keyed on the contract's chain + base seed block
# ---------------------------------------------------------------------------


def test_enroll_bases_watched_proxy_on_contract_chain(db_session, monkeypatch):
    from db.models import Job, JobStage, JobStatus
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)
    # This test models a deployment where base has passed the inv-14 enablement
    # checklist; enrollment gates off-allowlist chains (inv. 14), so make the
    # base-enabled premise explicit rather than relying on the {1} default.
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")

    proto = Protocol(name="__mc_enroll__")
    db_session.add(proto)
    db_session.flush()

    proxy_addr = _addr("e")
    db_session.add(
        Contract(
            address=proxy_addr,
            chain="base",
            protocol_id=proto.id,
            contract_name="BaseProxy",
            is_proxy=True,
            proxy_type="eip1967",
            implementation=_addr("f"),
        )
    )
    db_session.add(Job(address=proxy_addr, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    db_session.commit()

    block_urls: list[str] = []

    def _rpc(url, method, params, *a, **kw):
        block_urls.append(url)
        return "0x100"

    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", _rpc)

    # Seed with the mainnet URL; the base contract must still resolve its own route.
    enroll_protocol_contracts(db_session, proto.id, MAINNET_SEED, "ethereum")

    wp = db_session.execute(select(WatchedProxy).where(WatchedProxy.proxy_address == proxy_addr)).scalar_one()
    assert wp.chain == "base"

    mc = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == proxy_addr)).scalar_one()
    assert mc.chain == "base"

    # The enrollment seed-block read went to the base route, not the mainnet seed.
    assert block_urls and all(u == BASE_URL for u in block_urls)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
