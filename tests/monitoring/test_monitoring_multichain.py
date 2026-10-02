"""Drives a Base (8453) input through poller, scanner, TVL and enrollment; only the wire is stubbed."""

from __future__ import annotations

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


def test_enroll_bases_watched_proxy_on_contract_chain(db_session, monkeypatch):
    from db.models import Job, JobStage, JobStatus
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)
    # This test models a deployment where Base is enabled. Enrollment gates
    # off-allowlist chains, so make the
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

    enroll_protocol_contracts(db_session, proto.id, MAINNET_SEED, "ethereum")

    wp = db_session.execute(select(WatchedProxy).where(WatchedProxy.proxy_address == proxy_addr)).scalar_one()
    assert wp.chain == "base"

    mc = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == proxy_addr)).scalar_one()
    assert mc.chain == "base"

    assert block_urls and all(u == BASE_URL for u in block_urls)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
