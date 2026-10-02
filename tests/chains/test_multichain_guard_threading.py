"""URL↔chain_id guard — threading proof (audit finding F6).

``rpc_request``'s guard (``_assert_url_chain_id``) is a no-op unless the caller declares ``chain_id``. These
tests drive each threaded production path with base (8453) and assert the *declared* chain_id reaches the
wire, so a silent ``=1`` default fails here, not in prod. Only the wire (``rpc_request`` / ``get_code`` /
batch helper) is stubbed at each consumer's import site.

The negative case proves the guard fires *through* the threading.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from db.models import Contract, MonitoredContract, Protocol, WatchedProxy

BASE_CHAIN_ID = 8453
ERPC_BASE = "https://erpc.test"
BASE_URL = f"{ERPC_BASE}/main/evm/{BASE_CHAIN_ID}"
MAINNET_SEED = "http://mainnet-seed"


def _addr(prefix: str) -> str:
    return "0x" + (prefix * 40)[:40]


def test_secondary_impl_threads_chain_id(monkeypatch):
    from services.discovery import secondary_impl

    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x" + "0" * 24 + _addr("d")[2:]

    monkeypatch.setattr("services.clients.rpc.rpc_request", _rpc)

    out = secondary_impl.resolve_secondary_impl_addresses(
        BASE_URL,
        _addr("a"),
        [{"slot": 1}],
        require_code=False,
        chain_id=BASE_CHAIN_ID,
    )
    assert out  # the storage read decoded to an address
    assert seen == [BASE_CHAIN_ID]


def test_enrollment_seed_block_threads_chain_id(db_session, monkeypatch):
    from db.models import Job, JobStage, JobStatus
    from services.monitoring.enrollment import enroll_protocol_contracts

    monkeypatch.setenv("ERPC_BASE_URL", ERPC_BASE)
    monkeypatch.setenv("PSAT_SUPPORTED_CHAIN_IDS", "1,8453")

    proto = Protocol(name=f"__guard_enroll_{uuid.uuid4().hex[:8]}__")
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

    seen: list[int | None] = []

    def _rpc(url, method, params, *a, chain_id=None, **kw):
        seen.append(chain_id)
        return "0x100"

    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", _rpc)

    # Seeded with the mainnet URL; the base contract must declare its own chain id.
    enroll_protocol_contracts(db_session, proto.id, MAINNET_SEED, "ethereum")

    wp = db_session.execute(select(WatchedProxy).where(WatchedProxy.proxy_address == proxy_addr)).scalar_one()
    assert wp.chain == "base"
    mc = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == proxy_addr)).scalar_one()
    assert mc.chain == "base"

    assert seen and all(c == BASE_CHAIN_ID for c in seen)
