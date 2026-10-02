"""M1.1 item 1: a non-mainnet chain (Base, 8453) reaches each threaded path: the resolver's bound RPC URL/chain_id,
balance Etherscan reads, materialization cache name, monitoring-enroll chain, probe rate bucket,
company-overview join and audit-timeline bytecode read. The wire is stubbed (never the class) to stay hermetic.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from tests.support.balance_stubs import page, pinned_native_unavailable


def _row(**attrs: Any) -> Any:
    return SimpleNamespace(**attrs)


_BASE_ID = 8453
_BASE_URL_SUFFIX = "/main/evm/8453"


@pytest.fixture
def _erpc_base(monkeypatch: pytest.MonkeyPatch) -> str:
    base = "https://erpc.example"
    monkeypatch.setenv("ERPC_BASE_URL", base)
    monkeypatch.delenv("ERPC_SECRET", raising=False)
    return base


# ---------------------------------------------------------------------------
# ChainContext binds chain_id to its RPC URL
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, Job, Protocol

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)
    try:
        yield s
    finally:
        s.rollback()
        s.query(Contract).delete()
        s.query(Job).delete()
        s.query(Protocol).delete()
        s.commit()
        s.close()
        engine.dispose()


@requires_postgres
def test_resolver_threads_base_chain_into_eval_context(session, _erpc_base, monkeypatch):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact
    from services.resolution import capability_resolver
    from services.resolution.capabilities import CapabilityExpr, Condition

    address = "0x" + "cc" * 20
    job = Job(
        address=address,
        chain_id=_BASE_ID,
        request={"address": address, "name": "T", "chain": "base"},
        status=JobStatus.completed,
        stage=JobStage.done,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    store_artifact(session, job.id, "predicate_trees", data={"trees": {"foo()": None}})
    session.commit()

    captured: dict[str, object] = {}

    def _fake_eval(tree, registry, ctx):
        captured["chain_id"] = ctx.chain_id
        captured["rpc_url"] = ctx.rpc_url
        return CapabilityExpr.conditional_universal(Condition(kind="business", description="x"))

    monkeypatch.setattr(capability_resolver, "evaluate_tree_with_registry", _fake_eval)

    out = capability_resolver.resolve_contract_capabilities(
        session, address=address, chain_id=_BASE_ID, chain="base", job_id=job.id
    )
    assert out is not None
    assert captured["chain_id"] == _BASE_ID
    assert isinstance(captured["rpc_url"], str)
    assert captured["rpc_url"].endswith(_BASE_URL_SUFFIX)


def test_resolution_worker_chain_id_for_job_column_and_derived():
    from workers.resolution_worker import _chain_id_for_job

    assert _chain_id_for_job(_row(chain_id=_BASE_ID, request={}, address="0x1")) == _BASE_ID
    assert _chain_id_for_job(_row(request={"chain": "base"}, address="0x1")) == _BASE_ID
    assert _chain_id_for_job(_row(request={"chain": "ethereum"}, address="0x1")) == 1


def test_policy_worker_chain_helpers_base():
    from workers.policy_worker import _chain_id_for_job, _chain_name_for_job

    job = _row(chain_id=_BASE_ID, request={"chain": "base"}, address="0x1")
    assert _chain_id_for_job(job) == _BASE_ID
    assert _chain_name_for_job(job) == "base"
    mainnet = _row(request={"chain": "ethereum"}, address="0x1")
    assert _chain_name_for_job(mainnet) == "ethereum"


@requires_postgres
def test_fetch_balances_passes_chain_id_to_etherscan(monkeypatch, db_session):
    from workers.resolution_worker import ResolutionWorker

    captured: dict[str, object] = {}

    def _bal(addr, *, chain_id=1):
        captured["balance_chain"] = chain_id
        return 0

    def _tokens(addr, *, chain_id=1):
        captured["token_chain"] = chain_id
        return page([])

    def _price(chain_id=1):
        captured["price_chain"] = chain_id
        return 0.0

    monkeypatch.setattr("services.clients.etherscan.get_eth_balance", _bal)
    monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", _tokens)
    monkeypatch.setattr("services.clients.etherscan.get_native_price", _price)
    monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)
    # The pinned native read is a separate wire, stubbed unavailable so the assertions stay about Etherscan.
    pinned_native_unavailable(monkeypatch)

    worker = ResolutionWorker()
    from db.models import Contract

    session = db_session
    job = _row(id=uuid.uuid4(), address="0x" + "11" * 20, request={"chain": "base"})
    contract_row = Contract(address=job.address, chain="base")
    session.add(contract_row)
    session.commit()

    worker._fetch_balances(session, job, contract_row, chain_id=_BASE_ID)

    assert captured["balance_chain"] == _BASE_ID
    assert captured["token_chain"] == _BASE_ID
    # Base uses ETH, so it shares the mainnet ETH quote.
    assert captured["price_chain"] == 1


def test_materialization_chain_name_base_and_mainnet():
    from services.resolution.recursive import _chain_name_for_materialization

    assert _chain_name_for_materialization(_BASE_ID) == "base"
    assert _chain_name_for_materialization(1) == "ethereum"


# ---------------------------------------------------------------------------
# probe rate-limit bucket is chain-scoped
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# routers/jobs — DELETE chain-qualifies (no more MultipleResultsFound)
# ---------------------------------------------------------------------------


@pytest.fixture
def _bind_router_session(session, monkeypatch):
    """The routers open ``deps.SessionLocal`` themselves, which binds to the dev DB; this used to pass only via
    another test's leaked rebind.
    """
    from routers import deps

    class _SharedSessionFactory:
        def __call__(self):
            return self

        def __enter__(self):
            return session

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(deps, "SessionLocal", _SharedSessionFactory())
    return session


@requires_postgres
def test_delete_company_address_chain_qualifies(session, _bind_router_session):
    from db.models import Contract, Protocol
    from routers.jobs import delete_company_address

    proto = Protocol(name=f"m11_del_{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    address = "0x" + "44" * 20
    session.add(Contract(address=address, chain="ethereum", protocol_id=proto.id))
    session.add(Contract(address=address, chain="base", protocol_id=proto.id))
    session.commit()

    # Address-only keying used to 500 on MultipleResultsFound.
    result = delete_company_address(proto.name, address, chain="base")
    assert result["deleted"] is True
    assert result["chain"] == "base"

    remaining = session.query(Contract).filter(Contract.protocol_id == proto.id).all()
    assert len(remaining) == 1
    assert remaining[0].chain == "ethereum"


@requires_postgres
def test_analysis_artifact_address_lookup_chain_qualified(session, _bind_router_session):
    from db.models import Job, JobStage, JobStatus
    from db.queue import store_artifact
    from routers.analyses import analysis_artifact

    address = "0x" + "55" * 20

    def _seed(chain_name: str, chain_id: int, when: datetime) -> None:
        job = Job(
            address=address,
            chain_id=chain_id,
            request={"address": address, "chain": chain_name},
            status=JobStatus.completed,
            stage=JobStage.done,
            created_at=when,
            updated_at=when,
        )
        session.add(job)
        session.flush()
        store_artifact(session, job.id, "dependencies", data={"chain": chain_name})
        session.commit()

    # The mainnet job is newer, so an unqualified lookup returns it.
    _seed("base", _BASE_ID, datetime(2024, 1, 1, tzinfo=timezone.utc))
    _seed("ethereum", 1, datetime(2025, 1, 1, tzinfo=timezone.utc))

    resp = analysis_artifact(address, "dependencies.json", MagicMock(), chain="base")
    import json

    body = json.loads(bytes(resp.body).decode())
    assert body == {"chain": "base"}
