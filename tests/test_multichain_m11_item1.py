"""M1.1 item 1 — second-chain threading proofs.

Every test here drives a non-mainnet chain (Base, id 8453) through one of the
threaded paths and asserts the chain reaches it: the resolver's bound RPC
URL/chain_id (inv. 7), the balance Etherscan reads, the materialization cache
name, the monitoring-enroll chain, the probe rate bucket, the company-overview
join, and the audit-timeline bytecode read. The wire is stubbed (never the
class) so the offline suite stays hermetic.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest


def _row(**attrs: Any) -> Any:
    """SimpleNamespace stand-in for a Job/Contract row, typed Any so call sites
    annotated with the ORM types accept it."""
    return SimpleNamespace(**attrs)


_BASE_ID = 8453
_BASE_URL_SUFFIX = "/main/evm/8453"
_MAINNET_URL_SUFFIX = "/main/evm/1"

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


@pytest.fixture
def _erpc_base(monkeypatch: pytest.MonkeyPatch) -> str:
    """Configure a deterministic eRPC base so URL routes are assertable."""
    base = "https://erpc.example"
    monkeypatch.setenv("ERPC_BASE_URL", base)
    monkeypatch.delenv("ERPC_SECRET", raising=False)
    return base


# ---------------------------------------------------------------------------
# inv. 7 — ChainContext binds chain_id to its RPC URL
# ---------------------------------------------------------------------------


def test_resolve_chain_context_binds_base_url_to_base_id(_erpc_base):
    from services.resolution.capability_resolver import _resolve_chain_context

    ctx = _resolve_chain_context(_BASE_ID, None, "base")
    assert ctx.chain_id == _BASE_ID
    assert ctx.rpc_url.endswith(_BASE_URL_SUFFIX)


def test_resolve_chain_context_mainnet_unchanged(_erpc_base):
    from services.resolution.capability_resolver import _resolve_chain_context

    ctx = _resolve_chain_context(1, None, "ethereum")
    assert ctx.chain_id == 1
    assert ctx.rpc_url.endswith(_MAINNET_URL_SUFFIX)


def test_resolve_chain_context_local_override_wins(_erpc_base):
    from services.resolution.capability_resolver import _resolve_chain_context

    ctx = _resolve_chain_context(_BASE_ID, "http://127.0.0.1:8545", "base")
    assert ctx.chain_id == _BASE_ID
    assert ctx.rpc_url == "http://127.0.0.1:8545"


# ---------------------------------------------------------------------------
# capability_resolver — a chain-8453 job reaches the EvaluationContext + URL
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


# ---------------------------------------------------------------------------
# workers — chain_id derivation + threading
# ---------------------------------------------------------------------------


def test_resolution_worker_chain_id_for_job_column_and_derived():
    from workers.resolution_worker import _chain_id_for_job

    assert _chain_id_for_job(_row(chain_id=_BASE_ID, request={}, address="0x1")) == _BASE_ID
    # No column → derive from request chain.
    assert _chain_id_for_job(_row(request={"chain": "base"}, address="0x1")) == _BASE_ID
    assert _chain_id_for_job(_row(request={"chain": "ethereum"}, address="0x1")) == 1


def test_policy_worker_chain_helpers_base():
    from workers.policy_worker import _chain_id_for_job, _chain_name_for_job

    job = _row(chain_id=_BASE_ID, request={"chain": "base"}, address="0x1")
    assert _chain_id_for_job(job) == _BASE_ID
    assert _chain_name_for_job(job) == "base"
    mainnet = _row(request={"chain": "ethereum"}, address="0x1")
    assert _chain_name_for_job(mainnet) == "ethereum"


def test_static_worker_parent_chain_name_never_none():
    from workers.static_worker import _parent_chain_name

    assert _parent_chain_name(_row(chain_id=_BASE_ID, request={}, address="0x1")) == "base"
    # Chain-less parent still resolves to a concrete name (mainnet), never None.
    assert _parent_chain_name(_row(request={}, address="0x1")) == "ethereum"


def test_fetch_balances_passes_chain_id_to_etherscan(monkeypatch):
    from workers.resolution_worker import ResolutionWorker

    captured: dict[str, object] = {}

    def _bal(addr, *, chain_id=1):
        captured["balance_chain"] = chain_id
        return 0

    def _tokens(addr, *, chain_id=1):
        captured["token_chain"] = chain_id
        return []

    def _price(*, chain_id=1):
        captured["price_chain"] = chain_id
        return 0.0

    monkeypatch.setattr("utils.etherscan.get_eth_balance", _bal)
    monkeypatch.setattr("utils.etherscan.get_token_balances", _tokens)
    monkeypatch.setattr("utils.etherscan.get_eth_price", _price)
    monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

    worker = ResolutionWorker()
    session = MagicMock()
    job = _row(id="job-1", address="0x" + "11" * 20, request={"chain": "base"})
    contract_row = _row(id=7)

    worker._fetch_balances(session, job, contract_row, chain_id=_BASE_ID)

    assert captured["balance_chain"] == _BASE_ID
    assert captured["token_chain"] == _BASE_ID
    assert captured["price_chain"] == _BASE_ID


# ---------------------------------------------------------------------------
# recursive — materialization cache keyed by the chain's canonical name
# ---------------------------------------------------------------------------


def test_materialization_chain_name_base_and_mainnet():
    from services.resolution.recursive import _chain_name_for_materialization

    assert _chain_name_for_materialization(_BASE_ID) == "base"
    assert _chain_name_for_materialization(1) == "ethereum"


def test_materialize_contract_artifacts_threads_chain(monkeypatch):
    from services.resolution import recursive

    captured: dict[str, object] = {}

    def _fake_cache(*, effective_address, bytecode_keccak, workspace_prefix, chain=None):
        captured["chain"] = chain
        return ("Name", {"subject": {}}, {"contract_address": effective_address}, None)

    monkeypatch.setattr(recursive, "_materialize_with_cross_process_cache", _fake_cache)
    monkeypatch.setattr("services.discovery.classifier.classify_single", lambda address, rpc_url, **_kw: None)
    monkeypatch.setattr(recursive, "build_control_snapshot", lambda _plan, _rpc, **_kw: {"controller_values": {}})
    monkeypatch.setattr(recursive, "_build_effective_permissions", lambda _a, _s: {"functions": []})

    recursive._materialize_contract_artifacts(
        "0x" + "22" * 20, "http://127.0.0.1:8545", workspace_prefix="t", chain="base"
    )
    assert captured["chain"] == "base"


# ---------------------------------------------------------------------------
# company_overview — a mainnet job never pairs with a same-address L2 contract
# ---------------------------------------------------------------------------


def test_job_matches_contract_chain_cross_chain():
    from services.aggregations.company_overview import _job_matches_contract_chain

    base_job = _row(chain_id=_BASE_ID, request={"chain": "base"}, address="0x1")
    mainnet_job = _row(chain_id=1, request={"chain": "ethereum"}, address="0x1")

    assert _job_matches_contract_chain(base_job, "base") is True
    assert _job_matches_contract_chain(base_job, "ethereum") is False
    assert _job_matches_contract_chain(mainnet_job, "ethereum") is True
    # NULL contract chain + alias fold to mainnet.
    assert _job_matches_contract_chain(mainnet_job, None) is True
    assert _job_matches_contract_chain(mainnet_job, "mainnet") is True
    assert _job_matches_contract_chain(base_job, None) is False


# ---------------------------------------------------------------------------
# probe rate-limit bucket is chain-scoped (inv. 12)
# ---------------------------------------------------------------------------


def test_probe_rate_bucket_is_chain_scoped(monkeypatch):
    from fastapi import HTTPException

    from routers import predicate_capabilities

    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_LIMIT", 1)
    monkeypatch.setattr(predicate_capabilities, "_PROBE_RATE_WINDOW_S", 60.0)
    predicate_capabilities._probe_rate_state.clear()

    addr = "0x" + "ab" * 20
    # First mainnet probe consumes the mainnet bucket.
    predicate_capabilities._probe_rate_check("k", addr, 1)
    # The Base bucket is independent — this must NOT be rate-limited.
    predicate_capabilities._probe_rate_check("k", addr, _BASE_ID)
    # A second mainnet probe trips the (now-full) mainnet bucket.
    with pytest.raises(HTTPException):
        predicate_capabilities._probe_rate_check("k", addr, 1)

    assert ("k", addr, 1) in predicate_capabilities._probe_rate_state
    assert ("k", addr, _BASE_ID) in predicate_capabilities._probe_rate_state


# ---------------------------------------------------------------------------
# contract_audit_timeline — bytecode read scoped to the contract's chain
# ---------------------------------------------------------------------------


def test_audit_timeline_bytecode_read_uses_contract_chain(monkeypatch):
    from services.aggregations import contract_audit_timeline

    captured: dict[str, object] = {}

    def _fake_pg_get(chain_id, addr):
        captured["chain_id"] = chain_id
        return ("0xdead", "0x" + "ab" * 32)

    monkeypatch.setattr("utils.rpc._pg_bytecode_get", _fake_pg_get)

    out = contract_audit_timeline._bytecode_keccak_now_batch({"0x" + "33" * 20}, chain_id=_BASE_ID)
    assert captured["chain_id"] == _BASE_ID
    assert out["0x" + "33" * 20] == "0x" + "ab" * 32


# ---------------------------------------------------------------------------
# routers/jobs — DELETE chain-qualifies (no more MultipleResultsFound) (inv. 12)
# ---------------------------------------------------------------------------


@pytest.fixture
def _bind_router_session(session, monkeypatch):
    """Point the router-facing ``deps.SessionLocal`` at this file's own test-DB
    session.

    The router functions under test open ``deps.SessionLocal()`` themselves,
    which binds to the app ``DATABASE_URL`` (``psat``) — a different database
    than this module's local ``session`` fixture, which seeds through
    ``TEST_DATABASE_URL`` (``psat_test``). Without this rebind the endpoint reads
    an empty DB and 404s. (In the full suite these passed only incidentally: an
    earlier test left ``deps.SessionLocal`` rebound at ``psat_test`` — an
    order-dependency this fixture removes.) Mirrors conftest's documented
    ``SessionFactory`` wiring, scoped to the seeded session so the endpoint sees
    exactly the rows the test committed."""
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

    # Address-only keying used to 500 on MultipleResultsFound; chain disambiguates.
    result = delete_company_address(proto.name, address, chain="base")
    assert result["deleted"] is True
    assert result["chain"] == "base"

    remaining = session.query(Contract).filter(Contract.protocol_id == proto.id).all()
    assert len(remaining) == 1
    assert remaining[0].chain == "ethereum"


# ---------------------------------------------------------------------------
# routers/analyses — address artifact lookup chain-qualifies when chain given
# ---------------------------------------------------------------------------


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

    # Mainnet job is the MORE recent one, so an unqualified lookup returns it;
    # a chain=base lookup must still select the Base job.
    _seed("base", _BASE_ID, datetime(2024, 1, 1, tzinfo=timezone.utc))
    _seed("ethereum", 1, datetime(2025, 1, 1, tzinfo=timezone.utc))

    resp = analysis_artifact(address, "dependencies.json", MagicMock(), chain="base")
    import json

    body = json.loads(bytes(resp.body).decode())
    assert body == {"chain": "base"}
