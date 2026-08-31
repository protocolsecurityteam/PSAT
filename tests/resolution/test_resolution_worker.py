"""Tests for ResolutionWorker — process(), _fetch_balances, _queue_discovered_contracts."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from db.models import ContractBalance, ContractBalanceFetch
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from tests.support.balance_stubs import page, pinned_native_unavailable
from tests.support.resolution_worker_stubs import (
    CHILD_ADDRESS,
    PROXY_ADDRESS,
    TARGET_ADDRESS,
    _job,
    _minimal_snapshot,
    _patch_all,
    _resolved_graph,
)
from utils.balance_status import NATIVE_STATUS_FETCH_FAILED, NATIVE_STATUS_NOT_DETERMINED
from workers.resolution_worker import ResolutionWorker


@pytest.fixture(autouse=True)
def _stub_etherscan_balances(monkeypatch):
    """Offline: ``_fetch_balances`` probes ETH + token balances via Etherscan.

    Benign defaults (no balances); tests exercising specific balance behaviour
    override these in-body (monkeypatch order lets the later setattr win).

    The pinned native read is a second, non-Etherscan wire the same call makes,
    and no test here exercises it — so the module takes the unpinned path its
    expectations were written against.
    """
    monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 0)
    monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda *a, **k: 0.0)
    monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
    pinned_native_unavailable(monkeypatch)


@pytest.fixture
def db_session_for_resolution():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Artifact, Job, JobDependency

    engine = create_engine(_DB_URL)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        session.query(JobDependency).delete()
        session.query(Artifact).delete()
        session.query(Job).delete()
        session.commit()
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# 1. Happy-path process()
# ---------------------------------------------------------------------------


class TestProcessHappyPath:
    """Snapshot and graph enrich the canonical assessment."""

    def test_stores_assessment_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        # Make scalar_one_or_none return None (no contract row) so DB writes are skipped
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        ctx = _patch_all(monkeypatch)

        worker.process(session, cast(Any, job))

        stored_names = [name for name, _ in ctx["store_calls"]]
        assert "assessment" in stored_names
        assert not {"control_snapshot", "resolved_control_graph"} & set(stored_names)


# ---------------------------------------------------------------------------
# 2. Proxy address override
# ---------------------------------------------------------------------------


class TestProxyAddressOverride:
    """When proxy_address is in request, tracking plan and analysis use it."""

    def test_proxy_overrides_contract_address(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        captured_plan: list[Any] = []

        def fake_build(plan: Any, rpc_url: str, **_kw: Any) -> dict:
            captured_plan.append(plan)
            return _minimal_snapshot()

        _patch_all(monkeypatch)
        monkeypatch.setattr("workers.resolution_worker.build_control_snapshot", fake_build)

        job = _job(request={"rpc_url": "https://rpc.example", "proxy_address": PROXY_ADDRESS})
        worker.process(session, cast(Any, job))

        # The plan passed to build_control_snapshot should have proxy address
        assert captured_plan[0]["contract_address"] == PROXY_ADDRESS


def _added(session) -> list:
    """Every object handed to ``session.add`` on a MagicMock session."""
    return [c.args[0] for c in session.add.call_args_list if c.args]


def _balance_rows(session) -> int:
    """HOLDINGS rows only. The fetch-provenance row is not a holding and must
    never be counted as one — that separation is the whole point of the plane."""
    return sum(1 for o in _added(session) if isinstance(o, ContractBalance))


def _fetch_objects(session) -> list:
    return [o for o in _added(session) if isinstance(o, ContractBalanceFetch)]


def _fetch_rows(session) -> int:
    return len(_fetch_objects(session))


# ---------------------------------------------------------------------------
# 3. _fetch_balances — ETH + tokens stored, price failure handled
# ---------------------------------------------------------------------------


class TestFetchBalancesHappyPath:
    """ETH + token balances stored, price fetch failure handled gracefully."""

    def test_stores_eth_and_tokens(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)
        job = _job()

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 1_000_000_000_000_000_000
        )  # 1 ETH
        monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda *a, **k: 2000.0)
        monkeypatch.setattr(
            "services.clients.etherscan.get_token_balances_page",
            lambda addr, *a, **k: page(
                [
                    {
                        "token_address": "0xtoken1",
                        "token_name": "USDC",
                        "token_symbol": "USDC",
                        "decimals": 6,
                        "balance": 1000000,
                        "price_usd": 1.0,
                        "usd_value": 1.0,
                    }
                ]
            ),
        )
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)

        # 2 holdings rows: 1 ETH + 1 token. The third ``add`` is the
        # ``ContractBalanceFetch`` provenance row, which is NOT a holding and is
        # counted separately for exactly that reason.
        assert _balance_rows(session) == 2
        assert _fetch_rows(session) == 1
        session.commit.assert_called()

    def test_price_failure_still_stores_eth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)
        job = _job()

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 1_000_000_000_000_000_000
        )
        monkeypatch.setattr("services.clients.etherscan.get_native_price", MagicMock(side_effect=Exception("API down")))
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)

        # Should still add ETH balance even if price failed
        assert _balance_rows(session) == 1
        assert _fetch_rows(session) == 1
        session.commit.assert_called()

    def test_balance_fetch_exception_writes_no_holding_but_leaves_a_trace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)
        job = _job()

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", MagicMock(side_effect=Exception("Network error"))
        )
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)

        # No holdings row on a failed read — the balance is not known, and the
        # earlier code path recorded that only via ``record_degraded``, leaving
        # the balance plane showing a plain absence. A provenance row now says
        # the read was attempted and failed.
        assert _balance_rows(session) == 0
        fetches = _fetch_objects(session)
        assert len(fetches) == 1
        assert fetches[0].native_status == NATIVE_STATUS_FETCH_FAILED

    def test_non_eth_native_chain_stores_native_symbol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A BSC job records its native gas balance under BNB at the BNB quote,
        never an ETH label — the native asset comes from the chain registry."""
        worker = ResolutionWorker()
        session = MagicMock()
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)
        job = _job(request={"chain": "bsc", "chain_id": 56})

        monkeypatch.setattr(
            "services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 2_000_000_000_000_000_000
        )  # 2 BNB
        monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda chain_id: 600.0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=56)

        native_rows = [o for o in _added(session) if isinstance(o, ContractBalance) and o.token_address is None]
        assert len(native_rows) == 1
        row = native_rows[0]
        assert row.token_symbol == "BNB"
        assert row.token_name == "BNB"
        assert row.price_usd == 600.0
        assert row.usd_value == 1200.0


# ---------------------------------------------------------------------------
# 4. _fetch_balances — no address / no contract_row returns early
# ---------------------------------------------------------------------------


class TestFetchBalancesEarlyReturn:
    """Returns early when address or contract_row is missing."""

    def test_no_address_returns_early(self) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        job = _job(address=None)
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)
        session.add.assert_not_called()

    def test_no_contract_row_returns_early(self) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        job = _job()

        cast(Any, worker)._fetch_balances(session, job, None, chain_id=1)
        session.add.assert_not_called()


# ---------------------------------------------------------------------------
# 5. _queue_discovered_contracts — creates child jobs, skips invalid
# ---------------------------------------------------------------------------


class TestQueueDiscoveredContracts:
    """Creates child jobs for valid contract nodes, skips invalid ones."""

    def test_creates_child_job_for_analyzed_contract(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        # No existing job
        session.execute.return_value.scalar_one_or_none.return_value = None

        create_calls: list[dict] = []

        def fake_create_job(_session: Any, request_dict: dict, initial_stage: Any = None) -> Any:
            create_calls.append(request_dict)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", fake_create_job)
        # The perimeter walk moved to services/discovery/perimeter; the resolution
        # worker still imports create_job for its dependency-provider spawn, so both
        # bindings are stubbed and the assertions below are unchanged.
        monkeypatch.setattr("services.discovery.perimeter.create_job", fake_create_job)

        graph = _resolved_graph(
            nodes=[
                {
                    "address": CHILD_ADDRESS,
                    "node_type": "contract",
                    "analyzed": True,
                    "contract_name": "ChildContract",
                },
            ]
        )

        job = _job()
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        assert len(create_calls) == 1
        assert create_calls[0]["address"] == CHILD_ADDRESS
        assert create_calls[0]["name"] == "ChildContract"
        assert create_calls[0]["parent_job_id"] == str(job.id)

    def test_propagates_chain_from_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": CHILD_ADDRESS, "node_type": "contract", "analyzed": True}])

        job = _job(request={"rpc_url": "https://rpc.example", "chain": "ethereum"})
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        assert len(create_calls) == 1
        assert create_calls[0]["chain"] == "ethereum"


# ---------------------------------------------------------------------------
# 6. _queue_discovered_contracts — company inheritance via parent chain
# ---------------------------------------------------------------------------


class TestQueueDiscoveredContractsCompanyInheritance:
    """Company is inherited from parent job chain when not set on current job."""

    def test_inherits_company_from_parent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()

        parent_id = str(uuid.uuid4())
        parent_job = SimpleNamespace(
            id=parent_id,
            company="Acme Corp",
            request={},
        )

        # First call (select Job where address=...) returns None (no existing job)
        # session.get(Job, parent_id) returns parent_job

        def fake_execute(stmt):
            result = MagicMock()
            result.scalar_one_or_none.return_value = None
            return result

        session.execute = fake_execute
        session.get = lambda model, pid: parent_job if pid == parent_id else None

        create_calls: list[dict] = []
        child_ns = SimpleNamespace(id=uuid.uuid4(), company=None)

        def fake_create_job(_session: Any, request_dict: dict, initial_stage: Any = None) -> Any:
            create_calls.append(request_dict)
            return child_ns

        monkeypatch.setattr("workers.resolution_worker.create_job", fake_create_job)
        # The perimeter walk moved to services/discovery/perimeter; the resolution
        # worker still imports create_job for its dependency-provider spawn, so both
        # bindings are stubbed and the assertions below are unchanged.
        monkeypatch.setattr("services.discovery.perimeter.create_job", fake_create_job)

        graph = _resolved_graph(nodes=[{"address": CHILD_ADDRESS, "node_type": "contract", "analyzed": True}])

        job = _job(company=None, request={"rpc_url": "https://rpc.example", "parent_job_id": parent_id})
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        assert len(create_calls) == 1
        # Company should be set on child job
        assert child_ns.company == "Acme Corp"

    def test_uses_job_company_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        create_calls: list[dict] = []
        child_ns = SimpleNamespace(id=uuid.uuid4(), company=None)

        def fake_create_job(_session: Any, request_dict: dict, initial_stage: Any = None) -> Any:
            create_calls.append(request_dict)
            return child_ns

        monkeypatch.setattr("workers.resolution_worker.create_job", fake_create_job)
        # The perimeter walk moved to services/discovery/perimeter; the resolution
        # worker still imports create_job for its dependency-provider spawn, so both
        # bindings are stubbed and the assertions below are unchanged.
        monkeypatch.setattr("services.discovery.perimeter.create_job", fake_create_job)

        graph = _resolved_graph(nodes=[{"address": CHILD_ADDRESS, "node_type": "contract", "analyzed": True}])

        job = _job(company="Direct Corp")
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        assert len(create_calls) == 1
        assert child_ns.company == "Direct Corp"


# ---------------------------------------------------------------------------
# 9. Missing artifacts raise RuntimeError
# ---------------------------------------------------------------------------


class TestMissingArtifactsRaise:
    """process() raises RuntimeError when the canonical assessment is missing or invalid."""

    def test_missing_assessment_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        job = _job()

        monkeypatch.setattr("workers.resolution_worker.get_artifact", lambda _s, _j, name: None)
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        with pytest.raises(RuntimeError, match="assessment artifact not found"):
            worker.process(session, cast(Any, job))

    def test_non_dict_assessment_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        job = _job()

        monkeypatch.setattr(
            "workers.resolution_worker.get_artifact",
            lambda _s, _j, name: "not a dict" if name == "assessment" else None,
        )
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        with pytest.raises(RuntimeError, match="assessment artifact failed validation"):
            worker.process(session, cast(Any, job))


# ---------------------------------------------------------------------------
# 10. Zero ETH balance skips ETH row
# ---------------------------------------------------------------------------


class TestFetchBalancesZeroEth:
    """Zero ETH balance does not add an ETH row."""

    def test_zero_eth_no_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)
        job = _job()

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)

        # No holdings row for a zero balance — a row here would be consumed as
        # "this deployment holds the native asset". The zero itself is recorded
        # on the fetch plane, and because this read came from the UNPINNED
        # Etherscan path it is ``not_determined``, never ``proven_zero``: the
        # answer carries no height, so it proves zero at no height.
        assert _balance_rows(session) == 0
        fetches = _fetch_objects(session)
        assert len(fetches) == 1
        assert fetches[0].native_status == NATIVE_STATUS_NOT_DETERMINED
        assert fetches[0].block_number is None
        session.commit.assert_called()


# ---------------------------------------------------------------------------
# 11. Proxy address used in _fetch_balances
# ---------------------------------------------------------------------------


class TestFetchBalancesProxyAddress:
    """Which address is read, and which row the answer is filed against.

    These are ONE decision now. Reading the proxy and filing the answer against
    the implementation's row is what let a later read at the implementation's own
    address win the native class wholesale and evict a real balance, so the row
    that owns the address owns the fetch. When no contract row owns the requested
    address, the read falls back to this row's OWN address rather than filing a
    foreign address against it — the DB-backed arm in
    ``test_contract_balance_provenance.py`` covers the case where the proxy does
    have a row.
    """

    def test_an_unowned_proxy_address_is_not_read_against_a_foreign_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)

        captured_addrs: list[str] = []

        def fake_get_eth(addr: str, *a, **k) -> int:
            captured_addrs.append(addr)
            return 0

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", fake_get_eth)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        job = _job(request={"proxy_address": PROXY_ADDRESS})
        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)

        assert captured_addrs[0] == TARGET_ADDRESS


# ---------------------------------------------------------------------------
# 12. _queue_discovered_contracts — parent chain walk edge cases
# ---------------------------------------------------------------------------


class TestQueueDiscoveredContractsParentChainEdgeCases:
    """Edge cases in the parent chain walk for company inheritance."""

    def test_parent_not_found_breaks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When parent_job_id references a nonexistent job, walk stops."""
        worker = ResolutionWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        session.get = lambda model, pid: None  # parent not found

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": CHILD_ADDRESS, "node_type": "contract", "analyzed": True}])
        job = _job(company=None, request={"rpc_url": "https://rpc.example", "parent_job_id": str(uuid.uuid4())})
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        # Should still create the job, just no company
        assert len(create_calls) == 1

    def test_multi_level_parent_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Walk through grandparent to find company."""
        worker = ResolutionWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None

        grandparent_id = str(uuid.uuid4())
        parent_id = str(uuid.uuid4())

        grandparent_job = SimpleNamespace(id=grandparent_id, company="GrandCorp", request={})
        parent_job = SimpleNamespace(
            id=parent_id,
            company=None,
            request={"parent_job_id": grandparent_id},
        )

        def fake_get(model: Any, pid: str) -> Any:
            if pid == parent_id:
                return parent_job
            if pid == grandparent_id:
                return grandparent_job
            return None

        session.get = fake_get

        create_calls: list[dict] = []
        child_ns = SimpleNamespace(id=uuid.uuid4(), company=None)

        def fake_create_job(_session: Any, request_dict: dict, initial_stage: Any = None) -> Any:
            create_calls.append(request_dict)
            return child_ns

        monkeypatch.setattr("workers.resolution_worker.create_job", fake_create_job)
        # The perimeter walk moved to services/discovery/perimeter; the resolution
        # worker still imports create_job for its dependency-provider spawn, so both
        # bindings are stubbed and the assertions below are unchanged.
        monkeypatch.setattr("services.discovery.perimeter.create_job", fake_create_job)

        graph = _resolved_graph(nodes=[{"address": CHILD_ADDRESS, "node_type": "contract", "analyzed": True}])
        job = _job(company=None, request={"rpc_url": "https://rpc.example", "parent_job_id": parent_id})
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        assert len(create_calls) == 1
        assert child_ns.company == "GrandCorp"


@requires_postgres
def test_dependency_emission_walks_check_trees(db_session_for_resolution):
    """Authority providers used only by resolver-side check_trees still
    need dependency gates."""
    from sqlalchemy import select

    from db.models import JobDependency, JobStage, JobStatus
    from db.queue import create_job, store_artifact

    session = db_session_for_resolution
    provider_addr = "0x" + uuid.uuid4().hex[:8] + "aa" * 16
    depender_addr = "0x" + uuid.uuid4().hex[:8] + "bb" * 16

    provider_job = create_job(
        session,
        {"address": provider_addr, "chain": "ethereum", "name": "Provider"},
        initial_stage=JobStage.coverage,
    )
    provider_job.status = JobStatus.queued
    session.commit()
    from tests.support.policy_builders import _assessment, _minimal_contract_analysis

    store_artifact(
        session,
        provider_job.id,
        "assessment",
        data=_assessment(analysis=_minimal_contract_analysis(address=provider_addr, name="Provider")),
    )

    depender_job = create_job(
        session,
        {"address": depender_addr, "chain": "ethereum", "name": "Depender"},
        initial_stage=JobStage.resolution,
    )
    store_artifact(
        session,
        depender_job.id,
        "predicate_trees",
        data={
            "schema_version": "semantic",
            "contract_name": "Depender",
            "trees": {},
            "check_trees": {
                "canCall(address,address,bytes4)": {
                    "op": "LEAF",
                    "leaf": {
                        "kind": "external_bool",
                        "operator": "truthy",
                        "authority_role": "delegated_authority",
                        "operands": [{"source": "msg_sender"}],
                        "set_descriptor": {
                            "kind": "external_set",
                            "authority_contract": {
                                "address_source": {
                                    "source": "state_variable",
                                    "state_variable_name": "authority",
                                }
                            },
                            "callee_signature": "canCall(address,address,bytes4)",
                        },
                    },
                }
            },
        },
    )

    snapshot = {
        "controller_values": {
            "external_contract:authority": {
                "value": provider_addr,
            }
        }
    }

    ResolutionWorker()._emit_dependency_edges_from_predicate_trees(
        session,
        cast(Any, depender_job),
        cast(Any, snapshot),
        "https://rpc.example",
    )

    dep = session.execute(select(JobDependency).where(JobDependency.depender_job_id == depender_job.id)).scalar_one()
    assert dep.provider_address == provider_addr
    assert dep.status == "satisfied"


def _authority_check_predicate_trees() -> dict:
    """A minimal predicate_trees artifact whose only leaf delegates auth to an
    external ``authority`` state variable — enough to emit one dependency edge."""
    return {
        "schema_version": "semantic",
        "contract_name": "Depender",
        "trees": {},
        "check_trees": {
            "canCall(address,address,bytes4)": {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "external_set",
                        "authority_contract": {
                            "address_source": {"source": "state_variable", "state_variable_name": "authority"}
                        },
                        "callee_signature": "canCall(address,address,bytes4)",
                    },
                },
            }
        },
    }


def test_dependency_emission_records_pending_status_metrics(db_session_for_resolution):
    """A provider with no policy artifacts yet → a 'pending' edge; the emitter
    folds the per-status breakdown into the stage metrics."""
    from sqlalchemy import select

    from db.models import JobDependency, JobStage
    from db.queue import create_job, store_artifact
    from utils.logging import stage_metrics_var

    session = db_session_for_resolution
    provider_addr = "0x" + uuid.uuid4().hex[:8] + "cc" * 16
    depender_addr = "0x" + uuid.uuid4().hex[:8] + "dd" * 16

    depender_job = create_job(
        session,
        {"address": depender_addr, "chain": "ethereum", "name": "Depender"},
        initial_stage=JobStage.resolution,
    )
    store_artifact(session, depender_job.id, "predicate_trees", data=_authority_check_predicate_trees())
    snapshot = {"controller_values": {"external_contract:authority": {"value": provider_addr}}}

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        ResolutionWorker()._emit_dependency_edges_from_predicate_trees(
            session, cast(Any, depender_job), cast(Any, snapshot), "https://rpc.example"
        )
    finally:
        stage_metrics_var.reset(token)

    dep = session.execute(select(JobDependency).where(JobDependency.depender_job_id == depender_job.id)).scalar_one()
    assert dep.status == "pending"
    assert metrics["dep_edges_inserted"] == 1
    assert metrics["dep_edges_pending"] == 1
    assert metrics["dep_edges_cycle_degraded"] == 0


def test_dependency_emission_warns_and_records_on_cycle(db_session_for_resolution, caplog):
    """A would-be cycle (B already depends on A; A now depends on B) is inserted
    non-blocking as ``cycle_degraded`` — and must surface a WARNING + metric
    instead of landing silently."""
    import logging as _logging

    from sqlalchemy import select

    from db.models import JobDependency, JobStage
    from db.queue import create_job, store_artifact
    from utils.logging import stage_metrics_var

    session = db_session_for_resolution
    a_addr = "0x" + uuid.uuid4().hex[:8] + "ee" * 16  # depender A
    b_addr = "0x" + uuid.uuid4().hex[:8] + "ff" * 16  # provider B

    job_a = create_job(
        session, {"address": a_addr, "chain": "ethereum", "name": "A"}, initial_stage=JobStage.resolution
    )
    job_b = create_job(
        session, {"address": b_addr, "chain": "ethereum", "name": "B"}, initial_stage=JobStage.resolution
    )
    session.commit()
    # Pre-existing edge B → A; adding A → B closes the cycle.
    session.add(
        JobDependency(
            depender_job_id=job_b.id,
            provider_chain="ethereum",
            provider_address=a_addr,
            required_stage=JobStage.policy,
            status="pending",
        )
    )
    session.commit()

    store_artifact(session, job_a.id, "predicate_trees", data=_authority_check_predicate_trees())
    snapshot = {"controller_values": {"external_contract:authority": {"value": b_addr}}}

    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        with caplog.at_level(_logging.WARNING, logger="workers.resolution_worker"):
            ResolutionWorker()._emit_dependency_edges_from_predicate_trees(
                session, cast(Any, job_a), cast(Any, snapshot), "https://rpc.example"
            )
    finally:
        stage_metrics_var.reset(token)

    dep = session.execute(
        select(JobDependency).where(
            JobDependency.depender_job_id == job_a.id,
            JobDependency.provider_address == b_addr,
        )
    ).scalar_one()
    assert dep.status == "cycle_degraded"
    assert dep.cycle_path is not None
    assert metrics["dep_edges_cycle_degraded"] == 1
    assert any("dependency cycle" in rec.message.lower() for rec in caplog.records)


def test_satisfy_dependencies_logs_flipped_count(db_session_for_resolution, caplog):
    """Completing a provider flips its dependents to ``satisfied`` and logs the
    count (was discarded by the caller, so the cross-contract unblock was
    invisible)."""
    import logging as _logging

    from sqlalchemy import select

    from db.models import JobDependency, JobStage
    from db.queue import create_job

    session = db_session_for_resolution
    provider_addr = "0x" + uuid.uuid4().hex[:8] + "ab" * 16
    depender_addr = "0x" + uuid.uuid4().hex[:8] + "cd" * 16

    provider_job = create_job(
        session, {"address": provider_addr, "chain": "ethereum", "name": "Provider"}, initial_stage=JobStage.policy
    )
    depender_job = create_job(
        session, {"address": depender_addr, "chain": "ethereum", "name": "Dep"}, initial_stage=JobStage.policy
    )
    session.commit()
    session.add(
        JobDependency(
            depender_job_id=depender_job.id,
            provider_chain="ethereum",
            provider_address=provider_addr,
            required_stage=JobStage.policy,
            status="pending",
        )
    )
    session.commit()

    with caplog.at_level(_logging.INFO, logger="workers.base"):
        flipped = ResolutionWorker()._satisfy_dependencies(
            session, cast(Any, provider_job), completed_stage=JobStage.policy
        )

    assert flipped == 1
    row = session.execute(select(JobDependency).where(JobDependency.depender_job_id == depender_job.id)).scalar_one()
    assert row.status == "satisfied"
    assert any("satisfied 1 dependent" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# 13. resolved_graph_path does not exist
# ---------------------------------------------------------------------------


class TestStructuralOwnershipPropagation:
    """``_queue_discovered_contracts`` looks up the parent's stored
    ``implementation`` / ``beacon`` fields plus its dep edges to decide
    whether each cascade child inherits structural ownership. Mocks
    fall short for this — multiple session.execute calls return
    different result sets — so we use a real Postgres session.

    These tests pin the exact behaviour the PR-87 review surfaced as
    correct: only edges whose recorded proxy/beacon fields actually
    link parent and dep grant structural propagation. The Lido stETH
    shape (member parent has a ``relationship_type='proxy'`` dep edge,
    but the parent's ``implementation`` field doesn't point to the
    dep) must NOT propagate ownership. Under the membership gate,
    ``parent_is_member`` is derived from the parent's MEMBERSHIP
    (``protocol_id`` set), never its source tags.
    """

    @staticmethod
    def _member_protocol(db_session) -> int:
        from db.models import Protocol

        row = Protocol(name=f"struct-prop-{uuid.uuid4().hex[:12]}")
        db_session.add(row)
        db_session.commit()
        return row.id

    @staticmethod
    def _make_parent(
        db_session,
        *,
        protocol_id: int | None,
        sources: list[str] | None,
        implementation: str | None = None,
        beacon: str | None = None,
        chain: str | None = None,
    ):
        from db.models import Contract

        addr = "0x" + uuid.uuid4().hex[:40].zfill(40)
        parent = Contract(
            address=addr,
            chain=chain,
            protocol_id=protocol_id,
            contract_name="StructParent",
            discovery_sources=sources,
            is_proxy=bool(implementation or beacon),
            implementation=implementation,
            beacon=beacon,
        )
        db_session.add(parent)
        db_session.commit()
        return parent

    @staticmethod
    def _make_dep_edge(db_session, *, parent, dep_addr: str, relationship_type: str):
        from db.models import ContractDependency

        db_session.add(
            ContractDependency(
                contract_id=parent.id,
                dependency_address=dep_addr,
                relationship_type=relationship_type,
                source=["dynamic"],
            )
        )
        db_session.commit()

    @staticmethod
    def _make_proxy_orphan(db_session, *, addr: str, implementation: str | None = None, chain: str | None = None):
        """Pre-seed the dep address as an existing Contract row whose
        ``implementation`` points back at the parent — the proxy-direction
        check requires the dep's row to exist with the back-link."""
        from db.models import Contract

        row = Contract(
            address=addr,
            chain=chain,
            protocol_id=None,
            contract_name="DepProxy",
            is_proxy=True,
            implementation=implementation,
        )
        db_session.add(row)
        db_session.commit()
        return row

    @staticmethod
    def _link_parent_to_real_job(db_session, parent) -> Any:
        """Create a real Job row and attach the parent Contract to it.
        ``_queue_discovered_contracts`` selects the parent via
        ``Contract.job_id == job.id``; without a real Job the FK fails."""
        from db.models import Job, JobStage, JobStatus

        real_job = Job(
            id=uuid.uuid4(),
            stage=JobStage.resolution,
            status=JobStatus.processing,
            request={"rpc_url": "rpc"},
        )
        db_session.add(real_job)
        db_session.commit()
        parent.job_id = real_job.id
        db_session.commit()
        return _job(id=real_job.id, request={"rpc_url": "rpc"})

    @requires_postgres
    def test_implementation_edge_grants_structural_ownership(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Member parent + ``relationship_type='implementation'`` edge +
        ``parent.implementation == dep_addr`` → child request carries
        ``discovery_relationship='implementation'`` and
        ``parent_is_member=True``. This is the strongest case for
        propagation."""
        session = db_session_for_resolution
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        parent = self._make_parent(
            session,
            protocol_id=self._member_protocol(session),
            sources=["deployer_expansion"],
            implementation=dep_addr,
        )
        self._make_dep_edge(session, parent=parent, dep_addr=dep_addr, relationship_type="implementation")

        # Parent's Contract row is found via Contract.job_id == job.id, so
        # create a real Job row to satisfy the FK and let the lookup hit.
        from db.models import Job, JobStage, JobStatus

        real_job = Job(
            id=uuid.uuid4(),
            stage=JobStage.resolution,
            status=JobStatus.processing,
            request={"rpc_url": "rpc"},
        )
        session.add(real_job)
        session.commit()
        parent.job_id = real_job.id
        session.commit()
        job = _job(id=real_job.id, request={"rpc_url": "rpc"})

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": dep_addr, "node_type": "contract", "analyzed": True}])
        ResolutionWorker()._queue_discovered_contracts(session, cast(Any, job), graph, "rpc")

        assert len(create_calls) == 1
        assert create_calls[0]["discovery_relationship"] == "implementation"
        assert create_calls[0]["parent_is_member"] is True

    @requires_postgres
    def test_beacon_edge_grants_structural_ownership(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Member parent + ``relationship_type='beacon'`` edge +
        ``parent.beacon == dep_addr`` → child inherits."""
        session = db_session_for_resolution
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        parent = self._make_parent(
            session,
            protocol_id=self._member_protocol(session),
            sources=["ai_inventory"],
            beacon=dep_addr,
        )
        self._make_dep_edge(session, parent=parent, dep_addr=dep_addr, relationship_type="beacon")

        job = self._link_parent_to_real_job(session, parent)

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": dep_addr, "node_type": "contract", "analyzed": True}])
        ResolutionWorker()._queue_discovered_contracts(session, cast(Any, job), graph, "rpc")

        assert len(create_calls) == 1
        assert create_calls[0]["discovery_relationship"] == "beacon"
        assert create_calls[0]["parent_is_member"] is True

    @requires_postgres
    def test_proxy_edge_grants_when_dep_implementation_back_links(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Proxy direction: parent is the impl, dep is a proxy whose
        ``implementation`` is the parent. The structural check requires
        a Contract row for the dep with that back-link — exercises the
        batched dep-Contract lookup path in the worker."""
        session = db_session_for_resolution
        parent_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        protocol_id = self._member_protocol(session)

        from db.models import Contract, ContractDependency

        parent = Contract(
            address=parent_addr,
            protocol_id=protocol_id,
            contract_name="ImplParent",
            discovery_sources=["defillama"],
        )
        session.add(parent)
        session.commit()
        # Dep is a proxy that points back at the parent impl.
        session.add(
            Contract(
                address=dep_addr,
                protocol_id=None,
                contract_name="DepProxy",
                is_proxy=True,
                implementation=parent_addr,
            )
        )
        session.add(
            ContractDependency(
                contract_id=parent.id,
                dependency_address=dep_addr,
                relationship_type="proxy",
                source=["dynamic"],
            )
        )
        session.commit()

        # The witness pass runs the event-1 probe for unprobed candidates;
        # this test pins the W2 edge logic, so mark the dep already probed
        # (chain is NULL here → the unresolvable-chain attempt key).
        from db.models import ContractProbeAttempt
        from services.discovery.probes import UNRESOLVABLE_CHAIN_ID

        dep_row_id = session.query(Contract).filter_by(address=dep_addr).one().id
        session.add(
            ContractProbeAttempt(contract_id=dep_row_id, chain_id=UNRESOLVABLE_CHAIN_ID, results={"status": "probed"})
        )
        session.commit()

        from db.models import Job, JobStage, JobStatus

        real_job = Job(
            id=uuid.uuid4(),
            stage=JobStage.resolution,
            status=JobStatus.processing,
            request={"rpc_url": "rpc"},
        )
        session.add(real_job)
        session.commit()
        parent.job_id = real_job.id
        session.commit()
        job = _job(id=real_job.id, request={"rpc_url": "rpc"})

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": dep_addr, "node_type": "contract", "analyzed": True}])
        ResolutionWorker()._queue_discovered_contracts(session, cast(Any, job), graph, "rpc")

        assert len(create_calls) == 1
        assert create_calls[0]["discovery_relationship"] == "proxy"
        assert create_calls[0]["parent_is_member"] is True

        # The perimeter is the W2 producer now: the back-linked dep row was
        # nominated and earned a structural witness via the member parent —
        # but no protocol_id stamp (W1 is still missing).
        from db.models import WITNESS_RULE_W2_STRUCTURAL, ContractMembershipWitness

        dep_row = session.query(Contract).filter_by(address=dep_addr).one()
        assert dep_row.protocol_id is None
        assert dep_row.nominated_protocol_id == protocol_id
        witness = (
            session.query(ContractMembershipWitness)
            .filter_by(contract_id=dep_row.id, rule=WITNESS_RULE_W2_STRUCTURAL)
            .one()
        )
        assert witness.via_address == parent_addr
        assert witness.revoked_at is None
        assert witness.evidence["edge_kind"] == "proxy"

    @requires_postgres
    def test_proxy_back_link_on_another_chain_does_not_propagate(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The dep's back-linking Contract row exists only on ANOTHER chain
        (CREATE2 twin): the back-link is not evidence on the parent's chain,
        so the child must not inherit (readiness §2.5)."""
        session = db_session_for_resolution
        parent_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()

        from db.models import Contract, ContractDependency

        parent = Contract(
            address=parent_addr,
            chain="ethereum",
            protocol_id=self._member_protocol(session),
            contract_name="ImplParent",
            discovery_sources=["defillama"],
        )
        session.add(parent)
        session.commit()
        # The only row carrying the back-link is the same-address twin on base.
        session.add(
            Contract(
                address=dep_addr,
                chain="base",
                protocol_id=None,
                contract_name="DepProxyTwin",
                is_proxy=True,
                implementation=parent_addr,
            )
        )
        session.add(
            ContractDependency(
                contract_id=parent.id,
                dependency_address=dep_addr,
                relationship_type="proxy",
                source=["dynamic"],
            )
        )
        session.commit()

        from db.models import Job, JobStage, JobStatus

        real_job = Job(
            id=uuid.uuid4(),
            stage=JobStage.resolution,
            status=JobStatus.processing,
            request={"rpc_url": "rpc"},
        )
        session.add(real_job)
        session.commit()
        parent.job_id = real_job.id
        session.commit()
        job = _job(id=real_job.id, request={"rpc_url": "rpc"})

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": dep_addr, "node_type": "contract", "analyzed": True}])
        ResolutionWorker()._queue_discovered_contracts(session, cast(Any, job), graph, "rpc")

        assert len(create_calls) == 1
        assert "discovery_relationship" not in create_calls[0], (
            "a cross-chain twin's back-link satisfied the structural check — the lookup is no longer chain-scoped"
        )
        assert "parent_is_member" not in create_calls[0]

    @requires_postgres
    def test_relationship_type_alone_does_not_propagate(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression for the PR-87 review bug: member parent has an edge
        with ``relationship_type='proxy'`` but the parent's stored
        ``implementation`` does NOT equal the dep address (Lido stETH
        shape — etherfi calls stETH, stETH is *a* proxy, but stETH is
        not etherfi's proxy). The child must NOT receive
        ``discovery_relationship``."""
        session = db_session_for_resolution
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        unrelated_impl = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        # Parent has SOME implementation set but it's not dep_addr.
        parent = self._make_parent(
            session,
            protocol_id=self._member_protocol(session),
            sources=["deployer_expansion"],
            implementation=unrelated_impl,
        )
        self._make_dep_edge(session, parent=parent, dep_addr=dep_addr, relationship_type="proxy")

        job = self._link_parent_to_real_job(session, parent)

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": dep_addr, "node_type": "contract", "analyzed": True}])
        ResolutionWorker()._queue_discovered_contracts(session, cast(Any, job), graph, "rpc")

        assert len(create_calls) == 1
        assert "discovery_relationship" not in create_calls[0], (
            "structural propagation fired on relationship_type alone — Lido stETH shape is no longer being filtered out"
        )
        assert "parent_is_member" not in create_calls[0]

    @requires_postgres
    def test_non_member_parent_blocks_propagation(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Parent is not a member (``protocol_id`` NULL) — its source tags are
        irrelevant. Even with a perfect structural link, ``parent_is_member``
        lands False and no witness can be produced: only a member's stored
        resolution admits (spec §3.2 W2)."""
        session = db_session_for_resolution
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        parent = self._make_parent(
            session,
            protocol_id=None,
            sources=["deployer_expansion"],
            implementation=dep_addr,
        )
        self._make_dep_edge(session, parent=parent, dep_addr=dep_addr, relationship_type="implementation")

        job = self._link_parent_to_real_job(session, parent)

        create_calls: list[dict] = []

        def _fake_create(_s, req, **kw):
            create_calls.append(req)
            return SimpleNamespace(id=uuid.uuid4(), company=None)

        monkeypatch.setattr("workers.resolution_worker.create_job", _fake_create)
        monkeypatch.setattr("services.discovery.perimeter.create_job", _fake_create)

        graph = _resolved_graph(nodes=[{"address": dep_addr, "node_type": "contract", "analyzed": True}])
        ResolutionWorker()._queue_discovered_contracts(session, cast(Any, job), graph, "rpc")

        assert len(create_calls) == 1
        # The relationship is still passed (parent IS structurally linked),
        # but parent_is_member is False — gate's structural branch will
        # decline to adopt.
        assert create_calls[0].get("parent_is_member") is False


class TestResolvedGraphEmpty:
    """An empty graph does not create a second artifact."""

    def test_graph_empty_skips_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        job = _job()

        def fake_resolve_empty(
            *,
            root_artifacts: Any = None,
            rpc_url: str = "",
            max_depth: int = 6,
            workspace_prefix: str = "",
            nested_artifacts_override: Any = None,
            **_kw: Any,
        ) -> tuple[dict, dict]:
            return {}, {}

        ctx = _patch_all(monkeypatch)
        monkeypatch.setattr("workers.resolution_worker.resolve_control_graph", fake_resolve_empty)

        worker.process(session, cast(Any, job))

        stored_names = [name for name, _ in ctx["store_calls"]]
        assert "assessment" in stored_names
        assert "control_snapshot" not in stored_names
        assert "resolved_control_graph" not in stored_names


# ---------------------------------------------------------------------------
# 10. The persistence boundary for the three-state columns.
#
# ``authority_provenance`` / ``analysis_state`` / ``graph_max_depth`` were added
# with in-memory assertions only: every test stopped at the artifact dict. This
# is the hop where "absent in the snapshot => SQL NULL" either holds or quietly
# becomes a value, and where the jsonb-null trap lives (a Python ``None`` written
# into a JSONB column lands as the jsonb scalar ``null``, which passes an
# ``IS NULL`` test and is NOT the same as no value). Asserted through the real
# ``ResolutionWorker.process`` writes, in SQL, with a present row and an absent
# row in the SAME pass so neither state can be a fixture artifact.
# ---------------------------------------------------------------------------


@requires_postgres
def test_three_state_columns_reach_postgres_and_absence_lands_sql_null(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import text

    from db.models import Contract, Job, JobStage, JobStatus

    determined = "0x" + "d1" * 20
    undetermined = "0x" + "d2" * 20

    real_job = Job(
        id=uuid.uuid4(),
        address=TARGET_ADDRESS,
        chain_id=1,
        stage=JobStage.resolution,
        status=JobStatus.processing,
        request={"rpc_url": "rpc", "chain": "ethereum"},
    )
    db_session.add(real_job)
    db_session.commit()
    contract = Contract(address=TARGET_ADDRESS, chain="ethereum", job_id=real_job.id)
    db_session.add(contract)
    db_session.commit()

    snapshot = {
        "contract_address": TARGET_ADDRESS,
        "block_number": 100,
        "controller_values": {
            # PROVEN: the tracked controller gates callers, and the read carried
            # a details payload.
            "gate": {
                "value": determined,
                "resolved_type": "contract",
                "source": "storage",
                "details": {"read": "getter_call"},
                "authority_provenance": "caller_gate",
            },
            # NOT DETERMINED: the plan carried no provenance for this slot and
            # the read produced no details. Both must land SQL NULL — not the
            # empty string, not the jsonb scalar null.
            "silent": {
                "value": undetermined,
                "resolved_type": "contract",
                "source": "storage",
            },
        },
    }
    graph = {
        "root_contract_address": TARGET_ADDRESS,
        "max_depth": 6,
        "nodes": [
            {
                "address": determined,
                "node_type": "contract",
                "resolved_type": "safe",
                "label": "Gate",
                "depth": 1,
                "analyzed": False,
                "analysis_state": "not_analyzable",
            },
            {
                "address": undetermined,
                "node_type": "contract",
                "resolved_type": "unknown",
                "label": "Silent",
                "depth": 1,
                "analyzed": False,
                # analysis_state ABSENT — the honest fifth state.
            },
        ],
        "edges": [],
    }

    _patch_all(monkeypatch, snapshot=snapshot, resolved_graph=graph)
    ResolutionWorker().process(db_session, cast(Any, _job(id=real_job.id, request=real_job.request)))

    cv_rows = {
        cid: (prov, details_typeof, details_is_sql_null)
        for cid, prov, details_typeof, details_is_sql_null in db_session.execute(
            text(
                "select controller_id, authority_provenance, jsonb_typeof(details), details is null"
                " from controller_values where contract_id = :cid"
            ),
            {"cid": contract.id},
        ).all()
    }
    # Proven-present round-trips verbatim; the details payload is a real object.
    assert cv_rows["gate"] == ("caller_gate", "object", False)
    # Not-determined is SQL NULL on both columns. ``jsonb_typeof`` is the
    # discriminator that an ``IS NULL`` test cannot make: the trap value would
    # report typeof 'null' with ``details is null`` also true.
    assert cv_rows["silent"] == (None, None, True)

    node_rows = {
        addr: (state, max_depth, analyzed)
        for addr, state, max_depth, analyzed in db_session.execute(
            text(
                "select address, analysis_state, graph_max_depth, analyzed"
                " from control_graph_nodes where contract_id = :cid"
            ),
            {"cid": contract.id},
        ).all()
    }
    # Proven-present, plus the walk's horizon that makes ``depth`` interpretable.
    assert node_rows[determined] == ("not_analyzable", 6, False)
    # Absent in the graph => SQL NULL, never a guessed token. ``graph_max_depth``
    # is a fact about the WALK, so it is present on every node of that walk.
    assert node_rows[undetermined] == (None, 6, False)
    assert (
        db_session.execute(
            text("select count(*) from control_graph_nodes where contract_id = :cid and analysis_state = 'null'"),
            {"cid": contract.id},
        ).scalar()
        == 0
    ), "not-determined was persisted as the four-character string 'null'"


@requires_postgres
def test_graph_without_max_depth_persists_sql_null_not_zero(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    """The adverse branch of ``graph_max_depth``: a graph that never recorded its
    horizon must persist NULL. ``0`` would read as a real horizon and make every
    node at depth >= 1 look deliberately cut off."""
    from sqlalchemy import text

    from db.models import Contract, Job, JobStage, JobStatus

    real_job = Job(
        id=uuid.uuid4(),
        address=TARGET_ADDRESS,
        chain_id=1,
        stage=JobStage.resolution,
        status=JobStatus.processing,
        request={"rpc_url": "rpc", "chain": "ethereum"},
    )
    db_session.add(real_job)
    db_session.commit()
    contract = Contract(address=TARGET_ADDRESS, chain="ethereum", job_id=real_job.id)
    db_session.add(contract)
    db_session.commit()

    graph = _resolved_graph(
        nodes=[
            {
                "address": CHILD_ADDRESS,
                "node_type": "contract",
                "resolved_type": "eoa",
                "label": "child",
                "depth": 1,
                "analyzed": False,
                "analysis_state": "not_analyzable",
            }
        ]
    )
    assert "max_depth" not in graph

    _patch_all(monkeypatch, resolved_graph=graph)
    ResolutionWorker().process(db_session, cast(Any, _job(id=real_job.id, request=real_job.request)))

    row = db_session.execute(
        text("select analysis_state, graph_max_depth from control_graph_nodes where contract_id = :cid"),
        {"cid": contract.id},
    ).first()
    assert row is not None
    assert row[0] == "not_analyzable"
    assert row[1] is None
