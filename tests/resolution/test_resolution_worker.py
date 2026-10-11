from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from db.models import Contract, ContractBalance, ContractBalanceFetch
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from tests.support.balance_stubs import page, pinned_native_unavailable
from tests.support.resolution_worker_stubs import (
    CHILD_ADDRESS,
    PROXY_ADDRESS,
    TARGET_ADDRESS,
    _job,
    _patch_all,
    _resolved_graph,
)
from utils.balance_status import NATIVE_STATUS_NOT_DETERMINED
from workers.resolution_worker import ResolutionWorker


@pytest.fixture(autouse=True)
def _stub_etherscan_balances(monkeypatch):
    """Etherscan balance probes default to empty.

    The pinned native read is a separate wire, so the module takes the unpinned path.
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


def _added(session) -> list:
    return list(session.scalars(select(ContractBalance))) + list(session.scalars(select(ContractBalanceFetch)))


def _balance_rows(session) -> int:
    """HOLDINGS rows only; the fetch-provenance row is not a holding and must never be counted as one."""
    return sum(1 for o in _added(session) if isinstance(o, ContractBalance))


def _fetch_objects(session) -> list:
    return [o for o in _added(session) if isinstance(o, ContractBalanceFetch)]


class TestFetchBalancesEarlyReturn:
    def test_no_address_returns_early(self) -> None:
        worker = ResolutionWorker()
        session = MagicMock()
        job = _job(address=None)
        fake_contract = SimpleNamespace(id=42, address=TARGET_ADDRESS, protocol_id=None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)
        session.add.assert_not_called()


@requires_postgres
class TestFetchBalancesZeroEth:
    def test_zero_eth_no_row(self, monkeypatch: pytest.MonkeyPatch, db_session) -> None:
        worker = ResolutionWorker()
        session = db_session
        fake_contract = Contract(address=TARGET_ADDRESS, chain="ethereum")
        session.add(fake_contract)
        session.commit()
        job = _job()

        monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 0)
        monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
        monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

        cast(Any, worker)._fetch_balances(session, job, fake_contract, chain_id=1)

        # A zero-balance row would read as "holds the native asset"; the unpinned read has no height, so the fetch plane
        # records ``not_determined``, never ``proven_zero``.
        assert _balance_rows(session) == 0
        fetches = sorted(_fetch_objects(session), key=lambda f: f.native_status == "unattempted")
        assert len(fetches) == 2
        assert fetches[0].native_status == NATIVE_STATUS_NOT_DETERMINED
        assert fetches[0].block_number is None


@requires_postgres
class TestFetchBalancesProxyAddress:
    """Read address and filed row are one decision; reading the proxy but filing against the implementation let a
    later read evict a real balance. The proxy-has-a-row arm is in ``test_contract_balance_provenance.py``.
    """

    def test_an_unowned_proxy_address_is_not_read_against_a_foreign_row(
        self, monkeypatch: pytest.MonkeyPatch, db_session
    ) -> None:
        worker = ResolutionWorker()
        session = db_session
        fake_contract = Contract(address=TARGET_ADDRESS, chain="ethereum")
        session.add(fake_contract)
        session.commit()

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


class TestQueueDiscoveredContractsParentChainEdgeCases:
    def test_multi_level_parent_walk(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
        monkeypatch.setattr("services.discovery.perimeter.create_job", fake_create_job)

        graph = _resolved_graph(nodes=[{"address": CHILD_ADDRESS, "node_type": "contract", "analyzed": True}])
        job = _job(company=None, request={"rpc_url": "https://rpc.example", "parent_job_id": parent_id})
        worker._queue_discovered_contracts(session, cast(Any, job), graph, "https://rpc.example")

        assert len(create_calls) == 1
        assert child_ns.company == "GrandCorp"


@requires_postgres
def test_dependency_emission_walks_check_trees(db_session_for_resolution):
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
    store_artifact(session, provider_job.id, "effective_permissions", data={"functions": []})

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


@pytest.mark.parametrize("proxy", [False, True])
def test_terminal_provider_does_not_leave_late_dependency_pending(db_session_for_resolution, proxy):
    from db.models import JobDependency, JobStage, JobStatus
    from db.queue import claim_job, create_job, store_artifact

    session = db_session_for_resolution
    target, implementation, depender = ["0x" + byte * 20 for byte in ("91", "92", "93")]
    provider = create_job(session, {"address": target, "chain": "ethereum"})
    provider.status = JobStatus.completed if proxy else JobStatus.failed_terminal
    provider.stage = JobStage.done if proxy else JobStage.discovery
    if proxy:
        session.add(
            Contract(address=target, chain="ethereum", job_id=provider.id, is_proxy=True, implementation=implementation)
        )
        child = create_job(session, {"address": implementation, "chain": "ethereum", "parent_job_id": str(provider.id)})
        child.status = JobStatus.failed_terminal
    session.commit()
    job = create_job(session, {"address": depender, "chain": "ethereum"}, initial_stage=JobStage.policy)
    store_artifact(session, job.id, "predicate_trees", data=_authority_check_predicate_trees())
    snapshot = {"controller_values": {"external_contract:authority": {"value": target}}}
    ResolutionWorker()._emit_dependency_edges_from_predicate_trees(
        session, job, cast(Any, snapshot), "http://rpc.example"
    )
    edge = session.execute(select(JobDependency).where(JobDependency.depender_job_id == job.id)).scalar_one()
    assert edge.provider_address == (implementation if proxy else target)
    assert edge.status == "degraded"
    claimed = claim_job(session, JobStage.policy, "test-worker")
    assert claimed is not None and claimed.id == job.id


def test_slot_backed_authority_enqueues_provider_at_runtime_address(db_session_for_resolution, monkeypatch):
    from db.models import JobDependency, JobStage
    from db.queue import create_job, store_artifact

    session = db_session_for_resolution
    runtime, implementation, target = ["0x" + byte * 20 for byte in ("81", "82", "83")]
    job = create_job(
        session,
        {"address": implementation, "proxy_address": runtime, "chain": "ethereum"},
        initial_stage=JobStage.resolution,
    )
    trees = _authority_check_predicate_trees()
    source = trees["check_trees"]["canCall(address,address,bytes4)"]["leaf"]["set_descriptor"]["authority_contract"]
    slot = "0x" + f"{123:064x}"
    source["address_source"] = {"source": "view_call", "storage_slot": slot}
    store_artifact(session, job.id, "predicate_trees", data=trees)
    calls = []

    def rpc(url, method, params, **kwargs):
        calls.append((method, params))
        return "0x" + "00" * 12 + target[2:]

    monkeypatch.setattr("services.clients.rpc.rpc_request", rpc)
    ResolutionWorker()._emit_dependency_edges_from_predicate_trees(
        session, job, cast(Any, {"block_number": 100, "controller_values": {}}), "http://rpc.example"
    )
    edge = session.execute(select(JobDependency).where(JobDependency.depender_job_id == job.id)).scalar_one()
    assert edge.provider_address == target
    assert edge.status == "pending"
    assert calls == [("eth_getStorageAt", [runtime, slot, "0x64"])]


def test_dependency_emission_records_pending_status_metrics(db_session_for_resolution):
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
    """The count was previously discarded, hiding the unblock."""
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


class TestStructuralOwnershipPropagation:
    """PR-87 review: only edges whose proxy/beacon fields actually link parent and dep propagate, so the Lido stETH
    shape must not. ``parent_is_member`` comes from membership, never source tags. Real Postgres because mocks
    can't serve the multiple result sets.
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
        """The parent lookup uses ``Contract.job_id``, so the FK needs a real Job."""
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
    def test_beacon_edge_grants_structural_ownership(
        self, db_session_for_resolution, monkeypatch: pytest.MonkeyPatch
    ) -> None:
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

        # Mark the dep already probed so the witness pass skips its event-1 probe.
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

        # W2 structural witness via the member parent, but no protocol_id stamp.
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
        """The back-linking row exists only on ANOTHER chain (CREATE2 twin): not evidence on the parent's chain."""
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
        """PR-87 review: stETH is *a* proxy, not etherfi's."""
        session = db_session_for_resolution
        dep_addr = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
        unrelated_impl = ("0x" + uuid.uuid4().hex[:40].zfill(40)).lower()
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
        """A non-member parent (``protocol_id`` NULL): source tags are irrelevant, ``parent_is_member``
        is False and no witness is produced (W2)."""
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
        assert create_calls[0].get("parent_is_member") is False


# The persistence boundary for the three-state columns, asserted in SQL with a present and an absent row in
# the same pass. Python ``None`` in a JSONB column lands as the jsonb scalar ``null``, which passes ``IS NULL``
# yet is not "no value".


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
            "gate": {
                "value": determined,
                "resolved_type": "contract",
                "source": "storage",
                "details": {"read": "getter_call"},
                "authority_provenance": "caller_gate",
            },
            # Both must land SQL NULL, not "" or jsonb null.
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
    assert cv_rows["gate"] == ("caller_gate", "object", False)
    # ``jsonb_typeof`` discriminates what ``IS NULL`` cannot.
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
    assert node_rows[determined] == ("not_analyzable", 6, False)
    # ``graph_max_depth`` is a fact about the walk, present on every node.
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
    """``0`` would make every node at depth >= 1 look cut off."""
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
