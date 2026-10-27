"""The current implementation of a known proxy ends in the same state whatever order the proxy and the implementation
are submitted in: one implementation job holds the contract row, carries the proxy's context, resolves against the
proxy's storage, and is the one the proxy's card renders.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

GOVERNOR = "0x" + "a1" * 20
STALE_GOVERNOR = "0x" + "b2" * 20
ZERO = "0x" + "00" * 20


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


@pytest.fixture(autouse=True)
def _stub_membership_probe(monkeypatch):
    from services.discovery.probes import ProbeResult

    monkeypatch.setattr(
        "services.discovery.membership_gate.probe",
        lambda session, contract: ProbeResult(contract_id=contract.id, chain_id=None, routable=False),
    )


def _age(session, job, seconds: int) -> None:
    from db.models import Job

    stamp = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    session.execute(sa_update(Job).where(Job.id == job.id).values(updated_at=stamp))
    session.commit()


def _proxy(session, proxy: str, impl: str | None, *, proxy_type: str = "eip1967"):
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job

    job = create_job(session, {"address": proxy, "chain": "ethereum", "rpc_url": "http://stub"})
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    row = Contract(
        job_id=job.id,
        address=proxy,
        chain="ethereum",
        contract_name="Proxy",
        is_proxy=True,
        proxy_type=proxy_type,
        implementation=impl,
    )
    session.add(row)
    session.flush()
    session.add(ContractSummary(contract_id=row.id, control_model="proxy"))
    session.commit()
    return job, row


def _analysed_impl(session, impl: str, *, proxy: str | None = None):
    """A completed analysis of *impl* holding its contract row, with the static bundle a cache hit copies."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, ContractSummary, JobStage, JobStatus
    from db.queue import create_job, store_artifact, store_source_files

    request = {"address": impl, "chain": "ethereum", "rpc_url": "http://stub"}
    if proxy is not None:
        request.update(proxy_address=proxy, proxy_type="eip1967", discovery_relationship="implementation")
    job = create_job(session, request)
    job.status = JobStatus.completed
    job.stage = JobStage.done
    job.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    session.commit()

    row = session.query(Contract).filter(Contract.address == impl, Contract.chain == "ethereum").one_or_none()
    if row is None:
        row = Contract(address=impl, chain="ethereum", contract_name="Core", source_verified=True)
        session.add(row)
        session.flush()
        session.add(ContractSummary(contract_id=row.id, control_model="ownable"))
    row.job_id = job.id
    session.commit()

    store_source_files(session, job.id, {"src/Core.sol": "contract Core { address governor; }"})
    store_artifact(session, job.id, "contract_analysis", data={"subject": {"address": impl}, "contract_name": "Core"})
    store_artifact(
        session,
        job.id,
        "control_tracking_plan",
        data={"schema_version": "0.1", "contract_address": impl, "contract_name": "Core", "tracked_controllers": []},
    )
    store_artifact(
        session,
        job.id,
        "predicate_trees",
        data={"schema_version": "semantic", "contract_name": "Core", "trees": {}, "check_trees": {}},
    )
    store_artifact(session, job.id, "effects", data={"schema_version": "semantic", "functions": {}})
    return job, row


def _submit(session, impl: str, **extra):
    from db.queue import create_job

    return create_job(session, {"address": impl, "chain": "ethereum", "rpc_url": "http://stub", **extra})


def _discovery(monkeypatch):
    from workers.discovery import DiscoveryWorker

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda _addr, **_kw: {
            "ContractName": "Core",
            "CompilerVersion": "v0.8.24+commit.e11b9ed9",
            "SourceCode": "pragma solidity ^0.8.24; contract Core { address governor; }",
            "OptimizationUsed": "1",
            "Runs": "200",
            "EVMVersion": "shanghai",
            "LicenseType": "MIT",
        },
    )
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addresses, **kw: {})
    return worker


def _resolve(session, monkeypatch, job, *, proxy: str) -> None:
    """Resolution with only the wire stubbed; the governor reads as set only when read at the proxy."""
    from workers.resolution_worker import ResolutionWorker

    def fake_snapshot(plan, rpc_url, *_a, **_k):
        read_addr = (plan.get("contract_address") or "").lower()
        return {
            "contract_address": read_addr,
            "block_number": 7_000_000,
            "controller_values": {
                "state_variable:governor": {
                    "value": GOVERNOR if read_addr == proxy.lower() else ZERO,
                    "resolved_type": "eoa",
                    "details": {},
                    "source": "governor",
                    "block_number": 7_000_000,
                    "observed_via": "eth_call",
                }
            },
        }

    worker = ResolutionWorker()
    monkeypatch.setattr("workers.resolution_worker.build_control_snapshot", fake_snapshot)
    monkeypatch.setattr(
        "workers.resolution_worker.resolve_control_graph",
        lambda **_k: ({"root_contract_address": "", "nodes": [], "edges": []}, {}),
    )
    monkeypatch.setattr("workers.resolution_worker.store_nested_artifacts", lambda *a, **k: None)
    for name in ("_fetch_balances", "_queue_discovered_contracts", "_emit_dependency_edges_from_predicate_trees"):
        monkeypatch.setattr(worker, name, lambda *a, **k: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_heartbeat", lambda *a, **k: None)
    worker.process(session, job)


def _complete(session, job) -> None:
    from db.models import JobStage, JobStatus

    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()


def _card_impl(session, proxy_job):
    """The implementation job and contract the proxy's company-page card renders."""
    from services.aggregations.company_overview.entity_keys import _entity_key
    from services.aggregations.company_overview.jobs import prefetch_contracts, resolve_implementation_contracts

    contracts = prefetch_contracts(session, [proxy_job])
    impl_job_by_entity, contracts = resolve_implementation_contracts(session, [proxy_job], contracts)
    proxy_row = contracts[proxy_job.id]
    impl_job = impl_job_by_entity.get(_entity_key(proxy_row.chain, proxy_row.implementation))
    return impl_job, contracts.get(impl_job.id) if impl_job is not None else None


def _assert_proxy_context(job, proxy: str) -> None:
    request = job.request or {}
    assert request.get("proxy_address") == proxy.lower(), request
    assert request.get("proxy_type") == "eip1967", request
    assert request.get("discovery_relationship") == "implementation", request


def test_impl_resubmitted_after_its_proxy_runs_in_the_proxy_context(db_session, monkeypatch):
    from db.models import WITNESS_RULE_W2_STRUCTURAL, Contract, ContractMembershipWitness, ControllerValue, Protocol
    from db.queue import reconcile_impl_job_for_proxy
    from services.discovery import membership_gate
    from services.discovery.membership_gate import (
        HUMAN_ASSERTION_REQUEST_KEY,
        HumanAssertion,
        human_assertion_request_payload,
    )

    proxy, impl = _addr(), _addr()
    proxy_job, proxy_row = _proxy(db_session, proxy, impl)
    proxy_impl_job, impl_row = _analysed_impl(db_session, impl, proxy=proxy)
    db_session.add(
        ControllerValue(
            contract_id=impl_row.id,
            deployment_address=proxy,
            controller_id="state_variable:governor",
            value=STALE_GOVERNOR,
        )
    )
    protocol = Protocol(name=f"Proto-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    proxy_row.protocol_id = protocol.id
    db_session.commit()
    _age(db_session, proxy_impl_job, 3600)

    nominations: list[tuple[str, object]] = []
    real_nominate = membership_gate.nominate

    def spy(session, *, contract, protocol_id, source_tag, human_assertion=None):
        nominations.append((contract.address, human_assertion))
        return real_nominate(
            session, contract=contract, protocol_id=protocol_id, source_tag=source_tag, human_assertion=human_assertion
        )

    monkeypatch.setattr(membership_gate, "nominate", spy)

    assertion = human_assertion_request_payload(HumanAssertion(actor="admin", asserted_at=datetime.now(timezone.utc)))
    submitted = _submit(db_session, impl, protocol_id=protocol.id, **{HUMAN_ASSERTION_REQUEST_KEY: assertion})
    _discovery(monkeypatch)._process_address(db_session, submitted)

    db_session.refresh(submitted)
    _assert_proxy_context(submitted, proxy)
    assert (submitted.request or {}).get("cache_source_job_id") == str(proxy_impl_job.id)
    db_session.refresh(impl_row)
    assert impl_row.job_id == submitted.id
    assert nominations and all(addr == impl and ha is not None for addr, ha in nominations)
    assert impl_row.nominated_protocol_id == protocol.id
    assert (submitted.request or {}).get("parent_job_id") == str(proxy_job.id)
    structural = (
        db_session.query(ContractMembershipWitness)
        .filter(
            ContractMembershipWitness.contract_id == impl_row.id,
            ContractMembershipWitness.rule == WITNESS_RULE_W2_STRUCTURAL,
        )
        .all()
    )
    assert [(w.protocol_id, w.revoked_at) for w in structural] == [(protocol.id, None)]

    _resolve(db_session, monkeypatch, submitted, proxy=proxy)
    values = db_session.query(ControllerValue).filter(ControllerValue.contract_id == impl_row.id).all()
    assert [(v.deployment_address, v.value) for v in values] == [(proxy, GOVERNOR)]

    _complete(db_session, submitted)
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "skip"
    card_job, card_contract = _card_impl(db_session, proxy_job)
    assert card_job is not None and card_job.id == submitted.id
    assert card_contract is not None and card_contract.address == impl
    assert db_session.query(Contract).filter(Contract.address == impl).count() == 1


def test_impl_submitted_before_its_proxy_is_backpatched_by_the_proxy(db_session, monkeypatch):
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    proxy, impl = _addr(), _addr()
    submitted = _submit(db_session, impl)
    _discovery(monkeypatch)._process_address(db_session, submitted)
    db_session.refresh(submitted)
    assert "proxy_address" not in (submitted.request or {})

    _complete(db_session, submitted)
    _proxy(db_session, proxy, impl)
    decision = reconcile_impl_job_for_proxy(
        db_session, impl_addr=impl, proxy_addr=proxy, proxy_type="eip1967", chain="ethereum"
    )
    assert decision == "backpatched"
    db_session.refresh(submitted)
    _assert_proxy_context(submitted, proxy)
    assert (submitted.stage, submitted.status) == (JobStage.static, JobStatus.queued)


def test_impl_of_a_known_proxy_without_an_impl_job_takes_the_proxy_context(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import reconcile_impl_job_for_proxy

    proxy, impl = _addr(), _addr()
    _proxy(db_session, proxy, impl)
    submitted = _submit(db_session, impl)
    _discovery(monkeypatch)._process_address(db_session, submitted)

    db_session.refresh(submitted)
    _assert_proxy_context(submitted, proxy)
    row = db_session.query(Contract).filter(Contract.address == impl).one()
    assert row.job_id == submitted.id
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "skip"


def test_a_superseded_impl_keeps_its_standalone_analysis(db_session, monkeypatch):
    """An implementation the proxy was upgraded away from was once analysed behind it; a resubmission reads its own
    storage, as before, and the old proxy context is not carried over from that analysis."""
    proxy, old_impl, current_impl = _addr(), _addr(), _addr()
    _proxy(db_session, proxy, current_impl)
    behind_proxy, old_row = _analysed_impl(db_session, old_impl, proxy=proxy)
    _age(db_session, behind_proxy, 3600)

    submitted = _submit(db_session, old_impl)
    _discovery(monkeypatch)._process_address(db_session, submitted)

    db_session.refresh(submitted)
    assert "proxy_address" not in (submitted.request or {})
    assert (submitted.request or {}).get("cache_source_job_id") == str(behind_proxy.id)
    db_session.refresh(old_row)
    assert old_row.job_id == submitted.id


def test_a_shared_impl_takes_the_context_of_the_proxy_without_an_impl_job(db_session, monkeypatch):
    from db.queue import reconcile_impl_job_for_proxy

    covered, uncovered, impl = _addr(), _addr(), _addr()
    _proxy(db_session, covered, impl)
    _proxy(db_session, uncovered, impl)
    covered_impl_job, impl_row = _analysed_impl(db_session, impl, proxy=covered)

    submitted = _submit(db_session, impl)
    _discovery(monkeypatch)._process_address(db_session, submitted)

    db_session.refresh(submitted)
    _assert_proxy_context(submitted, uncovered)
    db_session.refresh(covered_impl_job)
    assert (covered_impl_job.request or {}).get("proxy_address") == covered
    for proxy in (covered, uncovered):
        assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "skip"


def test_a_conversion_landing_mid_discovery_survives_the_discovery_request_write(db_session, monkeypatch):
    """The proxy's static stage converts the impl job between its discovery claim and the cache-hit request write."""
    from db.models import Contract, Job
    from db.queue import copy_static_cache, reconcile_impl_job_for_proxy

    proxy, impl = _addr(), _addr()
    _, proxy_row = _proxy(db_session, proxy, None)
    donor, _ = _analysed_impl(db_session, impl)
    _age(db_session, donor, 3600)
    submitted = _submit(db_session, impl)

    decisions: list[str] = []

    def copy_then_proxy_static_runs(session, src, dst):
        copied = copy_static_cache(session, src, dst)
        with Session(db_session.get_bind(), expire_on_commit=False) as proxy_worker:
            linked = proxy_worker.get(Contract, proxy_row.id)
            assert linked is not None
            linked.implementation = impl
            proxy_worker.commit()
            decisions.append(
                reconcile_impl_job_for_proxy(
                    proxy_worker, impl_addr=impl, proxy_addr=proxy, proxy_type="eip1967", chain="ethereum"
                )
            )
        return copied

    monkeypatch.setattr("workers.discovery.copy_static_cache", copy_then_proxy_static_runs)
    _discovery(monkeypatch)._process_address(db_session, submitted)

    assert decisions == ["backpatched"]
    with Session(db_session.get_bind()) as reader:
        stored = reader.get(Job, submitted.id)
        assert stored is not None
        _assert_proxy_context(stored, proxy)
        assert (stored.request or {}).get("static_cached") is True
        assert (stored.request or {}).get("cache_source_job_id") == str(donor.id)


def test_a_conversion_never_replaces_a_proxy_context_taken_meanwhile(db_session):
    """Two proxies sharing the implementation reconcile at once; the second to write must not take the first's job."""
    from db.models import Job
    from db.queue.jobs import _convert_impl_job_to_proxy_context

    first, second, impl = _addr(), _addr(), _addr()
    submitted = _submit(db_session, impl)

    with Session(db_session.get_bind(), expire_on_commit=False) as second_proxy_worker:
        stale = second_proxy_worker.get(Job, submitted.id)
        assert stale is not None and "proxy_address" not in (stale.request or {})
        first_converted = _convert_impl_job_to_proxy_context(db_session, submitted, proxy_addr=first)
        second_converted = _convert_impl_job_to_proxy_context(second_proxy_worker, stale, proxy_addr=second)

        db_session.refresh(submitted)
        assert (submitted.request or {}).get("proxy_address") == first
        assert (stale.request or {}).get("proxy_address") == first
        assert (first_converted, second_converted) == (True, False)


def _claim(session, stage):
    from db.queue import claim_job

    claimed = claim_job(session, stage, "test-worker")
    assert claimed is not None
    return claimed


def _backpatch_from_proxy_worker(db_session, impl: str, proxy: str) -> str:
    from db.queue import reconcile_impl_job_for_proxy

    with Session(db_session.get_bind(), expire_on_commit=False) as proxy_worker:
        return reconcile_impl_job_for_proxy(
            proxy_worker, impl_addr=impl, proxy_addr=proxy, proxy_type="eip1967", chain="ethereum"
        )


def test_a_conversion_during_static_reruns_static_in_the_proxy_context(db_session):
    """The running static worker keeps its lease and finishes; its exit sends the job back to static, so the stage
    that ran on the claim-time request is redone in the proxy's context and no second worker writes alongside it."""
    from db.models import Job, JobStage, JobStatus
    from db.queue import RESTART_STATIC_REQUEST_KEY, get_artifact, store_artifact
    from workers.base import BaseWorker

    proxy, impl = _addr(), _addr()
    submitted = _submit(db_session, impl)
    submitted.stage = JobStage.static
    db_session.commit()

    runs: list[str | None] = []
    decisions: list[str] = []

    class StaticStage(BaseWorker):
        stage = JobStage.static
        next_stage = JobStage.resolution

        def process(self, session, job):
            runs.append((job.request or {}).get("proxy_address"))
            if len(runs) == 1:
                decisions.append(_backpatch_from_proxy_worker(db_session, impl, proxy))
                with Session(db_session.get_bind()) as reader:
                    mid = reader.get(Job, job.id)
                    assert mid is not None
                    assert (mid.status, mid.lease_id) == (JobStatus.processing, job.lease_id)
            store_artifact(session, job.id, "contract_flags", data={"proxy_address": runs[-1]})

    worker = StaticStage()
    worker._execute_job(db_session, _claim(db_session, JobStage.static))

    db_session.refresh(submitted)
    assert decisions == ["backpatched"]
    assert (submitted.stage, submitted.status, submitted.lease_id) == (JobStage.static, JobStatus.queued, None)
    assert RESTART_STATIC_REQUEST_KEY not in (submitted.request or {})
    _assert_proxy_context(submitted, proxy)

    worker._execute_job(db_session, _claim(db_session, JobStage.static))
    db_session.refresh(submitted)
    assert runs == [None, proxy]
    assert (submitted.stage, submitted.status) == (JobStage.resolution, JobStatus.queued)
    assert get_artifact(db_session, submitted.id, "contract_flags") == {"proxy_address": proxy}


@pytest.mark.parametrize("exit_path", ["requeue", "terminal", "complete"])
def test_every_exit_of_a_stage_running_when_converted_returns_the_job_to_static(db_session, exit_path):
    from db.models import JobStage, JobStatus
    from db.queue import RESTART_STATIC_REQUEST_KEY, complete_job, fail_job_terminal, requeue_job

    proxy, impl = _addr(), _addr()
    submitted = _submit(db_session, impl)
    submitted.stage = JobStage.resolution
    db_session.commit()
    lease = _claim(db_session, JobStage.resolution).lease_id

    assert _backpatch_from_proxy_worker(db_session, impl, proxy) == "backpatched"
    db_session.refresh(submitted)
    assert (submitted.status, submitted.lease_id) == (JobStatus.processing, lease)

    if exit_path == "requeue":
        requeue_job(
            db_session, submitted.id, "boom", retry_count=1, next_attempt_at=datetime.now(timezone.utc), lease_id=lease
        )
        expected = (JobStage.static, JobStatus.queued)
    elif exit_path == "terminal":
        fail_job_terminal(db_session, submitted.id, "boom", kind="terminal", lease_id=lease)
        expected = (JobStage.static, JobStatus.failed_terminal)
    else:
        complete_job(db_session, submitted.id, lease_id=lease)
        expected = (JobStage.static, JobStatus.queued)

    db_session.refresh(submitted)
    assert (submitted.stage, submitted.status) == expected
    assert RESTART_STATIC_REQUEST_KEY not in (submitted.request or {})
    _assert_proxy_context(submitted, proxy)
    if exit_path == "requeue":
        assert (submitted.retry_count, submitted.next_attempt_at) == (0, None)


@pytest.mark.parametrize("upgraded", [False, True], ids=["pointer_kept", "proxy_upgraded"])
def test_an_impl_waits_while_its_proxy_is_being_reanalysed(db_session, monkeypatch, upgraded):
    """The proxy row's pointer is not a witness while a run of that proxy can still rewrite it."""
    from db.models import Contract, JobStage, JobStatus
    from db.queue import create_job

    proxy, impl, new_impl = _addr(), _addr(), _addr()
    _, proxy_row = _proxy(db_session, proxy, impl)
    proxy_impl_job, impl_row = _analysed_impl(db_session, impl, proxy=proxy)
    _age(db_session, proxy_impl_job, 3600)
    submitted = _submit(db_session, impl)
    rerun = create_job(db_session, {"address": proxy, "chain": "ethereum"})

    worker = _discovery(monkeypatch)
    worker._execute_job(db_session, _claim(db_session, JobStage.discovery))

    db_session.refresh(submitted)
    assert (submitted.stage, submitted.status, submitted.retry_count) == (JobStage.discovery, JobStatus.queued, 0)
    assert submitted.next_attempt_at is not None and submitted.lease_id is None
    assert "proxy_address" not in (submitted.request or {})
    db_session.refresh(impl_row)
    assert impl_row.job_id == proxy_impl_job.id

    settled = db_session.get(Contract, proxy_row.id)
    assert settled is not None
    settled.job_id = rerun.id
    if upgraded:
        settled.implementation = new_impl
    rerun.status = JobStatus.completed
    rerun.stage = JobStage.done
    db_session.commit()

    worker._process_address(db_session, submitted)
    db_session.refresh(submitted)
    if upgraded:
        assert "proxy_address" not in (submitted.request or {})
    else:
        _assert_proxy_context(submitted, proxy)
        assert (submitted.request or {}).get("parent_job_id") == str(rerun.id)


def test_proxy_context_survives_the_cross_chain_reuse_request_write(db_session, monkeypatch):
    """The proxy converts the job while discovery copies a same-source donor's code plane from another chain."""
    from types import SimpleNamespace

    from db.models import Contract, Job

    proxy, impl = _addr(), _addr()
    _, proxy_row = _proxy(db_session, proxy, None)
    submitted = _submit(db_session, impl)
    donor_id = uuid.uuid4()
    decisions: list[str] = []

    def lookup(session, address, chain=None, source_content_hash=None):
        return SimpleNamespace(id=donor_id) if source_content_hash else None

    def copy_then_proxy_static_runs(session, src, dst, *, target_address):
        with Session(db_session.get_bind(), expire_on_commit=False) as proxy_worker:
            linked = proxy_worker.get(Contract, proxy_row.id)
            assert linked is not None
            linked.implementation = impl
            proxy_worker.commit()
        decisions.append(_backpatch_from_proxy_worker(db_session, impl, proxy))
        return 1

    monkeypatch.setattr("workers.discovery.find_completed_static_cache", lookup)
    monkeypatch.setattr("workers.discovery.copy_static_cache_cross_chain", copy_then_proxy_static_runs)
    _discovery(monkeypatch)._process_address(db_session, submitted)

    assert decisions == ["backpatched"]
    with Session(db_session.get_bind()) as reader:
        stored = reader.get(Job, submitted.id)
        assert stored is not None
        _assert_proxy_context(stored, proxy)
        assert (stored.request or {}).get("static_cached") is True
        assert (stored.request or {}).get("cross_chain_cache_source_job_id") == str(donor_id)


def test_dependents_stay_blocked_until_the_proxy_context_rerun(db_session):
    """A stage that ran on the pre-conversion request never releases dependents; the re-run's same stage does."""
    from db.models import JobDependency, JobStage, JobStatus
    from workers.base import BaseWorker

    proxy, impl = _addr(), _addr()
    submitted = _submit(db_session, impl)
    submitted.stage = JobStage.resolution
    dependent = _submit(db_session, _addr())
    dependent.stage = JobStage.policy
    db_session.commit()
    edge = JobDependency(
        depender_job_id=dependent.id,
        provider_chain="ethereum",
        provider_address=impl,
        required_stage=JobStage.resolution,
    )
    db_session.add(edge)
    db_session.commit()
    decisions: list[str] = []

    class Stage(BaseWorker):
        def process(self, session, job):
            if not decisions:
                decisions.append(_backpatch_from_proxy_worker(db_session, impl, proxy))

    class ResolutionStage(Stage):
        stage = JobStage.resolution
        next_stage = JobStage.policy

    class StaticStage(Stage):
        stage = JobStage.static
        next_stage = JobStage.resolution

    ResolutionStage()._execute_job(db_session, _claim(db_session, JobStage.resolution))
    db_session.refresh(submitted)
    db_session.refresh(edge)
    assert decisions == ["backpatched"]
    assert (submitted.stage, submitted.status) == (JobStage.static, JobStatus.queued)
    assert edge.status == "pending"

    StaticStage()._execute_job(db_session, _claim(db_session, JobStage.static))
    ResolutionStage()._execute_job(db_session, _claim(db_session, JobStage.resolution))
    db_session.refresh(submitted)
    db_session.refresh(edge)
    assert (submitted.stage, submitted.status) == (JobStage.policy, JobStatus.queued)
    _assert_proxy_context(submitted, proxy)
    assert edge.status == "satisfied"


@pytest.mark.parametrize("case", ["proxy_job_in_coverage", "beacon_job_in_resolution", "proxy_job_blocked_in_static"])
def test_an_impl_does_not_wait_on_a_proxy_job_that_cannot_rewrite_the_pointer(db_session, monkeypatch, case):
    from db.models import JobDependency, JobStage, JobStatus
    from db.queue import create_job

    proxy, impl = _addr(), _addr()
    beacon = case == "beacon_job_in_resolution"
    _, proxy_row = _proxy(db_session, proxy, impl, proxy_type="beacon" if beacon else "eip1967")
    if beacon:
        proxy_row.is_proxy = False
    rerun = create_job(db_session, {"address": proxy, "chain": "ethereum"})
    rerun.stage = {
        "proxy_job_in_coverage": JobStage.coverage,
        "beacon_job_in_resolution": JobStage.resolution,
        "proxy_job_blocked_in_static": JobStage.static,
    }[case]
    rerun.status = JobStatus.queued
    db_session.commit()
    if case == "proxy_job_blocked_in_static":
        db_session.add(
            JobDependency(
                depender_job_id=rerun.id,
                provider_chain="ethereum",
                provider_address=impl,
                required_stage=JobStage.policy,
            )
        )
        db_session.commit()

    submitted = _submit(db_session, impl)
    _discovery(monkeypatch)._process_address(db_session, submitted)

    db_session.refresh(submitted)
    request = submitted.request or {}
    assert request.get("proxy_address") == proxy
    assert request.get("proxy_type") == ("beacon" if beacon else "eip1967")
