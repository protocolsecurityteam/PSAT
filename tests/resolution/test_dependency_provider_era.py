"""Dependency providers and cross-contract artifact reads are gated on the analyzer era.

A provider job from another era counts as missing: one fresh provider is spawned and the edge stays pending until it
lands, and no reader is served the stale artifacts meanwhile. A current provider still satisfies at once, and a terminal
failure with no era stands instead of being re-spawned on every lookup.
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import Contract, Job, JobDependency, JobStage, JobStatus
from db.queue import create_job, store_artifact
from services.resolution.capability_resolver import (
    find_analysis_job_for_address,
    find_dependency_provider_job_for_address,
)
from tests.conftest import DATABASE_URL, requires_postgres
from workers.resolution_worker import ResolutionWorker

pytestmark = [requires_postgres]

CURRENT = ANALYSIS_SCHEMA_VERSION
STALE = 6

_TREES = {
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
_PROVIDER_TREES = {
    "schema_version": "semantic",
    "contract_name": "Provider",
    "trees": {"setX()": {"op": "LEAF", "leaf": {"kind": "unsupported"}}},
}


def _address(tag: str) -> str:
    return ("0x" + uuid.uuid4().hex[:8] + tag * 16).lower()


@pytest.fixture()
def session():
    engine = create_engine(DATABASE_URL)
    s = Session(engine, expire_on_commit=False)
    minted: list[str] = []
    s.info["minted"] = minted
    try:
        yield s
    finally:
        s.rollback()
        if minted:
            jobs = select(Job.id).where(Job.address.in_(minted))
            s.query(JobDependency).filter(JobDependency.depender_job_id.in_(jobs)).delete(synchronize_session=False)
            s.query(JobDependency).filter(JobDependency.provider_address.in_(minted)).delete(synchronize_session=False)
            s.query(Contract).filter(Contract.address.in_(minted)).delete(synchronize_session=False)
            s.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
            s.commit()
        s.close()
        engine.dispose()


def _job(
    session: Session,
    address: str,
    *,
    status: JobStatus,
    version: int | None,
    artifacts: dict[str, Any] | None = None,
    donor: Job | None = None,
    **request_extra: Any,
) -> Job:
    session.info["minted"].append(address)
    request = {"address": address, "chain": "ethereum", **request_extra}
    if donor is not None:
        request["cache_source_job_id"] = str(donor.id)
    job = create_job(session, request)
    job.status = status
    job.stage = JobStage.done if status == JobStatus.completed else JobStage.static
    job.analysis_schema_version = version
    session.commit()
    for name, data in (artifacts or {}).items():
        store_artifact(session, job.id, name, data=data)
    session.commit()
    return job


def _depender(session: Session) -> Job:
    address = _address("dd")
    job = _job(session, address, status=JobStatus.processing, version=CURRENT, artifacts={"predicate_trees": _TREES})
    job.stage = JobStage.resolution
    session.commit()
    return job


def _emit(session: Session, depender: Job, provider_addr: str, worker: ResolutionWorker | None = None) -> None:
    snapshot = {"controller_values": {"external_contract:authority": {"value": provider_addr}}}
    (worker or ResolutionWorker())._emit_dependency_edges_from_predicate_trees(
        session, cast(Any, depender), cast(Any, snapshot), "https://rpc.example"
    )


def _edge(session: Session, depender: Job) -> JobDependency:
    return session.execute(select(JobDependency).where(JobDependency.depender_job_id == depender.id)).scalar_one()


def _provider_jobs(session: Session, address: str) -> list[Job]:
    session.expire_all()
    return list(session.execute(select(Job).where(Job.address == address).order_by(Job.created_at)).scalars())


def test_a_stale_provider_is_replaced_not_satisfied(session):
    provider = _address("aa")
    stale = _job(
        session,
        provider,
        status=JobStatus.completed,
        version=STALE,
        artifacts={"effective_permissions": {"functions": []}, "predicate_trees": _PROVIDER_TREES},
    )
    depender = _depender(session)

    _emit(session, depender, provider)

    edge = _edge(session, depender)
    assert edge.status == "pending"
    assert edge.satisfied_at is None
    jobs = _provider_jobs(session, provider)
    assert [job.id for job in jobs][0] == stale.id and len(jobs) == 2
    fresh = jobs[1]
    assert (fresh.status, fresh.stage) == (JobStatus.queued, JobStage.discovery)
    assert (fresh.request or {}).get("discovered_by") == "resolution_dependency"


def test_a_current_provider_still_satisfies(session):
    provider = _address("ab")
    current = _job(
        session,
        provider,
        status=JobStatus.completed,
        version=CURRENT,
        artifacts={"effective_permissions": {"functions": []}},
    )
    depender = _depender(session)

    _emit(session, depender, provider)

    edge = _edge(session, depender)
    assert edge.status == "satisfied"
    assert edge.satisfied_at is not None
    assert [job.id for job in _provider_jobs(session, provider)] == [current.id]


def test_a_cache_hit_provider_inherits_its_donors_era(session):
    provider = _address("ac")
    donor = _job(session, _address("ad"), status=JobStatus.completed, version=CURRENT)
    hit = _job(
        session,
        provider,
        status=JobStatus.completed,
        version=None,
        donor=donor,
        artifacts={"effective_permissions": {"functions": []}},
    )
    depender = _depender(session)

    _emit(session, depender, provider)

    assert _edge(session, depender).status == "satisfied"
    assert [job.id for job in _provider_jobs(session, provider)] == [hit.id]


def test_two_dependers_racing_spawn_one_provider(session):
    provider = _address("ae")
    _job(session, provider, status=JobStatus.completed, version=STALE)
    dependers = [_depender(session), _depender(session)]
    barrier = threading.Barrier(len(dependers))
    errors: list[BaseException] = []
    # The worker installs signal handlers, which only the main thread may do.
    workers = {depender.id: ResolutionWorker() for depender in dependers}

    def run(depender: Job) -> None:
        engine = create_engine(DATABASE_URL)
        try:
            with Session(engine, expire_on_commit=False) as own:
                barrier.wait()
                _emit(own, own.get(Job, depender.id) or depender, provider, workers[depender.id])
        except BaseException as exc:  # surfaced below
            errors.append(exc)
        finally:
            engine.dispose()

    threads = [threading.Thread(target=run, args=(depender,)) for depender in dependers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors

    jobs = _provider_jobs(session, provider)
    assert len(jobs) == 2
    assert [job.status for job in jobs] == [JobStatus.completed, JobStatus.queued]
    assert {_edge(session, depender).status for depender in dependers} == {"pending"}


def test_a_fresh_provider_in_flight_is_not_spawned_again(session):
    provider = _address("af")
    _job(session, provider, status=JobStatus.completed, version=STALE)
    first, second = _depender(session), _depender(session)

    _emit(session, first, provider)
    _emit(session, second, provider)
    _emit(session, first, provider)

    assert len(_provider_jobs(session, provider)) == 2
    assert _edge(session, second).status == "pending"


def test_an_unstamped_terminal_failure_stands_and_degrades_the_edge(session):
    provider = _address("b1")
    failed = _job(session, provider, status=JobStatus.failed_terminal, version=None)
    depender = _depender(session)

    _emit(session, depender, provider)
    _emit(session, _depender(session), provider)

    assert [job.id for job in _provider_jobs(session, provider)] == [failed.id]
    edge = _edge(session, depender)
    # The failure already degraded its dependents and won't run again; a pending edge would block forever.
    assert edge.status == "degraded"
    assert edge.satisfied_at is not None


def test_a_stale_terminal_failure_is_retried_once(session):
    provider = _address("b2")
    _job(session, provider, status=JobStatus.failed_terminal, version=STALE)

    _emit(session, _depender(session), provider)
    _emit(session, _depender(session), provider)

    jobs = _provider_jobs(session, provider)
    assert [job.status for job in jobs] == [JobStatus.failed_terminal, JobStatus.queued]


def test_a_provider_waiting_on_a_retry_stands_and_spawns_no_duplicate(session):
    from datetime import datetime, timedelta, timezone

    from db.queue import requeue_job

    provider = _address("b4")
    retrying = _job(session, provider, status=JobStatus.processing, version=None)
    requeue_job(
        session,
        retrying.id,
        "transient",
        retry_count=1,
        next_attempt_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    dependers = [_depender(session) for _ in range(3)]

    for depender in dependers:
        _emit(session, depender, provider)
        _emit(session, depender, provider)

    assert [job.id for job in _provider_jobs(session, provider)] == [retrying.id]
    assert {_edge(session, depender).status for depender in dependers} == {"pending"}


@pytest.mark.parametrize("version", [None, CURRENT])
def test_a_failed_provider_that_nothing_will_run_is_replaced_once(session, version):
    from db.queue import fail_job

    provider = _address("b5")
    dead = _job(session, provider, status=JobStatus.processing, version=version)
    fail_job(session, dead.id, "boom")
    dependers = [_depender(session) for _ in range(3)]

    for depender in dependers:
        _emit(session, depender, provider)
        _emit(session, depender, provider)

    jobs = _provider_jobs(session, provider)
    assert [job.status for job in jobs] == [JobStatus.failed, JobStatus.queued]
    # Waiting on the failed row would block every depender forever; the one fresh provider is what they wait on.
    assert {_edge(session, depender).status for depender in dependers} == {"pending"}
    assert find_dependency_provider_job_for_address(session, provider, chain="ethereum") is not None


def test_a_proxy_whose_implementation_job_failed_spawns_one_provider(session):
    from db.queue import fail_job

    proxy, impl = _address("d9"), _address("da")
    proxy_job, impl_job = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=CURRENT)
    fail_job(session, impl_job.id, "boom")
    first, second = _depender(session), _depender(session)

    _emit(session, first, proxy)
    _emit(session, second, proxy)
    _emit(session, first, proxy)

    jobs = _provider_jobs(session, proxy)
    assert [job.id for job in jobs][0] == proxy_job.id and len(jobs) == 2
    assert {_edge(session, d).status for d in (first, second)} == {"pending"}


def test_a_failed_job_never_stands_for_the_current_analyzer(session):
    from db.queue import fail_job, job_stands_for_current_analyzer

    for version in (None, CURRENT):
        job = _job(session, _address("db"), status=JobStatus.processing, version=version)
        fail_job(session, job.id, "boom")
        session.refresh(job)
        assert job.status == JobStatus.failed
        assert not job_stands_for_current_analyzer(session, job)


def test_a_live_provider_is_preferred_over_a_standing_failure(session):
    provider = _address("b3")
    _job(session, provider, status=JobStatus.failed_terminal, version=None)
    live = _job(session, provider, status=JobStatus.processing, version=CURRENT)
    # The failure is the newest row; it must not hide the live attempt.
    failed_last = _job(session, provider, status=JobStatus.failed_terminal, version=None)
    assert failed_last.updated_at >= live.updated_at

    lookup = find_dependency_provider_job_for_address(session, provider, chain="ethereum")
    assert lookup is not None and lookup.analysis_job.id == live.id


def test_cross_contract_reads_never_fall_back_to_a_stale_artifact(session):
    registry = _address("c1")
    _job(
        session,
        registry,
        status=JobStatus.completed,
        version=STALE,
        artifacts={"predicate_trees": _PROVIDER_TREES, "effects": {"functions": {"setX()": {}}}},
    )

    for name in ("predicate_trees", "effects", "effective_permissions"):
        assert find_analysis_job_for_address(session, registry, required_artifact=name, completed_only=False) is None
    assert find_analysis_job_for_address(session, registry, required_artifact="predicate_trees") is None

    current = _job(session, registry, status=JobStatus.completed, version=CURRENT)
    store_artifact(session, current.id, "predicate_trees", data=_PROVIDER_TREES)
    session.commit()
    lookup = find_analysis_job_for_address(session, registry, required_artifact="predicate_trees")
    assert lookup is not None and lookup.analysis_job.id == current.id


def test_a_proxy_reads_only_a_current_implementation(session):
    proxy = _address("c2")
    impl = _address("c3")
    proxy_job = _job(session, proxy, status=JobStatus.completed, version=CURRENT)
    session.add(Contract(address=proxy, chain="ethereum", job_id=proxy_job.id, is_proxy=True, implementation=impl))
    session.commit()
    _job(
        session,
        impl,
        status=JobStatus.completed,
        version=STALE,
        artifacts={"predicate_trees": _PROVIDER_TREES},
        proxy_address=proxy,
        parent_job_id=str(proxy_job.id),
    )

    assert find_analysis_job_for_address(session, proxy, chain="ethereum") is None

    fresh = _job(
        session,
        impl,
        status=JobStatus.completed,
        version=CURRENT,
        artifacts={"predicate_trees": _PROVIDER_TREES},
        proxy_address=proxy,
        parent_job_id=str(proxy_job.id),
    )
    lookup = find_analysis_job_for_address(session, proxy, chain="ethereum")
    assert lookup is not None
    assert (lookup.runtime_job.id, lookup.analysis_job.id) == (proxy_job.id, fresh.id)


def _proxy_over(session: Session, proxy: str, impl: str, *, proxy_version: int | None, impl_version: int | None):
    proxy_job = _job(session, proxy, status=JobStatus.completed, version=proxy_version)
    session.add(Contract(address=proxy, chain="ethereum", job_id=proxy_job.id, is_proxy=True, implementation=impl))
    session.commit()
    impl_job = _job(
        session,
        impl,
        status=JobStatus.completed,
        version=impl_version,
        artifacts={"effective_permissions": {"functions": []}, "predicate_trees": _UNSUPPORTED_TREES},
        proxy_address=proxy,
        parent_job_id=str(proxy_job.id),
    )
    return proxy_job, impl_job


_UNSUPPORTED_TREES = {
    "schema_version": "semantic",
    "contract_name": "Impl",
    "trees": {
        "tryFn()": {
            "op": "LEAF",
            "leaf": {
                "kind": "unsupported",
                "operator": "truthy",
                "authority_role": "business",
                "operands": [],
                "unsupported_reason": "opaque_try_catch",
                "references_msg_sender": False,
                "parameter_indices": [],
                "expression": "h.helper()",
                "basis": ["opaque_try_catch"],
            },
        }
    },
}


def test_a_current_proxy_over_a_stale_implementation_spawns_one_provider(session):
    proxy, impl = _address("d1"), _address("d2")
    proxy_job, _stale_impl = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=STALE)
    first, second = _depender(session), _depender(session)

    _emit(session, first, proxy)
    _emit(session, second, proxy)
    _emit(session, first, proxy)

    jobs = _provider_jobs(session, proxy)
    # The completed proxy job never writes policy artifacts, so waiting on it would block the depender forever.
    assert [job.id for job in jobs][0] == proxy_job.id and len(jobs) == 2
    assert jobs[1].status == JobStatus.queued
    assert {_edge(session, d).status for d in (first, second)} == {"pending"}
    assert {_edge(session, d).provider_address for d in (first, second)} == {proxy}


def test_a_current_proxy_over_a_current_implementation_still_satisfies(session):
    proxy, impl = _address("d3"), _address("d4")
    proxy_job, impl_job = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=CURRENT)
    depender = _depender(session)

    _emit(session, depender, proxy)

    assert [job.id for job in _provider_jobs(session, proxy)] == [proxy_job.id]
    edge = _edge(session, depender)
    assert (edge.status, edge.provider_address) == ("satisfied", impl)


def test_an_older_proxy_shows_its_own_eras_implementation_by_job_id(session):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    proxy, impl = _address("d5"), _address("d6")
    proxy_job, impl_job = _proxy_over(session, proxy, impl, proxy_version=STALE, impl_version=STALE)

    out = resolve_contract_capabilities(session, address=proxy, chain_id=1, job_id=proxy_job.id, chain="ethereum")
    assert out is not None and out["tryFn()"]["kind"] == "unsupported"
    # Another contract's authority read refuses the same stale implementation.
    assert find_analysis_job_for_address(session, proxy, chain="ethereum", completed_only=False) is None


def test_a_current_proxy_never_shows_a_stale_implementation_by_job_id(session):
    from services.resolution.capability_resolver import resolve_contract_capabilities

    proxy, impl = _address("d7"), _address("d8")
    proxy_job, _impl_job = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=STALE)

    assert resolve_contract_capabilities(session, address=proxy, chain_id=1, job_id=proxy_job.id) is None


def test_a_beacon_over_a_stale_implementation_satisfies_without_spawning(session):
    beacon, impl = _address("e1"), _address("e2")
    beacon_job = _job(
        session,
        beacon,
        status=JobStatus.completed,
        version=CURRENT,
        artifacts={"effective_permissions": {"functions": []}},
    )
    # A beacon names an implementation but isn't a proxy, and runs policy itself.
    session.add(Contract(address=beacon, chain="ethereum", job_id=beacon_job.id, is_proxy=False, implementation=impl))
    session.commit()
    _job(session, impl, status=JobStatus.completed, version=STALE)
    depender = _depender(session)

    _emit(session, depender, beacon)
    _emit(session, _depender(session), beacon)

    assert [job.id for job in _provider_jobs(session, beacon)] == [beacon_job.id]
    assert _edge(session, depender).status == "satisfied"


def test_a_spawned_provider_is_found_even_after_the_proxy_job_is_touched(session):
    from datetime import datetime, timezone

    from sqlalchemy import update

    proxy, impl = _address("e3"), _address("e4")
    proxy_job, _stale_impl = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=STALE)
    _emit(session, _depender(session), proxy)
    # A later write to the completed proxy job sorts it ahead of the queued provider by recency.
    session.execute(update(Job).where(Job.id == proxy_job.id).values(updated_at=datetime.now(timezone.utc)))
    session.commit()

    _emit(session, _depender(session), proxy)

    assert [job.status for job in _provider_jobs(session, proxy)] == [JobStatus.completed, JobStatus.queued]


def test_a_completed_proxy_job_is_never_a_static_cache_donor(session):
    """The spawned provider for a proxy over a stale implementation must reach its own static stage, which reconciles
    the implementation; a cache hit on the completed proxy job would skip it and spawn again on every emission.
    """
    from db.models import SourceFile
    from db.queue import find_completed_static_cache

    proxy, impl = _address("e5"), _address("e6")
    proxy_job, _impl_job = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=CURRENT)
    session.add(SourceFile(job_id=proxy_job.id, path="Proxy.sol", content="contract Proxy {}"))
    store_artifact(session, proxy_job.id, "contract_flags", data={"is_proxy": True})
    session.commit()

    assert find_completed_static_cache(session, proxy, chain="ethereum") is None


@pytest.mark.parametrize("version", [None, CURRENT], ids=["unstamped", "stamped-current"])
def test_a_spawned_provider_that_failed_terminally_stands(session, version):
    proxy, impl = _address("e7"), _address("e8")
    proxy_job, _stale_impl = _proxy_over(session, proxy, impl, proxy_version=CURRENT, impl_version=STALE)
    _emit(session, _depender(session), proxy)
    spawned = _provider_jobs(session, proxy)[1]
    spawned.status = JobStatus.failed_terminal
    spawned.analysis_schema_version = version
    session.commit()
    depender = _depender(session)

    _emit(session, depender, proxy)

    jobs = _provider_jobs(session, proxy)
    assert [job.id for job in jobs] == [proxy_job.id, spawned.id]
    edge = _edge(session, depender)
    assert edge.status == "degraded"
