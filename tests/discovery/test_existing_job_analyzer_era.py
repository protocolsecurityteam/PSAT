"""Dedupe of an address's existing jobs against the current analyzer era.

An existing job stands in for a new one only when it was produced by the current analyzer (completed under a proven era)
or is still running current code; otherwise the address is analysed again, exactly once.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update as sa_update

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import Job, JobStage, JobStatus
from db.queue import create_job, find_existing_job_for_address, reconcile_impl_job_for_proxy
from tests.conftest import requires_postgres

pytestmark = [requires_postgres]

CURRENT = ANALYSIS_SCHEMA_VERSION
STALE = ANALYSIS_SCHEMA_VERSION - 1


@pytest.fixture()
def addr(db_session):
    minted: list[str] = []

    def factory() -> str:
        address = ("0x" + uuid.uuid4().hex + "0" * 8).lower()
        minted.append(address)
        return address

    yield factory
    db_session.rollback()
    if minted:
        db_session.query(Job).filter(Job.address.in_(minted)).delete(synchronize_session=False)
        db_session.commit()


def _job(
    session,
    address: str,
    status: JobStatus,
    version: int | None,
    *,
    donor: Job | None = None,
    age_s: int = 0,
    **request_extra,
) -> Job:
    request = {"address": address, "chain": "ethereum", **request_extra}
    if donor is not None:
        request["cache_source_job_id"] = str(donor.id)
    job = create_job(session, request)
    job.status = status
    job.stage = JobStage.done if status == JobStatus.completed else JobStage.static
    job.analysis_schema_version = version
    session.commit()
    if age_s:
        stamp = datetime.now(timezone.utc) - timedelta(seconds=age_s)
        session.execute(sa_update(Job).where(Job.id == job.id).values(updated_at=stamp))
        session.commit()
    return job


@pytest.mark.parametrize(
    ("status", "version", "stands"),
    [
        pytest.param(JobStatus.completed, CURRENT, True, id="completed_current"),
        pytest.param(JobStatus.completed, STALE, False, id="completed_stale"),
        pytest.param(JobStatus.completed, None, False, id="completed_unprovable"),
        pytest.param(JobStatus.queued, None, True, id="queued"),
        pytest.param(JobStatus.processing, STALE, True, id="processing"),
        pytest.param(JobStatus.failed, None, False, id="retrying_failure_excluded"),
        pytest.param(JobStatus.failed_terminal, None, True, id="terminal_before_analyzer"),
        pytest.param(JobStatus.failed_terminal, STALE, False, id="terminal_stale"),
        pytest.param(JobStatus.failed_terminal, CURRENT, True, id="terminal_current"),
    ],
)
def test_existing_job_stands_only_under_the_current_analyzer(db_session, addr, status, version, stands):
    address = addr()
    job = _job(db_session, address, status, version)
    found = find_existing_job_for_address(db_session, address, chain="ethereum")
    assert (found.id if found is not None else None) == (job.id if stands else None)


@pytest.mark.parametrize(("donor_version", "stands"), [(CURRENT, True), (STALE, False), (None, False)])
def test_cache_hit_job_takes_the_era_of_its_donor_chain(db_session, addr, donor_version, stands):
    address = addr()
    donor = _job(db_session, addr(), JobStatus.completed, donor_version)
    middle = _job(db_session, address, JobStatus.completed, None, donor=donor, age_s=60)
    newest = _job(db_session, address, JobStatus.completed, None, donor=middle)
    found = find_existing_job_for_address(db_session, address, chain="ethereum")
    assert (found.id if found is not None else None) == (newest.id if stands else None)


def test_a_current_job_wins_over_older_and_newer_stale_ones(db_session, addr):
    address = addr()
    _job(db_session, address, JobStatus.completed, STALE, age_s=120)
    current = _job(db_session, address, JobStatus.completed, CURRENT, age_s=60)
    _job(db_session, address, JobStatus.completed, None)
    found = find_existing_job_for_address(db_session, address, chain="ethereum")
    assert found is not None and found.id == current.id


def test_stale_job_on_another_chain_is_not_consulted(db_session, addr):
    address = addr()
    _job(db_session, address, JobStatus.completed, CURRENT)
    assert find_existing_job_for_address(db_session, address, chain="base") is None


@pytest.mark.parametrize(
    ("status", "version", "decision"),
    [
        pytest.param(JobStatus.completed, CURRENT, "skip", id="current"),
        pytest.param(JobStatus.queued, None, "skip", id="in_flight"),
        pytest.param(JobStatus.completed, STALE, "spawn", id="stale"),
        pytest.param(JobStatus.completed, None, "spawn", id="unprovable"),
    ],
)
def test_impl_behind_same_proxy_is_respawned_only_when_stale(db_session, addr, status, version, decision):
    impl, proxy = addr(), addr()
    _job(db_session, impl, status, version, proxy_address=proxy)
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == decision


@pytest.mark.parametrize(("version", "decision"), [(CURRENT, "backpatched"), (STALE, "spawn")])
def test_stale_standalone_impl_is_not_backpatched(db_session, addr, version, decision):
    impl, proxy = addr(), addr()
    standalone = _job(db_session, impl, JobStatus.completed, version)
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == decision
    db_session.refresh(standalone)
    assert ((standalone.request or {}).get("proxy_address") == proxy) == (decision == "backpatched")


def test_a_respawned_impl_is_skipped_on_the_next_proxy_pass(db_session, addr):
    impl, proxy = addr(), addr()
    _job(db_session, impl, JobStatus.completed, STALE, proxy_address=proxy, age_s=60)
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "spawn"
    create_job(db_session, {"address": impl, "chain": "ethereum", "proxy_address": proxy})
    assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "skip"


def test_a_stale_impl_job_is_not_reported_as_another_proxys(db_session, addr, caplog):
    impl, proxy = addr(), addr()
    _job(db_session, impl, JobStatus.completed, STALE, proxy_address=proxy)
    with caplog.at_level("WARNING", logger="db.queue"):
        assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, chain="ethereum") == "spawn"
    assert not any("behind multiple proxies" in r.getMessage() for r in caplog.records)
