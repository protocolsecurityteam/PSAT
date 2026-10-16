from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Job
from db.queue import create_job, fail_job_terminal, find_existing_job_for_address
from db.queue.jobs import create_discovery_child
from db.queue.source_failures import SOURCE_ABSENCE, record_source_absence
from tests.conftest import requires_postgres

pytestmark = requires_postgres
ADDRESS = "0x" + "41" * 20


def failed_child(session, *, proxy=None):
    parent = create_job(session, {"company": "source-scope"})
    request: dict[str, Any] = {"address": ADDRESS, "chain": "ethereum"}
    if proxy:
        request["proxy_address"] = proxy
    child, created = create_discovery_child(session, parent, request)
    assert created
    record_source_absence(session, child, 1)
    fail_job_terminal(session, child.id, "VerifiedSourceUnavailable", kind="terminal")
    return parent, child, request


def test_eight_automatic_requests_share_one_failed_blocker(db_session):
    parent, failed, request = failed_child(db_session)
    for _ in range(8):
        child, created = create_discovery_child(db_session, parent, request)
        assert child.id == failed.id and not created
        found = find_existing_job_for_address(db_session, ADDRESS, "ethereum", parent_job=parent)
        assert found is not None and found.id == failed.id
    assert len(db_session.execute(select(Job).where(Job.address == ADDRESS)).scalars().all()) == 1
    assert failed.analysis_schema_version is None  # absence is not successful analysis


@pytest.mark.parametrize("change", ["expiry", "version", "root", "proxy", "chain", "force"])
def test_source_absence_does_not_block_fresh_scope_or_retry(db_session, monkeypatch, change):
    parent, failed, request = failed_child(db_session)
    assert failed.request is not None
    if change == "expiry":
        marker = {
            **failed.request[SOURCE_ABSENCE],
            "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        }
        failed.request = {**failed.request, SOURCE_ABSENCE: marker}
        db_session.commit()
    elif change == "version":
        from db import contract_materializations as cache

        monkeypatch.setattr(cache, "ANALYSIS_SCHEMA_VERSION", cache.ANALYSIS_SCHEMA_VERSION + 1)
    elif change == "root":
        parent = create_job(db_session, {"company": "new-source-scope"})
    elif change == "proxy":
        request["proxy_address"] = "0x" + "42" * 20
    elif change == "chain":
        request["chain"] = "base"
    else:
        request["force"] = True
    child, created = create_discovery_child(db_session, parent, request)
    assert created and child.id != failed.id


def test_old_free_text_failure_is_rechecked_not_indefinitely_cached(db_session):
    parent = create_job(db_session, {"company": "legacy-source-scope"})
    failed = create_job(db_session, {"address": ADDRESS, "chain": "ethereum"})
    fail_job_terminal(db_session, failed.id, f"RuntimeError: No verified source code for {ADDRESS}", kind="terminal")
    assert find_existing_job_for_address(db_session, ADDRESS, "ethereum", parent_job=parent) is None


def test_concurrent_automatic_enqueue_has_one_child(db_session):
    parent = create_job(db_session, {"company": "concurrent-source-scope"})
    engine, pid = db_session.get_bind(), parent.id
    barrier = Barrier(2)

    def enqueue():
        with Session(engine) as session:
            root = session.get(Job, pid)
            assert root is not None
            barrier.wait(timeout=10)
            child, created = create_discovery_child(session, root, {"address": ADDRESS, "chain": "ethereum"})
            return child.id, created

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: enqueue(), range(2)))
    assert results[0][0] == results[1][0]
    assert sum(created for _, created in results) == 1


@pytest.mark.parametrize("change", [None, "root", "protocol", "proxy", "force", "standalone"])
def test_proxy_source_failure_requires_the_same_cascade_and_deployment(db_session, change):
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
    from db.models import Contract, JobStatus, Protocol
    from db.queue import reconcile_impl_job_for_proxy
    from services.resolution.capability_resolver import find_dependency_provider_job_for_address

    proxy = "0x" + "43" * 20
    parent, failed, _ = failed_child(db_session, proxy=None if change == "standalone" else proxy)
    runtime, _ = create_discovery_child(db_session, parent, {"address": proxy, "chain": "ethereum"})
    runtime.status = JobStatus.completed
    runtime.analysis_schema_version = ANALYSIS_SCHEMA_VERSION
    db_session.add(Contract(address=proxy, chain="ethereum", job_id=runtime.id, is_proxy=True, implementation=ADDRESS))
    db_session.commit()
    if change == "root":
        parent = create_job(db_session, {"company": "different-root"})
    elif change == "protocol":
        protocol = Protocol(name="different-protocol")
        db_session.add(protocol)
        db_session.flush()
        parent.protocol_id = protocol.id
    elif change == "proxy":
        proxy = "0x" + "44" * 20
    elif change == "force":
        parent.request = {**(parent.request or {}), "force": True}
    db_session.commit()
    decision = reconcile_impl_job_for_proxy(
        db_session, impl_addr=ADDRESS, proxy_addr=proxy, chain="ethereum", parent_job=parent
    )
    assert decision == ("skip" if change is None else "spawn")
    provider = find_dependency_provider_job_for_address(db_session, proxy, chain="ethereum", parent_job=parent)
    if change is None:
        assert provider is not None and provider.analysis_job.id == failed.id
    else:
        assert provider is None
    if change == "standalone":
        assert not (failed.request or {}).get("proxy_address")


def test_reverse_order_impl_skips_release_each_lock(db_session, monkeypatch):
    from threading import local

    from sqlalchemy import text

    from db import queue
    from db.models import Contract
    from services.discovery.secondary_impl import queue_secondary_impl_jobs

    parent = create_job(db_session, {"company": "lock-cascade"})
    implementations = ["0x" + "51" * 20, "0x" + "52" * 20]
    proxies = ["0x" + "53" * 20, "0x" + "54" * 20]
    contracts = []
    for proxy in proxies:
        contract = Contract(address=proxy, chain="ethereum")
        db_session.add(contract)
        db_session.commit()
        contracts.append(contract.id)
        for address in implementations:
            create_discovery_child(
                db_session, parent, {"address": address, "chain": "ethereum", "proxy_address": proxy}
            )
    engine, pid = db_session.get_bind(), parent.id
    barrier, thread = Barrier(2), local()
    original = queue.reconcile_impl_job_for_proxy

    def synchronized_skip(*args, **kwargs):
        decision = original(*args, **kwargs)
        assert decision == "skip"
        if not getattr(thread, "synchronized", False):
            thread.synchronized = True
            barrier.wait(timeout=5)  # both transactions hold their first, different lock
        return decision

    monkeypatch.setattr(queue, "reconcile_impl_job_for_proxy", synchronized_skip)

    def enqueue(index):
        with Session(engine) as session:
            session.execute(text("SET lock_timeout = '3s'"))
            root = session.get(Job, pid)
            contract = session.get(Contract, contracts[index])
            assert root is not None and contract is not None
            return queue_secondary_impl_jobs(
                session,
                proxy_contract=contract,
                secondary_addrs=implementations if index == 0 else list(reversed(implementations)),
                parent_job=root,
                rpc_url="http://unused",
                proxy_type="split",
                root_job_id=str(pid),
                chain="ethereum",
                protocol_id=None,
                force=False,
                base_name="lock-test",
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert list(executor.map(enqueue, range(2))) == [[], []]
