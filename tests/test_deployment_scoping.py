"""Per-deployment resolution-result scoping + proxy-aware impl-job reconcile.

Covers the structural fix for proxy/impl authority under-resolution:

  * ``db.deployment`` — the deployment derivation + scope predicate.
  * ``db.queue.reconcile_impl_job_for_proxy`` — the discovery-ordering fix: a
    standalone (no-proxy) impl job is *converted* to proxy context (and
    re-enqueued) instead of being skipped, so it stops resolving against its own
    empty storage; a same-proxy job is a true duplicate; a different-proxy job is
    a genuine shared impl (N proxies → 1 impl) that spawns its own deployment.
  * the writers' delete-scope — two deployments of one impl ``contract_id``
    coexist without clobbering each other, and a re-resolution sweeps legacy
    untagged (NULL) rows.
  * ``capability_resolver`` — a job reads only its own deployment's controller
    values, not a sibling proxy's.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402


def _addr() -> str:
    return "0x" + (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


def _now():
    return datetime.now(timezone.utc)


def _fn_record(status: str = "resolved_empty") -> dict:
    return {
        "function": "f()",
        "abi_signature": "f()",
        "selector": "0xdeadbeef",
        "effect_labels": [],
        "effect_targets": [],
        "authority_public": False,
        "status": status,
    }


# ---------------------------------------------------------------------------
# db.deployment (pure)
# ---------------------------------------------------------------------------


def test_normalize_deployment():
    from db.deployment import normalize_deployment

    assert normalize_deployment("0x" + "Ab" * 20) == "0x" + "ab" * 20  # lowercased
    assert normalize_deployment(None) is None
    assert normalize_deployment("not-an-address") is None
    assert normalize_deployment("0x1234") is None  # wrong length


# ---------------------------------------------------------------------------
# reconcile_impl_job_for_proxy — the discovery-ordering fix
# ---------------------------------------------------------------------------


def _mk_job(session, address, *, proxy=None, status, stage, root=None):
    from db.models import Job

    req = {"address": address}
    if proxy:
        req["proxy_address"] = proxy
    if root:
        req["root_job_id"] = root
    job = Job(
        id=uuid.uuid4(),
        address=address,
        status=status,
        stage=stage,
        request=req,
        created_at=_now(),
        updated_at=_now(),
    )
    session.add(job)
    session.commit()
    return job


def _cleanup_jobs(session, addrs):
    from db.models import Job

    session.query(Job).filter(Job.address.in_(addrs)).delete(synchronize_session=False)
    session.commit()


@requires_postgres
def test_reconcile_skip_same_proxy(db_session):
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    impl, proxy = _addr(), _addr()
    _mk_job(db_session, impl, proxy=proxy, status=JobStatus.completed, stage=JobStage.done)
    try:
        assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy) == "skip"
    finally:
        _cleanup_jobs(db_session, [impl])


@requires_postgres
def test_reconcile_backpatches_completed_standalone_and_reenqueues(db_session):
    """The actual LRTSquared bug: a standalone impl that already resolved
    (against its own empty storage) gets converted to proxy context AND
    re-enqueued from static so secondary-impl linkage fires + resolution re-reads
    against the proxy."""
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    impl, proxy = _addr(), _addr()
    job = _mk_job(db_session, impl, status=JobStatus.completed, stage=JobStage.done)
    try:
        decision = reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, proxy_type="eip1967")
        assert decision == "backpatched"
        db_session.refresh(job)
        assert isinstance(job.request, dict)
        assert job.request["proxy_address"] == proxy
        assert job.request["proxy_type"] == "eip1967"
        assert job.request["discovery_relationship"] == "implementation"
        # Re-enqueued from static (a completed job had to re-run).
        assert job.stage == JobStage.static
        assert job.status == JobStatus.queued
        assert job.lease_id is None
    finally:
        _cleanup_jobs(db_session, [impl])


@requires_postgres
def test_reconcile_backpatches_queued_standalone_without_reenqueue(db_session):
    """A standalone job still queued before resolution just gains proxy context;
    no stage reset is needed (it hasn't run yet)."""
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    impl, proxy = _addr(), _addr()
    job = _mk_job(db_session, impl, status=JobStatus.queued, stage=JobStage.static)
    try:
        assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy) == "backpatched"
        db_session.refresh(job)
        assert isinstance(job.request, dict)
        assert job.request["proxy_address"] == proxy
        assert job.stage == JobStage.static  # unchanged — not past resolution
        assert job.status == JobStatus.queued
    finally:
        _cleanup_jobs(db_session, [impl])


@requires_postgres
def test_reconcile_spawn_when_no_existing_job(db_session):
    from db.queue import reconcile_impl_job_for_proxy

    assert reconcile_impl_job_for_proxy(db_session, impl_addr=_addr(), proxy_addr=_addr()) == "spawn"


@requires_postgres
def test_reconcile_spawn_for_different_proxy_shared_impl(db_session):
    """A job already bound to proxy P1 means a genuine shared impl when P2 links
    the same bytecode — spawn a separate per-deployment job (the N>1 case)."""
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    impl, p1, p2 = _addr(), _addr(), _addr()
    _mk_job(db_session, impl, proxy=p1, status=JobStatus.completed, stage=JobStage.done)
    try:
        assert reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=p2) == "spawn"
    finally:
        _cleanup_jobs(db_session, [impl])


@requires_postgres
def test_reconcile_force_scopes_by_root_job(db_session):
    """In --force mode the lookup is cascade-scoped: a same-proxy job from a
    *different* cascade does not count as a duplicate."""
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    impl, proxy = _addr(), _addr()
    other_root = str(uuid.uuid4())
    _mk_job(db_session, impl, proxy=proxy, status=JobStatus.completed, stage=JobStage.done, root=other_root)
    try:
        # Same proxy, but a different cascade root → not a dup in this cascade.
        decision = reconcile_impl_job_for_proxy(
            db_session, impl_addr=impl, proxy_addr=proxy, root_job_id=str(uuid.uuid4())
        )
        assert decision == "spawn"
    finally:
        _cleanup_jobs(db_session, [impl])


# ---------------------------------------------------------------------------
# Writer delete-scope — per-deployment isolation + legacy NULL sweep
# ---------------------------------------------------------------------------


@requires_postgres
def test_writer_isolates_deployments(db_session):
    from db.models import Contract, EffectiveFunction
    from services.policy.effective_permissions_writer import write_effective_function_rows

    addr, p1, p2 = _addr(), _addr(), _addr()
    c = Contract(address=addr, chain="ethereum")
    db_session.add(c)
    db_session.commit()

    def _write(dep):
        write_effective_function_rows(
            db_session,
            contract_id=c.id,
            function_records=[_fn_record()],
            capability_by_function={},
            deployment_address=dep,
        )
        db_session.commit()

    _write(p1)
    _write(p2)
    rows = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == c.id).all()
    assert {r.deployment_address for r in rows} == {p1, p2}  # both deployments coexist
    assert len(rows) == 2

    # Re-resolving p1 must not touch p2's rows.
    _write(p1)
    rows = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == c.id).all()
    assert {r.deployment_address for r in rows} == {p1, p2}
    assert len(rows) == 2


@requires_postgres
def test_writer_sweeps_legacy_null_rows(db_session):
    """A legacy untagged (NULL) row is swept the first time the deployment
    re-resolves — the back-patch/re-resolution cleanup path."""
    from db.models import Contract, EffectiveFunction
    from services.policy.effective_permissions_writer import write_effective_function_rows

    addr, proxy = _addr(), _addr()
    c = Contract(address=addr, chain="ethereum")
    db_session.add(c)
    db_session.commit()

    # Legacy standalone resolution: deployment NULL.
    write_effective_function_rows(
        db_session,
        contract_id=c.id,
        function_records=[_fn_record()],
        capability_by_function={},
        deployment_address=None,
    )
    db_session.commit()
    # Re-resolve in proxy context → sweeps the NULL row.
    write_effective_function_rows(
        db_session,
        contract_id=c.id,
        function_records=[_fn_record()],
        capability_by_function={},
        deployment_address=proxy,
    )
    db_session.commit()

    rows = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == c.id).all()
    assert len(rows) == 1
    assert rows[0].deployment_address == proxy  # NULL legacy row gone


# ---------------------------------------------------------------------------
# capability_resolver — per-deployment controller-value read
# ---------------------------------------------------------------------------


@requires_postgres
def test_controller_values_scoped_to_job_deployment(db_session):
    from db.models import Contract, ControllerValue, Job, JobStage, JobStatus
    from services.resolution.capability_resolver import _load_state_var_values

    impl, p1, p2 = _addr(), _addr(), _addr()
    job = Job(
        id=uuid.uuid4(),
        address=impl,
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"address": impl, "proxy_address": p1, "chain": "ethereum"},
        created_at=_now(),
        updated_at=_now(),
    )
    db_session.add(job)
    c = Contract(address=impl, chain="ethereum", job_id=job.id)
    db_session.add(c)
    db_session.commit()

    # Same controller, two deployments of the shared impl row.
    db_session.add(
        ControllerValue(
            contract_id=c.id, deployment_address=p1, controller_id="state_variable:owner", value="0x" + "a" * 40
        )
    )
    db_session.add(
        ControllerValue(
            contract_id=c.id, deployment_address=p2, controller_id="state_variable:owner", value="0x" + "b" * 40
        )
    )
    db_session.commit()

    try:
        vals = _load_state_var_values(db_session, impl, job_id=job.id, chain="ethereum")
        # The job's deployment is p1 → it reads p1's value, not the sibling p2's.
        assert vals.get("owner") == "0x" + "a" * 40
    finally:
        _cleanup_jobs(db_session, [impl])


# ---------------------------------------------------------------------------
# static_worker wiring — _resolve_proxy converts a pre-existing standalone impl
# ---------------------------------------------------------------------------


@requires_postgres
def test_resolve_proxy_backpatches_standalone_impl(db_session, monkeypatch):
    """The end-to-end discovery-ordering fix: a proxy whose impl was already
    analyzed standalone (the LRTSquared shape) converts that impl job to proxy
    context instead of skipping it, so it stops resolving against empty storage."""
    from db.models import Contract, JobStage, JobStatus
    from workers.static_worker import StaticWorker

    proxy, impl = _addr(), _addr()
    proxy_job = _mk_job(db_session, proxy, status=JobStatus.processing, stage=JobStage.static, root=str(uuid.uuid4()))
    # _resolve_proxy needs an rpc_url in the request + a Contract row for the proxy.
    proxy_job.request = {**(proxy_job.request or {}), "rpc_url": "http://stub", "chain": "ethereum"}
    db_session.add(Contract(address=proxy, chain="ethereum", job_id=proxy_job.id))
    impl_job = _mk_job(db_session, impl, status=JobStatus.completed, stage=JobStage.done)
    db_session.commit()

    monkeypatch.setattr(
        "services.discovery.classifier.classify_single",
        lambda *a, **k: {
            "type": "proxy",
            "proxy_type": "eip1967",
            "implementation": impl,
            "beacon": None,
            "admin": None,
            "facets": None,
        },
    )
    worker = StaticWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    try:
        worker._resolve_proxy(db_session, proxy_job, proxy, "UUPSProxy")
        db_session.refresh(impl_job)
        assert isinstance(impl_job.request, dict)
        assert impl_job.request["proxy_address"] == proxy
        assert impl_job.request["discovery_relationship"] == "implementation"
        assert impl_job.stage == JobStage.static  # completed job re-enqueued
        assert impl_job.status == JobStatus.queued
        # The proxy row records the implementation link.
        proxy_row = db_session.query(Contract).filter(Contract.address == proxy).one()
        assert (proxy_row.implementation or "").lower() == impl
    finally:
        _cleanup_jobs(db_session, [proxy, impl])
