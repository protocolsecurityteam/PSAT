"""Per-deployment resolution-result scoping + proxy-aware impl-job reconcile.

Covers ``db.deployment`` (derivation + scope predicate), ``db.queue.reconcile_impl_job_for_proxy``
(a standalone impl job is *converted* to proxy context and re-enqueued instead of skipped;
same-proxy is a true duplicate; different-proxy is a genuine shared impl), the writers'
delete-scope (two deployments of one ``contract_id`` coexist; re-resolution sweeps legacy
NULL rows), and ``capability_resolver`` reading only its own deployment's controller values.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from tests.conftest import requires_postgres


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
def test_reconcile_backpatches_completed_standalone_and_reenqueues(db_session):
    """The LRTSquared bug: a standalone impl that already resolved against its own empty
    storage is converted to proxy context AND re-enqueued from static."""
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


# (existing job's proxy / cascade root, caller's proxy / cascade root, decision). Keys are resolved to fresh
# addresses / root ids per run; ``None`` existing_job means no job for the impl exists.
@requires_postgres
@pytest.mark.parametrize(
    ("existing_job", "call_proxy", "call_root", "expected"),
    [
        pytest.param(("p1", None), "p1", None, "skip", id="skip_same_proxy"),
        pytest.param(None, "p1", None, "spawn", id="spawn_when_no_existing_job"),
        # A job already bound to proxy P1 means a genuine shared impl when P2 links the same bytecode: spawn a
        # separate per-deployment job (the N>1 case).
        pytest.param(("p1", None), "p2", None, "spawn", id="spawn_for_different_proxy_shared_impl"),
        # In --force mode the lookup is cascade-scoped: a same-proxy job from a *different* cascade does not
        # count as a duplicate.
        pytest.param(("p1", "r1"), "p1", "r2", "spawn", id="force_scopes_by_root_job"),
    ],
)
def test_reconcile_decision_table(db_session, existing_job, call_proxy, call_root, expected):
    from db.models import JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy

    impl = _addr()
    proxies = {"p1": _addr(), "p2": _addr()}
    roots = {"r1": str(uuid.uuid4()), "r2": str(uuid.uuid4())}
    if existing_job:
        job_proxy, job_root = existing_job
        _mk_job(
            db_session,
            impl,
            proxy=proxies[job_proxy],
            status=JobStatus.completed,
            stage=JobStage.done,
            root=roots[job_root] if job_root else None,
        )
    try:
        decision = reconcile_impl_job_for_proxy(
            db_session,
            impl_addr=impl,
            proxy_addr=proxies[call_proxy],
            **({"root_job_id": roots[call_root]} if call_root else {}),
        )
        assert decision == expected
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

    write_effective_function_rows(
        db_session,
        contract_id=c.id,
        function_records=[_fn_record()],
        capability_by_function={},
        deployment_address=None,
    )
    db_session.commit()
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
        assert vals.get("owner") == "0x" + "a" * 40
    finally:
        _cleanup_jobs(db_session, [impl])


# ---------------------------------------------------------------------------
# static_worker wiring — _resolve_proxy converts a pre-existing standalone impl
# ---------------------------------------------------------------------------


@requires_postgres
def test_resolve_proxy_backpatches_standalone_impl(db_session, monkeypatch):
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
        proxy_row = db_session.query(Contract).filter(Contract.address == proxy).one()
        assert (proxy_row.implementation or "").lower() == impl
    finally:
        _cleanup_jobs(db_session, [proxy, impl])


# ---------------------------------------------------------------------------
# End-to-end heal (verdict regression point (d)) through the REAL resolution + policy
# stack; only the snapshot/graph/balance wire is stubbed. ``build_control_snapshot`` keys
# its governor read off the address the worker hands it (the proxy when
# ``request.proxy_address`` is set), so if the override regresses the governor reads 0x0
# and the function stays resolved_empty.
# ---------------------------------------------------------------------------

_GATE_FN = "setGovernor(address)"


def _governor_gate_tree() -> dict:
    """A ``msg.sender == governor`` caller-authority equality leaf — the shape
    ``build_predicate_artifacts`` emits (see test_canonical_authority_getter_resolution)."""
    return {
        "op": "LEAF",
        "leaf": {
            "kind": "equality",
            "operator": "eq",
            "authority_role": "caller_authority",
            "operands": [
                {"source": "msg_sender"},
                {"source": "state_variable", "state_variable_name": "governor"},
            ],
            "references_msg_sender": True,
            "parameter_indices": [],
            "expression": "msg.sender == governor",
            "basis": [],
        },
    }


def _gate_fn_record() -> dict:
    return {
        "function": _GATE_FN,
        "abi_signature": _GATE_FN,
        "selector": "0x1c0d2bf2",
        "effect_labels": [],
        "effect_targets": [],
        "authority_public": False,
    }


def _stub_resolution_wire(monkeypatch, worker, *, proxy: str, governor: str) -> None:
    """Stub only the RPC-touching seams of ResolutionWorker. ``build_control_snapshot``
    models proxy-vs-impl storage: the governor lives in the proxy and reads 0x0 against the
    impl, so the address it sees shows whether ``request.proxy_address`` was honored."""
    zero = "0x" + "00" * 20

    def fake_snapshot(plan, rpc_url, *_a, **_k):
        read_addr = (plan.get("contract_address") or "").lower()
        gov = governor if read_addr == proxy.lower() else zero
        return {
            "contract_address": read_addr,
            "block_number": 7_000_000,
            "controller_values": {
                "state_variable:governor": {
                    "value": gov,
                    "resolved_type": "eoa",
                    "details": {},
                    "source": "governor",
                    "block_number": 7_000_000,
                    "observed_via": "eth_call",
                }
            },
        }

    def fake_graph(*, root_artifacts=None, rpc_url="", **_k):
        return {"root_contract_address": root_artifacts and "", "nodes": [], "edges": []}, {}

    monkeypatch.setattr("workers.resolution_worker.build_control_snapshot", fake_snapshot)
    monkeypatch.setattr("workers.resolution_worker.resolve_control_graph", fake_graph)
    monkeypatch.setattr("workers.resolution_worker.store_nested_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_fetch_balances", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_queue_discovered_contracts", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_emit_dependency_edges_from_predicate_trees", lambda *a, **k: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_heartbeat", lambda *a, **k: None)


def _gate_status_and_principal(db_session, job, contract, deployment):
    """Run the REAL policy resolve + writer for ``job`` and return
    ``(status, principal_addresses)`` for the governor-gated function."""
    from db.models import EffectiveFunction, FunctionPrincipal
    from services.policy.effective_permissions_writer import write_effective_function_rows
    from services.resolution.capability_resolver import resolve_contract_capabilities

    caps = resolve_contract_capabilities(db_session, address=contract.address, chain_id=1, job_id=job.id)
    assert caps is not None and _GATE_FN in caps, f"resolver returned no capability for {_GATE_FN}: {caps}"
    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=[_gate_fn_record()],
        capability_by_function=caps,
        deployment_address=deployment,
    )
    db_session.commit()
    rows = db_session.query(EffectiveFunction).filter(EffectiveFunction.contract_id == contract.id).all()
    assert len(rows) == 1, (
        f"expected exactly one effective_function row, got {[(r.abi_signature, r.deployment_address) for r in rows]}"
    )
    ef = rows[0]
    principals = [
        p.address for p in db_session.query(FunctionPrincipal).filter(FunctionPrincipal.function_id == ef.id).all()
    ]
    return ef, principals, caps[_GATE_FN]


@requires_postgres
def test_end_to_end_heal_standalone_impl_resolves_after_backpatch(db_session, monkeypatch):
    """The full LRTSquared-shaped heal: a governor-gated impl function that resolves_empty
    standalone (governor read against empty impl storage) resolves to the governor once the
    proxy is discovered and ``reconcile_impl_job_for_proxy`` back-patches the impl job.

    Revert-proof at three points: the reconcile back-patch, the resolution proxy-override,
    and the per-deployment controller-value read/sweep.
    """
    from db.models import Contract, JobStage, JobStatus
    from db.queue import reconcile_impl_job_for_proxy, store_artifact
    from workers.resolution_worker import ResolutionWorker

    impl, proxy = _addr(), _addr()
    governor = "0x" + "a1" * 20

    job = _mk_job(db_session, impl, status=JobStatus.completed, stage=JobStage.done, root=str(uuid.uuid4()))
    job.request = {**(job.request or {}), "rpc_url": "http://stub", "chain": "ethereum"}
    contract = Contract(address=impl, chain="ethereum", contract_name="Core", job_id=job.id)
    db_session.add(contract)
    db_session.commit()
    store_artifact(
        db_session,
        job.id,
        "contract_analysis",
        data={"subject": {"address": impl}, "contract_name": "Core", "functions": []},
    )
    store_artifact(
        db_session,
        job.id,
        "control_tracking_plan",
        data={"schema_version": "0.1", "contract_address": impl, "contract_name": "Core", "tracked_controllers": []},
    )
    store_artifact(
        db_session,
        job.id,
        "predicate_trees",
        data={
            "schema_version": "semantic",
            "contract_name": "Core",
            "trees": {_GATE_FN: _governor_gate_tree()},
            "check_trees": {},
        },
    )
    db_session.commit()

    worker = ResolutionWorker()
    _stub_resolution_wire(monkeypatch, worker, proxy=proxy, governor=governor)

    try:
        # --- Phase A: standalone resolution is a false-negative (the bug) ---
        worker.process(db_session, job)
        ef_a, principals_a, cap_a = _gate_status_and_principal(db_session, job, contract, deployment=None)
        assert ef_a.status == "resolved_empty", f"standalone gate should be resolved_empty, got {ef_a.status} ({cap_a})"
        assert principals_a == []
        assert ef_a.deployment_address is None

        # --- Step: proxy discovered later → reconcile back-patches the impl job ---
        decision = reconcile_impl_job_for_proxy(db_session, impl_addr=impl, proxy_addr=proxy, proxy_type="eip1967")
        assert decision == "backpatched"
        db_session.refresh(job)
        req = job.request
        assert isinstance(req, dict)
        assert req["proxy_address"] == proxy  # the impl now carries proxy context

        # --- Phase B: re-resolution against the proxy heals the function ---
        worker.process(db_session, job)
        ef_b, principals_b, cap_b = _gate_status_and_principal(db_session, job, contract, deployment=proxy)
        assert ef_b.status != "resolved_empty", f"proxy-context gate should resolve, got resolved_empty ({cap_b})"
        assert principals_b == [governor], f"gate should resolve to the proxy's governor, got {principals_b}"
        assert ef_b.deployment_address == proxy
        from db.models import EffectiveFunction

        assert (
            db_session.query(EffectiveFunction)
            .filter(EffectiveFunction.contract_id == contract.id, EffectiveFunction.status == "resolved_empty")
            .count()
            == 0
        )
    finally:
        db_session.rollback()
        db_session.query(Contract).filter(Contract.address == impl).delete(synchronize_session=False)
        db_session.commit()
        _cleanup_jobs(db_session, [impl])
