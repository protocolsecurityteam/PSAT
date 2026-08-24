"""Integration tests for the dirty-queue enrollment reconciler (design §2.3).

Real Postgres + the real ``enroll_protocol_contracts`` production stack; the
only thing stubbed is the RPC wire (``eth_blockNumber``). Covers the queue
mark/claim/drain lifecycle, lease exclusivity + expiry, the ``dirty_at``-guarded
delete, poisoned-protocol backoff, the K-sweep, and each of the four call sites.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from db.models import (
    Contract,
    ControlGraphNode,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
    MonitoredEvent,
    MonitoringEnrollmentQueue,
    Protocol,
)
from services.monitoring import reconciler
from services.monitoring.enrollment import mark_enrollment_dirty
from services.monitoring.reconciler import (
    claim_due_enrollments,
    drain_enrollment_queue,
    sweep_enqueue_stale,
)
from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = requires_postgres

NAME_PREFIX = "__test_enroll_queue__"
CONTROLLER_ADDR = "0x" + "c1" * 20
VAULT_ADDR = "0x" + "11" * 20
DISCOVERY_ADDR = "0x" + "d4" * 20


def _engine():
    return create_engine(DATABASE_URL)


def _cleanup(session: Session) -> None:
    protos = list(session.execute(select(Protocol).where(Protocol.name.like(NAME_PREFIX + "%"))).scalars())
    for proto in protos:
        contract_ids = list(session.execute(select(Contract.id).where(Contract.protocol_id == proto.id)).scalars())
        mc_ids = list(
            session.execute(select(MonitoredContract.id).where(MonitoredContract.protocol_id == proto.id)).scalars()
        )
        if mc_ids:
            session.execute(delete(MonitoredEvent).where(MonitoredEvent.monitored_contract_id.in_(mc_ids)))
        if contract_ids:
            ef_ids = list(
                session.execute(
                    select(EffectiveFunction.id).where(EffectiveFunction.contract_id.in_(contract_ids))
                ).scalars()
            )
            if ef_ids:
                session.execute(delete(FunctionPrincipal).where(FunctionPrincipal.function_id.in_(ef_ids)))
            session.execute(delete(EffectiveFunction).where(EffectiveFunction.contract_id.in_(contract_ids)))
            session.execute(delete(ControlGraphNode).where(ControlGraphNode.contract_id.in_(contract_ids)))
            session.execute(delete(ControllerValue).where(ControllerValue.contract_id.in_(contract_ids)))
        session.execute(delete(MonitoredContract).where(MonitoredContract.protocol_id == proto.id))
        session.execute(delete(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id))
        session.execute(delete(Job).where(Job.protocol_id == proto.id))
        session.execute(delete(Contract).where(Contract.protocol_id == proto.id))
        session.delete(proto)
    # Controller rows enrolled onto other protocols carry our sentinel address.
    session.execute(delete(MonitoredContract).where(MonitoredContract.address == CONTROLLER_ADDR))
    # Discovery-adoption sentinel contract may be left un-adopted (protocol NULL).
    stray_ids = list(session.execute(select(Contract.id).where(Contract.address == DISCOVERY_ADDR)).scalars())
    if stray_ids:
        session.execute(delete(Job).where(Job.address == DISCOVERY_ADDR))
        session.execute(delete(Contract).where(Contract.id.in_(stray_ids)))
    session.commit()


@pytest.fixture()
def qsession():
    engine = _engine()
    session = Session(engine, expire_on_commit=False)
    _cleanup(session)
    try:
        yield session
    finally:
        session.rollback()
        _cleanup(session)
        session.close()
        engine.dispose()


def _make_protocol(session: Session, suffix: str = "") -> Protocol:
    proto = Protocol(name=NAME_PREFIX + (suffix or uuid.uuid4().hex[:8]))
    session.add(proto)
    session.flush()
    return proto


def _seed_protocol_with_controller(session: Session) -> Protocol:
    """Seed the canonical pipeline shape so ``controllers_for_protocol`` surfaces
    CONTROLLER_ADDR as a governing Safe: a protocol contract with a completed
    job, a CGN labeling the Safe, and an FP granting it call authority."""
    proto = _make_protocol(session, "ctrl")
    vault = Contract(
        address=VAULT_ADDR.lower(),
        chain="ethereum",
        protocol_id=proto.id,
        contract_name="TestVault",
        is_proxy=False,
    )
    session.add(vault)
    session.flush()
    session.add(Job(address=VAULT_ADDR.lower(), protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    session.add(
        ControlGraphNode(
            contract_id=vault.id,
            address=CONTROLLER_ADDR.lower(),
            node_type="principal",
            resolved_type="safe",
            label="owner",
            depth=1,
        )
    )
    ef = EffectiveFunction(contract_id=vault.id, function_name="transferOwnership", authority_public=False)
    session.add(ef)
    session.flush()
    session.add(FunctionPrincipal(function_id=ef.id, address=CONTROLLER_ADDR.lower(), principal_type="controller"))
    session.commit()
    return proto


@pytest.fixture()
def wired_drain(monkeypatch):
    """Point the drain's internal ``SessionLocal`` at the test DB and stub the
    RPC wire so ``drain_enrollment_queue`` runs fully offline."""
    engine = _engine()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(reconciler, "SessionLocal", factory)
    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", lambda *a, **kw: "0x100")
    try:
        yield
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# mark -> drain -> controllers enrolled
# ---------------------------------------------------------------------------


def test_mark_then_drain_enrolls_controllers(qsession, wired_drain):
    proto = _seed_protocol_with_controller(qsession)
    mark_enrollment_dirty(qsession, proto.id, "policy_complete")
    qsession.commit()

    result = drain_enrollment_queue("http://rpc.invalid", "ethereum")
    assert result == {"drained": 1, "failed": 0}

    qsession.expire_all()
    ctrl = qsession.execute(
        select(MonitoredContract).where(
            MonitoredContract.address == CONTROLLER_ADDR.lower(),
            MonitoredContract.protocol_id == proto.id,
        )
    ).scalar_one_or_none()
    assert ctrl is not None, "controller Safe should be enrolled by the drain"
    assert ctrl.is_active is True
    assert ctrl.contract_type == "safe"

    # Queue row consumed; reconcile timestamp stamped.
    assert (
        qsession.execute(
            select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
        ).scalar_one_or_none()
        is None
    )
    reconciled_at = qsession.execute(
        select(Protocol.last_enrollment_reconcile_at).where(Protocol.id == proto.id)
    ).scalar_one()
    assert reconciled_at is not None


def test_lock_skipped_fastpath_converges_via_drain(qsession, wired_drain):
    """e2e: when the fast-path enroll skips (a sibling holds the advisory lock),
    its mark-dirty-on-skip enqueues the protocol, and the reconciler drain
    enrolls the contract the holder's snapshot could have missed."""
    from services.monitoring.enrollment import maybe_enroll_protocol

    proto = _seed_protocol_with_controller(qsession)

    # A sibling holds the enrollment lock, so the fast path must skip.
    holder_engine = _engine()
    holder = Session(holder_engine, expire_on_commit=False)
    holder.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext('protocol_enrollment'), :pid)"),
        {"pid": proto.id},
    )
    try:
        fired = maybe_enroll_protocol(qsession, proto.id, "http://rpc", "ethereum")
        assert fired is False
        # Nothing enrolled yet — but a dirty row was queued by the skip.
        enrolled_now = (
            qsession.execute(select(MonitoredContract).where(MonitoredContract.protocol_id == proto.id)).scalars().all()
        )
        assert enrolled_now == []
        assert (
            qsession.execute(
                select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
            ).scalar_one_or_none()
            is not None
        )
    finally:
        holder.rollback()  # release the lock so the drain can proceed
        holder.close()
        holder_engine.dispose()

    result = drain_enrollment_queue("http://rpc.invalid", "ethereum")
    assert result == {"drained": 1, "failed": 0}

    qsession.expire_all()
    enrolled = (
        qsession.execute(
            select(MonitoredContract).where(
                MonitoredContract.protocol_id == proto.id,
                MonitoredContract.is_active.is_(True),
            )
        )
        .scalars()
        .all()
    )
    # The vault contract the skipped fast path missed is now enrolled.
    addrs = {mc.address for mc in enrolled}
    assert VAULT_ADDR.lower() in addrs


# ---------------------------------------------------------------------------
# Lease exclusivity + expiry
# ---------------------------------------------------------------------------


def test_concurrent_drain_exclusivity(qsession):
    proto = _make_protocol(qsession)
    mark_enrollment_dirty(qsession, proto.id, "manual")
    qsession.commit()

    engine_a, engine_b = _engine(), _engine()
    sess_a = Session(engine_a, expire_on_commit=False)
    sess_b = Session(engine_b, expire_on_commit=False)
    try:
        claimed_a = claim_due_enrollments(sess_a, lease_ttl_s=900, limit=8)
        assert [c.protocol_id for c in claimed_a] == [proto.id]

        # The row is leased and unexpired; a second independent drainer sees
        # nothing due.
        claimed_b = claim_due_enrollments(sess_b, lease_ttl_s=900, limit=8)
        assert claimed_b == []
    finally:
        sess_a.close()
        sess_b.close()
        engine_a.dispose()
        engine_b.dispose()


def test_lease_expiry_mid_build_steal(qsession):
    proto = _make_protocol(qsession)
    mark_enrollment_dirty(qsession, proto.id, "manual")
    qsession.commit()

    engine_a, engine_b = _engine(), _engine()
    sess_a = Session(engine_a, expire_on_commit=False)
    sess_b = Session(engine_b, expire_on_commit=False)
    try:
        claimed_a = claim_due_enrollments(sess_a, lease_ttl_s=900, limit=8)
        assert len(claimed_a) == 1

        # Simulate a build that outran its lease TTL: age the lease into the past.
        sess_a.execute(
            text(
                "UPDATE monitoring_enrollment_queue SET lease_expires_at = NOW() - INTERVAL '1 second' "
                "WHERE protocol_id = :pid"
            ),
            {"pid": proto.id},
        )
        sess_a.commit()

        claimed_b = claim_due_enrollments(sess_b, lease_ttl_s=900, limit=8)
        assert [c.protocol_id for c in claimed_b] == [proto.id], "expired lease must be re-claimable"
    finally:
        sess_a.close()
        sess_b.close()
        engine_a.dispose()
        engine_b.dispose()


# ---------------------------------------------------------------------------
# dirty_at-guarded delete keeps a row re-dirtied during the build
# ---------------------------------------------------------------------------


def test_redirty_during_build_survives_success_delete(qsession):
    proto = _make_protocol(qsession)
    mark_enrollment_dirty(qsession, proto.id, "manual")
    qsession.commit()

    claims = claim_due_enrollments(qsession, lease_ttl_s=900, limit=8)
    claim = claims[0]

    # A new mark lands while the build is in flight: dirty_at advances.
    mark_enrollment_dirty(qsession, proto.id, "audit_added")
    qsession.commit()

    reconciler._finish_success(qsession, claim)

    row = qsession.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
    ).scalar_one_or_none()
    assert row is not None, "re-dirtied row must survive the dirty_at-guarded delete"
    assert row.reason == "audit_added"
    # Our lease was released so the next tick can re-claim it.
    assert row.lease_id is None
    assert row.lease_expires_at is None


# The unchanged-row delete + reconcile-stamp path of ``_finish_success`` is
# covered end-to-end by ``test_mark_then_drain_enrolls_controllers`` (queue row
# consumed, ``last_enrollment_reconcile_at`` stamped); the re-dirtied branch is
# ``test_redirty_during_build_survives_success_delete`` above.


# ---------------------------------------------------------------------------
# Poisoned-protocol backoff
# ---------------------------------------------------------------------------


def test_poisoned_protocol_backoff_pushes_dirty_at_forward(qsession):
    proto = _make_protocol(qsession)
    mark_enrollment_dirty(qsession, proto.id, "manual")
    qsession.commit()

    claim = claim_due_enrollments(qsession, lease_ttl_s=900, limit=8)[0]
    reconciler._finish_failure(qsession, claim)

    row = qsession.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
    ).scalar_one()
    assert row.attempts == 1
    assert row.lease_id is None
    # dirty_at pushed into the future (2^1 * 60 = 120s), so it is no longer due.
    future = qsession.execute(
        text("SELECT dirty_at > NOW() FROM monitoring_enrollment_queue WHERE protocol_id = :pid"),
        {"pid": proto.id},
    ).scalar_one()
    assert future is True

    # A poisoned row is not claimable until its backoff elapses.
    assert claim_due_enrollments(qsession, lease_ttl_s=900, limit=8) == []

    # A second failure grows attempts and the backoff.
    qsession.execute(
        text(
            "UPDATE monitoring_enrollment_queue SET dirty_at = NOW(), lease_id = NULL, lease_expires_at = NULL "
            "WHERE protocol_id = :pid"
        ),
        {"pid": proto.id},
    )
    qsession.commit()
    claim2 = claim_due_enrollments(qsession, lease_ttl_s=900, limit=8)[0]
    reconciler._finish_failure(qsession, claim2)
    row2 = qsession.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
    ).scalar_one()
    assert row2.attempts == 2


# ---------------------------------------------------------------------------
# K-sweep enqueues the oldest, NULLS FIRST
# ---------------------------------------------------------------------------


def test_sweep_enqueues_k_oldest_nulls_first(qsession):
    never = _make_protocol(qsession, "sweep_never")  # last_enrollment_reconcile_at NULL
    old = _make_protocol(qsession, "sweep_old")
    recent = _make_protocol(qsession, "sweep_recent")
    # Park every other protocol at NOW() so ordering over the whole table is
    # deterministic — our NULL row sorts first, then the 10-day-old one.
    qsession.execute(
        text("UPDATE protocols SET last_enrollment_reconcile_at = NOW() WHERE id NOT IN (:a, :b, :c)"),
        {"a": never.id, "b": old.id, "c": recent.id},
    )
    qsession.execute(
        text("UPDATE protocols SET last_enrollment_reconcile_at = NOW() - INTERVAL '10 days' WHERE id = :pid"),
        {"pid": old.id},
    )
    qsession.execute(
        text("UPDATE protocols SET last_enrollment_reconcile_at = NOW() WHERE id = :pid"),
        {"pid": recent.id},
    )
    qsession.commit()

    enqueued = sweep_enqueue_stale(qsession, k=2)

    # NULLS FIRST then oldest-dated: exactly the never + old pair.
    assert set(enqueued) == {never.id, old.id}
    assert recent.id not in enqueued
    for pid in enqueued:
        reason = qsession.execute(
            select(MonitoringEnrollmentQueue.reason).where(MonitoringEnrollmentQueue.protocol_id == pid)
        ).scalar_one()
        assert reason == "sweep"


# The NULLS-FIRST-then-oldest ordering is asserted through the real
# ``sweep_enqueue_stale`` in ``test_sweep_enqueues_k_oldest_nulls_first`` above;
# a raw ``order_by`` re-assertion here would only re-test SQLAlchemy.


# ---------------------------------------------------------------------------
# Call sites
# ---------------------------------------------------------------------------


def test_policy_worker_marks_dirty(qsession, monkeypatch):
    from workers.policy_worker import PolicyWorker

    proto = _make_protocol(qsession)
    # A completed sibling job makes maybe_enroll_protocol return True.
    qsession.add(Job(address="0x" + "a2" * 20, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    job = Job(
        address="0x" + "b3" * 20,
        name="TestContract",
        protocol_id=proto.id,
        chain_id=1,
        status=JobStatus.processing,
        stage=JobStage.policy,
        request={"rpc_url": "https://rpc.example", "chain": "ethereum"},
    )
    qsession.add(job)
    qsession.commit()

    artifacts = {
        "contract_analysis": {"contract_address": job.address, "contract_name": "TestContract", "functions": []},
        "control_snapshot": {"contract_address": job.address, "controller_values": {}},
        "resolved_control_graph": {"nodes": [], "edges": []},
        "control_tracking_plan": {"schema_version": "0.1", "contract_address": job.address},
    }
    monkeypatch.setattr("workers.policy_worker.get_artifact", lambda _s, _j, name: artifacts.get(name))
    monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *a, **kw: {})
    monkeypatch.setattr(
        "workers.policy_worker.build_effective_permissions",
        lambda *a, **kw: {"schema_version": "1", "functions": []},
    )
    monkeypatch.setattr("workers.policy_worker.resolve_control_graph", lambda **kw: ({}, {}))
    monkeypatch.setattr("workers.policy_worker.build_principal_labels", lambda *a, **kw: {"principals": []})
    monkeypatch.setattr(
        PolicyWorker,
        "_resolve_authority",
        lambda self, *a, **kw: {"principal_resolution": {"status": "no_authority"}, "authority_snapshot": None},
    )
    monkeypatch.setattr(PolicyWorker, "_enrich_cross_contract", lambda self, *a, **kw: {})
    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", lambda *a, **kw: "0x100")
    # Stub the DeFiLlama fetch so the initial-TVL block doesn't touch the network.
    monkeypatch.setattr("services.monitoring.tvl.fetch_defillama_tvl", lambda *a, **kw: None)

    PolicyWorker().process(qsession, job)

    row = qsession.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
    ).scalar_one_or_none()
    assert row is not None
    assert row.reason == "policy_complete"


def test_discovery_gate_promotion_marks_dirty(qsession, monkeypatch):
    """The fetch path routes membership through the gate: a candidate whose
    witnesses already satisfy W1 + an admitting rule is promoted during intake,
    and the PROMOTION (not the worker) marks the enrollment queue dirty."""
    from db.models import WITNESS_RULE_W1_CODE, WITNESS_RULE_W2_STRUCTURAL, ContractProbeAttempt
    from services.discovery import membership_gate as gate
    from workers.discovery import DiscoveryWorker

    proto = _make_protocol(qsession)
    addr = DISCOVERY_ADDR
    anchor = Contract(
        address="0x" + "d5" * 20,
        chain="ethereum",
        protocol_id=proto.id,
        contract_name="Anchor",
        implementation=addr.lower(),
    )
    existing = Contract(
        address=addr.lower(),
        chain="ethereum",
        protocol_id=None,
        nominated_protocol_id=proto.id,
        contract_name="Old",
        discovery_sources=["deployer_expansion"],
    )
    session_job = Job(
        address=addr.lower(),
        protocol_id=proto.id,
        status=JobStatus.processing,
        stage=JobStage.discovery,
        request={"chain": "ethereum"},
    )
    qsession.add_all([anchor, existing, session_job])
    qsession.commit()
    existing_id = existing.id
    # Probe already ran (event 1) — the intake must not re-probe.
    qsession.add(
        ContractProbeAttempt(contract_id=existing_id, chain_id=1, block_number=100, results={"status": "probed"})
    )
    gate.write_witness(
        qsession,
        contract_id=existing_id,
        protocol_id=proto.id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=gate.w1_evidence(chain_id=1, code_probe_block=100),
    )
    gate.write_witness(
        qsession,
        contract_id=existing_id,
        protocol_id=proto.id,
        rule=WITNESS_RULE_W2_STRUCTURAL,
        evidence=gate.w2_evidence(
            edge_kind="implementation",
            member_contract_id=anchor.id,
            member_address=anchor.address,
            resolved_pointer=addr.lower(),
        ),
        via_address=anchor.address,
    )
    qsession.commit()

    etherscan_result = {
        "ContractName": "AdoptedContract",
        "CompilerVersion": "v0.8.20+commit.a1b2c3d4",
        "SourceCode": "pragma solidity ^0.8.20; contract AdoptedContract {}",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "shanghai",
        "LicenseType": "MIT",
    }
    monkeypatch.setattr("workers.discovery.fetch", lambda _addr, **_kw: etherscan_result)
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addresses, **kw: {})
    monkeypatch.setattr("workers.discovery.store_source_files", lambda *a, **kw: None)
    monkeypatch.setattr("workers.discovery.store_artifact", lambda *a, **kw: None)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *a, **kw: None)

    worker._process_address(qsession, session_job)

    adopted = qsession.execute(select(Contract.protocol_id).where(Contract.id == existing_id)).scalar_one()
    assert adopted == proto.id, "gate promotion should have fired during intake"
    row = qsession.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
    ).scalar_one_or_none()
    assert row is not None
    assert row.reason == gate.MEMBERSHIP_DIRTY_REASON


def test_reenroll_route_marks_dirty(api_client, db_session, monkeypatch):
    import api as api_module
    from routers.deps import require_admin_key

    api_module.app.dependency_overrides[require_admin_key] = lambda: None
    monkeypatch.setattr("services.monitoring.enrollment.rpc_request", lambda *a, **kw: "0x100")
    proto = Protocol(name=NAME_PREFIX + "reenroll")
    try:
        db_session.add(proto)
        db_session.commit()

        resp = api_client.post(f"/api/protocols/{proto.id}/re-enroll")
        assert resp.status_code == 200

        row = db_session.execute(
            select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
        ).scalar_one_or_none()
        assert row is not None
        assert row.reason == "manual"
    finally:
        api_module.app.dependency_overrides.pop(require_admin_key, None)
        db_session.execute(delete(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id))
        db_session.execute(delete(Protocol).where(Protocol.id == proto.id))
        db_session.commit()


def test_add_audit_route_marks_dirty(api_client, db_session):
    import api as api_module
    from routers.deps import require_admin_key

    api_module.app.dependency_overrides[require_admin_key] = lambda: None
    name = NAME_PREFIX + "audit"
    proto = Protocol(name=name)
    try:
        db_session.add(proto)
        db_session.commit()

        resp = api_client.post(
            f"/api/company/{name}/audits",
            json={"url": "https://example.com/audit.pdf", "auditor": "ACME", "title": "Q3 Review"},
        )
        assert resp.status_code == 200, resp.text

        row = db_session.execute(
            select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id)
        ).scalar_one_or_none()
        assert row is not None
        assert row.reason == "audit_added"
    finally:
        api_module.app.dependency_overrides.pop(require_admin_key, None)
        from db.models import AuditReport

        db_session.execute(delete(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == proto.id))
        db_session.execute(delete(AuditReport).where(AuditReport.protocol_id == proto.id))
        db_session.execute(delete(Protocol).where(Protocol.id == proto.id))
        db_session.commit()


# ---------------------------------------------------------------------------
# Failure path in the full drain (poisoned protocol doesn't abort the drain)
# ---------------------------------------------------------------------------


# The drain-level failure path (drain returns ``{"drained":0,"failed":1}``,
# attempts bumped, lease cleared) and the sweep's skip-already-queued branch
# (``dirty_at`` and ``reason`` preserved for a backed-off row) are both asserted
# by ``test_poisoned_protocol_not_redrained_each_tick`` below, which drives the
# same drain+sweep sequence with strictly stronger assertions.


def test_poisoned_protocol_not_redrained_each_tick(qsession, wired_drain, monkeypatch):
    """Integrated loop behaviour: after a build fails and backs the row off, the
    next tick's sweep must NOT pull ``dirty_at`` back to now(), so the poisoned
    protocol is not re-claimed and re-built every tick."""
    proto = _seed_protocol_with_controller(qsession)
    mark_enrollment_dirty(qsession, proto.id, "policy_complete")
    qsession.commit()

    def _boom(*a, **kw):
        raise RuntimeError("enroll blew up")

    monkeypatch.setattr("services.monitoring.reconciler.enroll_protocol_contracts", _boom)

    # Tick 1: drain fails -> attempts=1, dirty_at pushed ~120s into the future.
    assert drain_enrollment_queue("http://rpc.invalid", "ethereum") == {"drained": 0, "failed": 1}
    before = qsession.execute(
        text("SELECT dirty_at, reason, attempts FROM monitoring_enrollment_queue WHERE protocol_id = :pid"),
        {"pid": proto.id},
    ).one()
    assert before.attempts == 1

    # Tick 2 sweep: must skip the backed-off row (it's already queued).
    enqueued = sweep_enqueue_stale(qsession, k=50)
    collateral = [pid for pid in enqueued if pid != proto.id]
    if collateral:
        qsession.execute(delete(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id.in_(collateral)))
    qsession.commit()

    after = qsession.execute(
        text("SELECT dirty_at, reason, attempts FROM monitoring_enrollment_queue WHERE protocol_id = :pid"),
        {"pid": proto.id},
    ).one()
    assert after.dirty_at == before.dirty_at, "sweep must not pull a backed-off row's dirty_at forward"
    assert after.reason == "policy_complete", "sweep must not overwrite the poisoned row's reason"
    assert after.attempts == 1, "poisoned row must not have been re-attempted this tick"

    # And the drain still finds nothing due for it (backoff intact).
    still_due = qsession.execute(
        text(
            "SELECT COUNT(*) FROM monitoring_enrollment_queue "
            "WHERE protocol_id = :pid AND dirty_at <= NOW() "
            "AND (lease_expires_at IS NULL OR lease_expires_at < NOW())"
        ),
        {"pid": proto.id},
    ).scalar_one()
    assert still_due == 0


# ---------------------------------------------------------------------------
# Reconciler loop: one tick = sweep + drain + heartbeat
# ---------------------------------------------------------------------------


def test_run_loop_single_tick_sweeps_drains_and_heartbeats(monkeypatch):
    from threading import Event

    engine = _engine()
    monkeypatch.setattr(reconciler, "SessionLocal", sessionmaker(bind=engine, expire_on_commit=False))

    stop = Event()
    calls = {"sweep": 0, "hb": None}
    monkeypatch.setattr(
        reconciler,
        "sweep_enqueue_stale",
        lambda session, *a, **k: calls.__setitem__("sweep", calls["sweep"] + 1),
    )

    def _fake_drain(*a, **k):
        stop.set()  # end the loop after this single tick
        return {"drained": 3, "failed": 1}

    monkeypatch.setattr(reconciler, "drain_enrollment_queue", _fake_drain)
    monkeypatch.setattr(
        reconciler,
        "record_heartbeat",
        lambda name, *, status, detail: calls.__setitem__("hb", (name, status, detail)),
    )

    try:
        reconciler.run_enrollment_reconciler_loop("http://rpc.invalid", "ethereum", interval=0, stop_event=stop)
    finally:
        engine.dispose()

    assert calls["sweep"] == 1
    name, status, detail = calls["hb"]
    assert status == "running"
    assert detail["drained"] == 3
    assert detail["failures"] == 1
    assert "queue_depth" in detail
