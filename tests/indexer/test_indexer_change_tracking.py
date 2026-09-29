"""Real PostgreSQL contracts for durable indexer scheduling (no external I/O)."""

from datetime import timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from db.models import (
    Artifact,
    Contract,
    ControllerValue,
    IndexedEventCursor,
    IndexedEventLog,
    IndexerWork,
    Job,
    JobStage,
    JobStatus,
    MonitoredContract,
)
from services.resolution import indexer_scheduler as scheduler
from services.resolution.indexer_work import claim_one, finish, mark_dirty, repair_due
from tests.conftest import requires_postgres
from tests.resolution.test_deferred_resolution_reconcile import (
    _role_store_cap,
    _seed_completed_job_with_cap,
    _seed_role_set_row,
    _seed_role_store_cursor,
)

pytestmark = requires_postgres
AUTH = "0x" + "a7" * 20
ADDR = "0x" + "b8" * 20


@pytest.fixture
def session(db_session):
    db_session.execute(delete(IndexerWork))
    db_session.commit()
    yield db_session
    db_session.rollback()
    db_session.execute(delete(IndexerWork))
    db_session.commit()


def clean(session):
    session.execute(update(IndexerWork).values(dirty=False, completed_at=func.now()))
    session.commit()
    session.expire_all()


def work(session, kind, key):
    session.expire_all()
    return session.get(IndexerWork, (kind, str(key)))


def job(session):
    row = Job(address=ADDR, chain_id=1, status=JobStatus.completed, stage=JobStage.done, request={"chain": "ethereum"})
    session.add(row)
    session.commit()
    return row


def test_claim_revision_failure_retry_and_new_write(session):
    mark_dirty(session, "job", "sample")
    session.commit()
    claimed = claim_one(session, ("job",))
    assert claimed is not None
    with Session(session.get_bind()) as writer:
        mark_dirty(writer, "job", "sample")
        writer.commit()
    finish(session, claimed, success=True)
    row = work(session, "job", "sample")
    assert row.dirty and row.revision == 2 and row.lease_id is None
    claimed = claim_one(session, ("job",))
    assert claimed is not None
    finish(session, claimed, success=False)
    assert claim_one(session, ("job",)) is None  # Failed work is not hot-looped.
    assert work(session, "job", "sample").attempts == 1
    assert repair_due(session, ("job",)) == 0
    mark_dirty(session, "job", "sample")
    session.commit()
    assert claim_one(session, ("job",)) is not None  # A new input bypasses old backoff.


@pytest.mark.parametrize("success", [True, False])
def test_expired_owner_cannot_acknowledge_or_reschedule_new_owner(session, success):
    mark_dirty(session, "job", "sample")
    session.commit()
    old = claim_one(session, ("job",))
    assert old is not None
    assert claim_one(session, ("job",)) is None
    session.execute(update(IndexerWork).values(lease_expires_at=func.now() - timedelta(seconds=1)))
    session.commit()
    new = claim_one(session, ("job",))
    assert new is not None
    finish(session, old, success=success, remove=True)
    row = work(session, "job", "sample")
    assert row.dirty and row.lease_id == new.lease_id and row.attempts == 0
    finish(session, new, success=True)
    assert not work(session, "job", "sample").dirty


def test_daily_repair_is_bounded_and_preserves_failure_backoff(session):
    for key in ("a", "b", "c"):
        mark_dirty(session, "job", key)
    session.commit()
    clean(session)
    session.execute(update(IndexerWork).values(completed_at=func.now() - timedelta(days=2)))
    session.commit()
    assert repair_due(session, ("job",), limit=2) == 2
    assert repair_due(session, ("job",), limit=2) == 1
    assert repair_due(session, ("job",), limit=2) == 0


def test_artifact_same_metadata_write_is_not_lost_and_rollback_is_atomic(session):
    row = job(session)
    artifact = Artifact(job_id=row.id, name="predicate_trees", storage_key="same-key", stored_object_size_bytes=42)
    session.add(artifact)
    session.commit()
    clean(session)
    # An object rewrite can have identical metadata. A real UPDATE must wake it.
    session.execute(update(Artifact).where(Artifact.id == artifact.id).values(storage_key="same-key"))
    session.rollback()
    assert not work(session, "job", row.id).dirty
    session.execute(update(Artifact).where(Artifact.id == artifact.id).values(storage_key="same-key"))
    session.commit()
    assert work(session, "job", row.id).dirty
    clean(session)
    session.add(Artifact(job_id=row.id, name="unrelated", data={}))
    session.commit()
    assert not work(session, "job", row.id).dirty


def test_controller_and_proxy_changes_wake_enrollment_but_job_heartbeat_does_not(session):
    row = job(session)
    contract = Contract(job_id=row.id, address=ADDR, chain="ethereum")
    session.add(contract)
    session.flush()
    controller = ControllerValue(contract_id=contract.id, controller_id="state:authority", value=AUTH)
    session.add(controller)
    session.commit()
    clean(session)
    session.execute(update(Job).where(Job.id == row.id).values(updated_at=func.now(), detail="heartbeat"))
    session.commit()
    assert not work(session, "job", row.id).dirty
    controller.value = "0x" + "c9" * 20
    session.commit()
    assert work(session, "job", row.id).dirty
    clean(session)
    row.request = {"chain": "ethereum", "proxy_address": AUTH}
    session.commit()
    assert work(session, "job", row.id).dirty


def test_tracking_plan_changes_wake_enrollment_but_scan_progress_does_not(session):
    row = MonitoredContract(address=ADDR, chain="ethereum", monitoring_config={"tracked_topics": []}, is_active=True)
    session.add(row)
    session.commit()
    clean(session)
    row.last_scanned_block = 500
    row.last_known_state = {"x": 1}
    session.commit()
    assert not work(session, "monitored", row.id).dirty
    row.monitoring_config = {"tracked_topics": [{"topic0": "0x" + "11" * 32}]}
    session.commit()
    assert work(session, "monitored", row.id).dirty


def test_cursor_empty_head_progress_does_not_wake_reconcile_but_readiness_and_rewind_do(session):
    _seed_role_store_cursor(session, AUTH, backfill_complete=False, last_block=100)
    session.commit()
    clean(session)
    session.execute(update(IndexedEventCursor).values(last_indexed_block=200, last_run_at=func.now()))
    session.commit()
    assert not work(session, "reconcile", 1).dirty
    session.execute(update(IndexedEventCursor).values(backfill_complete=True))
    session.commit()
    assert work(session, "reconcile", 1).dirty
    clean(session)
    session.execute(update(IndexedEventCursor).values(last_indexed_block=190))
    session.commit()
    assert work(session, "reorg", "1:" + AUTH).dirty  # Even when no log existed to DELETE.


def test_statement_trigger_ignores_empty_and_duplicate_log_inserts(session):
    _seed_role_set_row(session, AUTH, block=100)
    session.commit()
    clean(session)
    original = session.execute(select(IndexedEventLog)).scalar_one()
    values = {col.name: getattr(original, col.name) for col in IndexedEventLog.__table__.columns}
    session.execute(insert(IndexedEventLog).values(**values).on_conflict_do_nothing())
    session.commit()
    assert not work(session, "reconcile", 1).dirty
    session.execute(delete(IndexedEventLog).where(IndexedEventLog.block_number < 0))
    session.commit()
    assert work(session, "reorg", "1:" + AUTH) is None
    session.execute(delete(IndexedEventLog))
    session.commit()
    assert work(session, "reorg", "1:" + AUTH).dirty


def test_unchanged_enrollment_reads_no_artifact_and_poison_does_not_block_siblings(session, monkeypatch):
    import workers.event_log_indexer as indexer

    first = job(session)
    second = Job(address="0x" + "d1" * 20, chain_id=1, status=JobStatus.completed, stage=JobStage.done)
    session.add(second)
    session.commit()

    def read(_session, job_id, name):
        if job_id == first.id:
            raise ValueError("broken object")
        return {}

    read_mock = Mock(side_effect=read)
    monkeypatch.setattr(indexer, "get_artifact", read_mock)
    assert scheduler.drain_enrollment(session) == 0
    assert read_mock.call_count == 2
    assert work(session, "job", first.id).dirty
    assert not work(session, "job", second.id).dirty
    read_mock.reset_mock()
    scheduler.drain_enrollment(session)
    read_mock.assert_not_called()
    # Repair only the failed source; a new write allows it to run immediately.
    read_mock.side_effect = None
    read_mock.return_value = {}
    mark_dirty(session, "job", str(first.id))
    session.commit()
    scheduler.drain_enrollment(session)
    assert read_mock.call_count == 1
    assert not work(session, "job", first.id).dirty


def test_transient_missing_seed_stays_pending_until_retry_succeeds(session, monkeypatch):
    import workers.event_log_indexer as indexer

    row = job(session)
    monkeypatch.setattr(indexer, "get_artifact", lambda *_: {})
    monkeypatch.setattr(
        indexer,
        "_descriptors_from_artifact",
        lambda _: [{"enumeration_hint": [{"topic0": "0x" + "22" * 32, "event_address": AUTH}]}],
    )
    monkeypatch.setattr(indexer, "_seed_block", lambda *_a, **_kw: None)
    assert scheduler.drain_enrollment(session) == 0
    assert work(session, "job", row.id).dirty
    monkeypatch.setattr(indexer, "_seed_block", lambda *_a, **_kw: 100)
    monkeypatch.setattr(indexer, "_witness_seed_block", lambda *_a, **_kw: (100, "creation_block_minus_one"))
    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    assert scheduler.drain_enrollment(session) == 1
    assert not work(session, "job", row.id).dirty


@pytest.mark.parametrize("second_kind", ["job", "monitored"])
@pytest.mark.parametrize("second_chain", [1, 8453])
@pytest.mark.parametrize("raises", [False, True])
def test_drain_shares_failed_lookups_and_retries_with_fresh_caches(
    session, monkeypatch, second_kind, second_chain, raises
):
    import workers.event_log_indexer as indexer

    first = job(session)
    topics = ["0x" + "22" * 32, "0x" + "33" * 32]
    chain_name = "ethereum" if second_chain == 1 else "base"
    if second_kind == "job":
        second = Job(address=ADDR, chain_id=second_chain, status=JobStatus.completed, stage=JobStage.done)
    else:
        second = MonitoredContract(
            address=AUTH,
            chain=chain_name,
            is_active=True,
            monitoring_config={"tracked_topics": [{"topic0": topics[1]}]},
        )
    session.add(second)
    session.commit()
    sources = [("job", first.id), (second_kind, second.id)]
    monkeypatch.setattr(indexer, "supported_chain_ids", lambda: {1, 8453})
    monkeypatch.setattr(indexer, "get_artifact", lambda _s, source_id, _n: {"first": source_id == first.id})
    monkeypatch.setattr(
        indexer,
        "_descriptors_from_artifact",
        lambda artifact: [
            {"enumeration_hint": [{"topic0": topics[0 if artifact["first"] else 1], "event_address": AUTH}]}
        ],
    )
    creation = Mock(side_effect=TimeoutError("unavailable") if raises else None, return_value=None)
    monkeypatch.setattr(indexer, "get_contract_creation_block", creation)
    rpc = Mock(
        side_effect=lambda _url, method, params, **_kw: (
            [] if method == "eth_getLogs" else ("0x" if params[1] == hex(100) else "0x6000")
        )
    )
    monkeypatch.setattr(indexer, "require_rpc_url", lambda **_kw: "https://rpc.invalid")
    monkeypatch.setattr(indexer, "rpc_request", rpc)

    assert scheduler.drain_enrollment(session) == 0
    chains = {1, second_chain}
    assert creation.call_count == len(chains)
    assert {call.kwargs["chain_id"] for call in creation.call_args_list} == chains
    assert all(work(session, kind, key).dirty for kind, key in sources)
    assert all(work(session, kind, key).attempts == 1 for kind, key in sources)
    rpc.assert_not_called()
    scheduler.drain_enrollment(session)
    assert creation.call_count == len(chains)  # Backoff still applies per source.

    creation.reset_mock()
    creation.side_effect = None
    creation.return_value = 101
    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    assert scheduler.drain_enrollment(session) == 2
    assert creation.call_count == len(chains)
    assert rpc.call_count == 3 * len(chains)  # Witness reads are shared too.
    assert all(not work(session, kind, key).dirty for kind, key in sources)
    assert session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one() == 2


def test_drain_shares_delegated_role_probes_until_next_pass(session, monkeypatch):
    import workers.event_log_indexer as indexer

    sources = [job(session), job(session)]
    monkeypatch.setattr(indexer, "get_artifact", lambda *_: {})
    monkeypatch.setattr(indexer, "_descriptors_from_artifact", lambda _: [{"authority_contract": {"address": AUTH}}])
    monkeypatch.setattr(indexer, "_is_delegated_role_gate_descriptor", lambda _: True)
    probe = Mock(side_effect=TimeoutError("unavailable"))
    creation = Mock(return_value=None)
    monkeypatch.setattr(indexer, "resolve_probe_code", probe)
    monkeypatch.setattr(indexer, "get_contract_creation_block", creation)
    assert scheduler.drain_enrollment(session) == 0
    assert probe.call_count == creation.call_count == 1
    assert all(work(session, "job", source.id).dirty for source in sources)

    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    scheduler.drain_enrollment(session)
    assert probe.call_count == creation.call_count == 2
    assert all(work(session, "job", source.id).attempts == 2 for source in sources)


def test_reconciliation_runs_only_after_changes_and_retains_capped_work(session, monkeypatch):
    mark_dirty(session, "reconcile", "1")
    session.commit()
    deferred = Mock(return_value=0)
    drift = Mock(return_value=0)
    monkeypatch.setattr(scheduler, "reconcile_deferred_resolutions", deferred)
    monkeypatch.setattr(scheduler, "reconcile_role_set_drift", drift)
    scheduler.drain_reconciliation(session)
    scheduler.drain_reconciliation(session)
    assert deferred.call_count == drift.call_count == 1
    mark_dirty(session, "reconcile", "1")
    session.commit()
    deferred.return_value = 2
    scheduler.drain_reconciliation(session, job_limit=2)
    assert work(session, "reconcile", 1).dirty
    deferred.return_value = 0
    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    scheduler.drain_reconciliation(session)
    assert not work(session, "reconcile", 1).dirty


def test_reorg_removal_below_fold_frontier_requeues_once_after_warming(session):
    row = _seed_completed_job_with_cap(session, address=ADDR, capability_expr=_role_store_cap(AUTH, 100))
    _seed_role_store_cursor(session, AUTH, backfill_complete=False, last_block=90)
    _seed_role_set_row(session, AUTH, block=95)
    session.commit()
    clean(session)
    session.execute(delete(IndexedEventLog))
    session.commit()
    scheduler.drain_reconciliation(session)
    assert work(session, "reorg", "1:" + AUTH) is None
    assert work(session, "refresh_job", row.id).dirty
    assert session.get(Job, row.id).status == JobStatus.completed
    session.execute(update(IndexedEventCursor).values(backfill_complete=True, last_indexed_block=110))
    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    scheduler.drain_reconciliation(session)
    session.expire_all()
    assert session.get(Job, row.id).status == JobStatus.queued
    assert work(session, "refresh_job", row.id) is None
    # A later successful analysis is not forced again by a stuck chain marker.
    row = session.get(Job, row.id)
    row.status = JobStatus.completed
    row.stage = JobStage.done
    session.commit()
    scheduler.drain_reconciliation(session)
    assert session.get(Job, row.id).status == JobStatus.completed


def test_role_drift_uses_one_probe_per_distinct_frontier(session, monkeypatch):
    from services.resolution import deferred_reconciler as reconciler

    for i in range(6):
        _seed_completed_job_with_cap(
            session, address="0x" + f"{i + 100:040x}", capability_expr=_role_store_cap(AUTH, 100 + i % 2)
        )
    warm = Mock(return_value=True)
    probe = Mock(return_value=False)
    monkeypatch.setattr(reconciler, "_authority_backfilled", warm)
    monkeypatch.setattr(reconciler, "_role_row_past_frontier", probe)
    assert reconciler.reconcile_role_set_drift(session, chain_id=1) == 0
    assert warm.call_count == 1
    assert probe.call_count == 2


def test_role_lookup_preserves_case_insensitive_history(session):
    from services.resolution.deferred_reconciler import _role_row_past_frontier

    _seed_role_set_row(session, AUTH, block=200)
    session.flush()
    session.execute(update(IndexedEventLog).values(event_address=AUTH.upper()))
    session.commit()
    assert _role_row_past_frontier(session, 1, AUTH, 100)


def test_partial_seed_failure_preserves_siblings_and_retries_missing_only(session, monkeypatch):
    import workers.event_log_indexer as indexer

    row = job(session)
    addresses = ["0x" + f"{i:040x}" for i in (123, 124, 125)]
    missing = addresses[1]
    topic = "0x" + "11" * 32
    monkeypatch.setattr(indexer, "get_artifact", lambda *_: {})
    monkeypatch.setattr(
        indexer,
        "_descriptors_from_artifact",
        lambda _: [{"enumeration_hint": [{"topic0": topic, "event_address": addr} for addr in addresses]}],
    )
    monkeypatch.setattr(indexer, "_seed_block", lambda addr, *_a, **_kw: None if addr == missing else 100)
    monkeypatch.setattr(indexer, "_witness_seed_block", lambda *_a, **_kw: (100, "creation_block_minus_one"))
    assert scheduler.drain_enrollment(session) == 2
    assert work(session, "job", row.id).dirty
    assert session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one() == 2
    monkeypatch.setattr(indexer, "_seed_block", lambda *_a, **_kw: 100)
    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    assert scheduler.drain_enrollment(session) == 1
    assert not work(session, "job", row.id).dirty


def test_reconcile_self_dirty_is_left_for_next_pass(session, monkeypatch):
    mark_dirty(session, "reconcile", "1")
    session.commit()

    def self_dirty(s, **_):
        mark_dirty(s, "reconcile", "1")
        s.commit()
        return 0

    mocked = Mock(side_effect=self_dirty)
    monkeypatch.setattr(scheduler, "reconcile_deferred_resolutions", mocked)
    monkeypatch.setattr(scheduler, "reconcile_role_set_drift", lambda *_a, **_kw: 0)
    scheduler.drain_reconciliation(session)
    assert mocked.call_count == 1
    assert work(session, "reconcile", 1).dirty


def test_refresh_rechecks_locked_job_and_never_clears_concurrent_lease(session):
    import uuid

    from services.resolution.deferred_reconciler import refresh_invalidated_job
    from services.resolution.indexer_work import WorkPending

    row = _seed_completed_job_with_cap(session, address=ADDR, capability_expr=_role_store_cap(AUTH, 100))
    _seed_role_store_cursor(session, AUTH)
    session.commit()
    assert session.get(Job, row.id).status == JobStatus.completed
    lease = uuid.uuid4()
    with Session(session.get_bind()) as writer:
        writer.execute(
            update(Job)
            .where(Job.id == row.id)
            .values(status=JobStatus.processing, stage=JobStage.policy, lease_id=lease)
        )
        writer.commit()
    with pytest.raises(WorkPending):
        refresh_invalidated_job(session, row.id)
    assert session.get(Job, row.id).lease_id == lease
    assert session.get(Job, row.id).status == JobStatus.processing


def test_active_refresh_with_temporarily_missing_capability_stays_pending(session):
    from services.resolution.deferred_reconciler import refresh_invalidated_job
    from services.resolution.indexer_work import WorkPending

    row = job(session)
    row.status = JobStatus.processing
    session.commit()
    with pytest.raises(WorkPending):
        refresh_invalidated_job(session, row.id)


def test_log_move_invalidates_old_and_new_owners(session):
    _seed_role_set_row(session, AUTH, block=95)
    session.commit()
    clean(session)
    session.execute(update(IndexedEventLog).values(chain_id=8453, event_address=ADDR))
    session.commit()
    assert work(session, "reorg", "1:" + AUTH).dirty
    assert work(session, "reorg", "8453:" + ADDR).dirty
    assert work(session, "reconcile", 8453).dirty


def test_single_owner_update_marks_each_key_once(session):
    row = job(session)
    contract = Contract(job_id=row.id, address=ADDR, chain="ethereum")
    session.add(contract)
    session.flush()
    controller = ControllerValue(contract_id=contract.id, controller_id="state:authority", value=AUTH)
    session.add(controller)
    session.commit()
    before = work(session, "job", row.id).revision
    before_chain = work(session, "reconcile", 1).revision
    controller.value = ADDR
    session.commit()
    assert work(session, "job", row.id).revision == before + 1
    assert work(session, "reconcile", 1).revision == before_chain + 1


def test_claim_refreshes_cached_revision_after_concurrent_write(session):
    mark_dirty(session, "job", "source")
    session.commit()
    cached = work(session, "job", "source")
    assert cached.revision == 1
    with Session(session.get_bind()) as writer:
        mark_dirty(writer, "job", "source")
        writer.commit()
    claim = claim_one(session, ("job",))
    assert claim is not None
    assert claim.revision == 2
    finish(session, claim, success=True)
    assert not work(session, "job", "source").dirty


def test_more_than_500_sources_drain_in_bounded_batches_without_rereads(session, monkeypatch):
    import workers.event_log_indexer as indexer

    session.add_all(
        [
            Job(address=f"0x{i + 1:040x}", chain_id=1, status=JobStatus.completed, stage=JobStage.done)
            for i in range(501)
        ]
    )
    session.commit()
    reader = Mock(return_value={})
    monkeypatch.setattr(indexer, "get_artifact", reader)
    scheduler.drain_enrollment(session, limit=50)
    assert reader.call_count == 50
    for _ in range(10):
        scheduler.drain_enrollment(session, limit=50)
    assert reader.call_count == 501
    scheduler.drain_enrollment(session, limit=50)
    assert reader.call_count == 501


def test_enrollment_commits_before_next_external_read(session, monkeypatch):
    import workers.event_log_indexer as indexer

    row = job(session)
    addresses = [AUTH, ADDR]
    topic = "0x" + "77" * 32
    monkeypatch.setattr(indexer, "get_artifact", lambda *_: {})
    monkeypatch.setattr(
        indexer,
        "_descriptors_from_artifact",
        lambda _: [{"enumeration_hint": [{"topic0": topic, "event_address": a} for a in addresses]}],
    )
    observed = []

    def seed(address, *_a, **_kw):
        if address == ADDR:
            with Session(session.get_bind()) as other:
                other.execute(text("SET LOCAL lock_timeout='100ms'"))
                observed.append(other.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one())
                # The previous cursor's trigger must not hold the chain work row
                # locked while this next source is making an external request.
                mark_dirty(other, "reconcile", "1")
                other.commit()
        return 100

    monkeypatch.setattr(indexer, "_seed_block", seed)
    monkeypatch.setattr(indexer, "_witness_seed_block", lambda *_a, **_kw: (100, "creation_block_minus_one"))
    assert scheduler.drain_enrollment(session) == 2
    assert observed == [1]
    assert not work(session, "job", row.id).dirty


def test_lost_lease_cannot_renew_or_lock_for_reorg_side_effects(session):
    from services.resolution.indexer_work import WorkPending, lock_claim, renew_and_commit

    mark_dirty(session, "reorg", "1:" + AUTH)
    session.commit()
    old = claim_one(session, ("reorg",))
    assert old is not None
    session.execute(update(IndexerWork).values(lease_expires_at=func.now() - timedelta(seconds=1)))
    session.commit()
    with pytest.raises(WorkPending):
        renew_and_commit(session, old)
    new = claim_one(session, ("reorg",))
    assert new is not None
    with pytest.raises(WorkPending):
        lock_claim(session, old)
    session.rollback()
    assert work(session, "reorg", "1:" + AUTH).lease_id == new.lease_id


def test_crash_mid_role_authority_does_not_commit_an_incomplete_topic_group(session, monkeypatch):
    import workers.event_log_indexer as indexer
    from services.resolution.role_store_standards import all_topic0s

    row = job(session)
    topics = all_topic0s()[:2]
    monkeypatch.setattr(indexer, "get_artifact", lambda *_: {})
    monkeypatch.setattr(indexer, "_descriptors_from_artifact", lambda _: [{"authority_contract": {"address": AUTH}}])
    monkeypatch.setattr(indexer, "_is_delegated_role_gate_descriptor", lambda _: True)
    monkeypatch.setattr(indexer, "_role_store_topic0s", lambda *_: topics)
    monkeypatch.setattr(indexer, "_seed_block", lambda *_a, **_kw: 100)
    monkeypatch.setattr(indexer, "_witness_seed_block", lambda *_a, **_kw: (100, "creation_block_minus_one"))
    original = indexer._enroll_witnessed
    count = [0]

    def crash_after_first_insert(*args, **kwargs):
        count[0] += 1
        if count[0] == 2:
            raise RuntimeError("interrupted authority enrollment")
        return original(*args, **kwargs)

    monkeypatch.setattr(indexer, "_enroll_witnessed", crash_after_first_insert)
    scheduler.drain_enrollment(session)
    assert session.execute(select(func.count()).select_from(IndexedEventCursor)).scalar_one() == 0
    assert work(session, "job", row.id).dirty
    monkeypatch.setattr(indexer, "_enroll_witnessed", original)
    session.execute(update(IndexerWork).values(available_at=func.now()))
    session.commit()
    assert scheduler.drain_enrollment(session) == 2
    assert set(session.execute(select(IndexedEventCursor.topic0)).scalars()) == set(topics)
    assert not work(session, "job", row.id).dirty


def test_tracking_budget_does_not_disable_job_enrollment(session, monkeypatch):
    import workers.event_log_indexer as indexer

    row = job(session)
    monitored = MonitoredContract(
        address=ADDR, chain="ethereum", is_active=True, monitoring_config={"tracked_topics": []}
    )
    session.add(monitored)
    session.commit()
    reader = Mock(return_value={})
    monkeypatch.setattr(indexer, "get_artifact", reader)
    scheduler.drain_enrollment(session, tracked_limit=0)
    assert reader.call_count == 1
    assert not work(session, "job", row.id).dirty
    assert work(session, "monitored", monitored.id).dirty
    scheduler.drain_enrollment(session, tracked_limit=1)
    assert not work(session, "monitored", monitored.id).dirty
