"""A lock timeout inside the audit row loop is retried, not fatal, and never double-claims or half-persists a row.

Faults are real: another connection holds the row (or the lifecycle gate) ``FOR UPDATE`` while the worker's sessions
run with a short ``lock_timeout``. Only the PDF download is stubbed.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from services.worker_lifecycle import register_boot
from tests.conftest import DATABASE_URL, requires_postgres, requires_storage
from tests.support.pdf import minimal_pdf_with_text

pytestmark = [requires_postgres, requires_storage]

_SCOPE = "Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 15


@pytest.fixture
def lifecycle(db_session, monkeypatch):
    boot = uuid.uuid4()
    db_session.execute(text("UPDATE worker_lifecycle SET paused=false, next_start_at=NULL WHERE id=1"))
    register_boot(db_session, boot, "lockfault")
    monkeypatch.setenv("PSAT_WORKER_BOOT_ID", str(boot))
    yield db_session
    db_session.rollback()
    db_session.execute(text("UPDATE worker_lifecycle SET boot_id=NULL, phase='stopped', paused=true WHERE id=1"))
    db_session.commit()


@pytest.fixture
def audits(lifecycle):
    from db.models import AuditReport, Protocol

    protocol = Protocol(name=f"lockfault-{uuid.uuid4().hex[:8]}")
    lifecycle.add(protocol)
    lifecycle.commit()
    urls = [f"https://example.invalid/lockfault-{i}.pdf" for i in range(2)]
    rows = [
        AuditReport(protocol_id=protocol.id, url=url, pdf_url=url, title="t", auditor="a", date="2025-01-01")
        for url in urls
    ]
    lifecycle.add_all(rows)
    lifecycle.commit()
    ids = [row.id for row in rows]
    yield dict(zip(ids, urls))
    lifecycle.rollback()
    lifecycle.query(AuditReport).filter(AuditReport.protocol_id == protocol.id).delete()
    lifecycle.query(Protocol).filter(Protocol.id == protocol.id).delete()
    lifecycle.commit()


@pytest.fixture
def engines():
    worker_engine = create_engine(DATABASE_URL, connect_args={"options": "-c lock_timeout=100"})
    blocker_engine = create_engine(DATABASE_URL)
    yield worker_engine, blocker_engine
    worker_engine.dispose()
    blocker_engine.dispose()


def _worker(monkeypatch, worker_engine, downloads: Counter, on_download=None):
    import workers.audit_row_worker as loop_mod
    import workers.audit_text_extraction as worker_mod

    factory = sessionmaker(bind=worker_engine, expire_on_commit=False)
    monkeypatch.setattr(loop_mod, "SessionLocal", factory)
    monkeypatch.setattr(worker_mod, "SessionLocal", factory)
    pdf = minimal_pdf_with_text(_SCOPE)

    def fake_download(url, session=None):
        downloads[url] += 1
        if on_download is not None:
            on_download(url)
        return pdf

    monkeypatch.setattr("services.audits.text_extraction.download_pdf", fake_download)
    monkeypatch.setattr("services.audits.text_extraction.download_text", fake_download)
    with patch("signal.signal"):
        worker = worker_mod.AuditTextExtractionWorker()
    worker.idle_poll_interval = 0.02
    return worker


def _run(worker) -> tuple[threading.Thread, list[BaseException]]:
    errors: list[BaseException] = []

    def target() -> None:
        try:
            worker.run_loop()
        except BaseException as exc:  # noqa: BLE001 - the test inspects what escaped
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, errors


def _statuses(session, ids) -> dict[int, tuple]:
    rows = session.execute(
        text(
            "SELECT id, text_extraction_status, text_storage_key, text_extracted_at FROM audit_reports "
            "WHERE id = ANY(:ids)"
        ),
        {"ids": list(ids)},
    ).all()
    return {row[0]: tuple(row[1:]) for row in rows}


def _wait_for(predicate, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_lock_timeout_on_the_claim_gate_claims_nothing_and_the_loop_survives(
    lifecycle, audits, engines, storage_bucket, monkeypatch
):
    worker_engine, blocker_engine = engines
    downloads: Counter = Counter()
    worker = _worker(monkeypatch, worker_engine, downloads)
    blocker = blocker_engine.connect()
    blocker_tx = blocker.begin()
    blocker.execute(text("SELECT 1 FROM worker_lifecycle WHERE id = 1 FOR UPDATE"))

    thread, errors = _run(worker)
    try:
        time.sleep(0.6)
        assert thread.is_alive() and not errors
        assert all(state[0] is None for state in _statuses(lifecycle, audits).values())
        assert not any(downloads[url] for url in audits.values())
        assert worker._db_failing_since is not None
    finally:
        blocker_tx.commit()
        blocker.close()

    try:
        assert _wait_for(lambda: all(s[0] == "success" for s in _statuses(lifecycle, audits).values()))
    finally:
        worker._running = False
        thread.join(timeout=10)
    assert not errors
    assert {url: downloads[url] for url in audits.values()} == {url: 1 for url in audits.values()}
    assert worker._db_failing_since is None


def test_lock_timeout_on_persist_retries_without_reclaiming_or_partial_writes(
    lifecycle, audits, engines, storage_bucket, monkeypatch
):
    worker_engine, blocker_engine = engines
    downloads: Counter = Counter()
    target_id, target_url = next(iter(audits.items()))
    blocker = blocker_engine.connect()
    blocker_tx = blocker.begin()
    locked = threading.Event()

    def lock_target_row(url: str) -> None:
        # The claim has committed by now, so the row lock is free to take before the worker persists.
        if url == target_url and not locked.is_set():
            blocker.execute(text("SELECT 1 FROM audit_reports WHERE id = :id FOR UPDATE"), {"id": target_id})
            locked.set()

    worker = _worker(monkeypatch, worker_engine, downloads, on_download=lock_target_row)
    thread, errors = _run(worker)
    try:
        assert locked.wait(timeout=10)
        time.sleep(0.6)
        mid = _statuses(lifecycle, [target_id])[target_id]
        assert mid == ("processing", None, None)
        assert thread.is_alive() and not errors
    finally:
        blocker_tx.commit()
        blocker.close()

    try:
        assert _wait_for(lambda: all(s[0] == "success" for s in _statuses(lifecycle, audits).values()))
    finally:
        worker._running = False
        thread.join(timeout=10)
    assert not errors
    assert {url: downloads[url] for url in audits.values()} == {url: 1 for url in audits.values()}
    status, storage_key, extracted_at = _statuses(lifecycle, [target_id])[target_id]
    assert (status, storage_key) == ("success", f"audits/text/{target_id}.txt") and extracted_at is not None


def test_sustained_lock_timeouts_exit_after_the_grace_period(lifecycle, audits, engines, storage_bucket, monkeypatch):
    worker_engine, blocker_engine = engines
    downloads: Counter = Counter()
    worker = _worker(monkeypatch, worker_engine, downloads)
    worker.db_failure_grace_seconds = 0.5
    blocker = blocker_engine.connect()
    blocker_tx = blocker.begin()
    blocker.execute(text("SELECT 1 FROM worker_lifecycle WHERE id = 1 FOR UPDATE"))
    try:
        thread, errors = _run(worker)
        thread.join(timeout=10)
        assert not thread.is_alive()
    finally:
        blocker_tx.rollback()
        blocker.close()

    assert len(errors) == 1 and isinstance(errors[0], OperationalError)
    assert not any(downloads[url] for url in audits.values())
    assert all(state[0] is None for state in _statuses(lifecycle, audits).values())


def _scope_worker(monkeypatch, worker_engine):
    import workers.audit_scope_extraction as scope_mod

    monkeypatch.setattr(scope_mod, "SessionLocal", sessionmaker(bind=worker_engine, expire_on_commit=False))
    with patch("signal.signal"):
        return scope_mod.AuditScopeExtractionWorker()


def _scope_state(session, audit_id: int) -> tuple:
    return session.execute(
        text("SELECT scope_extraction_status, scope_contracts FROM audit_reports WHERE id = :id"), {"id": audit_id}
    ).one()


def test_scope_persist_lock_timeout_propagates_with_nothing_written(lifecycle, audits, engines, monkeypatch):
    from services.audits import ScopeExtractionOutcome

    worker_engine, blocker_engine = engines
    worker = _scope_worker(monkeypatch, worker_engine)
    audit_id = next(iter(audits))
    blocker = blocker_engine.connect()
    blocker_tx = blocker.begin()
    blocker.execute(text("SELECT 1 FROM audit_reports WHERE id = :id FOR UPDATE"), {"id": audit_id})
    try:
        with pytest.raises(OperationalError):
            worker._persist_outcome(audit_id, ScopeExtractionOutcome(status="success", contracts=("Pool",)))
    finally:
        blocker_tx.rollback()
        blocker.close()
    assert tuple(_scope_state(lifecycle, audit_id)) == (None, None)


def test_coverage_refresh_lock_timeout_rolls_back_the_whole_scope_write(lifecycle, audits, engines, monkeypatch):
    from services.audits import ScopeExtractionOutcome

    worker_engine, _ = engines
    worker = _scope_worker(monkeypatch, worker_engine)
    audit_id = next(iter(audits))

    def coverage_lock_timeout(session, *_args, **_kwargs):
        session.execute(text("SET LOCAL lock_timeout = 1"))
        session.execute(text("SELECT pg_advisory_xact_lock(0)"))
        raise AssertionError("the advisory lock is held by the test, so the line above must time out")

    holder = worker_engine.connect()
    holder_tx = holder.begin()
    holder.execute(text("SELECT pg_advisory_xact_lock(0)"))
    monkeypatch.setattr("services.audits.coverage.upsert_coverage_for_audit", coverage_lock_timeout)
    try:
        with pytest.raises(OperationalError):
            worker._persist_outcome(audit_id, ScopeExtractionOutcome(status="success", contracts=("Pool",)))
    finally:
        holder_tx.rollback()
        holder.close()
    assert tuple(_scope_state(lifecycle, audit_id)) == (None, None)


def test_a_persist_blocked_past_its_window_leaves_the_row_and_keeps_the_loop(
    lifecycle, audits, engines, storage_bucket, monkeypatch
):
    worker_engine, blocker_engine = engines
    downloads: Counter = Counter()
    target_id, target_url = next(iter(audits.items()))
    blocker = blocker_engine.connect()
    blocker_tx = blocker.begin()
    locked = threading.Event()

    def lock_target_row(url: str) -> None:
        if url == target_url and not locked.is_set():
            blocker.execute(text("SELECT 1 FROM audit_reports WHERE id = :id FOR UPDATE"), {"id": target_id})
            locked.set()

    worker = _worker(monkeypatch, worker_engine, downloads, on_download=lock_target_row)
    worker.stale_processing_seconds = 2
    thread, errors = _run(worker)
    try:
        assert locked.wait(timeout=10)
        others = [audit_id for audit_id in audits if audit_id != target_id]
        assert _wait_for(lambda: all(_statuses(lifecycle, others)[i][0] == "success" for i in others))
        time.sleep(1.5)
        assert thread.is_alive() and not errors
        assert _statuses(lifecycle, [target_id])[target_id] == ("processing", None, None)
        # Given up, never re-claimed while this worker still held the outcome.
        assert downloads[target_url] == 1

        # The loop moved on rather than retrying one row until the grace period ends the process.
        from db.models import AuditReport

        late_url = "https://example.invalid/lockfault-late.pdf"
        late = AuditReport(
            protocol_id=lifecycle.get(AuditReport, target_id).protocol_id,
            url=late_url,
            pdf_url=late_url,
            title="t",
            auditor="a",
            date="2025-01-01",
        )
        lifecycle.add(late)
        lifecycle.commit()
        assert _wait_for(lambda: _statuses(lifecycle, [late.id])[late.id][0] == "success")
    finally:
        worker._running = False
        blocker_tx.rollback()
        blocker.close()
        thread.join(timeout=10)
    assert not errors
