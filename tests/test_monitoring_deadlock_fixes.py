"""Integration tests for the four monitoring deadlock-hardening fixes.

Drives the real ``poll_for_state_changes`` / ``run_poll_loop`` /
``run_scan_loop`` production paths against the real test DB (shared
``db_session`` fixture), stubbing only the wire — ``rpc_batch_request_with_status`` and,
for the deadlock cases, the narrowest DB statement that Postgres would abort.
Never replaces the repo classes.

Covers:
  1. Chunk-level deadlock isolation in the poller — a deadlock at the stamp
     (pre-commit) or during the suppression-SELECT autoflush rolls back only its
     chunk, leaves it unstamped, and the pass finishes ``partial`` with the
     other chunks committed. A non-deadlock OperationalError still kills the pass.
  2. Per-chunk post-commit notification — committed chunks notify exactly once;
     a rolled-back chunk never notifies.
  3. Loop de-phasing — the poller offsets its first pass; the scanner does not.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from threading import Event
from unittest.mock import MagicMock, patch

import psycopg2
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session as SASession
from sqlalchemy.sql import Update

from db.models import MonitoredContract, MonitoredEvent
from services.monitoring import unified_watcher as uw
from services.monitoring.unified_watcher import poll_for_state_changes

RECENT = datetime(2025, 1, 1, tzinfo=timezone.utc)


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _word(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def _entry(field: str, selector: str, **extra: object) -> dict:
    e: dict[str, object] = {"field": field, "kind": "getter_call", "selector": selector, "type_kind": "address"}
    e.update(extra)
    return e


def _seed(
    session: SASession,
    n: int,
    *,
    plan: list[dict],
    last_known_state: dict | None = None,
    last_polled_at: datetime | None = None,
) -> MonitoredContract:
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=ADDR(n),
        chain="ethereum",
        contract_type="regular",
        monitoring_config={"polling_plan": plan},
        last_known_state=last_known_state if last_known_state is not None else {},
        last_scanned_block=0,
        needs_polling=True,
        is_active=True,
        last_polled_at=last_polled_at,
    )
    session.add(mc)
    session.commit()
    return mc


def _rpc_mock(returns: Mapping[str, str | None]):
    def _mock(url, calls):
        out: list[tuple[str | None, bool]] = []
        for method, params in calls:
            to = params[0]["to"] if method == "eth_call" else params[0]
            out.append((returns.get(to.lower()), False))
        return out

    return _mock


def _deadlock_error() -> OperationalError:
    """A SQLAlchemy OperationalError wrapping a psycopg2 deadlock, shaped exactly
    like the one Postgres raises when it aborts one side of a lock cycle."""
    return OperationalError("UPDATE monitored_contracts ...", {}, psycopg2.errors.DeadlockDetected("deadlock detected"))


def _conn_lost_error() -> OperationalError:
    """A non-deadlock OperationalError — the class that must NOT be swallowed."""
    return OperationalError("SELECT 1", {}, psycopg2.OperationalError("server closed the connection unexpectedly"))


def _deadlock_on_nth(session: SASession, *, predicate, raise_on: int, error_factory):
    """Wrap ``session.execute`` so the Nth statement matching *predicate* raises
    *error_factory()* before touching the DB — simulating Postgres aborting that
    exact statement. Returns the installed wrapper's call so the caller patches it."""
    real_execute = session.execute
    state = {"hits": 0}

    def wrapper(statement, *args, **kwargs):
        if predicate(statement):
            state["hits"] += 1
            if state["hits"] == raise_on:
                raise error_factory()
        return real_execute(statement, *args, **kwargs)

    return wrapper


def _is_stamp_update(statement) -> bool:
    return isinstance(statement, Update) and "monitored_contracts" in str(statement)


def _is_suppression_select(statement) -> bool:
    # The suppression query is the only one filtering on detected_at.
    return "detected_at" in str(statement)


# ---------------------------------------------------------------------------
# Fix 1 — chunk-level deadlock isolation
# ---------------------------------------------------------------------------


def test_deadlock_at_stamp_isolates_chunk_and_reports_partial(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "3")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    a = _seed(
        db_session,
        1,
        plan=[_entry("t", "0xaa01")],
        last_known_state={"t": ADDR(90)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    b = _seed(
        db_session,
        2,
        plan=[_entry("t", "0xbb01")],
        last_known_state={"t": ADDR(91)},
        last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
    )
    c = _seed(
        db_session,
        3,
        plan=[_entry("t", "0xcc01")],
        last_known_state={"t": ADDR(92)},
        last_polled_at=datetime(2022, 1, 1, tzinfo=timezone.utc),
    )

    returns = {ADDR(1): _word(ADDR(190)), ADDR(2): _word(ADDR(191)), ADDR(3): _word(ADDR(192))}
    captured: list[dict] = []

    # Chunk order is a, b, c (last_polled_at asc). Deadlock the 2nd stamp (b).
    wrapper = _deadlock_on_nth(db_session, predicate=_is_stamp_update, raise_on=2, error_factory=_deadlock_error)
    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_rpc_mock(returns)),
        patch.object(db_session, "execute", side_effect=wrapper),
        patch("services.monitoring.record_heartbeat", side_effect=lambda p, *, status, detail: captured.append(detail)),
    ):
        events = poll_for_state_changes(db_session, "http://rpc")  # must not raise

    assert len(events) == 2  # a and c committed; b rolled back

    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    with SASession(engine) as fresh:
        ra, rb, rc = (fresh.get(MonitoredContract, x.id) for x in (a, b, c))
        assert ra is not None and rb is not None and rc is not None
        assert ra.last_polled_at is not None and ra.last_polled_at > RECENT  # committed + stamped
        assert ra.last_known_state and ra.last_known_state["t"] == ADDR(190)
        assert rb.last_polled_at == datetime(2021, 1, 1, tzinfo=timezone.utc)  # unstamped -> retries first
        assert rb.last_known_state and rb.last_known_state["t"] == ADDR(91)  # in-memory mutation rolled back
        assert rc.last_polled_at is not None and rc.last_polled_at > RECENT  # later chunk still ran
        assert rc.last_known_state and rc.last_known_state["t"] == ADDR(192)
        evt = {(e.monitored_contract_id, e.event_type) for e in fresh.execute(select(MonitoredEvent)).scalars().all()}
        assert (a.id, "state_changed_poll") in evt
        assert (c.id, "state_changed_poll") in evt
        assert (b.id, "state_changed_poll") not in evt
    engine.dispose()

    assert captured[-1]["partial"] is True
    assert captured[-1]["chunks_failed"] == 1


def test_deadlock_during_suppression_autoflush_rolls_back_in_memory_state(db_session, monkeypatch):
    """The incident deadlock surfaced during a query-invoked autoflush, before
    the commit. Prove the try/except boundary covers that: a deadlock at the
    suppression SELECT reverts the chunk's already-staged last_known_state."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "3")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    a = _seed(
        db_session,
        1,
        plan=[_entry("t", "0xaa01")],
        last_known_state={"t": ADDR(90)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    # b's entry suppresses when the scanner already saw an ownership event; the
    # prior event below makes the suppression SELECT actually fire.
    b = _seed(
        db_session,
        2,
        plan=[_entry("guardian", "0xbb01", suppress_when_scan_event_types=["ownership_transferred"])],
        last_known_state={"guardian": ADDR(91)},
        last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add(
        MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=b.id,
            event_type="ownership_transferred",
            block_number=1,
            tx_hash="0xdead",
            data={},
        )
    )
    db_session.commit()

    returns = {ADDR(1): _word(ADDR(190)), ADDR(2): _word(ADDR(191))}
    wrapper = _deadlock_on_nth(db_session, predicate=_is_suppression_select, raise_on=1, error_factory=_deadlock_error)
    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_rpc_mock(returns)),
        patch.object(db_session, "execute", side_effect=wrapper),
    ):
        events = poll_for_state_changes(db_session, "http://rpc")  # must not raise

    assert len(events) == 1  # only a

    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    with SASession(engine) as fresh:
        ra, rb = fresh.get(MonitoredContract, a.id), fresh.get(MonitoredContract, b.id)
        assert ra is not None and rb is not None
        assert ra.last_polled_at is not None and ra.last_polled_at > RECENT
        assert ra.last_known_state and ra.last_known_state["t"] == ADDR(190)
        # The deadlock hit AFTER b's state was staged in memory but BEFORE commit;
        # rollback must revert both the value and the (missing) stamp.
        assert rb.last_polled_at == datetime(2021, 1, 1, tzinfo=timezone.utc)
        assert rb.last_known_state and rb.last_known_state["guardian"] == ADDR(91)
    engine.dispose()


def test_non_deadlock_operational_error_kills_the_pass(db_session, monkeypatch):
    """A connection-loss OperationalError must propagate (run_poll_loop then
    records an honest degraded cycle), never be masked as a per-chunk retry."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "3")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    a = _seed(
        db_session,
        1,
        plan=[_entry("t", "0xaa01")],
        last_known_state={"t": ADDR(90)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    b = _seed(
        db_session,
        2,
        plan=[_entry("t", "0xbb01")],
        last_known_state={"t": ADDR(91)},
        last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
    )

    returns = {ADDR(1): _word(ADDR(190)), ADDR(2): _word(ADDR(191))}
    wrapper = _deadlock_on_nth(db_session, predicate=_is_stamp_update, raise_on=2, error_factory=_conn_lost_error)
    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_rpc_mock(returns)),
        patch.object(db_session, "execute", side_effect=wrapper),
        pytest.raises(OperationalError),
    ):
        poll_for_state_changes(db_session, "http://rpc")

    # Chunk a committed durably before the fatal error killed the pass.
    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    with SASession(engine) as fresh:
        ra, rb = fresh.get(MonitoredContract, a.id), fresh.get(MonitoredContract, b.id)
        assert ra is not None and rb is not None
        assert ra.last_polled_at is not None and ra.last_polled_at > RECENT
        assert rb.last_polled_at == datetime(2021, 1, 1, tzinfo=timezone.utc)
    engine.dispose()


def test_deadlock_in_reanalysis_autoflush_is_isolated_not_fatal(db_session, monkeypatch):
    """Regression for the reviewer's A1 hole: a deadlock surfacing during
    maybe_queue_reanalysis's Job-SELECT autoflush (the incident's exact
    statement) used to be swallowed by the reanalysis inner handler, poisoning
    the session so the NEXT statement raised PendingRollbackError past the chunk
    handler and killed the whole pass. Drives the real poll path; only the wire
    and the DB abort (a before_cursor_execute hook raising DeadlockDetected on
    the flushed UPDATE, exactly as Postgres would) are simulated.
    """
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")

    # contract_id=None so _sync_relational_from_poll no-ops and the reanalysis
    # Job SELECT is the first query after the staged last_known_state mutation —
    # its autoflush emits the UPDATE the hook aborts. "owner" is a reanalysis
    # trigger so maybe_queue_reanalysis actually runs.
    mc = _seed(
        db_session,
        1,
        plan=[_entry("owner", "0x8da5cb5b")],
        last_known_state={"owner": ADDR(90)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )

    arm = {"on": False}
    engine = db_session.get_bind()

    def _abort_update(conn, cursor, statement, parameters, context, executemany):
        if arm["on"] and statement.strip().upper().startswith("UPDATE MONITORED_CONTRACTS"):
            arm["on"] = False
            raise psycopg2.errors.DeadlockDetected("deadlock detected")

    def _rpc(url, calls):
        arm["on"] = True  # arm as the chunk's DB phase begins
        return [(_word(ADDR(190)), False) for _ in calls]

    captured: list[dict] = []
    event.listen(engine, "before_cursor_execute", _abort_update)
    try:
        with (
            patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_rpc),
            patch(
                "services.monitoring.record_heartbeat",
                side_effect=lambda p, *, status, detail: captured.append(detail),
            ),
        ):
            events = poll_for_state_changes(db_session, "http://rpc")  # must NOT raise
    finally:
        event.remove(engine, "before_cursor_execute", _abort_update)

    assert events == []  # the only chunk deadlocked and rolled back
    assert captured[-1]["partial"] is True
    assert captured[-1]["chunks_failed"] == 1

    # Row is unstamped (retries first) and the observed value is unchanged.
    db_session.rollback()
    reloaded = db_session.get(MonitoredContract, mc.id)
    assert reloaded is not None
    assert reloaded.last_polled_at == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert reloaded.last_known_state and reloaded.last_known_state["owner"] == ADDR(90)


# ---------------------------------------------------------------------------
# Fix 2 — per-chunk post-commit notification
# ---------------------------------------------------------------------------


def test_notifies_committed_chunks_once_never_the_rolled_back_chunk(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "3")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    # Seed order (last_polled_at asc) = a, b, c; only the committed chunks' event
    # ids matter here, read back from the pass return value.
    _seed(
        db_session,
        1,
        plan=[_entry("t", "0xaa01")],
        last_known_state={"t": ADDR(90)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    _seed(
        db_session,
        2,
        plan=[_entry("t", "0xbb01")],
        last_known_state={"t": ADDR(91)},
        last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
    )
    _seed(
        db_session,
        3,
        plan=[_entry("t", "0xcc01")],
        last_known_state={"t": ADDR(92)},
        last_polled_at=datetime(2022, 1, 1, tzinfo=timezone.utc),
    )

    notified: list[uuid.UUID] = []

    def _record_notify(session, events):
        notified.extend(e.id for e in events)

    returns = {ADDR(1): _word(ADDR(190)), ADDR(2): _word(ADDR(191)), ADDR(3): _word(ADDR(192))}
    wrapper = _deadlock_on_nth(db_session, predicate=_is_stamp_update, raise_on=2, error_factory=_deadlock_error)
    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_rpc_mock(returns)),
        patch.object(db_session, "execute", side_effect=wrapper),
        patch("services.monitoring.notifier.notify_protocol_events", side_effect=_record_notify),
    ):
        events = poll_for_state_changes(db_session, "http://rpc")

    committed_event_ids = {e.id for e in events}
    # Exactly the committed chunks (a, c) were notified, each once; b never was.
    assert sorted(notified) == sorted(committed_event_ids)
    assert len(notified) == len(set(notified)) == 2


# ---------------------------------------------------------------------------
# Fix 4 — cleansed baseline emits no phantom on first real observation
# ---------------------------------------------------------------------------


def test_cleansed_owner_absent_state_emits_no_phantom(db_session, monkeypatch):
    """After the merge cleanses a poisoned zero owner (owner absent from state),
    the first live poll of a real owner is a silent baseline — not a phantom."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    _seed(db_session, 1, plan=[_entry("owner", "0xaa01")], last_known_state={})  # owner absent

    with patch(
        "services.monitoring.unified_watcher.rpc_batch_request_with_status",
        side_effect=_rpc_mock({ADDR(1): _word(ADDR(200))}),
    ):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert events == []  # first observation of a real owner is silent


# ---------------------------------------------------------------------------
# Fix 3 — loop de-phasing
# ---------------------------------------------------------------------------


def test_poll_startup_offset_is_half_interval_by_default():
    assert uw._poll_startup_offset(600) == 300.0
    assert 0 < uw._poll_startup_offset(uw.DEFAULT_POLL_INTERVAL) < uw.DEFAULT_POLL_INTERVAL


def test_poll_startup_offset_env_override(monkeypatch):
    monkeypatch.setenv("PSAT_POLL_STARTUP_OFFSET_S", "0")
    assert uw._poll_startup_offset(600) == 0.0
    monkeypatch.setenv("PSAT_POLL_STARTUP_OFFSET_S", "7.5")
    assert uw._poll_startup_offset(600) == 7.5


def test_poll_loop_waits_offset_before_first_pass(monkeypatch):
    waits: list[float | None] = []
    beats: list[str] = []
    ev = Event()

    def rec_wait(timeout=None):
        waits.append(timeout)
        return True  # signal stop so the loop exits right after the offset wait

    monkeypatch.setattr(ev, "wait", rec_wait)
    poll_mock = MagicMock()
    monkeypatch.setattr(uw, "poll_for_state_changes", poll_mock)
    # A "starting" beat must land BEFORE the offset wait so a fresh-DB poller
    # isn't classified dead during the de-phasing gap (never-beat == stale).
    monkeypatch.setattr(uw, "record_heartbeat", lambda process, *, status, detail: beats.append(status))

    uw.run_poll_loop("http://rpc", interval=600, stop_event=ev)

    assert beats == ["starting"]  # beaten once, before the wait
    assert waits == [300.0]  # only the startup offset ran
    poll_mock.assert_not_called()  # the offset precedes the first pass


def test_poll_loop_startup_offset_override_disables_shift(monkeypatch):
    """The standalone --poll runner passes startup_offset_s=0 → no pre-wait."""
    waits: list[float | None] = []
    ev = Event()

    def rec_wait(timeout=None):
        waits.append(timeout)
        return True

    def _poll(session, url):
        ev.set()  # stop after the first pass
        return []

    monkeypatch.setattr(ev, "wait", rec_wait)
    monkeypatch.setattr(uw, "poll_for_state_changes", _poll)
    monkeypatch.setattr(uw, "SessionLocal", lambda: contextlib.nullcontext(MagicMock()))
    monkeypatch.setattr(uw, "record_heartbeat", lambda *a, **k: None)

    uw.run_poll_loop("http://rpc", interval=600, stop_event=ev, startup_offset_s=0.0)

    # No 300s offset wait — the first wait is the post-pass interval wait.
    assert waits == [600.0]


def test_scan_loop_does_not_offset_first_pass(monkeypatch):
    order: list = []
    ev = Event()

    def fake_scan(session, rpc_url):
        order.append("scan")
        ev.set()  # stop after the first pass
        return uw.ScanResult([])

    def rec_wait(timeout=None):
        order.append(("wait", timeout))
        return True

    monkeypatch.setattr(uw, "scan_for_events", fake_scan)
    monkeypatch.setattr(uw, "SessionLocal", lambda: contextlib.nullcontext(MagicMock()))
    monkeypatch.setattr(ev, "wait", rec_wait)

    uw.run_scan_loop("http://rpc", interval=600, stop_event=ev)

    assert order[0] == "scan"  # the scanner runs its first pass with no pre-wait
