"""The real ``poll_for_state_changes`` with only the RPC wire stubbed.

Errored chunks stamp and rotate normally, since always-reverting entries would pin the rotation; a
transport-failed chunk publishes nothing and stays retry-first. Any non-observed entry marks the pass partial.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session as SASession

from db.models import (
    MonitoredContract,
    MonitoredEvent,
)
from services.monitoring.unified_watcher import poll_for_state_changes

# Clock-skew-proof "was stamped" check.
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
    watched_proxy_id: uuid.UUID | None = None,
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
        watched_proxy_id=watched_proxy_id,
    )
    session.add(mc)
    session.commit()
    return mc


def _make_mock(
    returns: Mapping[str, str | None],
    error_on: set[int] | None = None,
    transport_on: set[int] | None = None,
):
    """``transport`` means the node never answered; the real helper never raises."""
    batches: list[list] = []
    state = {"n": 0}

    def _mock(url, calls):
        state["n"] += 1
        batches.append(calls)
        if error_on and state["n"] in error_on:
            return [(None, "error")] * len(calls)
        if transport_on and state["n"] in transport_on:
            return [(None, "transport")] * len(calls)
        out: list[tuple[str | None, str]] = []
        for method, params in calls:
            to = params[0]["to"] if method == "eth_call" else params[0]
            out.append((returns.get(to.lower()), "ok"))
        return out

    return _mock, batches


def _addrs_in_batch(batch: list) -> list[str]:
    return [(params[0]["to"] if method == "eth_call" else params[0]).lower() for method, params in batch]


def test_chunking_keeps_one_contracts_entries_together(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "10")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 3)

    # C's calls start a fresh chunk rather than split across the boundary.
    a = _seed(
        db_session,
        1,
        plan=[_entry("f1", "0xaa01"), _entry("f2", "0xaa02")],
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    b = _seed(db_session, 2, plan=[_entry("g1", "0xbb01")], last_polled_at=datetime(2020, 1, 2, tzinfo=timezone.utc))
    c = _seed(
        db_session,
        3,
        plan=[_entry("h1", "0xcc01"), _entry("h2", "0xcc02")],
        last_polled_at=datetime(2020, 1, 3, tzinfo=timezone.utc),
    )

    mock, batches = _make_mock({})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=mock):
        poll_for_state_changes(db_session, "http://rpc")

    assert len(batches) == 2
    assert _addrs_in_batch(batches[0]) == [ADDR(1), ADDR(1), ADDR(2)]  # A+B packed
    assert _addrs_in_batch(batches[1]) == [ADDR(3), ADDR(3)]  # C whole, not split

    for mc in (a, b, c):
        hosting = [i for i, batch in enumerate(batches) if mc.address in _addrs_in_batch(batch)]
        assert len(hosting) == 1


def test_failed_chunk_is_durable_partial_and_leaves_others_intact(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "3")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    a = _seed(
        db_session,
        1,
        plan=[_entry("trackedAddr", "0xaa01")],
        last_known_state={"trackedAddr": ADDR(90)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    b = _seed(
        db_session,
        2,
        plan=[_entry("trackedAddr", "0xbb01")],
        last_known_state={"trackedAddr": ADDR(91)},
        last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
    )
    c = _seed(
        db_session,
        3,
        plan=[_entry("trackedAddr", "0xcc01")],
        last_known_state={"trackedAddr": ADDR(92)},
        last_polled_at=datetime(2022, 1, 1, tzinfo=timezone.utc),
    )

    returns = {ADDR(1): _word(ADDR(190)), ADDR(3): _word(ADDR(192))}
    # One chunk per contract; chunk 2 gets per-call reverts, an observed outcome.
    mock, _ = _make_mock(returns, error_on={2})
    captured: list[tuple] = []

    def _cap(process, *, status, detail):
        captured.append((process, status, detail))

    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=mock),
        patch("services.monitoring.record_heartbeat", side_effect=_cap),
    ):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert len(events) == 2  # a and c detected; b's call errored

    # A fresh connection sees each chunk: the commit was per chunk.
    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    with SASession(engine) as fresh:
        ra = fresh.get(MonitoredContract, a.id)
        rb = fresh.get(MonitoredContract, b.id)
        rc = fresh.get(MonitoredContract, c.id)
        assert ra is not None and rb is not None and rc is not None
        assert ra.last_polled_at is not None and ra.last_polled_at > RECENT  # chunk 1 stamped + persisted
        assert ra.last_known_state and ra.last_known_state["trackedAddr"] == ADDR(190)
        assert ra.last_poll_status == {"trackedAddr": "ok"}
        # Otherwise always-reverting entries would pin the front.
        assert rb.last_polled_at is not None and rb.last_polled_at > RECENT
        assert rb.last_known_state and rb.last_known_state["trackedAddr"] == ADDR(91)  # value plane untouched
        assert rb.last_poll_status == {"trackedAddr": "error"}
        assert rc.last_polled_at is not None and rc.last_polled_at > RECENT  # chunk 3 still processed
        assert rc.last_known_state and rc.last_known_state["trackedAddr"] == ADDR(192)
        assert rc.last_poll_status == {"trackedAddr": "ok"}

        evt_types = {
            (e.monitored_contract_id, e.event_type) for e in fresh.execute(select(MonitoredEvent)).scalars().all()
        }
        assert (a.id, "state_changed_poll") in evt_types
        assert (c.id, "state_changed_poll") in evt_types
        assert (b.id, "state_changed_poll") not in evt_types
    engine.dispose()

    detail = captured[-1][2]
    assert detail["partial"] is True
    assert detail["chunks_failed"] == 0  # no chunk rolled back — the error is per-entry
    assert detail["chunks_transport_failed"] == 0  # every batch was answered
    assert detail["entry_errors"] == 1
    assert detail["entries_no_value"] == 0  # a and c both decoded values
    assert detail["chunks"] == 3
    assert detail["contracts_selected"] == 3


def test_transport_failed_chunk_publishes_nothing_and_is_retry_first(db_session, monkeypatch):
    """An outage keeps prior status and sorts first next pass, and never publishes ``error``."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "2")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    seeded_b = datetime(2021, 1, 1, tzinfo=timezone.utc)
    a = _seed(
        db_session, 1, plan=[_entry("trackedAddr", "0xaa01")], last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc)
    )
    b = _seed(db_session, 2, plan=[_entry("trackedAddr", "0xbb01")], last_polled_at=seeded_b)

    captured: list[tuple] = []

    def _cap(process, *, status, detail):
        captured.append((process, status, detail))

    mock, _ = _make_mock({ADDR(1): _word(ADDR(190))}, transport_on={2})
    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=mock),
        patch("services.monitoring.record_heartbeat", side_effect=_cap),
    ):
        poll_for_state_changes(db_session, "http://rpc")

    db_session.expire_all()
    ra = db_session.get(MonitoredContract, a.id)
    assert ra.last_polled_at > RECENT
    assert ra.last_poll_status == {"trackedAddr": "ok"}
    rb = db_session.get(MonitoredContract, b.id)
    assert rb.last_polled_at == seeded_b  # unstamped -> sorts first next pass
    assert rb.last_poll_status is None  # nothing published for an unobserved outcome

    detail = captured[-1][2]
    assert detail["partial"] is True
    assert detail["chunks_transport_failed"] == 1
    assert detail["entry_errors"] == 0  # transport is NOT an entry error

    mock2, _ = _make_mock({ADDR(1): _word(ADDR(190)), ADDR(2): _word(ADDR(191))})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=mock2):
        poll_for_state_changes(db_session, "http://rpc")
    db_session.expire_all()
    rb = db_session.get(MonitoredContract, b.id)
    assert rb.last_polled_at > RECENT
    assert rb.last_poll_status == {"trackedAddr": "ok"}


def test_answered_empty_return_publishes_no_value_not_ok(db_session, monkeypatch):
    """Answered empty: not ``ok``, not ``error``."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    mc = _seed(db_session, 1, plan=[_entry("_initialized", "0xdeadbeef")], last_polled_at=RECENT)

    captured: list[tuple] = []

    def _cap(process, *, status, detail):
        captured.append((process, status, detail))

    with (
        patch(
            "services.monitoring.unified_watcher.rpc_batch_request_classified",
            side_effect=lambda url, calls: [("0x", "ok")] * len(calls),
        ),
        patch("services.monitoring.record_heartbeat", side_effect=_cap),
    ):
        poll_for_state_changes(db_session, "http://rpc")

    db_session.expire_all()
    row = db_session.get(MonitoredContract, mc.id)
    assert row.last_poll_status == {"_initialized": "no_value"}
    assert row.last_known_state == {}  # nothing decodable ever reaches the value plane
    assert row.last_polled_at > RECENT  # an answered call IS a completed poll

    detail = captured[-1][2]
    assert detail["partial"] is True
    assert detail["entries_no_value"] == 1
    assert detail["entry_errors"] == 0


def test_answered_zero_word_is_ok_and_pass_is_not_partial(db_session, monkeypatch):
    """A zero word is an observed value; a negative must come from failing to observe.

    The zero stays out of ``last_known_state``.
    """
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    plan = [_entry("owner", "0x8da5cb5b"), _entry("guardian", "0xaa02")]
    mc = _seed(db_session, 1, plan=plan, last_polled_at=RECENT)

    captured: list[tuple] = []

    def _cap(process, *, status, detail):
        captured.append((process, status, detail))

    def _mock(url, calls):
        assert len(calls) == 2
        return [("0x" + "0" * 64, "ok"), (_word(ADDR(190)), "ok")]

    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=_mock),
        patch("services.monitoring.record_heartbeat", side_effect=_cap),
    ):
        poll_for_state_changes(db_session, "http://rpc")

    db_session.expire_all()
    row = db_session.get(MonitoredContract, mc.id)
    assert row.last_poll_status == {"owner": "ok", "guardian": "ok"}
    assert row.last_known_state == {"guardian": ADDR(190)}  # zero never stored
    assert row.last_polled_at > RECENT

    process, status, detail = captured[-1]
    assert status == "running"  # nothing failed, nothing was unobserved
    assert detail["partial"] is False
    assert detail["entries_no_value"] == 0
    assert detail["entry_errors"] == 0


def test_last_poll_status_is_served_on_monitored_contracts(db_session, api_client, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    plan = [_entry("good", "0xaa01"), _entry("dead", "0xaa02"), _entry("hollow", "0xaa03")]
    mc = _seed(db_session, 1, plan=plan, last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc))

    def _mock(url, calls):
        return [(_word(ADDR(190)), "ok"), (None, "error"), ("0x", "ok")]

    with patch("services.monitoring.unified_watcher.rpc_batch_request_classified", side_effect=_mock):
        poll_for_state_changes(db_session, "http://rpc")

    resp = api_client.get("/api/monitored-contracts")
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["id"] == str(mc.id))
    assert row["last_poll_status"] == {"good": "ok", "dead": "error", "hollow": "no_value"}
    assert row["last_known_state"] == {"good": ADDR(190)}
