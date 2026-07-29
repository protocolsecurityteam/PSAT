"""Integration tests for the poller rotation + chunked-commit driver.

Exercises the real ``poll_for_state_changes`` production path against the real
test DB (via the shared ``db_session`` fixture) with only the RPC wire
(``rpc_batch_request_with_status``) stubbed — never the repo classes. Covers:

  - rotation order (``last_polled_at ASC NULLS FIRST``) + slice cap
  - chunk packing at ``MAX_BATCH_SIZE`` keeping a contract's calls together
  - per-entry poll status: errored calls publish ``error`` in
    ``last_poll_status``, never touch ``last_known_state``, and mark the
    pass ``partial``; a transport-failed chunk stamps with every entry
    ``error`` (NOT retry-first — always-reverting entries exist in
    persisted plans and would otherwise pin the rotation)
  - scanner-duplicate suppression, first-observation baseline, and
    ``last_known_state`` updates surviving the driver rewrite
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
    ProxyUpgradeEvent,
    WatchedProxy,
)
from services.monitoring.unified_watcher import poll_for_state_changes

# A timestamp every seeded ``last_polled_at`` is strictly below and every
# server-stamped one is strictly above — clock-skew-proof "was stamped" check.
RECENT = datetime(2025, 1, 1, tzinfo=timezone.utc)


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _word(addr: str) -> str:
    """Right-pad a 20-byte address into a 32-byte ABI word."""
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


def _make_mock(returns: Mapping[str, str | None], fail_on: set[int] | None = None):
    """Build a ``rpc_batch_request_with_status`` stub that records each
    batch's calls and returns per-``to``-address ``(value, had_error)``
    pairs from *returns*.

    *fail_on* is a set of 1-based invocation indexes whose whole batch
    comes back as ``(None, True)`` slots — exactly how the real helper
    reports a wholesale transport failure (it never raises).
    """
    batches: list[list] = []
    state = {"n": 0}

    def _mock(url, calls):
        state["n"] += 1
        batches.append(calls)
        if fail_on and state["n"] in fail_on:
            return [(None, True)] * len(calls)
        out: list[tuple[str | None, bool]] = []
        for method, params in calls:
            to = params[0]["to"] if method == "eth_call" else params[0]
            out.append((returns.get(to.lower()), False))
        return out

    return _mock, batches


def _addrs_in_batch(batch: list) -> list[str]:
    return [(params[0]["to"] if method == "eth_call" else params[0]).lower() for method, params in batch]


# ---------------------------------------------------------------------------
# Rotation order + slice cap
# ---------------------------------------------------------------------------


def test_rotation_orders_nulls_first_then_ascending_and_caps_slice(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "2")
    plan = [_entry("trackedAddr", "0xaa000001")]

    a = _seed(db_session, 1, plan=plan, last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    b = _seed(db_session, 2, plan=plan, last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc))
    c = _seed(db_session, 3, plan=plan, last_polled_at=None)
    d = _seed(db_session, 4, plan=plan, last_polled_at=datetime(2022, 1, 1, tzinfo=timezone.utc))

    mock, _ = _make_mock({})  # returns None everywhere -> no events, just rotation
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert events == []
    db_session.expire_all()
    # NULLS FIRST (c) then oldest (a); cap=2 stops there.
    assert db_session.get(MonitoredContract, c.id).last_polled_at > RECENT
    assert db_session.get(MonitoredContract, a.id).last_polled_at > RECENT
    # b and d were beyond the slice — untouched.
    assert db_session.get(MonitoredContract, b.id).last_polled_at == datetime(2021, 1, 1, tzinfo=timezone.utc)
    assert db_session.get(MonitoredContract, d.id).last_polled_at == datetime(2022, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Chunk packing
# ---------------------------------------------------------------------------


def test_chunking_keeps_one_contracts_entries_together(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "10")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 3)

    # A: 2 calls, B: 1 call, C: 2 calls. With a 3-call budget the packer fills
    # [A(2)+B(1)] exactly, then starts a fresh chunk for C rather than splitting
    # C's 2 calls across the boundary.
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
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        poll_for_state_changes(db_session, "http://rpc")

    assert len(batches) == 2
    assert _addrs_in_batch(batches[0]) == [ADDR(1), ADDR(1), ADDR(2)]  # A+B packed
    assert _addrs_in_batch(batches[1]) == [ADDR(3), ADDR(3)]  # C whole, not split

    # No contract's address spans two batches.
    for mc in (a, b, c):
        hosting = [i for i, batch in enumerate(batches) if mc.address in _addrs_in_batch(batch)]
        assert len(hosting) == 1


# ---------------------------------------------------------------------------
# Per-entry status + partial reporting
# ---------------------------------------------------------------------------


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
    # Order is a, b, c (by last_polled_at); MAX_BATCH_SIZE=1 -> one chunk each.
    # Chunk 2 (contract b) fails transport-wholesale: every slot (None, True).
    mock, _ = _make_mock(returns, fail_on={2})
    captured: list[tuple] = []

    def _cap(process, *, status, detail):
        captured.append((process, status, detail))

    with (
        patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock),
        patch("services.monitoring.record_heartbeat", side_effect=_cap),
    ):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert len(events) == 2  # a and c detected; b's call errored

    # Durability: a fresh connection sees each chunk's committed rows,
    # proving the commit happened per chunk and not as one pass-wide transaction.
    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    with SASession(engine) as fresh:
        ra = fresh.get(MonitoredContract, a.id)
        rb = fresh.get(MonitoredContract, b.id)
        rc = fresh.get(MonitoredContract, c.id)
        assert ra is not None and rb is not None and rc is not None
        assert ra.last_polled_at is not None and ra.last_polled_at > RECENT  # chunk 1 stamped + persisted
        assert ra.last_known_state and ra.last_known_state["trackedAddr"] == ADDR(190)
        assert ra.last_poll_status == {"trackedAddr": "ok"}
        # The errored chunk is stamped too — the outcome is published as
        # per-entry status, not silence, and the contract rotates normally
        # (an unstamped-on-error rule would pin always-reverting entries
        # to the front of the rotation forever).
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
    assert detail["entry_errors"] == 1
    assert detail["chunks"] == 3
    assert detail["contracts_selected"] == 3


def test_errored_chunk_contracts_rotate_normally_not_retry_first(db_session, monkeypatch):
    """A transport-failed chunk stamps its contracts (statuses all
    ``error``) instead of holding them at the front of the rotation —
    persisted plans contain always-reverting entries, and retry-first on
    RPC error would let them crowd out every other contract's slot."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "2")
    monkeypatch.setattr("services.monitoring.unified_watcher.MAX_BATCH_SIZE", 1)

    a = _seed(
        db_session, 1, plan=[_entry("trackedAddr", "0xaa01")], last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc)
    )
    b = _seed(
        db_session, 2, plan=[_entry("trackedAddr", "0xbb01")], last_polled_at=datetime(2021, 1, 1, tzinfo=timezone.utc)
    )

    # Pass 1: a stamped ok; b's chunk (invocation 2) transport-fails ->
    # b is stamped as well, with the error published per entry.
    mock1, _ = _make_mock({}, fail_on={2})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock1):
        poll_for_state_changes(db_session, "http://rpc")

    db_session.expire_all()
    assert db_session.get(MonitoredContract, a.id).last_polled_at > RECENT
    rb = db_session.get(MonitoredContract, b.id)
    assert rb.last_polled_at > RECENT
    assert rb.last_poll_status == {"trackedAddr": "error"}

    # Pass 2: b's status heals to ok once the call succeeds again.
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "2")
    mock2, _ = _make_mock({})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock2):
        poll_for_state_changes(db_session, "http://rpc")

    db_session.expire_all()
    assert db_session.get(MonitoredContract, b.id).last_poll_status == {"trackedAddr": "ok"}


def test_entry_not_dispatched_is_absent_from_status_map(db_session, monkeypatch):
    """Three states end-to-end: a value entry is ``ok``, a reverting one is
    ``error``, and an entry the loop can't dispatch (unrecognized kind)
    stays absent from the map — not-polled, never conflated with either."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    plan = [
        _entry("good", "0xaa01"),
        _entry("dead", "0xaa02"),
        {"field": "weird", "kind": "future_kind"},
    ]
    mc = _seed(db_session, 1, plan=plan, last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc))

    def _mock(url, calls):
        # Plan order: good, dead (the future_kind entry produced no call).
        assert len(calls) == 2
        return [(_word(ADDR(190)), False), (None, True)]

    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_mock):
        poll_for_state_changes(db_session, "http://rpc")

    db_session.expire_all()
    reloaded = db_session.get(MonitoredContract, mc.id)
    assert reloaded.last_poll_status == {"good": "ok", "dead": "error"}
    assert "weird" not in reloaded.last_poll_status
    assert reloaded.last_known_state == {"good": ADDR(190)}


def test_last_poll_status_is_served_on_monitored_contracts(db_session, api_client, monkeypatch):
    """The status map reaches the published surface: GET
    /api/monitored-contracts serves per-entry ok/error alongside the
    value plane, so a reverting entry is visible as such."""
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    plan = [_entry("good", "0xaa01"), _entry("dead", "0xaa02")]
    mc = _seed(db_session, 1, plan=plan, last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc))

    def _mock(url, calls):
        return [(_word(ADDR(190)), False), (None, True)]

    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=_mock):
        poll_for_state_changes(db_session, "http://rpc")

    resp = api_client.get("/api/monitored-contracts")
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["id"] == str(mc.id))
    assert row["last_poll_status"] == {"good": "ok", "dead": "error"}
    assert row["last_known_state"] == {"good": ADDR(190)}


# ---------------------------------------------------------------------------
# Preserved computation: change, first-observation, suppression, write-through
# ---------------------------------------------------------------------------


def test_value_change_emits_event_updates_state_and_stamps(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    mc = _seed(
        db_session,
        1,
        plan=[_entry("trackedAddr", "0xaa01")],
        last_known_state={"trackedAddr": ADDR(80)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )

    mock, _ = _make_mock({ADDR(1): _word(ADDR(180))})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert len(events) == 1
    assert events[0].event_type == "state_changed_poll"
    db_session.expire_all()
    reloaded = db_session.get(MonitoredContract, mc.id)
    assert reloaded.last_known_state["trackedAddr"] == ADDR(180)
    assert reloaded.last_polled_at > RECENT


def test_first_observation_updates_state_without_event(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    mc = _seed(
        db_session,
        1,
        plan=[_entry("trackedAddr", "0xaa01")],
        last_known_state={},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )

    mock, _ = _make_mock({ADDR(1): _word(ADDR(180))})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert events == []  # old_value None -> baseline, no event
    db_session.expire_all()
    reloaded = db_session.get(MonitoredContract, mc.id)
    assert reloaded.last_known_state["trackedAddr"] == ADDR(180)
    assert reloaded.last_polled_at > RECENT


def test_suppression_when_scanner_already_detected(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    mc = _seed(
        db_session,
        1,
        plan=[_entry("guardian", "0xaa01", suppress_when_scan_event_types=["ownership_transferred"])],
        last_known_state={"guardian": ADDR(80)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add(
        MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type="ownership_transferred",
            block_number=1,
            tx_hash="0xdead",
            data={},
        )
    )
    db_session.commit()

    mock, _ = _make_mock({ADDR(1): _word(ADDR(180))})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert events == []  # suppressed by the recent scanner event
    db_session.expire_all()
    reloaded = db_session.get(MonitoredContract, mc.id)
    # State still advanced (recorded before the suppression check) and stamped.
    assert reloaded.last_known_state["guardian"] == ADDR(180)
    assert reloaded.last_polled_at > RECENT
    poll_events = (
        db_session.execute(
            select(MonitoredEvent).where(
                MonitoredEvent.monitored_contract_id == mc.id,
                MonitoredEvent.event_type == "state_changed_poll",
            )
        )
        .scalars()
        .all()
    )
    assert poll_events == []


def test_implementation_change_writes_proxy_upgrade_event(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    wp = WatchedProxy(
        id=uuid.uuid4(),
        proxy_address=ADDR(1),
        chain="ethereum",
        last_known_implementation=ADDR(70),
    )
    db_session.add(wp)
    db_session.commit()

    mc = _seed(
        db_session,
        1,
        plan=[_entry("implementation", "0xaa01")],
        last_known_state={"implementation": ADDR(70)},
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        watched_proxy_id=wp.id,
    )

    mock, _ = _make_mock({ADDR(1): _word(ADDR(170))})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert len(events) == 1
    db_session.expire_all()
    upgrades = (
        db_session.execute(select(ProxyUpgradeEvent).where(ProxyUpgradeEvent.watched_proxy_id == wp.id)).scalars().all()
    )
    assert len(upgrades) == 1
    assert upgrades[0].new_implementation == ADDR(170)
    assert db_session.get(WatchedProxy, wp.id).last_known_implementation == ADDR(170)
    assert db_session.get(MonitoredContract, mc.id).last_polled_at > RECENT


def test_contract_without_poll_entries_still_rotates(db_session, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    mc = _seed(db_session, 1, plan=[], last_polled_at=None)

    mock, batches = _make_mock({})
    with patch("services.monitoring.unified_watcher.rpc_batch_request_with_status", side_effect=mock):
        events = poll_for_state_changes(db_session, "http://rpc")

    assert events == []
    assert batches == []  # no RPC issued for an empty plan
    db_session.expire_all()
    # Stamped anyway so it doesn't perpetually occupy the NULLS-FIRST slot.
    assert db_session.get(MonitoredContract, mc.id).last_polled_at > RECENT
